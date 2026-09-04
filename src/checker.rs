use crate::capability::combined;
#[cfg(feature = "tracing")]
use crate::DEFAULT_SECURITY_RULE_CATEGORY;
use crate::{
    AccessEvaluation, BatchEvalCtx, CombineOp, Decision, DelegatingPolicy, EvalCtx, EvalTrace,
    EvaluationSession, FilterError, Hydrator, LookupAuthorizedError, LookupAuthorizedPage,
    LookupSource, Policy, PolicyBatchItem, PolicyDomain, PolicyEvalResult, SecurityRuleMetadata,
    VetoPolicy, PERMISSION_CHECKER_POLICY_TYPE,
};
use async_trait::async_trait;
use std::any::Any;
use std::borrow::{Borrow, Cow};
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
#[cfg(feature = "tracing")]
use tracing::Instrument;

#[derive(Clone, Copy)]
pub(crate) enum Phase {
    Veto,
    Grant,
}

impl Phase {
    fn decisive(self) -> Decision {
        match self {
            Self::Veto => Decision::Forbid,
            Self::Grant => Decision::Grant,
        }
    }
    fn reduce(self, previous: Decision, next: Decision) -> Decision {
        if next == self.decisive()
            || (next == Decision::Indeterminate && previous != self.decisive())
        {
            next
        } else {
            previous
        }
    }
}

#[derive(Default)]
pub(crate) struct EvaluationState {
    pub(crate) delegates: HashMap<Vec<usize>, Box<dyn Any + Send + Sync>>,
}
pub(crate) struct PhaseScope<'a> {
    pub(crate) state: &'a mut EvaluationState,
    pub(crate) item_indices: &'a [usize],
    pub(crate) path: &'a [usize],
}

#[async_trait]
pub(crate) trait PhasePolicy<D: PolicyDomain>: Send + Sync {
    async fn evaluate(&self, ctx: &EvalCtx<'_, D>, scope: &mut PhaseScope<'_>) -> PolicyEvalResult;
    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, D>,
        scope: &mut PhaseScope<'_>,
    ) -> Vec<PolicyEvalResult>;
    fn policy_type(&self) -> Cow<'static, str>;
    #[cfg_attr(not(feature = "tracing"), allow(dead_code))]
    fn security_rule(&self) -> SecurityRuleMetadata;
}
struct GrantAdapter<P>(P);
struct VetoAdapter<P>(P);
macro_rules! adapter {
    ($adapter:ident, $policy:ident) => {
        #[async_trait]
        impl<D: PolicyDomain, P: $policy<D>> PhasePolicy<D> for $adapter<P> {
            async fn evaluate(
                &self,
                ctx: &EvalCtx<'_, D>,
                _scope: &mut PhaseScope<'_>,
            ) -> PolicyEvalResult {
                self.0.evaluate(ctx).await.0
            }
            async fn evaluate_batch<'item>(
                &self,
                ctx: &BatchEvalCtx<'item, D>,
                _scope: &mut PhaseScope<'_>,
            ) -> Vec<PolicyEvalResult> {
                self.0
                    .evaluate_batch(ctx)
                    .await
                    .into_iter()
                    .map(|result| result.0)
                    .collect()
            }
            fn policy_type(&self) -> Cow<'static, str> {
                self.0.policy_type()
            }
            fn security_rule(&self) -> SecurityRuleMetadata {
                self.0.security_rule()
            }
        }
    };
}
adapter!(GrantAdapter, Policy);
adapter!(VetoAdapter, VetoPolicy);

/// Grant and veto policies for one authorization domain.
pub struct PermissionChecker<D: PolicyDomain> {
    name: Option<Cow<'static, str>>,
    grants: Vec<Arc<dyn PhasePolicy<D>>>,
    vetoes: Vec<Arc<dyn PhasePolicy<D>>>,
    max_batch_size: Option<NonZeroUsize>,
    next_delegate_id: usize,
}
impl<D: PolicyDomain> Clone for PermissionChecker<D> {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            grants: self.grants.clone(),
            vetoes: self.vetoes.clone(),
            max_batch_size: self.max_batch_size,
            next_delegate_id: self.next_delegate_id,
        }
    }
}
impl<D: PolicyDomain> Default for PermissionChecker<D> {
    fn default() -> Self {
        Self::new()
    }
}
impl<D: PolicyDomain> PermissionChecker<D> {
    /// Creates an empty checker, which denies every request.
    pub fn new() -> Self {
        Self {
            name: None,
            grants: Vec::new(),
            vetoes: Vec::new(),
            max_batch_size: None,
            next_delegate_id: 0,
        }
    }
    /// Creates a checker named for telemetry.
    pub fn named(name: impl Into<Cow<'static, str>>) -> Self {
        Self {
            name: Some(name.into()),
            ..Self::new()
        }
    }
    /// Returns the telemetry name.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    /// Limits the number of resources passed to each policy batch.
    pub fn with_max_batch_size(mut self, max_batch_size: NonZeroUsize) -> Self {
        self.max_batch_size = Some(max_batch_size);
        self
    }
    /// Adds a policy that can grant or abstain.
    pub fn add_policy<P: Policy<D> + 'static>(&mut self, policy: P) {
        self.grants.push(Arc::new(GrantAdapter(policy)));
    }
    /// Adds a policy that can veto or pass. Vetoes always run before grants.
    pub fn add_veto<P: VetoPolicy<D> + 'static>(&mut self, policy: P) {
        self.vetoes.push(Arc::new(VetoAdapter(policy)));
    }
    /// Atomically installs both capabilities of a child checker.
    ///
    /// Child vetoes run during the parent's veto phase and child grants during
    /// its grant phase. No child policy is evaluated twice per resource.
    pub fn add_delegate<ChildD: PolicyDomain>(&mut self, delegate: DelegatingPolicy<D, ChildD>) {
        let (veto, grant) = delegate.into_phases(self.next_delegate_id);
        self.next_delegate_id += 1;
        self.vetoes.push(veto);
        self.grants.push(grant);
    }
    /// Binds request inputs and the request-scoped fact session.
    pub fn bind<'a>(
        &'a self,
        session: &'a EvaluationSession,
        subject: &'a D::Subject,
        action: &'a D::Action,
        context: &'a D::Context,
    ) -> BoundEvaluator<'a, D> {
        BoundEvaluator {
            checker: self,
            session,
            subject,
            action,
            context,
        }
    }

    pub(crate) async fn evaluate_phase<'item>(
        &self,
        phase: Phase,
        ctx: &BatchEvalCtx<'item, D>,
        scope: &mut PhaseScope<'_>,
    ) -> Vec<PolicyEvalResult> {
        let policies = match phase {
            Phase::Veto => &self.vetoes,
            Phase::Grant => &self.grants,
        };
        let mut children = vec![Vec::new(); ctx.items.len()];
        let mut decisions = vec![Decision::NotApplicable; ctx.items.len()];
        let mut pending: Vec<usize> = (0..ctx.items.len()).collect();
        let decisive = phase.decisive();
        for policy in policies {
            let chunk_size = self
                .max_batch_size
                .map(NonZeroUsize::get)
                .unwrap_or(usize::MAX);
            #[cfg_attr(not(feature = "tracing"), allow(clippy::unused_enumerate_index))]
            for (_chunk_index, indices) in pending.chunks(chunk_size).enumerate() {
                let items: Vec<_> = indices
                    .iter()
                    .map(|&index| PolicyBatchItem {
                        resource: ctx.items[index].resource,
                    })
                    .collect();
                let item_indices: Vec<_> = indices
                    .iter()
                    .map(|&index| scope.item_indices[index])
                    .collect();
                let mut child_scope = PhaseScope {
                    state: scope.state,
                    item_indices: &item_indices,
                    path: scope.path,
                };
                let policy_type = policy.policy_type();
                #[cfg(feature = "tracing")]
                let policy_span = tracing::debug_span!(
                    "gatehouse.batch_policy",
                    policy.type = policy_type.as_ref(),
                    policy.effect = phase_effect(phase),
                    policy.pending_count = indices.len(),
                    policy.chunk_index = _chunk_index,
                    policy.chunk_count = pending.len().div_ceil(chunk_size),
                    policy.granted_count = tracing::field::Empty,
                    policy.denied_count = tracing::field::Empty,
                    policy.forbidden_count = tracing::field::Empty,
                    policy.indeterminate_count = tracing::field::Empty,
                );
                let results = {
                    let inner = BatchEvalCtx::new(
                        ctx.session(),
                        ctx.subject,
                        ctx.action,
                        ctx.context,
                        &items,
                        policy_type.clone(),
                    );
                    let results = policy.evaluate_batch(&inner, &mut child_scope);
                    #[cfg(feature = "tracing")]
                    let results = results.instrument(policy_span.clone());
                    let results = results.await;
                    inner.finish(results)
                };
                let results = if results.len() == indices.len() {
                    results
                } else {
                    #[cfg(feature = "tracing")]
                    tracing::warn!(policy.type = policy_type.as_ref(), expected = indices.len(), actual = results.len(), "Policy batch result count did not match input count");
                    indices
                        .iter()
                        .map(|_| {
                            PolicyEvalResult::indeterminate(
                                policy_type.clone(),
                                "Policy batch result count did not match input count",
                            )
                        })
                        .collect()
                };
                #[cfg(feature = "tracing")]
                {
                    let count = |decision| {
                        results
                            .iter()
                            .filter(|result| result.decision() == decision)
                            .count()
                    };
                    policy_span.record("policy.granted_count", count(Decision::Grant));
                    policy_span.record("policy.denied_count", count(Decision::NotApplicable));
                    policy_span.record("policy.forbidden_count", count(Decision::Forbid));
                    policy_span
                        .record("policy.indeterminate_count", count(Decision::Indeterminate));
                }
                for (&index, result) in indices.iter().zip(results) {
                    let decision = result.decision();
                    #[cfg(feature = "tracing")]
                    emit_policy_event(policy.as_ref(), &result, phase);
                    decisions[index] = phase.reduce(decisions[index], decision);
                    children[index].push(result);
                }
            }
            pending.retain(|&index| decisions[index] != decisive);
            if pending.is_empty() {
                break;
            }
        }
        children
            .into_iter()
            .zip(decisions)
            .map(|(children, decision)| {
                combined(
                    PERMISSION_CHECKER_POLICY_TYPE,
                    CombineOp::DenyOverrides,
                    children,
                    decision,
                )
            })
            .collect()
    }

    pub(crate) async fn evaluate_phase_one(
        &self,
        phase: Phase,
        ctx: &EvalCtx<'_, D>,
        scope: &mut PhaseScope<'_>,
    ) -> PolicyEvalResult {
        let policies = match phase {
            Phase::Veto => &self.vetoes,
            Phase::Grant => &self.grants,
        };
        let mut children = Vec::with_capacity(policies.len());
        let mut decision = Decision::NotApplicable;
        for policy in policies {
            let inner = EvalCtx::new(
                ctx.session(),
                ctx.subject,
                ctx.action,
                ctx.resource,
                ctx.context,
                policy.policy_type(),
            );
            let result = policy.evaluate(&inner, scope).await;
            let result = inner.finish(result);
            #[cfg(feature = "tracing")]
            emit_policy_event(policy.as_ref(), &result, phase);
            decision = phase.reduce(decision, result.decision());
            children.push(result);
            if decision == phase.decisive() {
                break;
            }
        }
        combined(
            PERMISSION_CHECKER_POLICY_TYPE,
            CombineOp::DenyOverrides,
            children,
            decision,
        )
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(skip_all, fields(checker.name = self.name(), policy_count = self.grants.len() + self.vetoes.len(), outcome, policy.type)))]
    async fn evaluate_one(
        &self,
        session: &EvaluationSession,
        subject: &D::Subject,
        action: &D::Action,
        resource: &D::Resource,
        context: &D::Context,
    ) -> AccessEvaluation {
        let mut state = EvaluationState::default();
        let mut scope = PhaseScope {
            state: &mut state,
            item_indices: &[0],
            path: &[],
        };
        let ctx = EvalCtx::new(
            session,
            subject,
            action,
            resource,
            context,
            PERMISSION_CHECKER_POLICY_TYPE,
        );
        let veto = self.evaluate_phase_one(Phase::Veto, &ctx, &mut scope).await;
        let root = if veto.decision() == Decision::NotApplicable {
            let grant = self
                .evaluate_phase_one(Phase::Grant, &ctx, &mut scope)
                .await;
            let decision = grant.decision();
            let mut children = match veto {
                PolicyEvalResult::Combined { children, .. } => children,
                _ => unreachable!(),
            };
            let grant_children = match grant {
                PolicyEvalResult::Combined { children, .. } => children,
                _ => unreachable!(),
            };
            if children.is_empty() {
                children = grant_children;
            } else {
                children.extend(grant_children);
            }
            combined(
                PERMISSION_CHECKER_POLICY_TYPE,
                CombineOp::DenyOverrides,
                children,
                decision,
            )
        } else {
            veto
        };
        let evaluation = evaluation_from_tree(root);
        #[cfg(feature = "tracing")]
        {
            let (outcome, policy_type) = match &evaluation {
                AccessEvaluation::Granted { policy_type, .. } => {
                    ("granted", Some(policy_type.as_ref()))
                }
                AccessEvaluation::Denied { trace, .. } => (
                    "denied",
                    trace
                        .root()
                        .and_then(PolicyEvalResult::forbidden_leaf)
                        .map(|(name, _)| name),
                ),
                AccessEvaluation::Indeterminate { trace, .. } => (
                    "indeterminate",
                    trace
                        .root()
                        .and_then(PolicyEvalResult::indeterminate_leaf)
                        .map(|(name, _)| name),
                ),
            };
            tracing::Span::current().record("outcome", outcome);
            if let Some(policy_type) = policy_type {
                tracing::Span::current().record("policy.type", policy_type);
            }
        }
        evaluation
    }

    async fn evaluate_resources<'item>(
        &self,
        session: &EvaluationSession,
        subject: &D::Subject,
        action: &D::Action,
        context: &D::Context,
        items: &[PolicyBatchItem<'item, D>],
    ) -> Vec<AccessEvaluation> {
        if items.is_empty() {
            return Vec::new();
        }
        let batch = BatchEvalCtx::new(
            session,
            subject,
            action,
            context,
            items,
            PERMISSION_CHECKER_POLICY_TYPE,
        );
        let mut state = EvaluationState::default();
        let item_indices: Vec<_> = (0..items.len()).collect();
        let mut scope = PhaseScope {
            state: &mut state,
            item_indices: &item_indices,
            path: &[],
        };
        let veto_results = self.evaluate_phase(Phase::Veto, &batch, &mut scope).await;
        let grant_indices: Vec<_> = veto_results
            .iter()
            .enumerate()
            .filter_map(|(index, result)| {
                (result.decision() == Decision::NotApplicable).then_some(index)
            })
            .collect();
        let grant_items: Vec<_> = grant_indices
            .iter()
            .map(|&index| PolicyBatchItem {
                resource: items[index].resource,
            })
            .collect();
        let grant_ctx = BatchEvalCtx::new(
            session,
            subject,
            action,
            context,
            &grant_items,
            PERMISSION_CHECKER_POLICY_TYPE,
        );
        let mut scope = PhaseScope {
            state: &mut state,
            item_indices: &grant_indices,
            path: &[],
        };
        let grant_results = self
            .evaluate_phase(Phase::Grant, &grant_ctx, &mut scope)
            .await;
        let mut grants = grant_indices.into_iter().zip(grant_results).peekable();
        veto_results
            .into_iter()
            .enumerate()
            .map(|(index, veto)| {
                let decision = veto.decision();
                let mut children = match veto {
                    PolicyEvalResult::Combined { children, .. } => children,
                    _ => unreachable!(),
                };
                let decision = if grants
                    .peek()
                    .is_some_and(|(grant_index, _)| *grant_index == index)
                {
                    let (_, grant) = grants.next().expect("matching grant index");
                    let decision = grant.decision();
                    if let PolicyEvalResult::Combined {
                        children: grant_children,
                        ..
                    } = grant
                    {
                        children.extend(grant_children);
                    }
                    decision
                } else {
                    decision
                };
                evaluation_from_tree(combined(
                    PERMISSION_CHECKER_POLICY_TYPE,
                    CombineOp::DenyOverrides,
                    children,
                    decision,
                ))
            })
            .collect()
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(name = "evaluate_batch", skip_all, fields(checker.name = self.name(), policy_count = self.grants.len() + self.vetoes.len(), max_batch_size, item_count, granted_count, denied_count, indeterminate_count)))]
    async fn evaluate_batch_by<I, F>(
        &self,
        session: &EvaluationSession,
        subject: &D::Subject,
        action: &D::Action,
        context: &D::Context,
        resources: I,
        resource_of: F,
    ) -> Vec<(I::Item, AccessEvaluation)>
    where
        I: IntoIterator,
        F: for<'item> Fn(&'item I::Item) -> &'item D::Resource,
    {
        let resources: Vec<_> = resources.into_iter().collect();
        let items: Vec<_> = resources
            .iter()
            .map(|item| PolicyBatchItem {
                resource: resource_of(item),
            })
            .collect();
        let evaluations = self
            .evaluate_resources(session, subject, action, context, &items)
            .await;
        #[cfg(feature = "tracing")]
        {
            if let Some(size) = self.max_batch_size {
                tracing::Span::current().record("max_batch_size", size.get());
            }
            let granted = evaluations
                .iter()
                .filter(|result| result.is_granted())
                .count();
            let indeterminate = evaluations
                .iter()
                .filter(|result| result.is_indeterminate())
                .count();
            tracing::Span::current().record("item_count", evaluations.len());
            tracing::Span::current().record("granted_count", granted);
            tracing::Span::current().record("indeterminate_count", indeterminate);
            tracing::Span::current()
                .record("denied_count", evaluations.len() - granted - indeterminate);
        }
        resources.into_iter().zip(evaluations).collect()
    }
    async fn evaluate_batch<I>(
        &self,
        session: &EvaluationSession,
        subject: &D::Subject,
        action: &D::Action,
        context: &D::Context,
        resources: I,
    ) -> Vec<(I::Item, AccessEvaluation)>
    where
        I: IntoIterator,
        I::Item: Borrow<D::Resource>,
    {
        self.evaluate_batch_by(session, subject, action, context, resources, |item| {
            Borrow::<D::Resource>::borrow(item)
        })
        .await
    }
}

/// A request-bound evaluator for one checker, subject, action, context, and
/// evaluation session.
pub struct BoundEvaluator<'a, D: PolicyDomain> {
    checker: &'a PermissionChecker<D>,
    session: &'a EvaluationSession,
    subject: &'a D::Subject,
    action: &'a D::Action,
    context: &'a D::Context,
}

impl<'a, D: PolicyDomain> BoundEvaluator<'a, D> {
    /// Evaluates one resource.
    pub async fn check(&self, resource: &D::Resource) -> AccessEvaluation {
        self.checker
            .evaluate_one(
                self.session,
                self.subject,
                self.action,
                resource,
                self.context,
            )
            .await
    }

    /// Evaluates a batch of already-loaded resources, preserving input order.
    pub async fn evaluate<I>(&self, resources: I) -> Vec<(I::Item, AccessEvaluation)>
    where
        I: IntoIterator,
        I::Item: Borrow<D::Resource>,
    {
        self.checker
            .evaluate_batch(
                self.session,
                self.subject,
                self.action,
                self.context,
                resources,
            )
            .await
    }

    /// Evaluates a batch of caller-owned items by projecting each item to the
    /// resource used for authorization.
    ///
    /// Use this for list endpoints that carry wide database rows but authorize
    /// a narrower resource projection:
    ///
    /// ```rust,ignore
    /// let decisions = bound.evaluate_by(rows, |row| &row.authz_resource).await;
    /// ```
    pub async fn evaluate_by<I, F>(
        &self,
        items: I,
        resource_of: F,
    ) -> Vec<(I::Item, AccessEvaluation)>
    where
        I: IntoIterator,
        F: for<'item> Fn(&'item I::Item) -> &'item D::Resource,
    {
        self.checker
            .evaluate_batch_by(
                self.session,
                self.subject,
                self.action,
                self.context,
                items,
                resource_of,
            )
            .await
    }

    /// Returns only the resources granted by [`Self::evaluate`].
    ///
    /// Denied and indeterminate resources are both excluded. Use
    /// [`Self::evaluate`] and inspect each [`AccessEvaluation`] when callers
    /// must distinguish an authorization-data outage from an ordinary denial.
    pub async fn filter<I>(&self, resources: I) -> Vec<I::Item>
    where
        I: IntoIterator,
        I::Item: Borrow<D::Resource>,
    {
        self.evaluate(resources)
            .await
            .into_iter()
            .filter_map(|(item, evaluation)| evaluation.is_granted().then_some(item))
            .collect()
    }

    /// Returns only the caller-owned items granted by [`Self::evaluate_by`].
    ///
    /// The returned values are the original input items, not cloned projected
    /// resources. Denied and indeterminate items are both excluded; use
    /// [`Self::evaluate_by`] when callers must distinguish them.
    pub async fn filter_by<I, F>(&self, items: I, resource_of: F) -> Vec<I::Item>
    where
        I: IntoIterator,
        F: for<'item> Fn(&'item I::Item) -> &'item D::Resource,
    {
        self.evaluate_by(items, resource_of)
            .await
            .into_iter()
            .filter_map(|(item, evaluation)| evaluation.is_granted().then_some(item))
            .collect()
    }

    /// Returns granted resources, or all input evaluations if any is indeterminate.
    ///
    /// Definite denials are excluded. A failure that is superseded by a decisive
    /// grant does not fail the batch. No partial authorized list is returned.
    pub async fn try_filter<I>(&self, resources: I) -> Result<Vec<I::Item>, FilterError<I::Item>>
    where
        I: IntoIterator,
        I::Item: Borrow<D::Resource>,
    {
        Self::collect_authorized(self.evaluate(resources).await)
    }

    /// Like [`Self::try_filter`], projecting caller-owned items to their resources.
    ///
    /// On error, all original items and evaluations are retained in input order.
    pub async fn try_filter_by<I, F>(
        &self,
        items: I,
        resource_of: F,
    ) -> Result<Vec<I::Item>, FilterError<I::Item>>
    where
        I: IntoIterator,
        F: for<'item> Fn(&'item I::Item) -> &'item D::Resource,
    {
        Self::collect_authorized(self.evaluate_by(items, resource_of).await)
    }

    fn collect_authorized<T>(
        evaluations: Vec<(T, AccessEvaluation)>,
    ) -> Result<Vec<T>, FilterError<T>> {
        if evaluations
            .iter()
            .any(|(_, evaluation)| evaluation.is_indeterminate())
        {
            return Err(FilterError { evaluations });
        }
        Ok(evaluations
            .into_iter()
            .filter_map(|(item, evaluation)| evaluation.is_granted().then_some(item))
            .collect())
    }

    /// Looks up one candidate page, hydrates it, and returns authorized
    /// resources from that page.
    ///
    /// Indeterminate resources are excluded exactly like denials, so this
    /// method can return `Ok` with a shorter or empty page during an
    /// authorization-data outage. Drive the lookup and hydration steps
    /// directly, then use [`Self::evaluate`] if the caller must surface that
    /// distinction.
    pub async fn lookup_page<L, H>(
        &self,
        lookup: &L,
        hydrator: &H,
        cursor: Option<&[u8]>,
        limit: NonZeroUsize,
    ) -> Result<LookupAuthorizedPage<D::Resource>, LookupAuthorizedError<L::Error, H::Error>>
    where
        L: LookupSource<D>,
        H: Hydrator<L::Id, Resource = D::Resource>,
    {
        let page = self
            .lookup_candidates(lookup, hydrator, cursor, limit)
            .await?;
        Ok(LookupAuthorizedPage {
            resources: self.filter(page.resources).await,
            next_cursor: page.next_cursor,
        })
    }

    /// Looks up and hydrates one candidate page, failing if authorization is indeterminate.
    ///
    /// Definite denials are excluded. On authorization failure, the error retains
    /// all hydrated resources and evaluations. No next cursor is returned: retry
    /// the same input cursor after recovery rather than silently skipping a page.
    pub async fn try_lookup_page<L, H>(
        &self,
        lookup: &L,
        hydrator: &H,
        cursor: Option<&[u8]>,
        limit: NonZeroUsize,
    ) -> Result<
        LookupAuthorizedPage<D::Resource>,
        LookupAuthorizedError<L::Error, H::Error, D::Resource>,
    >
    where
        L: LookupSource<D>,
        H: Hydrator<L::Id, Resource = D::Resource>,
    {
        let page = self
            .lookup_candidates(lookup, hydrator, cursor, limit)
            .await?;
        Ok(LookupAuthorizedPage {
            resources: self
                .try_filter(page.resources)
                .await
                .map_err(LookupAuthorizedError::Evaluation)?,
            next_cursor: page.next_cursor,
        })
    }

    async fn lookup_candidates<L, H, R>(
        &self,
        lookup: &L,
        hydrator: &H,
        cursor: Option<&[u8]>,
        limit: NonZeroUsize,
    ) -> Result<LookupAuthorizedPage<D::Resource>, LookupAuthorizedError<L::Error, H::Error, R>>
    where
        L: LookupSource<D>,
        H: Hydrator<L::Id, Resource = D::Resource>,
    {
        #[cfg(feature = "tracing")]
        let lookup_span = tracing::debug_span!(
            "gatehouse.lookup",
            lookup.limit = limit.get(),
            lookup.has_cursor = cursor.is_some(),
        );
        let page = lookup.lookup_page(self.subject, self.action, self.context, cursor, limit);
        #[cfg(feature = "tracing")]
        let page = page.instrument(lookup_span);
        let page = page.await.map_err(LookupAuthorizedError::Lookup)?;

        if cursor.is_some() && page.next_cursor.as_deref() == cursor {
            return Err(LookupAuthorizedError::LookupCursorStuck);
        }

        if page.ids.is_empty() {
            return Ok(LookupAuthorizedPage {
                resources: Vec::new(),
                next_cursor: page.next_cursor,
            });
        }

        #[cfg(feature = "tracing")]
        let hydrate_span = tracing::debug_span!(
            "gatehouse.hydrate",
            hydrate.candidate_count = page.ids.len()
        );
        let hydrated = hydrator.hydrate(&page.ids);
        #[cfg(feature = "tracing")]
        let hydrated = hydrated.instrument(hydrate_span);
        let hydrated = hydrated.await.map_err(LookupAuthorizedError::Hydrate)?;

        if hydrated.len() != page.ids.len() {
            return Err(LookupAuthorizedError::HydratorContractViolation {
                expected: page.ids.len(),
                actual: hydrated.len(),
            });
        }

        let resources = hydrated.into_iter().flatten().collect::<Vec<_>>();
        Ok(LookupAuthorizedPage {
            resources,
            next_cursor: page.next_cursor,
        })
    }
}

fn evaluation_from_tree(tree: PolicyEvalResult) -> AccessEvaluation {
    let decision = tree.decision();
    match decision {
        Decision::Grant => {
            let (policy_type, reason) = winning_grant(&tree)
                .unwrap_or((Cow::Borrowed(PERMISSION_CHECKER_POLICY_TYPE), None));
            AccessEvaluation::Granted {
                policy_type,
                reason,
                trace: EvalTrace::with_root(tree),
            }
        }
        Decision::Forbid => {
            let reason = tree
                .forbidden_leaf()
                .map(|(name, reason)| match reason {
                    Some(reason) => format!("Forbidden by {name}: {reason}"),
                    None => format!("Forbidden by {name}"),
                })
                .unwrap_or_else(|| "Access forbidden".into());
            AccessEvaluation::Denied {
                reason,
                trace: EvalTrace::with_root(tree),
            }
        }
        Decision::Indeterminate => {
            let reason = tree
                .indeterminate_leaf()
                .map(|(name, reason)| format!("Could not evaluate {name}: {reason}"))
                .unwrap_or_else(|| "Authorization could not be evaluated".into());
            AccessEvaluation::Indeterminate {
                reason,
                trace: EvalTrace::with_root(tree),
            }
        }
        _ => AccessEvaluation::Denied {
            reason: if matches!(&tree, PolicyEvalResult::Combined { children, .. } if children.is_empty())
            {
                "No policies configured".into()
            } else {
                "All policies denied access".into()
            },
            trace: EvalTrace::with_root(tree),
        },
    }
}
fn winning_grant(tree: &PolicyEvalResult) -> Option<(Cow<'static, str>, Option<String>)> {
    match tree {
        PolicyEvalResult::Combined { children, .. } => children
            .iter()
            .find(|child| child.is_granted())
            .map(|child| {
                let policy_type = match child {
                    PolicyEvalResult::Granted { policy_type, .. }
                    | PolicyEvalResult::NotApplicable { policy_type, .. }
                    | PolicyEvalResult::Forbidden { policy_type, .. }
                    | PolicyEvalResult::Indeterminate { policy_type, .. }
                    | PolicyEvalResult::Combined { policy_type, .. } => policy_type.clone(),
                };
                (policy_type, child.reason())
            }),
        _ => None,
    }
}
#[cfg(feature = "tracing")]
fn emit_policy_event<D: PolicyDomain>(
    policy: &dyn PhasePolicy<D>,
    result: &PolicyEvalResult,
    phase: Phase,
) {
    let metadata = policy.security_rule();
    let policy_type = policy.policy_type();
    let reason = result.reason();
    let event_outcome = match result.decision() {
        Decision::Grant => "success",
        Decision::Indeterminate => "unknown",
        _ => "failure",
    };
    let effect = phase_effect(phase);
    tracing::trace!(target: "gatehouse::security", {
        security_rule.name = metadata.name().unwrap_or(policy_type.as_ref()),
        security_rule.category = metadata.category().unwrap_or(DEFAULT_SECURITY_RULE_CATEGORY),
        security_rule.description = metadata.description(), security_rule.reference = metadata.reference(),
        security_rule.ruleset.name = metadata.ruleset_name().unwrap_or(PERMISSION_CHECKER_POLICY_TYPE),
        security_rule.uuid = metadata.uuid(), security_rule.version = metadata.version(), security_rule.license = metadata.license(),
        event.outcome = event_outcome, policy.type = policy_type.as_ref(), policy.effect = effect, policy.result.reason = reason.as_deref(),
        }, "Security rule evaluated");
}

#[cfg(feature = "tracing")]
fn phase_effect(phase: Phase) -> &'static str {
    match phase {
        Phase::Grant => "allow",
        Phase::Veto => "deny",
    }
}
