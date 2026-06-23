use crate::{
    AccessEvaluation, BatchEvalCtx, CombineOp, Effect, EvalCtx, EvalTrace, EvaluationSession,
    Hydrator, LookupAuthorizedError, LookupAuthorizedPage, LookupSource, Policy, PolicyBatchItem,
    PolicyDomain, PolicyEvalResult, DEFAULT_SECURITY_RULE_CATEGORY, PERMISSION_CHECKER_POLICY_TYPE,
};
use std::borrow::{Borrow, Cow};
use std::num::NonZeroUsize;
use std::sync::Arc;
use tracing::Instrument;

fn forbid_summary(policy_type: &str, reason: Option<&str>) -> String {
    match reason {
        Some(reason) => format!("Forbidden by {policy_type}: {reason}"),
        None => format!("Forbidden by {policy_type}"),
    }
}

const FORBID_EFFECT_GRANT_REASON: &str =
    "Forbid-effect policy returned a grant; treated as not applicable";

fn checker_root(children: Vec<PolicyEvalResult>, outcome: bool) -> PolicyEvalResult {
    PolicyEvalResult::Combined {
        policy_type: std::borrow::Cow::Borrowed(PERMISSION_CHECKER_POLICY_TYPE),
        operation: CombineOp::DenyOverrides,
        children,
        outcome,
    }
}

/// A policy stack for one [`PolicyDomain`].
pub struct PermissionChecker<D: PolicyDomain> {
    name: Option<std::borrow::Cow<'static, str>>,
    policies: Vec<Arc<dyn Policy<D>>>,
    effects: Vec<Effect>,
    veto_capable_count: usize,
    max_batch_size: Option<NonZeroUsize>,
}

impl<D: PolicyDomain> Clone for PermissionChecker<D> {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            policies: self.policies.clone(),
            effects: self.effects.clone(),
            veto_capable_count: self.veto_capable_count,
            max_batch_size: self.max_batch_size,
        }
    }
}

impl<D: PolicyDomain> Default for PermissionChecker<D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: PolicyDomain> PermissionChecker<D> {
    /// Creates a new checker with no policies and no name.
    pub fn new() -> Self {
        Self {
            name: None,
            policies: Vec::new(),
            effects: Vec::new(),
            veto_capable_count: 0,
            max_batch_size: None,
        }
    }

    /// Creates a new checker tagged with a name for telemetry.
    pub fn named(name: impl Into<std::borrow::Cow<'static, str>>) -> Self {
        Self {
            name: Some(name.into()),
            policies: Vec::new(),
            effects: Vec::new(),
            veto_capable_count: 0,
            max_batch_size: None,
        }
    }

    /// Returns the checker name if set.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Sets the maximum number of pending items passed to one policy batch.
    pub fn with_max_batch_size(mut self, max_batch_size: NonZeroUsize) -> Self {
        self.max_batch_size = Some(max_batch_size);
        self
    }

    /// Adds a policy to the checker.
    ///
    /// Veto-capable policies are scheduled ahead of allow-only policies so a
    /// forbid is always observed before the grant short-circuit.
    pub fn add_policy<P: Policy<D> + 'static>(&mut self, policy: P) {
        let effect = policy.effect();
        if effect.can_forbid() {
            self.policies
                .insert(self.veto_capable_count, Arc::new(policy));
            self.effects.insert(self.veto_capable_count, effect);
            self.veto_capable_count += 1;
        } else {
            self.policies.push(Arc::new(policy));
            self.effects.push(effect);
        }
    }

    /// Adds a hand-written policy that can actively forbid access even if it
    /// does not override [`Policy::effect`].
    pub fn add_forbid_policy<P: Policy<D> + 'static>(&mut self, policy: P) {
        self.policies
            .insert(self.veto_capable_count, Arc::new(policy));
        self.effects
            .insert(self.veto_capable_count, Effect::AllowOrForbid);
        self.veto_capable_count += 1;
    }

    /// Binds a request-scoped evaluation session and shared inputs to this
    /// checker.
    ///
    /// All evaluations require an explicit session. Fact-free callers can pass
    /// [`EvaluationSession::empty`], while fact-backed paths should pass a
    /// request session created from [`crate::FactRegistry::session`].
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

    fn declared_effect(&self, policy_index: usize) -> Effect {
        self.effects
            .get(policy_index)
            .copied()
            .unwrap_or(Effect::Allow)
    }

    pub(crate) fn aggregate_effect(&self) -> Effect {
        let can_grant = self.effects.iter().any(|effect| effect.can_grant());
        let can_forbid = self.effects.iter().any(|effect| effect.can_forbid());
        Effect::from_capabilities(can_grant, can_forbid)
    }

    #[tracing::instrument(skip_all, fields(checker.name = tracing::field::Empty, policy_count = self.policies.len(), outcome = tracing::field::Empty, policy.type = tracing::field::Empty))]
    async fn evaluate_one(
        &self,
        session: &EvaluationSession,
        subject: &D::Subject,
        action: &D::Action,
        resource: &D::Resource,
        context: &D::Context,
    ) -> AccessEvaluation {
        if let Some(name) = self.name.as_deref() {
            tracing::Span::current().record("checker.name", name);
        }
        if self.policies.is_empty() {
            tracing::Span::current().record("outcome", "denied");
            let result = PolicyEvalResult::not_applicable(
                PERMISSION_CHECKER_POLICY_TYPE,
                "No policies configured",
            );

            return AccessEvaluation::Denied {
                trace: EvalTrace::with_root(result),
                reason: "No policies configured".to_string(),
            };
        }

        let mut policy_results = Vec::with_capacity(self.policies.len());
        let mut first_grant: Option<(Cow<'static, str>, Option<String>)> = None;

        for (policy_index, policy) in self.policies.iter().enumerate() {
            let declared_effect = self.declared_effect(policy_index);
            let ctx = EvalCtx {
                session,
                subject,
                action,
                resource,
                context,
                policy_type: policy.policy_type(),
            };
            let mut result = policy.evaluate(&ctx).await;
            if declared_effect == Effect::Forbid && result.is_granted() {
                tracing::warn!(
                    policy.type = ctx.policy_type.as_ref(),
                    "{FORBID_EFFECT_GRANT_REASON}"
                );
                result = PolicyEvalResult::not_applicable(
                    ctx.policy_type.clone(),
                    FORBID_EFFECT_GRANT_REASON,
                );
            }

            let result_passes = result.is_granted();
            let result_forbids = result.is_forbidden();
            let policy_type_str: &str = ctx.policy_type.as_ref();
            let metadata = policy.security_rule();
            let reason = result.reason();
            let reason_str = reason.as_deref();
            let rule_name = metadata.name().unwrap_or(policy_type_str);
            let category = metadata
                .category()
                .unwrap_or(DEFAULT_SECURITY_RULE_CATEGORY);
            let ruleset_name = metadata
                .ruleset_name()
                .unwrap_or(PERMISSION_CHECKER_POLICY_TYPE);
            let event_outcome = if result_passes { "success" } else { "failure" };
            let policy_effect = declared_effect.telemetry_label();

            tracing::trace!(
                target: "gatehouse::security",
                {
                    security_rule.name = rule_name,
                    security_rule.category = category,
                    security_rule.description = metadata.description(),
                    security_rule.reference = metadata.reference(),
                    security_rule.ruleset.name = ruleset_name,
                    security_rule.uuid = metadata.uuid(),
                    security_rule.version = metadata.version(),
                    security_rule.license = metadata.license(),
                    event.outcome = event_outcome,
                    policy.type = policy_type_str,
                    policy.effect = policy_effect,
                    policy.result.reason = reason_str,
                },
                "Security rule evaluated"
            );

            let forbidden = result_forbids.then(|| {
                result
                    .forbidden_leaf()
                    .map(|(policy_type, reason)| {
                        (policy_type.to_string(), reason.map(str::to_owned))
                    })
                    .unwrap_or_else(|| (policy_type_str.to_string(), reason.clone()))
            });

            policy_results.push(result);

            if let Some((forbid_policy_type, forbid_reason)) = forbidden {
                tracing::Span::current().record("outcome", "denied");
                tracing::Span::current().record("policy.type", forbid_policy_type.as_str());
                let combined = checker_root(policy_results, false);
                return AccessEvaluation::Denied {
                    trace: EvalTrace::with_root(combined),
                    reason: forbid_summary(&forbid_policy_type, forbid_reason.as_deref()),
                };
            }

            if result_passes {
                first_grant.get_or_insert_with(|| (ctx.policy_type.clone(), reason));
            }

            if policy_index + 1 >= self.veto_capable_count {
                if let Some((policy_type, reason)) = first_grant.take() {
                    tracing::Span::current().record("outcome", "granted");
                    tracing::Span::current().record("policy.type", policy_type.as_ref());
                    let combined = checker_root(policy_results, true);
                    return AccessEvaluation::Granted {
                        policy_type,
                        reason,
                        trace: EvalTrace::with_root(combined),
                    };
                }
            }
        }

        tracing::Span::current().record("outcome", "denied");
        let combined = checker_root(policy_results, false);
        AccessEvaluation::Denied {
            trace: EvalTrace::with_root(combined),
            reason: "All policies denied access".to_string(),
        }
    }

    #[tracing::instrument(name = "evaluate_batch", skip_all, fields(checker.name = tracing::field::Empty, item_count, granted_count, denied_count, max_batch_size, policy_count = self.policies.len()))]
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
        let items: Vec<I::Item> = resources.into_iter().collect();
        let item_count = items.len();
        if let Some(name) = self.name.as_deref() {
            tracing::Span::current().record("checker.name", name);
        }
        tracing::Span::current().record("item_count", item_count);
        if let Some(max_batch_size) = self.max_batch_size {
            tracing::Span::current().record("max_batch_size", max_batch_size.get());
        }

        let mut traces = vec![Vec::new(); item_count];
        let mut evaluations: Vec<Option<AccessEvaluation>> = vec![None; item_count];

        if self.policies.is_empty() {
            let results = items
                .into_iter()
                .map(|item| {
                    let result = PolicyEvalResult::not_applicable(
                        PERMISSION_CHECKER_POLICY_TYPE,
                        "No policies configured",
                    );
                    (
                        item,
                        AccessEvaluation::Denied {
                            trace: EvalTrace::with_root(result),
                            reason: "No policies configured".to_string(),
                        },
                    )
                })
                .collect();
            tracing::Span::current().record("granted_count", 0usize);
            tracing::Span::current().record("denied_count", item_count);
            return results;
        }

        let item_parts = items
            .iter()
            .map(|item| PolicyBatchItem::<D> {
                resource: resource_of(item),
            })
            .collect::<Vec<_>>();

        let mut pending: Vec<usize> = (0..item_count).collect();
        let mut first_grants: Vec<Option<(Cow<'static, str>, Option<String>)>> =
            vec![None; item_count];

        for (policy_index, policy) in self.policies.iter().enumerate() {
            if pending.is_empty() {
                break;
            }

            let declared_effect = self.declared_effect(policy_index);
            let policy_type = policy.policy_type();
            let policy_type_str: &str = policy_type.as_ref();
            let mut still_pending = Vec::new();
            let chunk_size = self
                .max_batch_size
                .map_or(pending.len(), NonZeroUsize::get)
                .max(1);
            let chunk_count = pending.len().div_ceil(chunk_size);

            for (chunk_index, pending_chunk) in pending.chunks(chunk_size).enumerate() {
                let policy_span = tracing::debug_span!(
                    "gatehouse.batch_policy",
                    policy.type = policy_type_str,
                    policy.effect = declared_effect.telemetry_label(),
                    policy.pending_count = pending_chunk.len(),
                    policy.chunk_index = chunk_index,
                    policy.chunk_count = chunk_count,
                    policy.granted_count = tracing::field::Empty,
                    policy.denied_count = tracing::field::Empty,
                    policy.forbidden_count = tracing::field::Empty,
                );
                let mut policy_granted_count = 0usize;
                let mut policy_denied_count = 0usize;
                let mut policy_forbidden_count = 0usize;
                let mut contract_violation_count = 0usize;
                let batch_items = pending_chunk
                    .iter()
                    .map(|&index| PolicyBatchItem {
                        resource: item_parts[index].resource,
                    })
                    .collect::<Vec<_>>();

                let batch_ctx = BatchEvalCtx {
                    session,
                    subject,
                    action,
                    context,
                    items: &batch_items,
                    policy_type: policy_type.clone(),
                };
                let policy_results = policy
                    .evaluate_batch(&batch_ctx)
                    .instrument(policy_span.clone())
                    .await;

                if policy_results.len() != pending_chunk.len() {
                    for &index in pending_chunk {
                        policy_denied_count += 1;
                        let policy_result = PolicyEvalResult::not_applicable(
                            policy_type.clone(),
                            "Policy batch result count did not match input count",
                        );
                        traces[index].push(policy_result);
                        let combined = checker_root(std::mem::take(&mut traces[index]), false);
                        evaluations[index] = Some(AccessEvaluation::Denied {
                            trace: EvalTrace::with_root(combined),
                            reason: "Policy batch result count did not match input count"
                                .to_string(),
                        });
                    }
                    policy_span.record("policy.granted_count", policy_granted_count);
                    policy_span.record("policy.denied_count", policy_denied_count);
                    policy_span.record("policy.forbidden_count", policy_forbidden_count);
                    continue;
                }

                for (&index, result) in pending_chunk.iter().zip(policy_results) {
                    let mut result = result;
                    if declared_effect == Effect::Forbid && result.is_granted() {
                        contract_violation_count += 1;
                        result = PolicyEvalResult::not_applicable(
                            policy_type.clone(),
                            FORBID_EFFECT_GRANT_REASON,
                        );
                    }
                    let result_passes = result.is_granted();
                    let result_forbids = result.is_forbidden();
                    let reason = result.reason();
                    let forbidden = result_forbids.then(|| {
                        result
                            .forbidden_leaf()
                            .map(|(policy_type, reason)| {
                                (policy_type.to_string(), reason.map(str::to_owned))
                            })
                            .unwrap_or_else(|| (policy_type_str.to_string(), reason.clone()))
                    });

                    traces[index].push(result);

                    if let Some((forbid_policy_type, forbid_reason)) = forbidden {
                        policy_forbidden_count += 1;
                        let combined = checker_root(std::mem::take(&mut traces[index]), false);
                        evaluations[index] = Some(AccessEvaluation::Denied {
                            trace: EvalTrace::with_root(combined),
                            reason: forbid_summary(&forbid_policy_type, forbid_reason.as_deref()),
                        });
                    } else {
                        if result_passes {
                            policy_granted_count += 1;
                            first_grants[index]
                                .get_or_insert_with(|| (policy_type.clone(), reason));
                        } else {
                            policy_denied_count += 1;
                        }

                        if policy_index + 1 >= self.veto_capable_count {
                            if let Some((grant_policy_type, grant_reason)) =
                                first_grants[index].take()
                            {
                                let combined =
                                    checker_root(std::mem::take(&mut traces[index]), true);
                                evaluations[index] = Some(AccessEvaluation::Granted {
                                    policy_type: grant_policy_type,
                                    reason: grant_reason,
                                    trace: EvalTrace::with_root(combined),
                                });
                            } else {
                                still_pending.push(index);
                            }
                        } else {
                            still_pending.push(index);
                        }
                    }
                }
                if contract_violation_count > 0 {
                    tracing::warn!(
                        policy.type = policy_type_str,
                        item_count = contract_violation_count,
                        "{FORBID_EFFECT_GRANT_REASON}"
                    );
                }
                policy_span.record("policy.granted_count", policy_granted_count);
                policy_span.record("policy.denied_count", policy_denied_count);
                policy_span.record("policy.forbidden_count", policy_forbidden_count);
            }
            pending = still_pending;
        }

        for index in pending {
            let combined = checker_root(std::mem::take(&mut traces[index]), false);
            evaluations[index] = Some(AccessEvaluation::Denied {
                trace: EvalTrace::with_root(combined),
                reason: "All policies denied access".to_string(),
            });
        }

        drop(item_parts);

        let mut granted_count = 0usize;
        let results = items
            .into_iter()
            .zip(evaluations.into_iter())
            .map(|(item, evaluation)| {
                let evaluation = evaluation.unwrap_or_else(|| {
                    let result = PolicyEvalResult::not_applicable(
                        PERMISSION_CHECKER_POLICY_TYPE,
                        "Batch item was not evaluated",
                    );
                    AccessEvaluation::Denied {
                        trace: EvalTrace::with_root(result),
                        reason: "Batch item was not evaluated".to_string(),
                    }
                });
                if evaluation.is_granted() {
                    granted_count += 1;
                }
                (item, evaluation)
            })
            .collect::<Vec<_>>();
        let denied_count = item_count - granted_count;
        tracing::Span::current().record("granted_count", granted_count);
        tracing::Span::current().record("denied_count", denied_count);
        results
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
    /// resources.
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

    /// Looks up one candidate page, hydrates it, and returns authorized
    /// resources from that page.
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
        let lookup_span = tracing::debug_span!(
            "gatehouse.lookup",
            lookup.limit = limit.get(),
            lookup.has_cursor = cursor.is_some(),
        );
        let page = lookup
            .lookup_page(self.subject, self.action, self.context, cursor, limit)
            .instrument(lookup_span)
            .await
            .map_err(LookupAuthorizedError::Lookup)?;

        if cursor.is_some() && page.next_cursor.as_deref() == cursor {
            return Err(LookupAuthorizedError::LookupCursorStuck);
        }

        if page.ids.is_empty() {
            return Ok(LookupAuthorizedPage {
                resources: Vec::new(),
                next_cursor: page.next_cursor,
            });
        }

        let hydrate_span = tracing::debug_span!(
            "gatehouse.hydrate",
            hydrate.candidate_count = page.ids.len()
        );
        let hydrated = hydrator
            .hydrate(&page.ids)
            .instrument(hydrate_span)
            .await
            .map_err(LookupAuthorizedError::Hydrate)?;

        if hydrated.len() != page.ids.len() {
            return Err(LookupAuthorizedError::HydratorContractViolation {
                expected: page.ids.len(),
                actual: hydrated.len(),
            });
        }

        let resources = hydrated.into_iter().flatten().collect::<Vec<_>>();
        let authorized = self.filter(resources).await;

        Ok(LookupAuthorizedPage {
            resources: authorized,
            next_cursor: page.next_cursor,
        })
    }
}
