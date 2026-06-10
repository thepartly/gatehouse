use crate::{
    AccessEvaluation, BatchEvalCtx, CombineOp, Effect, EvalCtx, EvalTrace, EvaluationSession,
    Hydrator, LookupAuthorizedError, LookupAuthorizedPage, LookupSource, Policy, PolicyBatchItem,
    PolicyEvalResult, DEFAULT_SECURITY_RULE_CATEGORY, PERMISSION_CHECKER_POLICY_TYPE,
};
use std::num::NonZeroUsize;
use std::sync::Arc;
use tracing::Instrument;

/// Builds the top-level denial reason for a forbid, naming the policy that
/// vetoed the request so the summary is actionable without opening the trace.
fn forbid_summary(policy_type: &str, reason: Option<&str>) -> String {
    match reason {
        Some(reason) => format!("Forbidden by {policy_type}: {reason}"),
        None => format!("Forbidden by {policy_type}"),
    }
}

/// Leaf reason recorded when a deny-declared policy violates its contract by
/// returning a grant; the checker fails closed and treats the result as not
/// applicable. See [`Policy::effect`].
const DENY_EFFECT_GRANT_REASON: &str =
    "Deny-effect policy returned a grant; treated as not applicable";

/// Builds the checker's root trace node: a deny-overrides combine over the
/// policy results evaluated so far.
fn checker_root(children: Vec<PolicyEvalResult>, outcome: bool) -> PolicyEvalResult {
    PolicyEvalResult::Combined {
        policy_type: std::borrow::Cow::Borrowed(PERMISSION_CHECKER_POLICY_TYPE),
        operation: CombineOp::DenyOverrides,
        children,
        outcome,
    }
}

/// A container for multiple policies, combined with fixed
/// **deny-overrides** semantics:
///
/// 1. any policy that **forbids** ([`PolicyEvalResult::Forbidden`], produced
///    by [`crate::Effect::Deny`] policies whose predicate matches) denies the
///    request, overriding every grant;
/// 2. otherwise any policy that grants, grants (OR semantics, short-circuits
///    on the first grant);
/// 3. otherwise the request is denied (default deny).
///
/// Policies declaring [`crate::Effect::Deny`] are evaluated before allow
/// policies so a veto is always observed before the grant short-circuit.
/// The semantics are fixed — there is no combining-algorithm knob — and the
/// effect is declared on the policy itself, so a policy's behaviour is
/// readable in isolation.
///
/// **Important**: if no policies are added, access is always denied.
///
/// # One checker per resource type
///
/// `PermissionChecker` is parameterised by `Resource` (the `R` generic).
/// Every policy in the checker sees the same `R`, so the idiomatic shape is
/// **one checker per resource type**: a `PermissionChecker<User, Document,
/// ReadAction, Ctx>` for documents, a separate `PermissionChecker<User,
/// Invoice, InvoiceAction, Ctx>` for invoices, and so on.
///
/// The anti-pattern is a single mega-checker whose `R` is a tag enum:
///
/// ```ignore
/// // Don't do this:
/// enum BillingResource { Event, Invoice, Product }
///
/// async fn evaluate(&self, ctx: &EvalCtx<'_, _, BillingResource, _, _>) -> PolicyEvalResult {
///     if !matches!(ctx.resource, BillingResource::Event) {
///         return ctx.deny("resource mismatch");   // tag dispatch in every policy
///     }
///     // ... real per-event logic, with the actual event data fished out of `ctx.context`
/// }
/// ```
///
/// That shape forces every policy to start with a tag discriminator and
/// pushes the per-instance data into `Context`, which makes
/// `LookupSource` / `Hydrator` and batch APIs awkward — the hydrator can
/// only produce tag values, not the real resources. If you find a policy
/// opening with `if !matches!(ctx.resource, ::X)`, the type system is
/// asking to do that dispatch for you: split into per-resource checkers
/// and let `R` carry the instance data.
///
/// Cross-cutting policies that apply to multiple resource types (a global
/// admin override, for example) can be implemented once as a generic
/// `Policy<S, R, A, C>` and added to each per-resource checker, or be
/// expressed as separate [`crate::DelegatingPolicy`] children.
///
/// Projects with many resource types typically end up wrapping their
/// per-resource checkers in a thin dispatching service trait or macro —
/// `MyAuthz::check::<R, A>(subject, action, resource, ctx)` style — so
/// call sites don't have to thread the right checker through manually.
/// That organizational layer is intentionally out of scope for gatehouse:
/// downstream patterns vary widely (typed-state, trait-object registries,
/// proc-macro builders) and prescribing one shape would lock in a
/// concrete dispatching style for every consumer. Build it in your own
/// codebase against gatehouse's primitives.
///
/// # Modeling list/scope endpoints
///
/// The "one checker per resource type" recipe maps cleanly onto per-item
/// authorization ("can this user view *this* invoice?"). List and scope
/// endpoints ("can this user list invoices in *this org*?") push back:
/// there is no single resource instance, and the authorization predicate
/// often runs against a scope (an organization, a project, a tenant).
///
/// Resist the temptation to widen the per-item checker's `R` into an
/// enum like `Resource { Item { id }, Listing { org_id } }` — that
/// reintroduces the tag-dispatch smell inside every policy. The cleaner
/// shape is **two checkers, one per concern**:
///
/// ```ignore
/// // Scope/list authorization: "can this user list within this scope?"
/// type InvoiceScopeChecker =
///     PermissionChecker<User, OrgScope, ListInvoicesAction, RequestCtx>;
///
/// // Per-item authorization: "can this user view this specific invoice?"
/// type InvoiceItemChecker =
///     PermissionChecker<User, Invoice, ViewInvoiceAction, RequestCtx>;
///
/// async fn list_invoices(
///     scope_checker: &InvoiceScopeChecker,
///     item_checker: &InvoiceItemChecker,
///     user: &User,
///     org: &OrgScope,
///     ctx: &RequestCtx,
///     session: &EvaluationSession,
///     lookup: &impl LookupSource<Subject = User, Id = InvoiceId>,
///     hydrator: &impl Hydrator<InvoiceId, Resource = Invoice>,
/// ) -> Result<Vec<Invoice>, ListError> {
///     // 1. Coarse gate: may the user list anything in this scope at all?
///     scope_checker
///         .check(user, &ListInvoicesAction, org, ctx)
///         .await
///         .to_result(|reason| ListError::Forbidden(reason.into()))?;
///
///     // 2. Per-item enumeration: hydrate candidates, route through the
///     //    item checker. Lookup is bounded by what its source enumerates,
///     //    so the candidate set is already scoped; the item checker
///     //    applies any remaining axes (sharing, admin override, etc).
///     item_checker
///         .lookup_authorized(
///             session, user, &ViewInvoiceAction, ctx,
///             lookup, page_size, hydrator,
///         )
///         .await
///         .map_err(ListError::from)
/// }
/// ```
///
/// Two checkers, two clear concerns, no tag dispatch. The scope check is
/// a single point evaluation (one row in the audit trail); the per-item
/// pass produces one trace per visible item. If your scope predicate is
/// trivial (everyone can list within their own org), you can drop the
/// scope checker entirely and rely on the lookup source's `WHERE
/// org_id = ?` filter — the per-item checker still validates each
/// hydrated row, so authorization is not smeared into the data layer.
#[derive(Clone)]
pub struct PermissionChecker<S, R, A, C> {
    name: Option<std::borrow::Cow<'static, str>>,
    /// Policies in evaluation order: deny-effect policies first, then allow
    /// policies, each group in registration order. [`Self::add_policy`]
    /// maintains this invariant using the policy's declared
    /// [`Policy::effect`], so evaluation iterates this list directly with no
    /// per-call partitioning. Deny-first scheduling is what makes
    /// deny-overrides deterministic: every policy that can veto runs before
    /// the allow phase, where a grant short-circuits the evaluation.
    policies: Vec<Arc<dyn Policy<S, R, A, C>>>,
    /// Number of deny-effect policies at the front of `policies`.
    deny_count: usize,
    max_batch_size: Option<NonZeroUsize>,
}

impl<S, R, A, C> Default for PermissionChecker<S, R, A, C>
where
    S: Sync,
    R: Sync,
    A: Sync,
    C: Sync,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<S, R, A, C> PermissionChecker<S, R, A, C>
where
    S: Sync,
    R: Sync,
    A: Sync,
    C: Sync,
{
    /// Creates a new `PermissionChecker` with no policies and no name.
    pub fn new() -> Self {
        Self {
            name: None,
            policies: Vec::new(),
            deny_count: 0,
            max_batch_size: None,
        }
    }

    /// Creates a new `PermissionChecker` tagged with a name.
    ///
    /// The name is recorded on the `evaluate_in_session` /
    /// `evaluate_batch_in_session_*` tracing spans as `checker.name`, so
    /// audit pipelines that route to multiple checkers (an `InvoiceChecker`
    /// alongside a `ProductChecker`, for example) can disambiguate which
    /// checker produced each evaluation when policy names are shared.
    ///
    /// `name` accepts `&'static str` (zero-allocation), `String`, or any
    /// `Cow<'static, str>`-convertible value.
    pub fn named(name: impl Into<std::borrow::Cow<'static, str>>) -> Self {
        Self {
            name: Some(name.into()),
            policies: Vec::new(),
            deny_count: 0,
            max_batch_size: None,
        }
    }

    /// Returns the checker's name if one was set via [`Self::named`].
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Sets the maximum number of pending items passed to a policy batch call.
    ///
    /// By default, batch evaluation passes all pending items to each policy in a
    /// single call. Configure this when backend limits, query planner behavior,
    /// or remote service constraints require smaller chunks.
    pub fn with_max_batch_size(mut self, max_batch_size: NonZeroUsize) -> Self {
        self.max_batch_size = Some(max_batch_size);
        self
    }

    /// Adds a policy to the checker.
    ///
    /// The policy's [`Policy::effect`] is read once here: deny-effect
    /// policies are scheduled ahead of allow policies so a veto is always
    /// observed before the grant short-circuit (see the type-level docs).
    /// Within each group, registration order is preserved.
    ///
    /// # Arguments
    ///
    /// * `policy` - A type implementing [`Policy`]. It is stored as an `Arc` for shared ownership.
    pub fn add_policy<P: Policy<S, R, A, C> + 'static>(&mut self, policy: P) {
        if policy.effect() == Effect::Deny {
            self.policies.insert(self.deny_count, Arc::new(policy));
            self.deny_count += 1;
        } else {
            self.policies.push(Arc::new(policy));
        }
    }

    /// The effect a policy declared when it was added, derived from its
    /// position in the deny-first `policies` ordering.
    fn declared_effect(&self, policy_index: usize) -> Effect {
        if policy_index < self.deny_count {
            Effect::Deny
        } else {
            Effect::Allow
        }
    }

    /// Convenience for RBAC/ABAC-only callers: evaluates against the
    /// process-wide [`EvaluationSession::shared_empty`] session.
    ///
    /// Equivalent to:
    ///
    /// ```ignore
    /// checker.evaluate_in_session(
    ///     EvaluationSession::shared_empty(),
    ///     subject, action, resource, context,
    /// ).await
    /// ```
    ///
    /// Use this when no policy in the checker reads fact-backed state.
    /// **For checkers with any fact-backed policy (ReBAC, custom
    /// `FactSource`-using policies)**, call [`Self::evaluate_in_session`]
    /// directly so the session can carry the registered `FactSource`s.
    /// The shared empty session has no fact sources registered, so any
    /// fact load would fail closed with
    /// [`crate::FactLoadError::SourceNotRegistered`].
    pub async fn check(
        &self,
        subject: &S,
        action: &A,
        resource: &R,
        context: &C,
    ) -> AccessEvaluation {
        self.evaluate_in_session(
            crate::EvaluationSession::shared_empty(),
            subject,
            action,
            resource,
            context,
        )
        .await
    }

    /// Evaluates all policies against the given parameters using a caller-owned
    /// request session.
    ///
    /// Policies are evaluated sequentially under deny-overrides semantics:
    /// declared-deny policies first (a forbid ends the evaluation as a
    /// denial), then allow policies with a short-circuit on the first grant.
    /// The returned [`AccessEvaluation`] contains a trace tree for the
    /// policies that were actually evaluated before short-circuiting.
    ///
    /// If a forbid fires, the top-level denial reason names the forbidding
    /// policy (`"Forbidden by <policy>: <reason>"`). If no policy grants,
    /// the reason is the summary string `"All policies denied access"`.
    /// Inspect the trace for individual policy reasons.
    #[tracing::instrument(skip_all, fields(checker.name = tracing::field::Empty, policy_count = self.policies.len(), outcome = tracing::field::Empty, policy.type = tracing::field::Empty))]
    pub async fn evaluate_in_session(
        &self,
        session: &EvaluationSession,
        subject: &S,
        action: &A,
        resource: &R,
        context: &C,
    ) -> AccessEvaluation {
        if let Some(name) = self.name.as_deref() {
            tracing::Span::current().record("checker.name", name);
        }
        if self.policies.is_empty() {
            tracing::Span::current().record("outcome", "denied");
            tracing::debug!("No policies configured");
            let result =
                PolicyEvalResult::denied(PERMISSION_CHECKER_POLICY_TYPE, "No policies configured");

            return AccessEvaluation::Denied {
                trace: EvalTrace::with_root(result),
                reason: "No policies configured".to_string(),
            };
        }
        tracing::trace!(num_policies = self.policies.len(), "Checking access");

        let mut policy_results = Vec::with_capacity(self.policies.len());

        // Evaluate each policy; `policies` is kept in deny-first order by
        // `add_policy`.
        for (policy_index, policy) in self.policies.iter().enumerate() {
            let declared_effect = self.declared_effect(policy_index);
            // Move the policy's name straight into the EvalCtx rather than
            // cloning, since for dynamic-name (`Cow::Owned`) policies the
            // clone is a fresh `String` allocation we don't need: the same
            // value is reachable through `ctx.policy_type` for telemetry,
            // and the eventual `AccessEvaluation::Granted` consumes `ctx`
            // by destructure on the grant branch.
            let ctx = EvalCtx {
                session,
                subject,
                action,
                resource,
                context,
                policy_type: policy.policy_type(),
            };
            let mut result = policy.evaluate(&ctx).await;
            if declared_effect == Effect::Deny && result.is_granted() {
                tracing::warn!(
                    policy.type = ctx.policy_type.as_ref(),
                    "{DENY_EFFECT_GRANT_REASON}"
                );
                result =
                    PolicyEvalResult::denied(ctx.policy_type.clone(), DENY_EFFECT_GRANT_REASON);
            }
            let result_passes = result.is_granted();
            let result_forbids = result.is_forbidden();

            // Extract metadata for tracing (always needed for security audit)
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
            let policy_effect = match declared_effect {
                Effect::Allow => "allow",
                Effect::Deny => "deny",
            };

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

            policy_results.push(result);

            // A forbid overrides everything: stop evaluating and deny.
            if result_forbids {
                tracing::Span::current().record("outcome", "denied");
                tracing::Span::current().record("policy.type", policy_type_str);
                let combined = checker_root(policy_results, false);
                return AccessEvaluation::Denied {
                    trace: EvalTrace::with_root(combined),
                    reason: forbid_summary(policy_type_str, reason.as_deref()),
                };
            }

            // If any policy allows access, return immediately
            if result_passes {
                tracing::Span::current().record("outcome", "granted");
                tracing::Span::current().record("policy.type", policy_type_str);
                let combined = checker_root(policy_results, true);

                // Destructure to move policy_type out of the EvalCtx
                // without an extra clone.
                let EvalCtx { policy_type, .. } = ctx;
                return AccessEvaluation::Granted {
                    policy_type,
                    reason,
                    trace: EvalTrace::with_root(combined),
                };
            }
        }

        // If all policies denied access
        tracing::Span::current().record("outcome", "denied");
        tracing::trace!("No policies allowed access, returning Forbidden");
        let combined = checker_root(policy_results, false);

        AccessEvaluation::Denied {
            trace: EvalTrace::with_root(combined),
            reason: "All policies denied access".to_string(),
        }
    }

    /// Evaluates a batch of caller-owned items using a caller-owned session.
    ///
    /// The `parts` callback tells gatehouse how to borrow the resource and
    /// context from each caller-owned item. Returned results preserve input
    /// order, including duplicate resources. Policy evaluation uses the same
    /// deny-overrides semantics as [`Self::evaluate_in_session`] (declared-deny
    /// policies first; a forbid finalizes an item as denied), but the checker
    /// evaluates each policy across the still-pending batch before moving to
    /// the next policy. This lets policies with set-oriented backends override
    /// [`Policy::evaluate_batch`] and collapse many point lookups into
    /// one backend call.
    ///
    /// The loop is intentionally policy-outer/items-inner, not a naive
    /// item-outer loop. OR short-circuiting is preserved per item and policy
    /// order is preserved globally, but callers should avoid relying on
    /// side effects from interleaving one item through every policy before the
    /// next item starts.
    ///
    /// If a policy returns the wrong number of batch results, affected items are
    /// denied rather than accidentally granted.
    ///
    /// ```rust
    /// # use gatehouse::*;
    /// # use async_trait::async_trait;
    /// # #[derive(Clone)]
    /// # struct User { id: u64 }
    /// # #[derive(Clone)]
    /// # struct Document { owner_id: u64 }
    /// # struct Read;
    /// # #[derive(Clone)]
    /// # struct RequestContext;
    /// # tokio_test::block_on(async {
    /// let user = User { id: 7 };
    /// let context = RequestContext;
    /// let session = EvaluationSession::empty();
    /// let documents = vec![
    ///     Document { owner_id: 7 },
    ///     Document { owner_id: 42 },
    /// ];
    ///
    /// let mut checker = PermissionChecker::new();
    /// checker.add_policy(AbacPolicy::new(
    ///     |user: &User, document: &Document, _action: &Read, _context: &RequestContext| {
    ///         user.id == document.owner_id
    ///     },
    /// ));
    ///
    /// let visible = checker
    ///     .filter_authorized_in_session_by_resource(&session, &user, &Read, documents, &context, |document| {
    ///         document
    ///     })
    ///     .await;
    ///
    /// assert_eq!(visible.len(), 1);
    /// # });
    /// ```
    #[tracing::instrument(skip_all, fields(checker.name = tracing::field::Empty, item_count, granted_count, denied_count, max_batch_size, policy_count = self.policies.len()))]
    pub async fn evaluate_batch_in_session_by<I, F>(
        &self,
        session: &EvaluationSession,
        subject: &S,
        action: &A,
        items: I,
        parts: F,
    ) -> Vec<(I::Item, AccessEvaluation)>
    where
        I: IntoIterator,
        F: for<'item> Fn(&'item I::Item) -> (&'item R, &'item C),
    {
        let items: Vec<I::Item> = items.into_iter().collect();
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
            let mut denied_count = 0usize;
            let results = items
                .into_iter()
                .map(|item| {
                    denied_count += 1;
                    let result = PolicyEvalResult::denied(
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
            tracing::Span::current().record("denied_count", denied_count);
            return results;
        }

        let item_parts = items
            .iter()
            .map(|item| {
                let (resource, context) = parts(item);
                PolicyBatchItem { resource, context }
            })
            .collect::<Vec<_>>();

        let mut pending: Vec<usize> = (0..item_count).collect();

        // `policies` is kept in deny-first order by `add_policy`, so a
        // forbid is always observed before an allow policy can grant an
        // item out of the pending set.
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
                    policy.effect = match declared_effect {
                        Effect::Allow => "allow",
                        Effect::Deny => "deny",
                    },
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
                let batch_items: Vec<_> = pending_chunk
                    .iter()
                    .map(|&index| PolicyBatchItem {
                        resource: item_parts[index].resource,
                        context: item_parts[index].context,
                    })
                    .collect();

                let batch_ctx = BatchEvalCtx {
                    session,
                    subject,
                    action,
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
                        let policy_result = PolicyEvalResult::denied(
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
                    if declared_effect == Effect::Deny && result.is_granted() {
                        contract_violation_count += 1;
                        result =
                            PolicyEvalResult::denied(policy_type.clone(), DENY_EFFECT_GRANT_REASON);
                    }
                    let result_passes = result.is_granted();
                    let result_forbids = result.is_forbidden();
                    let reason = result.reason();

                    traces[index].push(result);

                    if result_forbids {
                        policy_forbidden_count += 1;
                        let combined = checker_root(std::mem::take(&mut traces[index]), false);
                        evaluations[index] = Some(AccessEvaluation::Denied {
                            trace: EvalTrace::with_root(combined),
                            reason: forbid_summary(policy_type_str, reason.as_deref()),
                        });
                    } else if result_passes {
                        policy_granted_count += 1;
                        let combined = checker_root(std::mem::take(&mut traces[index]), true);
                        evaluations[index] = Some(AccessEvaluation::Granted {
                            policy_type: policy_type.clone(),
                            reason,
                            trace: EvalTrace::with_root(combined),
                        });
                    } else {
                        policy_denied_count += 1;
                        still_pending.push(index);
                    }
                }
                if contract_violation_count > 0 {
                    // One warning per chunk, not per item: a misbehaving
                    // policy in a large batch would otherwise flood the log.
                    tracing::warn!(
                        policy.type = policy_type_str,
                        item_count = contract_violation_count,
                        "{DENY_EFFECT_GRANT_REASON}"
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
                    let result = PolicyEvalResult::denied(
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

    /// Returns only the items granted by [`Self::evaluate_batch_in_session_by`].
    pub async fn filter_authorized_in_session_by<I, F>(
        &self,
        session: &EvaluationSession,
        subject: &S,
        action: &A,
        items: I,
        parts: F,
    ) -> Vec<I::Item>
    where
        I: IntoIterator,
        F: for<'item> Fn(&'item I::Item) -> (&'item R, &'item C),
    {
        self.evaluate_batch_in_session_by(session, subject, action, items, parts)
            .await
            .into_iter()
            .filter_map(|(item, evaluation)| evaluation.is_granted().then_some(item))
            .collect()
    }

    /// Evaluates caller-owned items that all share one context value.
    ///
    /// `resource` extracts `&R` from each item; the same `context` is used
    /// for every evaluation. Compare with
    /// [`Self::evaluate_batch_in_session_by`], which extracts both
    /// `(&R, &C)` per item.
    pub async fn evaluate_batch_in_session_by_resource<I, F>(
        &self,
        session: &EvaluationSession,
        subject: &S,
        action: &A,
        items: I,
        context: &C,
        resource: F,
    ) -> Vec<(I::Item, AccessEvaluation)>
    where
        I: IntoIterator,
        F: for<'item> Fn(&'item I::Item) -> &'item R,
    {
        let wrapped_items = items
            .into_iter()
            .map(|item| (item, context))
            .collect::<Vec<_>>();

        self.evaluate_batch_in_session_by(
            session,
            subject,
            action,
            wrapped_items,
            |(item, context)| (resource(item), *context),
        )
        .await
        .into_iter()
        .map(|((item, _context), evaluation)| (item, evaluation))
        .collect()
    }

    /// Returns only authorized items with a shared context.
    ///
    /// Filter analogue of [`Self::evaluate_batch_in_session_by_resource`].
    pub async fn filter_authorized_in_session_by_resource<I, F>(
        &self,
        session: &EvaluationSession,
        subject: &S,
        action: &A,
        items: I,
        context: &C,
        resource: F,
    ) -> Vec<I::Item>
    where
        I: IntoIterator,
        F: for<'item> Fn(&'item I::Item) -> &'item R,
    {
        self.evaluate_batch_in_session_by_resource(
            session, subject, action, items, context, resource,
        )
        .await
        .into_iter()
        .filter_map(|(item, evaluation)| evaluation.is_granted().then_some(item))
        .collect()
    }

    /// Look up one page of candidate IDs from `lookup`, hydrate them via
    /// `hydrator`, and return only the resources that the full policy
    /// stack authorizes.
    ///
    /// This is the page-oriented primitive behind
    /// [`Self::lookup_authorized`]. Use it directly when you need
    /// candidate-page-grained streaming — for example, a list endpoint
    /// that emits results as they are confirmed without buffering the
    /// whole authorized population.
    ///
    /// `next_cursor` paginates the **candidate** stream from `lookup`,
    /// not the authorized output. A `Some(cursor)` with an empty
    /// `resources` vector is normal: every candidate in this page was
    /// denied by the policy stack. Continue paging until `next_cursor`
    /// is `None`.
    ///
    /// Cursor-progress is enforced here, not just in
    /// [`Self::lookup_authorized`]: if the source returns a `next_cursor`
    /// equal to the cursor that was just consumed, this method aborts
    /// with [`LookupAuthorizedError::LookupCursorStuck`] rather than
    /// returning a page that would lead a streaming caller into an
    /// infinite loop.
    ///
    /// See [`LookupSource`] for the completeness contract: the source
    /// must enumerate a superset of every resource that any policy in
    /// this checker could grant; lookup narrows the candidate set but
    /// does not replace policy evaluation.
    #[allow(
        clippy::too_many_arguments,
        reason = "orchestration entry point: session + subject + action + context + lookup + \
                  cursor + limit + hydrator are all genuinely independent inputs; bundling \
                  them would obscure the call site without saving anything."
    )]
    pub async fn lookup_authorized_page<L, H>(
        &self,
        session: &EvaluationSession,
        subject: &S,
        action: &A,
        context: &C,
        lookup: &L,
        cursor: Option<&[u8]>,
        limit: NonZeroUsize,
        hydrator: &H,
    ) -> Result<LookupAuthorizedPage<R>, LookupAuthorizedError<L::Error, H::Error>>
    where
        L: LookupSource<Subject = S>,
        H: Hydrator<L::Id, Resource = R>,
        R: Send,
    {
        let lookup_span = tracing::debug_span!(
            "gatehouse.lookup",
            lookup.limit = limit.get(),
            lookup.has_cursor = cursor.is_some(),
        );
        let page = lookup
            .lookup_page(subject, cursor, limit)
            .instrument(lookup_span)
            .await
            .map_err(LookupAuthorizedError::Lookup)?;

        // Enforce the cursor-progress contract before anything else: if the
        // source returned the same cursor that was just consumed, a caller
        // following the "loop until next_cursor is None" guidance would
        // spin. Catch it here (not just in the collecting loop) so the
        // page-oriented streaming API is just as safe.
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

        let resources: Vec<R> = hydrated.into_iter().flatten().collect();
        let authorized = self
            .filter_authorized_in_session_by_resource(
                session,
                subject,
                action,
                resources,
                context,
                |resource| resource,
            )
            .await;

        Ok(LookupAuthorizedPage {
            resources: authorized,
            next_cursor: page.next_cursor,
        })
    }

    /// Drive [`Self::lookup_authorized_page`] until the source is
    /// exhausted, collecting every authorized resource into a single
    /// `Vec`.
    ///
    /// This is the all-or-error convenience: any backend error from the
    /// lookup source or hydrator aborts the whole operation; the caller
    /// does not see partial results. For very large authorized
    /// populations, prefer [`Self::lookup_authorized_page`] and stream
    /// results page by page.
    ///
    /// Cursor-progress is enforced: if the source returns a `next_cursor`
    /// equal to the cursor that was just consumed, gatehouse aborts with
    /// [`LookupAuthorizedError::LookupCursorStuck`] rather than loop
    /// forever.
    #[allow(
        clippy::too_many_arguments,
        reason = "see lookup_authorized_page for the rationale."
    )]
    pub async fn lookup_authorized<L, H>(
        &self,
        session: &EvaluationSession,
        subject: &S,
        action: &A,
        context: &C,
        lookup: &L,
        page_size: NonZeroUsize,
        hydrator: &H,
    ) -> Result<Vec<R>, LookupAuthorizedError<L::Error, H::Error>>
    where
        L: LookupSource<Subject = S>,
        H: Hydrator<L::Id, Resource = R>,
        R: Send,
    {
        let mut authorized = Vec::new();
        let mut cursor: Option<Vec<u8>> = None;
        loop {
            let page = self
                .lookup_authorized_page(
                    session,
                    subject,
                    action,
                    context,
                    lookup,
                    cursor.as_deref(),
                    page_size,
                    hydrator,
                )
                .await?;
            authorized.extend(page.resources);
            // Cursor-progress is enforced inside `lookup_authorized_page`,
            // so we just trust the returned `next_cursor` here.
            match page.next_cursor {
                None => return Ok(authorized),
                Some(next) => cursor = Some(next),
            }
        }
    }
}

impl<S, R, A> PermissionChecker<S, R, A, ()>
where
    S: Sync,
    R: Sync,
    A: Sync,
{
    /// Evaluates a batch where each caller-owned item is the resource and the
    /// context type is `()`.
    ///
    /// This is the ergonomic shortcut for list-like checks that do not need a
    /// per-item context value.
    pub async fn evaluate_batch_resources_in_session<I>(
        &self,
        session: &EvaluationSession,
        subject: &S,
        action: &A,
        resources: I,
    ) -> Vec<(R, AccessEvaluation)>
    where
        I: IntoIterator<Item = R>,
    {
        self.evaluate_batch_in_session_by_resource(
            session,
            subject,
            action,
            resources,
            &(),
            |resource| resource,
        )
        .await
    }

    /// Returns only resources granted by
    /// [`Self::evaluate_batch_resources_in_session`].
    pub async fn filter_authorized_resources_in_session<I>(
        &self,
        session: &EvaluationSession,
        subject: &S,
        action: &A,
        resources: I,
    ) -> Vec<R>
    where
        I: IntoIterator<Item = R>,
    {
        self.evaluate_batch_resources_in_session(session, subject, action, resources)
            .await
            .into_iter()
            .filter_map(|(resource, evaluation)| evaluation.is_granted().then_some(resource))
            .collect()
    }
}
