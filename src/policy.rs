use crate::{EvaluationSession, FactProvenance, PolicyEvalResult, SecurityRuleMetadata};
use async_trait::async_trait;
use std::borrow::Cow;

/// The declared effect of a policy: whether a match grants or forbids access.
///
/// `Allow` (the default everywhere) means the policy grants access when it
/// matches. `Forbid` means the policy **forbids** access when it matches — a
/// matched forbid produces [`PolicyEvalResult::Forbidden`], which
/// [`crate::PermissionChecker`] honors over any grant from sibling policies
/// (deny-overrides semantics).
///
/// The effect travels with the policy: set it via
/// [`crate::PolicyBuilder::forbid`], or declare it on a hand-written policy
/// by overriding [`Policy::effect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// The policy grants access when its predicates pass.
    Allow,
    /// The policy forbids access when its predicates pass.
    Forbid,
}

/// A borrowed resource/context pair passed to batch policy evaluators.
///
/// Values are borrowed from caller-owned batch items, so policy implementations
/// can evaluate a batch without forcing resources or contexts to be cloned.
pub struct PolicyBatchItem<'a, Resource, Context> {
    /// The target resource for this item.
    pub resource: &'a Resource,
    /// Additional context for this item.
    pub context: &'a Context,
}

/// Per-item policy evaluation context.
pub struct EvalCtx<'a, Subject, Action, Resource, Context> {
    /// Request-scoped fact session.
    pub session: &'a EvaluationSession,
    /// Entity requesting access.
    pub subject: &'a Subject,
    /// Action being performed.
    pub action: &'a Action,
    /// Target resource.
    pub resource: &'a Resource,
    /// Additional per-request evaluation context.
    ///
    /// Carries request-scoped inputs that aren't properties of the
    /// subject or resource: the current wall-clock time, the MFA
    /// freshness on the auth session, the caller's network zone,
    /// tenant-level overrides. Rule of thumb: if **same subject, same
    /// resource, different calls → different decisions**, the
    /// distinguishing input belongs on `Context`. If the decision is
    /// fully determined by the subject and resource, `Context = ()`
    /// is fine.
    ///
    /// `Context` is **not** the place for relationship data — that
    /// loads through a [`FactSource`](crate::FactSource) on the
    /// [`EvaluationSession`](crate::EvaluationSession). See the
    /// crate-level "When to populate the Context type" section and
    /// `examples/mfa_freshness_context.rs` for fuller treatment.
    pub context: &'a Context,
    /// The current policy's [`Policy::policy_type`], captured by the
    /// checker before dispatch. On the single-item path
    /// ([`crate::PermissionChecker::evaluate_in_session`]) the checker
    /// captures it exactly once and moves it into this field; on the
    /// batch path ([`crate::PermissionChecker::evaluate_batch_in_session`])
    /// the checker captures it once per policy and clones it into each
    /// `BatchEvalCtx` chunk. Used by [`Self::grant`] /
    /// [`Self::not_applicable`] / [`Self::forbid`] so policy bodies don't need
    /// to re-pass `self.policy_type()` on every result.
    ///
    /// Stored as [`Cow<'static, str>`] so the shortcut path is truly
    /// zero-allocation for policies that return `Cow::Borrowed("Name")`
    /// (every built-in policy, and any user policy with a static name).
    ///
    /// Dynamic-name policies pay more on the helper path than a static-
    /// name policy does. On the single-item path the checker calls
    /// `policy.policy_type()` (alloc 1, the `String` inside the
    /// `Cow::Owned`) and moves the `Cow` straight into the `EvalCtx`,
    /// and then `ctx.grant` / `ctx.not_applicable` clones it into the result
    /// (alloc 2). On the batch path the checker keeps the local
    /// `Cow` alive across chunks and clones it into each
    /// `BatchEvalCtx`, so the cost rises further with the number of
    /// chunks the policy fans out over. The shortcut path cannot
    /// avoid these — `ctx.policy_type` is behind a shared
    /// `&EvalCtx` / `&BatchEvalCtx` reference and cannot be moved out
    /// from inside the policy body. If allocation cost matters, return
    /// a `Cow::Borrowed` from a `'static` name table so the whole
    /// chain stays zero-allocation.
    pub policy_type: Cow<'static, str>,
}

impl<'a, S, A, R, C> EvalCtx<'a, S, A, R, C> {
    /// Shorthand for `PolicyEvalResult::granted(ctx.policy_type, Some(reason))`.
    ///
    /// Symmetric with [`Self::not_applicable`]: both take the reason as a string. The
    /// underlying [`PolicyEvalResult::Granted`] variant allows a `None`
    /// reason, but in practice grants almost always carry one, so the
    /// shortcut requires it; for the rare no-reason case call
    /// [`PolicyEvalResult::granted`] directly with `None`.
    pub fn grant(&self, reason: impl Into<String>) -> PolicyEvalResult {
        PolicyEvalResult::granted(self.policy_type.clone(), Some(reason.into()))
    }

    /// Shorthand for `PolicyEvalResult::not_applicable(ctx.policy_type, reason)`.
    pub fn not_applicable(&self, reason: impl Into<String>) -> PolicyEvalResult {
        PolicyEvalResult::not_applicable(self.policy_type.clone(), reason)
    }

    /// Shorthand for `PolicyEvalResult::forbidden(ctx.policy_type, reason)`.
    ///
    /// Use this for an **active veto** — "this request is forbidden" — as
    /// opposed to [`Self::not_applicable`]'s "this policy does not grant". A policy
    /// that can return a forbid should also override [`Policy::effect`] to
    /// return [`Effect::Forbid`] so [`crate::PermissionChecker`] evaluates it
    /// before grant short-circuiting can skip it.
    pub fn forbid(&self, reason: impl Into<String>) -> PolicyEvalResult {
        PolicyEvalResult::forbidden(self.policy_type.clone(), reason)
    }

    /// Shorthand for [`PolicyEvalResult::granted_with_facts`] tagged with
    /// `ctx.policy_type`. See [`Self::grant`] for the reason-handling
    /// rationale.
    pub fn grant_with_facts(
        &self,
        reason: impl Into<String>,
        provenance: Vec<FactProvenance>,
    ) -> PolicyEvalResult {
        PolicyEvalResult::granted_with_facts(
            self.policy_type.clone(),
            Some(reason.into()),
            provenance,
        )
    }

    /// Shorthand for [`PolicyEvalResult::not_applicable_with_facts`] tagged with
    /// `ctx.policy_type`.
    pub fn not_applicable_with_facts(
        &self,
        reason: impl Into<String>,
        provenance: Vec<FactProvenance>,
    ) -> PolicyEvalResult {
        PolicyEvalResult::not_applicable_with_facts(self.policy_type.clone(), reason, provenance)
    }

    /// Shorthand for [`PolicyEvalResult::forbidden_with_facts`] tagged with
    /// `ctx.policy_type`. See [`Self::forbid`] for when a forbid is the
    /// right result.
    pub fn forbid_with_facts(
        &self,
        reason: impl Into<String>,
        provenance: Vec<FactProvenance>,
    ) -> PolicyEvalResult {
        PolicyEvalResult::forbidden_with_facts(self.policy_type.clone(), reason, provenance)
    }
}

/// Batch policy evaluation context.
///
/// A batch holds one `subject` and one `action` evaluated against many
/// `(resource, context)` items — it answers "can this subject perform this
/// action on each of these resources?". This matches the dominant batch shape
/// (filtering a list of resources by a single verb, or authorizing a fan-out of
/// frames that share an action) and is what lets set-oriented backends load the
/// facts for every item in one round trip: the shared `(subject, action)` is
/// the stable axis the prefetch keys on.
///
/// If items need different actions, either group them and run one batch per
/// action, or carry the per-item action inside `Context` and have the policy
/// read it from there.
pub struct BatchEvalCtx<'a, Subject, Action, Resource, Context> {
    /// Request-scoped fact session.
    pub session: &'a EvaluationSession,
    /// Entity requesting access.
    pub subject: &'a Subject,
    /// Action being performed, shared across every item in the batch.
    pub action: &'a Action,
    /// Borrowed resource/context pairs.
    pub items: &'a [PolicyBatchItem<'a, Resource, Context>],
    /// The current policy's [`Policy::policy_type`]. Same field as on
    /// [`EvalCtx`]; propagated to per-item `EvalCtx`s by the default
    /// `evaluate_batch` impl and by combinators when they fan out.
    pub policy_type: Cow<'static, str>,
}

/// A generic async trait representing a single authorization policy.
/// A policy determines if a subject is allowed to perform an action on
/// a resource within a given context.
///
/// The input types must be [`Sync`] because policies receive borrowed inputs
/// across async evaluation, including [`BatchEvalCtx`] batch evaluation.
#[async_trait]
pub trait Policy<Subject, Action, Resource, Context>: Send + Sync
where
    Subject: Sync,
    Resource: Sync,
    Action: Sync,
    Context: Sync,
{
    /// Evaluates whether access should be granted.
    ///
    /// If the body does I/O whose result depends on subject- or
    /// action-derived inputs but **not** on the resource (looking up
    /// the subject's tenant, resolving an org → customer mapping, etc.),
    /// don't call the backing service directly from inside `evaluate`
    /// — every item in a list endpoint will repeat the same lookup.
    /// Register a [`FactSource`](crate::FactSource) and consume it via
    /// `ctx.session.get(key).await` so the request-scoped session
    /// deduplicates and caches the result for the whole batch. See the
    /// [`FactSource`](crate::FactSource) rustdoc for the
    /// `(subject, scope) → resolved-id` pattern, which the built-in
    /// [`RebacPolicy`](crate::RebacPolicy) generalises to relationship
    /// facts.
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, Subject, Action, Resource, Context>,
    ) -> PolicyEvalResult;

    /// Evaluates access for a batch of resource/context pairs.
    ///
    /// The default implementation preserves single-item semantics by evaluating
    /// each item sequentially. Policies with set-oriented backends can override
    /// this method to reduce round trips while returning one result per input
    /// item in the same order.
    ///
    /// **The serial default is intentional.** The trait cannot know your
    /// concurrency budget, and `N` policies × `M` items run through
    /// `join_all` can easily exhaust the connection pools your `FactSource`s
    /// and downstream services depend on. If your batch work is genuinely
    /// concurrent-safe, override `evaluate_batch` with the concurrency
    /// shape your downstream limits allow: `futures::future::join_all` for
    /// small fixed fan-outs, `FuturesUnordered` for streaming, a
    /// semaphore-bounded variant for connection-pool-aware throughput.
    /// Don't expect gatehouse to choose for you.
    ///
    /// The checker still evaluates policies in policy order, so batched
    /// evaluation can differ from a naive item-outer loop when later policies
    /// have side effects or observe mutable external state. Prefer pure policy
    /// predicates and use traces to audit the policy-ordered batch behavior.
    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, Subject, Action, Resource, Context>,
    ) -> Vec<PolicyEvalResult> {
        let mut results = Vec::with_capacity(ctx.items.len());
        for item in ctx.items {
            let item_ctx = EvalCtx {
                session: ctx.session,
                subject: ctx.subject,
                action: ctx.action,
                resource: item.resource,
                context: item.context,
                policy_type: ctx.policy_type.clone(),
            };
            results.push(self.evaluate(&item_ctx).await);
        }
        results
    }

    /// Policy name for debugging, trace trees, and telemetry fallbacks.
    ///
    /// Returns [`Cow<'static, str>`] so the common static-name case
    /// (`Cow::Borrowed("MyPolicy")`) is zero-allocation end-to-end —
    /// the checker captures this once per evaluation into
    /// [`EvalCtx::policy_type`], and [`EvalCtx::grant`] / [`EvalCtx::not_applicable`]
    /// clone the [`Cow`] (which is a no-op for `Borrowed`).
    ///
    /// Dynamic-name policies return `Cow::Owned(self.name.clone())`
    /// and pay one allocation here, plus one more on the single-item
    /// `ctx.grant` / `ctx.not_applicable` helper path (the batch path also clones
    /// into each `BatchEvalCtx` chunk) — see
    /// [`EvalCtx::policy_type`] for the full accounting. This is a
    /// regression from the pre-`Cow` trait shape where
    /// `policy_type(&self) -> &str` let dynamic names return
    /// `&self.name` without allocating. Prefer a `'static` name table
    /// when you can; the dynamic case still works correctly, just at
    /// extra cost.
    fn policy_type(&self) -> Cow<'static, str>;

    /// The declared effect of this policy. Defaults to [`Effect::Allow`].
    ///
    /// [`crate::PermissionChecker`] reads this declaration **once, when the
    /// policy is added**, to schedule evaluation: policies declaring
    /// [`Effect::Forbid`] run **before** the allow policies, so a matched
    /// forbid is always observed before the grant short-circuit can end the
    /// evaluation. The declaration must therefore be constant for the
    /// policy's lifetime. Policies built with
    /// [`crate::PolicyBuilder::forbid`] declare this automatically.
    ///
    /// **Contract:** a hand-written policy that can return
    /// [`PolicyEvalResult::Forbidden`] must override this to return
    /// [`Effect::Forbid`]. The checker still honors a forbid it happens to
    /// observe from an undeclared policy, but without the declaration a
    /// sibling's grant can short-circuit evaluation before the forbid is
    /// reached — the veto would then depend on registration order.
    /// Conversely, a policy declaring `Effect::Forbid` must not return
    /// `Granted`; the checker treats such a result as not applicable
    /// (fail-closed) and logs a warning.
    fn effect(&self) -> Effect {
        Effect::Allow
    }

    /// Metadata describing the security rule that backs this policy.
    ///
    /// Implementors can override this method to surface additional semantic
    /// information. The default implementation returns empty metadata which
    /// still allows downstream telemetry to fall back to the policy type.
    fn security_rule(&self) -> SecurityRuleMetadata {
        SecurityRuleMetadata::default()
    }
}

// Tell the compiler that a Box<dyn Policy> implements the Policy trait so we can keep
// our internal policy type private.
#[async_trait]
impl<S, A, R, C> Policy<S, A, R, C> for Box<dyn Policy<S, A, R, C>>
where
    S: Sync,
    R: Sync,
    A: Sync,
    C: Sync,
{
    async fn evaluate(&self, ctx: &EvalCtx<'_, S, A, R, C>) -> PolicyEvalResult {
        (**self).evaluate(ctx).await
    }

    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, S, A, R, C>,
    ) -> Vec<PolicyEvalResult> {
        (**self).evaluate_batch(ctx).await
    }

    fn policy_type(&self) -> Cow<'static, str> {
        (**self).policy_type()
    }

    fn effect(&self) -> Effect {
        (**self).effect()
    }

    fn security_rule(&self) -> SecurityRuleMetadata {
        (**self).security_rule()
    }
}
