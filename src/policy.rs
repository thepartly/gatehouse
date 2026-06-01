use crate::{EvaluationSession, FactProvenance, PolicyEvalResult, SecurityRuleMetadata};
use async_trait::async_trait;

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
pub struct EvalCtx<'a, Subject, Resource, Action, Context> {
    /// Request-scoped fact session.
    pub session: &'a EvaluationSession,
    /// Entity requesting access.
    pub subject: &'a Subject,
    /// Action being performed.
    pub action: &'a Action,
    /// Target resource.
    pub resource: &'a Resource,
    /// Additional evaluation context.
    pub context: &'a Context,
    /// The current policy's [`Policy::policy_type`], captured once by the
    /// checker before dispatch. Used by [`Self::grant`] / [`Self::deny`] so
    /// policy bodies don't need to re-pass `self.policy_type()` on every
    /// result.
    pub policy_type: &'a str,
}

impl<'a, S, R, A, C> EvalCtx<'a, S, R, A, C> {
    /// Shorthand for `PolicyEvalResult::granted(ctx.policy_type, Some(reason))`.
    ///
    /// Symmetric with [`Self::deny`]: both take the reason as a string. The
    /// underlying [`PolicyEvalResult::Granted`] variant allows a `None`
    /// reason, but in practice grants almost always carry one, so the
    /// shortcut requires it; for the rare no-reason case call
    /// [`PolicyEvalResult::granted`] directly with `None`.
    ///
    /// **Performance note.** `ctx.policy_type` is a non-static `&str`
    /// borrowed from the policy, so the shortcut allocates one `String`
    /// per call to attach it to the result. For zero-allocation grants on
    /// hot paths, call [`PolicyEvalResult::granted`] directly with a
    /// `&'static str` literal — that path goes through
    /// `Cow::Borrowed`.
    pub fn grant(&self, reason: impl Into<String>) -> PolicyEvalResult {
        PolicyEvalResult::granted(self.policy_type.to_string(), Some(reason.into()))
    }

    /// Shorthand for `PolicyEvalResult::denied(ctx.policy_type, reason)`.
    ///
    /// See [`Self::grant`] for the per-call allocation note.
    pub fn deny(&self, reason: impl Into<String>) -> PolicyEvalResult {
        PolicyEvalResult::denied(self.policy_type.to_string(), reason)
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
            self.policy_type.to_string(),
            Some(reason.into()),
            provenance,
        )
    }

    /// Shorthand for [`PolicyEvalResult::denied_with_facts`] tagged with
    /// `ctx.policy_type`.
    pub fn deny_with_facts(
        &self,
        reason: impl Into<String>,
        provenance: Vec<FactProvenance>,
    ) -> PolicyEvalResult {
        PolicyEvalResult::denied_with_facts(self.policy_type.to_string(), reason, provenance)
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
pub struct BatchEvalCtx<'a, Subject, Resource, Action, Context> {
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
    pub policy_type: &'a str,
}

/// A generic async trait representing a single authorization policy.
/// A policy determines if a subject is allowed to perform an action on
/// a resource within a given context.
///
/// The input types must be [`Sync`] because policies receive borrowed inputs
/// across async evaluation, including [`BatchEvalCtx`] batch evaluation.
#[async_trait]
pub trait Policy<Subject, Resource, Action, Context>: Send + Sync
where
    Subject: Sync,
    Resource: Sync,
    Action: Sync,
    Context: Sync,
{
    /// Evaluates whether access should be granted.
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, Subject, Resource, Action, Context>,
    ) -> PolicyEvalResult;

    /// Evaluates access for a batch of resource/context pairs.
    ///
    /// The default implementation preserves single-item semantics by evaluating
    /// each item sequentially. Policies with set-oriented backends can override
    /// this method to reduce round trips while returning one result per input
    /// item in the same order.
    ///
    /// The checker still evaluates policies in policy order, so batched
    /// evaluation can differ from a naive item-outer loop when later policies
    /// have side effects or observe mutable external state. Prefer pure policy
    /// predicates and use traces to audit the policy-ordered batch behavior.
    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, Subject, Resource, Action, Context>,
    ) -> Vec<PolicyEvalResult> {
        let mut results = Vec::with_capacity(ctx.items.len());
        for item in ctx.items {
            let item_ctx = EvalCtx {
                session: ctx.session,
                subject: ctx.subject,
                action: ctx.action,
                resource: item.resource,
                context: item.context,
                policy_type: ctx.policy_type,
            };
            results.push(self.evaluate(&item_ctx).await);
        }
        results
    }

    /// Policy name for debugging, trace trees, and telemetry fallbacks.
    fn policy_type(&self) -> &str;

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
impl<S, R, A, C> Policy<S, R, A, C> for Box<dyn Policy<S, R, A, C>>
where
    S: Send + Sync,
    R: Send + Sync,
    A: Send + Sync,
    C: Send + Sync,
{
    async fn evaluate(&self, ctx: &EvalCtx<'_, S, R, A, C>) -> PolicyEvalResult {
        (**self).evaluate(ctx).await
    }

    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, S, R, A, C>,
    ) -> Vec<PolicyEvalResult> {
        (**self).evaluate_batch(ctx).await
    }

    fn policy_type(&self) -> &str {
        (**self).policy_type()
    }

    fn security_rule(&self) -> SecurityRuleMetadata {
        (**self).security_rule()
    }
}
