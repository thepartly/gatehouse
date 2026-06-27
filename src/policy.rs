use crate::{EvaluationSession, FactProvenance, PolicyEvalResult, SecurityRuleMetadata};
use async_trait::async_trait;
use std::borrow::Cow;
use std::sync::Arc;

/// Names the four Rust types that make up one authorization domain.
///
/// A domain is usually one resource family in an application: documents,
/// invoices, projects, packages. The marker type keeps policy APIs anchored to
/// a business domain instead of repeating `<Subject, Action, Resource, Context>`
/// on every checker, policy, and builder.
pub trait PolicyDomain: Send + Sync + 'static {
    /// Entity requesting access.
    type Subject: Send + Sync;
    /// Operation being attempted.
    type Action: Send + Sync;
    /// Target resource or scope resource.
    type Resource: Send + Sync;
    /// Request-scoped evaluation inputs.
    type Context: Send + Sync;
}

/// The declared effect of a policy: whether it can grant, forbid, or both.
///
/// `Allow` (the default everywhere) means the policy grants access when it
/// matches. `Forbid` means the policy **forbids** access when it matches: a
/// matched forbid produces [`PolicyEvalResult::Forbidden`], which
/// [`crate::PermissionChecker`] honors over any grant from sibling policies.
/// `AllowOrForbid` is for composed or custom policies that can produce either
/// result depending on their inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Effect {
    /// The policy may grant access, but must not actively forbid.
    Allow,
    /// The policy may actively forbid access, but must not grant.
    Forbid,
    /// The policy may either grant or actively forbid access.
    AllowOrForbid,
}

impl Effect {
    /// Whether this effect can produce a grant.
    pub fn can_grant(self) -> bool {
        matches!(self, Self::Allow | Self::AllowOrForbid)
    }

    /// Whether this effect can produce an active forbid.
    pub fn can_forbid(self) -> bool {
        matches!(self, Self::Forbid | Self::AllowOrForbid)
    }

    pub(crate) fn from_capabilities(can_grant: bool, can_forbid: bool) -> Self {
        match (can_grant, can_forbid) {
            (true, true) => Self::AllowOrForbid,
            (false, true) => Self::Forbid,
            _ => Self::Allow,
        }
    }

    pub(crate) fn telemetry_label(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Forbid => "deny",
            Self::AllowOrForbid => "allow_or_forbid",
        }
    }
}

/// A borrowed resource passed to batch policy evaluators.
///
/// Values are borrowed from caller-owned batch items, so policy implementations
/// can evaluate a batch without forcing resources to be cloned.
pub struct PolicyBatchItem<'a, D: PolicyDomain> {
    /// The target resource for this item.
    pub resource: &'a D::Resource,
}

/// Per-item policy evaluation context.
pub struct EvalCtx<'a, D: PolicyDomain> {
    /// Request-scoped fact session.
    pub session: &'a EvaluationSession,
    /// Entity requesting access.
    pub subject: &'a D::Subject,
    /// Action being performed.
    pub action: &'a D::Action,
    /// Target resource.
    pub resource: &'a D::Resource,
    /// Additional per-request evaluation context.
    ///
    /// Carries request-scoped inputs that are not properties of the subject or
    /// resource: current time, MFA freshness, network zone, tenant-level
    /// overrides. Relationship data belongs behind a [`crate::FactSource`] and
    /// loads through [`EvaluationSession`].
    pub context: &'a D::Context,
    /// The current policy's [`Policy::policy_type`], captured by the checker
    /// before dispatch and used by [`Self::grant`],
    /// [`Self::not_applicable`], and [`Self::forbid`].
    pub policy_type: Cow<'static, str>,
}

impl<'a, D: PolicyDomain> EvalCtx<'a, D> {
    /// Shorthand for `PolicyEvalResult::granted(ctx.policy_type, Some(reason))`.
    pub fn grant(&self, reason: impl Into<String>) -> PolicyEvalResult {
        PolicyEvalResult::granted(self.policy_type.clone(), Some(reason.into()))
    }

    /// Shorthand for `PolicyEvalResult::not_applicable(ctx.policy_type, reason)`.
    pub fn not_applicable(&self, reason: impl Into<String>) -> PolicyEvalResult {
        PolicyEvalResult::not_applicable(self.policy_type.clone(), reason)
    }

    /// Shorthand for `PolicyEvalResult::forbidden(ctx.policy_type, reason)`.
    ///
    /// Use this for an active veto. A hand-written policy that can only veto
    /// should override [`Policy::effect`] to return [`Effect::Forbid`]. A policy
    /// that can grant or veto should return [`Effect::AllowOrForbid`]. Both
    /// make [`crate::PermissionChecker`] evaluate the policy before allow-only
    /// policies so grant short-circuiting cannot skip the veto.
    pub fn forbid(&self, reason: impl Into<String>) -> PolicyEvalResult {
        PolicyEvalResult::forbidden(self.policy_type.clone(), reason)
    }

    /// Shorthand for [`PolicyEvalResult::granted_with_facts`] tagged with
    /// `ctx.policy_type`.
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

    /// Shorthand for [`PolicyEvalResult::not_applicable_with_facts`] tagged
    /// with `ctx.policy_type`.
    pub fn not_applicable_with_facts(
        &self,
        reason: impl Into<String>,
        provenance: Vec<FactProvenance>,
    ) -> PolicyEvalResult {
        PolicyEvalResult::not_applicable_with_facts(self.policy_type.clone(), reason, provenance)
    }

    /// Shorthand for [`PolicyEvalResult::forbidden_with_facts`] tagged with
    /// `ctx.policy_type`.
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
/// A batch holds one subject, one action, and one request context evaluated
/// against many resources.
pub struct BatchEvalCtx<'a, D: PolicyDomain> {
    /// Request-scoped fact session.
    pub session: &'a EvaluationSession,
    /// Entity requesting access.
    pub subject: &'a D::Subject,
    /// Action being performed, shared across every item in the batch.
    pub action: &'a D::Action,
    /// Request-scoped context, shared across every item in the batch.
    pub context: &'a D::Context,
    /// Borrowed resources.
    pub items: &'a [PolicyBatchItem<'a, D>],
    /// The current policy's [`Policy::policy_type`].
    pub policy_type: Cow<'static, str>,
}

/// A generic async trait representing a single authorization policy for one
/// [`PolicyDomain`].
#[async_trait]
pub trait Policy<D: PolicyDomain>: Send + Sync {
    /// Evaluates whether access should be granted.
    async fn evaluate(&self, ctx: &EvalCtx<'_, D>) -> PolicyEvalResult;

    /// Evaluates access for a batch of resources.
    ///
    /// The default implementation preserves single-item semantics by evaluating
    /// each item sequentially. Policies with set-oriented backends can override
    /// this method to reduce round trips while returning one result per input
    /// item in the same order.
    async fn evaluate_batch<'item>(&self, ctx: &BatchEvalCtx<'item, D>) -> Vec<PolicyEvalResult> {
        let mut results = Vec::with_capacity(ctx.items.len());
        for item in ctx.items {
            let item_ctx = EvalCtx {
                session: ctx.session,
                subject: ctx.subject,
                action: ctx.action,
                resource: item.resource,
                context: ctx.context,
                policy_type: ctx.policy_type.clone(),
            };
            results.push(self.evaluate(&item_ctx).await);
        }
        results
    }

    /// Policy name for debugging, trace trees, and telemetry fallbacks.
    fn policy_type(&self) -> Cow<'static, str>;

    /// The declared effect of this policy. Defaults to [`Effect::Allow`].
    ///
    /// [`crate::PermissionChecker`] reads this declaration when the policy is
    /// added. Policies declaring [`Effect::Forbid`] or
    /// [`Effect::AllowOrForbid`] run before allow-only policies, so a matched
    /// forbid is observed before a grant can short-circuit.
    ///
    /// A policy that returns [`PolicyEvalResult::Forbidden`] while leaving this
    /// at the default [`Effect::Allow`] still vetoes wherever it is observed,
    /// but the checker emits a contract-violation `WARN`: the veto is not
    /// scheduled ahead of grants and an earlier grant can short-circuit before
    /// it is reached. Declare [`Effect::Forbid`] or [`Effect::AllowOrForbid`]
    /// for an order-independent veto.
    fn effect(&self) -> Effect {
        Effect::Allow
    }

    /// Metadata describing the security rule that backs this policy.
    fn security_rule(&self) -> SecurityRuleMetadata {
        SecurityRuleMetadata::default()
    }
}

#[async_trait]
impl<D> Policy<D> for Box<dyn Policy<D>>
where
    D: PolicyDomain,
{
    async fn evaluate(&self, ctx: &EvalCtx<'_, D>) -> PolicyEvalResult {
        (**self).evaluate(ctx).await
    }

    async fn evaluate_batch<'item>(&self, ctx: &BatchEvalCtx<'item, D>) -> Vec<PolicyEvalResult> {
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

#[async_trait]
impl<D> Policy<D> for Arc<dyn Policy<D>>
where
    D: PolicyDomain,
{
    async fn evaluate(&self, ctx: &EvalCtx<'_, D>) -> PolicyEvalResult {
        (**self).evaluate(ctx).await
    }

    async fn evaluate_batch<'item>(&self, ctx: &BatchEvalCtx<'item, D>) -> Vec<PolicyEvalResult> {
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
