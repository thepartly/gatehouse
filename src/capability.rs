use crate::{
    BatchEvalCtx, CombineOp, Decision, EvalCtx, FactProvenance, PolicyDomain, PolicyEvalResult,
    SecurityRuleMetadata,
};
use async_trait::async_trait;
use std::{borrow::Cow, sync::Arc};

/// A grant policy's authority-bearing result. Its audit tree is read-only.
///
/// ```compile_fail
/// use gatehouse::{GrantResult, PolicyEvalResult};
/// let result: GrantResult = PolicyEvalResult::forbidden("blocked", "disabled").into();
/// ```
#[derive(Clone, Debug)]
pub struct GrantResult(pub(crate) PolicyEvalResult);

/// A veto policy's authority-bearing result. It cannot grant access.
#[derive(Clone, Debug)]
pub struct VetoResult(pub(crate) PolicyEvalResult);

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::GrantResult {}
    impl Sealed for super::VetoResult {}
    impl Sealed for crate::PolicyEvalResult {}
}

/// Results accepted by recording contexts. Implementations are sealed.
pub trait PolicyResult: sealed::Sealed {
    /// Consumes the result into its audit tree.
    fn into_trace(self) -> PolicyEvalResult;
    /// Attaches context-recorded evidence without changing the result capability.
    fn attach_recorded(self, recorded: Vec<FactProvenance>) -> Self;
}

impl PolicyResult for PolicyEvalResult {
    fn into_trace(self) -> PolicyEvalResult {
        self
    }
    fn attach_recorded(self, recorded: Vec<FactProvenance>) -> Self {
        crate::policy::attach_recorded(self, recorded)
    }
}

macro_rules! shared_result {
    ($name:ident) => {
        impl $name {
            /// Returns the immutable audit tree.
            pub fn trace(&self) -> &PolicyEvalResult {
                &self.0
            }
            /// Returns the aggregate decision.
            pub fn decision(&self) -> Decision {
                self.0.decision()
            }
            /// Returns the policy name.
            pub fn policy_type(&self) -> &str {
                self.0.policy_type()
            }
            /// Returns the reason attached to the result.
            pub fn reason(&self) -> Option<String> {
                self.0.reason()
            }
            /// Returns facts attached to this node.
            pub fn provenance(&self) -> &[FactProvenance] {
                self.0.provenance()
            }
            /// Creates an indeterminate result.
            pub fn indeterminate(
                policy_type: impl Into<Cow<'static, str>>,
                reason: impl Into<String>,
            ) -> Self {
                Self(PolicyEvalResult::indeterminate(policy_type, reason))
            }
            /// Creates an indeterminate result with explicit evidence.
            pub fn indeterminate_with_facts(
                policy_type: impl Into<Cow<'static, str>>,
                reason: impl Into<String>,
                provenance: Vec<FactProvenance>,
            ) -> Self {
                Self(PolicyEvalResult::indeterminate_with_facts(
                    policy_type,
                    reason,
                    provenance,
                ))
            }
        }
    };
}
shared_result!(GrantResult);
shared_result!(VetoResult);

impl PolicyResult for GrantResult {
    fn into_trace(self) -> PolicyEvalResult {
        self.0
    }
    fn attach_recorded(self, recorded: Vec<FactProvenance>) -> Self {
        Self(crate::policy::attach_recorded(self.0, recorded))
    }
}
impl PolicyResult for VetoResult {
    fn into_trace(self) -> PolicyEvalResult {
        self.0
    }
    fn attach_recorded(self, recorded: Vec<FactProvenance>) -> Self {
        Self(crate::policy::attach_recorded(self.0, recorded))
    }
}
impl GrantResult {
    /// Creates a grant.
    pub fn granted(policy_type: impl Into<Cow<'static, str>>, reason: Option<String>) -> Self {
        Self(PolicyEvalResult::granted(policy_type, reason))
    }
    /// Creates a grant with explicit evidence.
    pub fn granted_with_facts(
        policy_type: impl Into<Cow<'static, str>>,
        reason: Option<String>,
        provenance: Vec<FactProvenance>,
    ) -> Self {
        Self(PolicyEvalResult::granted_with_facts(
            policy_type,
            reason,
            provenance,
        ))
    }
    /// Creates an abstention.
    pub fn not_applicable(
        policy_type: impl Into<Cow<'static, str>>,
        reason: impl Into<String>,
    ) -> Self {
        Self(PolicyEvalResult::not_applicable(policy_type, reason))
    }
    /// Creates an abstention with explicit evidence.
    pub fn not_applicable_with_facts(
        policy_type: impl Into<Cow<'static, str>>,
        reason: impl Into<String>,
        provenance: Vec<FactProvenance>,
    ) -> Self {
        Self(PolicyEvalResult::not_applicable_with_facts(
            policy_type,
            reason,
            provenance,
        ))
    }
    /// Whether this policy granted.
    pub fn is_granted(&self) -> bool {
        self.0.is_granted()
    }
    /// Combines grant results with AND semantics. An empty conjunction abstains.
    pub fn all(policy_type: impl Into<Cow<'static, str>>, children: Vec<Self>) -> Self {
        let decision = if children.is_empty()
            || children
                .iter()
                .any(|child| child.decision() == Decision::NotApplicable)
        {
            Decision::NotApplicable
        } else if children
            .iter()
            .any(|child| child.decision() == Decision::Indeterminate)
        {
            Decision::Indeterminate
        } else {
            Decision::Grant
        };
        Self(combined(
            policy_type,
            CombineOp::And,
            children.into_iter().map(|child| child.0).collect(),
            decision,
        ))
    }
    /// Combines grant results with OR semantics. An empty disjunction abstains.
    pub fn any(policy_type: impl Into<Cow<'static, str>>, children: Vec<Self>) -> Self {
        let decision = if children.iter().any(Self::is_granted) {
            Decision::Grant
        } else if children
            .iter()
            .any(|child| child.decision() == Decision::Indeterminate)
        {
            Decision::Indeterminate
        } else {
            Decision::NotApplicable
        };
        Self(combined(
            policy_type,
            CombineOp::Or,
            children.into_iter().map(|child| child.0).collect(),
            decision,
        ))
    }
}
impl VetoResult {
    /// Creates a definite veto.
    pub fn forbid(policy_type: impl Into<Cow<'static, str>>, reason: impl Into<String>) -> Self {
        Self(PolicyEvalResult::forbidden(policy_type, reason))
    }
    /// Creates a definite veto with explicit evidence.
    pub fn forbid_with_facts(
        policy_type: impl Into<Cow<'static, str>>,
        reason: impl Into<String>,
        provenance: Vec<FactProvenance>,
    ) -> Self {
        Self(PolicyEvalResult::forbidden_with_facts(
            policy_type,
            reason,
            provenance,
        ))
    }
    /// Passes without granting any authority.
    pub fn pass(policy_type: impl Into<Cow<'static, str>>, reason: impl Into<String>) -> Self {
        Self(PolicyEvalResult::not_applicable(policy_type, reason))
    }
    /// Passes with explicit evidence.
    pub fn pass_with_facts(
        policy_type: impl Into<Cow<'static, str>>,
        reason: impl Into<String>,
        provenance: Vec<FactProvenance>,
    ) -> Self {
        Self(PolicyEvalResult::not_applicable_with_facts(
            policy_type,
            reason,
            provenance,
        ))
    }
    /// Whether this policy vetoed.
    pub fn is_forbidden(&self) -> bool {
        self.decision() == Decision::Forbid
    }
}

pub(crate) fn combined(
    policy_type: impl Into<Cow<'static, str>>,
    operation: CombineOp,
    children: Vec<PolicyEvalResult>,
    decision: Decision,
) -> PolicyEvalResult {
    PolicyEvalResult::Combined {
        provenance: Vec::new(),
        policy_type: policy_type.into(),
        operation,
        children,
        decision,
    }
}

/// A policy that can veto or pass, but cannot grant.
#[async_trait]
pub trait VetoPolicy<D: PolicyDomain>: Send + Sync {
    /// Evaluates the veto for one resource.
    async fn evaluate(&self, ctx: &EvalCtx<'_, D>) -> VetoResult;
    /// Returns one result per input, in the same order.
    async fn evaluate_batch<'item>(&self, ctx: &BatchEvalCtx<'item, D>) -> Vec<VetoResult> {
        let mut results = Vec::with_capacity(ctx.items.len());
        for item in ctx.items {
            let inner = EvalCtx::new(
                ctx.session(),
                ctx.subject,
                ctx.action,
                item.resource,
                ctx.context,
                ctx.policy_type.clone(),
            );
            let result = self.evaluate(&inner).await;
            results.push(inner.finish(result));
        }
        results
    }
    /// Name for audit trees and telemetry.
    fn policy_type(&self) -> Cow<'static, str>;
    /// Security-rule metadata.
    fn security_rule(&self) -> SecurityRuleMetadata {
        SecurityRuleMetadata::default()
    }
}
macro_rules! forward_veto {
    ($container:ident) => {
        #[async_trait]
        impl<D: PolicyDomain> VetoPolicy<D> for $container<dyn VetoPolicy<D>> {
            async fn evaluate(&self, ctx: &EvalCtx<'_, D>) -> VetoResult {
                (**self).evaluate(ctx).await
            }
            async fn evaluate_batch<'item>(&self, ctx: &BatchEvalCtx<'item, D>) -> Vec<VetoResult> {
                (**self).evaluate_batch(ctx).await
            }
            fn policy_type(&self) -> Cow<'static, str> {
                (**self).policy_type()
            }
            fn security_rule(&self) -> SecurityRuleMetadata {
                (**self).security_rule()
            }
        }
    };
}
forward_veto!(Box);
forward_veto!(Arc);
