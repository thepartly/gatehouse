use crate::{EvalCtx, Policy, PolicyDomain, PolicyEvalResult};
use async_trait::async_trait;
use std::marker::PhantomData;

/// Role-based access control policy.
///
/// The required-role resolver receives `(action, resource)` and the
/// subject-role resolver receives the subject. Access is granted when the
/// subject holds at least one required role.
pub struct RbacPolicy<D: PolicyDomain, F1, F2> {
    required_roles_resolver: F1,
    subject_roles_resolver: F2,
    _domain: PhantomData<D>,
}

impl<D: PolicyDomain, F1, F2> RbacPolicy<D, F1, F2> {
    /// Creates an RBAC policy from required-role and subject-role resolvers.
    pub fn new(required_roles_resolver: F1, subject_roles_resolver: F2) -> Self {
        Self {
            required_roles_resolver,
            subject_roles_resolver,
            _domain: PhantomData,
        }
    }
}

#[async_trait]
impl<D, F1, F2, RoleId> Policy<D> for RbacPolicy<D, F1, F2>
where
    D: PolicyDomain,
    RoleId: PartialEq,
    F1: Fn(&D::Action, &D::Resource) -> Vec<RoleId> + Sync + Send,
    F2: Fn(&D::Subject) -> Vec<RoleId> + Sync + Send,
{
    async fn evaluate(&self, ctx: &EvalCtx<'_, D>) -> PolicyEvalResult {
        let required_roles = (self.required_roles_resolver)(ctx.action, ctx.resource);
        let subject_roles = (self.subject_roles_resolver)(ctx.subject);
        let has_role = required_roles
            .iter()
            .any(|role| subject_roles.contains(role));

        if has_role {
            ctx.grant("User has required role")
        } else {
            ctx.not_applicable("User doesn't have required role")
        }
    }

    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("RbacPolicy")
    }
}
