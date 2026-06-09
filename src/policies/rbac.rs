use crate::{EvalCtx, Policy, PolicyEvalResult};
use async_trait::async_trait;

/// A role-based access control policy.
///
/// `required_roles_resolver` is a closure that determines which roles are required
/// for the given (resource, action). `user_roles_resolver` extracts the subject's roles.
/// Access is granted if the subject holds at least one of the required roles.
///
/// The role identifier type is generic — any `PartialEq` type works. Use a
/// domain enum when the role set is closed (the compiler then checks role
/// names), string ids when roles are configuration-driven, or
/// [`Uuid`](uuid::Uuid)s when integrating with an external identity system.
/// The two resolver closures must agree on the same role type; it is
/// inferred from their return types.
///
/// # Example
///
/// ```rust
/// # use gatehouse::*;
/// # use uuid::Uuid;
/// #[derive(Debug, Clone)]
/// struct User { role_ids: Vec<Uuid> }
/// #[derive(Debug, Clone)]
/// struct Resource;
/// #[derive(Debug, Clone)]
/// struct Action;
/// #[derive(Debug, Clone)]
/// struct Ctx;
///
/// let editor_role = Uuid::new_v4();
///
/// let rbac = RbacPolicy::new(
///     // required_roles_resolver: which roles can access this resource/action?
///     move |_resource: &Resource, _action: &Action| vec![editor_role],
///     // user_roles_resolver: which roles does this user have?
///     |user: &User| user.role_ids.clone(),
/// );
///
/// let mut checker = PermissionChecker::new();
/// checker.add_policy(rbac);
///
/// # tokio_test::block_on(async {
/// let session = EvaluationSession::empty();
/// let authorised = User { role_ids: vec![editor_role] };
/// assert!(checker.evaluate_in_session(&session, &authorised, &Action, &Resource, &Ctx).await.is_granted());
///
/// let unauthorised = User { role_ids: vec![Uuid::new_v4()] };
/// assert!(!checker.evaluate_in_session(&session, &unauthorised, &Action, &Resource, &Ctx).await.is_granted());
/// # });
/// ```
///
/// With a domain role enum instead of `Uuid`s:
///
/// ```rust
/// # use gatehouse::*;
/// #[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// enum Role { Admin, Editor }
/// #[derive(Debug, Clone)]
/// struct User { roles: Vec<Role> }
/// # #[derive(Debug, Clone)]
/// # struct Resource;
/// # #[derive(Debug, Clone)]
/// # struct Action;
///
/// let rbac = RbacPolicy::new(
///     |_resource: &Resource, _action: &Action| vec![Role::Admin, Role::Editor],
///     |user: &User| user.roles.clone(),
/// );
///
/// let mut checker = PermissionChecker::new();
/// checker.add_policy(rbac);
///
/// # tokio_test::block_on(async {
/// let editor = User { roles: vec![Role::Editor] };
/// assert!(checker.check(&editor, &Action, &Resource, &()).await.is_granted());
/// # });
/// ```
pub struct RbacPolicy<S, F1, F2> {
    required_roles_resolver: F1,
    user_roles_resolver: F2,
    _marker: std::marker::PhantomData<S>,
}

impl<S, F1, F2> RbacPolicy<S, F1, F2> {
    /// Creates a new RBAC policy from two resolver closures.
    pub fn new(required_roles_resolver: F1, user_roles_resolver: F2) -> Self {
        Self {
            required_roles_resolver,
            user_roles_resolver,
            _marker: std::marker::PhantomData,
        }
    }
}

// `RoleId` is constrained through the closures' `Fn(...) -> Vec<RoleId>`
// output bindings, so it is inferred from the resolvers rather than being a
// parameter on the struct. `PartialEq` is the only capability the policy
// needs (the `contains` check below).
#[async_trait]
impl<S, R, A, C, F1, F2, RoleId> Policy<S, R, A, C> for RbacPolicy<S, F1, F2>
where
    S: Sync + Send,
    R: Sync + Send,
    A: Sync + Send,
    C: Sync + Send,
    RoleId: PartialEq,
    F1: Fn(&R, &A) -> Vec<RoleId> + Sync + Send,
    F2: Fn(&S) -> Vec<RoleId> + Sync + Send,
{
    async fn evaluate(&self, ctx: &EvalCtx<'_, S, R, A, C>) -> PolicyEvalResult {
        let required_roles = (self.required_roles_resolver)(ctx.resource, ctx.action);
        let user_roles = (self.user_roles_resolver)(ctx.subject);
        let has_role = required_roles.iter().any(|role| user_roles.contains(role));

        if has_role {
            ctx.grant("User has required role")
        } else {
            ctx.deny("User doesn't have required role")
        }
    }

    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("RbacPolicy")
    }
}
