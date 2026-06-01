use crate::{EvalCtx, Policy, PolicyEvalResult};
use async_trait::async_trait;

/// An attribute-based access control policy.
/// Define a `condition` closure that determines whether a subject is allowed to
/// perform an action on a resource, given the additional context. If it returns
/// true, access is granted. Otherwise, access is denied.
///
/// ## Example
///
/// We define simple types for a user, a resource, an action, and a context.
/// We then create a built-in ABAC policy that grants access if the user "owns"
/// a resource as determined by the resource's owner_id.
///
/// ```rust
/// # use async_trait::async_trait;
/// # use std::sync::Arc;
/// # use uuid::Uuid;
/// # use gatehouse::*;
///
/// // Define our core types.
/// #[derive(Debug, Clone)]
/// struct User {
///     id: Uuid,
/// }
///
/// #[derive(Debug, Clone)]
/// struct Resource {
///     owner_id: Uuid,
/// }
///
/// #[derive(Debug, Clone)]
/// struct Action;
///
/// #[derive(Debug, Clone)]
/// struct EmptyContext;
///
/// // Create an ABAC policy.
/// // This policy grants access if the user's ID matches the resource's owner.
/// let abac_policy = AbacPolicy::new(
///     |user: &User, resource: &Resource, _action: &Action, _context: &EmptyContext| {
///         user.id == resource.owner_id
///     },
/// );
///
/// // Create a PermissionChecker and add the ABAC policy.
/// let mut checker = PermissionChecker::<User, Resource, Action, EmptyContext>::new();
/// checker.add_policy(abac_policy);
///
/// // Create a sample user
/// let user = User {
///     id: Uuid::new_v4(),
/// };
///
/// // Create a resource owned by the user, and one that is not
/// let owned_resource = Resource { owner_id: user.id };
/// let other_resource = Resource { owner_id: Uuid::new_v4() };
/// let context = EmptyContext;
/// let session = EvaluationSession::empty();
///
/// # tokio_test::block_on(async {
/// // This check should succeed because the user is the owner:
/// assert!(checker.evaluate_in_session(&session, &user, &Action, &owned_resource, &context).await.is_granted());
///
/// // This check should fail because the user is not the owner:
/// assert!(!checker.evaluate_in_session(&session, &user, &Action, &other_resource, &context).await.is_granted());
/// # });
/// ```
///
pub struct AbacPolicy<S, R, A, C, F> {
    condition: F,
    _marker: std::marker::PhantomData<(S, R, A, C)>,
}

impl<S, R, A, C, F> AbacPolicy<S, R, A, C, F> {
    /// Creates a new ABAC policy from a condition closure.
    pub fn new(condition: F) -> Self {
        Self {
            condition,
            _marker: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<S, R, A, C, F> Policy<S, R, A, C> for AbacPolicy<S, R, A, C, F>
where
    S: Sync + Send,
    R: Sync + Send,
    A: Sync + Send,
    C: Sync + Send,
    F: Fn(&S, &R, &A, &C) -> bool + Sync + Send,
{
    async fn evaluate(&self, ctx: &EvalCtx<'_, S, R, A, C>) -> PolicyEvalResult {
        let condition_met = (self.condition)(ctx.subject, ctx.resource, ctx.action, ctx.context);

        if condition_met {
            ctx.grant("Condition evaluated to true")
        } else {
            ctx.deny("Condition evaluated to false")
        }
    }

    fn policy_type(&self) -> &str {
        "AbacPolicy"
    }
}
