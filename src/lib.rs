//! A flexible authorization library that combines role‐based (RBAC),
//! attribute‐based (ABAC), and relationship‐based (ReBAC) policies.
//! It also provides combinators (AndPolicy, OrPolicy, NotPolicy) for
//! composing complex authorization logic.
//!
//! # Overview
//!
//! A *Policy* is an asynchronous decision unit that checks if a given subject may
//! perform an action on a resource within a given context. Policies implement the
//! [`Policy`] trait. A [`PermissionChecker`] aggregates multiple policies and uses OR
//! logic by default (i.e. if any policy grants access, then access is allowed).
//!
//! ## Policies
//!
//! Below we define a simple system where a user may read a document if they
//! are an admin (via a simple role-based policy) or if they are the owner of the document (via
//! an attribute-based policy).
//!
//! ```rust
//! # use uuid::Uuid;
//! # use async_trait::async_trait;
//! # use std::sync::Arc;
//! # use permissions::*;
//!
//! // Define our core types.
//! #[derive(Debug, Clone)]
//! pub struct User {
//!     pub id: Uuid,
//!     pub roles: Vec<String>,
//! }
//!
//! #[derive(Debug, Clone)]
//! pub struct Document {
//!     pub id: Uuid,
//!     pub owner_id: Uuid,
//! }
//!
//! #[derive(Debug, Clone)]
//! pub struct ReadAction;
//!
//! #[derive(Debug, Clone)]
//! pub struct EmptyContext;
//!
//! // A simple RBAC policy: grant access if the user has the "admin" role.
//! struct AdminPolicy;
//! #[async_trait]
//! impl Policy<User, Document, ReadAction, EmptyContext> for AdminPolicy {
//!     async fn evaluate_access(
//!         &self,
//!         user: &User,
//!         _action: &ReadAction,
//!         _resource: &Document,
//!         _context: &EmptyContext,
//!     ) -> PolicyEvalResult {
//!         if user.roles.contains(&"admin".to_string()) {
//!             PolicyEvalResult::Granted {
//!                 policy_type: self.policy_type(),
//!                 reason: Some("User is admin".to_string()),
//!             }
//!         } else {
//!             PolicyEvalResult::Denied {
//!                 policy_type: self.policy_type(),
//!                 reason: "User is not admin".to_string(),
//!             }
//!         }
//!     }
//! }
//!
//! // An ABAC policy: grant access if the user is the owner of the document.
//! struct OwnerPolicy;
//!
//! #[async_trait]
//! impl Policy<User, Document, ReadAction, EmptyContext> for OwnerPolicy {
//!     async fn evaluate_access(
//!         &self,
//!         user: &User,
//!         _action: &ReadAction,
//!         document: &Document,
//!         _context: &EmptyContext,
//!     ) -> PolicyEvalResult {
//!         if user.id == document.owner_id {
//!             PolicyEvalResult::Granted {
//!                 policy_type: self.policy_type(),
//!                 reason: Some("User is the owner".to_string()),
//!             }
//!         } else {
//!             PolicyEvalResult::Denied {
//!                policy_type: self.policy_type(),
//!                reason: "User is not the owner".to_string(),
//!            }
//!         }
//!     }
//! }
//!
//! // Create a PermissionChecker (which uses OR semantics by default) and add both policies.
//! fn create_document_checker() -> PermissionChecker<User, Document, ReadAction, EmptyContext> {
//!     let mut checker = PermissionChecker::new();
//!     checker.add_policy(AdminPolicy);
//!     checker.add_policy(OwnerPolicy);
//!     checker
//! }
//!
//! # tokio_test::block_on(async {
//! let admin_user = User {
//!     id: Uuid::new_v4(),
//!     roles: vec!["admin".into()],
//! };
//!
//! let owner_user = User {
//!     id: Uuid::new_v4(),
//!     roles: vec!["user".into()],
//! };
//!
//! let document = Document {
//!     id: Uuid::new_v4(),
//!     owner_id: owner_user.id,
//! };
//!
//! let checker = create_document_checker();
//!
//! // An admin should have access.
//! assert!(checker.evaluate_access(&admin_user, &ReadAction, &document, &EmptyContext).await.is_granted());
//!
//! // The owner should have access.
//! assert!(checker.evaluate_access(&owner_user, &ReadAction, &document, &EmptyContext).await.is_granted());
//!
//! // A random user should be denied access.
//! let random_user = User {
//!     id: Uuid::new_v4(),
//!     roles: vec!["user".into()],
//! };
//! assert!(!checker.evaluate_access(&random_user, &ReadAction, &document, &EmptyContext).await.is_granted());
//! # });
//! ```
//!
//! # Evaluation Tracing
//!
//! The permission system provides detailed tracing of policy decisions, see [`AccessEvaluation`]\
//! for an example.
//!
//!
//! ## Combinators
//!
//! Sometimes you may want to require that several policies pass (AND), require that
//! at least one passes (OR), or even invert a policy (NOT). `permissions` provides:
//!
//! - [`AndPolicy`]: Grants access only if all inner policies allow access. Otherwise,
//!   returns a combined error.
//! - [`OrPolicy`]: Grants access if any inner policy allows access; otherwise returns a
//!   combined error.
//! - [`NotPolicy`]: Inverts the decision of an inner policy.
//!
//!
//! ## Built in Policies
//! The library provides a few built-in policies:
//!  - [`RbacPolicy`]: A role-based access control policy.
//!  - [`AbacPolicy`]: An attribute-based access control policy.
//!  - [`RebacPolicy`]: A relationship-based access control policy.
//!

use async_trait::async_trait;
use std::fmt;
use std::sync::Arc;

/// Internal result of evaluating a single policy or a combination of policies
#[derive(Debug, Clone)]
pub enum PolicyEvalResult {
    Granted {
        policy_type: String,
        reason: Option<String>,
    },
    Denied {
        policy_type: String,
        reason: String,
    },
    Combined {
        policy_type: String,
        operation: String, // "AND", "OR", "NOT"
        children: Vec<PolicyEvalResult>,
        outcome: bool,
    },
}

/// Access evaluation result
///
/// Complete result of a permission evaluation that includes
/// both success and failure cases with detailed tracing.
///
/// ### Evaluation Tracing
///
/// The permission system provides detailed tracing of policy decisions:
/// ```rust
/// # use permissions::*;
/// # use uuid::Uuid;
/// #
/// # // Define simple types for the example
/// # #[derive(Debug, Clone)]
/// # struct User { id: Uuid }
/// # #[derive(Debug, Clone)]
/// # struct Document { id: Uuid }
/// # #[derive(Debug, Clone)]
/// # struct ReadAction;
/// # #[derive(Debug, Clone)]
/// # struct EmptyContext;
/// #
/// # async fn example() -> AccessEvaluation {
/// #     let mut checker = PermissionChecker::<User, Document, ReadAction, EmptyContext>::new();
/// #     let user = User { id: Uuid::new_v4() };
/// #     let document = Document { id: Uuid::new_v4() };
/// #     checker.evaluate_access(&user, &ReadAction, &document, &EmptyContext).await
/// # }
/// #
/// # tokio_test::block_on(async {
/// let result = example().await;
///
/// match result {
///     AccessEvaluation::Granted { policy_type, reason, trace } => {
///         println!("Access granted by {}: {:?}", policy_type, reason);
///         println!("Full evaluation trace:\n{}", trace.format());
///     }
///     AccessEvaluation::Denied { reason, trace } => {
///         println!("Access denied: {}", reason);
///         println!("Full evaluation trace:\n{}", trace.format());
///     }
/// }
/// # });
/// ```
#[derive(Debug, Clone)]
pub enum AccessEvaluation {
    Granted {
        /// The policy that granted access
        policy_type: String,
        /// Optional reason for granting
        reason: Option<String>,
        /// Full evaluation trace including any rejected policies
        trace: EvalTrace,
    },
    Denied {
        /// The complete evaluation trace showing all policy decisions
        trace: EvalTrace,
        /// Summary reason for denial
        reason: String,
    },
}

impl AccessEvaluation {
    /// Whether access was granted
    pub fn is_granted(&self) -> bool {
        matches!(self, Self::Granted { .. })
    }

    /// Helper method to convert to Result type
    pub fn to_result<E>(&self, error_fn: impl FnOnce(&str) -> E) -> Result<(), E> {
        match self {
            Self::Granted { .. } => Ok(()),
            Self::Denied { reason, .. } => Err(error_fn(reason)),
        }
    }
}
/// Container for the evaluation tree
/// Detailed trace of all policy evaluations
#[derive(Debug, Clone, Default)]
pub struct EvalTrace {
    root: Option<PolicyEvalResult>,
}

impl EvalTrace {
    pub fn new() -> Self {
        Self { root: None }
    }

    pub fn with_root(result: PolicyEvalResult) -> Self {
        Self { root: Some(result) }
    }

    pub fn set_root(&mut self, result: PolicyEvalResult) {
        self.root = Some(result);
    }

    pub fn root(&self) -> Option<&PolicyEvalResult> {
        self.root.as_ref()
    }

    /// Returns a formatted representation of the evaluation tree
    pub fn format(&self) -> String {
        match &self.root {
            Some(root) => root.format(0),
            None => "No evaluation trace available".to_string(),
        }
    }
}

impl PolicyEvalResult {
    /// Returns whether this evaluation resulted in access being granted
    pub fn outcome(&self) -> bool {
        match self {
            Self::Granted { .. } => true,
            Self::Denied { .. } => false,
            Self::Combined { outcome, .. } => *outcome,
        }
    }

    /// Returns the reason string if available
    pub fn reason(&self) -> Option<String> {
        match self {
            Self::Granted { reason, .. } => reason.clone(),
            Self::Denied { reason, .. } => Some(reason.clone()),
            Self::Combined { .. } => None,
        }
    }

    /// Formats the evaluation tree with indentation for readability
    pub fn format(&self, indent: usize) -> String {
        let indent_str = " ".repeat(indent);
        match self {
            Self::Granted {
                policy_type,
                reason,
            } => {
                let reason_text = reason
                    .as_ref()
                    .map_or("".to_string(), |r| format!(": {}", r));
                format!("{}✓ {} GRANTED{}", indent_str, policy_type, reason_text)
            }
            Self::Denied {
                policy_type,
                reason,
            } => {
                format!("{}✗ {} DENIED: {}", indent_str, policy_type, reason)
            }
            Self::Combined {
                policy_type,
                operation,
                children,
                outcome,
            } => {
                let outcome_char = if *outcome { "✓" } else { "✗" };
                let mut result = format!(
                    "{}{} {} ({})",
                    indent_str, outcome_char, policy_type, operation
                );

                for child in children {
                    result.push_str(&format!("\n{}", child.format(indent + 2)));
                }
                result
            }
        }
    }
}

/// A generic async Policy trait representing a single authorization policy.
///
/// Each `Policy` must implement the `evaluate_access` method, which returns an
/// `PolicyEvalResult`.
#[async_trait]
pub trait Policy<Subject, Resource, Action, Context>: Send + Sync {
    /// Check whether access is allowed, with detailed evaluation results
    /// Determines if `subject` is allowed to perform `action` on `resource`,
    /// potentially taking additional context into account.
    async fn evaluate_access(
        &self,
        subject: &Subject,
        action: &Action,
        resource: &Resource,
        context: &Context,
    ) -> PolicyEvalResult;

    /// Policy type name for debugging
    fn policy_type(&self) -> String {
        std::any::type_name::<Self>()
            .split("::")
            .last()
            .unwrap_or("Unknown")
            .to_string()
    }
}

/// A unified interface for context used during permissions checks.
pub trait PermissionContext: fmt::Debug + Send + Sync {}

/// A trait for resources in a permission check.
pub trait PermissionResource: fmt::Debug + Send + Sync {}

/// A trait for actions in a permission check.
pub trait PermissionAction: fmt::Debug + Send + Sync {}

/// A container for multiple policies, applied in an "OR" fashion.
/// (If any policy returns Ok, access is granted)
/// **Important**:
/// If no policies are added, access is always denied.
pub struct PermissionChecker<S, R, A, C> {
    policies: Vec<std::sync::Arc<dyn Policy<S, R, A, C>>>,
}

impl<S, R, A, C> Default for PermissionChecker<S, R, A, C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S, R, A, C> PermissionChecker<S, R, A, C> {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    pub fn add_policy<P: Policy<S, R, A, C> + 'static>(&mut self, policy: P) {
        self.policies.push(std::sync::Arc::new(policy));
    }

    /// Evaluates the subject/resource/action/context against all policies.
    ///
    /// Returns full trace of evaluation.
    #[tracing::instrument(skip_all)]
    pub async fn evaluate_access(
        &self,
        subject: &S,
        action: &A,
        resource: &R,
        context: &C,
    ) -> AccessEvaluation {
        if self.policies.is_empty() {
            tracing::debug!("No policies configured");
            let result = PolicyEvalResult::Denied {
                policy_type: "PermissionChecker".to_string(),
                reason: "No policies configured".to_string(),
            };

            return AccessEvaluation::Denied {
                trace: EvalTrace::with_root(result),
                reason: "No policies configured".to_string(),
            };
        }
        tracing::trace!(num_policies = self.policies.len(), "Checking access");

        let mut policy_results = Vec::new();

        // Evaluate each policy
        for policy in &self.policies {
            let result = policy
                .evaluate_access(subject, action, resource, context)
                .await;
            let result_passes = result.outcome();
            policy_results.push(result.clone());

            // If any policy allows access, return immediately
            if result_passes {
                let combined = PolicyEvalResult::Combined {
                    policy_type: "PermissionChecker".to_string(),
                    operation: "OR".to_string(),
                    children: policy_results,
                    outcome: true,
                };

                return AccessEvaluation::Granted {
                    policy_type: policy.policy_type(),
                    reason: result.reason(),
                    trace: EvalTrace::with_root(combined),
                };
            }
        }

        // If all policies denied access
        tracing::trace!("No policies allowed access, returning Forbidden");
        let combined = PolicyEvalResult::Combined {
            policy_type: "PermissionChecker".to_string(),
            operation: "OR".to_string(),
            children: policy_results,
            outcome: false,
        };

        AccessEvaluation::Denied {
            trace: EvalTrace::with_root(combined),
            reason: "All policies denied access".to_string(),
        }
    }
}

/// A role-based access control policy.
///
/// `required_roles_resolver` is a closure that determines which roles are required
/// for the given (resource, action). `user_roles_resolver` extracts the subject's roles.
pub struct RbacPolicy<S, F1, F2> {
    required_roles_resolver: F1,
    user_roles_resolver: F2,
    _marker: std::marker::PhantomData<S>,
}

impl<S, F1, F2> RbacPolicy<S, F1, F2> {
    pub fn new(required_roles_resolver: F1, user_roles_resolver: F2) -> Self {
        Self {
            required_roles_resolver,
            user_roles_resolver,
            _marker: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<S, R, A, C, F1, F2> Policy<S, R, A, C> for RbacPolicy<S, F1, F2>
where
    S: Sync + Send,
    R: Sync + Send,
    A: Sync + Send,
    C: Sync + Send,
    F1: Fn(&R, &A) -> Vec<uuid::Uuid> + Sync + Send,
    F2: Fn(&S) -> Vec<uuid::Uuid> + Sync + Send,
{
    async fn evaluate_access(
        &self,
        subject: &S,
        action: &A,
        resource: &R,
        _context: &C,
    ) -> PolicyEvalResult {
        let required_roles = (self.required_roles_resolver)(resource, action);
        let user_roles = (self.user_roles_resolver)(subject);
        let has_role = required_roles.iter().any(|role| user_roles.contains(role));

        if has_role {
            PolicyEvalResult::Granted {
                policy_type: Policy::<S, R, A, C>::policy_type(self),
                reason: Some("User has required role".to_string()),
            }
        } else {
            PolicyEvalResult::Denied {
                policy_type: Policy::<S, R, A, C>::policy_type(self),
                reason: "User doesn't have required role".to_string(),
            }
        }
    }
}

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
/// # use permissions::*;
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
///
/// # tokio_test::block_on(async {
/// // This check should succeed because the user is the owner:
/// assert!(checker.evaluate_access(&user, &Action, &owned_resource, &context).await.is_granted());
///
/// // This check should fail because the user is not the owner:
/// assert!(checker.evaluate_access(&user, &Action, &other_resource, &context).await.is_granted() == false);
/// # });
/// ```
///
pub struct AbacPolicy<S, R, A, C, F> {
    condition: F,
    _marker: std::marker::PhantomData<(S, R, A, C)>,
}

impl<S, R, A, C, F> AbacPolicy<S, R, A, C, F> {
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
    async fn evaluate_access(
        &self,
        subject: &S,
        action: &A,
        resource: &R,
        context: &C,
    ) -> PolicyEvalResult {
        let condition_met = (self.condition)(subject, resource, action, context);

        if condition_met {
            PolicyEvalResult::Granted {
                policy_type: self.policy_type(),
                reason: Some("Condition evaluated to true".to_string()),
            }
        } else {
            PolicyEvalResult::Denied {
                policy_type: self.policy_type(),
                reason: "Condition evaluated to false".to_string(),
            }
        }
    }
}

/// A trait that abstracts a relationship resolver.
/// Given a subject and a resource, the resolver answers whether the
/// specified relationship e.g. "creator", "manager" exists between them.
#[async_trait]
pub trait RelationshipResolver<S, R>: Send + Sync {
    async fn has_relationship(&self, subject: &S, resource: &R, relationship: &str) -> bool;
}

/// ### ReBAC Policy
///
/// In this example, we show how to use a built-in relationship-based (ReBAC) policy. We define
/// a dummy relationship resolver that checks if a user is the manager of a project.
///
/// ```rust
/// use async_trait::async_trait;
/// use std::sync::Arc;
/// use uuid::Uuid;
/// use permissions::*;
///
/// #[derive(Debug, Clone)]
/// pub struct Employee {
///     pub id: Uuid,
/// }
///
/// #[derive(Debug, Clone)]
/// pub struct Project {
///     pub id: Uuid,
///     pub manager_id: Uuid,
/// }
///
/// #[derive(Debug, Clone)]
/// pub struct AccessAction;
///
/// #[derive(Debug, Clone)]
/// pub struct EmptyContext;
///
/// // Define a dummy relationship resolver that considers an employee to be a manager
/// // of a project if their id matches the project's manager_id.
/// struct DummyRelationshipResolver;
///
/// #[async_trait]
/// impl RelationshipResolver<Employee, Project> for DummyRelationshipResolver {
///     async fn has_relationship(
///         &self,
///         employee: &Employee,
///         project: &Project,
///         relationship: &str,
///     ) -> bool {
///         relationship == "manager" && employee.id == project.manager_id
///     }
/// }
///
/// // Create a ReBAC policy that checks for the "manager" relationship.
/// let rebac_policy = RebacPolicy::<Employee, Project, AccessAction, EmptyContext, _>::new(
///     "manager",
///     DummyRelationshipResolver,
/// );
///
/// // Create a PermissionChecker and add the ReBAC policy.
/// let mut checker = PermissionChecker::<Employee, Project, AccessAction, EmptyContext>::new();
/// checker.add_policy(rebac_policy);
///
/// // Create a sample employee and project.
/// let manager = Employee { id: Uuid::new_v4() };
/// let project = Project {
///     id: Uuid::new_v4(),
///     manager_id: manager.id,
/// };
/// let context = EmptyContext;
///
/// // The manager should have access.
/// # tokio_test::block_on(async {
/// assert!(checker.evaluate_access(&manager, &AccessAction, &project, &context).await.is_granted());
///
/// // A different employee should be denied access.
/// let other_employee = Employee { id: Uuid::new_v4() };
/// assert!(!checker.evaluate_access(&other_employee, &AccessAction, &project, &context).await.is_granted());
/// # });
/// ```
pub struct RebacPolicy<S, R, A, C, RG> {
    pub relationship: String,
    pub resolver: RG,
    _marker: std::marker::PhantomData<(S, R, A, C)>,
}

impl<S, R, A, C, RG> RebacPolicy<S, R, A, C, RG> {
    /// Create a new RebacPolicy for a given relationship string.
    pub fn new(relationship: impl Into<String>, resolver: RG) -> Self {
        Self {
            relationship: relationship.into(),
            resolver,
            _marker: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<S, R, A, C, RG> Policy<S, R, A, C> for RebacPolicy<S, R, A, C, RG>
where
    S: Sync + Send,
    R: Sync + Send,
    A: Sync + Send,
    C: Sync + Send,
    RG: RelationshipResolver<S, R> + Send + Sync,
{
    async fn evaluate_access(
        &self,
        subject: &S,
        _action: &A,
        resource: &R,
        _context: &C,
    ) -> PolicyEvalResult {
        let has_relationship = self
            .resolver
            .has_relationship(subject, resource, &self.relationship)
            .await;

        if has_relationship {
            PolicyEvalResult::Granted {
                policy_type: self.policy_type(),
                reason: Some(format!(
                    "Subject has '{}' relationship with resource",
                    self.relationship
                )),
            }
        } else {
            PolicyEvalResult::Denied {
                policy_type: self.policy_type(),
                reason: format!(
                    "Subject does not have '{}' relationship with resource",
                    self.relationship
                ),
            }
        }
    }
}

/// ---
/// Policy Combinators
/// ---

/// AndPolicy
///
/// Combines multiple policies with a logical AND. Access is granted only if every
/// inner policy grants access.
pub struct AndPolicy<S, R, A, C> {
    policies: Vec<Arc<dyn Policy<S, R, A, C>>>,
}

impl<S, R, A, C> AndPolicy<S, R, A, C> {
    pub fn new(policies: Vec<Arc<dyn Policy<S, R, A, C>>>) -> Self {
        Self { policies }
    }
}

#[async_trait]
impl<S, R, A, C> Policy<S, R, A, C> for AndPolicy<S, R, A, C>
where
    S: Sync + Send,
    R: Sync + Send,
    A: Sync + Send,
    C: Sync + Send,
{
    // Override the default policy_type implementation
    fn policy_type(&self) -> String {
        "AndPolicy".to_string()
    }

    async fn evaluate_access(
        &self,
        subject: &S,
        action: &A,
        resource: &R,
        context: &C,
    ) -> PolicyEvalResult {
        let mut children_results = Vec::new();

        for policy in &self.policies {
            let result = policy
                .evaluate_access(subject, action, resource, context)
                .await;
            children_results.push(result.clone());

            // Short-circuit on first denial
            if !result.outcome() {
                return PolicyEvalResult::Combined {
                    policy_type: self.policy_type(),
                    operation: "AND".to_string(),
                    children: children_results,
                    outcome: false,
                };
            }
        }

        // All policies granted access
        PolicyEvalResult::Combined {
            policy_type: self.policy_type(),
            operation: "AND".to_string(),
            children: children_results,
            outcome: true,
        }
    }
}

/// OrPolicy
///
/// Combines multiple policies with a logical OR. Access is granted if any inner policy
/// grants access.
pub struct OrPolicy<S, R, A, C> {
    policies: Vec<Arc<dyn Policy<S, R, A, C>>>,
}

impl<S, R, A, C> OrPolicy<S, R, A, C> {
    pub fn new(policies: Vec<Arc<dyn Policy<S, R, A, C>>>) -> Self {
        Self { policies }
    }
}

#[async_trait]
impl<S, R, A, C> Policy<S, R, A, C> for OrPolicy<S, R, A, C>
where
    S: Sync + Send,
    R: Sync + Send,
    A: Sync + Send,
    C: Sync + Send,
{
    // Override the default policy_type implementation
    fn policy_type(&self) -> String {
        "OrPolicy".to_string()
    }
    async fn evaluate_access(
        &self,
        subject: &S,
        action: &A,
        resource: &R,
        context: &C,
    ) -> PolicyEvalResult {
        let mut children_results = Vec::new();

        for policy in &self.policies {
            let result = policy
                .evaluate_access(subject, action, resource, context)
                .await;
            children_results.push(result.clone());

            // Short-circuit on first success
            if result.outcome() {
                return PolicyEvalResult::Combined {
                    policy_type: self.policy_type(),
                    operation: "OR".to_string(),
                    children: children_results,
                    outcome: true,
                };
            }
        }

        // All policies denied access
        PolicyEvalResult::Combined {
            policy_type: self.policy_type(),
            operation: "OR".to_string(),
            children: children_results,
            outcome: false,
        }
    }
}

/// NotPolicy
///
/// Inverts the result of an inner policy. If the inner policy allows access, then NotPolicy
/// denies it, and vice versa.
pub struct NotPolicy<S, R, A, C> {
    policy: Arc<dyn Policy<S, R, A, C>>,
}

impl<S, R, A, C> NotPolicy<S, R, A, C> {
    pub fn new(policy: impl Policy<S, R, A, C> + 'static) -> Self {
        Self {
            policy: Arc::new(policy),
        }
    }
}

#[async_trait]
impl<S, R, A, C> Policy<S, R, A, C> for NotPolicy<S, R, A, C>
where
    S: Sync + Send,
    R: Sync + Send,
    A: Sync + Send,
    C: Sync + Send,
{
    // Override the default policy_type implementation
    fn policy_type(&self) -> String {
        "NotPolicy".to_string()
    }

    async fn evaluate_access(
        &self,
        subject: &S,
        action: &A,
        resource: &R,
        context: &C,
    ) -> PolicyEvalResult {
        let inner_result = self
            .policy
            .evaluate_access(subject, action, resource, context)
            .await;

        PolicyEvalResult::Combined {
            policy_type: Policy::<S, R, A, C>::policy_type(self),
            operation: "NOT".to_string(),
            children: vec![inner_result.clone()],
            outcome: !inner_result.outcome(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Dummy resource/action/context types for testing
    #[derive(Debug, Clone)]
    pub struct TestSubject {
        pub id: uuid::Uuid,
    }

    #[derive(Debug, Clone)]
    pub struct TestResource {
        pub id: uuid::Uuid,
    }

    #[derive(Debug, Clone)]
    pub struct TestAction;

    #[derive(Debug, Clone)]
    pub struct TestContext;

    // A policy that always allows
    struct AlwaysAllowPolicy;

    #[async_trait]
    impl Policy<TestSubject, TestResource, TestAction, TestContext> for AlwaysAllowPolicy {
        async fn evaluate_access(
            &self,
            _subject: &TestSubject,
            _action: &TestAction,
            _resource: &TestResource,
            _context: &TestContext,
        ) -> PolicyEvalResult {
            PolicyEvalResult::Granted {
                policy_type: self.policy_type(),
                reason: Some("Always allow policy".to_string()),
            }
        }
    }

    // A policy that always denies, with a custom reason
    struct AlwaysDenyPolicy(&'static str);

    #[async_trait]
    impl Policy<TestSubject, TestResource, TestAction, TestContext> for AlwaysDenyPolicy {
        async fn evaluate_access(
            &self,
            _subject: &TestSubject,
            _action: &TestAction,
            _resource: &TestResource,
            _context: &TestContext,
        ) -> PolicyEvalResult {
            PolicyEvalResult::Denied {
                policy_type: self.policy_type(),
                reason: self.0.to_string(),
            }
        }
    }

    #[tokio::test]
    async fn test_no_policies() {
        let checker =
            PermissionChecker::<TestSubject, TestResource, TestAction, TestContext>::new();

        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };
        let result = checker
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;

        match result {
            AccessEvaluation::Denied { reason, trace: _ } => {
                assert!(reason.contains("No policies configured"));
            }
            _ => panic!("Expected Denied(No policies configured), got {:?}", result),
        }
    }

    #[tokio::test]
    async fn test_one_policy_allow() {
        let mut checker = PermissionChecker::new();
        checker.add_policy(AlwaysAllowPolicy);

        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        let result = checker
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;

        if let AccessEvaluation::Granted {
            policy_type,
            reason,
            trace,
        } = result
        {
            assert_eq!(policy_type, "AlwaysAllowPolicy");
            assert_eq!(reason, Some("Always allow policy".to_string()));
            // Check the trace to ensure the policy was evaluated
            let trace_str = trace.format();
            assert!(trace_str.contains("AlwaysAllowPolicy"));
        } else {
            panic!("Expected AccessEvaluation::Granted, got {:?}", result);
        }
    }

    #[tokio::test]
    async fn test_one_policy_deny() {
        let mut checker = PermissionChecker::new();
        checker.add_policy(AlwaysDenyPolicy("DeniedByPolicy"));

        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        let result = checker
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;

        assert!(!result.is_granted());
        if let AccessEvaluation::Denied { reason, trace } = result {
            assert!(reason.contains("All policies denied access"));
            let trace_str = trace.format();
            assert!(trace_str.contains("DeniedByPolicy"));
        } else {
            panic!("Expected AccessEvaluation::Denied, got {:?}", result);
        }
    }

    #[tokio::test]
    async fn test_multiple_policies_or_success() {
        // First policy denies, second allows. Checker should return Ok, short-circuiting on second.
        let mut checker = PermissionChecker::new();
        checker.add_policy(AlwaysDenyPolicy("DenyPolicy"));
        checker.add_policy(AlwaysAllowPolicy);

        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };
        let result = checker
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;
        if let AccessEvaluation::Granted {
            policy_type,
            trace,
            reason: _,
        } = result
        {
            assert_eq!(policy_type, "AlwaysAllowPolicy");
            let trace_str = trace.format();
            assert!(trace_str.contains("DenyPolicy"));
        } else {
            panic!("Expected AccessEvaluation::Granted, got {:?}", result);
        }
    }

    #[tokio::test]
    async fn test_multiple_policies_all_deny_collect_reasons() {
        // Both policies deny, so we expect a Forbidden
        let mut checker = PermissionChecker::new();
        checker.add_policy(AlwaysDenyPolicy("DenyPolicy1"));
        checker.add_policy(AlwaysDenyPolicy("DenyPolicy2"));

        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };
        let result = checker
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;

        if let AccessEvaluation::Denied { trace, reason } = result {
            let trace_str = trace.format();
            assert!(trace_str.contains("DenyPolicy1"));
            assert!(trace_str.contains("DenyPolicy2"));
            assert_eq!(reason, "All policies denied access");
        } else {
            panic!("Expected AccessEvaluation::Denied, got {:?}", result);
        }
    }

    // RebacPolicy tests with a dummy resolver.

    /// In-memory relationship resolver for testing.
    /// It holds a vector of tuples (subject_id, resource_id, relationship)
    /// to represent existing relationships.
    pub struct DummyRelationshipResolver {
        relationships: Vec<(uuid::Uuid, uuid::Uuid, String)>,
    }

    impl DummyRelationshipResolver {
        pub fn new(relationships: Vec<(uuid::Uuid, uuid::Uuid, String)>) -> Self {
            Self { relationships }
        }
    }

    #[async_trait]
    impl RelationshipResolver<TestSubject, TestResource> for DummyRelationshipResolver {
        async fn has_relationship(
            &self,
            subject: &TestSubject,
            resource: &TestResource,
            relationship: &str,
        ) -> bool {
            self.relationships
                .iter()
                .any(|(s, r, rel)| s == &subject.id && r == &resource.id && rel == relationship)
        }
    }

    #[tokio::test]
    async fn test_rebac_policy_allows_when_relationship_exists() {
        let subject_id = uuid::Uuid::new_v4();
        let resource_id = uuid::Uuid::new_v4();
        let relationship = "manager";

        let subject = TestSubject { id: subject_id };
        let resource = TestResource { id: resource_id };

        // Create a dummy resolver that knows the subject is a manager of the resource.
        let resolver = DummyRelationshipResolver::new(vec![(
            subject_id,
            resource_id,
            relationship.to_string(),
        )]);

        let policy = RebacPolicy::<TestSubject, TestResource, TestAction, TestContext, _>::new(
            relationship,
            resolver,
        );

        // Action and context are not used by RebacPolicy, so we pass dummy values.
        let result = policy
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;

        assert!(
            result.outcome(),
            "Access should be allowed if relationship exists"
        );
    }

    #[tokio::test]
    async fn test_rebac_policy_denies_when_relationship_missing() {
        let subject_id = uuid::Uuid::new_v4();
        let resource_id = uuid::Uuid::new_v4();
        let relationship = "manager";

        let subject = TestSubject { id: subject_id };
        let resource = TestResource { id: resource_id };

        // Create a dummy resolver with no relationships.
        let resolver = DummyRelationshipResolver::new(vec![]);

        let policy = RebacPolicy::<TestSubject, TestResource, TestAction, TestContext, _>::new(
            relationship,
            resolver,
        );

        let result = policy
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;
        // Check access is denied
        assert!(
            !result.outcome(),
            "Access should be denied if relationship does not exist"
        );
    }

    // Combinator tests.
    #[tokio::test]
    async fn test_and_policy_allows_when_all_allow() {
        let policy = AndPolicy::new(vec![
            Arc::new(AlwaysAllowPolicy),
            Arc::new(AlwaysAllowPolicy),
        ]);
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };
        let result = policy
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;
        assert!(
            result.outcome(),
            "AndPolicy should allow access when all inner policies allow"
        );
    }
    #[tokio::test]
    async fn test_and_policy_denies_when_one_denies() {
        let policy = AndPolicy::new(vec![
            Arc::new(AlwaysAllowPolicy),
            Arc::new(AlwaysDenyPolicy("DenyInAnd")),
        ]);
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };
        let result = policy
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;
        match result {
            PolicyEvalResult::Combined {
                policy_type,
                operation,
                children,
                outcome,
            } => {
                assert_eq!(operation, "AND");
                assert!(!outcome);
                assert_eq!(children.len(), 2);
                assert!(children[1].format(0).contains("DenyInAnd"));
                assert_eq!(policy_type, "AndPolicy");
            }
            _ => panic!("Expected Combined result from AndPolicy, got {:?}", result),
        }
    }
    #[tokio::test]
    async fn test_or_policy_allows_when_one_allows() {
        let policy = OrPolicy::new(vec![
            Arc::new(AlwaysDenyPolicy("Deny1")),
            Arc::new(AlwaysAllowPolicy),
        ]);
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };
        let result = policy
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;
        assert!(
            result.outcome(),
            "OrPolicy should allow access when at least one inner policy allows"
        );
    }
    #[tokio::test]
    async fn test_or_policy_denies_when_all_deny() {
        let policy = OrPolicy::new(vec![
            Arc::new(AlwaysDenyPolicy("Deny1")),
            Arc::new(AlwaysDenyPolicy("Deny2")),
        ]);
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };
        let result = policy
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;
        match result {
            PolicyEvalResult::Combined {
                policy_type,
                operation,
                children,
                outcome,
            } => {
                assert_eq!(operation, "OR");
                assert!(!outcome);
                assert_eq!(children.len(), 2);
                assert!(children[0].format(0).contains("Deny1"));
                assert!(children[1].format(0).contains("Deny2"));
                assert_eq!(policy_type, "OrPolicy");
            }
            _ => panic!("Expected Combined result from OrPolicy, got {:?}", result),
        }
    }
    #[tokio::test]
    async fn test_not_policy_allows_when_inner_denies() {
        let policy = NotPolicy::new(AlwaysDenyPolicy("AlwaysDeny"));
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };
        let result = policy
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;
        assert!(
            result.outcome(),
            "NotPolicy should allow access when inner policy denies"
        );
    }
    #[tokio::test]
    async fn test_not_policy_denies_when_inner_allows() {
        let policy = NotPolicy::new(AlwaysAllowPolicy);
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };
        let result = policy
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;
        match result {
            PolicyEvalResult::Combined {
                policy_type,
                operation,
                children,
                outcome,
            } => {
                assert_eq!(operation, "NOT");
                assert!(!outcome);
                assert_eq!(children.len(), 1);
                assert!(children[0].format(0).contains("AlwaysAllowPolicy"));
                assert_eq!(policy_type, "NotPolicy");
            }
            _ => panic!("Expected Combined result from NotPolicy, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn test_empty_policies_in_combinators() {
        // Test AndPolicy with no policies
        let and_policy =
            AndPolicy::<TestSubject, TestResource, TestAction, TestContext>::new(vec![]);
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        let result = and_policy
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;

        // By logical identity, AND with no operands should be true (vacuously satisfied)
        match result {
            PolicyEvalResult::Combined {
                outcome, children, ..
            } => {
                assert!(
                    outcome,
                    "Empty AndPolicy should allow access (vacuous truth)"
                );
                assert_eq!(children.len(), 0);
            }
            _ => panic!("Expected Combined result"),
        }

        // Test OrPolicy with no policies
        let or_policy = OrPolicy::<TestSubject, TestResource, TestAction, TestContext>::new(vec![]);
        let result = or_policy
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;

        // By logical identity, OR with no operands should be false
        match result {
            PolicyEvalResult::Combined {
                outcome, children, ..
            } => {
                assert!(
                    !outcome,
                    "Empty OrPolicy should deny access (vacuous falsehood)"
                );
                assert_eq!(children.len(), 0);
            }
            _ => panic!("Expected Combined result"),
        }
    }

    #[tokio::test]
    async fn test_deeply_nested_combinators() {
        // Create a complex policy structure: NOT(AND(Allow, OR(Deny, NOT(Deny))))
        let inner_not = NotPolicy::new(AlwaysDenyPolicy("InnerDeny"));

        let inner_or = OrPolicy::new(vec![
            Arc::new(AlwaysDenyPolicy("MidDeny")),
            Arc::new(inner_not),
        ]);

        let inner_and = AndPolicy::new(vec![Arc::new(AlwaysAllowPolicy), Arc::new(inner_or)]);

        let outer_not = NotPolicy::new(inner_and);

        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        let result = outer_not
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;

        // This complex structure should result in a denial
        assert!(!result.outcome());

        // Verify the correct structure of the trace
        let trace_str = result.format(0);
        assert!(trace_str.contains("NOT"));
        assert!(trace_str.contains("AND"));
        assert!(trace_str.contains("OR"));
        assert!(trace_str.contains("InnerDeny"));
    }

    #[derive(Debug, Clone)]
    struct FeatureFlagContext {
        feature_enabled: bool,
    }

    struct FeatureFlagPolicy;

    #[async_trait]
    impl Policy<TestSubject, TestResource, TestAction, FeatureFlagContext> for FeatureFlagPolicy {
        async fn evaluate_access(
            &self,
            _subject: &TestSubject,
            _action: &TestAction,
            _resource: &TestResource,
            context: &FeatureFlagContext,
        ) -> PolicyEvalResult {
            if context.feature_enabled {
                PolicyEvalResult::Granted {
                    policy_type: self.policy_type(),
                    reason: Some("Feature flag enabled".to_string()),
                }
            } else {
                PolicyEvalResult::Denied {
                    policy_type: self.policy_type(),
                    reason: "Feature flag disabled".to_string(),
                }
            }
        }
    }

    #[tokio::test]
    async fn test_context_sensitive_policy() {
        let policy = FeatureFlagPolicy;
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        // Test with flag enabled
        let context_enabled = FeatureFlagContext {
            feature_enabled: true,
        };
        let result = policy
            .evaluate_access(&subject, &TestAction, &resource, &context_enabled)
            .await;
        assert!(result.outcome());

        // Test with flag disabled
        let context_disabled = FeatureFlagContext {
            feature_enabled: false,
        };
        let result = policy
            .evaluate_access(&subject, &TestAction, &resource, &context_disabled)
            .await;
        assert!(!result.outcome());
    }

    #[tokio::test]
    async fn test_short_circuit_evaluation() {
        // Create a counter to track policy evaluation
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc as StdArc;

        let evaluation_count = StdArc::new(AtomicUsize::new(0));

        struct CountingPolicy {
            result: bool,
            counter: StdArc<AtomicUsize>,
        }

        #[async_trait]
        impl Policy<TestSubject, TestResource, TestAction, TestContext> for CountingPolicy {
            async fn evaluate_access(
                &self,
                _subject: &TestSubject,
                _action: &TestAction,
                _resource: &TestResource,
                _context: &TestContext,
            ) -> PolicyEvalResult {
                self.counter.fetch_add(1, Ordering::SeqCst);

                if self.result {
                    PolicyEvalResult::Granted {
                        policy_type: self.policy_type(),
                        reason: Some("Counting policy granted".to_string()),
                    }
                } else {
                    PolicyEvalResult::Denied {
                        policy_type: self.policy_type(),
                        reason: "Counting policy denied".to_string(),
                    }
                }
            }
        }

        // Test AND short circuit on first deny
        let count_clone = evaluation_count.clone();
        evaluation_count.store(0, Ordering::SeqCst);

        let and_policy = AndPolicy::new(vec![
            Arc::new(CountingPolicy {
                result: false,
                counter: count_clone.clone(),
            }),
            Arc::new(CountingPolicy {
                result: true,
                counter: count_clone,
            }),
        ]);

        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };
        and_policy
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;

        assert_eq!(
            evaluation_count.load(Ordering::SeqCst),
            1,
            "AND policy should short-circuit after first deny"
        );

        // Test OR short circuit on first allow
        let count_clone = evaluation_count.clone();
        evaluation_count.store(0, Ordering::SeqCst);

        let or_policy = OrPolicy::new(vec![
            Arc::new(CountingPolicy {
                result: true,
                counter: count_clone.clone(),
            }),
            Arc::new(CountingPolicy {
                result: false,
                counter: count_clone,
            }),
        ]);

        or_policy
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;

        assert_eq!(
            evaluation_count.load(Ordering::SeqCst),
            1,
            "OR policy should short-circuit after first allow"
        );
    }
}
