//! A flexible authorization library that combines role‐based (RBAC),
//! attribute‐based (ABAC), and relationship‐based (ReBAC) policies.
//! The library provides a generic `Policy` trait for defining custom policies,
//! a builder pattern for creating custom policies as well as several built-in
//! policies for common use cases, and combinators for composing complex
//! authorization logic.
//!
//! # Overview
//!
//! A *Policy* is an asynchronous decision unit that checks if a given subject may
//! perform an action on a resource within a given context. Policies implement the
//! [`Policy`] trait. A [`PermissionChecker`] aggregates multiple policies and uses OR
//! logic by default (i.e. if any policy grants access, then access is allowed).
//! The [`PolicyBuilder`] offers a builder pattern for creating custom policies.
//!
//! ## Built in Policies
//! The library provides a few built-in policies:
//!  - [`RbacPolicy`]: A role-based access control policy.
//!  - [`AbacPolicy`]: An attribute-based access control policy.
//!  - [`RebacPolicy`]: A relationship-based access control policy.
//!
//! ## Custom Policies
//!
//! Below we define a simple system where a user may read a document if they
//! are an admin (via a simple role-based policy) or if they are the owner of the document (via
//! an attribute-based policy).
//!
//! ```rust
//! # use uuid::Uuid;
//! # use async_trait::async_trait;
//! # use std::sync::Arc;
//! # use gatehouse::*;
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
//!     fn policy_type(&self) -> String { "AdminPolicy".to_string() }
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
//!     fn policy_type(&self) -> String {
//!         "OwnerPolicy".to_string()
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
//! ## Evaluation Tracing
//!
//! The permission system provides detailed tracing of policy decisions, see [`AccessEvaluation`]
//! for an example.
//!
//!
//! ## Combinators
//!
//! Sometimes you may want to require that several policies pass (AND), require that
//! at least one passes (OR), or even invert a policy (NOT). `gatehouse` provides
//! combinators for this purpose:
//!
//! - [`AndPolicy`]: Grants access only if all inner policies allow access. Otherwise,
//!   returns a combined error.
//! - [`OrPolicy`]: Grants access if any inner policy allows access; otherwise returns a
//!   combined error.
//! - [`NotPolicy`]: Inverts the decision of an inner policy.
//!
//!

#![allow(clippy::type_complexity)]
use async_trait::async_trait;
use std::fmt::{self, Display};
use std::sync::Arc;

const DEFAULT_SECURITY_RULE_CATEGORY: &str = "Access Control";
const PERMISSION_CHECKER_POLICY_TYPE: &str = "PermissionChecker";

/// Metadata describing the security rule associated with a [`Policy`].
///
/// These fields follow the OpenTelemetry semantic conventions for security
/// rules: <https://opentelemetry.io/docs/specs/semconv/registry/attributes/security-rule/>.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecurityRuleMetadata {
    name: Option<String>,
    category: Option<String>,
    description: Option<String>,
    reference: Option<String>,
    ruleset_name: Option<String>,
    uuid: Option<String>,
    version: Option<String>,
    license: Option<String>,
}

impl SecurityRuleMetadata {
    /// Creates an empty metadata container.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the `security_rule.name` attribute.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the `security_rule.category` attribute.
    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.category = Some(category.into());
        self
    }

    /// Sets the `security_rule.description` attribute.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets the `security_rule.reference` attribute.
    pub fn with_reference(mut self, reference: impl Into<String>) -> Self {
        self.reference = Some(reference.into());
        self
    }

    /// Sets the `security_rule.ruleset.name` attribute.
    pub fn with_ruleset_name(mut self, ruleset_name: impl Into<String>) -> Self {
        self.ruleset_name = Some(ruleset_name.into());
        self
    }

    /// Sets the `security_rule.uuid` attribute.
    pub fn with_uuid(mut self, uuid: impl Into<String>) -> Self {
        self.uuid = Some(uuid.into());
        self
    }

    /// Sets the `security_rule.version` attribute.
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Sets the `security_rule.license` attribute.
    pub fn with_license(mut self, license: impl Into<String>) -> Self {
        self.license = Some(license.into());
        self
    }

    /// Returns the configured `security_rule.name` value.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Returns the configured `security_rule.category` value.
    pub fn category(&self) -> Option<&str> {
        self.category.as_deref()
    }

    /// Returns the configured `security_rule.description` value.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Returns the configured `security_rule.reference` value.
    pub fn reference(&self) -> Option<&str> {
        self.reference.as_deref()
    }

    /// Returns the configured `security_rule.ruleset.name` value.
    pub fn ruleset_name(&self) -> Option<&str> {
        self.ruleset_name.as_deref()
    }

    /// Returns the configured `security_rule.uuid` value.
    pub fn uuid(&self) -> Option<&str> {
        self.uuid.as_deref()
    }

    /// Returns the configured `security_rule.version` value.
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// Returns the configured `security_rule.license` value.
    pub fn license(&self) -> Option<&str> {
        self.license.as_deref()
    }
}

/// The type of boolean combining operation a policy might represent.
#[derive(Debug, PartialEq, Clone)]
pub enum CombineOp {
    And,
    Or,
    Not,
}

impl fmt::Display for CombineOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CombineOp::And => write!(f, "AND"),
            CombineOp::Or => write!(f, "OR"),
            CombineOp::Not => write!(f, "NOT"),
        }
    }
}

/// The result of evaluating a single policy (or a combination).
///
/// This enum is used both by individual policies and by combinators to represent the
/// outcome of access evaluation.
///
/// - [`PolicyEvalResult::Granted`]: Indicates that access is granted, with an optional reason.
/// - [`PolicyEvalResult::Denied`]: Indicates that access is denied, along with an explanatory reason.
/// - [`PolicyEvalResult::Combined`]: Represents the aggregate result of combining multiple policies.
#[derive(Debug, Clone)]
pub enum PolicyEvalResult {
    /// Access granted. Contains the policy type and an optional reason.
    Granted {
        policy_type: String,
        reason: Option<String>,
    },
    /// Access denied. Contains the policy type and a reason.
    Denied { policy_type: String, reason: String },
    /// Combined result from multiple policy evaluations.
    /// Contains the policy type, the combining operation ([`CombineOp`]),
    /// a list of child evaluation results, and the overall outcome.
    Combined {
        policy_type: String,
        operation: CombineOp,
        children: Vec<PolicyEvalResult>,
        outcome: bool,
    },
}

/// The complete result of a permission evaluation.
/// Contains both the final decision and a detailed trace for debugging.
///
/// ### Evaluation Tracing
///
/// The permission system provides detailed tracing of policy decisions:
/// ```rust
/// # use gatehouse::*;
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
    /// Access was granted.
    Granted {
        /// The policy that granted access
        policy_type: String,
        /// Optional reason for granting
        reason: Option<String>,
        /// Full evaluation trace including any rejected policies
        trace: EvalTrace,
    },
    /// Access was denied.
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

    /// Converts the evaluation into a `Result`, mapping a denial into an error.
    pub fn to_result<E>(&self, error_fn: impl FnOnce(&str) -> E) -> Result<(), E> {
        match self {
            Self::Granted { .. } => Ok(()),
            Self::Denied { reason, .. } => Err(error_fn(reason)),
        }
    }

    pub fn display_trace(&self) -> String {
        let trace = match self {
            AccessEvaluation::Granted {
                policy_type: _,
                reason: _,
                trace,
            } => trace,
            AccessEvaluation::Denied { reason: _, trace } => trace,
        };

        // If there's an actual tree to show, add it. Otherwise, fallback.
        let trace_str = trace.format();
        if trace_str == "No evaluation trace available" {
            format!("{}\n(No evaluation trace available)", self)
        } else {
            format!("{}\nEvaluation Trace:\n{}", self, trace_str)
        }
    }
}

/// A concise line about the final decision.
impl fmt::Display for AccessEvaluation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Granted {
                policy_type,
                reason,
                trace: _,
            } => {
                // Headline
                match reason {
                    Some(r) => write!(f, "[GRANTED] by {} - {}", policy_type, r),
                    None => write!(f, "[GRANTED] by {}", policy_type),
                }
            }
            Self::Denied { reason, trace: _ } => {
                write!(f, "[Denied] - {}", reason)
            }
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
    pub fn is_granted(&self) -> bool {
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
                format!("{}✔ {} GRANTED{}", indent_str, policy_type, reason_text)
            }
            Self::Denied {
                policy_type,
                reason,
            } => {
                format!("{}✘ {} DENIED: {}", indent_str, policy_type, reason)
            }
            Self::Combined {
                policy_type,
                operation,
                children,
                outcome,
            } => {
                let outcome_char = if *outcome { "✔" } else { "✘" };
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

impl fmt::Display for PolicyEvalResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tree = self.format(0);
        write!(f, "{}", tree)
    }
}

/// A generic async trait representing a single authorization policy.
/// A policy determines if a subject is allowed to perform an action on
/// a resource within a given context.
#[async_trait]
pub trait Policy<Subject, Resource, Action, Context>: Send + Sync {
    /// Evaluates whether access should be granted.
    ///
    /// # Arguments
    ///
    /// * `subject` - The entity requesting access.
    /// * `action` - The action being performed.
    /// * `resource` - The target resource.
    /// * `context` - Additional context that may affect the decision.
    ///
    /// # Returns
    ///
    /// A [`PolicyEvalResult`] indicating whether access is granted or denied.
    async fn evaluate_access(
        &self,
        subject: &Subject,
        action: &Action,
        resource: &Resource,
        context: &Context,
    ) -> PolicyEvalResult;

    /// Policy name for debugging
    fn policy_type(&self) -> String;

    /// Metadata describing the security rule that backs this policy.
    ///
    /// Implementors can override this method to surface additional semantic
    /// information. The default implementation returns empty metadata which
    /// still allows downstream telemetry to fall back to the policy type.
    fn security_rule(&self) -> SecurityRuleMetadata {
        SecurityRuleMetadata::default()
    }
}

/// A container for multiple policies, applied in an "OR" fashion.
/// (If any policy returns Ok, access is granted)
/// **Important**:
/// If no policies are added, access is always denied.
#[derive(Clone)]
pub struct PermissionChecker<S, R, A, C> {
    policies: Vec<Arc<dyn Policy<S, R, A, C>>>,
}

impl<S, R, A, C> Default for PermissionChecker<S, R, A, C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S, R, A, C> PermissionChecker<S, R, A, C> {
    /// Creates a new `PermissionChecker` with no policies.
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    /// Adds a policy to the checker.
    ///
    /// # Arguments
    ///
    /// * `policy` - A type implementing [`Policy`]. It is stored as an `Arc` for shared ownership.
    pub fn add_policy<P: Policy<S, R, A, C> + 'static>(&mut self, policy: P) {
        self.policies.push(Arc::new(policy));
    }

    /// Evaluates all policies against the given parameters.
    ///
    /// Policies are evaluated sequentially with OR semantics (short-circuiting on first success).
    /// Returns an [`AccessEvaluation`] with detailed tracing.
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
                policy_type: PERMISSION_CHECKER_POLICY_TYPE.to_string(),
                reason: "No policies configured".to_string(),
            };

            return AccessEvaluation::Denied {
                trace: EvalTrace::with_root(result),
                reason: "No policies configured".to_string(),
            };
        }
        tracing::trace!(num_policies = self.policies.len(), "Checking access");

        let mut policy_results = Vec::with_capacity(self.policies.len());

        // Evaluate each policy
        for policy in &self.policies {
            let result = policy
                .evaluate_access(subject, action, resource, context)
                .await;
            let result_passes = result.is_granted();

            // Extract metadata for tracing (always needed for security audit)
            let policy_type = policy.policy_type();
            let policy_type_str = policy_type.as_str();
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
                    policy.result.reason = reason_str,
                },
                "Security rule evaluated"
            );

            policy_results.push(result);

            // If any policy allows access, return immediately
            if result_passes {
                let combined = PolicyEvalResult::Combined {
                    policy_type: PERMISSION_CHECKER_POLICY_TYPE.to_string(),
                    operation: CombineOp::Or,
                    children: policy_results,
                    outcome: true,
                };

                return AccessEvaluation::Granted {
                    policy_type,
                    reason,
                    trace: EvalTrace::with_root(combined),
                };
            }
        }

        // If all policies denied access
        tracing::trace!("No policies allowed access, returning Forbidden");
        let combined = PolicyEvalResult::Combined {
            policy_type: PERMISSION_CHECKER_POLICY_TYPE.to_string(),
            operation: CombineOp::Or,
            children: policy_results,
            outcome: false,
        };

        AccessEvaluation::Denied {
            trace: EvalTrace::with_root(combined),
            reason: "All policies denied access".to_string(),
        }
    }
}

/// Represents the intended effect of a policy.
///
/// `Allow` means the policy grants access; `Deny` means it denies access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Deny,
}

/// An internal policy type (not exposed to API users) that is constructed via the builder.
struct InternalPolicy<S, R, A, C> {
    name: String,
    effect: Effect,
    // The predicate returns true if all conditions pass.
    predicate: Box<dyn Fn(&S, &A, &R, &C) -> bool + Send + Sync>,
}

#[async_trait]
impl<S, R, A, C> Policy<S, R, A, C> for InternalPolicy<S, R, A, C>
where
    S: Send + Sync,
    R: Send + Sync,
    A: Send + Sync,
    C: Send + Sync,
{
    async fn evaluate_access(
        &self,
        subject: &S,
        action: &A,
        resource: &R,
        context: &C,
    ) -> PolicyEvalResult {
        if (self.predicate)(subject, action, resource, context) {
            match self.effect {
                Effect::Allow => PolicyEvalResult::Granted {
                    policy_type: self.name.clone(),
                    reason: Some("Policy allowed access".into()),
                },
                Effect::Deny => PolicyEvalResult::Denied {
                    policy_type: self.name.clone(),
                    reason: "Policy denied access".into(),
                },
            }
        } else {
            // Predicate didn't match – treat as non-applicable (denied).
            PolicyEvalResult::Denied {
                policy_type: self.name.clone(),
                reason: "Policy predicate did not match".into(),
            }
        }
    }
    fn policy_type(&self) -> String {
        self.name.clone()
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
    async fn evaluate_access(
        &self,
        subject: &S,
        action: &A,
        resource: &R,
        context: &C,
    ) -> PolicyEvalResult {
        (**self)
            .evaluate_access(subject, action, resource, context)
            .await
    }

    fn policy_type(&self) -> String {
        (**self).policy_type()
    }

    fn security_rule(&self) -> SecurityRuleMetadata {
        (**self).security_rule()
    }
}

/// A builder API for creating custom policies.
///
/// A fluent interface to combine predicate functions on the subject, action, resource,
/// and context. Use it to construct a policy that can be added to a [`PermissionChecker`].
///
pub struct PolicyBuilder<S, R, A, C>
where
    S: Send + Sync + 'static,
    R: Send + Sync + 'static,
    A: Send + Sync + 'static,
    C: Send + Sync + 'static,
{
    name: String,
    effect: Effect,
    subject_pred: Option<Box<dyn Fn(&S) -> bool + Send + Sync>>,
    action_pred: Option<Box<dyn Fn(&A) -> bool + Send + Sync>>,
    resource_pred: Option<Box<dyn Fn(&R) -> bool + Send + Sync>>,
    context_pred: Option<Box<dyn Fn(&C) -> bool + Send + Sync>>,
    // Note the order here matches the evaluate_access signature
    extra_condition: Option<Box<dyn Fn(&S, &A, &R, &C) -> bool + Send + Sync>>,
}

impl<Subject, Resource, Action, Context> PolicyBuilder<Subject, Resource, Action, Context>
where
    Subject: Send + Sync + 'static,
    Resource: Send + Sync + 'static,
    Action: Send + Sync + 'static,
    Context: Send + Sync + 'static,
{
    /// Creates a new policy builder with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            effect: Effect::Allow,
            subject_pred: None,
            action_pred: None,
            resource_pred: None,
            context_pred: None,
            extra_condition: None,
        }
    }

    /// Sets the effect (Allow or Deny) for the policy.
    /// Defaults to Allow
    pub fn effect(mut self, effect: Effect) -> Self {
        self.effect = effect;
        self
    }

    /// Adds a predicate that tests the subject.
    pub fn subjects<F>(mut self, pred: F) -> Self
    where
        F: Fn(&Subject) -> bool + Send + Sync + 'static,
    {
        self.subject_pred = Some(Box::new(pred));
        self
    }

    /// Adds a predicate that tests the action.
    pub fn actions<F>(mut self, pred: F) -> Self
    where
        F: Fn(&Action) -> bool + Send + Sync + 'static,
    {
        self.action_pred = Some(Box::new(pred));
        self
    }

    /// Adds a predicate that tests the resource.
    pub fn resources<F>(mut self, pred: F) -> Self
    where
        F: Fn(&Resource) -> bool + Send + Sync + 'static,
    {
        self.resource_pred = Some(Box::new(pred));
        self
    }

    /// Add a predicate that validates the context.
    pub fn context<F>(mut self, pred: F) -> Self
    where
        F: Fn(&Context) -> bool + Send + Sync + 'static,
    {
        self.context_pred = Some(Box::new(pred));
        self
    }

    /// Add a condition that considers all four inputs.
    pub fn when<F>(mut self, pred: F) -> Self
    where
        F: Fn(&Subject, &Action, &Resource, &Context) -> bool + Send + Sync + 'static,
    {
        self.extra_condition = Some(Box::new(pred));
        self
    }

    /// Build the policy. Returns a boxed policy that can be added to a PermissionChecker.
    pub fn build(self) -> Box<dyn Policy<Subject, Resource, Action, Context>> {
        let effect = self.effect;
        let subject_pred = self.subject_pred;
        let action_pred = self.action_pred;
        let resource_pred = self.resource_pred;
        let context_pred = self.context_pred;
        let extra_condition = self.extra_condition;

        let predicate = Box::new(move |s: &Subject, a: &Action, r: &Resource, c: &Context| {
            subject_pred.as_ref().is_none_or(|f| f(s))
                && action_pred.as_ref().is_none_or(|f| f(a))
                && resource_pred.as_ref().is_none_or(|f| f(r))
                && context_pred.as_ref().is_none_or(|f| f(c))
                && extra_condition.as_ref().is_none_or(|f| f(s, a, r, c))
        });

        Box::new(InternalPolicy {
            name: self.name,
            effect,
            predicate,
        })
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

    fn policy_type(&self) -> String {
        "RbacPolicy".to_string()
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
///
/// # tokio_test::block_on(async {
/// // This check should succeed because the user is the owner:
/// assert!(checker.evaluate_access(&user, &Action, &owned_resource, &context).await.is_granted());
///
/// // This check should fail because the user is not the owner:
/// assert!(!checker.evaluate_access(&user, &Action, &other_resource, &context).await.is_granted());
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

    fn policy_type(&self) -> String {
        "AbacPolicy".to_string()
    }
}

/// A trait that abstracts a relationship resolver.
/// Given a subject and a resource, the resolver answers whether the
/// specified relationship e.g. "creator", "manager" exists between them.
#[async_trait]
pub trait RelationshipResolver<S, R, Re>: Send + Sync {
    async fn has_relationship(&self, subject: &S, resource: &R, relationship: &Re) -> bool;
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
/// use gatehouse::*;
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
/// impl RelationshipResolver<Employee, Project, String> for DummyRelationshipResolver {
///     async fn has_relationship(
///         &self,
///         employee: &Employee,
///         project: &Project,
///         relationship: &String,
///     ) -> bool {
///         relationship == "manager" && employee.id == project.manager_id
///     }
/// }
///
/// // Create a ReBAC policy that checks for the "manager" relationship.
/// let rebac_policy = RebacPolicy::<Employee, Project, AccessAction, EmptyContext, _, _>::new(
///     "manager".to_string(),
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
pub struct RebacPolicy<S, R, A, C, Re, RG> {
    pub relationship: Re,
    pub resolver: RG,
    _marker: std::marker::PhantomData<(S, R, A, C)>,
}

impl<S, R, A, C, Re, RG> RebacPolicy<S, R, A, C, Re, RG> {
    /// Create a new `RebacPolicy` for a given relationship.
    pub fn new(relationship: Re, resolver: RG) -> Self {
        Self {
            relationship,
            resolver,
            _marker: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<S, R, A, C, Re, RG> Policy<S, R, A, C> for RebacPolicy<S, R, A, C, Re, RG>
where
    S: Sync + Send,
    R: Sync + Send,
    A: Sync + Send,
    C: Sync + Send,
    Re: Sync + Send + Display,
    RG: RelationshipResolver<S, R, Re> + Send + Sync,
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

    fn policy_type(&self) -> String {
        "RebacPolicy".to_string()
    }
}

/// ---
/// Policy Combinators
/// ---
///
/// AndPolicy
///
/// Combines multiple policies with a logical AND. Access is granted only if every
/// inner policy grants access.
pub struct AndPolicy<S, R, A, C> {
    policies: Vec<Arc<dyn Policy<S, R, A, C>>>,
}

/// Error returned when no policies are provided to a combinator policy.
#[derive(Debug, Copy, Clone)]
pub struct EmptyPoliciesError(pub &'static str);

impl<S, R, A, C> AndPolicy<S, R, A, C> {
    pub fn try_new(policies: Vec<Arc<dyn Policy<S, R, A, C>>>) -> Result<Self, EmptyPoliciesError> {
        if policies.is_empty() {
            Err(EmptyPoliciesError(
                "AndPolicy must have at least one policy",
            ))
        } else {
            Ok(Self { policies })
        }
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
        let mut children_results = Vec::with_capacity(self.policies.len());

        for policy in &self.policies {
            let result = policy
                .evaluate_access(subject, action, resource, context)
                .await;
            let is_granted = result.is_granted();
            children_results.push(result);

            // Short-circuit on first denial
            if !is_granted {
                return PolicyEvalResult::Combined {
                    policy_type: self.policy_type(),
                    operation: CombineOp::And,
                    children: children_results,
                    outcome: false,
                };
            }
        }

        // All policies granted access
        PolicyEvalResult::Combined {
            policy_type: self.policy_type(),
            operation: CombineOp::And,
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
    pub fn try_new(policies: Vec<Arc<dyn Policy<S, R, A, C>>>) -> Result<Self, EmptyPoliciesError> {
        if policies.is_empty() {
            Err(EmptyPoliciesError("OrPolicy must have at least one policy"))
        } else {
            Ok(Self { policies })
        }
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
        let mut children_results = Vec::with_capacity(self.policies.len());

        for policy in &self.policies {
            let result = policy
                .evaluate_access(subject, action, resource, context)
                .await;
            let is_granted = result.is_granted();
            children_results.push(result);

            // Short-circuit on first success
            if is_granted {
                return PolicyEvalResult::Combined {
                    policy_type: self.policy_type(),
                    operation: CombineOp::Or,
                    children: children_results,
                    outcome: true,
                };
            }
        }

        // All policies denied access
        PolicyEvalResult::Combined {
            policy_type: self.policy_type(),
            operation: CombineOp::Or,
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
        let is_granted = inner_result.is_granted();

        PolicyEvalResult::Combined {
            policy_type: Policy::<S, R, A, C>::policy_type(self),
            operation: CombineOp::Not,
            children: vec![inner_result],
            outcome: !is_granted,
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

    #[test]
    fn security_rule_metadata_builder_sets_fields() {
        let metadata = SecurityRuleMetadata::new()
            .with_name("Example")
            .with_category("Access Control")
            .with_description("Example description")
            .with_reference("https://example.com/rule")
            .with_ruleset_name("ExampleRuleset")
            .with_uuid("1234")
            .with_version("1.0.0")
            .with_license("Apache-2.0");

        assert_eq!(metadata.name(), Some("Example"));
        assert_eq!(metadata.category(), Some("Access Control"));
        assert_eq!(metadata.description(), Some("Example description"));
        assert_eq!(metadata.reference(), Some("https://example.com/rule"));
        assert_eq!(metadata.ruleset_name(), Some("ExampleRuleset"));
        assert_eq!(metadata.uuid(), Some("1234"));
        assert_eq!(metadata.version(), Some("1.0.0"));
        assert_eq!(metadata.license(), Some("Apache-2.0"));
    }

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

        fn policy_type(&self) -> String {
            "AlwaysAllowPolicy".to_string()
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

        fn policy_type(&self) -> String {
            "AlwaysDenyPolicy".to_string()
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
    impl RelationshipResolver<TestSubject, TestResource, String> for DummyRelationshipResolver {
        async fn has_relationship(
            &self,
            subject: &TestSubject,
            resource: &TestResource,
            relationship: &String,
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
        let relationship = "manager".to_string();

        let subject = TestSubject { id: subject_id };
        let resource = TestResource { id: resource_id };

        // Create a dummy resolver that knows the subject is a manager of the resource.
        let resolver = DummyRelationshipResolver::new(vec![(
            subject_id,
            resource_id,
            relationship.to_string(),
        )]);

        let policy = RebacPolicy::<TestSubject, TestResource, TestAction, TestContext, _, _>::new(
            relationship,
            resolver,
        );

        // Action and context are not used by RebacPolicy, so we pass dummy values.
        let result = policy
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;

        assert!(
            result.is_granted(),
            "Access should be allowed if relationship exists"
        );
    }

    #[tokio::test]
    async fn test_rebac_policy_denies_when_relationship_missing() {
        let subject_id = uuid::Uuid::new_v4();
        let resource_id = uuid::Uuid::new_v4();
        let relationship = "manager".to_string();

        let subject = TestSubject { id: subject_id };
        let resource = TestResource { id: resource_id };

        // Create a dummy resolver with no relationships.
        let resolver = DummyRelationshipResolver::new(vec![]);

        let policy = RebacPolicy::<TestSubject, TestResource, TestAction, TestContext, _, _>::new(
            relationship,
            resolver,
        );

        let result = policy
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;
        // Check access is denied
        assert!(
            !result.is_granted(),
            "Access should be denied if relationship does not exist"
        );
    }

    // Combinator tests.
    #[tokio::test]
    async fn test_and_policy_allows_when_all_allow() {
        let policy = AndPolicy::try_new(vec![
            Arc::new(AlwaysAllowPolicy),
            Arc::new(AlwaysAllowPolicy),
        ])
        .expect("Unable to create and-policy policy");
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
            result.is_granted(),
            "AndPolicy should allow access when all inner policies allow"
        );
    }
    #[tokio::test]
    async fn test_and_policy_denies_when_one_denies() {
        let policy = AndPolicy::try_new(vec![
            Arc::new(AlwaysAllowPolicy),
            Arc::new(AlwaysDenyPolicy("DenyInAnd")),
        ])
        .expect("Unable to create and-policy policy");
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
                assert_eq!(operation, CombineOp::And);
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
        let policy = OrPolicy::try_new(vec![
            Arc::new(AlwaysDenyPolicy("Deny1")),
            Arc::new(AlwaysAllowPolicy),
        ])
        .expect("Unable to create or-policy policy");
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
            result.is_granted(),
            "OrPolicy should allow access when at least one inner policy allows"
        );
    }
    #[tokio::test]
    async fn test_or_policy_denies_when_all_deny() {
        let policy = OrPolicy::try_new(vec![
            Arc::new(AlwaysDenyPolicy("Deny1")),
            Arc::new(AlwaysDenyPolicy("Deny2")),
        ])
        .expect("Unable to create or-policy policy");
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
                assert_eq!(operation, CombineOp::Or);
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
            result.is_granted(),
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
                assert_eq!(operation, CombineOp::Not);
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
        let and_policy_result =
            AndPolicy::<TestSubject, TestResource, TestAction, TestContext>::try_new(vec![]);

        assert!(and_policy_result.is_err());

        // Test OrPolicy with no policies
        let or_policy_result =
            OrPolicy::<TestSubject, TestResource, TestAction, TestContext>::try_new(vec![]);
        assert!(or_policy_result.is_err());
    }

    #[tokio::test]
    async fn test_deeply_nested_combinators() {
        // Create a complex policy structure: NOT(AND(Allow, OR(Deny, NOT(Deny))))
        let inner_not = NotPolicy::new(AlwaysDenyPolicy("InnerDeny"));

        let inner_or = OrPolicy::try_new(vec![
            Arc::new(AlwaysDenyPolicy("MidDeny")),
            Arc::new(inner_not),
        ])
        .expect("Unable to create or-policy policy");

        let inner_and = AndPolicy::try_new(vec![Arc::new(AlwaysAllowPolicy), Arc::new(inner_or)])
            .expect("Unable to create and-policy policy");

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
        assert!(!result.is_granted());

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

        fn policy_type(&self) -> String {
            "FeatureFlagPolicy".to_string()
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
        assert!(result.is_granted());

        // Test with flag disabled
        let context_disabled = FeatureFlagContext {
            feature_enabled: false,
        };
        let result = policy
            .evaluate_access(&subject, &TestAction, &resource, &context_disabled)
            .await;
        assert!(!result.is_granted());
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

            fn policy_type(&self) -> String {
                "CountingPolicy".to_string()
            }
        }

        // Test AND short circuit on first deny
        let count_clone = evaluation_count.clone();
        evaluation_count.store(0, Ordering::SeqCst);

        let and_policy = AndPolicy::try_new(vec![
            Arc::new(CountingPolicy {
                result: false,
                counter: count_clone.clone(),
            }),
            Arc::new(CountingPolicy {
                result: true,
                counter: count_clone,
            }),
        ])
        .expect("Unable to create 'and' policy");

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

        let or_policy = OrPolicy::try_new(vec![
            Arc::new(CountingPolicy {
                result: true,
                counter: count_clone.clone(),
            }),
            Arc::new(CountingPolicy {
                result: false,
                counter: count_clone,
            }),
        ])
        .unwrap();

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

#[cfg(test)]
mod policy_builder_tests {
    use super::*;
    use uuid::Uuid;

    // Define simple test types
    #[derive(Debug, Clone)]
    struct TestSubject {
        pub name: String,
    }
    #[derive(Debug, Clone)]
    struct TestAction;
    #[derive(Debug, Clone)]
    struct TestResource;
    #[derive(Debug, Clone)]
    struct TestContext;

    // Test that with no predicates the builder returns a policy that always "matches"
    #[tokio::test]
    async fn test_policy_builder_allows_when_no_predicates() {
        let policy = PolicyBuilder::<TestSubject, TestResource, TestAction, TestContext>::new(
            "NoPredicatesPolicy",
        )
        .build();

        let result = policy
            .evaluate_access(
                &TestSubject { name: "Any".into() },
                &TestAction,
                &TestResource,
                &TestContext,
            )
            .await;
        assert!(
            result.is_granted(),
            "Policy built with no predicates should allow access (default true)"
        );
    }

    // Test that a subject predicate is applied correctly.
    #[tokio::test]
    async fn test_policy_builder_with_subject_predicate() {
        let policy = PolicyBuilder::<TestSubject, TestResource, TestAction, TestContext>::new(
            "SubjectPolicy",
        )
        .subjects(|s: &TestSubject| s.name == "Alice")
        .build();

        // Should allow if the subject's name is "Alice"
        let result1 = policy
            .evaluate_access(
                &TestSubject {
                    name: "Alice".into(),
                },
                &TestAction,
                &TestResource,
                &TestContext,
            )
            .await;
        assert!(
            result1.is_granted(),
            "Policy should allow access for subject 'Alice'"
        );

        // Otherwise, it should deny
        let result2 = policy
            .evaluate_access(
                &TestSubject { name: "Bob".into() },
                &TestAction,
                &TestResource,
                &TestContext,
            )
            .await;
        assert!(
            !result2.is_granted(),
            "Policy should deny access for subject not named 'Alice'"
        );
    }

    // Test that setting the effect to Deny overrides an otherwise matching predicate.
    #[tokio::test]
    async fn test_policy_builder_effect_deny() {
        let policy =
            PolicyBuilder::<TestSubject, TestResource, TestAction, TestContext>::new("DenyPolicy")
                .effect(Effect::Deny)
                .build();

        // Even though no predicate fails (so predicate returns true),
        // the effect should result in a Denied outcome.
        let result = policy
            .evaluate_access(
                &TestSubject {
                    name: "Anyone".into(),
                },
                &TestAction,
                &TestResource,
                &TestContext,
            )
            .await;
        assert!(
            !result.is_granted(),
            "Policy with effect Deny should result in denial even if the predicate passes"
        );
    }

    // Test that extra conditions (combining multiple inputs) work correctly.
    #[tokio::test]
    async fn test_policy_builder_with_extra_condition() {
        #[derive(Debug, Clone)]
        struct ExtendedSubject {
            pub id: Uuid,
            pub name: String,
        }
        #[derive(Debug, Clone)]
        struct ExtendedResource {
            pub owner_id: Uuid,
        }
        #[derive(Debug, Clone)]
        struct ExtendedAction;
        #[derive(Debug, Clone)]
        struct ExtendedContext;

        // Build a policy that checks:
        //   1. Subject's name is "Alice"
        //   2. And that subject.id == resource.owner_id (via extra condition)
        let subject_id = Uuid::new_v4();
        let policy = PolicyBuilder::<
            ExtendedSubject,
            ExtendedResource,
            ExtendedAction,
            ExtendedContext,
        >::new("AliceOwnerPolicy")
        .subjects(|s: &ExtendedSubject| s.name == "Alice")
        .when(|s, _a, r, _c| s.id == r.owner_id)
        .build();

        // Case where both conditions are met.
        let result1 = policy
            .evaluate_access(
                &ExtendedSubject {
                    id: subject_id,
                    name: "Alice".into(),
                },
                &ExtendedAction,
                &ExtendedResource {
                    owner_id: subject_id,
                },
                &ExtendedContext,
            )
            .await;
        assert!(
            result1.is_granted(),
            "Policy should allow access when conditions are met"
        );

        // Case where extra condition fails (different id)
        let result2 = policy
            .evaluate_access(
                &ExtendedSubject {
                    id: subject_id,
                    name: "Alice".into(),
                },
                &ExtendedAction,
                &ExtendedResource {
                    owner_id: Uuid::new_v4(),
                },
                &ExtendedContext,
            )
            .await;
        assert!(
            !result2.is_granted(),
            "Policy should deny access when extra condition fails"
        );
    }
}
