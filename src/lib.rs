//! An in-process authorization engine for Rust.
//!
//! Gatehouse composes role-based (RBAC), attribute-based (ABAC), and
//! relationship-based (ReBAC) policies while keeping authorization logic in
//! Rust. Relationship facts are loaded through request-scoped
//! [`EvaluationSession`] values, so list endpoints can batch, deduplicate, and
//! coalesce backend calls without moving policy logic into the data layer.
//!
//! # Overview
//!
//! A *Policy* is an asynchronous decision unit that checks if a given subject may
//! perform an action on a resource within a given context. Policies implement the
//! [`Policy`] trait. A [`PermissionChecker`] aggregates multiple policies and uses OR
//! logic by default (i.e. if any policy grants access, then access is allowed).
//! The [`PolicyBuilder`] offers a builder pattern for creating custom policies.
//! Custom [`Policy`] implementations must provide both [`Policy::evaluate`]
//! and [`Policy::policy_type`].
//!
//! ## Decision Semantics
//!
//! `gatehouse` deliberately keeps decision semantics simple and explicit:
//!
//! - [`PermissionChecker`] evaluates policies sequentially with OR semantics and
//!   short-circuits on the first grant.
//! - An empty [`PermissionChecker`] denies access with the reason
//!   `"No policies configured"`.
//! - [`AndPolicy`] short-circuits on the first denial.
//! - [`OrPolicy`] short-circuits on the first grant.
//! - [`NotPolicy`] inverts the decision of its inner policy.
//! - [`PolicyBuilder`] combines all configured predicates with AND logic.
//! - [`PolicyBuilder::effect`] changes the result returned by that specific
//!   built policy when its combined predicate matches. A non-match is still
//!   treated as denied/non-applicable, and the effect does not create global
//!   deny-overrides-allow semantics when used inside [`PermissionChecker`].
//!
//! Denials from [`AccessEvaluation`] are intentionally summary-level. For example,
//! a failed [`PermissionChecker`] returns the top-level reason
//! `"All policies denied access"`. Use the attached [`EvalTrace`] to inspect the
//! individual policy reasons that led to that outcome.
//!
//! ## Trace Semantics
//!
//! [`EvalTrace`] records the policies and combinator branches that were actually
//! evaluated. Because [`PermissionChecker`], [`AndPolicy`], and [`OrPolicy`]
//! short-circuit, the trace tree does not include policies that were never run.
//!
//! ## Fact-Loaded Authorization
//!
//! Gatehouse treats non-trivial authorization as computation over facts loaded
//! for one request. [`FactSource::load_many`] receives unique fact keys and
//! returns exactly one result per key; [`EvaluationSession`] expands duplicate
//! caller inputs, preserves caller order, caches results for the request, and
//! joins concurrent in-flight loads for the same key.
//!
//! [`RebacPolicy`] is the first built-in policy backed by this model. It
//! extracts flat subject/resource IDs, builds [`RelationshipQuery`] keys, and
//! asks the session for relationship facts.
//!
//! ## Quick Start
//!
//! The fastest way to define a policy is with [`PolicyBuilder`]:
//!
//! ```rust
//! # use gatehouse::*;
//! #[derive(Debug, Clone)]
//! struct User { roles: Vec<String> }
//! #[derive(Debug, Clone)]
//! struct Document;
//! #[derive(Debug, Clone)]
//! struct ReadAction;
//! #[derive(Debug, Clone)]
//! struct AppContext;
//!
//! let policy = PolicyBuilder::<User, Document, ReadAction, AppContext>::new("AdminOnly")
//!     .subjects(|user: &User| user.roles.iter().any(|r| r == "admin"))
//!     .build();
//!
//! let mut checker = PermissionChecker::new();
//! checker.add_policy(policy);
//!
//! # tokio_test::block_on(async {
//! let session = EvaluationSession::empty();
//! let admin = User { roles: vec!["admin".into()] };
//! assert!(checker.evaluate_in_session(&session, &admin, &ReadAction, &Document, &AppContext).await.is_granted());
//!
//! let guest = User { roles: vec!["guest".into()] };
//! assert!(!checker.evaluate_in_session(&session, &guest, &ReadAction, &Document, &AppContext).await.is_granted());
//! # });
//! ```
//!
//! ## Built-in Policies
//!
//! The library provides several built-in policies:
//!  - [`RbacPolicy`]: A role-based access control policy.
//!  - [`AbacPolicy`]: An attribute-based access control policy.
//!  - [`RebacPolicy`]: A relationship-based access control policy backed by
//!    [`FactSource`] and [`EvaluationSession`].
//!
//! ## Custom Policies
//!
//! For full control, implement the [`Policy`] trait directly. Below we define a simple
//! system where a user may read a document if they are an admin (via a role-based policy)
//! or if they are the owner of the document (via an attribute-based policy).
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
//!     async fn evaluate(&self, ctx: &EvalCtx<'_, User, Document, ReadAction, EmptyContext>) -> PolicyEvalResult {
//!         if ctx.subject.roles.contains(&"admin".to_string()) {
//!             PolicyEvalResult::Granted {
//!                 policy_type: self.policy_type().to_string(),
//!                 reason: Some("User is admin".to_string()),
//!             }
//!         } else {
//!             PolicyEvalResult::Denied {
//!                 policy_type: self.policy_type().to_string(),
//!                 reason: "User is not admin".to_string(),
//!             }
//!         }
//!     }
//!     fn policy_type(&self) -> &str { "AdminPolicy" }
//! }
//!
//! // An ABAC policy: grant access if the user is the owner of the document.
//! struct OwnerPolicy;
//!
//! #[async_trait]
//! impl Policy<User, Document, ReadAction, EmptyContext> for OwnerPolicy {
//!     async fn evaluate(&self, ctx: &EvalCtx<'_, User, Document, ReadAction, EmptyContext>) -> PolicyEvalResult {
//!         if ctx.subject.id == ctx.resource.owner_id {
//!             PolicyEvalResult::Granted {
//!                 policy_type: self.policy_type().to_string(),
//!                 reason: Some("User is the owner".to_string()),
//!             }
//!         } else {
//!             PolicyEvalResult::Denied {
//!                policy_type: self.policy_type().to_string(),
//!                reason: "User is not the owner".to_string(),
//!            }
//!         }
//!     }
//!     fn policy_type(&self) -> &str {
//!         "OwnerPolicy"
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
//! let session = EvaluationSession::empty();
//!
//! // An admin should have access.
//! assert!(checker.evaluate_in_session(&session, &admin_user, &ReadAction, &document, &EmptyContext).await.is_granted());
//!
//! // The owner should have access.
//! assert!(checker.evaluate_in_session(&session, &owner_user, &ReadAction, &document, &EmptyContext).await.is_granted());
//!
//! // A random user should be denied access.
//! let random_user = User {
//!     id: Uuid::new_v4(),
//!     roles: vec!["user".into()],
//! };
//! assert!(!checker.evaluate_in_session(&session, &random_user, &ReadAction, &document, &EmptyContext).await.is_granted());
//! # });
//! ```
//!
//! ## Evaluation Tracing
//!
//! The permission system provides detailed tracing of policy decisions, see [`AccessEvaluation`]
//! for an example.
//!
//! ## Tracing And Telemetry
//!
//! When trace-level events are enabled, [`PermissionChecker::evaluate_in_session`]
//! creates an instrumented span and each evaluated policy records a `trace!`
//! event on the `gatehouse::security` target. Batch evaluation records
//! aggregate item counts on [`PermissionChecker::evaluate_batch_in_session_by`]
//! and per-policy counts on nested `gatehouse.batch_policy` spans.
//!
//! Emitted fields:
//!
//! - `security_rule.name`
//! - `security_rule.category`
//! - `security_rule.description`
//! - `security_rule.reference`
//! - `security_rule.ruleset.name`
//! - `security_rule.uuid`
//! - `security_rule.version`
//! - `security_rule.license`
//! - `event.outcome`
//! - `policy.type`
//! - `policy.result.reason`
//!
//! When [`Policy::security_rule`] is not overridden, tracing falls back to:
//!
//! - `security_rule.name = policy_type()`
//! - `security_rule.category = "Access Control"`
//! - `security_rule.ruleset.name = "PermissionChecker"`
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
//! - [`DelegatingPolicy`]: Maps the current inputs into another authorization
//!   domain and delegates to a child [`PermissionChecker`] while preserving
//!   batching.
//!
//!

#![warn(missing_docs)]
#![allow(clippy::type_complexity)]

mod builder;
mod checker;
mod combinators;
mod facts;
mod lookup;
mod metadata;
mod policies;
mod policy;
mod results;
mod session;

pub use builder::{Effect, PolicyBuilder};
pub use checker::PermissionChecker;
pub use combinators::{AndPolicy, EmptyPoliciesError, NotPolicy, OrPolicy};
pub use facts::{
    FactKey, FactLoadError, FactLoadResult, FactSource, FactSourceRegistrationError,
    RelationshipQuery,
};
pub use lookup::{Hydrator, LookupAuthorizedError, LookupAuthorizedPage, LookupPage, LookupSource};
pub use metadata::SecurityRuleMetadata;
pub(crate) use metadata::{DEFAULT_SECURITY_RULE_CATEGORY, PERMISSION_CHECKER_POLICY_TYPE};
pub use policies::{AbacPolicy, DelegatingPolicy, RbacPolicy, RebacPolicy};
pub use policy::{BatchEvalCtx, EvalCtx, Policy, PolicyBatchItem};
pub use results::{AccessEvaluation, CombineOp, EvalTrace, PolicyEvalResult};
pub use session::{EvaluationSession, EvaluationSessionBuilder};

// The shared unit-test module pulls in tokio-based async tests via dev-deps
// that are intentionally loom-incompatible (`tokio::net`, axum, hyper, etc.).
// Gate it out under `cfg(loom)` so the loom build's minimal dependency graph
// stays clean. The synchronous core's deterministic tests and the loom
// permutation tests both live in `src/session/core.rs` and are unaffected.
#[cfg(all(test, not(loom)))]
mod tests;
