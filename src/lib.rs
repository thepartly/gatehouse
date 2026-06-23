//! An in-process authorization engine for Rust.
//!
//! Gatehouse keeps authorization logic in Rust while giving policy code a
//! request-scoped fact session for relationship and backend-loaded data. The
//! public API is centered on one [`PolicyDomain`] marker per authorization
//! domain, a [`PermissionChecker`] that owns that domain's policy stack, and a
//! [`BoundEvaluator`] created for one request/session/subject/action/context.
//!
//! # Overview
//!
//! A [`Policy`] is an asynchronous decision unit for one [`PolicyDomain`]. The
//! domain names the four Rust types involved in a decision:
//!
//! - `Subject`: the caller.
//! - `Action`: the operation being attempted.
//! - `Resource`: the target resource or scope resource.
//! - `Context`: request-scoped inputs such as current time, MFA freshness,
//!   network zone, tenant config, or feature flags.
//!
//! Relationship data and other backend-loaded authorization facts do not
//! belong in `Context`; expose them as [`FactKey`] values loaded by an
//! [`EvaluationSession`]. The session batches, deduplicates, caches, and
//! coalesces fact loads for one request.
//!
//! # Quick Start
//!
//! The fastest way to define a synchronous predicate policy is
//! [`PolicyBuilder`]:
//!
//! ```rust
//! # use gatehouse::*;
//! #[derive(Debug, Clone)]
//! struct User {
//!     id: u64,
//!     roles: Vec<&'static str>,
//! }
//! #[derive(Debug, Clone)]
//! struct Document {
//!     owner_id: u64,
//! }
//! #[derive(Debug, Clone)]
//! struct ReadAction;
//!
//! struct Documents;
//! impl PolicyDomain for Documents {
//!     type Subject = User;
//!     type Action = ReadAction;
//!     type Resource = Document;
//!     type Context = ();
//! }
//!
//! let admin_policy = PolicyBuilder::<Documents>::new("AdminOnly")
//!     .subjects(|user: &User| user.roles.contains(&"admin"))
//!     .build();
//!
//! let owner_policy = PolicyBuilder::<Documents>::new("OwnerOnly")
//!     .when(|user: &User, _action: &ReadAction, document: &Document, _ctx: &()| {
//!         user.id == document.owner_id
//!     })
//!     .build();
//!
//! let mut checker = PermissionChecker::<Documents>::new();
//! checker.add_policy(admin_policy);
//! checker.add_policy(owner_policy);
//!
//! # tokio_test::block_on(async {
//! let session = EvaluationSession::empty();
//! let document = Document { owner_id: 7 };
//! let admin = User { id: 1, roles: vec!["admin"] };
//! let owner = User { id: 7, roles: vec!["user"] };
//! let guest = User { id: 2, roles: vec!["user"] };
//!
//! assert!(checker.bind(&session, &admin, &ReadAction, &()).check(&document).await.is_granted());
//! assert!(checker.bind(&session, &owner, &ReadAction, &()).check(&document).await.is_granted());
//! assert!(!checker.bind(&session, &guest, &ReadAction, &()).check(&document).await.is_granted());
//! # });
//! ```
//!
//! # Core Flows
//!
//! Bind request-wide inputs once, then evaluate resources through the bound
//! evaluator:
//!
//! ```rust,ignore
//! let session = registry.session();
//! let bound = checker.bind(&session, &subject, &action, &request_context);
//!
//! let decision = bound.check(&resource).await;
//! let decisions = bound.evaluate(resources.clone()).await;
//! let authorized = bound.filter(resources).await;
//! let page = bound.lookup_page(&lookup, &hydrator, cursor.as_deref(), limit).await?;
//! ```
//!
//! Use [`EvaluationSession::empty`] for fact-free decisions. Use a session from
//! [`FactRegistry::session`] when any policy calls `ctx.session.get(...)`, such
//! as [`RebacPolicy`] or a custom fact-backed policy.
//!
//! [`BoundEvaluator::evaluate`] preserves input order and returns one
//! [`AccessEvaluation`] per input resource. [`BoundEvaluator::filter`] keeps
//! only granted resources. [`BoundEvaluator::lookup_page`] is for list
//! endpoints where the application cannot load every possible candidate first;
//! the [`LookupSource`] enumerates candidate IDs, a [`Hydrator`] resolves them,
//! and the full policy stack authorizes the hydrated resources.
//!
//! # Decision Semantics
//!
//! Gatehouse deliberately keeps combining semantics fixed:
//!
//! - [`PermissionChecker`] applies deny-overrides. A policy that returns
//!   [`PolicyEvalResult::Forbidden`] denies the request and overrides grants
//!   from sibling policies.
//! - Policies declaring [`Effect::Forbid`] are evaluated before allow policies
//!   so a veto cannot be skipped by grant short-circuiting.
//! - If no policy forbids, the first grant wins.
//! - If nothing grants, the checker denies with `"All policies denied access"`.
//! - An empty checker denies with `"No policies configured"`.
//! - [`PolicyEvalResult::NotApplicable`] means the policy did not grant.
//!   [`PolicyEvalResult::Forbidden`] means the policy actively vetoed.
//! - [`PolicyBuilder`] combines configured predicates with AND logic.
//!   [`PolicyBuilder::forbid`] makes a matching built policy forbid; a
//!   non-match remains not applicable and does not block.
//! - [`AndPolicy`] short-circuits on the first non-grant. [`OrPolicy`]
//!   short-circuits on the first grant. [`NotPolicy`] inverts the inner
//!   decision.
//! - Inside combinators, a forbidden child behaves like a non-grant. Register
//!   global veto rules directly on the checker; use `grant.and(block.not())`
//!   when an exclusion should gate only one grant path.
//!
//! Denials from [`AccessEvaluation`] are summary-level. Use
//! [`AccessEvaluation::display_trace`] or the attached [`EvalTrace`] to inspect
//! individual policy reasons and fact provenance.
//!
//! # Fact-Loaded Authorization
//!
//! [`FactSource::load_many`] receives unique fact keys and must return exactly
//! one result per key in the same order. [`EvaluationSession`] expands
//! duplicate caller inputs, preserves caller order, caches results for the
//! request, chunks loads according to [`FactSource::max_batch_size`], and joins
//! concurrent in-flight loads for the same key.
//!
//! [`RebacPolicy`] is the built-in fact-backed policy. It extracts flat
//! subject/resource IDs, builds [`RelationshipQuery`] keys, and grants only
//! when the request session loads a `Found(true)` relationship fact. Missing
//! sources, missing facts, backend errors, and fact-source contract violations
//! fail closed to denied ReBAC decisions.
//!
//! # Built-In Policies
//!
//! - [`RbacPolicy`]: role-based access control from caller roles and required
//!   roles for the `(action, resource)` pair.
//! - [`RebacPolicy`]: relationship-based access control backed by
//!   [`FactSource`] and [`EvaluationSession`].
//! - [`DelegatingPolicy`]: maps the current inputs into another
//!   [`PolicyDomain`] and delegates to a child [`PermissionChecker`].
//!
//! Use [`PolicyBuilder::when`] for attribute-style predicates that compare
//! subject, action, resource, and context in one synchronous closure.
//!
//! # Custom Policies
//!
//! Implement [`Policy`] directly when a rule needs async work, custom batching,
//! custom telemetry metadata, or hand-written forbid behavior:
//!
//! ```rust
//! # use async_trait::async_trait;
//! # use std::borrow::Cow;
//! # use gatehouse::*;
//! # #[derive(Debug, Clone)] struct User { id: u64 }
//! # #[derive(Debug, Clone)] struct Document { owner_id: u64 }
//! # #[derive(Debug, Clone)] struct ReadAction;
//! # struct Documents;
//! # impl PolicyDomain for Documents {
//! #     type Subject = User;
//! #     type Action = ReadAction;
//! #     type Resource = Document;
//! #     type Context = ();
//! # }
//! struct OwnerPolicy;
//!
//! #[async_trait]
//! impl Policy<Documents> for OwnerPolicy {
//!     async fn evaluate(&self, ctx: &EvalCtx<'_, Documents>) -> PolicyEvalResult {
//!         if ctx.subject.id == ctx.resource.owner_id {
//!             ctx.grant("subject owns the document")
//!         } else {
//!             ctx.not_applicable("subject does not own the document")
//!         }
//!     }
//!
//!     fn policy_type(&self) -> Cow<'static, str> {
//!         Cow::Borrowed("OwnerPolicy")
//!     }
//! }
//! ```
//!
//! # Tracing
//!
//! When trace-level events are enabled, checker evaluation records spans for
//! single-resource and batch evaluation, and each evaluated policy records a
//! `trace!` event on the `gatehouse::security` target. Batch evaluation also
//! records per-policy counts on nested `gatehouse.batch_policy` spans.

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

pub use builder::PolicyBuilder;
pub use checker::{BoundEvaluator, PermissionChecker};
pub use combinators::{AndPolicy, EmptyPoliciesError, NotPolicy, OrPolicy, PolicyExt};
pub use facts::{FactKey, FactLoadError, FactLoadResult, FactSource, RelationshipQuery};
pub use lookup::{Hydrator, LookupAuthorizedError, LookupAuthorizedPage, LookupPage, LookupSource};
pub use metadata::SecurityRuleMetadata;
pub(crate) use metadata::{DEFAULT_SECURITY_RULE_CATEGORY, PERMISSION_CHECKER_POLICY_TYPE};
pub use policies::{DelegatingPolicy, RbacPolicy, RebacPolicy};
pub use policy::{BatchEvalCtx, Effect, EvalCtx, Policy, PolicyBatchItem, PolicyDomain};
pub use results::{
    AccessEvaluation, CombineOp, EvalTrace, FactOutcome, FactProvenance, PolicyEvalResult,
};
pub use session::{EvaluationSession, FactRegistry, FactRegistryBuilder};

// The shared unit-test module pulls in tokio-based async tests via dev-deps
// that are intentionally loom-incompatible (`tokio::net`, axum, hyper, etc.).
// Gate it out under `cfg(loom)` so the loom build's minimal dependency graph
// stays clean. The synchronous core's deterministic tests and the loom
// permutation tests both live in `src/session/core.rs` and are unaffected.
#[cfg(all(test, not(loom)))]
mod tests;
