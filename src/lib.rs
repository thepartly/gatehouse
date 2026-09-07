#![forbid(unsafe_code)]

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
//! let authorized = bound.try_filter(resources).await?;
//! let authorized_rows = bound.try_filter_by(rows, |row| &row.authz_resource).await?;
//! let page = bound.try_lookup_page(&lookup, &hydrator, cursor.as_deref(), limit).await?;
//! ```
//!
//! Use [`EvaluationSession::empty`] for fact-free decisions. Use a session from
//! [`FactRegistry::session`] when any policy loads facts — via `ctx.fact(...)`
//! (which also records provenance) or the raw session — such as [`RebacPolicy`]
//! or a custom fact-backed policy.
//!
//! [`BoundEvaluator::evaluate`] preserves input order and retains every item
//! and decision. [`BoundEvaluator::try_filter`] excludes definite denials but
//! fails on indeterminate decisions; [`BoundEvaluator::try_filter_by`] applies
//! the same rule to projected caller-owned rows. Errors retain all input items
//! and evaluations. The original `filter` helpers deliberately omit outages.
//!
//! [`BoundEvaluator::try_lookup_page`] enumerates candidate IDs, hydrates them,
//! and strictly authorizes one page. [`LookupSource`] must cover every grant
//! path, including admin overrides. On evaluation failure, no next cursor is
//! returned: retry the same cursor with a fresh session after recovery.
//!
//! # Decision Semantics
//!
//! [`Policy`] returns [`GrantResult`]: grant, abstention, or indeterminate.
//! [`VetoPolicy`] returns [`VetoResult`]: veto, pass, or indeterminate. Register
//! them with [`PermissionChecker::add_policy`] and [`PermissionChecker::add_veto`].
//! These types prevent grant policies from returning veto authority.
//!
//! A definite veto denies access. An unresolved veto blocks grants. After
//! vetoes pass, any grant authorizes, including a grant after another grant
//! policy failed. With no grant, uncertainty yields [`AccessEvaluation::Indeterminate`];
//! otherwise access is denied. An empty checker denies access.
//!
//! [`AndPolicy`], [`OrPolicy`], and [`NotPolicy`] compose grants only. A definite
//! abstention settles AND; a definite grant settles OR; NOT retains uncertainty.
//! Use `grant.and(blocked.not())` for a local exclusion. Vetoes use
//! [`AllOfVeto`] or [`AnyOfVeto`]; a pass settles all-of and a veto settles any-of,
//! otherwise uncertainty remains. Veto negation is not supported.
//!
//! [`PolicyBuilder::build`] produces a grant policy;
//! [`PolicyBuilder::build_veto`] produces a veto when its predicate matches.
//! Register [`DelegatingPolicy`] once with [`PermissionChecker::add_delegate`]
//! to preserve both child capabilities and their distinct failure semantics.
//!
//! [`PolicyEvalResult`] is the inspectable audit tree, not a policy return type.
//! Typed result constructors compute aggregate decisions; arbitrary raw trees
//! cannot be promoted into typed authority. [`GrantResult::all`] and
//! [`GrantResult::any`] support custom grant aggregates.
//!
//! Use [`AccessEvaluation::into_result`] to distinguish [`AccessError::Denied`]
//! from [`AccessError::Indeterminate`] without parsing reasons. Both errors retain
//! the full trace and classified fact errors. The original `to_result` combines
//! both outcomes into one reason-only callback.
//!
//! Recorded successful, missing, and failed facts are retained on every node,
//! including aggregates. Recorded errors upgrade abstention/pass to indeterminate;
//! decisive grants and vetoes remain decisive. Attaching evidence has the same
//! behavior for leaves and aggregate nodes. Call `ctx.finish(result)` when
//! evaluating a policy directly; the checker and built-in combinators do this
//! automatically.
//!
//! # Cargo Features
//!
//! `tracing` is enabled by default. Disable default features to remove its
//! instrumentation and dependency; decisions, returned [`EvalTrace`], and fact
//! provenance remain available. No telemetry events or contract warnings are
//! emitted without tracing. `serde` independently enables audit serialization.
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
//! when the request session loads a `Found(true)` relationship fact. A
//! `Found(false)` or `Missing` fact is an ordinary non-grant; missing
//! sources, backend errors, and fact-source contract violations fail closed
//! as [`PolicyEvalResult::Indeterminate`] — never a grant, and structurally
//! distinguishable from a policy denial.
//!
//! # Long-Lived Streams
//!
//! [`EvaluationSession`] caches are scoped to one authorization pass. For SSE,
//! WebSocket, and other long-lived streams, do not hold one fact-backed session
//! for the stream lifetime.
//!
//! If your product contract authorizes once at stream open, create a fresh
//! session, compute the visible ID set with [`BoundEvaluator::try_filter`] or
//! [`BoundEvaluator::try_filter_by`], drop the session, and only emit frames for
//! that set. If the stream must observe mid-stream permission revocation, run
//! periodic reauthorization with a fresh [`FactRegistry::session`] and re-bind
//! the checker for that pass.
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
//! or custom telemetry metadata. Implement [`VetoPolicy`] for custom vetoes.
//! A grant policy looks like this:
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
//!     async fn evaluate(&self, ctx: &EvalCtx<'_, Documents>) -> GrantResult {
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
mod capability;
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
pub use capability::{GrantResult, PolicyResult, VetoPolicy, VetoResult};
pub use checker::{BoundEvaluator, PermissionChecker};
pub use combinators::{
    AllOfVeto, AndPolicy, AnyOfVeto, EmptyPoliciesError, NotPolicy, OrPolicy, PolicyExt,
    VetoPolicyExt,
};
pub use facts::{
    FactKey, FactLoadError, FactLoadErrorKind, FactLoadResult, FactSource, RelationshipQuery,
};
pub use lookup::{Hydrator, LookupAuthorizedError, LookupAuthorizedPage, LookupPage, LookupSource};
pub use metadata::SecurityRuleMetadata;
#[cfg(feature = "tracing")]
pub(crate) use metadata::DEFAULT_SECURITY_RULE_CATEGORY;
pub(crate) use metadata::PERMISSION_CHECKER_POLICY_TYPE;
pub use policies::{DelegatingPolicy, RbacPolicy, RebacPolicy};
pub use policy::{BatchEvalCtx, EvalCtx, Policy, PolicyBatchItem, PolicyDomain};
pub use results::{
    AccessError, AccessEvaluation, CombineOp, Decision, EvalTrace, FactOutcome, FactProvenance,
    FilterError, PolicyEvalResult,
};
pub use session::{EvaluationSession, FactRegistry, FactRegistryBuilder};

// The shared unit-test module pulls in tokio-based async tests via dev-deps
// that are intentionally loom-incompatible (`tokio::net`, axum, hyper, etc.).
// Gate it out under `cfg(loom)` so the loom build's minimal dependency graph
// stays clean. The synchronous core's deterministic tests and the loom
// permutation tests both live in `src/session/core.rs` and are unaffected.
#[cfg(all(test, not(loom)))]
mod tests;
