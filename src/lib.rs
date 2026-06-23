//! An in-process authorization engine for Rust.
//!
//! Gatehouse composes role-based (RBAC), relationship-based (ReBAC), and
//! ABAC-style predicate policies while keeping authorization logic in Rust.
//! Relationship facts are loaded through request-scoped
//! [`EvaluationSession`] values, so list endpoints can batch, deduplicate, and
//! coalesce backend calls without moving policy logic into the data layer.
//!
//! # Overview
//!
//! A [`Policy`] is an asynchronous decision unit: it checks whether a subject
//! may perform an action on a resource in a context. A [`PermissionChecker`]
//! runs one or more policies and returns an [`AccessEvaluation`] containing the
//! final decision plus the trace of policies that were actually evaluated.
//!
//! The common shape is one checker per resource type. For example, use a
//! `PermissionChecker<User, DocumentAction, Document, RequestContext>` for
//! documents and a separate checker for invoices. Cross-cutting policies such
//! as an admin override can be reused across those checkers. See the
//! [`PermissionChecker`] docs for the "one checker per resource type" and
//! list/scope endpoint recipes.
//!
//! ## Quick Start
//!
//! The fastest way to define a policy is with [`PolicyBuilder`]:
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
//! let admin_policy = PolicyBuilder::<User, ReadAction, Document, ()>::new("AdminOnly")
//!     .subjects(|user: &User| user.roles.contains(&"admin"))
//!     .build();
//!
//! let owner_policy = PolicyBuilder::<User, ReadAction, Document, ()>::new("OwnerOnly")
//!     .when(|user: &User, _action: &ReadAction, document: &Document, _ctx: &()| {
//!         user.id == document.owner_id
//!     })
//!     .build();
//!
//! let mut checker = PermissionChecker::new();
//! checker.add_policy(admin_policy);
//! checker.add_policy(owner_policy);
//!
//! # tokio_test::block_on(async {
//! let document = Document { owner_id: 7 };
//! let admin = User { id: 1, roles: vec!["admin"] };
//! let owner = User { id: 7, roles: vec!["user"] };
//! let guest = User { id: 2, roles: vec!["user"] };
//!
//! assert!(checker.check(&admin, &ReadAction, &document, &()).await.is_granted());
//! assert!(checker.check(&owner, &ReadAction, &document, &()).await.is_granted());
//! assert!(!checker.check(&guest, &ReadAction, &document, &()).await.is_granted());
//! # });
//! ```
//!
//! ## Which API should I use?
//!
//! Three workflows cover most call sites:
//!
//! ```text
//! single resource
//!   subject + action + resource + context
//!       -> check / evaluate_in_session
//!       -> AccessEvaluation
//!
//! already-loaded candidates
//!   Vec<item>
//!       -> evaluate_batch_in_session   (keep every decision)
//!       -> filter_authorized_in_session (keep only allowed items)
//!
//! unknown candidate set
//!   LookupSource -> Hydrator -> lookup_authorized_page
//! ```
//!
//! Start with [`PermissionChecker::check`] for ordinary point checks that do
//! not load facts. Use [`PermissionChecker::evaluate_in_session`] when any
//! policy reads fact-backed state.
//!
//! For lists where you already have the candidate resources, use
//! [`PermissionChecker::filter_authorized_in_session`] when you only need the
//! allowed items, or [`PermissionChecker::evaluate_batch_in_session`] when you
//! need the full per-item [`AccessEvaluation`] trace. Both methods accept an
//! item iterator plus a closure that borrows `(&resource, &context)` from each
//! item.
//!
//! For lists where the candidate set is too large to load first, use
//! [`PermissionChecker::lookup_authorized_page`] with a [`LookupSource`] and
//! [`Hydrator`].
//!
//! `check` uses [`EvaluationSession::shared_empty`] internally. For ReBAC or
//! any custom policy that calls `ctx.session.get(...)`, build a [`FactRegistry`]
//! at application setup, create a request session with
//! [`FactRegistry::session`], and pass it to
//! [`PermissionChecker::evaluate_in_session`] or the corresponding batch API:
//!
//! ```rust,ignore
//! type DocumentRelationship = RelationshipQuery<UserId, DocumentId, Relation>;
//!
//! let registry = FactRegistry::builder()
//!     .with::<DocumentRelationship, _>(relationship_source)
//!     .build();
//! let session = registry.session();
//!
//! let decision = checker
//!     .evaluate_in_session(&session, &user, &Action::View, &document, &request_context)
//!     .await;
//! ```
//!
//! ## Decision Semantics
//!
//! `gatehouse` deliberately keeps decision semantics fixed: there is no
//! combining-algorithm setting.
//!
//! - [`PermissionChecker`] applies **deny-overrides**. Any policy that
//!   *forbids* (a declared [`Effect::Forbid`] policy whose predicate matches,
//!   producing [`PolicyEvalResult::Forbidden`]) denies the request and
//!   overrides every grant. If no policy forbids, any granting policy grants
//!   (`OR`, short-circuiting on the first grant). If nothing grants, the
//!   request is denied.
//! - Forbid-effect policies are evaluated before allow policies, so a veto is
//!   not skipped by the grant short-circuit. Registration order within each
//!   effect group is preserved; registration order between deny and allow
//!   policies does not change the decision.
//! - [`PolicyEvalResult::NotApplicable`] means "this policy did not grant".
//!   [`PolicyEvalResult::Forbidden`] means "this policy actively vetoed".
//! - An empty [`PermissionChecker`] denies access with the reason
//!   `"No policies configured"`.
//! - [`AndPolicy`] short-circuits on the first non-grant.
//! - [`OrPolicy`] short-circuits on the first grant.
//! - [`NotPolicy`] inverts the decision of its inner policy.
//! - Inside combinators a `Forbidden` child behaves like `Denied`: forbids are
//!   honored at the checker level, not propagated through combinator trees.
//!   Register forbidding policies directly on the checker; use
//!   `AndPolicy[grant, NotPolicy(block)]` when an exclusion should gate only
//!   one grant path.
//! - [`PolicyBuilder`] combines configured predicates with AND logic.
//!   [`PolicyBuilder::forbid`] makes a matching policy forbid; a non-match is
//!   not applicable and never blocks anything.
//! - Hand-written policies that can return `Forbidden` via [`EvalCtx::forbid`]
//!   must override [`Policy::effect`] to return [`Effect::Forbid`]. A
//!   forbid-effect policy that returns `Granted` violates the contract; the
//!   checker treats that result as not applicable and logs a warning.
//!
//! Denials from [`AccessEvaluation`] are intentionally summary-level: a veto
//! reports `"Forbidden by <policy>: <reason>"` (also exposed through
//! [`AccessEvaluation::forbidden_by`]), and a no-grant denial reports
//! `"All policies denied access"`. Use [`AccessEvaluation::display_trace`] or
//! the attached [`EvalTrace`] to inspect individual policy reasons.
//!
//! ## Trace Semantics
//!
//! [`EvalTrace`] records the policies and combinator branches that actually
//! ran. Because [`PermissionChecker`], [`AndPolicy`], and [`OrPolicy`]
//! short-circuit, the trace tree does not include policies that were never
//! evaluated. The checker's root node is a `DENY_OVERRIDES` combine node whose
//! children appear in evaluation order: forbid-effect policies first, then allow
//! policies. A checker with no policies is the exception: its trace is the
//! single `"No policies configured"` denial leaf.
//!
//! ## Modeling Inputs
//!
//! Gatehouse's generic parameters are meant to keep authorization inputs in
//! the place that owns them:
//!
//! | Input | Put here |
//! | --- | --- |
//! | Caller identity and stable caller attributes | `Subject` |
//! | The verb or operation being attempted | `Action` |
//! | The target instance, or a scope resource for a scope/list check | `Resource` |
//! | Request-scoped values such as current time, MFA freshness, network zone, tenant config, or feature flags | `Context` |
//! | Relationship data or other backend lookups that should batch, cache, and fail closed per request | [`FactSource`] loaded through [`EvaluationSession`] |
//!
//! Use `Context = ()` when the decision is fully determined by subject,
//! resource, and action. Reach for a real context struct when the same subject,
//! resource, and action can produce different decisions on different calls.
//! Do not put relationship data such as "who has viewer access on this
//! document" in `Context`; expose it as a typed [`FactKey`] and load it through
//! the session. See `examples/mfa_freshness_context.rs` for a concrete context
//! example.
//!
//! ## Fact-Loaded Authorization
//!
//! Gatehouse treats non-trivial authorization as computation over facts loaded
//! for one request. [`FactSource::load_many`] receives unique fact keys and
//! must return exactly one result per key in the same order. The
//! [`EvaluationSession`] expands duplicate caller inputs, preserves caller
//! order, caches results for the request, chunks loads according to
//! [`FactSource::max_batch_size`], and joins concurrent in-flight loads for the
//! same key.
//!
//! Build a [`FactRegistry`] once during application setup, register the
//! sources the application may need, and create a fresh
//! [`EvaluationSession`] from [`FactRegistry::session`] for each request.
//!
//! [`FactSource`] is Gatehouse's request-scoped DataLoader-style primitive. If
//! your application already uses a DataLoader implementation, call it directly
//! from inside [`FactSource::load_many`]. Gatehouse owns the authorization
//! fact graph for the request; the underlying loader can own backend-specific
//! batching or longer-lived caching. The same composition pattern applies to
//! [`Hydrator::hydrate`] for lookup-style listings.
//!
//! [`RebacPolicy`] is the built-in fact-backed policy. It extracts flat
//! subject/resource IDs, builds [`RelationshipQuery`] keys, and grants only
//! when the request session loads a `Found(true)` relationship fact. Missing
//! sources, missing facts, backend errors, and fact-source contract violations
//! fail closed to denied ReBAC decisions.
//!
//! [`LookupSource`] and [`Hydrator`] support list endpoints where the caller
//! cannot load every possible candidate first. The lookup source must enumerate
//! a candidate superset for every grant path in the consuming checker; gatehouse
//! then hydrates those IDs and runs the full policy stack on the hydrated
//! subset.
//!
//! ## Built-in Policies
//!
//! The library provides several built-in policies:
//!  - [`RbacPolicy`]: A role-based access control policy.
//!  - [`RebacPolicy`]: A relationship-based access control policy backed by
//!    [`FactSource`] and [`EvaluationSession`].
//!  - [`DelegatingPolicy`]: A policy that maps the current inputs into another
//!    authorization domain and delegates to a child [`PermissionChecker`].
//!
//! Use [`PolicyBuilder::when`] for attribute-style predicates that compare
//! subject, action, resource, and context in one synchronous closure.
//!
//! ## Custom Policies
//!
//! Use [`PolicyBuilder`] for synchronous predicates. Implement [`Policy`]
//! directly when the policy needs async work, a custom batch path, custom
//! telemetry metadata, or explicit forbid-effect behavior.
//!
//! ```rust
//! # use async_trait::async_trait;
//! # use std::borrow::Cow;
//! # use gatehouse::*;
//!
//! #[derive(Debug, Clone)]
//! struct User { id: u64 }
//! #[derive(Debug, Clone)]
//! struct Document { owner_id: u64 }
//! #[derive(Debug, Clone)]
//! struct ReadAction;
//!
//! struct OwnerPolicy;
//!
//! #[async_trait]
//! impl Policy<User, ReadAction, Document, ()> for OwnerPolicy {
//!     async fn evaluate(&self, ctx: &EvalCtx<'_, User, ReadAction, Document, ()>) -> PolicyEvalResult {
//!         if ctx.subject.id == ctx.resource.owner_id {
//!             ctx.grant("subject owns document")
//!         } else {
//!             ctx.not_applicable("subject does not own document")
//!         }
//!     }
//!
//!     fn policy_type(&self) -> Cow<'static, str> {
//!         Cow::Borrowed("OwnerPolicy")
//!     }
//! }
//!
//! # tokio_test::block_on(async {
//! let mut checker = PermissionChecker::new();
//! checker.add_policy(OwnerPolicy);
//!
//! let user = User { id: 7 };
//! let document = Document { owner_id: 7 };
//! assert!(checker.check(&user, &ReadAction, &document, &()).await.is_granted());
//! # });
//! ```
//!
//! ## Tracing And Telemetry
//!
//! When trace-level events are enabled, [`PermissionChecker::evaluate_in_session`]
//! creates an instrumented span and each evaluated policy records a `trace!`
//! event on the `gatehouse::security` target. Batch evaluation records checker
//! aggregate counts on [`PermissionChecker::evaluate_batch_in_session`],
//! per-policy counts on nested `gatehouse.batch_policy` spans.
//!
//! Reason strings and [`FactProvenance`] details are emitted verbatim. Do not
//! put credentials, tokens, raw PII, or other sensitive values in policy reason
//! strings, rendered fact keys, or fact-load error details if production
//! tracing subscribers will receive them.
//!
//! Security event fields:
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
//! Sometimes you may want to require that several policies pass (AND), require
//! that at least one passes (OR), or invert a policy (NOT). `gatehouse`
//! provides combinators for this purpose:
//!
//! - [`AndPolicy`]: Grants access only if all inner policies allow access.
//!   Otherwise, returns a combined non-grant decision.
//! - [`OrPolicy`]: Grants access if any inner policy allows access. Otherwise,
//!   returns a combined non-grant decision.
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

pub use builder::PolicyBuilder;
pub use checker::PermissionChecker;
pub use combinators::{AndPolicy, EmptyPoliciesError, NotPolicy, OrPolicy};
pub use facts::{FactKey, FactLoadError, FactLoadResult, FactSource, RelationshipQuery};
pub use lookup::{Hydrator, LookupAuthorizedError, LookupAuthorizedPage, LookupPage, LookupSource};
pub use metadata::SecurityRuleMetadata;
pub(crate) use metadata::{DEFAULT_SECURITY_RULE_CATEGORY, PERMISSION_CHECKER_POLICY_TYPE};
pub use policies::{DelegatingPolicy, RbacPolicy, RebacPolicy};
pub use policy::{BatchEvalCtx, Effect, EvalCtx, Policy, PolicyBatchItem};
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
