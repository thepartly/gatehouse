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
//! [`Policy`] trait. A [`PermissionChecker`] aggregates multiple policies with
//! deny-overrides semantics: any matching [`Effect::Deny`] policy denies access;
//! otherwise, if any policy grants access, then access is allowed.
//! The [`PolicyBuilder`] offers a builder pattern for creating custom policies.
//! Custom [`Policy`] implementations must provide both [`Policy::evaluate`]
//! and [`Policy::policy_type`].
//!
//! ## Decision Semantics
//!
//! `gatehouse` deliberately keeps decision semantics simple, explicit, and
//! fixed — there is no combining-algorithm knob:
//!
//! - [`PermissionChecker`] applies **deny-overrides**: any policy that
//!   *forbids* (an [`Effect::Deny`] policy whose predicate matches, producing
//!   [`PolicyEvalResult::Forbidden`]) denies the request, overriding every
//!   grant. Otherwise the policies combine with OR semantics and
//!   short-circuit on the first grant. Otherwise the request is denied.
//! - Deny-effect policies are evaluated before allow policies, so a veto is
//!   never skipped by the grant short-circuit. Registration order does not
//!   change the decision.
//! - An empty [`PermissionChecker`] denies access with the reason
//!   `"No policies configured"`.
//! - [`AndPolicy`] short-circuits on the first non-grant.
//! - [`OrPolicy`] short-circuits on the first grant.
//! - [`NotPolicy`] inverts the decision of its inner policy.
//! - Inside combinators a `Forbidden` child behaves exactly like `Denied`:
//!   forbids are honored at the checker level, not propagated through
//!   combinator trees. Register forbidding policies directly on the checker;
//!   use `AndPolicy[grant, NotPolicy(block)]` when an exclusion should gate
//!   only one grant path (see `examples/deny_override.rs`).
//! - [`PolicyBuilder`] combines all configured predicates with AND logic.
//!   [`PolicyBuilder::effect`] declares whether a match grants or forbids; a
//!   non-match is "not applicable" either way and never blocks anything.
//! - Hand-written policies that can return `Forbidden` (via
//!   [`EvalCtx::forbid`]) must override [`Policy::effect`] to declare
//!   [`Effect::Deny`]; see [`Policy::effect`] for the contract.
//!
//! Denials from [`AccessEvaluation`] are intentionally summary-level: a veto
//! reports `"Forbidden by <policy>: <reason>"` (also exposed structurally via
//! [`AccessEvaluation::forbidden_by`]), and a no-grant denial reports
//! `"All policies denied access"`. Use the attached [`EvalTrace`] to inspect
//! the individual policy reasons that led to that outcome.
//!
//! ## Trace Semantics
//!
//! [`EvalTrace`] records the policies and combinator branches that were actually
//! evaluated. Because [`PermissionChecker`], [`AndPolicy`], and [`OrPolicy`]
//! short-circuit, the trace tree does not include policies that were never run.
//! The checker's root node is a `DENY_OVERRIDES` combine node whose children
//! appear in evaluation order: deny-effect policies first, then allow
//! policies. A forbid ends the evaluation, so a vetoed request's trace shows
//! the forbidding policy as its last child. The exception is a checker with
//! no policies at all, whose trace is the single `"No policies configured"`
//! denial leaf with no combine node around it.
//!
//! ## When to populate the Context type
//!
//! `Context` carries **request-scoped inputs the decision depends on but
//! that don't belong on the subject or resource and aren't fact-loadable
//! relationships**. The current wall-clock time, the MFA freshness on
//! the auth session, the caller's network zone, the request's tenant
//! config — all properties of the *call*, not of the user or the thing
//! being authorized. A few shapes show up repeatedly:
//!
//! - **Time-of-day / business hours.** "Finance approvers can issue refunds
//!   between 09:00 and 17:00 in the company timezone, except admins."
//!   The current wall-clock time isn't a property of the user or the
//!   invoice — it's a property of the *call*. Put a `current_time: SystemTime`
//!   (or `OffsetDateTime`, or a `Clock` trait object for testability) on
//!   `Context` and have the policy compare against the resource's
//!   business-hours window. The `examples/actix_web.rs` `RequestContext`
//!   uses exactly this shape for the draft-recency policy.
//!
//! - **Authentication / MFA freshness.** "Approving a payment over $10k
//!   requires an MFA assertion within the last 5 minutes." MFA freshness
//!   lives on the request (the session token records when MFA was last
//!   reasserted), not on the user record. A `mfa_verified_at:
//!   Option<SystemTime>` on `Context` lets the high-value policy short-
//!   circuit deny when freshness has lapsed without forcing every policy
//!   to plumb the auth-session through their own arguments. See
//!   `examples/mfa_freshness_context.rs` for the full end-to-end shape.
//!
//! - **Device / network trust posture.** "Production database access
//!   requires the request to come from a managed device on the corporate
//!   VPN." `device_trust_score: u8`, `network_zone: NetworkZone`, or
//!   `client_ip: IpAddr` on `Context` are the typical shape. Policies
//!   that don't care about posture simply ignore the field.
//!
//! - **Request-wide parameters shared across actions.** When the same
//!   per-request input shapes the decision for many different actions
//!   — `export_destination: ExportDestination`, `purpose: AccessPurpose`,
//!   `client_app_version: SemVer` — `Context` is the right home for it.
//!   Per-action attributes that only one action cares about belong on
//!   the action enum instead.
//!
//! - **Tenant / feature-flag overrides.** A `tenant_config:
//!   &'a TenantPolicyConfig` reference lets policies read tenant-level
//!   toggles ("this tenant has BYOK enabled", "this tenant requires
//!   approval for refunds over $X") without each policy looking the
//!   tenant up itself. Distinct from [`FactSource`]-loaded facts: those
//!   are looked up by key during evaluation; the tenant config is
//!   already resolved at request entry.
//!
//! `Context = ()` is the right call when every decision boils down to
//! "does the subject have role X" — pure RBAC, no time, no posture,
//! no per-request flags. Reach for a real `Context` struct as soon as
//! a policy needs to compare against something time-varying or
//! per-request that isn't a property of the subject, the resource, or
//! a fact-loadable relationship.
//!
//! `Context` is **not** the place for relationship data ("who has
//! viewer access on this document"). That lives behind a
//! [`FactSource`] and gets loaded through the [`EvaluationSession`] so
//! batch evaluation can deduplicate and coalesce.
//!
//! ## Fact-Loaded Authorization
//!
//! Gatehouse treats non-trivial authorization as computation over facts loaded
//! for one request. [`FactSource::load_many`] receives unique fact keys and
//! returns exactly one result per key; [`EvaluationSession`] expands duplicate
//! caller inputs, preserves caller order, caches results for the request, and
//! joins concurrent in-flight loads for the same key.
//!
//! [`FactSource`] is Gatehouse's **request-scoped DataLoader-style primitive**:
//! the session deduplicates and caches keys before calling the source, then
//! chunks the unique key set according to
//! [`FactSource::max_batch_size`] — so the source may receive one or more
//! batched calls per request, each over a slice of the unique keys. If your
//! application already uses a DataLoader implementation (for example
//! `async_graphql::dataloader` from the `async-graphql` crate, or the
//! `ultra-batch` crate), call it directly from inside
//! [`FactSource::load_many`] — gatehouse does not need its own batching
//! layer for the data fetch, only for the per-request fact graph. The same
//! composition pattern applies to the [`Hydrator`] used by lookup-style
//! listings (`Hydrator::hydrate`).
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
//! let admin = User { roles: vec!["admin".into()] };
//! assert!(checker.check(&admin, &ReadAction, &Document, &AppContext).await.is_granted());
//!
//! let guest = User { roles: vec!["guest".into()] };
//! assert!(!checker.check(&guest, &ReadAction, &Document, &AppContext).await.is_granted());
//! # });
//! ```
//!
//! `check` is the everyday entry point for policies that don't need
//! [`FactSource`]-loaded relationship data. For fact-backed checkers
//! (RBAC/ABAC alongside [`RebacPolicy`], or any policy reading from an
//! [`EvaluationSession`]), use [`PermissionChecker::evaluate_in_session`]
//! and pass a session loaded for the request.
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
//!             ctx.grant("User is admin")
//!         } else {
//!             ctx.deny("User is not admin")
//!         }
//!     }
//!     fn policy_type(&self) -> std::borrow::Cow<'static, str> {
//!         std::borrow::Cow::Borrowed("AdminPolicy")
//!     }
//! }
//!
//! // An ABAC policy: grant access if the user is the owner of the document.
//! struct OwnerPolicy;
//!
//! #[async_trait]
//! impl Policy<User, Document, ReadAction, EmptyContext> for OwnerPolicy {
//!     async fn evaluate(&self, ctx: &EvalCtx<'_, User, Document, ReadAction, EmptyContext>) -> PolicyEvalResult {
//!         if ctx.subject.id == ctx.resource.owner_id {
//!             ctx.grant("User is the owner")
//!         } else {
//!             ctx.deny("User is not the owner")
//!         }
//!     }
//!     fn policy_type(&self) -> std::borrow::Cow<'static, str> {
//!         std::borrow::Cow::Borrowed("OwnerPolicy")
//!     }
//! }
//!
//! // Create a PermissionChecker (deny-overrides over the registered policies;
//! // with no deny-effect policies this is simply OR) and add both policies.
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
//! assert!(checker.check(&admin_user, &ReadAction, &document, &EmptyContext).await.is_granted());
//!
//! // The owner should have access.
//! assert!(checker.check(&owner_user, &ReadAction, &document, &EmptyContext).await.is_granted());
//!
//! // A random user should be denied access.
//! let random_user = User {
//!     id: Uuid::new_v4(),
//!     roles: vec!["user".into()],
//! };
//! assert!(!checker.check(&random_user, &ReadAction, &document, &EmptyContext).await.is_granted());
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

pub use builder::PolicyBuilder;
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
pub use policy::{BatchEvalCtx, Effect, EvalCtx, Policy, PolicyBatchItem};
pub use results::{
    AccessEvaluation, CombineOp, EvalTrace, FactOutcome, FactProvenance, PolicyEvalResult,
};
pub use session::{EvaluationSession, EvaluationSessionBuilder};

// The shared unit-test module pulls in tokio-based async tests via dev-deps
// that are intentionally loom-incompatible (`tokio::net`, axum, hyper, etc.).
// Gate it out under `cfg(loom)` so the loom build's minimal dependency graph
// stays clean. The synchronous core's deterministic tests and the loom
// permutation tests both live in `src/session/core.rs` and are unaffected.
#[cfg(all(test, not(loom)))]
mod tests;
