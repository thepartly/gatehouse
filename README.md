# Gatehouse 

[![Build status](https://github.com/thepartly/gatehouse/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/thepartly/gatehouse/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/gatehouse)](https://crates.io/crates/gatehouse)
[![Documentation](https://docs.rs/gatehouse/badge.svg)](https://docs.rs/gatehouse)

An in-process authorization engine for Rust. Compose RBAC, ABAC, and relationship-based policies; load relationship facts through a request-scoped session that batches, deduplicates, and coalesces backend calls. List endpoints stay correct and fast without pushing policy into your data layer.

![Gatehouse Logo](https://raw.githubusercontent.com/thepartly/gatehouse/main/.github/logo.svg)

## Features
- **In-process authorization**: Keep policy logic in Rust without requiring a separate authorization service
- **Multi-paradigm policies**: Compose RBAC, ABAC, and ReBAC patterns
- **Request-scoped fact loading**: Load relationship facts through `EvaluationSession` and `FactSource`
- **Batch-safe list endpoints**: Authorize many resources with policy-correct batching, deduplication, and caller-order preservation
- **Policy Composition**: Combine policies with logical operators (`AND`, `OR`, `NOT`)
- **Detailed Evaluation Tracing**: Decision trace for the policies and branches that were actually evaluated
- **Fluent Builder API**: Construct custom policies with a PolicyBuilder.
- **Type Safety**: Strongly typed resources/actions/contexts
- **Async Ready**: Built with async/await support

## Quick Start

```rust
use gatehouse::*;

#[derive(Debug, Clone)]
struct User {
    id: u64,
    roles: Vec<String>,
}

#[derive(Debug, Clone)]
struct Document {
    owner_id: u64,
}

#[derive(Debug, Clone)]
struct Action;

#[derive(Debug, Clone)]
struct Context;

let admin_policy = PolicyBuilder::<User, Document, Action, Context>::new("AdminOnly")
    .subjects(|user| user.roles.iter().any(|role| role == "admin"))
    .build();

let owner_policy = PolicyBuilder::<User, Document, Action, Context>::new("OwnerOnly")
    .when(|user, _action, resource, _ctx| resource.owner_id == user.id)
    .build();

let mut checker = PermissionChecker::new();
checker.add_policy(admin_policy);
checker.add_policy(owner_policy);

# tokio_test::block_on(async {
let user = User {
    id: 1,
    roles: vec!["admin".to_string()],
};
let document = Document { owner_id: 1 };

let session = EvaluationSession::empty();
let evaluation = checker
    .evaluate_in_session(&session, &user, &Action, &document, &Context)
    .await;

assert!(evaluation.is_granted());
println!("{}", evaluation.display_trace());

let outcome: Result<(), String> = evaluation.to_result(|reason| reason.to_string());
assert!(outcome.is_ok());
# });
```

## Why v0.3 Matters

Simple checks still look like normal Rust predicates. The difference shows up when an endpoint has to authorize a page, feed, subscription batch, or search result. Before v0.3, those paths either paid N policy evaluations and N backend round trips, or duplicated policy logic into SQL and risked bypassing later checker policies.

Gatehouse now treats authorization as computation over request-scoped facts. A policy stack can keep in-memory checks, combinators, and relationship checks in one place, while `EvaluationSession` batches and caches the fact loads needed by that request.

You do not need to model every check as a fact. RBAC and ABAC-style predicates stay simple and in-process; fact sources are the production path for data that would otherwise require per-resource I/O, such as relationship checks behind list endpoints.

If you are upgrading from 0.2, see `MIGRATION.md` for the `RelationshipResolver` to `FactSource` migration path and `Policy` trait changes.

## Decision Semantics

- `PermissionChecker` evaluates policies sequentially with `OR` semantics and short-circuits on the first grant.
- An empty `PermissionChecker` always denies with the reason `"No policies configured"`.
- `AndPolicy` short-circuits on the first denial; `OrPolicy` short-circuits on the first grant.
- `NotPolicy` inverts the result of its inner policy.
- `PolicyBuilder` combines all configured predicates with `AND` logic.
- `PolicyBuilder::effect(Effect::Deny)` changes a matching policy result from allow to deny; a non-match is still treated as denied/non-applicable. It does not create global "deny overrides allow" behavior when used inside `PermissionChecker`.
- `AccessEvaluation::Denied.reason` is a summary string such as `"All policies denied access"`. Inspect the trace tree for individual policy reasons.
- Evaluation traces only contain policies and branches that were actually evaluated before short-circuiting.

## Core Components

### `Policy` Trait

The foundation of the authorization system:

```rust
use async_trait::async_trait;
use gatehouse::{BatchEvalCtx, EvalCtx, Policy, PolicyEvalResult, SecurityRuleMetadata};

#[async_trait]
trait Policy<Subject, Resource, Action, Context>: Send + Sync {
    async fn evaluate(&self, ctx: &EvalCtx<'_, Subject, Resource, Action, Context>)
        -> PolicyEvalResult;

    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, Subject, Resource, Action, Context>,
    ) -> Vec<PolicyEvalResult>;

    fn policy_type(&self) -> &str;

    fn security_rule(&self) -> SecurityRuleMetadata {
        SecurityRuleMetadata::default()
    }
}
```

### `PermissionChecker`

Aggregates multiple policies (e.g. RBAC, ABAC) with `OR` logic by default: if any policy grants access, permission is granted. The returned `AccessEvaluation` contains both the final decision and a trace tree of the evaluated policies.

```rust,ignore
let mut checker = PermissionChecker::new();
checker.add_policy(rbac_policy);
checker.add_policy(owner_policy);

// Check if access is granted
let session = EvaluationSession::empty();
let evaluation = checker
    .evaluate_in_session(&session, &user, &action, &resource, &context)
    .await;
if evaluation.is_granted() {
    // Access allowed
} else {
    // Access denied
}

println!("{}", evaluation.display_trace());
```

### Batch Authorization

List and subscription endpoints often need to answer "which of these resources can this subject access?" Use `evaluate_batch_in_session_by` when you need the decision for every input item, or `filter_authorized_in_session_by` when you only need the authorized subset.

```rust
let session = EvaluationSession::empty();
let visible_posts = checker
    .filter_authorized_with_context_in_session_by(
        &session,
        &user,
        &Action::View,
        posts,
        &request_context,
        |post| post,
    )
    .await;
```

The caller keeps ownership of resource loading and context construction. Gatehouse borrows the resource/context pair from each item, preserves input order, and applies the same per-item `OR` semantics as `evaluate_in_session`.

If the item itself is the resource and the context type is `()`, use `evaluate_batch_resources_in_session` or `filter_authorized_resources_in_session`.

Policies can override `Policy::evaluate_batch` to collapse backend work. `RebacPolicy` builds `RelationshipQuery` fact keys and loads them through the request-scoped `EvaluationSession`, so deduplication, chunking, caching, and fail-closed source errors live in one `FactSource` layer. Combinator policies (`AndPolicy`, `OrPolicy`, and `NotPolicy`) preserve batching for their inner policies.

`PermissionChecker::with_max_batch_size` caps the number of still-pending items passed to each policy batch call. Fact-backed policies can also set `FactSource::max_batch_size`, which caps source-level loads after session deduplication.

```rust
use std::num::NonZeroUsize;

let checker = PermissionChecker::new()
    .with_max_batch_size(NonZeroUsize::new(500).unwrap());
```

### Fact Sources And Sessions

`EvaluationSession` is request-scoped. Register the fact sources needed for one request, run the checker, then drop the session. Declare all request sources in one place with `EvaluationSession::builder()`:

```rust,ignore
let session = EvaluationSession::builder()
    .with_arc::<RelationshipQuery<Uuid, Uuid, Relation>>(Arc::clone(&relationships))
    .build();
```

`register` and `register_arc` fail fast if the same fact key type is registered twice. Use `replace` or `replace_arc` only when overwriting a source is intentional. Use `try_register`, `try_register_arc`, `try_replace`, or `try_replace_arc` when setup code should handle registration errors without panicking.

For hot RBAC/ABAC-only paths, `EvaluationSession::shared_empty()` returns a process-wide empty session and avoids per-call allocation. Only use it when no fact-backed policies are expected; it rejects source registration.

The source registry is keyed by the exact Rust fact key type. If two backends serve the same logical key shape, define distinct key/newtype wrappers rather than registering both under one `RelationshipQuery<...>` type.

#### Cache Lifetime And Revocation

Cached facts, cached errors, and in-flight load state do not outlive the request-scoped session. This is a correctness boundary as well as a performance detail: if a permission is revoked after one request has loaded it, a new request builds a new session and must load the fact again.

`FactSource::load_many` receives unique keys and must return exactly one result per key in the same order. The session handles duplicate expansion and caller-order preservation. Missing sources, backend errors, missing facts, wrong result counts, and cancelled loader tasks all fail closed.

If the leader task for an in-flight fact load is cancelled or panics, the session caches `FactLoadError::LoaderCancelled` for those keys and wakes waiters. That intentionally poisons those keys for the rest of the request-scoped session so the request fails closed instead of hanging. Build a fresh session for a retry or a new request.

`RebacPolicy` is the first built-in fact-backed policy. It extracts subject/resource IDs, builds `RelationshipQuery<SubjectId, ResourceId, Relation>` keys, and asks the session for those relationship facts.

Use a typed relation enum when your domain has a fixed relation set, even if the backing store uses strings. The `EvaluationSession` deduplicates and caches by the typed `RelationshipQuery`; the `FactSource` owns the backend boundary and can convert `Relation::Viewer` to `"viewer"` when binding SQL parameters. The `pg18_bulk_rebac` example demonstrates this pattern against a PostgreSQL `text` column.

If several relationship domains all look like `Uuid -> Uuid`, prefer one domain relation enum and dispatch inside the corresponding `FactSource`. If you need separate source registrations, wrap IDs in domain newtypes so each `RelationshipQuery<SubjectId, ResourceId, Relation>` has a distinct Rust type.

### PolicyBuilder
The `PolicyBuilder` provides a fluent API to construct custom policies by chaining predicate functions for 
subjects, actions, resources, and context. Every configured predicate must pass for the built policy to grant access. Once built, the policy can be added to a `PermissionChecker`.

Use `PolicyBuilder` for synchronous predicate logic. If your policy needs async I/O or external lookups, implement `Policy` directly.

```rust,ignore
let custom_policy = PolicyBuilder::<MySubject, MyResource, MyAction, MyContext>::new("CustomPolicy")
    .subjects(|s| /* ... */)
    .actions(|a| /* ... */)
    .resources(|r| /* ... */)
    .context(|c| /* ... */)
    .when(|s, a, r, c| /* ... */)
    .build();
```

### Built-in Policies
- `RbacPolicy`: Role-based access control. Grants when at least one required role for `(resource, action)` is present in the subject's roles.
- `AbacPolicy`: Attribute-based access control. Grants when its boolean condition closure returns `true`.
- `RebacPolicy`: Relationship-based access control. Extracts flat subject/resource IDs, builds `RelationshipQuery` keys, and grants when the request-scoped `EvaluationSession` loads `Found(true)` from a registered `FactSource`.
- `DelegatingPolicy`: Delegates a decision to another `PermissionChecker` after mapping parent-domain inputs into child-domain inputs. Batch delegation preserves the child checker's batch path and trace.

Fact-backed ReBAC failures fail closed: missing sources, missing facts, source errors, and source contract violations produce denied decisions rather than panics or accidental grants.

### Combinators

- `AndPolicy`: Grants access only if all inner policies allow access. Must be created with at least one policy.
- `OrPolicy`: Grants access if any inner policy allows access. Must be created with at least one policy.
- `NotPolicy`: Inverts the decision of an inner policy.
- `DelegatingPolicy`: Cross-domain delegation through another checker, useful when one resource's access depends on another authorization domain.

## Tracing And Telemetry

When trace-level events are enabled, `PermissionChecker::evaluate_in_session` creates an instrumented span and every evaluated policy records a `trace!` event on the `gatehouse::security` target. Batch evaluation records checker-level aggregate fields and nested `gatehouse.batch_policy` spans with per-policy pending/granted/denied counts.

Span, event target, and field names listed here are public observability API. Renaming or removing them is treated as a semver-major change.

Span and event names:

- `evaluate_in_session` span for single-item checker evaluation
- `evaluate_batch_in_session_by` span for batch checker evaluation
- `gatehouse.batch_policy` span for each policy batch pass
- `gatehouse.fact_load` span for each source-level fact load
- `gatehouse::security` target for per-policy security events

Single-item security event fields:

- `security_rule.name`
- `security_rule.category`
- `security_rule.description`
- `security_rule.reference`
- `security_rule.ruleset.name`
- `security_rule.uuid`
- `security_rule.version`
- `security_rule.license`
- `event.outcome`
- `policy.type`
- `policy.result.reason`

Single-item checker span fields:

- `policy_count`
- `outcome`
- `policy.type`

Batch checker span fields:

- `item_count`
- `granted_count`
- `denied_count`
- `policy_count`
- `max_batch_size`

Nested `gatehouse.batch_policy` span fields:

- `policy.type`
- `policy.pending_count`
- `policy.chunk_index`
- `policy.chunk_count`
- `policy.granted_count`
- `policy.denied_count`

`gatehouse.fact_load` span fields:

- `fact.name`
- `fact.load_id`
- `fact.key_count`
- `fact.unique_key_count`

Fallback behavior when `security_rule()` is not overridden:

- `security_rule.name` falls back to `policy_type()`
- `security_rule.category` falls back to `"Access Control"`
- `security_rule.ruleset.name` falls back to `"PermissionChecker"`

## Examples

See the `examples` directory for complete demonstrations of:
- Role-based access control (`rbac_policy`)
- Attribute-style custom policies with `PolicyBuilder` (`policy_builder`)
- Relationship-based access control (`rebac_policy`)
- In-RAM relationship facts shared across request sessions (`in_ram_rebac`)
- PostgreSQL-backed batched relationship facts (`pg18_bulk_rebac`)
- Group authorization with trace output (`groups_policy`)
- Policy combinators (`combinator_policy`)
- Axum integration with shared policies, app state, request-scoped sessions, and a bulk invoice listing endpoint (`axum`)
- Actix Web integration with shared policies (`actix_web`)

Run with:

```shell
cargo run --example rbac_policy
```

## Performance

Criterion benchmarks in `benches/permission_checker.rs` exercise `PermissionChecker::evaluate_in_session` across
several policy stack sizes. Run them with `cargo bench` to track changes in evaluation latency as you evolve
your policy definitions.

The `in_ram_fact_source` Criterion group isolates Gatehouse's session overhead when the source itself is hot and in-process; it is not a benchmark for network or database latency. The `latency_fact_source` group injects a fixed async delay per source call so the benchmarks also show the intended shape under backend latency: N per-item sessions versus one batched session, and independent repeated loads versus shared-session in-flight coalescing.

The `pg18_bulk_rebac` example demonstrates a SQL-backed ReBAC `FactSource` using PostgreSQL 18. It models a list endpoint with an in-memory `PublicPost` policy plus a SQL-backed `viewer` relationship policy, then compares N point queries through per-item sessions with one batched `WITH ORDINALITY` query through `filter_authorized_with_context_in_session_by`:

```shell
DATABASE_URL="host=localhost port=15432 user=postgres password=test dbname=awa_test" \
  cargo run --example pg18_bulk_rebac --release
```

The example prints a CSV so you can compare your own database and machine. Local PostgreSQL 18.3 runs of the mixed-policy example show modest wins for tiny lists and tens-to-low-hundreds improvements once the list is large enough for round trips to dominate. Exact numbers vary; the important property is that the policy stack stays in Gatehouse while relationship fact loading collapses to batched SQL.

The PostgreSQL example uses `tokio-postgres` directly to keep the demonstration small. `sqlx` users should keep the same boundary: implement `FactSource<RelationshipQuery<...>>`, map backend errors to `FactLoadError::backend`, and preserve the one-result-per-input-key contract.
