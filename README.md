# Gatehouse 

[![Build status](https://github.com/thepartly/gatehouse/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/thepartly/gatehouse/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/gatehouse)](https://crates.io/crates/gatehouse)
[![Documentation](https://docs.rs/gatehouse/badge.svg)](https://docs.rs/gatehouse)

A flexible authorization library that combines role-based (RBAC), attribute-based (ABAC), and relationship-based (ReBAC) access control policies.

![Gatehouse Logo](https://raw.githubusercontent.com/thepartly/gatehouse/main/.github/logo.svg)

## Features
- **Multi-paradigm Authorization**: Support for RBAC, ABAC, and ReBAC patterns
- **Policy Composition**: Combine policies with logical operators (`AND`, `OR`, `NOT`)
- **Detailed Evaluation Tracing**: Complete decision trace for debugging and auditing
- **Fluent Builder API**: Construct custom policies with a PolicyBuilder.
- **Type Safety**: Strongly typed resources/actions/contexts
- **Async Ready**: Built with async/await support

## Core Components

### `Policy` Trait

The foundation of the authorization system:

```rust
#[async_trait]
trait Policy<Subject, Resource, Action, Context> {
    async fn evaluate(&self, ctx: &EvalCtx<'_, Subject, Resource, Action, Context>)
        -> PolicyEvalResult;
}
```

### `PermissionChecker`

Aggregates multiple policies (e.g. RBAC, ABAC) with `OR` logic by default: if any policy grants access, permission is granted.

```rust
let mut checker = PermissionChecker::new();
checker.add_policy(rbac_policy);
checker.add_policy(owner_policy);

// Check if access is granted
let session = EvaluationSession::empty();
let result = checker
    .evaluate_in_session(&session, &user, &action, &resource, &context)
    .await;
if result.is_granted() {
    // Access allowed
} else {
    // Access denied
}
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

Policies can override `Policy::evaluate_batch` to collapse backend work. `RebacPolicy` builds `RelationshipQuery` fact keys and loads them through the request-scoped `EvaluationSession`, so deduplication, chunking, caching, and fail-closed source errors live in one `FactSource` layer. Combinator policies (`AndPolicy`, `OrPolicy`, and `NotPolicy`) preserve batching for their inner policies.

`PermissionChecker::with_max_batch_size` caps the number of still-pending items passed to each policy batch call. Fact-backed policies can also set `FactSource::max_batch_size`, which caps source-level loads after session deduplication.

```rust
use std::num::NonZeroUsize;

let checker = PermissionChecker::new()
    .with_max_batch_size(NonZeroUsize::new(500).unwrap());
```

### PolicyBuilder
The `PolicyBuilder` provides a fluent API to construct custom policies by chaining predicate functions for 
subjects, actions, resources, and context. Once built, the policy can be added to a [`PermissionChecker`].

```rust
let custom_policy = PolicyBuilder::<MySubject, MyResource, MyAction, MyContext>::new("CustomPolicy")
    .subjects(|s| /* ... */)
    .actions(|a| /* ... */)
    .resources(|r| /* ... */)
    .context(|c| /* ... */)
    .when(|s, a, r, c| /* ... */)
    .build();
```

### Built-in Policies
- RbacPolicy: Role-based access control
- AbacPolicy: Attribute-based access control
- RebacPolicy: Relationship-based access control

### Combinators

AndPolicy: Grants access only if all inner policies allow access
OrPolicy: Grants access if any inner policy allows access
NotPolicy: Inverts the decision of an inner policy

## Examples

See the `examples` directory for complete demonstrations of:
- Role-based access control (`rbac_policy`)
- Relationship-based access control (`rebac_policy`)
- Policy combinators (`combinator_policy`)
- Axum integration with shared policies (`axum`)
- Actix Web integration with shared policies (`actix_web`)

Run with:

```shell
cargo run --example rbac_policy
```

## Performance

Criterion benchmarks in `benches/permission_checker.rs` exercise `PermissionChecker::evaluate_in_session` across
several policy stack sizes. Run them with `cargo bench` to track changes in evaluation latency as you evolve
your policy definitions.

The `pg18_bulk_rebac` example demonstrates a SQL-backed ReBAC `FactSource` using PostgreSQL 18. It compares N point queries through per-item sessions with one bulk `WITH ORDINALITY` query through `filter_authorized_with_context_in_session_by`:

```shell
DATABASE_URL="host=localhost port=15432 user=postgres password=test dbname=awa_test" \
  cargo run --example pg18_bulk_rebac --release
```

On a local PostgreSQL 18.3 container, the bulk path was about 5x faster for 10 resources, 34x faster for 100 resources, and over 100x faster for 1,000+ resources.
