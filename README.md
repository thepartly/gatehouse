# Gatehouse 

[![Build status](https://github.com/thepartly/gatehouse/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/thepartly/gatehouse/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/gatehouse)](https://crates.io/crates/gatehouse)
[![Documentation](https://docs.rs/gatehouse/badge.svg)](https://docs.rs/gatehouse)

A flexible authorization library that combines role-based (RBAC), attribute-based (ABAC), and relationship-based (ReBAC) access control policies.

![Gatehouse Logo](https://raw.githubusercontent.com/thepartly/gatehouse/main/.github/logo.svg)

## Features
- **Multi-paradigm Authorization**: Support for RBAC, ABAC, and ReBAC patterns
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

let evaluation = checker
    .evaluate_access(&user, &Action, &document, &Context)
    .await;

assert!(evaluation.is_granted());
println!("{}", evaluation.display_trace());

let outcome: Result<(), String> = evaluation.to_result(|reason| reason.to_string());
assert!(outcome.is_ok());
# });
```

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

```rust,ignore
#[async_trait]
trait Policy<Subject, Resource, Action, Context>: Send + Sync {
    async fn evaluate_access(
        &self,
        subject: &Subject,
        action: &Action,
        resource: &Resource,
        context: &Context,
    ) -> PolicyEvalResult;

    fn policy_type(&self) -> String;

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
let evaluation = checker.evaluate_access(&user, &action, &resource, &context).await;
if evaluation.is_granted() {
    // Access allowed
} else {
    // Access denied
}

println!("{}", evaluation.display_trace());
```

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
- `RebacPolicy`: Relationship-based access control. Grants when its `RelationshipResolver` returns `true` for the configured relationship.

`RelationshipResolver` returns `bool`, so resolver errors and timeouts need to be handled by the resolver implementation and mapped to `false` or to your own surrounding telemetry/logging strategy.

### Combinators

- `AndPolicy`: Grants access only if all inner policies allow access. Must be created with at least one policy.
- `OrPolicy`: Grants access if any inner policy allows access. Must be created with at least one policy.
- `NotPolicy`: Inverts the decision of an inner policy.

## Tracing And Telemetry

When trace-level events are enabled, `PermissionChecker::evaluate_access` creates an instrumented span and every evaluated policy records a `trace!` event on the `gatehouse::security` target.

Emitted fields:

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

Fallback behavior when `security_rule()` is not overridden:

- `security_rule.name` falls back to `policy_type()`
- `security_rule.category` falls back to `"Access Control"`
- `security_rule.ruleset.name` falls back to `"PermissionChecker"`

## Examples

See the `examples` directory for complete demonstrations of:
- Role-based access control (`rbac_policy`)
- Attribute-style custom policies with `PolicyBuilder` (`policy_builder`)
- Relationship-based access control (`rebac_policy`)
- Group authorization with trace output (`groups_policy`)
- Policy combinators (`combinator_policy`)
- Axum integration with shared policies (`axum`)
- Actix Web integration with shared policies (`actix_web`)

Run with:

```shell
cargo run --example rbac_policy
```

## Performance

Criterion benchmarks in `benches/permission_checker.rs` exercise `PermissionChecker::evaluate_access` across
several policy stack sizes. Run them with `cargo bench` to track changes in evaluation latency as you evolve
your policy definitions.
