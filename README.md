# Permissions Library

A flexible authorization library that combines role-based (RBAC), attribute-based (ABAC), and relationship-based (ReBAC) access control policies.

## Features
- 
- **Multi-paradigm Authorization**: Support for RBAC, ABAC, and ReBAC patterns
- **Policy Composition**: Combine policies with logical operators (`AND`, `OR`, `NOT`)
- **Detailed Evaluation Tracing**: Complete decision trace for debugging and auditing
- **Type Safety**: Strongly typed resources/actions/contexts
- **Async Ready**: Built with async/await support

## Core Components

### `Policy` Trait

The foundation of the authorization system:

```rust
#[async_trait]
trait Policy<Subject, Resource, Action, Context> {
    async fn evaluate_access(
        &self,
        subject: &Subject,
        action: &Action,
        resource: &Resource,
        context: &Context,
    ) -> PolicyEvalResult;
}
```

### `PermissionChecker`

Aggregates multiple policies (e.g. RBAC, ABAC) with `OR` logic by default: if any policy grants access, permission is granted.

```rust
let mut checker = PermissionChecker::new();
checker.add_policy(rbac_policy);
checker.add_policy(owner_policy);

// Check if access is granted
let result = checker.evaluate_access(&user, &action, &resource, &context).await;
if result.is_granted() {
    // Access allowed
} else {
    // Access denied
}
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

See the `examples` directory for complete demonstration of:
- Role-based access control (`rbac_policy`)
- Relationship-based access control (`rebac_policy`)
- Policy combinators (`combinator_policy`)

Run with:

```shell
cargo run --package permissions --example rbac_policy
```