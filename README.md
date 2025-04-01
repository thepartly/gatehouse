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

See the `examples` directory for complete demonstration of:
- Role-based access control (`rbac_policy`)
- Relationship-based access control (`rebac_policy`)
- Policy combinators (`combinator_policy`)

Run with:

```shell
cargo run --example rbac_policy
```

Below is an updated section you can add to your README (e.g., at the bottom) to document the Docker build and run process. It also notes that a screenshot of a successful build is available in the `image/screenshots` folder.

---

## Docker

You can build and run the Axum example using Docker. Make sure the Dockerfile is placed in the root of the repository (alongside `Cargo.toml`, `Cargo.lock`, `src/`, and `examples/`).

### Build the Docker Image

Open a terminal in your project root and run:

```bash
docker build -t gatehouse-axum .
```

### Run the Docker Container

After building the image, run the container with:

```bash
docker run -p 8000:8000 gatehouse-axum 
```

This command maps port 8000 of your container to port 8000 on your host, allowing you to access the Axum service at [http://localhost:8000](http://localhost:8000).

> **Note:** A screenshot showing a successful build and container run is available at `image/screenshots`.

---

