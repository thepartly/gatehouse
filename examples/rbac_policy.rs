//! # Role-Based Access Control Policy Example
//!
//! The built-in `RbacPolicy` takes two resolver closures: which roles the
//! (action, resource) pair requires, and which roles the subject holds.
//! Access is granted when at least one required role is held.
//!
//! The role identifier type is generic — this example uses a domain enum so
//! the output reads as names and the compiler checks the role set. `Uuid`
//! role ids (for integration with an external identity system) work the same
//! way; only the resolver closures change.
//!
//! To run this example:
//! ```
//! cargo run --example rbac_policy
//! ```

use gatehouse::*;
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Role {
    Admin,
    Editor,
    Viewer,
}

#[derive(Debug, Clone)]
struct User {
    name: &'static str,
    roles: HashSet<Role>,
}

#[derive(Debug, Clone)]
struct Document {
    name: &'static str,
    /// Roles that may read this document. Any one of them suffices.
    required_roles: HashSet<Role>,
}

#[derive(Debug, Clone)]
struct ReadAction;

fn user<const N: usize>(name: &'static str, roles: [Role; N]) -> User {
    User {
        name,
        roles: roles.into_iter().collect(),
    }
}

fn document<const N: usize>(name: &'static str, required_roles: [Role; N]) -> Document {
    Document {
        name,
        required_roles: required_roles.into_iter().collect(),
    }
}

#[tokio::main]
async fn main() {
    // The first resolver reads the requirement off the resource/action; the
    // second extracts the subject's roles. The role type (`Role`) is inferred
    // from the closures' return types.
    let rbac_policy = RbacPolicy::new(
        |_action: &ReadAction, doc: &Document| doc.required_roles.iter().copied().collect(),
        |user: &User| user.roles.iter().copied().collect(),
    );

    let mut checker = PermissionChecker::<User, ReadAction, Document, ()>::new();
    checker.add_policy(rbac_policy);

    let admin = user("admin", [Role::Admin]);
    let editor = user("editor", [Role::Editor]);
    let multi_role = user("editor+viewer", [Role::Editor, Role::Viewer]);
    let no_roles = user("no-roles", []);

    let admin_doc = document("admin handbook", [Role::Admin]);
    let editor_doc = document("style guide", [Role::Editor]);
    let shared_doc = document("team wiki", [Role::Editor, Role::Viewer]);

    // (user, document, expected outcome)
    let cases = [
        (&admin, &admin_doc, true),
        (&admin, &editor_doc, false), // admin role is not editor — no hierarchy here
        (&editor, &admin_doc, false),
        (&editor, &editor_doc, true),
        (&multi_role, &editor_doc, true),
        (&multi_role, &shared_doc, true),
        (&no_roles, &admin_doc, false),
        (&no_roles, &shared_doc, false),
    ];

    println!("{:<16} {:<16} verdict", "user", "document");
    println!("{}", "-".repeat(42));
    for (user, document, expected_granted) in cases {
        let decision = checker.check(user, &ReadAction, document, &()).await;
        println!(
            "{:<16} {:<16} {}",
            user.name,
            document.name,
            if decision.is_granted() {
                "GRANTED"
            } else {
                "DENIED"
            }
        );
        assert_eq!(decision.is_granted(), expected_granted);
    }

    // Note the admin/style-guide denial above: `RbacPolicy` is a flat
    // role-match with no built-in hierarchy. If admins should read
    // everything, either include `Role::Admin` in each document's required
    // set or add a separate admin-override policy to the checker.

    println!("\nWhy the editor is denied the admin handbook:");
    let decision = checker.check(&editor, &ReadAction, &admin_doc, &()).await;
    println!("{}", decision.display_trace());
}
