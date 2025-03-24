//! # Role-Based Access Control Policy Example
//!
//! This example demonstrates how to use the built-in RBAC policy
//! for role-based permission management.
//!
//! To run this example:
//! ```
//! cargo run --example rbac_policy
//! ```

use gatehouse::*;
use std::collections::HashSet;
use uuid::Uuid;

// Define types for our permission system
#[derive(Debug, Clone)]
struct User {
    id: Uuid,
    roles: HashSet<Uuid>,
}

#[derive(Debug, Clone)]
struct Document {
    id: Uuid,
    required_role_ids: HashSet<Uuid>,
}

#[derive(Debug, Clone)]
struct ReadAction;

#[derive(Debug, Clone)]
struct EmptyContext;

#[tokio::main]
async fn main() {
    println!("=== RBAC Policy Example ===\n");

    // Create some role IDs
    let admin_role_id = Uuid::new_v4();
    let editor_role_id = Uuid::new_v4();
    let viewer_role_id = Uuid::new_v4();

    println!("Role IDs:");
    println!("  Admin:  {}", admin_role_id);
    println!("  Editor: {}", editor_role_id);
    println!("  Viewer: {}", viewer_role_id);
    println!();

    // Create users with different roles
    let admin_user = User {
        id: Uuid::new_v4(),
        roles: [admin_role_id].into_iter().collect(),
    };

    let editor_user = User {
        id: Uuid::new_v4(),
        roles: [editor_role_id].into_iter().collect(),
    };

    let multi_role_user = User {
        id: Uuid::new_v4(),
        roles: [editor_role_id, viewer_role_id].into_iter().collect(),
    };

    let unauthorized_user = User {
        id: Uuid::new_v4(),
        roles: HashSet::new(),
    };

    println!("Users:");
    println!("  Admin User ID:      {}", admin_user.id);
    println!("  Editor User ID:     {}", editor_user.id);
    println!("  Multi-role User ID: {}", multi_role_user.id);
    println!("  No-role User ID:    {}", unauthorized_user.id);
    println!();

    // Create documents with different role requirements
    let admin_doc = Document {
        id: Uuid::new_v4(),
        required_role_ids: [admin_role_id].into_iter().collect(),
    };

    let editor_doc = Document {
        id: Uuid::new_v4(),
        required_role_ids: [editor_role_id].into_iter().collect(),
    };

    let multi_role_doc = Document {
        id: Uuid::new_v4(),
        required_role_ids: [editor_role_id, viewer_role_id].into_iter().collect(),
    };

    println!("Documents:");
    println!("  Admin Document:      {}", admin_doc.id);
    println!("  Editor Document:     {}", editor_doc.id);
    println!("  Multi-role Document: {}", multi_role_doc.id);
    println!();

    // Create RBAC policy
    // The first function extracts required roles from a document
    // The second function extracts roles from a user
    let rbac_policy = RbacPolicy::new(
        |doc: &Document, _: &ReadAction| doc.required_role_ids.iter().cloned().collect(),
        |user: &User| user.roles.iter().cloned().collect(),
    );

    // Create a strongly typed permission checker and add our RBAC policy
    let mut checker = PermissionChecker::<User, Document, ReadAction, EmptyContext>::new();
    checker.add_policy(rbac_policy);

    println!("=== Testing Access Control ===\n");

    // Test admin user accessing various documents
    test_access(
        &checker,
        "Admin user",
        &admin_user,
        "Admin document",
        &admin_doc,
    )
    .await;
    test_access(
        &checker,
        "Admin user",
        &admin_user,
        "Editor document",
        &editor_doc,
    )
    .await;

    // Test editor user accessing various documents
    test_access(
        &checker,
        "Editor user",
        &editor_user,
        "Admin document",
        &admin_doc,
    )
    .await;
    test_access(
        &checker,
        "Editor user",
        &editor_user,
        "Editor document",
        &editor_doc,
    )
    .await;

    // Test multi-role user
    test_access(
        &checker,
        "Multi-role user",
        &multi_role_user,
        "Editor document",
        &editor_doc,
    )
    .await;
    test_access(
        &checker,
        "Multi-role user",
        &multi_role_user,
        "Multi-role document",
        &multi_role_doc,
    )
    .await;

    // Test unauthorized user
    test_access(
        &checker,
        "Unauthorized user",
        &unauthorized_user,
        "Admin document",
        &admin_doc,
    )
    .await;
    test_access(
        &checker,
        "Unauthorized user",
        &unauthorized_user,
        "Editor document",
        &editor_doc,
    )
    .await;
}

async fn test_access(
    checker: &PermissionChecker<User, Document, ReadAction, EmptyContext>,
    user_desc: &str,
    user: &User,
    doc_desc: &str,
    doc: &Document,
) {
    let context = EmptyContext;
    let action = ReadAction;

    let result = checker.evaluate_access(user, &action, doc, &context).await;

    println!(
        "{} accessing {}: {}",
        user_desc,
        doc_desc,
        if result.is_granted() {
            "GRANTED ✓"
        } else {
            "DENIED ✗"
        }
    );

    println!(
        "Evaluation trace:\n{}\n",
        match &result {
            AccessEvaluation::Granted { trace, .. } => trace.format(),
            AccessEvaluation::Denied { trace, .. } => trace.format(),
        }
    );
}
