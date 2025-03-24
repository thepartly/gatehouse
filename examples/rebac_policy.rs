//! # Relationship-Based Access Control Policy Example
//!
//! This example demonstrates how to use the built-in ReBAC policy
//! for relationship-based permissions management, including error handling
//! during relationship resolution.
//!
//! To run this example:
//! ```
//! cargo run --example rebac_policy
//! ```

use async_trait::async_trait;
use gatehouse::*;
use std::time::Duration;
use uuid::Uuid;

// Define types for our permission system
#[derive(Debug, Clone)]
struct User {
    id: Uuid,
    name: String,
}

#[derive(Debug, Clone)]
struct Project {
    id: Uuid,
    name: String,
}

#[derive(Debug, Clone)]
struct EditAction;

#[derive(Debug, Clone)]
struct EmptyContext;

// A relationship resolver that simulates database access
// and can demonstrate different error conditions
#[derive(Debug, Clone)]
struct ProjectRelationshipResolver {
    // Simulate a database of relationships: (user_id, project_id, relationship_type)
    relationships: Vec<(Uuid, Uuid, String)>,
    // Flag to simulate a database error
    simulate_error: bool,
    // Flag to simulate a timeout
    simulate_timeout: bool,
}

impl ProjectRelationshipResolver {
    fn new(relationships: Vec<(Uuid, Uuid, String)>) -> Self {
        Self {
            relationships,
            simulate_error: false,
            simulate_timeout: false,
        }
    }

    fn with_error(mut self) -> Self {
        self.simulate_error = true;
        self
    }

    fn with_timeout(mut self) -> Self {
        self.simulate_timeout = true;
        self
    }
}

#[async_trait]
impl RelationshipResolver<User, Project> for ProjectRelationshipResolver {
    async fn has_relationship(&self, user: &User, project: &Project, relationship: &str) -> bool {
        println!(
            "Checking if user {} has '{}' relationship with project {}",
            user.name, relationship, project.name
        );

        // Simulate a database error
        if self.simulate_error {
            println!("⚠️  Database error while checking relationship!");
            return false; // Return false on error
        }

        // Simulate a timeout
        if self.simulate_timeout {
            println!("⏱️  Simulating database timeout (3 seconds)...");
            tokio::time::sleep(Duration::from_secs(3)).await;
            println!("⚠️  Database timeout while checking relationship!");
            return false; // Return false on timeout
        }

        // Normal processing - check if relationship exists
        let has_rel = self.relationships.iter().any(|(user_id, project_id, rel)| {
            *user_id == user.id && *project_id == project.id && rel == relationship
        });

        println!(
            "Relationship check result: {}",
            if has_rel { "EXISTS ✓" } else { "MISSING ✗" }
        );
        has_rel
    }
}

#[tokio::main]
async fn main() {
    println!("=== ReBAC Policy Example ===\n");

    // Create some users
    let owner = User {
        id: Uuid::new_v4(),
        name: "Alice (Owner)".to_string(),
    };

    let contributor = User {
        id: Uuid::new_v4(),
        name: "Bob (Contributor)".to_string(),
    };

    let viewer = User {
        id: Uuid::new_v4(),
        name: "Charlie (Viewer)".to_string(),
    };

    let unauthorized = User {
        id: Uuid::new_v4(),
        name: "Dave (Unauthorized)".to_string(),
    };

    println!("Users:");
    println!("  Owner:        {}", owner.name);
    println!("  Contributor:  {}", contributor.name);
    println!("  Viewer:       {}", viewer.name);
    println!("  Unauthorized: {}", unauthorized.name);
    println!();

    // Create a project
    let project = Project {
        id: Uuid::new_v4(),
        name: "Sample Project".to_string(),
    };

    println!("Project:");
    println!("  Name: {}", project.name);
    println!("  ID:   {}", project.id);
    println!();

    // Setup relationship database
    let relationships = vec![
        (owner.id, project.id, "owner".to_string()),
        (contributor.id, project.id, "contributor".to_string()),
        (viewer.id, project.id, "viewer".to_string()),
    ];

    println!("=== Normal Relationship Resolution ===\n");

    // Create resolver with normal operation
    let normal_resolver = ProjectRelationshipResolver::new(relationships.clone());

    // Create ReBAC policies for different relationships
    let owner_policy = RebacPolicy::<User, Project, EditAction, EmptyContext, _>::new(
        "owner",
        normal_resolver.clone(),
    );

    let contributor_policy = RebacPolicy::<User, Project, EditAction, EmptyContext, _>::new(
        "contributor",
        normal_resolver.clone(),
    );

    let _viewer_policy =
        RebacPolicy::<User, Project, EditAction, EmptyContext, _>::new("viewer", normal_resolver);

    // Create a permission checker with multiple policies
    // Only owners and contributors can edit, not viewers
    let mut checker = PermissionChecker::<User, Project, EditAction, EmptyContext>::new();
    checker.add_policy(owner_policy);
    checker.add_policy(contributor_policy);

    // Test normal access
    println!("Testing normal access patterns:");
    test_access(&checker, &owner, &project).await;
    test_access(&checker, &contributor, &project).await;
    test_access(&checker, &viewer, &project).await;
    test_access(&checker, &unauthorized, &project).await;

    println!("\n=== Error During Relationship Resolution ===\n");

    // Create a resolver that simulates a database error
    let error_resolver = ProjectRelationshipResolver::new(relationships.clone()).with_error();
    let error_policy =
        RebacPolicy::<User, Project, EditAction, EmptyContext, _>::new("owner", error_resolver);

    let mut error_checker = PermissionChecker::<User, Project, EditAction, EmptyContext>::new();
    error_checker.add_policy(error_policy);

    println!("Testing with database error:");
    test_access(&error_checker, &owner, &project).await;

    println!("\n=== Timeout During Relationship Resolution ===\n");

    // Create a resolver that simulates a timeout
    let timeout_resolver = ProjectRelationshipResolver::new(relationships).with_timeout();
    let timeout_policy =
        RebacPolicy::<User, Project, EditAction, EmptyContext, _>::new("owner", timeout_resolver);

    let mut timeout_checker = PermissionChecker::<User, Project, EditAction, EmptyContext>::new();
    timeout_checker.add_policy(timeout_policy);

    println!("Testing with database timeout:");
    test_access(&timeout_checker, &owner, &project).await;
}

async fn test_access(
    checker: &PermissionChecker<User, Project, EditAction, EmptyContext>,
    user: &User,
    project: &Project,
) {
    let context = EmptyContext;
    let action = EditAction;

    println!("\nChecking if {} can edit {}:", user.name, project.name);
    let result = checker
        .evaluate_access(user, &action, project, &context)
        .await;

    println!(
        "Access {} for {}",
        if result.is_granted() {
            "GRANTED ✓"
        } else {
            "DENIED ✗"
        },
        user.name
    );

    println!(
        "Evaluation trace:\n{}\n",
        match &result {
            AccessEvaluation::Granted { trace, .. } => trace.format(),
            AccessEvaluation::Denied { trace, .. } => trace.format(),
        }
    );
}
