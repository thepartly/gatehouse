//! # Relationship-Based Access Control Policy Example
//!
//! This example demonstrates ReBAC in the v0.3 shape: `RebacPolicy` extracts
//! flat IDs and loads relationship facts through a request-scoped
//! `EvaluationSession`. The happy path declares sources with
//! `EvaluationSession::builder()` so all request-scoped dependencies are
//! visible in one place. Relationship store failures are returned as
//! `FactLoadResult::Error` and fail closed to denial.
//!
//! To run this example:
//! ```
//! cargo run --example rebac_policy
//! ```

use async_trait::async_trait;
use gatehouse::*;
use std::collections::HashSet;
use std::fmt;
use uuid::Uuid;

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

#[derive(Debug, Clone)]
struct ProjectRelationshipSource {
    relationships: HashSet<RelationshipQuery<Uuid, Uuid, String>>,
    fail: bool,
}

impl ProjectRelationshipSource {
    fn new(relationships: HashSet<RelationshipQuery<Uuid, Uuid, String>>) -> Self {
        Self {
            relationships,
            fail: false,
        }
    }

    fn with_error(mut self) -> Self {
        self.fail = true;
        self
    }
}

#[async_trait]
impl FactSource<RelationshipQuery<Uuid, Uuid, String>> for ProjectRelationshipSource {
    async fn load_many(
        &self,
        keys: &[RelationshipQuery<Uuid, Uuid, String>],
    ) -> Vec<FactLoadResult<bool>> {
        keys.iter()
            .map(|key| {
                println!(
                    "Loading relationship fact: subject={} relation={} resource={}",
                    key.subject_id, key.relation, key.resource_id
                );

                if self.fail {
                    FactLoadResult::Error(FactLoadError::backend_message(
                        "simulated relationship store error",
                    ))
                } else {
                    FactLoadResult::Found(self.relationships.contains(key))
                }
            })
            .collect()
    }
}

#[tokio::main]
async fn main() {
    println!("=== ReBAC Policy Example ===\n");

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
    let project = Project {
        id: Uuid::new_v4(),
        name: "Sample Project".to_string(),
    };

    let relationships = HashSet::from([
        RelationshipQuery {
            subject_id: owner.id,
            resource_id: project.id,
            relation: "owner".to_string(),
        },
        RelationshipQuery {
            subject_id: contributor.id,
            resource_id: project.id,
            relation: "contributor".to_string(),
        },
        RelationshipQuery {
            subject_id: viewer.id,
            resource_id: project.id,
            relation: "viewer".to_string(),
        },
    ]);

    let session = EvaluationSession::builder()
        .with::<RelationshipQuery<Uuid, Uuid, String>, _>(ProjectRelationshipSource::new(
            relationships.clone(),
        ))
        .build();

    let mut checker = PermissionChecker::<User, Project, EditAction, EmptyContext>::new();
    checker.add_policy(RebacPolicy::new(
        |user: &User| user.id,
        |project: &Project| project.id,
        "owner".to_string(),
    ));
    checker.add_policy(RebacPolicy::new(
        |user: &User| user.id,
        |project: &Project| project.id,
        "contributor".to_string(),
    ));

    println!("Testing normal access patterns:");
    test_access(&checker, &session, &owner, &project).await;
    test_access(&checker, &session, &contributor, &project).await;
    test_access(&checker, &session, &viewer, &project).await;
    test_access(&checker, &session, &unauthorized, &project).await;

    println!("\n=== Error During Relationship Loading ===\n");
    let error_session = EvaluationSession::builder()
        .with::<RelationshipQuery<Uuid, Uuid, String>, _>(
            ProjectRelationshipSource::new(relationships).with_error(),
        )
        .build();
    test_access(&checker, &error_session, &owner, &project).await;

    enum_relationship_example().await;
}

async fn test_access(
    checker: &PermissionChecker<User, Project, EditAction, EmptyContext>,
    session: &EvaluationSession,
    user: &User,
    project: &Project,
) {
    let context = EmptyContext;
    let action = EditAction;

    println!("\nChecking if {} can edit {}:", user.name, project.name);
    let result = checker
        .evaluate_in_session(session, user, &action, project, &context)
        .await;

    println!(
        "Access {} for {}",
        if result.is_granted() {
            "GRANTED"
        } else {
            "DENIED"
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Relation {
    Owner,
    Contributor,
    Viewer,
}

impl fmt::Display for Relation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Relation::Owner => write!(f, "owner"),
            Relation::Contributor => write!(f, "contributor"),
            Relation::Viewer => write!(f, "viewer"),
        }
    }
}

struct EnumRelationshipSource {
    relationships: HashSet<RelationshipQuery<Uuid, Uuid, Relation>>,
}

#[async_trait]
impl FactSource<RelationshipQuery<Uuid, Uuid, Relation>> for EnumRelationshipSource {
    async fn load_many(
        &self,
        keys: &[RelationshipQuery<Uuid, Uuid, Relation>],
    ) -> Vec<FactLoadResult<bool>> {
        keys.iter()
            .map(|key| FactLoadResult::Found(self.relationships.contains(key)))
            .collect()
    }
}

async fn enum_relationship_example() {
    println!("\n=== Enum-Based Relationship Types ===\n");

    let alice = User {
        id: Uuid::new_v4(),
        name: "Alice".to_string(),
    };
    let bob = User {
        id: Uuid::new_v4(),
        name: "Bob".to_string(),
    };
    let charlie = User {
        id: Uuid::new_v4(),
        name: "Charlie".to_string(),
    };
    let project = Project {
        id: Uuid::new_v4(),
        name: "Typed Project".to_string(),
    };

    let session = EvaluationSession::builder()
        .with::<RelationshipQuery<Uuid, Uuid, Relation>, _>(EnumRelationshipSource {
            relationships: HashSet::from([
                RelationshipQuery {
                    subject_id: alice.id,
                    resource_id: project.id,
                    relation: Relation::Owner,
                },
                RelationshipQuery {
                    subject_id: bob.id,
                    resource_id: project.id,
                    relation: Relation::Contributor,
                },
                RelationshipQuery {
                    subject_id: charlie.id,
                    resource_id: project.id,
                    relation: Relation::Viewer,
                },
            ]),
        })
        .build();

    let mut checker = PermissionChecker::<User, Project, EditAction, EmptyContext>::new();
    checker.add_policy(RebacPolicy::new(
        |user: &User| user.id,
        |project: &Project| project.id,
        Relation::Owner,
    ));

    let context = EmptyContext;
    let action = EditAction;

    for (user, expected_granted, role) in [
        (&alice, true, "owner"),
        (&bob, false, "contributor"),
        (&charlie, false, "viewer"),
    ] {
        let result = checker
            .evaluate_in_session(&session, user, &action, &project, &context)
            .await;
        println!(
            "{} ({}) edit access: {}",
            user.name,
            role,
            if result.is_granted() {
                "GRANTED"
            } else {
                "DENIED"
            },
        );
        assert_eq!(result.is_granted(), expected_granted);
    }
}
