//! # Relationship-Based Access Control Policy Example
//!
//! This example demonstrates ReBAC: `RebacPolicy` extracts flat IDs and loads
//! relationship facts through a request-scoped `EvaluationSession`. The happy
//! path declares sources once in a `FactRegistry`, then creates a fresh session
//! from that registry for each request.
//!
//! Relations are a domain enum (`Relation::Owner`), not strings: the session
//! deduplicates and caches by the typed `RelationshipQuery` key, the compiler
//! checks relation names, and any backend-specific serialization stays inside
//! the `FactSource`. Relationship store failures are returned as
//! `FactLoadResult::Error` and fail closed to denial — asserted at the end.
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
    name: &'static str,
}

#[derive(Debug, Clone)]
struct Project {
    id: Uuid,
    name: &'static str,
}

#[derive(Debug, Clone)]
struct EditAction;

struct ProjectDomain;

impl PolicyDomain for ProjectDomain {
    type Subject = User;
    type Action = EditAction;
    type Resource = Project;
    type Context = ();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

type ProjectRelationship = RelationshipQuery<Uuid, Uuid, Relation>;

/// In-memory relationship store. The print in `load_many` makes the session's
/// behaviour visible when the example runs: each unique key is loaded once
/// per session, however many policies ask about it.
#[derive(Debug, Clone)]
struct ProjectRelationshipSource {
    relationships: HashSet<ProjectRelationship>,
    fail: bool,
}

impl ProjectRelationshipSource {
    fn new(relationships: HashSet<ProjectRelationship>) -> Self {
        Self {
            relationships,
            fail: false,
        }
    }

    /// Simulate a relationship store outage for the fail-closed section.
    fn with_error(mut self) -> Self {
        self.fail = true;
        self
    }
}

#[async_trait]
impl FactSource<ProjectRelationship> for ProjectRelationshipSource {
    async fn load_many(&self, keys: &[ProjectRelationship]) -> Vec<FactLoadResult<bool>> {
        keys.iter()
            .map(|key| {
                println!(
                    "  loading fact: subject={} relation={} resource={}",
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
        name: "Alice",
    };
    let contributor = User {
        id: Uuid::new_v4(),
        name: "Bob",
    };
    let viewer = User {
        id: Uuid::new_v4(),
        name: "Charlie",
    };
    let outsider = User {
        id: Uuid::new_v4(),
        name: "Dave",
    };
    let project = Project {
        id: Uuid::new_v4(),
        name: "Sample Project",
    };

    let relationships = HashSet::from([
        ProjectRelationship {
            subject_id: owner.id,
            resource_id: project.id,
            relation: Relation::Owner,
        },
        ProjectRelationship {
            subject_id: contributor.id,
            resource_id: project.id,
            relation: Relation::Contributor,
        },
        ProjectRelationship {
            subject_id: viewer.id,
            resource_id: project.id,
            relation: Relation::Viewer,
        },
    ]);

    let registry = FactRegistry::builder()
        .with::<ProjectRelationship, _>(ProjectRelationshipSource::new(relationships.clone()))
        .build();
    let session = registry.session();

    // Editing requires an owner OR contributor relationship; a viewer
    // relationship exists in the store but grants nothing here.
    let mut checker = PermissionChecker::<ProjectDomain>::new();
    checker.add_policy(RebacPolicy::<ProjectDomain, Uuid, Uuid, Relation>::new(
        |user: &User| user.id,
        |project: &Project| project.id,
        Relation::Owner,
    ));
    checker.add_policy(RebacPolicy::<ProjectDomain, Uuid, Uuid, Relation>::new(
        |user: &User| user.id,
        |project: &Project| project.id,
        Relation::Contributor,
    ));

    // (user, relationship held, expected outcome)
    let cases = [
        (&owner, "owner", true),
        (&contributor, "contributor", true),
        (&viewer, "viewer", false),
        (&outsider, "none", false),
    ];
    for (user, held, expected_granted) in cases {
        println!("Can {} ({held}) edit {}?", user.name, project.name);
        let decision = checker
            .bind(&session, user, &EditAction, &())
            .check(&project)
            .await;
        println!(
            "  -> {}\n",
            if decision.is_granted() {
                "GRANTED"
            } else {
                "DENIED"
            }
        );
        assert_eq!(decision.is_granted(), expected_granted);
    }

    // The trace records the facts each policy consulted (the `↳ fact` lines)
    // alongside its decision — here the viewer's denial shows both
    // relationship lookups coming back false. Note that no new "loading fact"
    // lines appear: this re-check runs in the same session, so the facts come
    // from the session cache.
    println!("Why {} is denied:", viewer.name);
    let decision = checker
        .bind(&session, &viewer, &EditAction, &())
        .check(&project)
        .await;
    println!("{}\n", decision.display_trace());

    println!("=== Error During Relationship Loading ===\n");

    // A failing store must never grant: the load error is carried into the
    // trace and the decision fails closed to denial — even for the owner.
    let error_registry = FactRegistry::builder()
        .with::<ProjectRelationship, _>(ProjectRelationshipSource::new(relationships).with_error())
        .build();
    let error_session = error_registry.session();
    let decision = checker
        .bind(&error_session, &owner, &EditAction, &())
        .check(&project)
        .await;
    println!("{}", decision.display_trace());
    decision.assert_denied();
    decision.assert_trace_contains("simulated relationship store error");
}
