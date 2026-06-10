//! In-RAM FactSource-backed ReBAC example.
//!
//! This is the small, production-shaped version of the v0.3 fact model: the
//! application owns one shared relationship source, each request creates a fresh
//! `EvaluationSession`, and list endpoints batch relationship checks through
//! the same `PermissionChecker` used for single-resource checks.

use async_trait::async_trait;
use dashmap::DashSet;
use gatehouse::{
    EvaluationSession, FactLoadResult, FactSource, PermissionChecker, RebacPolicy,
    RelationshipQuery,
};
use std::fmt;
use std::sync::Arc;
use uuid::Uuid;

type RelationshipKey = RelationshipQuery<Uuid, Uuid, Relation>;

#[derive(Debug, Clone)]
struct User {
    id: Uuid,
}

#[derive(Debug, Clone)]
struct Document {
    id: Uuid,
    title: &'static str,
}

#[derive(Debug, Clone)]
struct View;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Relation {
    Viewer,
    Editor,
}

impl fmt::Display for Relation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Viewer => f.write_str("viewer"),
            Self::Editor => f.write_str("editor"),
        }
    }
}

#[derive(Default)]
struct InRamRelationships {
    grants: DashSet<RelationshipKey>,
}

impl InRamRelationships {
    fn grant(&self, subject_id: Uuid, resource_id: Uuid, relation: Relation) {
        self.grants.insert(RelationshipKey {
            subject_id,
            resource_id,
            relation,
        });
    }
}

#[async_trait]
impl FactSource<RelationshipKey> for InRamRelationships {
    async fn load_many(&self, keys: &[RelationshipKey]) -> Vec<FactLoadResult<bool>> {
        keys.iter()
            .map(|key| FactLoadResult::Found(self.grants.contains(key)))
            .collect()
    }
}

fn request_session(relationships: &Arc<dyn FactSource<RelationshipKey>>) -> EvaluationSession {
    EvaluationSession::builder()
        .with_arc::<RelationshipKey>(Arc::clone(relationships))
        .build()
}

fn build_checker() -> PermissionChecker<User, Document, View, ()> {
    let mut checker = PermissionChecker::new();
    checker.add_policy(RebacPolicy::new(
        |user: &User| user.id,
        |document: &Document| document.id,
        Relation::Viewer,
    ));
    checker
}

#[tokio::main]
async fn main() {
    let user = User { id: Uuid::new_v4() };
    let documents = vec![
        Document {
            id: Uuid::new_v4(),
            title: "roadmap",
        },
        Document {
            id: Uuid::new_v4(),
            title: "incident report",
        },
        Document {
            id: Uuid::new_v4(),
            title: "finance plan",
        },
    ];

    let store = Arc::new(InRamRelationships::default());
    store.grant(user.id, documents[0].id, Relation::Viewer);
    store.grant(user.id, documents[1].id, Relation::Viewer);
    // The store can hold more relation types than any one policy consumes. This
    // editor grant is never matched below (the checker only asks about Viewer),
    // and is here to show the source and the policy stack are decoupled.
    store.grant(user.id, documents[1].id, Relation::Editor);
    let relationships: Arc<dyn FactSource<RelationshipKey>> = store;

    let checker = build_checker();
    let context = ();

    let first_request = request_session(&relationships);
    let visible = checker
        .filter_authorized_in_session_by_resource(
            &first_request,
            &user,
            &View,
            documents.clone(),
            &context,
            |document| document,
        )
        .await;
    println!(
        "batch list — visible documents: {:?}",
        visible
            .iter()
            .map(|document| document.title)
            .collect::<Vec<_>>()
    );

    // A fresh session for a single-resource check. The user has no viewer
    // relationship on the finance plan, so this denies.
    let second_request = request_session(&relationships);
    let can_view_finance = checker
        .evaluate_in_session(&second_request, &user, &View, &documents[2], &context)
        .await;
    println!(
        "single check — can view '{}'? {}",
        documents[2].title,
        if can_view_finance.is_granted() {
            "yes"
        } else {
            "no"
        }
    );
    assert!(!can_view_finance.is_granted());

    let shared = Arc::clone(&relationships);
    let concurrent_requests = (0..4)
        .map(|_| {
            let checker = checker.clone();
            let user = user.clone();
            let documents = documents.clone();
            let relationships = Arc::clone(&shared);
            tokio::spawn(async move {
                let session = request_session(&relationships);
                let context = ();
                checker
                    .filter_authorized_in_session_by_resource(
                        &session,
                        &user,
                        &View,
                        documents,
                        &context,
                        |document| document,
                    )
                    .await
                    .len()
            })
        })
        .collect::<Vec<_>>();

    println!("\n4 concurrent requests sharing one FactSource (each builds its own session):");
    for (index, request) in concurrent_requests.into_iter().enumerate() {
        let visible_count = request.await.unwrap();
        println!("  request {index}: {visible_count} visible document(s)");
        assert_eq!(visible_count, 2);
    }
}
