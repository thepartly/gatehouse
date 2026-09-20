//! PostgreSQL-backed batch ReBAC example.
//!
//! This models a list endpoint with two policies:
//!
//! - public posts are visible through an in-memory predicate policy
//! - private posts are visible when a `viewer` relationship exists in PostgreSQL
//!
//! The policy stack stays in Gatehouse. PostgreSQL is only responsible for
//! loading relationship facts, and `EvaluationSession` batches, deduplicates,
//! caches, and expands those facts back into caller order.

use async_trait::async_trait;
use gatehouse::{
    EvaluationSession, FactLoadError, FactLoadResult, FactRegistry, FactSource, PermissionChecker,
    PolicyBuilder, PolicyDomain, RebacPolicy, RelationshipQuery,
};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_postgres::{Client, NoTls, Statement};
use uuid::Uuid;

type RelationshipKey = RelationshipQuery<Uuid, Uuid, Relation>;

#[derive(Clone)]
struct User {
    id: Uuid,
}

#[derive(Clone)]
struct Post {
    id: Uuid,
    public: bool,
}

struct View;

struct PostDomain;

impl PolicyDomain for PostDomain {
    type Subject = User;
    type Action = View;
    type Resource = Post;
    type Context = ();
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Relation {
    Viewer,
}

impl Relation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
        }
    }
}

impl fmt::Display for Relation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone)]
struct PgRelationshipSource {
    client: Arc<Client>,
    point_stmt: Arc<Statement>,
    bulk_stmt: Arc<Statement>,
}

impl PgRelationshipSource {
    async fn load_point(&self, key: &RelationshipKey) -> FactLoadResult<bool> {
        let relationship = key.relation.as_str();
        match self
            .client
            .query_one(
                &*self.point_stmt,
                &[&key.subject_id, &relationship, &key.resource_id],
            )
            .await
        {
            Ok(row) => FactLoadResult::Found(row.get("allowed")),
            Err(error) => FactLoadResult::Error(FactLoadError::backend(error)),
        }
    }

    async fn load_bulk(&self, keys: &[RelationshipKey]) -> Vec<FactLoadResult<bool>> {
        let subject_ids = keys.iter().map(|key| key.subject_id).collect::<Vec<_>>();
        let post_ids = keys.iter().map(|key| key.resource_id).collect::<Vec<_>>();
        let relationships = keys
            .iter()
            .map(|key| key.relation.as_str())
            .collect::<Vec<_>>();

        match self
            .client
            .query(&*self.bulk_stmt, &[&subject_ids, &post_ids, &relationships])
            .await
        {
            Ok(rows) => rows
                .into_iter()
                .map(|row| FactLoadResult::Found(row.get("allowed")))
                .collect(),
            Err(error) => {
                let error = FactLoadError::backend(error);
                keys.iter()
                    .map(|_| FactLoadResult::Error(error.clone()))
                    .collect()
            }
        }
    }
}

#[async_trait]
impl FactSource<RelationshipKey> for PgRelationshipSource {
    async fn load_many(&self, keys: &[RelationshipKey]) -> Vec<FactLoadResult<bool>> {
        if keys.len() == 1 {
            return vec![self.load_point(&keys[0]).await];
        }

        self.load_bulk(keys).await
    }
}

async fn assert_point_and_bulk_agree(source: &PgRelationshipSource, keys: &[RelationshipKey]) {
    let bulk = source.load_bulk(keys).await;
    assert_eq!(
        bulk.len(),
        keys.len(),
        "bulk results must preserve cardinality"
    );
    for (key, bulk) in keys.iter().zip(bulk) {
        match (source.load_point(key).await, bulk) {
            (FactLoadResult::Found(point), FactLoadResult::Found(bulk)) => {
                assert_eq!(point, bulk, "point and bulk SQL should agree for {key:?}");
            }
            (point, bulk) => panic!("queries must succeed: {point:?} vs {bulk:?}"),
        }
    }
}

fn build_checker() -> PermissionChecker<PostDomain> {
    let public_posts = PolicyBuilder::<PostDomain>::new("PublicPost")
        .resources(|post| post.public)
        .build();
    let viewer_relationship = RebacPolicy::<PostDomain, Uuid, Uuid, Relation>::new(
        |user: &User| user.id,
        |post: &Post| post.id,
        Relation::Viewer,
    );

    let mut checker = PermissionChecker::new();
    checker.add_policy(public_posts);
    checker.add_policy(viewer_relationship);
    checker
}

fn session_with(source: &Arc<dyn FactSource<RelationshipKey>>) -> EvaluationSession {
    FactRegistry::builder()
        .with_arc::<RelationshipKey>(Arc::clone(source))
        .build()
        .session()
}

async fn connect() -> Arc<Client> {
    let database_url = std::env::var("DATABASE_URL")
        .expect("set DATABASE_URL to a PostgreSQL database; fixtures use a connection-local temporary table");

    let (client, connection) = tokio_postgres::connect(&database_url, NoTls)
        .await
        .expect("connect to PostgreSQL");
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            eprintln!("postgres connection error: {error}");
        }
    });
    Arc::new(client)
}

async fn prepare_source(client: Arc<Client>, grants: &[RelationshipKey]) -> PgRelationshipSource {
    client
        .batch_execute(
            "
            CREATE TEMPORARY TABLE gatehouse_example_post_relationships (
                subject_id uuid NOT NULL,
                post_id uuid NOT NULL,
                relationship text NOT NULL,
                PRIMARY KEY (subject_id, post_id, relationship)
            );
            ",
        )
        .await
        .expect("setup schema");

    let subject_ids = grants.iter().map(|key| key.subject_id).collect::<Vec<_>>();
    let granted_ids = grants.iter().map(|key| key.resource_id).collect::<Vec<_>>();
    let relationships = grants
        .iter()
        .map(|key| key.relation.as_str())
        .collect::<Vec<_>>();
    client
        .execute(
            "
            INSERT INTO pg_temp.gatehouse_example_post_relationships (subject_id, post_id, relationship)
            SELECT *
            FROM unnest($1::uuid[], $2::uuid[], $3::text[])
            ",
            &[&subject_ids, &granted_ids, &relationships],
        )
        .await
        .expect("seed grants");

    let point_stmt = Arc::new(
        client
            .prepare(
                "
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_temp.gatehouse_example_post_relationships
                    WHERE subject_id = $1
                      AND relationship = $2
                      AND post_id = $3
                ) AS allowed
                ",
            )
            .await
            .expect("prepare point query"),
    );
    let bulk_stmt = Arc::new(
        client
            .prepare(
                "
                WITH candidate_relationships AS (
                    SELECT subject_id, post_id, relationship, ord
                    FROM unnest($1::uuid[], $2::uuid[], $3::text[])
                        WITH ORDINALITY AS input(subject_id, post_id, relationship, ord)
                )
                SELECT
                    COALESCE(bool_or(g.post_id IS NOT NULL), false) AS allowed
                FROM candidate_relationships c
                LEFT JOIN pg_temp.gatehouse_example_post_relationships g
                  ON g.subject_id = c.subject_id
                 AND g.relationship = c.relationship
                 AND g.post_id = c.post_id
                GROUP BY c.ord, c.subject_id, c.post_id, c.relationship
                ORDER BY c.ord
                ",
            )
            .await
            .expect("prepare bulk query"),
    );

    PgRelationshipSource {
        client,
        point_stmt,
        bulk_stmt,
    }
}

#[tokio::main]
async fn main() {
    let client = connect().await;
    let version: String = client
        .query_one("SELECT version()", &[])
        .await
        .expect("version query should succeed")
        .get(0);
    println!("{version}");

    let subject = User { id: Uuid::new_v4() };
    let posts = (0..10_000)
        .map(|index| Post {
            id: Uuid::new_v4(),
            public: index % 5 == 0,
        })
        .collect::<Vec<_>>();
    let granted_ids = posts
        .iter()
        .enumerate()
        .filter_map(|(index, post)| (!post.public && index % 2 == 0).then_some(post.id))
        .collect::<Vec<_>>();
    let grants = granted_ids
        .iter()
        .map(|post_id| RelationshipQuery {
            subject_id: subject.id,
            resource_id: *post_id,
            relation: Relation::Viewer,
        })
        .collect::<Vec<_>>();
    let source = Arc::new(prepare_source(client, &grants).await);
    assert_point_and_bulk_agree(
        &source,
        &[
            RelationshipQuery {
                subject_id: subject.id,
                resource_id: posts
                    .iter()
                    .find(|post| granted_ids.contains(&post.id))
                    .expect("fixture should include a granted private post")
                    .id,
                relation: Relation::Viewer,
            },
            RelationshipQuery {
                subject_id: subject.id,
                resource_id: posts
                    .iter()
                    .enumerate()
                    .find(|(index, post)| !post.public && index % 2 == 1)
                    .expect("fixture should include a denied private post")
                    .1
                    .id,
                relation: Relation::Viewer,
            },
        ],
    )
    .await;
    let source: Arc<dyn FactSource<RelationshipKey>> = source;
    let checker = build_checker();

    println!("size,relationship_checks,naive_ms,bulk_ms,allowed,improvement");
    for &size in &[10usize, 100, 1_000, 5_000, 10_000] {
        let sample = posts.iter().take(size).cloned().collect::<Vec<_>>();
        let relationship_checks = sample.iter().filter(|post| !post.public).count();
        let naive = measure(|| async {
            let mut allowed = 0usize;
            for post in &sample {
                let session = session_with(&source);
                if checker
                    .bind(&session, &subject, &View, &())
                    .check(post)
                    .await
                    .is_granted()
                {
                    allowed += 1;
                }
            }
            allowed
        })
        .await;

        let bulk = measure(|| async {
            let session = session_with(&source);
            checker
                .bind(&session, &subject, &View, &())
                .try_filter(sample.clone())
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .len()
        })
        .await;

        assert_eq!(naive.output, bulk.output);
        println!(
            "{size},{relationship_checks},{:.3},{:.3},{},x{:.1}",
            naive.elapsed.as_secs_f64() * 1_000.0,
            bulk.elapsed.as_secs_f64() * 1_000.0,
            bulk.output,
            naive.elapsed.as_secs_f64() / bulk.elapsed.as_secs_f64()
        );
    }
}

struct Measurement<T> {
    elapsed: Duration,
    output: T,
}

async fn measure<F, Fut, T>(mut f: F) -> Measurement<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let mut best_elapsed = Duration::MAX;
    let mut best_output = None;

    for _ in 0..3 {
        let start = Instant::now();
        let output = f().await;
        let elapsed = start.elapsed();
        if elapsed < best_elapsed {
            best_elapsed = elapsed;
            best_output = Some(output);
        }
    }

    Measurement {
        elapsed: best_elapsed,
        output: best_output.expect("measurement should run at least once"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires DATABASE_URL; run by the PostgreSQL CI job"]
    async fn heterogeneous_bulk_preserves_order_and_fixtures_are_connection_local() {
        let first_subject = Uuid::from_u128(1);
        let second_subject = Uuid::from_u128(2);
        let first_post = Uuid::from_u128(10);
        let second_post = Uuid::from_u128(20);
        let key = |subject_id, resource_id| RelationshipQuery {
            subject_id,
            resource_id,
            relation: Relation::Viewer,
        };
        let grants = [
            key(first_subject, first_post),
            key(second_subject, second_post),
        ];
        let (first_client, second_client) = tokio::join!(connect(), connect());
        let (source, empty_source) = tokio::join!(
            prepare_source(first_client, &grants),
            prepare_source(second_client, &[]),
        );
        let keys = [
            key(second_subject, second_post),
            key(first_subject, second_post),
            key(first_subject, first_post),
            key(second_subject, second_post),
            key(second_subject, first_post),
            key(first_subject, Uuid::nil()),
            key(first_subject, first_post),
        ];
        assert_point_and_bulk_agree(&source, &keys).await;
        let decisions = source
            .load_many(&keys)
            .await
            .into_iter()
            .map(|result| match result {
                FactLoadResult::Found(allowed) => allowed,
                other => panic!("expected a decision, got {other:?}"),
            })
            .collect::<Vec<_>>();
        assert_eq!(decisions, [true, false, true, true, false, false, true]);
        assert!(source.load_many(&[]).await.is_empty());
        let empty_results = empty_source.load_many(&keys).await;
        assert_eq!(empty_results.len(), keys.len());
        assert!(empty_results
            .iter()
            .all(|result| matches!(result, FactLoadResult::Found(false))));
        assert_point_and_bulk_agree(&source, &keys).await;
    }
}
