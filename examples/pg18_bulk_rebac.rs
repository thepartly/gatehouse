use async_trait::async_trait;
use gatehouse::{PermissionChecker, RebacPolicy, RelationshipResolver};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_postgres::{Client, NoTls, Statement};
use uuid::Uuid;

static UNIT_CONTEXT: () = ();

#[derive(Clone)]
struct User {
    id: Uuid,
}

#[derive(Clone)]
struct Post {
    id: Uuid,
}

struct View;

#[derive(Clone)]
struct PgRelationshipResolver {
    client: Arc<Client>,
    point_stmt: Arc<Statement>,
    bulk_stmt: Arc<Statement>,
}

#[async_trait]
impl RelationshipResolver<User, Post, String> for PgRelationshipResolver {
    async fn has_relationship(
        &self,
        subject: &User,
        resource: &Post,
        relationship: &String,
    ) -> bool {
        self.client
            .query_one(
                &*self.point_stmt,
                &[&subject.id, relationship, &resource.id],
            )
            .await
            .expect("point relationship query should succeed")
            .get(0)
    }

    async fn has_relationship_batch<'item>(
        &self,
        subject: &'item User,
        resources: &'item [&'item Post],
        relationship: &'item String,
    ) -> Vec<bool> {
        let post_ids = resources.iter().map(|post| post.id).collect::<Vec<_>>();
        self.client
            .query(&*self.bulk_stmt, &[&subject.id, relationship, &post_ids])
            .await
            .expect("bulk relationship query should succeed")
            .into_iter()
            .map(|row| row.get("allowed"))
            .collect()
    }
}

#[tokio::main]
async fn main() {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "host=localhost port=15432 user=postgres password=test dbname=awa_test".to_string()
    });

    let (client, connection) = tokio_postgres::connect(&database_url, NoTls)
        .await
        .expect("connect to PostgreSQL 18");
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            eprintln!("postgres connection error: {error}");
        }
    });
    let client = Arc::new(client);

    let version: String = client
        .query_one("SELECT version()", &[])
        .await
        .expect("version query should succeed")
        .get(0);
    println!("{version}");

    client
        .batch_execute(
            "
            DROP TABLE IF EXISTS gatehouse_spike_post_grants;
            CREATE UNLOGGED TABLE gatehouse_spike_post_grants (
                subject_id uuid NOT NULL,
                post_id uuid NOT NULL,
                relationship text NOT NULL,
                PRIMARY KEY (subject_id, post_id, relationship)
            );
            ",
        )
        .await
        .expect("setup schema");

    let subject = User { id: Uuid::new_v4() };
    let relationship = "viewer".to_string();
    let posts = (0..10_000)
        .map(|_| Post { id: Uuid::new_v4() })
        .collect::<Vec<_>>();
    let granted_ids = posts
        .iter()
        .enumerate()
        .filter_map(|(index, post)| (index % 2 == 0).then_some(post.id))
        .collect::<Vec<_>>();
    let relationships = vec![relationship.clone(); granted_ids.len()];
    let subject_ids = vec![subject.id; granted_ids.len()];

    client
        .execute(
            "
            INSERT INTO gatehouse_spike_post_grants (subject_id, post_id, relationship)
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
                    FROM gatehouse_spike_post_grants
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
                WITH candidate_posts AS (
                    SELECT post_id, ord
                    FROM unnest($3::uuid[]) WITH ORDINALITY AS input(post_id, ord)
                )
                SELECT
                    COALESCE(bool_or(g.post_id IS NOT NULL), false) AS allowed
                FROM candidate_posts c
                LEFT JOIN gatehouse_spike_post_grants g
                  ON g.subject_id = $1
                 AND g.relationship = $2
                 AND g.post_id = c.post_id
                GROUP BY c.ord, c.post_id
                ORDER BY c.ord
                ",
            )
            .await
            .expect("prepare bulk query"),
    );

    let resolver = PgRelationshipResolver {
        client,
        point_stmt,
        bulk_stmt,
    };
    let policy = RebacPolicy::<User, Post, View, (), _, _>::new(relationship, resolver);
    let mut checker = PermissionChecker::new();
    checker.add_policy(policy);

    println!("size,naive_ms,bulk_ms,allowed,improvement");
    for &size in &[10usize, 100, 1_000, 5_000, 10_000] {
        let sample = posts.iter().take(size).cloned().collect::<Vec<_>>();
        let naive = measure(|| async {
            let mut allowed = 0usize;
            for post in &sample {
                if checker
                    .evaluate_access(&subject, &View, post, &UNIT_CONTEXT)
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
            checker
                .filter_authorized_with_context_by(
                    &subject,
                    &View,
                    sample.clone(),
                    &UNIT_CONTEXT,
                    |post| post,
                )
                .await
                .len()
        })
        .await;

        assert_eq!(naive.output, bulk.output);
        println!(
            "{size},{:.3},{:.3},{},x{:.1}",
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
