use async_trait::async_trait;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use gatehouse::{
    Effect, EvaluationSession, FactLoadResult, FactSource, PermissionChecker, PolicyBuilder,
    RebacPolicy, RelationshipQuery,
};
use std::collections::HashMap;
use std::hint::black_box;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

type Subject = ();
type Resource = ();
type Action = ();
type Context = ();

fn build_all_deny_checker(
    policy_count: usize,
) -> PermissionChecker<Subject, Resource, Action, Context> {
    let mut checker = PermissionChecker::new();

    for index in 0..policy_count {
        let policy = PolicyBuilder::<Subject, Resource, Action, Context>::new(format!(
            "deny_policy_{index}"
        ))
        .effect(Effect::Deny)
        .build();
        checker.add_policy(policy);
    }

    checker
}

fn build_trailing_allow_checker(
    policy_count: usize,
) -> PermissionChecker<Subject, Resource, Action, Context> {
    assert!(policy_count > 0, "policy count must be greater than zero");

    let mut checker = PermissionChecker::new();

    for index in 0..(policy_count - 1) {
        let policy = PolicyBuilder::<Subject, Resource, Action, Context>::new(format!(
            "deny_policy_{index}"
        ))
        .effect(Effect::Deny)
        .build();
        checker.add_policy(policy);
    }

    let allow_policy = PolicyBuilder::<Subject, Resource, Action, Context>::new(format!(
        "allow_policy_{}",
        policy_count - 1
    ))
    .build();
    checker.add_policy(allow_policy);

    checker
}

fn bench_permission_checker(c: &mut Criterion) {
    let runtime = Runtime::new().expect("failed to create Tokio runtime");
    let subject: Subject = ();
    let action: Action = ();
    let resource: Resource = ();
    let context: Context = ();
    let mut group = c.benchmark_group("permission_checker_evaluate_in_session");

    for &policy_count in &[1usize, 4, 16, 64] {
        let allow_checker = build_trailing_allow_checker(policy_count);
        group.bench_with_input(
            BenchmarkId::new("trailing_allow", policy_count),
            &allow_checker,
            |b, checker| {
                b.iter(|| {
                    let session = EvaluationSession::empty();
                    let result = runtime.block_on(
                        checker
                            .evaluate_in_session(&session, &subject, &action, &resource, &context),
                    );
                    black_box(result)
                });
            },
        );

        let deny_checker = build_all_deny_checker(policy_count);
        group.bench_with_input(
            BenchmarkId::new("all_deny", policy_count),
            &deny_checker,
            |b, checker| {
                b.iter(|| {
                    let session = EvaluationSession::empty();
                    let result = runtime.block_on(
                        checker
                            .evaluate_in_session(&session, &subject, &action, &resource, &context),
                    );
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

#[derive(Clone)]
struct BenchUser {
    id: Uuid,
}

#[derive(Clone)]
struct BenchResource {
    id: Uuid,
}

struct BenchAction;
struct BenchContext;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum BenchRelation {
    Viewer,
}

impl std::fmt::Display for BenchRelation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Viewer => f.write_str("viewer"),
        }
    }
}

type BenchRelationship = RelationshipQuery<Uuid, Uuid, BenchRelation>;

struct AlwaysFoundSource;

#[async_trait]
impl FactSource<BenchRelationship> for AlwaysFoundSource {
    async fn load_many(&self, keys: &[BenchRelationship]) -> Vec<FactLoadResult<bool>> {
        keys.iter().map(|_| FactLoadResult::Found(true)).collect()
    }
}

#[derive(Clone)]
struct LatencyFoundSource {
    delay: Duration,
    serial_gate: Option<Arc<AsyncMutex<()>>>,
}

impl LatencyFoundSource {
    fn concurrent(delay: Duration) -> Self {
        Self {
            delay,
            serial_gate: None,
        }
    }

    fn serialized(delay: Duration) -> Self {
        Self {
            delay,
            serial_gate: Some(Arc::new(AsyncMutex::new(()))),
        }
    }

    async fn wait(&self) {
        if let Some(serial_gate) = &self.serial_gate {
            let _guard = serial_gate.lock().await;
            tokio::time::sleep(self.delay).await;
        } else {
            tokio::time::sleep(self.delay).await;
        }
    }
}

#[async_trait]
impl FactSource<BenchRelationship> for LatencyFoundSource {
    async fn load_many(&self, keys: &[BenchRelationship]) -> Vec<FactLoadResult<bool>> {
        self.wait().await;
        keys.iter().map(|_| FactLoadResult::Found(true)).collect()
    }
}

struct CoarseReferenceSession {
    cache: Mutex<HashMap<BenchRelationship, FactLoadResult<bool>>>,
}

impl CoarseReferenceSession {
    fn cached(keys: &[BenchRelationship]) -> Self {
        Self {
            cache: Mutex::new(
                keys.iter()
                    .cloned()
                    .map(|key| (key, FactLoadResult::Found(true)))
                    .collect(),
            ),
        }
    }

    fn get_many(&self, keys: &[BenchRelationship]) -> Vec<FactLoadResult<bool>> {
        let cache = self.cache.lock().unwrap();
        keys.iter()
            .map(|key| cache.get(key).cloned().unwrap_or(FactLoadResult::Missing))
            .collect()
    }
}

fn build_rebac_checker() -> PermissionChecker<BenchUser, BenchResource, BenchAction, BenchContext> {
    let mut checker = PermissionChecker::new();
    checker.add_policy(RebacPolicy::new(
        |user: &BenchUser| user.id,
        |resource: &BenchResource| resource.id,
        BenchRelation::Viewer,
    ));
    checker
}

fn bench_in_ram_fact_source(c: &mut Criterion) {
    let runtime = Runtime::new().expect("failed to create Tokio runtime");
    let subject = BenchUser { id: Uuid::new_v4() };
    let action = BenchAction;
    let context = BenchContext;
    let source: Arc<dyn FactSource<BenchRelationship>> = Arc::new(AlwaysFoundSource);
    let checker = build_rebac_checker();
    let mut group = c.benchmark_group("in_ram_fact_source");

    for &item_count in &[1usize, 10, 100, 1_000] {
        let resources = (0..item_count)
            .map(|_| BenchResource { id: Uuid::new_v4() })
            .collect::<Vec<_>>();
        let keys = resources
            .iter()
            .map(|resource| BenchRelationship {
                subject_id: subject.id,
                resource_id: resource.id,
                relation: BenchRelation::Viewer,
            })
            .collect::<Vec<_>>();

        group.bench_with_input(
            BenchmarkId::new("session_get_many_uncached", item_count),
            &keys,
            |b, keys| {
                b.iter(|| {
                    let session = EvaluationSession::builder()
                        .with_arc::<BenchRelationship>(Arc::clone(&source))
                        .build();
                    let result = runtime.block_on(session.get_many(black_box(keys)));
                    black_box(result)
                });
            },
        );

        let cached_session = EvaluationSession::builder()
            .with_arc::<BenchRelationship>(Arc::clone(&source))
            .build();
        runtime.block_on(cached_session.get_many(&keys));
        group.bench_with_input(
            BenchmarkId::new("session_get_many_cached", item_count),
            &keys,
            |b, keys| {
                b.iter(|| {
                    let result = runtime.block_on(cached_session.get_many(black_box(keys)));
                    black_box(result)
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("checker_batch_uncached", item_count),
            &resources,
            |b, resources| {
                b.iter(|| {
                    let session = EvaluationSession::builder()
                        .with_arc::<BenchRelationship>(Arc::clone(&source))
                        .build();
                    let result =
                        runtime.block_on(checker.filter_authorized_with_context_in_session_by(
                            &session,
                            &subject,
                            &action,
                            black_box(resources.clone()),
                            &context,
                            |resource| resource,
                        ));
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

fn bench_latency_fact_source(c: &mut Criterion) {
    let runtime = Runtime::new().expect("failed to create Tokio runtime");
    let subject = BenchUser { id: Uuid::new_v4() };
    let action = BenchAction;
    let context = BenchContext;
    let checker = build_rebac_checker();
    let delay = Duration::from_millis(1);
    let batch_source: Arc<dyn FactSource<BenchRelationship>> =
        Arc::new(LatencyFoundSource::concurrent(delay));
    let coalescing_source: Arc<dyn FactSource<BenchRelationship>> =
        Arc::new(LatencyFoundSource::serialized(delay));
    let mut group = c.benchmark_group("latency_fact_source");
    group.sample_size(10);
    group.warm_up_time(Duration::from_millis(200));
    group.measurement_time(Duration::from_secs(2));

    for &item_count in &[10usize, 100] {
        let resources = (0..item_count)
            .map(|_| BenchResource { id: Uuid::new_v4() })
            .collect::<Vec<_>>();
        let keys = resources
            .iter()
            .map(|resource| BenchRelationship {
                subject_id: subject.id,
                resource_id: resource.id,
                relation: BenchRelation::Viewer,
            })
            .collect::<Vec<_>>();

        group.bench_with_input(
            BenchmarkId::new("naive_per_item_sessions", item_count),
            &resources,
            |b, resources| {
                b.iter(|| {
                    let result = runtime.block_on(async {
                        let mut authorized = Vec::new();
                        for resource in black_box(resources.clone()) {
                            let session = EvaluationSession::builder()
                                .with_arc::<BenchRelationship>(Arc::clone(&batch_source))
                                .build();
                            let mut visible = checker
                                .filter_authorized_with_context_in_session_by(
                                    &session,
                                    &subject,
                                    &action,
                                    vec![resource],
                                    &context,
                                    |resource| resource,
                                )
                                .await;
                            authorized.append(&mut visible);
                        }
                        authorized
                    });
                    black_box(result)
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("checker_batch_one_session", item_count),
            &resources,
            |b, resources| {
                b.iter(|| {
                    let session = EvaluationSession::builder()
                        .with_arc::<BenchRelationship>(Arc::clone(&batch_source))
                        .build();
                    let result =
                        runtime.block_on(checker.filter_authorized_with_context_in_session_by(
                            &session,
                            &subject,
                            &action,
                            black_box(resources.clone()),
                            &context,
                            |resource| resource,
                        ));
                    black_box(result)
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("independent_same_keys_4_tasks", item_count),
            &keys,
            |b, keys| {
                b.iter(|| {
                    runtime.block_on(async {
                        let source = Arc::clone(&coalescing_source);
                        let (a, b, c, d) = tokio::join!(
                            async {
                                let session = EvaluationSession::builder()
                                    .with_arc::<BenchRelationship>(Arc::clone(&source))
                                    .build();
                                session.get_many(black_box(keys)).await
                            },
                            async {
                                let session = EvaluationSession::builder()
                                    .with_arc::<BenchRelationship>(Arc::clone(&source))
                                    .build();
                                session.get_many(black_box(keys)).await
                            },
                            async {
                                let session = EvaluationSession::builder()
                                    .with_arc::<BenchRelationship>(Arc::clone(&source))
                                    .build();
                                session.get_many(black_box(keys)).await
                            },
                            async {
                                let session = EvaluationSession::builder()
                                    .with_arc::<BenchRelationship>(Arc::clone(&source))
                                    .build();
                                session.get_many(black_box(keys)).await
                            },
                        );
                        black_box((a, b, c, d))
                    })
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("coalesced_same_keys_4_tasks", item_count),
            &keys,
            |b, keys| {
                b.iter(|| {
                    let session = Arc::new(
                        EvaluationSession::builder()
                            .with_arc::<BenchRelationship>(Arc::clone(&coalescing_source))
                            .build(),
                    );
                    runtime.block_on(async {
                        let (a, b, c, d) = tokio::join!(
                            async { session.get_many(black_box(keys)).await },
                            async { session.get_many(black_box(keys)).await },
                            async { session.get_many(black_box(keys)).await },
                            async { session.get_many(black_box(keys)).await },
                        );
                        black_box((a, b, c, d))
                    })
                });
            },
        );
    }

    group.finish();
}

fn bench_parallel_fact_state(c: &mut Criterion) {
    let runtime = Runtime::new().expect("failed to create Tokio runtime");
    let subject = BenchUser { id: Uuid::new_v4() };
    let source: Arc<dyn FactSource<BenchRelationship>> = Arc::new(AlwaysFoundSource);
    let mut group = c.benchmark_group("parallel_in_ram_fact_state");

    for &item_count in &[100usize, 1_000, 10_000] {
        let resources = (0..item_count)
            .map(|_| BenchResource { id: Uuid::new_v4() })
            .collect::<Vec<_>>();
        let keys = resources
            .iter()
            .map(|resource| BenchRelationship {
                subject_id: subject.id,
                resource_id: resource.id,
                relation: BenchRelation::Viewer,
            })
            .collect::<Vec<_>>();
        let chunk_len = keys.len().div_ceil(4);
        let chunks = keys
            .chunks(chunk_len)
            .map(|chunk| chunk.to_vec())
            .collect::<Vec<_>>();
        assert_eq!(chunks.len(), 4);

        let coarse = Arc::new(CoarseReferenceSession::cached(&keys));
        group.bench_with_input(
            BenchmarkId::new("coarse_reference_cached_4_tasks", item_count),
            &chunks,
            |b, chunks| {
                b.iter(|| {
                    let coarse = Arc::clone(&coarse);
                    runtime.block_on(async {
                        let (a, b, c, d) = tokio::join!(
                            async { coarse.get_many(black_box(&chunks[0])) },
                            async { coarse.get_many(black_box(&chunks[1])) },
                            async { coarse.get_many(black_box(&chunks[2])) },
                            async { coarse.get_many(black_box(&chunks[3])) },
                        );
                        black_box((a, b, c, d))
                    })
                });
            },
        );

        let sharded = Arc::new(
            EvaluationSession::builder()
                .with_arc::<BenchRelationship>(Arc::clone(&source))
                .build(),
        );
        runtime.block_on(sharded.get_many(&keys));
        group.bench_with_input(
            BenchmarkId::new("sharded_session_cached_4_tasks", item_count),
            &chunks,
            |b, chunks| {
                b.iter(|| {
                    let sharded = Arc::clone(&sharded);
                    runtime.block_on(async {
                        let (a, b, c, d) = tokio::join!(
                            async { sharded.get_many(black_box(&chunks[0])).await },
                            async { sharded.get_many(black_box(&chunks[1])).await },
                            async { sharded.get_many(black_box(&chunks[2])).await },
                            async { sharded.get_many(black_box(&chunks[3])).await },
                        );
                        black_box((a, b, c, d))
                    })
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_permission_checker,
    bench_in_ram_fact_source,
    bench_latency_fact_source,
    bench_parallel_fact_state
);
criterion_main!(benches);
