use async_trait::async_trait;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use gatehouse::{
    EvaluationSession, FactLoadResult, FactRegistry, FactSource, PermissionChecker, PolicyBuilder,
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
) -> PermissionChecker<Subject, Action, Resource, Context> {
    let mut checker = PermissionChecker::new();

    for index in 0..policy_count {
        let policy = PolicyBuilder::<Subject, Action, Resource, Context>::new(format!(
            "deny_policy_{index}"
        ))
        .forbid()
        .build();
        checker.add_policy(policy);
    }

    checker
}

fn build_trailing_allow_checker(
    policy_count: usize,
) -> PermissionChecker<Subject, Action, Resource, Context> {
    assert!(policy_count > 0, "policy count must be greater than zero");

    let mut checker = PermissionChecker::new();

    for index in 0..(policy_count - 1) {
        let policy = PolicyBuilder::<Subject, Action, Resource, Context>::new(format!(
            "deny_policy_{index}"
        ))
        .forbid()
        .build();
        checker.add_policy(policy);
    }

    let allow_policy = PolicyBuilder::<Subject, Action, Resource, Context>::new(format!(
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
#[derive(Clone)]
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

fn build_rebac_checker() -> PermissionChecker<BenchUser, BenchAction, BenchResource, BenchContext> {
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
    let registry = FactRegistry::builder()
        .with_arc::<BenchRelationship>(Arc::clone(&source))
        .build();
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
                    let session = registry.session();
                    let result = runtime.block_on(session.get_many(black_box(keys)));
                    black_box(result)
                });
            },
        );

        let cached_session = registry.session();
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
                    let session = registry.session();
                    let result = runtime.block_on(
                        checker.filter_authorized_in_session(
                            &session,
                            &subject,
                            &action,
                            black_box(
                                resources
                                    .clone()
                                    .into_iter()
                                    .map(|resource| (resource, context.clone()))
                                    .collect::<Vec<_>>(),
                            ),
                            |(resource, context)| (resource, context),
                        ),
                    );
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
    let batch_registry = FactRegistry::builder()
        .with_arc::<BenchRelationship>(Arc::clone(&batch_source))
        .build();
    let coalescing_registry = FactRegistry::builder()
        .with_arc::<BenchRelationship>(Arc::clone(&coalescing_source))
        .build();
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
                            let session = batch_registry.session();
                            let mut visible = checker
                                .filter_authorized_in_session(
                                    &session,
                                    &subject,
                                    &action,
                                    vec![(resource, context.clone())],
                                    |(resource, context)| (resource, context),
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
                    let session = batch_registry.session();
                    let result = runtime.block_on(
                        checker.filter_authorized_in_session(
                            &session,
                            &subject,
                            &action,
                            black_box(
                                resources
                                    .clone()
                                    .into_iter()
                                    .map(|resource| (resource, context.clone()))
                                    .collect::<Vec<_>>(),
                            ),
                            |(resource, context)| (resource, context),
                        ),
                    );
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
                        let registry = coalescing_registry.clone();
                        let (a, b, c, d) = tokio::join!(
                            async {
                                let session = registry.session();
                                session.get_many(black_box(keys)).await
                            },
                            async {
                                let session = registry.session();
                                session.get_many(black_box(keys)).await
                            },
                            async {
                                let session = registry.session();
                                session.get_many(black_box(keys)).await
                            },
                            async {
                                let session = registry.session();
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
                    let session = Arc::new(coalescing_registry.session());
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
    let registry = FactRegistry::builder()
        .with_arc::<BenchRelationship>(Arc::clone(&source))
        .build();
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
                        let chunk_a = black_box(chunks[0].clone());
                        let chunk_b = black_box(chunks[1].clone());
                        let chunk_c = black_box(chunks[2].clone());
                        let chunk_d = black_box(chunks[3].clone());
                        let coarse_a = Arc::clone(&coarse);
                        let coarse_b = Arc::clone(&coarse);
                        let coarse_c = Arc::clone(&coarse);
                        let coarse_d = Arc::clone(&coarse);
                        let a = tokio::spawn(async move { coarse_a.get_many(&chunk_a) });
                        let b = tokio::spawn(async move { coarse_b.get_many(&chunk_b) });
                        let c = tokio::spawn(async move { coarse_c.get_many(&chunk_c) });
                        let d = tokio::spawn(async move { coarse_d.get_many(&chunk_d) });
                        let (a, b, c, d) = tokio::join!(a, b, c, d);
                        black_box((a.unwrap(), b.unwrap(), c.unwrap(), d.unwrap()))
                    })
                });
            },
        );

        let sharded = Arc::new(registry.session());
        runtime.block_on(sharded.get_many(&keys));
        group.bench_with_input(
            BenchmarkId::new("sharded_session_cached_4_tasks", item_count),
            &chunks,
            |b, chunks| {
                b.iter(|| {
                    let sharded = Arc::clone(&sharded);
                    runtime.block_on(async {
                        let chunk_a = black_box(chunks[0].clone());
                        let chunk_b = black_box(chunks[1].clone());
                        let chunk_c = black_box(chunks[2].clone());
                        let chunk_d = black_box(chunks[3].clone());
                        let sharded_a = Arc::clone(&sharded);
                        let sharded_b = Arc::clone(&sharded);
                        let sharded_c = Arc::clone(&sharded);
                        let sharded_d = Arc::clone(&sharded);
                        let a = tokio::spawn(async move { sharded_a.get_many(&chunk_a).await });
                        let b = tokio::spawn(async move { sharded_b.get_many(&chunk_b).await });
                        let c = tokio::spawn(async move { sharded_c.get_many(&chunk_c).await });
                        let d = tokio::spawn(async move { sharded_d.get_many(&chunk_d).await });
                        let (a, b, c, d) = tokio::join!(a, b, c, d);
                        black_box((a.unwrap(), b.unwrap(), c.unwrap(), d.unwrap()))
                    })
                });
            },
        );
    }

    group.finish();
}

// -----------------------------------------------------------------------
// PolicyBuilder per-axis batch shortcut: measure the gain vs the serial
// default. `BuilderSubjectOnly` is a PolicyBuilder-produced policy whose
// only predicate is on the subject; it overrides `evaluate_batch` to
// short-circuit subject/action axes once. `ManualSubjectOnly` is the
// equivalent hand-written Policy with no `evaluate_batch` override, so
// it falls through to the default serial loop and runs the predicate
// per item. Same predicate body in both, same batch size, isolated
// from the rest of the checker.
// -----------------------------------------------------------------------

#[derive(Clone)]
struct SubjectOnlyUser {
    is_staff: bool,
}

#[derive(Clone)]
struct SubjectOnlyResource;

struct SubjectOnlyAction;

#[derive(Clone)]
struct SubjectOnlyContext;

/// Mirrors the PolicyBuilder shape — dynamic name in `name: String`,
/// no `evaluate_batch` override, so it falls through to the trait's
/// serial-loop default. Makes the comparison with the overridden
/// builder path apples-to-apples (both pay the dynamic-name per-item
/// allocation cost; only the trace-event count differs).
struct ManualSubjectOnlyDynamic {
    name: String,
}

#[async_trait]
impl gatehouse::Policy<SubjectOnlyUser, SubjectOnlyAction, SubjectOnlyResource, SubjectOnlyContext>
    for ManualSubjectOnlyDynamic
{
    async fn evaluate(
        &self,
        ctx: &gatehouse::EvalCtx<
            '_,
            SubjectOnlyUser,
            SubjectOnlyAction,
            SubjectOnlyResource,
            SubjectOnlyContext,
        >,
    ) -> gatehouse::PolicyEvalResult {
        if ctx.subject.is_staff {
            ctx.grant("staff")
        } else {
            ctx.not_applicable("not staff")
        }
    }
    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Owned(self.name.clone())
    }
}

/// Same logic but with a static name. Lets the bench show the
/// gap between PolicyBuilder (which has to use dynamic names because
/// its builder API takes `impl Into<String>`) and a hand-written
/// static-name policy.
struct ManualSubjectOnlyStatic;

#[async_trait]
impl gatehouse::Policy<SubjectOnlyUser, SubjectOnlyAction, SubjectOnlyResource, SubjectOnlyContext>
    for ManualSubjectOnlyStatic
{
    async fn evaluate(
        &self,
        ctx: &gatehouse::EvalCtx<
            '_,
            SubjectOnlyUser,
            SubjectOnlyAction,
            SubjectOnlyResource,
            SubjectOnlyContext,
        >,
    ) -> gatehouse::PolicyEvalResult {
        if ctx.subject.is_staff {
            ctx.grant("staff")
        } else {
            ctx.not_applicable("not staff")
        }
    }
    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("ManualSubjectOnlyStatic")
    }
}

fn bench_subject_only_batch(c: &mut Criterion) {
    let runtime = Runtime::new().expect("failed to create Tokio runtime");
    let mut group = c.benchmark_group("policy_builder_subject_only_batch");

    let subject = SubjectOnlyUser { is_staff: true };
    let action = SubjectOnlyAction;
    let ctx = SubjectOnlyContext;

    for &item_count in &[1usize, 10, 25, 100] {
        let resources: Vec<SubjectOnlyResource> =
            (0..item_count).map(|_| SubjectOnlyResource).collect();

        let mut builder_checker = PermissionChecker::<
            SubjectOnlyUser,
            SubjectOnlyAction,
            SubjectOnlyResource,
            SubjectOnlyContext,
        >::new();
        builder_checker.add_policy(
            PolicyBuilder::<
                SubjectOnlyUser,
                SubjectOnlyAction,
                SubjectOnlyResource,
                SubjectOnlyContext,
            >::new("BuilderSubjectOnly")
            .subjects(|u: &SubjectOnlyUser| u.is_staff)
            .build(),
        );

        let mut manual_dynamic_checker = PermissionChecker::<
            SubjectOnlyUser,
            SubjectOnlyAction,
            SubjectOnlyResource,
            SubjectOnlyContext,
        >::new();
        manual_dynamic_checker.add_policy(ManualSubjectOnlyDynamic {
            name: "BuilderSubjectOnly".into(),
        });

        let mut manual_static_checker = PermissionChecker::<
            SubjectOnlyUser,
            SubjectOnlyAction,
            SubjectOnlyResource,
            SubjectOnlyContext,
        >::new();
        manual_static_checker.add_policy(ManualSubjectOnlyStatic);

        // PolicyBuilder path — overrides evaluate_batch to broadcast.
        group.bench_with_input(
            BenchmarkId::new("builder_overridden", item_count),
            &builder_checker,
            |b, checker| {
                b.iter(|| {
                    let session = EvaluationSession::empty();
                    let result = runtime.block_on(
                        checker.evaluate_batch_in_session(
                            &session,
                            &subject,
                            &action,
                            resources
                                .clone()
                                .into_iter()
                                .map(|resource| (resource, ctx.clone()))
                                .collect::<Vec<_>>(),
                            |(resource, context)| (resource, context),
                        ),
                    );
                    black_box(result)
                });
            },
        );

        // Hand-written Policy with a dynamic name — apples-to-apples
        // with the builder shape, both pay the per-item dynamic-name
        // allocation cost. Should isolate the cost/savings of the
        // batch override itself.
        group.bench_with_input(
            BenchmarkId::new("manual_dynamic_serial_default", item_count),
            &manual_dynamic_checker,
            |b, checker| {
                b.iter(|| {
                    let session = EvaluationSession::empty();
                    let result = runtime.block_on(
                        checker.evaluate_batch_in_session(
                            &session,
                            &subject,
                            &action,
                            resources
                                .clone()
                                .into_iter()
                                .map(|resource| (resource, ctx.clone()))
                                .collect::<Vec<_>>(),
                            |(resource, context)| (resource, context),
                        ),
                    );
                    black_box(result)
                });
            },
        );

        // Hand-written Policy with a static name — sets the floor for
        // what's achievable when the user can avoid the dynamic-name
        // path entirely.
        group.bench_with_input(
            BenchmarkId::new("manual_static_serial_default", item_count),
            &manual_static_checker,
            |b, checker| {
                b.iter(|| {
                    let session = EvaluationSession::empty();
                    let result = runtime.block_on(
                        checker.evaluate_batch_in_session(
                            &session,
                            &subject,
                            &action,
                            resources
                                .clone()
                                .into_iter()
                                .map(|resource| (resource, ctx.clone()))
                                .collect::<Vec<_>>(),
                            |(resource, context)| (resource, context),
                        ),
                    );
                    black_box(result)
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
    bench_parallel_fact_state,
    bench_subject_only_batch
);
criterion_main!(benches);
