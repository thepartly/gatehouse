use async_trait::async_trait;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use gatehouse::{
    Effect, EvaluationSession, FactLoadResult, FactSource, PermissionChecker, PolicyBuilder,
    RebacPolicy, RelationshipQuery,
};
use std::hint::black_box;
use std::sync::Arc;
use tokio::runtime::Runtime;
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

criterion_group!(benches, bench_permission_checker, bench_in_ram_fact_source);
criterion_main!(benches);
