use async_trait::async_trait;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use gatehouse::{
    BatchEvalCtx, EvalCtx, FactKey, FactLoadError, FactLoadResult, FactRegistry, FactSource,
    GrantResult, PermissionChecker, Policy, PolicyDomain,
};
use std::borrow::Cow;
use std::hint::black_box;
use tokio::runtime::Runtime;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Key(usize);
impl FactKey for Key {
    type Value = bool;
    const NAME: &'static str = "benchmark";
}

struct Source {
    fails: bool,
}
#[async_trait]
impl FactSource<Key> for Source {
    async fn load_many(&self, keys: &[Key]) -> Vec<FactLoadResult<bool>> {
        keys.iter()
            .map(|_| {
                if self.fails {
                    FactLoadResult::Error(FactLoadError::backend_message("unavailable"))
                } else {
                    FactLoadResult::Found(true)
                }
            })
            .collect()
    }
}
struct Domain;
impl PolicyDomain for Domain {
    type Subject = ();
    type Action = ();
    type Resource = Key;
    type Context = ();
}
struct Recorded;
#[async_trait]
impl Policy<Domain> for Recorded {
    async fn evaluate(&self, context: &EvalCtx<'_, Domain>) -> GrantResult {
        match context.fact(context.resource.clone()).await {
            FactLoadResult::Found(true) => context.grant("found"),
            _ => context.not_applicable("not found"),
        }
    }
    async fn evaluate_batch<'item>(
        &self,
        context: &BatchEvalCtx<'item, Domain>,
    ) -> Vec<GrantResult> {
        context
            .facts_by(Clone::clone)
            .await
            .into_iter()
            .map(|result| match result {
                FactLoadResult::Found(true) => GrantResult::granted("recorded", None),
                _ => GrantResult::not_applicable("recorded", "not found"),
            })
            .collect()
    }
    fn policy_type(&self) -> Cow<'static, str> {
        "recorded".into()
    }
}

fn recording(criterion: &mut Criterion) {
    let runtime = Runtime::new().unwrap();
    let mut group = criterion.benchmark_group("recording");
    for fails in [false, true] {
        let registry = FactRegistry::builder()
            .with::<Key, _>(Source { fails })
            .build();
        let session = registry.session();
        let _ = runtime.block_on(session.get(Key(0)));
        let label = if fails { "error" } else { "found" };
        group.bench_function(format!("raw_cached_{label}"), |bench| {
            bench.iter(|| black_box(runtime.block_on(session.get(Key(0)))))
        });
        group.bench_function(format!("recorded_cached_{label}"), |bench| {
            bench.iter(|| {
                let context = EvalCtx::<Domain>::new(&session, &(), &(), &Key(0), &(), "recorded");
                black_box(runtime.block_on(async {
                    let result = Recorded.evaluate(&context).await;
                    context.finish(result)
                }))
            })
        });
        let mut checker = PermissionChecker::<Domain>::new();
        checker.add_policy(Recorded);
        for size in [100, 1000, 10_000] {
            let resources = (0..size).map(Key).collect::<Vec<_>>();
            group.bench_with_input(
                BenchmarkId::new(format!("batch_{label}"), size),
                &resources,
                |bench, resources| {
                    bench.iter(|| {
                        let session = registry.session();
                        black_box(
                            runtime.block_on(
                                checker
                                    .bind(&session, &(), &(), &())
                                    .evaluate(resources.clone()),
                            ),
                        )
                    })
                },
            );
        }
        group.bench_function(format!("checker_cached_{label}"), |bench| {
            bench.iter(|| {
                black_box(runtime.block_on(checker.bind(&session, &(), &(), &()).check(&Key(0))))
            })
        });
        #[cfg(feature = "tracing")]
        {
            let subscriber = tracing_subscriber::Registry::default();
            let _guard = tracing::subscriber::set_default(subscriber);
            group.bench_function(format!("checker_registry_cached_{label}"), |bench| {
                bench.iter(|| {
                    black_box(
                        runtime.block_on(checker.bind(&session, &(), &(), &()).check(&Key(0))),
                    )
                })
            });
        }
    }
    group.finish();
}
criterion_group!(benches, recording);
criterion_main!(benches);
