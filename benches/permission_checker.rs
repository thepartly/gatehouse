use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use gatehouse::{Effect, PermissionChecker, PolicyBuilder};
use std::hint::black_box;
use tokio::runtime::Runtime;

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
    let mut group = c.benchmark_group("permission_checker_evaluate_access");

    for &policy_count in &[1usize, 4, 16, 64] {
        let allow_checker = build_trailing_allow_checker(policy_count);
        group.bench_with_input(
            BenchmarkId::new("trailing_allow", policy_count),
            &allow_checker,
            |b, checker| {
                b.iter(|| {
                    let result = runtime
                        .block_on(checker.evaluate_access(&subject, &action, &resource, &context));
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
                    let result = runtime
                        .block_on(checker.evaluate_access(&subject, &action, &resource, &context));
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_permission_checker);
criterion_main!(benches);
