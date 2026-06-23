use async_trait::async_trait;
use gatehouse::{
    AccessEvaluation, AndPolicy, BatchEvalCtx, DelegatingPolicy, Effect, EvalCtx,
    EvaluationSession, FactLoadResult, FactSource, Hydrator, LookupAuthorizedError, LookupPage,
    LookupSource, NotPolicy, OrPolicy, PermissionChecker, Policy, PolicyBatchItem, PolicyBuilder,
    PolicyDomain, PolicyEvalResult, RebacPolicy, RelationshipQuery,
};
use proptest::prelude::*;
use std::collections::HashSet;
use std::convert::Infallible;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
struct Subject;

#[derive(Debug, Clone)]
struct Action;

#[derive(Debug, Clone)]
struct Ctx;

#[derive(Debug, Clone)]
struct Resource {
    id: u8,
}

struct Domain;

impl PolicyDomain for Domain {
    type Subject = Subject;
    type Action = Action;
    type Resource = Resource;
    type Context = Ctx;
}

struct UnitContextDomain;

impl PolicyDomain for UnitContextDomain {
    type Subject = Subject;
    type Action = Action;
    type Resource = Resource;
    type Context = ();
}

fn bind<'a>(
    checker: &'a PermissionChecker<Domain>,
    session: &'a EvaluationSession,
) -> gatehouse::BoundEvaluator<'a, Domain> {
    checker.bind(session, &Subject, &Action, &Ctx)
}

async fn check_resource(
    checker: &PermissionChecker<Domain>,
    session: &EvaluationSession,
    resource: &Resource,
) -> AccessEvaluation {
    bind(checker, session).check(resource).await
}

async fn evaluate_resources<I>(
    checker: &PermissionChecker<Domain>,
    session: &EvaluationSession,
    resources: I,
) -> Vec<(I::Item, AccessEvaluation)>
where
    I: IntoIterator,
    I::Item: std::borrow::Borrow<Resource>,
{
    bind(checker, session).evaluate(resources).await
}

async fn filter_resources<I>(
    checker: &PermissionChecker<Domain>,
    session: &EvaluationSession,
    resources: I,
) -> Vec<I::Item>
where
    I: IntoIterator,
    I::Item: std::borrow::Borrow<Resource>,
{
    bind(checker, session).filter(resources).await
}

struct BatchGrantPolicy {
    name: &'static str,
    batch_calls: Arc<AtomicUsize>,
    single_calls: Arc<AtomicUsize>,
    seen_batches: Arc<Mutex<Vec<Vec<u8>>>>,
    grant: Arc<dyn Fn(u8) -> bool + Send + Sync>,
}

#[async_trait]
impl Policy<Domain> for BatchGrantPolicy {
    async fn evaluate(&self, ctx: &EvalCtx<'_, Domain>) -> PolicyEvalResult {
        self.single_calls.fetch_add(1, Ordering::SeqCst);
        self.result_for(ctx.resource.id)
    }

    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, Domain>,
    ) -> Vec<PolicyEvalResult> {
        self.batch_calls.fetch_add(1, Ordering::SeqCst);
        self.seen_batches.lock().unwrap().push(
            ctx.items
                .iter()
                .map(|item| item.resource.id)
                .collect::<Vec<_>>(),
        );
        ctx.items
            .iter()
            .map(|item| self.result_for(item.resource.id))
            .collect()
    }

    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed(self.name)
    }
}

impl BatchGrantPolicy {
    fn result_for(&self, resource_id: u8) -> PolicyEvalResult {
        if (self.grant)(resource_id) {
            PolicyEvalResult::granted(self.name, Some(format!("{resource_id} granted")))
        } else {
            PolicyEvalResult::not_applicable(self.name, format!("{resource_id} denied"))
        }
    }
}

struct RandomStackPolicy {
    name: String,
    spec: RandomPolicySpec,
}

#[async_trait]
impl Policy<Domain> for RandomStackPolicy {
    async fn evaluate(&self, ctx: &EvalCtx<'_, Domain>) -> PolicyEvalResult {
        self.result_for(ctx.resource.id)
    }

    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, Domain>,
    ) -> Vec<PolicyEvalResult> {
        ctx.items
            .iter()
            .map(|item| self.result_for(item.resource.id))
            .collect()
    }

    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Owned(self.name.clone())
    }

    fn effect(&self) -> Effect {
        self.spec.effect
    }
}

impl RandomStackPolicy {
    fn result_for(&self, resource_id: u8) -> PolicyEvalResult {
        match self.spec.leaf_outcome(resource_id) {
            LeafOutcome::Grant => {
                PolicyEvalResult::granted(self.name.clone(), Some(format!("{resource_id} granted")))
            }
            LeafOutcome::Forbid => {
                PolicyEvalResult::forbidden(self.name.clone(), format!("{resource_id} forbidden"))
            }
            LeafOutcome::NotApplicable => {
                PolicyEvalResult::not_applicable(self.name.clone(), format!("{resource_id} denied"))
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct RandomPolicySpec {
    grant_percent: u8,
    forbid_percent: u8,
    salt: u16,
    effect: Effect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LeafOutcome {
    Grant,
    Forbid,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExpectedDecision {
    Granted,
    Forbidden,
    Denied,
}

impl RandomPolicySpec {
    fn leaf_outcome(self, resource_id: u8) -> LeafOutcome {
        let grant_score = ((resource_id as u16 * 37) ^ self.salt).wrapping_add(self.salt / 3) % 100;
        let forbid_score =
            ((resource_id as u16 * 53) ^ self.salt).wrapping_add(self.salt / 5) % 100;
        let grant_matched = grant_score < self.grant_percent as u16;
        let forbid_matched = forbid_score < self.forbid_percent as u16;

        if self.effect.can_forbid() && forbid_matched {
            LeafOutcome::Forbid
        } else if self.effect.can_grant() && grant_matched {
            LeafOutcome::Grant
        } else {
            LeafOutcome::NotApplicable
        }
    }

    fn into_policy(self, index: usize) -> RandomStackPolicy {
        RandomStackPolicy {
            name: format!("random_{index}"),
            spec: self,
        }
    }
}

fn oracle_decision(specs: &[RandomPolicySpec], resource_id: u8) -> ExpectedDecision {
    let mut saw_grant = false;
    for outcome in specs.iter().map(|spec| spec.leaf_outcome(resource_id)) {
        match outcome {
            LeafOutcome::Forbid => return ExpectedDecision::Forbidden,
            LeafOutcome::Grant => saw_grant = true,
            LeafOutcome::NotApplicable => {}
        }
    }

    if saw_grant {
        ExpectedDecision::Granted
    } else {
        ExpectedDecision::Denied
    }
}

fn access_decision(evaluation: &AccessEvaluation) -> ExpectedDecision {
    if evaluation.is_granted() {
        ExpectedDecision::Granted
    } else if evaluation.forbidden_by().is_some() {
        ExpectedDecision::Forbidden
    } else {
        ExpectedDecision::Denied
    }
}

fn policy_decision(result: &PolicyEvalResult) -> ExpectedDecision {
    if result.is_forbidden() {
        ExpectedDecision::Forbidden
    } else if result.is_granted() {
        ExpectedDecision::Granted
    } else {
        ExpectedDecision::Denied
    }
}

fn checker_from_specs(
    specs: &[RandomPolicySpec],
    max_batch_size: Option<usize>,
) -> PermissionChecker<Domain> {
    let mut checker = if let Some(max_batch_size) = max_batch_size {
        PermissionChecker::new().with_max_batch_size(NonZeroUsize::new(max_batch_size).unwrap())
    } else {
        PermissionChecker::new()
    };
    for (index, spec) in specs.iter().copied().enumerate() {
        checker.add_policy(spec.into_policy(index));
    }
    checker
}

fn arc_policies_from_specs(specs: &[RandomPolicySpec]) -> Vec<Arc<dyn Policy<Domain>>> {
    specs
        .iter()
        .copied()
        .enumerate()
        .map(|(index, spec)| Arc::new(spec.into_policy(index)) as Arc<dyn Policy<Domain>>)
        .collect()
}

fn policy_spec_strategy() -> impl Strategy<Value = RandomPolicySpec> {
    prop_oneof![
        2 => (0u8..=100, any::<u16>()).prop_map(|(grant_percent, salt)| RandomPolicySpec {
            grant_percent,
            forbid_percent: 0,
            salt,
            effect: Effect::Allow,
        }),
        3 => (0u8..=100, any::<u16>()).prop_map(|(forbid_percent, salt)| RandomPolicySpec {
            grant_percent: 0,
            forbid_percent,
            salt,
            effect: Effect::Forbid,
        }),
        5 => (0u8..=100, 0u8..=100, any::<u16>()).prop_map(
            |(grant_percent, forbid_percent, salt)| RandomPolicySpec {
                grant_percent,
                forbid_percent,
                salt,
                effect: Effect::AllowOrForbid,
            }
        ),
    ]
}

fn adversarial_policy_stack_strategy() -> impl Strategy<Value = Vec<RandomPolicySpec>> {
    let exact_deferred_grant = prop::collection::vec(
        prop_oneof![
            Just(RandomPolicySpec {
                grant_percent: 0,
                forbid_percent: 0,
                salt: 0,
                effect: Effect::Allow,
            }),
            Just(RandomPolicySpec {
                grant_percent: 0,
                forbid_percent: 0,
                salt: 0,
                effect: Effect::AllowOrForbid,
            }),
        ],
        0..=3,
    )
    .prop_map(|mut tail| {
        let mut specs = vec![
            RandomPolicySpec {
                grant_percent: 100,
                forbid_percent: 0,
                salt: 0,
                effect: Effect::AllowOrForbid,
            },
            RandomPolicySpec {
                grant_percent: 0,
                forbid_percent: 0,
                salt: 0,
                effect: Effect::AllowOrForbid,
            },
        ];
        specs.append(&mut tail);
        specs
    });

    let veto_heavy = prop::collection::vec(policy_spec_strategy(), 2..=5).prop_filter(
        "at least two veto-capable policies, one mixed-capability policy",
        |specs| {
            specs.iter().filter(|spec| spec.effect.can_forbid()).count() >= 2
                && specs
                    .iter()
                    .any(|spec| spec.effect == Effect::AllowOrForbid)
        },
    );

    prop_oneof![
        5 => exact_deferred_grant,
        7 => veto_heavy,
        2 => prop::collection::vec(policy_spec_strategy(), 1..=5),
    ]
}

struct NeverConsultedPolicy {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Policy<Domain> for NeverConsultedPolicy {
    async fn evaluate(&self, _ctx: &EvalCtx<'_, Domain>) -> PolicyEvalResult {
        self.calls.fetch_add(1, Ordering::SeqCst);
        PolicyEvalResult::not_applicable(self.policy_type().to_string(), "single called")
    }

    async fn evaluate_batch<'item>(
        &self,
        _ctx: &BatchEvalCtx<'item, Domain>,
    ) -> Vec<PolicyEvalResult> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Vec::new()
    }

    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("NeverConsultedPolicy")
    }
}

#[tokio::test]
async fn empty_batch_returns_empty_and_does_not_consult_policies() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut checker = PermissionChecker::new();
    checker.add_policy(NeverConsultedPolicy {
        calls: Arc::clone(&calls),
    });

    let session = EvaluationSession::empty();
    let results = evaluate_resources(&checker, &session, Vec::<Resource>::new()).await;

    assert!(results.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn single_item_batch_matches_single_evaluation() {
    let mut checker = PermissionChecker::new();
    checker.add_policy(BatchGrantPolicy {
        name: "even",
        batch_calls: Arc::new(AtomicUsize::new(0)),
        single_calls: Arc::new(AtomicUsize::new(0)),
        seen_batches: Arc::new(Mutex::new(Vec::new())),
        grant: Arc::new(|resource_id| resource_id % 2 == 0),
    });
    let session = EvaluationSession::empty();
    let item = Resource { id: 4 };

    let single = check_resource(&checker, &session, &item).await.is_granted();
    let batch = evaluate_resources(&checker, &session, vec![item])
        .await
        .into_iter()
        .map(|(_item, evaluation)| evaluation.is_granted())
        .collect::<Vec<_>>();

    assert_eq!(batch, vec![single]);
}

#[tokio::test]
async fn resource_batch_uses_unit_context() {
    let mut checker = PermissionChecker::<UnitContextDomain>::new();
    checker.add_policy(
        PolicyBuilder::<UnitContextDomain>::new("even-resource")
            .resources(|resource: &Resource| resource.id % 2 == 0)
            .build(),
    );

    let session = EvaluationSession::empty();
    let bound = checker.bind(&session, &Subject, &Action, &());
    let results = bound
        .evaluate(vec![
            Resource { id: 1 },
            Resource { id: 2 },
            Resource { id: 3 },
        ])
        .await;

    let decisions = results
        .iter()
        .map(|(resource, evaluation)| (resource.id, evaluation.is_granted()))
        .collect::<Vec<_>>();
    assert_eq!(decisions, vec![(1, false), (2, true), (3, false)]);

    let visible = bound
        .filter(vec![
            Resource { id: 1 },
            Resource { id: 2 },
            Resource { id: 3 },
        ])
        .await;
    assert_eq!(
        visible
            .iter()
            .map(|resource| resource.id)
            .collect::<Vec<_>>(),
        vec![2]
    );
}

#[tokio::test]
async fn delegating_policy_preserves_child_batch_evaluation() {
    let child_batch_calls = Arc::new(AtomicUsize::new(0));
    let child_single_calls = Arc::new(AtomicUsize::new(0));
    let child_seen = Arc::new(Mutex::new(Vec::new()));

    let mut child_checker = PermissionChecker::new();
    child_checker.add_policy(BatchGrantPolicy {
        name: "child-even",
        batch_calls: Arc::clone(&child_batch_calls),
        single_calls: Arc::clone(&child_single_calls),
        seen_batches: Arc::clone(&child_seen),
        grant: Arc::new(|resource_id| resource_id % 2 == 0),
    });

    let delegating_policy = DelegatingPolicy::new(
        "DelegatedRead",
        child_checker,
        |_subject: &Subject| Subject,
        |_action: &Action| Action,
        |_subject: &Subject, _action: &Action, resource: &Resource, _context: &Ctx| Resource {
            id: resource.id + 1,
        },
        |_subject: &Subject, _action: &Action, _context: &Ctx| Ctx,
    );

    let mut checker = PermissionChecker::new();
    checker.add_policy(delegating_policy);

    let session = EvaluationSession::empty();
    let results = evaluate_resources(
        &checker,
        &session,
        vec![Resource { id: 0 }, Resource { id: 1 }, Resource { id: 2 }],
    )
    .await;

    let decisions = results
        .iter()
        .map(|(resource, evaluation)| (resource.id, evaluation.is_granted()))
        .collect::<Vec<_>>();
    assert_eq!(decisions, vec![(0, false), (1, true), (2, false)]);
    assert_eq!(child_batch_calls.load(Ordering::SeqCst), 1);
    assert_eq!(child_single_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        *child_seen.lock().unwrap(),
        vec![vec![1, 2, 3]],
        "delegation should preserve one child batch call with mapped resources"
    );

    let delegated_node = match &results[1].1 {
        AccessEvaluation::Granted { trace, .. } => trace.root().unwrap(),
        AccessEvaluation::Denied { .. } => panic!("expected delegated decision to grant"),
        _ => panic!("expected delegated decision to grant"),
    };
    assert!(delegated_node.format(0).contains("DelegatedRead"));
    assert!(delegated_node.format(0).contains("child-even"));
}

#[tokio::test]
async fn or_batch_does_not_re_evaluate_items_granted_by_earlier_policy() {
    let first_seen = Arc::new(Mutex::new(Vec::new()));
    let second_seen = Arc::new(Mutex::new(Vec::new()));
    let first_batch_calls = Arc::new(AtomicUsize::new(0));
    let second_batch_calls = Arc::new(AtomicUsize::new(0));

    let mut checker = PermissionChecker::new();
    checker.add_policy(BatchGrantPolicy {
        name: "even",
        batch_calls: Arc::clone(&first_batch_calls),
        single_calls: Arc::new(AtomicUsize::new(0)),
        seen_batches: Arc::clone(&first_seen),
        grant: Arc::new(|resource_id| resource_id % 2 == 0),
    });
    checker.add_policy(BatchGrantPolicy {
        name: "all",
        batch_calls: Arc::clone(&second_batch_calls),
        single_calls: Arc::new(AtomicUsize::new(0)),
        seen_batches: Arc::clone(&second_seen),
        grant: Arc::new(|_| true),
    });

    let items = (0..6).map(|id| Resource { id }).collect::<Vec<_>>();
    let session = EvaluationSession::empty();
    let results = evaluate_resources(&checker, &session, items).await;

    assert!(results
        .iter()
        .all(|(_item, evaluation)| evaluation.is_granted()));
    assert_eq!(first_batch_calls.load(Ordering::SeqCst), 1);
    assert_eq!(second_batch_calls.load(Ordering::SeqCst), 1);
    assert_eq!(*first_seen.lock().unwrap(), vec![vec![0, 1, 2, 3, 4, 5]]);
    assert_eq!(*second_seen.lock().unwrap(), vec![vec![1, 3, 5]]);
}

#[tokio::test]
async fn boxed_dyn_policy_dispatches_evaluate_batch_override() {
    let batch_calls = Arc::new(AtomicUsize::new(0));
    let single_calls = Arc::new(AtomicUsize::new(0));
    let boxed: Box<dyn Policy<Domain>> = Box::new(BatchGrantPolicy {
        name: "boxed",
        batch_calls: Arc::clone(&batch_calls),
        single_calls: Arc::clone(&single_calls),
        seen_batches: Arc::new(Mutex::new(Vec::new())),
        grant: Arc::new(|resource_id| resource_id == 1),
    });
    let session = EvaluationSession::empty();
    let owned_items = [Resource { id: 1 }, Resource { id: 2 }];
    let batch_items = owned_items
        .iter()
        .map(|resource| PolicyBatchItem { resource })
        .collect::<Vec<_>>();

    let results = boxed
        .evaluate_batch(&BatchEvalCtx {
            session: &session,
            subject: &Subject,
            action: &Action,
            context: &Ctx,
            items: &batch_items,
            policy_type: boxed.policy_type(),
        })
        .await;

    assert_eq!(results.len(), 2);
    assert!(results[0].is_granted());
    assert!(!results[1].is_granted());
    assert_eq!(batch_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        single_calls.load(Ordering::SeqCst),
        0,
        "boxed dyn Policy must forward evaluate_batch instead of using the default point loop"
    );
}

#[tokio::test]
async fn batch_decisions_match_naive_loop_for_simple_policy_stack() {
    let mut checker = PermissionChecker::new();
    checker.add_policy(BatchGrantPolicy {
        name: "divisible_by_three",
        batch_calls: Arc::new(AtomicUsize::new(0)),
        single_calls: Arc::new(AtomicUsize::new(0)),
        seen_batches: Arc::new(Mutex::new(Vec::new())),
        grant: Arc::new(|resource_id| resource_id % 3 == 0),
    });
    checker.add_policy(BatchGrantPolicy {
        name: "greater_than_four",
        batch_calls: Arc::new(AtomicUsize::new(0)),
        single_calls: Arc::new(AtomicUsize::new(0)),
        seen_batches: Arc::new(Mutex::new(Vec::new())),
        grant: Arc::new(|resource_id| resource_id > 4),
    });

    let items = (0..10).map(|id| Resource { id }).collect::<Vec<_>>();
    let session = EvaluationSession::empty();
    let batch = evaluate_resources(&checker, &session, items.clone())
        .await
        .into_iter()
        .map(|(_item, evaluation)| evaluation.is_granted())
        .collect::<Vec<_>>();

    let mut naive = Vec::new();
    for resource in &items {
        let session = EvaluationSession::empty();
        naive.push(
            check_resource(&checker, &session, resource)
                .await
                .is_granted(),
        );
    }

    assert_eq!(batch, naive);
}

fn assert_granted(evaluation: &AccessEvaluation, expected: bool) {
    assert_eq!(evaluation.is_granted(), expected);
}

#[tokio::test]
async fn batch_decisions_match_naive_loop_for_empty_and_mixed_items() {
    let mut checker = PermissionChecker::new();
    checker.add_policy(BatchGrantPolicy {
        name: "odd",
        batch_calls: Arc::new(AtomicUsize::new(0)),
        single_calls: Arc::new(AtomicUsize::new(0)),
        seen_batches: Arc::new(Mutex::new(Vec::new())),
        grant: Arc::new(|resource_id| resource_id % 2 == 1),
    });

    let session = EvaluationSession::empty();
    let empty = evaluate_resources(&checker, &session, Vec::<Resource>::new()).await;
    assert!(empty.is_empty());

    let items = vec![Resource { id: 1 }, Resource { id: 2 }];
    let batch = evaluate_resources(&checker, &session, items).await;
    assert_granted(&batch[0].1, true);
    assert_granted(&batch[1].1, false);
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1_000,
        ..ProptestConfig::default()
    })]

    #[test]
    fn checker_paths_match_deny_overrides_oracle(
        policy_specs in adversarial_policy_stack_strategy(),
        resource_ids in prop::collection::vec(0u8..64, 0..50),
        max_batch_size in prop::option::of(1usize..8),
    ) {
        let items = resource_ids
            .iter()
            .copied()
            .map(|id| Resource { id })
            .collect::<Vec<_>>();
        let expected = resource_ids
            .iter()
            .map(|id| oracle_decision(&policy_specs, *id))
            .collect::<Vec<_>>();

        let unchunked = checker_from_specs(&policy_specs, None);
        let unchunked_session = EvaluationSession::empty();
        let unchunked_batch = tokio_test::block_on(evaluate_resources(
            &unchunked,
            &unchunked_session,
            items.clone(),
        ))
        .into_iter()
        .map(|(_item, evaluation)| access_decision(&evaluation))
        .collect::<Vec<_>>();
        prop_assert_eq!(&unchunked_batch, &expected);

        let chunk_one = checker_from_specs(&policy_specs, Some(1));
        let chunk_one_session = EvaluationSession::empty();
        let chunk_one_batch = tokio_test::block_on(evaluate_resources(
            &chunk_one,
            &chunk_one_session,
            items.clone(),
        ))
        .into_iter()
        .map(|(_item, evaluation)| access_decision(&evaluation))
        .collect::<Vec<_>>();
        prop_assert_eq!(&chunk_one_batch, &expected);

        if let Some(max_batch_size) = max_batch_size {
            let chunked = checker_from_specs(&policy_specs, Some(max_batch_size));
            let chunked_session = EvaluationSession::empty();
            let chunked_batch = tokio_test::block_on(evaluate_resources(
                &chunked,
                &chunked_session,
                items.clone(),
            ))
            .into_iter()
            .map(|(_item, evaluation)| access_decision(&evaluation))
            .collect::<Vec<_>>();
            prop_assert_eq!(&chunked_batch, &expected);
        }

        let mut repeated_single = Vec::new();
        for resource in &items {
            let session = EvaluationSession::empty();
            let evaluation = tokio_test::block_on(check_resource(&unchunked, &session, resource));
            repeated_single.push(access_decision(&evaluation));
        }
        prop_assert_eq!(repeated_single, expected);
    }

    #[test]
    fn singleton_filter_matches_single_resource_check_for_random_policy_stacks(
        policy_specs in adversarial_policy_stack_strategy(),
        resource_id in 0u8..64,
        max_batch_size in prop::option::of(1usize..8),
    ) {
        let checker = checker_from_specs(&policy_specs, max_batch_size);

        let resource = Resource { id: resource_id };
        let single_session = EvaluationSession::empty();
        let single = tokio_test::block_on(check_resource(&checker, &single_session, &resource));
        let expected = oracle_decision(&policy_specs, resource_id);
        prop_assert_eq!(access_decision(&single), expected);

        let filter_session = EvaluationSession::empty();
        let filtered = tokio_test::block_on(filter_resources(&checker, &filter_session, vec![resource]));

        prop_assert_eq!(single.is_granted(), expected == ExpectedDecision::Granted);
        prop_assert_eq!(!filtered.is_empty(), expected == ExpectedDecision::Granted);
    }

    #[test]
    fn checker_decision_is_registration_order_invariant(
        policy_specs in adversarial_policy_stack_strategy(),
        resource_id in 0u8..64,
        rotation in 0usize..8,
        reverse in any::<bool>(),
    ) {
        let mut permuted = policy_specs.clone();
        let len = permuted.len();
        permuted.rotate_left(rotation % len);
        if reverse {
            permuted.reverse();
        }

        let checker = checker_from_specs(&policy_specs, None);
        let permuted_checker = checker_from_specs(&permuted, None);
        let resource = Resource { id: resource_id };

        let session = EvaluationSession::empty();
        let decision = tokio_test::block_on(check_resource(&checker, &session, &resource));
        let permuted_session = EvaluationSession::empty();
        let permuted_decision =
            tokio_test::block_on(check_resource(&permuted_checker, &permuted_session, &resource));

        let expected = oracle_decision(&policy_specs, resource_id);
        prop_assert_eq!(oracle_decision(&permuted, resource_id), expected);
        prop_assert_eq!(access_decision(&decision), expected);
        prop_assert_eq!(access_decision(&permuted_decision), expected);
    }

    #[test]
    fn combinator_single_and_batch_paths_agree(
        policy_specs in adversarial_policy_stack_strategy(),
        resource_id in 0u8..64,
        combinator in 0u8..3,
    ) {
        let policy: Box<dyn Policy<Domain>> = match combinator {
            0 => Box::new(AndPolicy::try_new(arc_policies_from_specs(&policy_specs)).unwrap()),
            1 => Box::new(OrPolicy::try_new(arc_policies_from_specs(&policy_specs)).unwrap()),
            _ => Box::new(NotPolicy::new(policy_specs[0].into_policy(0))),
        };

        let session = EvaluationSession::empty();
        let resource = Resource { id: resource_id };
        let single = tokio_test::block_on(policy.evaluate(&EvalCtx {
            session: &session,
            subject: &Subject,
            action: &Action,
            resource: &resource,
            context: &Ctx,
            policy_type: policy.policy_type(),
        }));

        let items = [PolicyBatchItem { resource: &resource }];
        let batch = tokio_test::block_on(policy.evaluate_batch(&BatchEvalCtx {
            session: &session,
            subject: &Subject,
            action: &Action,
            context: &Ctx,
            items: &items,
            policy_type: policy.policy_type(),
        }));

        prop_assert_eq!(batch.len(), 1);
        prop_assert_eq!(policy_decision(&single), policy_decision(&batch[0]));
    }
}

#[derive(Clone)]
struct MixedSubject {
    id: u8,
}

#[derive(Clone)]
struct MixedResource {
    id: u8,
    public: bool,
}

struct MixedAction;
struct MixedCtx;

struct MixedDomain;

impl PolicyDomain for MixedDomain {
    type Subject = MixedSubject;
    type Action = MixedAction;
    type Resource = MixedResource;
    type Context = MixedCtx;
}

type MixedRelationshipQuery = RelationshipQuery<u8, u8, &'static str>;
type MixedRelationshipCalls = Arc<Mutex<Vec<Vec<MixedRelationshipQuery>>>>;

struct MixedRelationshipSource {
    grants: HashSet<MixedRelationshipQuery>,
    calls: MixedRelationshipCalls,
}

#[async_trait]
impl FactSource<MixedRelationshipQuery> for MixedRelationshipSource {
    async fn load_many(&self, keys: &[MixedRelationshipQuery]) -> Vec<FactLoadResult<bool>> {
        self.calls.lock().unwrap().push(keys.to_vec());
        keys.iter()
            .map(|key| FactLoadResult::Found(self.grants.contains(key)))
            .collect()
    }
}

#[tokio::test]
async fn mixed_policy_stack_uses_in_memory_policy_and_rebac_session() {
    let subject = MixedSubject { id: 7 };
    let calls = Arc::new(Mutex::new(Vec::new()));
    let session = gatehouse::FactRegistry::builder()
        .with::<RelationshipQuery<u8, u8, &'static str>, _>(MixedRelationshipSource {
            grants: HashSet::from([RelationshipQuery {
                subject_id: subject.id,
                resource_id: 2,
                relation: "viewer",
            }]),
            calls: Arc::clone(&calls),
        })
        .build()
        .session();

    let mut checker = PermissionChecker::<MixedDomain>::new();
    checker.add_policy(
        PolicyBuilder::<MixedDomain>::new("PublicResource")
            .resources(|resource| resource.public)
            .build(),
    );
    checker.add_policy(RebacPolicy::<MixedDomain, u8, u8, &'static str>::new(
        |subject: &MixedSubject| subject.id,
        |resource: &MixedResource| resource.id,
        "viewer",
    ));

    let items = vec![
        MixedResource {
            id: 1,
            public: true,
        },
        MixedResource {
            id: 2,
            public: false,
        },
        MixedResource {
            id: 3,
            public: false,
        },
    ];
    let results = checker
        .bind(&session, &subject, &MixedAction, &MixedCtx)
        .evaluate(items)
        .await;

    assert_granted(&results[0].1, true);
    assert_granted(&results[1].1, true);
    assert_granted(&results[2].1, false);
    assert_eq!(
        *calls.lock().unwrap(),
        vec![vec![
            RelationshipQuery {
                subject_id: subject.id,
                resource_id: 2,
                relation: "viewer",
            },
            RelationshipQuery {
                subject_id: subject.id,
                resource_id: 3,
                relation: "viewer",
            },
        ]]
    );
}

// ---- deny-overrides semantics -------------------------------------

fn allow_everything(name: &str) -> Box<dyn Policy<Domain>> {
    PolicyBuilder::<Domain>::new(name.to_string()).build()
}

fn forbid_odd_resources(name: &str) -> Box<dyn Policy<Domain>> {
    PolicyBuilder::<Domain>::new(name.to_string())
        .resources(|resource: &Resource| resource.id % 2 == 1)
        .forbid()
        .build()
}

fn grant_even_resources(name: &str) -> impl Policy<Domain> {
    PolicyBuilder::<Domain>::new(name.to_string())
        .resources(|resource: &Resource| resource.id % 2 == 0)
        .build()
}

struct NamedNoopPolicy {
    name: &'static str,
}

#[async_trait]
impl Policy<Domain> for NamedNoopPolicy {
    async fn evaluate(&self, ctx: &EvalCtx<'_, Domain>) -> PolicyEvalResult {
        ctx.not_applicable("not applicable")
    }

    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed(self.name)
    }
}

#[derive(Debug, Clone)]
struct WideRow {
    row_id: &'static str,
    authz_resource: Resource,
}

struct StaticLookup {
    ids: Vec<u8>,
    next_cursor: Option<Vec<u8>>,
}

#[async_trait]
impl LookupSource<Domain> for StaticLookup {
    type Id = u8;
    type Error = Infallible;

    async fn lookup_page(
        &self,
        _subject: &Subject,
        _action: &Action,
        _context: &Ctx,
        _cursor: Option<&[u8]>,
        _limit: NonZeroUsize,
    ) -> Result<LookupPage<Self::Id>, Self::Error> {
        Ok(LookupPage {
            ids: self.ids.clone(),
            next_cursor: self.next_cursor.clone(),
        })
    }
}

struct ResourceHydrator;

#[async_trait]
impl Hydrator<u8> for ResourceHydrator {
    type Resource = Resource;
    type Error = Infallible;

    async fn hydrate(&self, ids: &[u8]) -> Result<Vec<Option<Self::Resource>>, Self::Error> {
        Ok(ids.iter().map(|id| Some(Resource { id: *id })).collect())
    }
}

#[tokio::test]
async fn checker_clone_preserves_name_batching_and_policies() {
    let mut checker =
        PermissionChecker::named("NamedChecker").with_max_batch_size(NonZeroUsize::new(1).unwrap());
    checker.add_policy(grant_even_resources("EvenResource"));

    assert_eq!(checker.name(), Some("NamedChecker"));

    let cloned = checker.clone();
    assert_eq!(cloned.name(), Some("NamedChecker"));

    let session = EvaluationSession::empty();
    let results = evaluate_resources(
        &cloned,
        &session,
        vec![Resource { id: 1 }, Resource { id: 2 }],
    )
    .await;

    assert_eq!(
        results
            .iter()
            .map(|(resource, evaluation)| (resource.id, evaluation.is_granted()))
            .collect::<Vec<_>>(),
        vec![(1, false), (2, true)]
    );
}

#[tokio::test]
async fn add_forbid_policy_declares_and_stably_orders_veto_capable_policies() {
    let session = EvaluationSession::empty();

    let mut veto_checker = PermissionChecker::new();
    veto_checker.add_policy(allow_everything("AllowAll"));
    veto_checker.add_forbid_policy(UndeclaredForbidPolicy);

    let blocked = check_resource(&veto_checker, &session, &Resource { id: 0 }).await;
    blocked.assert_forbidden_by("UndeclaredForbidPolicy");

    let mut order_checker = PermissionChecker::new();
    order_checker.add_forbid_policy(NamedNoopPolicy {
        name: "FirstVetoSlot",
    });
    order_checker.add_forbid_policy(NamedNoopPolicy {
        name: "SecondVetoSlot",
    });
    order_checker.add_policy(allow_everything("AllowAll"));

    let granted = check_resource(&order_checker, &session, &Resource { id: 0 }).await;
    granted.assert_granted_by("AllowAll");
    let trace = granted.trace().format();
    let first = trace.find("FirstVetoSlot").unwrap();
    let second = trace.find("SecondVetoSlot").unwrap();
    let allow = trace.find("AllowAll").unwrap();
    assert!(
        first < second && second < allow,
        "veto-capable insertion should preserve registration order before allow-only policies:\n{trace}"
    );
}

#[tokio::test]
async fn projected_row_helpers_evaluate_and_filter_original_items() {
    let mut checker = PermissionChecker::new();
    checker.add_policy(grant_even_resources("EvenResource"));
    let session = EvaluationSession::empty();
    let rows = vec![
        WideRow {
            row_id: "one",
            authz_resource: Resource { id: 1 },
        },
        WideRow {
            row_id: "two",
            authz_resource: Resource { id: 2 },
        },
        WideRow {
            row_id: "four",
            authz_resource: Resource { id: 4 },
        },
    ];

    let bound = bind(&checker, &session);
    let decisions = bound
        .evaluate_by(rows.clone(), |row| &row.authz_resource)
        .await;
    assert_eq!(
        decisions
            .iter()
            .map(|(row, evaluation)| (row.row_id, evaluation.is_granted()))
            .collect::<Vec<_>>(),
        vec![("one", false), ("two", true), ("four", true)]
    );

    let authorized = bound.filter_by(rows, |row| &row.authz_resource).await;
    assert_eq!(
        authorized.iter().map(|row| row.row_id).collect::<Vec<_>>(),
        vec!["two", "four"]
    );
}

#[tokio::test]
async fn lookup_page_accepts_exhausted_initial_page_and_rejects_stuck_cursor() {
    let mut checker = PermissionChecker::new();
    checker.add_policy(allow_everything("AllowAll"));
    let session = EvaluationSession::empty();
    let bound = bind(&checker, &session);
    let page_size = NonZeroUsize::new(10).unwrap();

    let exhausted = StaticLookup {
        ids: Vec::new(),
        next_cursor: None,
    };
    let empty_page = bound
        .lookup_page(&exhausted, &ResourceHydrator, None, page_size)
        .await
        .unwrap();
    assert!(empty_page.resources.is_empty());
    assert_eq!(empty_page.next_cursor, None);

    let cursor = b"same".to_vec();
    let stuck = StaticLookup {
        ids: vec![1],
        next_cursor: Some(cursor.clone()),
    };
    let err = bound
        .lookup_page(&stuck, &ResourceHydrator, Some(&cursor), page_size)
        .await
        .unwrap_err();
    assert!(matches!(err, LookupAuthorizedError::LookupCursorStuck));
}

struct MixedGrantPolicy;

#[async_trait]
impl Policy<Domain> for MixedGrantPolicy {
    async fn evaluate(&self, ctx: &EvalCtx<'_, Domain>) -> PolicyEvalResult {
        ctx.grant("granted")
    }

    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("MixedGrantPolicy")
    }

    fn effect(&self) -> Effect {
        Effect::AllowOrForbid
    }
}

struct MixedNotApplicablePolicy;

#[async_trait]
impl Policy<Domain> for MixedNotApplicablePolicy {
    async fn evaluate(&self, ctx: &EvalCtx<'_, Domain>) -> PolicyEvalResult {
        ctx.not_applicable("n/a")
    }

    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("MixedNotApplicablePolicy")
    }

    fn effect(&self) -> Effect {
        Effect::AllowOrForbid
    }
}

#[tokio::test]
async fn single_check_flushes_grant_after_veto_capable_prefix() {
    let mut checker = PermissionChecker::new();
    checker.add_policy(MixedGrantPolicy);
    checker.add_policy(MixedNotApplicablePolicy);

    let session = EvaluationSession::empty();
    let resource = Resource { id: 0 };

    let single = check_resource(&checker, &session, &resource).await;
    single.assert_granted_by("MixedGrantPolicy");

    let filtered = filter_resources(&checker, &session, vec![resource]).await;
    assert_eq!(filtered.len(), 1);
}

#[tokio::test]
async fn batch_forbid_overrides_grants_regardless_of_registration_order() {
    // The forbid policy is registered *after* the allow policy; forbid-first
    // scheduling must still veto before the allow phase grants.
    let mut checker = PermissionChecker::new();
    checker.add_policy(allow_everything("AllowAll"));
    checker.add_policy(forbid_odd_resources("OddBlock"));

    let session = EvaluationSession::empty();
    let items = (0..4).map(|id| Resource { id }).collect::<Vec<_>>();
    let results = evaluate_resources(&checker, &session, items).await;

    let decisions = results
        .iter()
        .map(|(resource, evaluation)| {
            (
                resource.id,
                evaluation.is_granted(),
                evaluation.forbidden_by().map(str::to_owned),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        decisions,
        vec![
            (0, true, None),
            (1, false, Some("OddBlock".to_string())),
            (2, true, None),
            (3, false, Some("OddBlock".to_string())),
        ]
    );

    // The filter convenience (and therefore the lookup pipeline built on
    // it) honors the forbid identically.
    let visible = filter_resources(
        &checker,
        &session,
        (0..4).map(|id| Resource { id }).collect::<Vec<_>>(),
    )
    .await;
    assert_eq!(
        visible
            .iter()
            .map(|resource| resource.id)
            .collect::<Vec<_>>(),
        vec![0, 2]
    );
}

#[tokio::test]
async fn single_and_batch_forbid_decisions_agree() {
    let mut checker = PermissionChecker::new();
    checker.add_policy(allow_everything("AllowAll"));
    checker.add_policy(forbid_odd_resources("OddBlock"));

    let session = EvaluationSession::empty();
    for id in 0..4 {
        let single = check_resource(&checker, &session, &Resource { id }).await;
        let batch = evaluate_resources(&checker, &session, vec![Resource { id }])
            .await
            .remove(0)
            .1;
        assert_eq!(single.is_granted(), batch.is_granted(), "id {id}");
        assert_eq!(single.forbidden_by(), batch.forbidden_by(), "id {id}");
    }
}

/// Forbids propagate through combinators so a fluent wrapper cannot silently
/// drop a veto.
#[tokio::test]
async fn forbid_inside_combinators_vetoes_access() {
    let session = EvaluationSession::empty();
    let blocked = Resource { id: 1 };

    // OR: the nested forbid overrides the allow arm.
    let or_gate = OrPolicy::try_new(vec![
        Arc::from(allow_everything("AllowAll")),
        Arc::from(forbid_odd_resources("OddBlock")),
    ])
    .unwrap();
    let mut or_checker = PermissionChecker::new();
    or_checker.add_policy(or_gate);
    let or_result = check_resource(&or_checker, &session, &blocked).await;
    or_result.assert_forbidden_by("OddBlock");

    // AND: the conjunction fails because the child actively vetoes.
    let and_gate = AndPolicy::try_new(vec![
        Arc::from(allow_everything("AllowAll")),
        Arc::from(forbid_odd_resources("OddBlock")),
    ])
    .unwrap();
    let mut and_checker = PermissionChecker::new();
    and_checker.add_policy(and_gate);
    let and_result = check_resource(&and_checker, &session, &blocked).await;
    and_result.assert_forbidden_by("OddBlock");

    // NOT still grants for a non-matching forbid child, but an active forbid
    // is not inverted into a grant.
    let mut not_checker = PermissionChecker::new();
    not_checker.add_policy(NotPolicy::new(forbid_odd_resources("OddBlock")));
    let not_result = check_resource(&not_checker, &session, &Resource { id: 0 }).await;
    assert!(
        not_result.is_granted(),
        "NOT(non-matching deny) is granted, as for any non-granting child"
    );
    let not_blocked = check_resource(&not_checker, &session, &blocked).await;
    not_blocked.assert_forbidden_by("OddBlock");
}

#[tokio::test]
async fn combinator_effects_preserve_nested_forbid_capability_for_checker_scheduling() {
    let allow_only_or = OrPolicy::try_new(vec![
        Arc::from(allow_everything("AllowA")),
        Arc::from(allow_everything("AllowB")),
    ])
    .unwrap();
    assert_eq!(allow_only_or.effect(), Effect::Allow);

    let allow_or_forbid = OrPolicy::try_new(vec![
        Arc::from(allow_everything("NestedAllow")),
        Arc::from(forbid_odd_resources("NestedBlock")),
    ])
    .unwrap();
    assert_eq!(allow_or_forbid.effect(), Effect::AllowOrForbid);

    let forbid_only_and = AndPolicy::try_new(vec![
        Arc::from(allow_everything("RequiredAllow")),
        Arc::from(forbid_odd_resources("RequiredBlock")),
    ])
    .unwrap();
    assert_eq!(forbid_only_and.effect(), Effect::Forbid);

    let mut checker = PermissionChecker::new();
    checker.add_policy(allow_everything("ParentAllow"));
    checker.add_policy(allow_or_forbid);

    let session = EvaluationSession::empty();
    let blocked = check_resource(&checker, &session, &Resource { id: 1 }).await;
    blocked.assert_forbidden_by("NestedBlock");
}

#[tokio::test]
async fn and_policy_requires_each_child_to_grant_across_veto_boundary() {
    let session = EvaluationSession::empty();

    let grant_then_required_non_grant = AndPolicy::try_new(vec![
        Arc::new(MixedGrantPolicy) as Arc<dyn Policy<Domain>>,
        Arc::new(NamedNoopPolicy {
            name: "RequiredAllow",
        }) as Arc<dyn Policy<Domain>>,
    ])
    .unwrap();
    let mut checker = PermissionChecker::new();
    checker.add_policy(grant_then_required_non_grant);
    let denied = check_resource(&checker, &session, &Resource { id: 0 }).await;
    assert!(!denied.is_granted());
    assert!(denied.trace().format().contains("RequiredAllow"));
    let batch = evaluate_resources(&checker, &session, vec![Resource { id: 0 }]).await;
    assert!(!batch[0].1.is_granted());

    let forbid_only_non_match_then_grant = AndPolicy::try_new(vec![
        Arc::from(forbid_odd_resources("OddBlock")),
        Arc::from(allow_everything("AllowAll")),
    ])
    .unwrap();
    let mut checker = PermissionChecker::new();
    checker.add_policy(forbid_only_non_match_then_grant);
    let denied = check_resource(&checker, &session, &Resource { id: 0 }).await;
    assert!(
        !denied.is_granted(),
        "a forbid-only child that does not match still does not satisfy AND"
    );
    let batch = evaluate_resources(&checker, &session, vec![Resource { id: 0 }]).await;
    assert!(!batch[0].1.is_granted());
}

#[tokio::test]
async fn or_policy_grants_from_first_allow_only_child_after_veto_boundary() {
    let session = EvaluationSession::empty();
    let or_gate = OrPolicy::try_new(vec![
        Arc::new(MixedNotApplicablePolicy) as Arc<dyn Policy<Domain>>,
        Arc::from(allow_everything("AllowAll")),
    ])
    .unwrap();
    let mut checker = PermissionChecker::new();
    checker.add_policy(or_gate);

    let granted = check_resource(&checker, &session, &Resource { id: 0 }).await;
    granted.assert_granted_by("OrPolicy");
    assert!(granted.trace().format().contains("AllowAll"));

    let batch = evaluate_resources(&checker, &session, vec![Resource { id: 0 }]).await;
    assert!(batch[0].1.is_granted());
    assert!(batch[0].1.trace().format().contains("AllowAll"));
}

/// Identity-mapped delegating policy whose child checker grants everything
/// except odd resource ids, which it forbids.
fn delegating_forbid_policy() -> DelegatingPolicy<Domain, Domain> {
    let mut child: PermissionChecker<Domain> = PermissionChecker::new();
    child.add_policy(allow_everything("ChildAllow"));
    child.add_policy(forbid_odd_resources("ChildBlock"));
    DelegatingPolicy::new(
        "DelegatedDecision",
        child,
        |_subject: &Subject| Subject,
        |_action: &Action| Action,
        |_subject: &Subject, _action: &Action, resource: &Resource, _ctx: &Ctx| Resource {
            id: resource.id,
        },
        |_subject: &Subject, _action: &Action, _ctx: &Ctx| Ctx,
    )
}

/// A forbid inside a delegated child checker propagates to the parent checker:
/// delegation must not silently downgrade a child veto into an ordinary
/// non-grant.
#[tokio::test]
async fn delegated_child_forbid_propagates_to_parent_checker() {
    let session = EvaluationSession::empty();
    for delegate_registered_first in [true, false] {
        let mut parent = PermissionChecker::new();
        if delegate_registered_first {
            parent.add_policy(delegating_forbid_policy());
            parent.add_policy(allow_everything("ParentAllow"));
        } else {
            parent.add_policy(allow_everything("ParentAllow"));
            parent.add_policy(delegating_forbid_policy());
        }

        let result = check_resource(&parent, &session, &Resource { id: 1 }).await;

        result.assert_forbidden_by("ChildBlock");
    }

    // Without the parent grant, the delegated veto is still reported as the
    // cause of denial.
    let mut parent_without_allow = PermissionChecker::new();
    parent_without_allow.add_policy(delegating_forbid_policy());
    let denied = check_resource(&parent_without_allow, &session, &Resource { id: 1 }).await;
    denied.assert_forbidden_by("ChildBlock");
}

/// A hand-written policy that declares `Effect::Forbid` and forbids via
/// `ctx.forbid` is honored on both evaluation paths.
struct SuspendedSubjectPolicy;

#[async_trait]
impl Policy<Domain> for SuspendedSubjectPolicy {
    async fn evaluate(&self, ctx: &EvalCtx<'_, Domain>) -> PolicyEvalResult {
        if ctx.resource.id == 1 {
            ctx.forbid("resource 1 is frozen")
        } else {
            ctx.not_applicable("not applicable")
        }
    }

    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("SuspendedSubjectPolicy")
    }

    fn effect(&self) -> Effect {
        Effect::Forbid
    }
}

#[tokio::test]
async fn custom_policy_forbid_via_ctx_forbid_is_honored() {
    let mut checker = PermissionChecker::new();
    checker.add_policy(allow_everything("AllowAll"));
    checker.add_policy(SuspendedSubjectPolicy);

    let session = EvaluationSession::empty();
    let blocked = check_resource(&checker, &session, &Resource { id: 1 }).await;
    blocked.assert_forbidden_by("SuspendedSubjectPolicy");

    let granted = check_resource(&checker, &session, &Resource { id: 0 }).await;
    granted.assert_granted_by("AllowAll");

    // Default evaluate_batch forwards to evaluate, so the batch path
    // observes the same forbids.
    let results = evaluate_resources(
        &checker,
        &session,
        vec![Resource { id: 0 }, Resource { id: 1 }],
    )
    .await;
    assert!(results[0].1.is_granted());
    assert_eq!(results[1].1.forbidden_by(), Some("SuspendedSubjectPolicy"));
}

/// Contract violation: a policy declaring `Effect::Forbid` must not grant.
/// The checker fails closed, treating the grant as not applicable.
struct MisbehavingForbidPolicy;

#[async_trait]
impl Policy<Domain> for MisbehavingForbidPolicy {
    async fn evaluate(&self, ctx: &EvalCtx<'_, Domain>) -> PolicyEvalResult {
        ctx.grant("grant from a forbid-effect policy")
    }

    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("MisbehavingForbidPolicy")
    }

    fn effect(&self) -> Effect {
        Effect::Forbid
    }
}

#[tokio::test]
async fn grant_from_forbid_declared_policy_is_treated_as_not_applicable() {
    // Alone in a checker, the misbehaving grant must not grant access.
    let mut checker = PermissionChecker::new();
    checker.add_policy(MisbehavingForbidPolicy);
    let session = EvaluationSession::empty();
    let alone = check_resource(&checker, &session, &Resource { id: 0 }).await;
    assert!(!alone.is_granted());
    assert_eq!(alone.forbidden_by(), None);

    // Alongside a real allow policy, the sibling grant still decides.
    checker.add_policy(allow_everything("AllowAll"));
    let with_allow = check_resource(&checker, &session, &Resource { id: 0 }).await;
    with_allow.assert_granted_by("AllowAll");

    // Same fail-closed handling on the batch path.
    let batch = evaluate_resources(&checker, &session, vec![Resource { id: 0 }]).await;
    assert!(batch[0].1.is_granted());
}

/// An *undeclared* forbid (default `Effect::Allow`) is honored when the
/// checker observes it, but a sibling grant evaluated earlier can
/// short-circuit before it is reached — declaring `Effect::Forbid` is what
/// makes a veto order-independent.
struct UndeclaredForbidPolicy;

#[async_trait]
impl Policy<Domain> for UndeclaredForbidPolicy {
    async fn evaluate(&self, ctx: &EvalCtx<'_, Domain>) -> PolicyEvalResult {
        ctx.forbid("forbid without declaring Effect::Forbid")
    }

    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("UndeclaredForbidPolicy")
    }
}

#[tokio::test]
async fn undeclared_forbid_is_honored_when_observed_but_not_scheduled_first() {
    let session = EvaluationSession::empty();

    // Observed before any grant: honored.
    let mut forbid_first = PermissionChecker::new();
    forbid_first.add_policy(UndeclaredForbidPolicy);
    forbid_first.add_policy(allow_everything("AllowAll"));
    let blocked = check_resource(&forbid_first, &session, &Resource { id: 0 }).await;
    blocked.assert_forbidden_by("UndeclaredForbidPolicy");

    // Grant short-circuits first: the undeclared forbid is never reached.
    // This pins the documented contract that forbidding policies must
    // declare Effect::Forbid to veto deterministically.
    let mut grant_first = PermissionChecker::new();
    grant_first.add_policy(allow_everything("AllowAll"));
    grant_first.add_policy(UndeclaredForbidPolicy);
    let granted = check_resource(&grant_first, &session, &Resource { id: 0 }).await;
    granted.assert_granted_by("AllowAll");
}

/// A forbid-effect policy whose batch override returns the wrong number of
/// results fails closed: affected items are denied, not granted by the
/// allow phase.
struct WrongLengthForbidPolicy;

#[async_trait]
impl Policy<Domain> for WrongLengthForbidPolicy {
    async fn evaluate(&self, ctx: &EvalCtx<'_, Domain>) -> PolicyEvalResult {
        ctx.not_applicable("not applicable")
    }

    async fn evaluate_batch<'item>(
        &self,
        _ctx: &BatchEvalCtx<'item, Domain>,
    ) -> Vec<PolicyEvalResult> {
        Vec::new()
    }

    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("WrongLengthForbidPolicy")
    }

    fn effect(&self) -> Effect {
        Effect::Forbid
    }
}

#[tokio::test]
async fn wrong_length_batch_from_forbid_policy_fails_closed() {
    let mut checker = PermissionChecker::new();
    checker.add_policy(allow_everything("AllowAll"));
    checker.add_policy(WrongLengthForbidPolicy);

    let session = EvaluationSession::empty();
    let results = evaluate_resources(
        &checker,
        &session,
        vec![Resource { id: 0 }, Resource { id: 1 }],
    )
    .await;

    for (_item, evaluation) in &results {
        assert!(
            !evaluation.is_granted(),
            "items touched by a broken forbid policy must fail closed"
        );
    }
}
