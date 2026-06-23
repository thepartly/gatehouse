use async_trait::async_trait;
use gatehouse::{
    AccessEvaluation, AndPolicy, BatchEvalCtx, DelegatingPolicy, Effect, EvalCtx,
    EvaluationSession, FactLoadResult, FactSource, NotPolicy, OrPolicy, PermissionChecker, Policy,
    PolicyBatchItem, PolicyBuilder, PolicyDomain, PolicyEvalResult, RebacPolicy, RelationshipQuery,
};
use proptest::prelude::*;
use std::collections::HashSet;
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
    grant_percent: u8,
    forbid_percent: u8,
    salt: u16,
    effect: Effect,
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
        self.effect
    }
}

impl RandomStackPolicy {
    fn result_for(&self, resource_id: u8) -> PolicyEvalResult {
        let grant_score = ((resource_id as u16 * 37) ^ self.salt).wrapping_add(self.salt / 3) % 100;
        let forbid_score =
            ((resource_id as u16 * 53) ^ self.salt).wrapping_add(self.salt / 5) % 100;
        let grant_matched = grant_score < self.grant_percent as u16;
        let forbid_matched = forbid_score < self.forbid_percent as u16;

        if self.effect == Effect::Forbid {
            if forbid_matched {
                PolicyEvalResult::forbidden(self.name.clone(), format!("{resource_id} forbidden"))
            } else {
                PolicyEvalResult::not_applicable(self.name.clone(), format!("{resource_id} denied"))
            }
        } else if self.effect == Effect::AllowOrForbid && forbid_matched {
            PolicyEvalResult::forbidden(self.name.clone(), format!("{resource_id} forbidden"))
        } else if grant_matched {
            PolicyEvalResult::granted(self.name.clone(), Some(format!("{resource_id} granted")))
        } else {
            PolicyEvalResult::not_applicable(self.name.clone(), format!("{resource_id} denied"))
        }
    }
}

fn effect_from_tag(tag: u8) -> Effect {
    match tag % 3 {
        0 => Effect::Allow,
        1 => Effect::Forbid,
        _ => Effect::AllowOrForbid,
    }
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
    fn batch_decisions_match_naive_loop_for_random_policy_stacks(
        policy_specs in prop::collection::vec((0u8..=100, 0u8..=100, any::<u16>(), 0u8..3), 1..=5),
        resource_ids in prop::collection::vec(0u8..64, 0..50),
        max_batch_size in prop::option::of(1usize..8),
    ) {
        let mut checker = if let Some(max_batch_size) = max_batch_size {
            PermissionChecker::new().with_max_batch_size(NonZeroUsize::new(max_batch_size).unwrap())
        } else {
            PermissionChecker::new()
        };
        for (index, (grant_percent, forbid_percent, salt, effect_tag)) in policy_specs.into_iter().enumerate() {
            checker.add_policy(RandomStackPolicy {
                name: format!("random_{index}"),
                grant_percent,
                forbid_percent,
                salt,
                effect: effect_from_tag(effect_tag),
            });
        }

        let items = resource_ids
            .iter()
            .copied()
            .map(|id| Resource { id })
            .collect::<Vec<_>>();
        let batch_session = EvaluationSession::empty();
        let batch = tokio_test::block_on(evaluate_resources(&checker, &batch_session, items.clone()))
        .into_iter()
        .map(|(_item, evaluation)| {
            (
                evaluation.is_granted(),
                evaluation.forbidden_by().map(str::to_owned),
            )
        })
        .collect::<Vec<_>>();

        let mut naive = Vec::new();
        for resource in &items {
            let session = EvaluationSession::empty();
            let evaluation = tokio_test::block_on(check_resource(&checker, &session, resource));
            naive.push((
                evaluation.is_granted(),
                evaluation.forbidden_by().map(str::to_owned),
            ));
        }

        prop_assert_eq!(batch, naive);
    }

    #[test]
    fn singleton_filter_matches_single_resource_check_for_random_policy_stacks(
        policy_specs in prop::collection::vec((0u8..=100, 0u8..=100, any::<u16>(), 0u8..3), 1..=5),
        resource_id in 0u8..64,
        max_batch_size in prop::option::of(1usize..8),
    ) {
        let mut checker = if let Some(max_batch_size) = max_batch_size {
            PermissionChecker::new().with_max_batch_size(NonZeroUsize::new(max_batch_size).unwrap())
        } else {
            PermissionChecker::new()
        };
        for (index, (grant_percent, forbid_percent, salt, effect_tag)) in policy_specs.into_iter().enumerate() {
            checker.add_policy(RandomStackPolicy {
                name: format!("random_{index}"),
                grant_percent,
                forbid_percent,
                salt,
                effect: effect_from_tag(effect_tag),
            });
        }

        let resource = Resource { id: resource_id };
        let single_session = EvaluationSession::empty();
        let single = tokio_test::block_on(check_resource(&checker, &single_session, &resource));

        let filter_session = EvaluationSession::empty();
        let filtered = tokio_test::block_on(filter_resources(&checker, &filter_session, vec![resource]));

        prop_assert_eq!(single.is_granted(), !filtered.is_empty());
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
