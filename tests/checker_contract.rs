use async_trait::async_trait;
use gatehouse::{
    AccessEvaluation, AndPolicy, BatchEvalCtx, DelegatingPolicy, Effect, EvalCtx,
    EvaluationSession, FactLoadResult, FactSource, NotPolicy, OrPolicy, PermissionChecker, Policy,
    PolicyBatchItem, PolicyBuilder, PolicyEvalResult, RebacPolicy, RelationshipQuery,
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

struct BatchGrantPolicy {
    name: &'static str,
    batch_calls: Arc<AtomicUsize>,
    single_calls: Arc<AtomicUsize>,
    seen_batches: Arc<Mutex<Vec<Vec<u8>>>>,
    grant: Arc<dyn Fn(u8) -> bool + Send + Sync>,
}

#[async_trait]
impl Policy<Subject, Action, Resource, Ctx> for BatchGrantPolicy {
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, Subject, Action, Resource, Ctx>,
    ) -> PolicyEvalResult {
        self.single_calls.fetch_add(1, Ordering::SeqCst);
        self.result_for(ctx.resource.id)
    }

    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, Subject, Action, Resource, Ctx>,
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
    salt: u16,
    effect: Effect,
}

#[async_trait]
impl Policy<Subject, Action, Resource, Ctx> for RandomStackPolicy {
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, Subject, Action, Resource, Ctx>,
    ) -> PolicyEvalResult {
        self.result_for(ctx.resource.id)
    }

    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, Subject, Action, Resource, Ctx>,
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
        let score = ((resource_id as u16 * 37) ^ self.salt).wrapping_add(self.salt / 3) % 100;
        let matched = score < self.grant_percent as u16;
        match (self.effect, matched) {
            (Effect::Allow, true) => {
                PolicyEvalResult::granted(self.name.clone(), Some(format!("{resource_id} granted")))
            }
            (Effect::Forbid, true) => {
                PolicyEvalResult::forbidden(self.name.clone(), format!("{resource_id} forbidden"))
            }
            (_, false) => {
                PolicyEvalResult::not_applicable(self.name.clone(), format!("{resource_id} denied"))
            }
        }
    }
}

struct NeverConsultedPolicy {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Policy<Subject, Action, Resource, Ctx> for NeverConsultedPolicy {
    async fn evaluate(
        &self,
        _ctx: &EvalCtx<'_, Subject, Action, Resource, Ctx>,
    ) -> PolicyEvalResult {
        self.calls.fetch_add(1, Ordering::SeqCst);
        PolicyEvalResult::not_applicable(self.policy_type().to_string(), "single called")
    }

    async fn evaluate_batch<'item>(
        &self,
        _ctx: &BatchEvalCtx<'item, Subject, Action, Resource, Ctx>,
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
    let results = checker
        .evaluate_batch_in_session(
            &session,
            &Subject,
            &Action,
            Vec::<(Resource, Ctx)>::new(),
            |item| (&item.0, &item.1),
        )
        .await;

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
    let item = (Resource { id: 4 }, Ctx);

    let single = checker
        .evaluate_in_session(&session, &Subject, &Action, &item.0, &item.1)
        .await
        .is_granted();
    let batch = checker
        .evaluate_batch_in_session(&session, &Subject, &Action, vec![item], |item| {
            (&item.0, &item.1)
        })
        .await
        .into_iter()
        .map(|(_item, evaluation)| evaluation.is_granted())
        .collect::<Vec<_>>();

    assert_eq!(batch, vec![single]);
}

#[tokio::test]
async fn resource_batch_uses_unit_context() {
    let mut checker = PermissionChecker::<Subject, Action, Resource, ()>::new();
    checker.add_policy(
        PolicyBuilder::<Subject, Action, Resource, ()>::new("even-resource")
            .resources(|resource: &Resource| resource.id % 2 == 0)
            .build(),
    );

    let session = EvaluationSession::empty();
    let results = checker
        .evaluate_batch_in_session(
            &session,
            &Subject,
            &Action,
            vec![Resource { id: 1 }, Resource { id: 2 }, Resource { id: 3 }],
            |resource| (resource, &()),
        )
        .await;

    let decisions = results
        .iter()
        .map(|(resource, evaluation)| (resource.id, evaluation.is_granted()))
        .collect::<Vec<_>>();
    assert_eq!(decisions, vec![(1, false), (2, true), (3, false)]);

    let visible = checker
        .filter_authorized_in_session(
            &session,
            &Subject,
            &Action,
            vec![Resource { id: 1 }, Resource { id: 2 }, Resource { id: 3 }],
            |resource| (resource, &()),
        )
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
        |_subject: &Subject, _action: &Action, _resource: &Resource, _context: &Ctx| Ctx,
    );

    let mut checker = PermissionChecker::new();
    checker.add_policy(delegating_policy);

    let session = EvaluationSession::empty();
    let results = checker
        .evaluate_batch_in_session(
            &session,
            &Subject,
            &Action,
            vec![
                (Resource { id: 0 }, Ctx),
                (Resource { id: 1 }, Ctx),
                (Resource { id: 2 }, Ctx),
            ],
            |(resource, context)| (resource, context),
        )
        .await;

    let decisions = results
        .iter()
        .map(|((resource, _context), evaluation)| (resource.id, evaluation.is_granted()))
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

    let items = (0..6).map(|id| (Resource { id }, Ctx)).collect::<Vec<_>>();
    let session = EvaluationSession::empty();
    let results = checker
        .evaluate_batch_in_session(&session, &Subject, &Action, items, |item| {
            (&item.0, &item.1)
        })
        .await;

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
    let boxed: Box<dyn Policy<Subject, Action, Resource, Ctx>> = Box::new(BatchGrantPolicy {
        name: "boxed",
        batch_calls: Arc::clone(&batch_calls),
        single_calls: Arc::clone(&single_calls),
        seen_batches: Arc::new(Mutex::new(Vec::new())),
        grant: Arc::new(|resource_id| resource_id == 1),
    });
    let session = EvaluationSession::empty();
    let owned_items = [(Resource { id: 1 }, Ctx), (Resource { id: 2 }, Ctx)];
    let batch_items = owned_items
        .iter()
        .map(|(resource, context)| PolicyBatchItem { resource, context })
        .collect::<Vec<_>>();

    let results = boxed
        .evaluate_batch(&BatchEvalCtx {
            session: &session,
            subject: &Subject,
            action: &Action,
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

    let items = (0..10).map(|id| (Resource { id }, Ctx)).collect::<Vec<_>>();
    let session = EvaluationSession::empty();
    let batch = checker
        .evaluate_batch_in_session(&session, &Subject, &Action, items.clone(), |item| {
            (&item.0, &item.1)
        })
        .await
        .into_iter()
        .map(|(_item, evaluation)| evaluation.is_granted())
        .collect::<Vec<_>>();

    let mut naive = Vec::new();
    for (resource, context) in &items {
        let session = EvaluationSession::empty();
        naive.push(
            checker
                .evaluate_in_session(&session, &Subject, &Action, resource, context)
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
    let empty = checker
        .evaluate_batch_in_session(
            &session,
            &Subject,
            &Action,
            Vec::<(Resource, Ctx)>::new(),
            |item| (&item.0, &item.1),
        )
        .await;
    assert!(empty.is_empty());

    let items = vec![(Resource { id: 1 }, Ctx), (Resource { id: 2 }, Ctx)];
    let batch = checker
        .evaluate_batch_in_session(&session, &Subject, &Action, items, |item| {
            (&item.0, &item.1)
        })
        .await;
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
        policy_specs in prop::collection::vec((0u8..=100, any::<u16>(), any::<bool>()), 1..=5),
        resource_ids in prop::collection::vec(0u8..64, 0..50),
        max_batch_size in prop::option::of(1usize..8),
    ) {
        let mut checker = if let Some(max_batch_size) = max_batch_size {
            PermissionChecker::new().with_max_batch_size(NonZeroUsize::new(max_batch_size).unwrap())
        } else {
            PermissionChecker::new()
        };
        for (index, (grant_percent, salt, is_deny)) in policy_specs.into_iter().enumerate() {
            checker.add_policy(RandomStackPolicy {
                name: format!("random_{index}"),
                grant_percent,
                salt,
                effect: if is_deny { Effect::Forbid } else { Effect::Allow },
            });
        }

        let subject = Subject;
        let action = Action;
        let items = resource_ids
            .iter()
            .copied()
            .map(|id| (Resource { id }, Ctx))
            .collect::<Vec<_>>();
        let batch_session = EvaluationSession::empty();
        let batch = tokio_test::block_on(checker.evaluate_batch_in_session(
            &batch_session,
            &subject,
            &action,
            items.clone(),
            |item| (&item.0, &item.1),
        ))
        .into_iter()
        .map(|(_item, evaluation)| {
            (
                evaluation.is_granted(),
                evaluation.forbidden_by().map(str::to_owned),
            )
        })
        .collect::<Vec<_>>();

        let mut naive = Vec::new();
        for (resource, context) in &items {
            let session = EvaluationSession::empty();
            let evaluation = tokio_test::block_on(checker.evaluate_in_session(
                &session,
                &subject,
                &action,
                resource,
                context,
            ));
            naive.push((
                evaluation.is_granted(),
                evaluation.forbidden_by().map(str::to_owned),
            ));
        }

        prop_assert_eq!(batch, naive);
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

    let mut checker = PermissionChecker::new();
    checker.add_policy(
        PolicyBuilder::<MixedSubject, MixedAction, MixedResource, MixedCtx>::new("PublicResource")
            .resources(|resource| resource.public)
            .build(),
    );
    checker.add_policy(RebacPolicy::new(
        |subject: &MixedSubject| subject.id,
        |resource: &MixedResource| resource.id,
        "viewer",
    ));

    let items = vec![
        (
            MixedResource {
                id: 1,
                public: true,
            },
            MixedCtx,
        ),
        (
            MixedResource {
                id: 2,
                public: false,
            },
            MixedCtx,
        ),
        (
            MixedResource {
                id: 3,
                public: false,
            },
            MixedCtx,
        ),
    ];
    let results = checker
        .evaluate_batch_in_session(&session, &subject, &MixedAction, items, |item| {
            (&item.0, &item.1)
        })
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

fn allow_everything(name: &str) -> Box<dyn Policy<Subject, Action, Resource, Ctx>> {
    PolicyBuilder::<Subject, Action, Resource, Ctx>::new(name.to_string()).build()
}

fn forbid_odd_resources(name: &str) -> Box<dyn Policy<Subject, Action, Resource, Ctx>> {
    PolicyBuilder::<Subject, Action, Resource, Ctx>::new(name.to_string())
        .resources(|resource: &Resource| resource.id % 2 == 1)
        .forbid()
        .build()
}

#[tokio::test]
async fn batch_forbid_overrides_grants_regardless_of_registration_order() {
    // The forbid policy is registered *after* the allow policy; forbid-first
    // scheduling must still veto before the allow phase grants.
    let mut checker = PermissionChecker::new();
    checker.add_policy(allow_everything("AllowAll"));
    checker.add_policy(forbid_odd_resources("OddBlock"));

    let session = EvaluationSession::empty();
    let items = (0..4).map(|id| (Resource { id }, Ctx)).collect::<Vec<_>>();
    let results = checker
        .evaluate_batch_in_session(&session, &Subject, &Action, items, |item| {
            (&item.0, &item.1)
        })
        .await;

    let decisions = results
        .iter()
        .map(|((resource, _ctx), evaluation)| {
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
    let visible = checker
        .filter_authorized_in_session(
            &session,
            &Subject,
            &Action,
            (0..4).map(|id| (Resource { id }, Ctx)).collect::<Vec<_>>(),
            |(resource, context)| (resource, context),
        )
        .await;
    assert_eq!(
        visible
            .iter()
            .map(|(resource, _context)| resource.id)
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
        let single = checker
            .evaluate_in_session(&session, &Subject, &Action, &Resource { id }, &Ctx)
            .await;
        let batch = checker
            .evaluate_batch_in_session(
                &session,
                &Subject,
                &Action,
                vec![(Resource { id }, Ctx)],
                |item| (&item.0, &item.1),
            )
            .await
            .remove(0)
            .1;
        assert_eq!(single.is_granted(), batch.is_granted(), "id {id}");
        assert_eq!(single.forbidden_by(), batch.forbidden_by(), "id {id}");
    }
}

/// Forbids are honored at the checker level only: inside combinators a
/// `Forbidden` child behaves exactly like `Denied`. Register forbidding
/// policies directly on the checker.
#[tokio::test]
async fn forbid_inside_combinators_acts_as_plain_denial() {
    let session = EvaluationSession::empty();
    let blocked = Resource { id: 1 };

    // OR: the allow arm wins; the nested forbid does not veto.
    let or_gate = OrPolicy::try_new(vec![
        Arc::from(allow_everything("AllowAll")),
        Arc::from(forbid_odd_resources("OddBlock")),
    ])
    .unwrap();
    let mut or_checker = PermissionChecker::new();
    or_checker.add_policy(or_gate);
    let or_result = or_checker
        .evaluate_in_session(&session, &Subject, &Action, &blocked, &Ctx)
        .await;
    assert!(or_result.is_granted());
    assert_eq!(or_result.forbidden_by(), None);

    // AND: a forbid is not a grant, so the conjunction fails — but as an
    // ordinary denial, not a checker-level veto.
    let and_gate = AndPolicy::try_new(vec![
        Arc::from(allow_everything("AllowAll")),
        Arc::from(forbid_odd_resources("OddBlock")),
    ])
    .unwrap();
    let mut and_checker = PermissionChecker::new();
    and_checker.add_policy(and_gate);
    let and_result = and_checker
        .evaluate_in_session(&session, &Subject, &Action, &blocked, &Ctx)
        .await;
    assert!(!and_result.is_granted());
    assert_eq!(and_result.forbidden_by(), None);

    // NOT: inverts not-granted into granted — the pre-Forbidden blocklist
    // polarity. A forbid that must veto belongs on the checker, not under
    // NOT.
    let mut not_checker = PermissionChecker::new();
    not_checker.add_policy(NotPolicy::new(forbid_odd_resources("OddBlock")));
    let not_result = not_checker
        .evaluate_in_session(&session, &Subject, &Action, &Resource { id: 0 }, &Ctx)
        .await;
    assert!(
        not_result.is_granted(),
        "NOT(non-matching deny) is granted, as for any non-granting child"
    );
}

/// Identity-mapped delegating policy whose child checker grants everything
/// except odd resource ids, which it forbids.
fn delegating_forbid_policy(
) -> DelegatingPolicy<Subject, Action, Resource, Ctx, Subject, Action, Resource, Ctx> {
    let mut child: PermissionChecker<Subject, Action, Resource, Ctx> = PermissionChecker::new();
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
        |_subject: &Subject, _action: &Action, _resource: &Resource, _ctx: &Ctx| Ctx,
    )
}

/// A forbid inside a delegated child checker is scoped to that checker:
/// the parent sees an ordinary denial from the delegating policy, and a
/// sibling grant in the parent still wins.
#[tokio::test]
async fn delegated_child_forbid_is_scoped_to_the_child_checker() {
    let mut parent = PermissionChecker::new();
    parent.add_policy(delegating_forbid_policy());
    parent.add_policy(allow_everything("ParentAllow"));

    let session = EvaluationSession::empty();
    let result = parent
        .evaluate_in_session(&session, &Subject, &Action, &Resource { id: 1 }, &Ctx)
        .await;

    // The child checker forbids id 1, so the delegate denies — but the
    // veto does not propagate: the parent's own allow still grants.
    result.assert_granted_by("ParentAllow");

    // Without the parent grant, the delegated denial is an ordinary
    // denial, not a parent-level forbid.
    let mut parent_without_allow = PermissionChecker::new();
    parent_without_allow.add_policy(delegating_forbid_policy());
    let denied = parent_without_allow
        .evaluate_in_session(&session, &Subject, &Action, &Resource { id: 1 }, &Ctx)
        .await;
    assert!(!denied.is_granted());
    assert_eq!(denied.forbidden_by(), None);
}

/// A hand-written policy that declares `Effect::Forbid` and forbids via
/// `ctx.forbid` is honored on both evaluation paths.
struct SuspendedSubjectPolicy;

#[async_trait]
impl Policy<Subject, Action, Resource, Ctx> for SuspendedSubjectPolicy {
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, Subject, Action, Resource, Ctx>,
    ) -> PolicyEvalResult {
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
    let blocked = checker
        .evaluate_in_session(&session, &Subject, &Action, &Resource { id: 1 }, &Ctx)
        .await;
    blocked.assert_forbidden_by("SuspendedSubjectPolicy");

    let granted = checker
        .evaluate_in_session(&session, &Subject, &Action, &Resource { id: 0 }, &Ctx)
        .await;
    granted.assert_granted_by("AllowAll");

    // Default evaluate_batch forwards to evaluate, so the batch path
    // observes the same forbids.
    let results = checker
        .evaluate_batch_in_session(
            &session,
            &Subject,
            &Action,
            vec![(Resource { id: 0 }, Ctx), (Resource { id: 1 }, Ctx)],
            |item| (&item.0, &item.1),
        )
        .await;
    assert!(results[0].1.is_granted());
    assert_eq!(results[1].1.forbidden_by(), Some("SuspendedSubjectPolicy"));
}

/// Contract violation: a policy declaring `Effect::Forbid` must not grant.
/// The checker fails closed, treating the grant as not applicable.
struct MisbehavingForbidPolicy;

#[async_trait]
impl Policy<Subject, Action, Resource, Ctx> for MisbehavingForbidPolicy {
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, Subject, Action, Resource, Ctx>,
    ) -> PolicyEvalResult {
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
    let alone = checker
        .evaluate_in_session(&session, &Subject, &Action, &Resource { id: 0 }, &Ctx)
        .await;
    assert!(!alone.is_granted());
    assert_eq!(alone.forbidden_by(), None);

    // Alongside a real allow policy, the sibling grant still decides.
    checker.add_policy(allow_everything("AllowAll"));
    let with_allow = checker
        .evaluate_in_session(&session, &Subject, &Action, &Resource { id: 0 }, &Ctx)
        .await;
    with_allow.assert_granted_by("AllowAll");

    // Same fail-closed handling on the batch path.
    let batch = checker
        .evaluate_batch_in_session(
            &session,
            &Subject,
            &Action,
            vec![(Resource { id: 0 }, Ctx)],
            |item| (&item.0, &item.1),
        )
        .await;
    assert!(batch[0].1.is_granted());
}

/// An *undeclared* forbid (default `Effect::Allow`) is honored when the
/// checker observes it, but a sibling grant evaluated earlier can
/// short-circuit before it is reached — declaring `Effect::Forbid` is what
/// makes a veto order-independent.
struct UndeclaredForbidPolicy;

#[async_trait]
impl Policy<Subject, Action, Resource, Ctx> for UndeclaredForbidPolicy {
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, Subject, Action, Resource, Ctx>,
    ) -> PolicyEvalResult {
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
    let blocked = forbid_first
        .evaluate_in_session(&session, &Subject, &Action, &Resource { id: 0 }, &Ctx)
        .await;
    blocked.assert_forbidden_by("UndeclaredForbidPolicy");

    // Grant short-circuits first: the undeclared forbid is never reached.
    // This pins the documented contract that forbidding policies must
    // declare Effect::Forbid to veto deterministically.
    let mut grant_first = PermissionChecker::new();
    grant_first.add_policy(allow_everything("AllowAll"));
    grant_first.add_policy(UndeclaredForbidPolicy);
    let granted = grant_first
        .evaluate_in_session(&session, &Subject, &Action, &Resource { id: 0 }, &Ctx)
        .await;
    granted.assert_granted_by("AllowAll");
}

/// A forbid-effect policy whose batch override returns the wrong number of
/// results fails closed: affected items are denied, not granted by the
/// allow phase.
struct WrongLengthForbidPolicy;

#[async_trait]
impl Policy<Subject, Action, Resource, Ctx> for WrongLengthForbidPolicy {
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, Subject, Action, Resource, Ctx>,
    ) -> PolicyEvalResult {
        ctx.not_applicable("not applicable")
    }

    async fn evaluate_batch<'item>(
        &self,
        _ctx: &BatchEvalCtx<'item, Subject, Action, Resource, Ctx>,
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
    let results = checker
        .evaluate_batch_in_session(
            &session,
            &Subject,
            &Action,
            vec![(Resource { id: 0 }, Ctx), (Resource { id: 1 }, Ctx)],
            |item| (&item.0, &item.1),
        )
        .await;

    for (_item, evaluation) in &results {
        assert!(
            !evaluation.is_granted(),
            "items touched by a broken forbid policy must fail closed"
        );
    }
}
