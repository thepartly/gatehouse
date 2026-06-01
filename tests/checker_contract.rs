use async_trait::async_trait;
use gatehouse::{
    AccessEvaluation, BatchEvalCtx, DelegatingPolicy, EvalCtx, EvaluationSession, FactLoadResult,
    FactSource, PermissionChecker, Policy, PolicyBatchItem, PolicyBuilder, PolicyEvalResult,
    RebacPolicy, RelationshipQuery,
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
impl Policy<Subject, Resource, Action, Ctx> for BatchGrantPolicy {
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, Subject, Resource, Action, Ctx>,
    ) -> PolicyEvalResult {
        self.single_calls.fetch_add(1, Ordering::SeqCst);
        self.result_for(ctx.resource.id)
    }

    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, Subject, Resource, Action, Ctx>,
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
            PolicyEvalResult::denied(self.name, format!("{resource_id} denied"))
        }
    }
}

struct RandomStackPolicy {
    name: String,
    grant_percent: u8,
    salt: u16,
}

#[async_trait]
impl Policy<Subject, Resource, Action, Ctx> for RandomStackPolicy {
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, Subject, Resource, Action, Ctx>,
    ) -> PolicyEvalResult {
        self.result_for(ctx.resource.id)
    }

    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, Subject, Resource, Action, Ctx>,
    ) -> Vec<PolicyEvalResult> {
        ctx.items
            .iter()
            .map(|item| self.result_for(item.resource.id))
            .collect()
    }

    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Owned(self.name.clone())
    }
}

impl RandomStackPolicy {
    fn result_for(&self, resource_id: u8) -> PolicyEvalResult {
        let score = ((resource_id as u16 * 37) ^ self.salt).wrapping_add(self.salt / 3) % 100;
        if score < self.grant_percent as u16 {
            PolicyEvalResult::granted(self.name.clone(), Some(format!("{resource_id} granted")))
        } else {
            PolicyEvalResult::denied(self.name.clone(), format!("{resource_id} denied"))
        }
    }
}

struct NeverConsultedPolicy {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Policy<Subject, Resource, Action, Ctx> for NeverConsultedPolicy {
    async fn evaluate(
        &self,
        _ctx: &EvalCtx<'_, Subject, Resource, Action, Ctx>,
    ) -> PolicyEvalResult {
        self.calls.fetch_add(1, Ordering::SeqCst);
        PolicyEvalResult::denied(self.policy_type().to_string(), "single called")
    }

    async fn evaluate_batch<'item>(
        &self,
        _ctx: &BatchEvalCtx<'item, Subject, Resource, Action, Ctx>,
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
        .evaluate_batch_in_session_by(
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
        .evaluate_batch_in_session_by(&session, &Subject, &Action, vec![item], |item| {
            (&item.0, &item.1)
        })
        .await
        .into_iter()
        .map(|(_item, evaluation)| evaluation.is_granted())
        .collect::<Vec<_>>();

    assert_eq!(batch, vec![single]);
}

#[tokio::test]
async fn resource_batch_shortcut_uses_unit_context() {
    let mut checker = PermissionChecker::<Subject, Resource, Action, ()>::new();
    checker.add_policy(
        PolicyBuilder::<Subject, Resource, Action, ()>::new("even-resource")
            .resources(|resource: &Resource| resource.id % 2 == 0)
            .build(),
    );

    let session = EvaluationSession::empty();
    let results = checker
        .evaluate_batch_resources_in_session(
            &session,
            &Subject,
            &Action,
            vec![Resource { id: 1 }, Resource { id: 2 }, Resource { id: 3 }],
        )
        .await;

    let decisions = results
        .iter()
        .map(|(resource, evaluation)| (resource.id, evaluation.is_granted()))
        .collect::<Vec<_>>();
    assert_eq!(decisions, vec![(1, false), (2, true), (3, false)]);

    let visible = checker
        .filter_authorized_resources_in_session(
            &session,
            &Subject,
            &Action,
            vec![Resource { id: 1 }, Resource { id: 2 }, Resource { id: 3 }],
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
        |_subject: &Subject, resource: &Resource, _action: &Action, _context: &Ctx| Resource {
            id: resource.id + 1,
        },
        |_subject: &Subject, _resource: &Resource, _action: &Action, _context: &Ctx| Ctx,
    );

    let mut checker = PermissionChecker::new();
    checker.add_policy(delegating_policy);

    let session = EvaluationSession::empty();
    let results = checker
        .evaluate_batch_in_session_by_resource(
            &session,
            &Subject,
            &Action,
            vec![Resource { id: 0 }, Resource { id: 1 }, Resource { id: 2 }],
            &Ctx,
            |resource| resource,
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
        .evaluate_batch_in_session_by(&session, &Subject, &Action, items, |item| {
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
    let boxed: Box<dyn Policy<Subject, Resource, Action, Ctx>> = Box::new(BatchGrantPolicy {
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
        .evaluate_batch_in_session_by(&session, &Subject, &Action, items.clone(), |item| {
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
        .evaluate_batch_in_session_by(
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
        .evaluate_batch_in_session_by(&session, &Subject, &Action, items, |item| {
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
        policy_specs in prop::collection::vec((0u8..=100, any::<u16>()), 1..=5),
        resource_ids in prop::collection::vec(0u8..64, 0..50),
        max_batch_size in prop::option::of(1usize..8),
    ) {
        let mut checker = if let Some(max_batch_size) = max_batch_size {
            PermissionChecker::new().with_max_batch_size(NonZeroUsize::new(max_batch_size).unwrap())
        } else {
            PermissionChecker::new()
        };
        for (index, (grant_percent, salt)) in policy_specs.into_iter().enumerate() {
            checker.add_policy(RandomStackPolicy {
                name: format!("random_{index}"),
                grant_percent,
                salt,
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
        let batch = tokio_test::block_on(checker.evaluate_batch_in_session_by(
            &batch_session,
            &subject,
            &action,
            items.clone(),
            |item| (&item.0, &item.1),
        ))
        .into_iter()
        .map(|(_item, evaluation)| evaluation.is_granted())
        .collect::<Vec<_>>();

        let mut naive = Vec::new();
        for (resource, context) in &items {
            let session = EvaluationSession::empty();
            naive.push(tokio_test::block_on(checker.evaluate_in_session(
                &session,
                &subject,
                &action,
                resource,
                context,
            ))
            .is_granted());
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
    let session = EvaluationSession::new();
    session.register::<RelationshipQuery<u8, u8, &'static str>, _>(MixedRelationshipSource {
        grants: HashSet::from([RelationshipQuery {
            subject_id: subject.id,
            resource_id: 2,
            relation: "viewer",
        }]),
        calls: Arc::clone(&calls),
    });

    let mut checker = PermissionChecker::new();
    checker.add_policy(
        PolicyBuilder::<MixedSubject, MixedResource, MixedAction, MixedCtx>::new("PublicResource")
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
        .evaluate_batch_in_session_by(&session, &subject, &MixedAction, items, |item| {
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
