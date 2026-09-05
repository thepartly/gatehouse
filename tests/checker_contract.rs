use async_trait::async_trait;
use gatehouse::{
    AccessEvaluation, AndPolicy, BatchEvalCtx, Decision, DelegatingPolicy, EvalCtx,
    EvaluationSession, FactLoadResult, FactOutcome, FactProvenance, FactSource, GrantResult,
    Hydrator, LookupAuthorizedError, LookupPage, LookupSource, OrPolicy, PermissionChecker, Policy,
    PolicyBatchItem, PolicyBuilder, PolicyDomain, PolicyExt, RebacPolicy, RelationshipQuery,
    VetoPolicy, VetoPolicyExt, VetoResult,
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

struct BatchGrantPolicy {
    name: &'static str,
    batch_calls: Arc<AtomicUsize>,
    single_calls: Arc<AtomicUsize>,
    seen_batches: Arc<Mutex<Vec<Vec<u8>>>>,
    grant: Arc<dyn Fn(u8) -> bool + Send + Sync>,
}

#[async_trait]
impl Policy<Domain> for BatchGrantPolicy {
    async fn evaluate(&self, ctx: &EvalCtx<'_, Domain>) -> GrantResult {
        self.single_calls.fetch_add(1, Ordering::SeqCst);
        self.result_for(ctx.resource.id)
    }

    async fn evaluate_batch<'item>(&self, ctx: &BatchEvalCtx<'item, Domain>) -> Vec<GrantResult> {
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
    fn result_for(&self, resource_id: u8) -> GrantResult {
        if (self.grant)(resource_id) {
            GrantResult::granted(self.name, Some(format!("{resource_id} granted")))
        } else {
            GrantResult::not_applicable(self.name, format!("{resource_id} denied"))
        }
    }
}

struct NeverConsultedPolicy {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Policy<Domain> for NeverConsultedPolicy {
    async fn evaluate(&self, _ctx: &EvalCtx<'_, Domain>) -> GrantResult {
        self.calls.fetch_add(1, Ordering::SeqCst);
        GrantResult::not_applicable(self.policy_type().to_string(), "single called")
    }

    async fn evaluate_batch<'item>(&self, _ctx: &BatchEvalCtx<'item, Domain>) -> Vec<GrantResult> {
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
    checker.add_delegate(delegating_policy);

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
        .evaluate_batch(&BatchEvalCtx::new(
            &session,
            &Subject,
            &Action,
            &Ctx,
            &batch_items,
            boxed.policy_type(),
        ))
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

fn forbid_odd_resources(name: &str) -> Box<dyn VetoPolicy<Domain>> {
    PolicyBuilder::<Domain>::new(name.to_string())
        .resources(|resource: &Resource| resource.id % 2 == 1)
        .build_veto()
}

fn grant_even_resources(name: &str) -> impl Policy<Domain> {
    PolicyBuilder::<Domain>::new(name.to_string())
        .resources(|resource: &Resource| resource.id % 2 == 0)
        .build()
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

fn delegating_forbid_policy() -> DelegatingPolicy<Domain, Domain> {
    let mut child: PermissionChecker<Domain> = PermissionChecker::new();
    child.add_policy(allow_everything("ChildAllow"));
    child.add_veto(forbid_odd_resources("ChildBlock"));
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
            parent.add_delegate(delegating_forbid_policy());
            parent.add_policy(allow_everything("ParentAllow"));
        } else {
            parent.add_policy(allow_everything("ParentAllow"));
            parent.add_delegate(delegating_forbid_policy());
        }

        let result = check_resource(&parent, &session, &Resource { id: 1 }).await;

        result.assert_forbidden_by("ChildBlock");
    }

    // Without the parent grant, the delegated veto is still reported as the
    // cause of denial.
    let mut parent_without_allow = PermissionChecker::new();
    parent_without_allow.add_delegate(delegating_forbid_policy());
    let denied = check_resource(&parent_without_allow, &session, &Resource { id: 1 }).await;
    denied.assert_forbidden_by("ChildBlock");
}

/// A hand-written policy that declares `Effect::Forbid` and forbids via
/// `ctx.forbid` is honored on both evaluation paths.
struct ErrorBearingNotApplicablePolicy;

#[async_trait]
impl Policy<Domain> for ErrorBearingNotApplicablePolicy {
    async fn evaluate(&self, ctx: &EvalCtx<'_, Domain>) -> GrantResult {
        ctx.not_applicable_with_facts(
            "fact was unavailable",
            vec![FactProvenance::new(
                "membership",
                "Membership(7)",
                FactOutcome::Error,
                Some("membership backend unavailable".to_string()),
            )],
        )
    }

    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("ErrorBearingNotApplicablePolicy")
    }
}

/// Negation must never manufacture a grant from a leaf that reports a failed
/// fact load, even when the policy deliberately used the explicit-provenance
/// escape hatch to keep the leaf itself `NotApplicable`.
#[tokio::test]
async fn not_policy_fail_closes_error_bearing_not_applicable() {
    let mut checker = PermissionChecker::new();
    checker.add_policy(ErrorBearingNotApplicablePolicy.not());
    let session = EvaluationSession::empty();

    let single = check_resource(&checker, &session, &Resource { id: 0 }).await;
    single.assert_indeterminate();
    assert!(!single.is_granted());
    assert_eq!(single.fact_load_errors().len(), 1);

    let batch = evaluate_resources(&checker, &session, vec![Resource { id: 0 }])
        .await
        .remove(0)
        .1;
    batch.assert_indeterminate();
    assert!(!batch.is_granted());
    assert_eq!(batch.fact_load_errors().len(), 1);
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct OddFlag(u8);

impl gatehouse::FactKey for OddFlag {
    const NAME: &'static str = "odd_flag";
    type Value = bool;
}

/// Answers `Found(id is odd)` and fails to load configured ids.
struct OddFlagSource {
    fail_ids: HashSet<u8>,
}

#[async_trait]
impl FactSource<OddFlag> for OddFlagSource {
    async fn load_many(&self, keys: &[OddFlag]) -> Vec<FactLoadResult<bool>> {
        keys.iter()
            .map(|OddFlag(id)| {
                if self.fail_ids.contains(id) {
                    FactLoadResult::Error(gatehouse::FactLoadError::backend_message(
                        "flag store unreachable",
                    ))
                } else {
                    FactLoadResult::Found(id % 2 == 1)
                }
            })
            .collect()
    }
}

fn odd_flag_session(fail_ids: impl IntoIterator<Item = u8>) -> EvaluationSession {
    gatehouse::FactRegistry::builder()
        .with::<OddFlag, _>(OddFlagSource {
            fail_ids: fail_ids.into_iter().collect(),
        })
        .build()
        .session()
}

/// A fact-backed policy that loads through the recording context but builds
/// its results **by hand** with the plain constructors — the #58 case 3
/// "forgetful" shape. Provenance (and the NotApplicable → Indeterminate
/// upgrade after a failed load) must therefore come from the caller-side
/// `EvalCtx::finish` / `BatchEvalCtx::finish` merge in the checker and
/// combinators; removing any of those calls breaks these tests.
struct HandBuiltOddPolicy;

impl HandBuiltOddPolicy {
    fn result_for(fact: FactLoadResult<bool>) -> GrantResult {
        match fact {
            FactLoadResult::Found(true) => {
                GrantResult::granted("HandBuiltOddPolicy", Some("odd resource".into()))
            }
            _ => GrantResult::not_applicable("HandBuiltOddPolicy", "not odd"),
        }
    }
}

#[async_trait]
impl Policy<Domain> for HandBuiltOddPolicy {
    async fn evaluate(&self, ctx: &EvalCtx<'_, Domain>) -> GrantResult {
        Self::result_for(ctx.fact(OddFlag(ctx.resource.id)).await)
    }

    async fn evaluate_batch<'item>(&self, ctx: &BatchEvalCtx<'item, Domain>) -> Vec<GrantResult> {
        ctx.facts_by(|resource| OddFlag(resource.id))
            .await
            .into_iter()
            .map(Self::result_for)
            .collect()
    }

    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("HandBuiltOddPolicy")
    }
}

/// A custom combinator-shaped policy that records a fact on its outer
/// context. `finish` must preserve a failed load even though `Combined` has no
/// provenance field of its own.
struct HandBuiltCombinedOddPolicy;

#[async_trait]
impl Policy<Domain> for HandBuiltCombinedOddPolicy {
    async fn evaluate(&self, ctx: &EvalCtx<'_, Domain>) -> GrantResult {
        let _ = ctx.fact(OddFlag(ctx.resource.id)).await;
        GrantResult::all(self.policy_type(), Vec::new())
    }

    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("HandBuiltCombinedOddPolicy")
    }
}

#[tokio::test]
async fn combined_policy_preserves_recorded_load_failures() {
    let mut checker = PermissionChecker::new();
    checker.add_policy(HandBuiltCombinedOddPolicy);
    let session = odd_flag_session([3]);

    let single = check_resource(&checker, &session, &Resource { id: 3 }).await;
    single.assert_indeterminate();
    assert_eq!(single.fact_load_errors().len(), 1);
    assert!(single.trace().format().contains("fact odd_flag [error]"));

    let batch = evaluate_resources(&checker, &session, vec![Resource { id: 3 }])
        .await
        .remove(0)
        .1;
    batch.assert_indeterminate();
    assert_eq!(batch.fact_load_errors().len(), 1);
    assert!(batch.trace().format().contains("fact odd_flag [error]"));
}

/// Facts recorded on the context reach the trace even when the policy
/// builds results by hand: the checker merges them after evaluation, on
/// both the single and the batch path.
#[tokio::test]
async fn recorded_facts_reach_the_trace_for_hand_built_results() {
    let mut checker = PermissionChecker::new();
    checker.add_policy(HandBuiltOddPolicy);
    let session = odd_flag_session([]);

    let granted = check_resource(&checker, &session, &Resource { id: 1 }).await;
    granted.assert_granted_by("HandBuiltOddPolicy");
    assert!(
        granted.trace().format().contains("fact odd_flag [found]"),
        "single-path grant must carry recorded provenance:\n{}",
        granted.trace().format()
    );

    let denied = check_resource(&checker, &session, &Resource { id: 2 }).await;
    denied.assert_denied();
    assert!(denied.trace().format().contains("fact odd_flag [found]"));

    let batch = evaluate_resources(
        &checker,
        &session,
        vec![Resource { id: 1 }, Resource { id: 2 }],
    )
    .await;
    for (resource, evaluation) in &batch {
        assert!(
            evaluation
                .trace()
                .format()
                .contains("fact odd_flag [found]"),
            "batch item {} must carry recorded provenance:\n{}",
            resource.id,
            evaluation.trace().format()
        );
    }
    assert!(batch[0].1.is_granted());
    assert!(!batch[1].1.is_granted());
}

/// A recorded load failure upgrades a hand-built `NotApplicable` to
/// `Indeterminate` when the checker merges the recorded facts — closing the
/// silent #58-case-3 gap on both evaluation paths.
#[tokio::test]
async fn recorded_load_failure_upgrades_hand_built_not_applicable() {
    let mut checker = PermissionChecker::new();
    checker.add_policy(HandBuiltOddPolicy);
    let session = odd_flag_session([3]);

    let single = check_resource(&checker, &session, &Resource { id: 3 }).await;
    single.assert_indeterminate();
    let errors = single.fact_load_errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].fact_name, "odd_flag");
    assert_eq!(
        errors[0].error_kind,
        Some(gatehouse::FactLoadErrorKind::Backend)
    );

    let batch = evaluate_resources(
        &checker,
        &session,
        vec![Resource { id: 3 }, Resource { id: 1 }],
    )
    .await;
    batch[0].1.assert_indeterminate();
    assert_eq!(batch[0].1.fact_load_errors().len(), 1);
    batch[1].1.assert_granted_by("HandBuiltOddPolicy");
    assert!(batch[1].1.fact_load_errors().is_empty());
}

/// The combinators perform the same recorded-fact merge for their children.
/// If `AndPolicy` / `OrPolicy` / `NotPolicy` dropped their `finish` calls,
/// the failing child would stay `NotApplicable` — turning the AND/OR result
/// into an ordinary denial and, worse, letting `NOT` invert it into a grant.
#[tokio::test]
async fn combinators_merge_recorded_facts_for_hand_built_children() {
    let failing = Resource { id: 3 };

    // AND: the upgraded Indeterminate child taints the conjunction.
    let mut and_checker = PermissionChecker::new();
    and_checker.add_policy(
        AndPolicy::try_new(vec![
            Arc::new(HandBuiltOddPolicy),
            Arc::new(allow_everything("AllowAll")) as Arc<dyn Policy<Domain>>,
        ])
        .unwrap(),
    );
    let session = odd_flag_session([3]);
    let single = check_resource(&and_checker, &session, &failing).await;
    single.assert_indeterminate();
    assert!(single.trace().format().contains("fact odd_flag [error]"));
    let batch = evaluate_resources(&and_checker, &session, vec![failing.clone()]).await;
    batch[0].1.assert_indeterminate();

    // OR: with no grant available, the disjunction is indeterminate.
    let mut or_checker = PermissionChecker::new();
    or_checker.add_policy(
        OrPolicy::try_new(vec![
            Arc::new(HandBuiltOddPolicy),
            Arc::new(
                PolicyBuilder::<Domain>::new("NoOpinion")
                    .when(|_, _, _, _| false)
                    .build(),
            ) as Arc<dyn Policy<Domain>>,
        ])
        .unwrap(),
    );
    let session = odd_flag_session([3]);
    let single = check_resource(&or_checker, &session, &failing).await;
    single.assert_indeterminate();
    let batch = evaluate_resources(&or_checker, &session, vec![failing.clone()]).await;
    batch[0].1.assert_indeterminate();

    // NOT: without the merge the failed child would look like an ordinary
    // non-grant and NOT would invert it into a grant.
    let mut not_checker = PermissionChecker::new();
    not_checker.add_policy(HandBuiltOddPolicy.not());
    let session = odd_flag_session([3]);
    let single = check_resource(&not_checker, &session, &failing).await;
    single.assert_indeterminate();
    assert!(!single.is_granted());
    let batch = evaluate_resources(&not_checker, &session, vec![failing]).await;
    batch[0].1.assert_indeterminate();
}

/// A `Forbid`-effect policy that (in violation of its contract) grants,
/// after consulting a fact through the recording context.
struct SharedFactPolicy;

#[async_trait]
impl Policy<Domain> for SharedFactPolicy {
    async fn evaluate(&self, ctx: &EvalCtx<'_, Domain>) -> GrantResult {
        match ctx.fact(OddFlag(0)).await {
            FactLoadResult::Found(true) => ctx.grant("shared flag set"),
            _ => ctx.not_applicable("shared flag not set"),
        }
    }

    async fn evaluate_batch<'item>(&self, ctx: &BatchEvalCtx<'item, Domain>) -> Vec<GrantResult> {
        let fact = ctx.fact(OddFlag(0)).await;
        ctx.items
            .iter()
            .map(|_| match &fact {
                FactLoadResult::Found(true) => {
                    GrantResult::granted("SharedFactPolicy", Some("shared flag set".into()))
                }
                _ => GrantResult::not_applicable("SharedFactPolicy", "shared flag not set"),
            })
            .collect()
    }

    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("SharedFactPolicy")
    }
}

#[tokio::test]
async fn batch_shared_fact_records_against_every_item() {
    let mut checker = PermissionChecker::new();
    checker.add_policy(SharedFactPolicy);

    let session = odd_flag_session([]);
    let batch = evaluate_resources(
        &checker,
        &session,
        vec![Resource { id: 10 }, Resource { id: 11 }],
    )
    .await;
    for (_, evaluation) in &batch {
        assert!(evaluation
            .trace()
            .format()
            .contains("fact odd_flag [found]"));
    }

    // A failing shared fact makes every hand-built NotApplicable item
    // indeterminate through the same merge.
    let session = odd_flag_session([0]);
    let batch = evaluate_resources(
        &checker,
        &session,
        vec![Resource { id: 10 }, Resource { id: 11 }],
    )
    .await;
    for (_, evaluation) in &batch {
        evaluation.assert_indeterminate();
        assert_eq!(evaluation.fact_load_errors().len(), 1);
    }
}

/// Combinator decision tables for indeterminate children. Distinguishes
/// the veto-prefix rules (indeterminate outranks a definite non-grant when
/// the child might have forbidden) from the allow-only rules (a definite
/// answer outranks the indeterminate when it settles the aggregate).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Truth {
    Yes,
    No,
    Unknown,
}

fn any_truth(values: impl IntoIterator<Item = Truth>) -> Truth {
    let mut unknown = false;
    for value in values {
        match value {
            Truth::Yes => return Truth::Yes,
            Truth::Unknown => unknown = true,
            Truth::No => {}
        }
    }
    if unknown {
        Truth::Unknown
    } else {
        Truth::No
    }
}
fn all_truth(values: impl IntoIterator<Item = Truth>) -> Truth {
    let mut unknown = false;
    for value in values {
        match value {
            Truth::No => return Truth::No,
            Truth::Unknown => unknown = true,
            Truth::Yes => {}
        }
    }
    if unknown {
        Truth::Unknown
    } else {
        Truth::Yes
    }
}

#[derive(Clone, Debug)]
enum Expression {
    Leaf([Truth; 3]),
    All(Box<Expression>, Box<Expression>),
    Any(Box<Expression>, Box<Expression>),
    Not(Box<Expression>),
}
impl Expression {
    fn interpret(&self, resource: u8) -> Truth {
        match self {
            Self::Leaf(values) => values[usize::from(resource % 3)],
            Self::All(left, right) => {
                all_truth([left.interpret(resource), right.interpret(resource)])
            }
            Self::Any(left, right) => {
                any_truth([left.interpret(resource), right.interpret(resource)])
            }
            Self::Not(child) => match child.interpret(resource) {
                Truth::Yes => Truth::No,
                Truth::No => Truth::Yes,
                Truth::Unknown => Truth::Unknown,
            },
        }
    }
    fn grant(&self) -> Box<dyn Policy<Domain>> {
        match self {
            Self::Leaf(values) => Box::new(GrantLeaf(*values)),
            Self::All(left, right) => Box::new(left.grant().and(right.grant())),
            Self::Any(left, right) => Box::new(left.grant().or(right.grant())),
            Self::Not(child) => Box::new(child.grant().not()),
        }
    }
    fn veto(&self) -> Box<dyn VetoPolicy<Domain>> {
        match self {
            Self::Leaf(values) => Box::new(VetoLeaf(*values)),
            Self::All(left, right) => Box::new(left.veto().all_of(right.veto())),
            Self::Any(left, right) => Box::new(left.veto().any_of(right.veto())),
            Self::Not(_) => unreachable!("veto strategy has no negation"),
        }
    }
}
struct GrantLeaf([Truth; 3]);
#[async_trait]
impl Policy<Domain> for GrantLeaf {
    async fn evaluate(&self, ctx: &EvalCtx<'_, Domain>) -> GrantResult {
        match self.0[usize::from(ctx.resource.id % 3)] {
            Truth::Yes => ctx.grant("grant"),
            Truth::No => ctx.not_applicable("abstain"),
            Truth::Unknown => ctx.indeterminate("grant unavailable"),
        }
    }
    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        "GrantLeaf".into()
    }
}
struct VetoLeaf([Truth; 3]);
#[async_trait]
impl VetoPolicy<Domain> for VetoLeaf {
    async fn evaluate(&self, ctx: &EvalCtx<'_, Domain>) -> VetoResult {
        match self.0[usize::from(ctx.resource.id % 3)] {
            Truth::Yes => ctx.forbid("veto"),
            Truth::No => ctx.pass("pass"),
            Truth::Unknown => ctx.veto_indeterminate("veto unavailable"),
        }
    }
    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        "VetoLeaf".into()
    }
}

#[derive(Clone, Debug)]
struct CheckerSpec {
    grants: Vec<Expression>,
    vetoes: Vec<Expression>,
    delegates: Vec<CheckerSpec>,
}
impl CheckerSpec {
    fn grant_truth(&self, resource: u8) -> Truth {
        any_truth(
            self.grants
                .iter()
                .map(|node| node.interpret(resource))
                .chain(
                    self.delegates
                        .iter()
                        .map(|child| child.grant_truth(resource)),
                ),
        )
    }
    fn veto_truth(&self, resource: u8) -> Truth {
        any_truth(
            self.vetoes
                .iter()
                .map(|node| node.interpret(resource))
                .chain(
                    self.delegates
                        .iter()
                        .map(|child| child.veto_truth(resource)),
                ),
        )
    }
    fn decision(&self, resource: u8) -> Decision {
        match self.veto_truth(resource) {
            Truth::Yes => Decision::Forbid,
            Truth::Unknown => Decision::Indeterminate,
            Truth::No => match self.grant_truth(resource) {
                Truth::Yes => Decision::Grant,
                Truth::No => Decision::NotApplicable,
                Truth::Unknown => Decision::Indeterminate,
            },
        }
    }
    fn checker(&self, reverse: bool, batch_size: usize) -> PermissionChecker<Domain> {
        let mut checker =
            PermissionChecker::new().with_max_batch_size(NonZeroUsize::new(batch_size).unwrap());
        if reverse {
            for veto in self.vetoes.iter().rev() {
                checker.add_veto(veto.veto());
            }
            for grant in self.grants.iter().rev() {
                checker.add_policy(grant.grant());
            }
        } else {
            for grant in &self.grants {
                checker.add_policy(grant.grant());
            }
            for veto in &self.vetoes {
                checker.add_veto(veto.veto());
            }
        }
        for child in &self.delegates {
            checker.add_delegate(identity_delegate(child.checker(reverse, batch_size)));
        }
        checker
    }
}
fn identity_delegate(checker: PermissionChecker<Domain>) -> DelegatingPolicy<Domain, Domain> {
    DelegatingPolicy::new(
        "Delegate",
        checker,
        |_: &Subject| Subject,
        |_: &Action| Action,
        |_: &Subject, _: &Action, resource: &Resource, _: &Ctx| resource.clone(),
        |_: &Subject, _: &Action, _: &Ctx| Ctx,
    )
}
fn truth_strategy() -> impl Strategy<Value = Truth> {
    prop_oneof![Just(Truth::Yes), Just(Truth::No), Just(Truth::Unknown)]
}
fn expression_strategy(grant: bool) -> BoxedStrategy<Expression> {
    prop::array::uniform3(truth_strategy())
        .prop_map(Expression::Leaf)
        .prop_recursive(3, 24, 2, move |inner| {
            let binary = prop_oneof![
                (inner.clone(), inner.clone())
                    .prop_map(|(left, right)| Expression::All(Box::new(left), Box::new(right))),
                (inner.clone(), inner.clone())
                    .prop_map(|(left, right)| Expression::Any(Box::new(left), Box::new(right))),
            ];
            if grant {
                prop_oneof![
                    binary.boxed(),
                    inner
                        .prop_map(|child| Expression::Not(Box::new(child)))
                        .boxed()
                ]
                .boxed()
            } else {
                binary.boxed()
            }
        })
        .boxed()
}
fn checker_strategy() -> impl Strategy<Value = CheckerSpec> {
    let local = (
        prop::collection::vec(expression_strategy(true), 0..4),
        prop::collection::vec(expression_strategy(false), 0..4),
    );
    local
        .clone()
        .prop_map(|(grants, vetoes)| CheckerSpec {
            grants,
            vetoes,
            delegates: Vec::new(),
        })
        .prop_recursive(2, 12, 2, move |inner| {
            (local.clone(), prop::collection::vec(inner, 1..3)).prop_map(
                |((grants, vetoes), delegates)| CheckerSpec {
                    grants,
                    vetoes,
                    delegates,
                },
            )
        })
}
fn access_decision(evaluation: &AccessEvaluation) -> Decision {
    evaluation
        .trace()
        .root()
        .expect("evaluation audit root")
        .decision()
}
proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]
    #[test]
    fn recursive_composition_and_delegation_match_independent_oracle(spec in checker_strategy(), resources in prop::collection::vec(0u8..24,0..16), reverse in any::<bool>(), batch_size in 1usize..6) {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let checker = spec.checker(reverse,batch_size);
            let session = EvaluationSession::empty();
            let batch = bind(&checker,&session).evaluate(resources.iter().map(|&id| Resource { id })).await;
            prop_assert_eq!(batch.len(),resources.len());
            for ((resource,batch),id) in batch.iter().zip(resources) {
                let expected = spec.decision(id);
                let single = bind(&checker,&session).check(resource).await;
                prop_assert_eq!(access_decision(batch),expected,"spec: {:?}, resource: {}",spec,id);
                prop_assert_eq!(access_decision(&single),expected);
                prop_assert_eq!(batch.trace().format(),single.trace().format());
                if expected == Decision::Forbid { prop_assert!(batch.forbidden_by().is_some()); }
                if expected == Decision::Indeterminate { prop_assert!(batch.indeterminate_reason().is_some_and(|reason| !reason.is_empty())); }
            }
            Ok(())
        })?;
    }
}

#[tokio::test]
async fn grant_and_veto_combinators_exhaustive_truth_tables() {
    let values = [Truth::Yes, Truth::No, Truth::Unknown];
    let session = EvaluationSession::empty();
    let resource = Resource { id: 0 };
    for left in values {
        for right in values {
            for conjunction in [true, false] {
                let expression = if conjunction {
                    Expression::All(
                        Box::new(Expression::Leaf([left; 3])),
                        Box::new(Expression::Leaf([right; 3])),
                    )
                } else {
                    Expression::Any(
                        Box::new(Expression::Leaf([left; 3])),
                        Box::new(Expression::Leaf([right; 3])),
                    )
                };
                let grant = expression.grant();
                let veto = expression.veto();
                let ctx = EvalCtx::new(&session, &Subject, &Action, &resource, &Ctx, "test");
                let items = [PolicyBatchItem {
                    resource: &resource,
                }];
                let batch_ctx =
                    BatchEvalCtx::new(&session, &Subject, &Action, &Ctx, &items, "test");
                let expected = expression.interpret(0);
                let grant_expected = match expected {
                    Truth::Yes => Decision::Grant,
                    Truth::No => Decision::NotApplicable,
                    Truth::Unknown => Decision::Indeterminate,
                };
                let veto_expected = match expected {
                    Truth::Yes => Decision::Forbid,
                    Truth::No => Decision::NotApplicable,
                    Truth::Unknown => Decision::Indeterminate,
                };
                assert_eq!(grant.evaluate(&ctx).await.decision(), grant_expected);
                assert_eq!(
                    grant.evaluate_batch(&batch_ctx).await[0].decision(),
                    grant_expected
                );
                assert_eq!(veto.evaluate(&ctx).await.decision(), veto_expected);
                assert_eq!(
                    veto.evaluate_batch(&batch_ctx).await[0].decision(),
                    veto_expected
                );
            }
        }
    }
}

#[tokio::test]
async fn delegated_grant_outage_does_not_block_parent_grant_but_veto_outage_does() {
    for veto in [Truth::No, Truth::Unknown, Truth::Yes] {
        let mut child = PermissionChecker::new();
        child.add_veto(VetoLeaf([veto; 3]));
        child.add_policy(GrantLeaf([Truth::Unknown; 3]));
        let mut parent = PermissionChecker::new();
        parent.add_delegate(identity_delegate(child));
        parent.add_policy(GrantLeaf([Truth::Yes; 3]));
        let expected = match veto {
            Truth::No => Decision::Grant,
            Truth::Unknown => Decision::Indeterminate,
            Truth::Yes => Decision::Forbid,
        };
        let session = EvaluationSession::empty();
        assert_eq!(
            access_decision(&bind(&parent, &session).check(&Resource { id: 0 }).await),
            expected
        );
        let batch = bind(&parent, &session)
            .evaluate(vec![Resource { id: 0 }, Resource { id: 1 }])
            .await;
        assert!(batch
            .iter()
            .all(|(_, result)| access_decision(result) == expected));
    }
}

struct CountingVeto {
    calls: Arc<AtomicUsize>,
}
#[async_trait]
impl VetoPolicy<Domain> for CountingVeto {
    async fn evaluate(&self, ctx: &EvalCtx<'_, Domain>) -> VetoResult {
        self.calls.fetch_add(1, Ordering::SeqCst);
        ctx.pass("pass")
    }
    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        "CountingVeto".into()
    }
}
#[tokio::test]
async fn atomic_delegation_evaluates_each_capability_once_per_resource() {
    let veto_calls = Arc::new(AtomicUsize::new(0));
    let grant_calls = Arc::new(AtomicUsize::new(0));
    let mut child = PermissionChecker::new();
    child.add_veto(CountingVeto {
        calls: veto_calls.clone(),
    });
    child.add_policy(BatchGrantPolicy {
        name: "grant",
        single_calls: grant_calls.clone(),
        batch_calls: Arc::new(AtomicUsize::new(0)),
        seen_batches: Arc::new(Mutex::new(Vec::new())),
        grant: Arc::new(|_| true),
    });
    let mut parent = PermissionChecker::new();
    parent.add_delegate(identity_delegate(child));
    let session = EvaluationSession::empty();
    assert!(bind(&parent, &session)
        .check(&Resource { id: 0 })
        .await
        .is_granted());
    assert_eq!(veto_calls.load(Ordering::SeqCst), 1);
    assert_eq!(grant_calls.load(Ordering::SeqCst), 1);
    let results = bind(&parent, &session)
        .evaluate(vec![Resource { id: 0 }, Resource { id: 1 }])
        .await;
    assert!(results.iter().all(|(_, result)| result.is_granted()));
    assert_eq!(veto_calls.load(Ordering::SeqCst), 3);
    assert_eq!(grant_calls.load(Ordering::SeqCst), 1);
}

struct WrongGrant(usize);
#[async_trait]
impl Policy<Domain> for WrongGrant {
    async fn evaluate(&self, ctx: &EvalCtx<'_, Domain>) -> GrantResult {
        ctx.indeterminate("unavailable")
    }
    async fn evaluate_batch<'item>(&self, _ctx: &BatchEvalCtx<'item, Domain>) -> Vec<GrantResult> {
        vec![GrantResult::granted("WrongGrant", None); self.0]
    }
    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        "WrongGrant".into()
    }
}
struct WrongVeto(usize);
#[async_trait]
impl VetoPolicy<Domain> for WrongVeto {
    async fn evaluate(&self, ctx: &EvalCtx<'_, Domain>) -> VetoResult {
        ctx.veto_indeterminate("unavailable")
    }
    async fn evaluate_batch<'item>(&self, _ctx: &BatchEvalCtx<'item, Domain>) -> Vec<VetoResult> {
        vec![VetoResult::pass("WrongVeto", "pass"); self.0]
    }
    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        "WrongVeto".into()
    }
}
#[tokio::test]
async fn malformed_batches_preserve_capability_specific_uncertainty() {
    for count in [0, 3] {
        let session = EvaluationSession::empty();
        let mut grants = PermissionChecker::new();
        grants.add_policy(WrongGrant(count));
        grants.add_policy(GrantLeaf([Truth::Yes; 3]));
        assert!(bind(&grants, &session)
            .evaluate(vec![Resource { id: 0 }, Resource { id: 1 }])
            .await
            .iter()
            .all(|(_, result)| result.is_granted()));
        for later in [Truth::No, Truth::Yes] {
            let mut vetoes = PermissionChecker::new();
            vetoes.add_veto(WrongVeto(count));
            vetoes.add_veto(VetoLeaf([later; 3]));
            vetoes.add_policy(GrantLeaf([Truth::Yes; 3]));
            let expected = if later == Truth::Yes {
                Decision::Forbid
            } else {
                Decision::Indeterminate
            };
            assert!(bind(&vetoes, &session)
                .evaluate(vec![Resource { id: 0 }, Resource { id: 1 }])
                .await
                .iter()
                .all(|(_, result)| access_decision(result) == expected));
        }
    }
}

#[tokio::test]
async fn malformed_combinator_batches_do_not_claim_definite_outcomes() {
    let session = EvaluationSession::empty();
    for count in [0, 3] {
        for (policy, expected) in [
            (
                WrongGrant(count).or(GrantLeaf([Truth::Yes; 3])).boxed(),
                Decision::Grant,
            ),
            (
                WrongGrant(count).and(GrantLeaf([Truth::Yes; 3])).boxed(),
                Decision::Indeterminate,
            ),
            (
                WrongGrant(count).and(GrantLeaf([Truth::No; 3])).boxed(),
                Decision::NotApplicable,
            ),
            (WrongGrant(count).not().boxed(), Decision::Indeterminate),
        ] {
            let mut checker = PermissionChecker::new();
            checker.add_policy(policy);
            assert!(bind(&checker, &session)
                .evaluate(vec![Resource { id: 0 }, Resource { id: 1 }])
                .await
                .iter()
                .all(|(_, result)| access_decision(result) == expected));
        }
        for (veto, expected) in [
            (
                WrongVeto(count).any_of(VetoLeaf([Truth::Yes; 3])).boxed(),
                Decision::Forbid,
            ),
            (
                WrongVeto(count).all_of(VetoLeaf([Truth::No; 3])).boxed(),
                Decision::Grant,
            ),
            (
                WrongVeto(count).all_of(VetoLeaf([Truth::Yes; 3])).boxed(),
                Decision::Indeterminate,
            ),
        ] {
            let mut checker = PermissionChecker::new();
            checker.add_veto(veto);
            checker.add_policy(GrantLeaf([Truth::Yes; 3]));
            assert!(bind(&checker, &session)
                .evaluate(vec![Resource { id: 0 }, Resource { id: 1 }])
                .await
                .iter()
                .all(|(_, result)| access_decision(result) == expected));
        }
    }
}

#[tokio::test]
async fn dormant_veto_descendant_does_not_override_all_of_pass_or_steal_attribution() {
    let session = EvaluationSession::empty();
    let mut checker = PermissionChecker::new();
    checker.add_veto(VetoLeaf([Truth::Yes; 3]).all_of(VetoLeaf([Truth::No; 3])));
    checker.add_policy(GrantLeaf([Truth::Yes; 3]));
    let result = bind(&checker, &session).check(&Resource { id: 0 }).await;
    assert!(result.is_granted());
    assert_eq!(result.forbidden_by(), None);
    checker.add_veto(PolicyBuilder::<Domain>::new("ActiveVeto").build_veto());
    let denied = bind(&checker, &session).check(&Resource { id: 0 }).await;
    denied.assert_forbidden_by("ActiveVeto");
    assert_eq!(
        denied.denied_reason(),
        Some("Forbidden by ActiveVeto: Policy forbids access")
    );
}

#[tokio::test]
async fn vetoes_run_in_registration_order_before_grants_and_stop_after_definite_veto() {
    struct NamedVeto {
        name: &'static str,
        truth: Truth,
    }
    #[async_trait]
    impl VetoPolicy<Domain> for NamedVeto {
        async fn evaluate(&self, ctx: &EvalCtx<'_, Domain>) -> VetoResult {
            match self.truth {
                Truth::Yes => ctx.forbid("blocked"),
                Truth::No => ctx.pass("passed"),
                Truth::Unknown => ctx.veto_indeterminate("unavailable"),
            }
        }
        fn policy_type(&self) -> std::borrow::Cow<'static, str> {
            self.name.into()
        }
    }
    let mut checker = PermissionChecker::new();
    checker.add_policy(allow_everything("GrantAfterVetoes"));
    checker.add_veto(NamedVeto {
        name: "FirstVeto",
        truth: Truth::No,
    });
    checker.add_veto(NamedVeto {
        name: "SecondVeto",
        truth: Truth::No,
    });
    let session = EvaluationSession::empty();
    let result = bind(&checker, &session).check(&Resource { id: 0 }).await;
    let trace = result.trace().format();
    assert!(trace.find("FirstVeto").unwrap() < trace.find("SecondVeto").unwrap());
    assert!(trace.find("SecondVeto").unwrap() < trace.find("GrantAfterVetoes").unwrap());
    checker.add_veto(NamedVeto {
        name: "UnresolvedVeto",
        truth: Truth::Unknown,
    });
    checker.add_veto(NamedVeto {
        name: "DefiniteVeto",
        truth: Truth::Yes,
    });
    checker.add_veto(NamedVeto {
        name: "SkippedVeto",
        truth: Truth::Yes,
    });
    let result = bind(&checker, &session).check(&Resource { id: 0 }).await;
    result.assert_forbidden_by("DefiniteVeto");
    assert!(!result.trace().format().contains("SkippedVeto"));
    assert!(!result.trace().format().contains("GrantAfterVetoes"));
    for (_, result) in bind(&checker, &session)
        .evaluate(vec![Resource { id: 0 }, Resource { id: 1 }])
        .await
    {
        result.assert_forbidden_by("DefiniteVeto");
        assert!(!result.trace().format().contains("SkippedVeto"));
        assert!(!result.trace().format().contains("GrantAfterVetoes"));
    }
}

#[tokio::test]
async fn not_preserves_uncertainty_and_inverts_only_definite_results() {
    let session = EvaluationSession::empty();
    for (input, expected) in [
        (Truth::Yes, Decision::NotApplicable),
        (Truth::No, Decision::Grant),
        (Truth::Unknown, Decision::Indeterminate),
    ] {
        let policy = GrantLeaf([input; 3]).not();
        let resource = Resource { id: 0 };
        let ctx = EvalCtx::new(&session, &Subject, &Action, &resource, &Ctx, "Not");
        let items = [PolicyBatchItem {
            resource: &resource,
        }];
        let batch = BatchEvalCtx::new(&session, &Subject, &Action, &Ctx, &items, "Not");
        assert_eq!(policy.evaluate(&ctx).await.decision(), expected);
        assert_eq!(policy.evaluate_batch(&batch).await[0].decision(), expected);
    }
}

#[tokio::test]
async fn checker_clone_preserves_vetoes_delegates_and_batch_limit() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut child = PermissionChecker::new();
    child.add_veto(VetoLeaf([Truth::No, Truth::Yes, Truth::No]));
    child.add_policy(BatchGrantPolicy {
        name: "Batched",
        batch_calls: Arc::new(AtomicUsize::new(0)),
        single_calls: Arc::new(AtomicUsize::new(0)),
        seen_batches: seen.clone(),
        grant: Arc::new(|_| true),
    });
    let mut checker =
        PermissionChecker::named("Cloned").with_max_batch_size(NonZeroUsize::new(2).unwrap());
    checker.add_delegate(identity_delegate(child));
    let cloned = checker.clone();
    let session = EvaluationSession::empty();
    let results = bind(&cloned, &session)
        .evaluate((0..8).map(|id| Resource { id }))
        .await;
    assert_eq!(
        results
            .iter()
            .map(|(_, result)| result.is_granted())
            .collect::<Vec<_>>(),
        vec![true, false, true, true, false, true, true, false]
    );
    assert!(seen.lock().unwrap().iter().all(|batch| batch.len() <= 2));
    assert_eq!(
        seen.lock()
            .unwrap()
            .iter()
            .flatten()
            .copied()
            .collect::<Vec<_>>(),
        vec![0, 2, 3, 5, 6]
    );
    assert_eq!(cloned.name(), Some("Cloned"));
}

#[tokio::test]
async fn veto_recording_upgrades_failed_pass_and_preserves_definite_forbid() {
    struct FactVeto(bool);
    #[async_trait]
    impl VetoPolicy<Domain> for FactVeto {
        async fn evaluate(&self, ctx: &EvalCtx<'_, Domain>) -> VetoResult {
            let _ = ctx.fact(OddFlag(ctx.resource.id)).await;
            if self.0 {
                VetoResult::forbid("FactVeto", "blocked")
            } else {
                VetoResult::pass("FactVeto", "pass")
            }
        }
        async fn evaluate_batch<'item>(
            &self,
            ctx: &BatchEvalCtx<'item, Domain>,
        ) -> Vec<VetoResult> {
            let _ = ctx.facts_by(|resource| OddFlag(resource.id)).await;
            ctx.items
                .iter()
                .map(|_| {
                    if self.0 {
                        VetoResult::forbid("FactVeto", "blocked")
                    } else {
                        VetoResult::pass("FactVeto", "pass")
                    }
                })
                .collect()
        }
        fn policy_type(&self) -> std::borrow::Cow<'static, str> {
            "FactVeto".into()
        }
    }
    for forbid in [false, true] {
        let mut checker = PermissionChecker::new();
        checker.add_veto(FactVeto(forbid));
        checker.add_policy(allow_everything("Allow"));
        let session = odd_flag_session([3]);
        let expected = if forbid {
            Decision::Forbid
        } else {
            Decision::Indeterminate
        };
        let result = bind(&checker, &session).check(&Resource { id: 3 }).await;
        assert_eq!(access_decision(&result), expected);
        assert_eq!(result.fact_load_errors().len(), 1);
        let result = bind(&checker, &session)
            .evaluate(vec![Resource { id: 3 }])
            .await
            .remove(0)
            .1;
        assert_eq!(access_decision(&result), expected);
        assert_eq!(result.fact_load_errors().len(), 1);
    }
}

#[tokio::test]
async fn veto_trait_objects_forward_batch_overrides_and_empty_inputs_are_not_evaluated() {
    struct BatchOnlyVeto;
    #[async_trait]
    impl VetoPolicy<Domain> for BatchOnlyVeto {
        async fn evaluate(&self, _ctx: &EvalCtx<'_, Domain>) -> VetoResult {
            panic!("batch override must be forwarded")
        }
        async fn evaluate_batch<'item>(
            &self,
            ctx: &BatchEvalCtx<'item, Domain>,
        ) -> Vec<VetoResult> {
            assert!(!ctx.items.is_empty());
            ctx.items
                .iter()
                .map(|_| VetoResult::pass("BatchOnlyVeto", "pass"))
                .collect()
        }
        fn policy_type(&self) -> std::borrow::Cow<'static, str> {
            "BatchOnlyVeto".into()
        }
    }
    let boxed: Box<dyn VetoPolicy<Domain>> = Box::new(BatchOnlyVeto);
    let shared: Arc<dyn VetoPolicy<Domain>> = Arc::new(boxed);
    let mut checker = PermissionChecker::new();
    checker.add_veto(shared);
    checker.add_policy(allow_everything("Allow"));
    let session = EvaluationSession::empty();
    assert!(bind(&checker, &session)
        .evaluate(Vec::<Resource>::new())
        .await
        .is_empty());
    assert!(bind(&checker, &session)
        .evaluate(vec![Resource { id: 0 }])
        .await
        .remove(0)
        .1
        .is_granted());
}

#[test]
fn empty_policy_combinators_are_rejected_and_empty_result_aggregates_abstain() {
    let error = AndPolicy::<Domain>::try_new(Vec::new())
        .err()
        .expect("empty conjunction must fail");
    assert_eq!(error.to_string(), "AndPolicy requires at least one policy");
    assert!(OrPolicy::<Domain>::try_new(Vec::new()).is_err());
    assert!(gatehouse::AllOfVeto::<Domain>::try_new(Vec::new()).is_err());
    assert!(gatehouse::AnyOfVeto::<Domain>::try_new(Vec::new()).is_err());
    assert_eq!(
        GrantResult::all("Empty", Vec::new()).decision(),
        Decision::NotApplicable
    );
    assert_eq!(
        GrantResult::any("Empty", Vec::new()).decision(),
        Decision::NotApplicable
    );
}

struct MappedValue(usize);
struct MappedDomain;
impl PolicyDomain for MappedDomain {
    type Subject = MappedValue;
    type Action = MappedValue;
    type Resource = MappedValue;
    type Context = MappedValue;
}
type MappedObservation = (char, usize, usize, usize, usize);
struct ObserveMapped {
    observed: Arc<Mutex<Vec<MappedObservation>>>,
    grants: bool,
}
#[async_trait]
impl Policy<MappedDomain> for ObserveMapped {
    async fn evaluate(&self, ctx: &EvalCtx<'_, MappedDomain>) -> GrantResult {
        self.observed.lock().unwrap().push((
            'G',
            ctx.subject.0,
            ctx.action.0,
            ctx.resource.0,
            ctx.context.0,
        ));
        if self.grants {
            ctx.grant("observed")
        } else {
            ctx.not_applicable("observed")
        }
    }
    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        "ObserveGrant".into()
    }
}
#[async_trait]
impl VetoPolicy<MappedDomain> for ObserveMapped {
    async fn evaluate(&self, ctx: &EvalCtx<'_, MappedDomain>) -> VetoResult {
        self.observed.lock().unwrap().push((
            'V',
            ctx.subject.0,
            ctx.action.0,
            ctx.resource.0,
            ctx.context.0,
        ));
        ctx.pass("observed")
    }
    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        "ObserveVeto".into()
    }
}

#[tokio::test]
async fn delegation_maps_once_across_capability_phases_and_batch_chunks() {
    let observed = Arc::new(Mutex::new(Vec::new()));
    let mut child = PermissionChecker::new();
    child.add_veto(ObserveMapped {
        observed: observed.clone(),
        grants: true,
    });
    child.add_policy(ObserveMapped {
        observed: observed.clone(),
        grants: true,
    });
    let counts: [Arc<AtomicUsize>; 4] = std::array::from_fn(|_| Arc::new(AtomicUsize::new(0)));
    let [subject_calls, action_calls, resource_calls, context_calls] = counts.clone();
    let delegate = DelegatingPolicy::new(
        "MappedOnce",
        child,
        move |_: &Subject| MappedValue(subject_calls.fetch_add(1, Ordering::SeqCst)),
        move |_: &Action| MappedValue(action_calls.fetch_add(1, Ordering::SeqCst)),
        move |_: &Subject, _: &Action, _: &Resource, _: &Ctx| {
            MappedValue(resource_calls.fetch_add(1, Ordering::SeqCst))
        },
        move |_: &Subject, _: &Action, _: &Ctx| {
            MappedValue(context_calls.fetch_add(1, Ordering::SeqCst))
        },
    );
    let mut checker = PermissionChecker::new().with_max_batch_size(NonZeroUsize::new(1).unwrap());
    checker.add_delegate(delegate);
    let session = EvaluationSession::empty();
    let results = bind(&checker, &session)
        .evaluate(vec![
            Resource { id: 0 },
            Resource { id: 0 },
            Resource { id: 1 },
        ])
        .await;
    assert!(results.iter().all(|(_, result)| result.is_granted()));
    assert_eq!(
        counts.each_ref().map(|count| count.load(Ordering::SeqCst)),
        [1, 1, 3, 1]
    );
    assert_eq!(
        *observed.lock().unwrap(),
        vec![
            ('V', 0, 0, 0, 0),
            ('V', 0, 0, 1, 0),
            ('V', 0, 0, 2, 0),
            ('G', 0, 0, 0, 0),
            ('G', 0, 0, 1, 0),
            ('G', 0, 0, 2, 0)
        ]
    );
    observed.lock().unwrap().clear();
    assert!(bind(&checker, &session)
        .check(&Resource { id: 0 })
        .await
        .is_granted());
    assert_eq!(
        counts.each_ref().map(|count| count.load(Ordering::SeqCst)),
        [2, 2, 4, 2]
    );
    assert_eq!(
        *observed.lock().unwrap(),
        vec![('V', 1, 1, 3, 1), ('G', 1, 1, 3, 1)]
    );
}

#[tokio::test]
async fn reused_child_checkers_keep_independent_nested_mapping_state() {
    let observed = Arc::new(Mutex::new(Vec::new()));
    let mut leaf = PermissionChecker::new();
    leaf.add_veto(ObserveMapped {
        observed: observed.clone(),
        grants: false,
    });
    leaf.add_policy(ObserveMapped {
        observed: observed.clone(),
        grants: false,
    });
    let mut middle = PermissionChecker::<MappedDomain>::new();
    middle.add_delegate(DelegatingPolicy::new(
        "Inner",
        leaf,
        |value: &MappedValue| MappedValue(value.0),
        |value: &MappedValue| MappedValue(value.0),
        |_: &MappedValue, _: &MappedValue, value: &MappedValue, _: &MappedValue| {
            MappedValue(value.0)
        },
        |_: &MappedValue, _: &MappedValue, value: &MappedValue| MappedValue(value.0),
    ));
    let mut parent = PermissionChecker::new();
    for offset in [10, 20] {
        parent.add_delegate(DelegatingPolicy::new(
            "Outer",
            middle.clone(),
            move |_: &Subject| MappedValue(offset),
            |_: &Action| MappedValue(0),
            move |_: &Subject, _: &Action, resource: &Resource, _: &Ctx| {
                MappedValue(offset + usize::from(resource.id))
            },
            |_: &Subject, _: &Action, _: &Ctx| MappedValue(0),
        ));
    }
    let session = EvaluationSession::empty();
    assert!(!bind(&parent, &session)
        .check(&Resource { id: 1 })
        .await
        .is_granted());
    assert_eq!(
        *observed.lock().unwrap(),
        vec![
            ('V', 10, 0, 11, 0),
            ('V', 20, 0, 21, 0),
            ('G', 10, 0, 11, 0),
            ('G', 20, 0, 21, 0)
        ]
    );
}

#[tokio::test]
async fn negation_preserves_failed_facts_nested_inside_custom_grant_aggregates() {
    struct AggregateWithFailedFact;
    #[async_trait]
    impl Policy<Domain> for AggregateWithFailedFact {
        async fn evaluate(&self, ctx: &EvalCtx<'_, Domain>) -> GrantResult {
            let leaf = ErrorBearingNotApplicablePolicy.evaluate(ctx).await;
            GrantResult::all("Outer", vec![GrantResult::any("Inner", vec![leaf])])
        }
        fn policy_type(&self) -> std::borrow::Cow<'static, str> {
            "AggregateWithFailedFact".into()
        }
    }
    let mut checker = PermissionChecker::new();
    checker.add_policy(AggregateWithFailedFact.not());
    let session = EvaluationSession::empty();
    let single = bind(&checker, &session).check(&Resource { id: 0 }).await;
    single.assert_indeterminate();
    assert_eq!(single.fact_load_errors().len(), 1);
    for (_, result) in bind(&checker, &session)
        .evaluate(vec![Resource { id: 0 }, Resource { id: 1 }])
        .await
    {
        result.assert_indeterminate();
        assert_eq!(result.fact_load_errors().len(), 1);
    }
}
