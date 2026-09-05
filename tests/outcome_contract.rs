use async_trait::async_trait;
use gatehouse::{
    AccessEvaluation, BatchEvalCtx, Decision, EvalCtx, EvaluationSession, FactLoadResult,
    FactOutcome, FactProvenance, FactSource, GrantResult, Hydrator, LookupAuthorizedError,
    LookupPage, LookupSource, PermissionChecker, Policy, PolicyBuilder, PolicyDomain, PolicyResult,
};
use std::{collections::HashSet, convert::Infallible, num::NonZeroUsize};
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
async fn evaluate_resources(
    checker: &PermissionChecker<Domain>,
    session: &EvaluationSession,
    resources: Vec<Resource>,
) -> Vec<(Resource, AccessEvaluation)> {
    bind(checker, session).evaluate(resources).await
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

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
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

#[tokio::test]
async fn typed_access_error_distinguishes_denial_from_outage() {
    let mut checker = PermissionChecker::new();
    checker.add_policy(HandBuiltOddPolicy);
    let session = odd_flag_session([3]);
    assert!(check_resource(&checker, &session, &Resource { id: 1 })
        .await
        .into_result()
        .is_ok());
    assert!(matches!(
        check_resource(&checker, &session, &Resource { id: 2 })
            .await
            .into_result(),
        Err(gatehouse::AccessError::Denied { .. })
    ));
    let error = check_resource(&checker, &session, &Resource { id: 3 })
        .await
        .into_result()
        .unwrap_err();
    assert!(matches!(
        error,
        gatehouse::AccessError::Indeterminate { .. }
    ));
    assert_eq!(error.fact_load_errors().len(), 1);
    assert_eq!(
        error.fact_load_errors()[0].error_kind,
        Some(gatehouse::FactLoadErrorKind::Backend)
    );
    assert!(error.to_string().contains("authorization indeterminate"));
}

#[tokio::test]
async fn strict_filters_keep_all_original_items_and_decisions_on_failure() {
    let mut checker = PermissionChecker::new();
    checker.add_policy(HandBuiltOddPolicy);
    let session = odd_flag_session([3]);
    let error = bind(&checker, &session)
        .try_filter(vec![
            Resource { id: 1 },
            Resource { id: 2 },
            Resource { id: 3 },
        ])
        .await
        .unwrap_err();
    assert_eq!(
        error
            .evaluations
            .iter()
            .map(|(item, _)| item.id)
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert!(error.evaluations[0].1.is_granted());
    error.evaluations[1].1.assert_denied();
    error.evaluations[2].1.assert_indeterminate();
    assert_eq!(error.evaluations[2].1.fact_load_errors().len(), 1);
    assert_eq!(
        error
            .indeterminate()
            .map(|(item, _)| item.id)
            .collect::<Vec<_>>(),
        [3]
    );

    let items = vec![
        ("one".to_string(), Resource { id: 1 }),
        ("three".to_string(), Resource { id: 3 }),
    ];
    let error = bind(&checker, &session)
        .try_filter_by(items, |item| &item.1)
        .await
        .unwrap_err();
    assert_eq!(error.evaluations[0].0 .0, "one");
    assert_eq!(error.evaluations[1].0 .0, "three");

    let allowed = bind(&checker, &session)
        .try_filter(vec![Resource { id: 1 }, Resource { id: 2 }])
        .await
        .unwrap();
    assert_eq!(allowed.iter().map(|item| item.id).collect::<Vec<_>>(), [1]);
    let allowed = bind(&checker, &session)
        .try_filter_by(
            vec![(1, Resource { id: 1 }), (2, Resource { id: 2 })],
            |item| &item.1,
        )
        .await
        .unwrap();
    assert_eq!(allowed.iter().map(|item| item.0).collect::<Vec<_>>(), [1]);
    assert!(bind(&checker, &session)
        .try_filter(Vec::<Resource>::new())
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn strict_filter_accepts_grant_after_irrelevant_allow_failure() {
    let mut checker = PermissionChecker::new();
    checker.add_policy(HandBuiltOddPolicy);
    checker.add_policy(
        PolicyBuilder::<Domain>::new("Override")
            .when(|_, _, _, _| true)
            .build(),
    );
    let session = odd_flag_session([3]);
    let allowed = bind(&checker, &session)
        .try_filter(vec![Resource { id: 3 }])
        .await
        .unwrap();
    assert_eq!(allowed[0].id, 3);
    assert!(check_resource(&checker, &session, &Resource { id: 3 })
        .await
        .into_result()
        .is_ok());
}

#[tokio::test]
async fn strict_lookup_fails_without_advancing_past_unresolved_page() {
    let mut checker = PermissionChecker::new();
    checker.add_policy(HandBuiltOddPolicy);
    let lookup = StaticLookup {
        ids: vec![1, 2, 3],
        next_cursor: Some(b"next".to_vec()),
    };
    let session = odd_flag_session([1, 3]);
    let error = bind(&checker, &session)
        .try_lookup_page(
            &lookup,
            &ResourceHydrator,
            Some(b"current"),
            NonZeroUsize::new(3).unwrap(),
        )
        .await
        .unwrap_err();
    let LookupAuthorizedError::Evaluation(error) = error else {
        panic!("expected authorization failure");
    };
    assert_eq!(
        error
            .evaluations
            .iter()
            .map(|(resource, _)| resource.id)
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert_eq!(
        error
            .evaluations
            .iter()
            .filter(|(_, evaluation)| evaluation.is_indeterminate())
            .count(),
        2
    );
    let recovered_session = odd_flag_session([]);
    let page = bind(&checker, &recovered_session)
        .try_lookup_page(
            &lookup,
            &ResourceHydrator,
            Some(b"current"),
            NonZeroUsize::new(3).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        page.resources
            .iter()
            .map(|resource| resource.id)
            .collect::<Vec<_>>(),
        [1, 3]
    );
    assert_eq!(page.next_cursor.as_deref(), Some(b"next".as_slice()));
}

struct RecordedAggregate {
    decision: Decision,
}

#[async_trait]
impl Policy<Domain> for RecordedAggregate {
    async fn evaluate(&self, ctx: &EvalCtx<'_, Domain>) -> GrantResult {
        ctx.fact(OddFlag(ctx.resource.id)).await;
        ctx.record(FactProvenance::new(
            "optional",
            "missing",
            FactOutcome::Missing,
            None,
        ));
        let child = if self.decision == Decision::Grant {
            GrantResult::granted("IndependentGrant", None)
        } else {
            GrantResult::not_applicable("IndependentAbstention", "does not apply")
        };
        GrantResult::all(self.policy_type(), vec![child]).attach_recorded(vec![
            FactProvenance::new("explicit", "last", FactOutcome::Found, None),
        ])
    }
    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        "RecordedAggregate".into()
    }
}

#[tokio::test]
async fn aggregate_provenance_is_lossless_and_decisive_grants_remain_decisive() {
    for decision in [Decision::Grant, Decision::NotApplicable] {
        let mut checker = PermissionChecker::new();
        checker.add_policy(RecordedAggregate { decision });
        let session = odd_flag_session([3]);
        for resource_id in [1, 3] {
            let single = check_resource(&checker, &session, &Resource { id: resource_id }).await;
            let batch = evaluate_resources(&checker, &session, vec![Resource { id: resource_id }])
                .await
                .remove(0)
                .1;
            for evaluation in [single, batch] {
                assert_eq!(evaluation.is_granted(), decision == Decision::Grant);
                assert_eq!(
                    evaluation.is_indeterminate(),
                    decision == Decision::NotApplicable && resource_id == 3
                );
                assert_eq!(
                    evaluation.fact_load_errors().len(),
                    usize::from(resource_id == 3)
                );
                let rendered = evaluation.trace().format();
                assert!(rendered.contains("fact odd_flag"));
                assert!(rendered.contains("fact optional [missing]"));
                assert!(rendered.contains("fact explicit [found]"));
                assert!(
                    rendered.find("fact odd_flag").unwrap()
                        < rendered.find("fact optional").unwrap()
                );
                assert!(
                    rendered.find("fact optional").unwrap()
                        < rendered.find("fact explicit").unwrap()
                );
            }
        }
    }
}

#[tokio::test]
async fn explicit_veto_is_a_typed_denial_and_is_excluded_from_strict_lists() {
    let mut checker = PermissionChecker::new();
    checker.add_policy(PolicyBuilder::<Domain>::new("Allow").build());
    checker.add_veto(
        PolicyBuilder::<Domain>::new("Block")
            .resources(|resource| resource.id == 2)
            .build_veto(),
    );
    let session = EvaluationSession::empty();
    let error = bind(&checker, &session)
        .check(&Resource { id: 2 })
        .await
        .into_result()
        .unwrap_err();
    assert!(matches!(error, gatehouse::AccessError::Denied { .. }));
    assert!(error.trace().format().contains("Block"));
    let allowed = bind(&checker, &session)
        .try_filter([Resource { id: 1 }, Resource { id: 2 }])
        .await
        .unwrap();
    assert_eq!(
        allowed
            .iter()
            .map(|resource| resource.id)
            .collect::<Vec<_>>(),
        [1]
    );
}

struct FailingLookup;

#[async_trait]
impl LookupSource<Domain> for FailingLookup {
    type Id = u8;
    type Error = std::io::Error;
    async fn lookup_page(
        &self,
        _: &Subject,
        _: &Action,
        _: &Ctx,
        _: Option<&[u8]>,
        _: NonZeroUsize,
    ) -> Result<LookupPage<u8>, Self::Error> {
        Err(std::io::Error::other("candidate backend unavailable"))
    }
}

#[tokio::test]
async fn strict_lookup_preserves_pipeline_failures_and_all_indeterminate_pages() {
    let mut checker = PermissionChecker::new();
    checker.add_policy(HandBuiltOddPolicy);
    let session = odd_flag_session([1, 3]);
    let bound = bind(&checker, &session);
    let limit = NonZeroUsize::new(2).unwrap();
    let error = bound
        .try_lookup_page(&FailingLookup, &ResourceHydrator, None, limit)
        .await
        .unwrap_err();
    assert!(
        matches!(error, LookupAuthorizedError::Lookup(error) if error.to_string() == "candidate backend unavailable")
    );

    let lookup = StaticLookup {
        ids: vec![1, 3],
        next_cursor: Some(b"next".to_vec()),
    };
    let failing_hydrator = |_: &[u8]| async {
        Err::<Vec<Option<Resource>>, _>(std::io::Error::other("resource backend unavailable"))
    };
    let error = bound
        .try_lookup_page(&lookup, &failing_hydrator, None, limit)
        .await
        .unwrap_err();
    assert!(
        matches!(error, LookupAuthorizedError::Hydrate(error) if error.to_string() == "resource backend unavailable")
    );

    let short_hydrator = |_: &[u8]| async { Ok::<Vec<Option<Resource>>, Infallible>(vec![]) };
    let error = bound
        .try_lookup_page(&lookup, &short_hydrator, None, limit)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        LookupAuthorizedError::HydratorContractViolation {
            expected: 2,
            actual: 0
        }
    ));

    let error = bound
        .try_lookup_page(&lookup, &ResourceHydrator, Some(b"next"), limit)
        .await
        .unwrap_err();
    assert!(matches!(error, LookupAuthorizedError::LookupCursorStuck));

    let error = bound
        .try_lookup_page(&lookup, &ResourceHydrator, None, limit)
        .await
        .unwrap_err();
    let LookupAuthorizedError::Evaluation(error) = error else {
        panic!("expected evaluation failure");
    };
    assert_eq!(
        error
            .indeterminate()
            .map(|(resource, _)| resource.id)
            .collect::<Vec<_>>(),
        [1, 3]
    );
}

#[tokio::test]
async fn strict_errors_support_borrowed_non_debug_rows() {
    struct Row<'a> {
        resource: Resource,
        label: &'a str,
    }
    fn as_standard_error<'a>(
        error: impl std::error::Error + 'a,
    ) -> Box<dyn std::error::Error + 'a> {
        Box::new(error)
    }
    let label = String::from("caller-owned data");
    let mut checker = PermissionChecker::new();
    checker.add_policy(HandBuiltOddPolicy);
    let session = odd_flag_session([3]);
    let result = bind(&checker, &session)
        .try_filter_by(
            vec![Row {
                resource: Resource { id: 3 },
                label: &label,
            }],
            |row| &row.resource,
        )
        .await;
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("unavailable fact must fail the strict filter"),
    };
    assert_eq!(error.evaluations[0].0.label, label);
    assert!(format!("{error:?}").contains("Indeterminate"));
    let error = as_standard_error(error);
    assert!(error
        .to_string()
        .contains("could not determine authorization"));

    let error: LookupAuthorizedError<Infallible, Infallible, Row<'_>> =
        LookupAuthorizedError::Evaluation(gatehouse::FilterError {
            evaluations: vec![(
                Row {
                    resource: Resource { id: 3 },
                    label: &label,
                },
                AccessEvaluation::Indeterminate {
                    reason: "offline".into(),
                    trace: gatehouse::EvalTrace::new(),
                },
            )],
        });
    assert!(!format!("{error:?}").contains(&label));
    let error = as_standard_error(error);
    assert!(error.source().is_none());
}

struct ExplicitFailure {
    aggregate: bool,
}

#[async_trait]
impl Policy<Domain> for ExplicitFailure {
    async fn evaluate(&self, _: &EvalCtx<'_, Domain>) -> GrantResult {
        let result = GrantResult::not_applicable_with_facts(
            "ExplicitFailure",
            "membership not established",
            vec![FactProvenance::from_load_result(
                "membership",
                "subject",
                &FactLoadResult::<bool>::Error(gatehouse::FactLoadError::backend_message(
                    "private backend detail",
                )),
            )],
        );
        if self.aggregate {
            GrantResult::all("EvidenceAggregate", vec![result])
        } else {
            result
        }
    }
    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        "ExplicitFailure".into()
    }
}

#[tokio::test]
async fn indeterminate_attribution_retains_aggregate_and_negated_fact_causes() {
    use gatehouse::PolicyExt;
    let mut aggregate = PermissionChecker::new();
    aggregate.add_policy(RecordedAggregate {
        decision: Decision::NotApplicable,
    });
    let mut negated = PermissionChecker::new();
    negated.add_policy(ExplicitFailure { aggregate: false }.not().not());
    let mut negated_aggregate = PermissionChecker::new();
    negated_aggregate.add_policy(ExplicitFailure { aggregate: true }.not().not());
    let session = odd_flag_session([3]);
    for (checker, expected_policy) in [
        (&aggregate, "RecordedAggregate"),
        (&negated, "ExplicitFailure"),
        (&negated_aggregate, "ExplicitFailure"),
    ] {
        let single = check_resource(checker, &session, &Resource { id: 3 }).await;
        let batch = evaluate_resources(checker, &session, vec![Resource { id: 3 }])
            .await
            .remove(0)
            .1;
        for evaluation in [single, batch] {
            evaluation.assert_indeterminate();
            assert_eq!(evaluation.fact_load_errors().len(), 1);
            assert_eq!(evaluation.indeterminate_reason(), Some(format!("Could not evaluate {expected_policy}: A consulted fact could not be loaded").as_str()));
            assert!(!evaluation.to_string().contains("private backend detail"));
        }
    }
}

struct ResolvedThenUnknown;

#[async_trait]
impl Policy<Domain> for ResolvedThenUnknown {
    async fn evaluate(&self, _: &EvalCtx<'_, Domain>) -> GrantResult {
        GrantResult::any(
            "Outer",
            vec![
                GrantResult::all(
                    "Resolved",
                    vec![
                        GrantResult::not_applicable("DefiniteNonMatch", "not applicable"),
                        GrantResult::indeterminate("InactiveFailure", "irrelevant failure"),
                    ],
                )
                .attach_recorded(vec![FactProvenance::new(
                    "optional",
                    "key",
                    FactOutcome::Found,
                    None,
                )]),
                GrantResult::indeterminate("ActiveFailure", "required input unavailable"),
            ],
        )
    }
    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        "ResolvedThenUnknown".into()
    }
}

#[tokio::test]
async fn indeterminate_attribution_skips_resolved_subtrees() {
    let mut checker = PermissionChecker::new();
    checker.add_policy(ResolvedThenUnknown);
    let session = EvaluationSession::empty();
    let evaluation = check_resource(&checker, &session, &Resource { id: 0 }).await;
    evaluation.assert_indeterminate();
    assert_eq!(
        evaluation.indeterminate_reason(),
        Some("Could not evaluate ActiveFailure: required input unavailable")
    );
}
