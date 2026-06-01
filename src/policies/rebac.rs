use crate::{
    BatchEvalCtx, EvalCtx, FactKey, FactLoadResult, FactOutcome, FactProvenance, Policy,
    PolicyEvalResult, RelationshipQuery,
};
use async_trait::async_trait;
use std::fmt;
use std::hash::Hash;
use std::sync::Arc;

/// ### ReBAC Policy
///
/// ReBAC is backed by [`crate::FactSource`] in v0.3. A policy extracts flat,
/// hashable IDs from the subject and resource, builds a [`RelationshipQuery`],
/// then loads relationship facts through the request-scoped
/// [`crate::EvaluationSession`].
///
/// The `Relation` type can be a domain enum rather than a string. That keeps
/// policy code type-safe while leaving backend-specific serialization inside
/// the [`crate::FactSource`]. For example, a SQL-backed source can load
/// `RelationshipQuery<Uuid, Uuid, Relation>` keys and convert
/// `Relation::Viewer` to a `text` column value only when binding query
/// parameters. The session deduplicates and caches by the typed key, not by the
/// serialized storage representation.
///
/// When several relationship domains have the same ID shape, such as
/// `Uuid -> Uuid`, use a domain relation enum and dispatch inside one
/// `FactSource`, or newtype the IDs so each domain has a distinct
/// `RelationshipQuery` type and therefore a distinct session registration.
///
/// `RebacPolicy` is the convenience policy for boolean relationship checks. If
/// a relationship carries payload, such as rank, weight, or a scope set, define
/// a custom [`crate::FactKey`] with `Value = YourPayload` and write a [`crate::Policy`] that
/// interprets the loaded value.
///
/// `Relation` must implement [`fmt::Display`] so Gatehouse can produce
/// human-readable denial reasons and traces. The subject and resource ID types
/// must implement [`fmt::Debug`] so the consulted relationship can be rendered
/// into the [`crate::FactProvenance`] attached to each decision; common ID
/// types (`Uuid`, `String`, integers) already satisfy this, but a custom ID
/// newtype must `#[derive(Debug)]` or it will fail to satisfy the `Policy`
/// bound. Backend serialization should live in the [`crate::FactSource`], not
/// in the `Debug`/`Display` output, unless that is explicitly your storage
/// format.
///
/// **Provenance/log safety.** The rendered relationship inside
/// [`crate::FactProvenance::key`] uses the `Debug` output of your ID types
/// verbatim. If those IDs carry fields that should not be written to audit
/// logs (e.g. a token, a tenant secret), implement `Debug` manually to
/// redact them before this policy is used in a checker whose decisions are
/// persisted.
///
/// ```rust
/// use async_trait::async_trait;
/// use std::collections::HashSet;
/// use uuid::Uuid;
/// use gatehouse::*;
///
/// #[derive(Debug, Clone)]
/// pub struct Employee { pub id: Uuid }
///
/// #[derive(Debug, Clone)]
/// pub struct Project { pub id: Uuid }
///
/// #[derive(Debug, Clone)]
/// pub struct AccessAction;
///
/// #[derive(Debug, Clone)]
/// pub struct EmptyContext;
///
/// struct ProjectRelationships {
///     grants: HashSet<RelationshipQuery<Uuid, Uuid, String>>,
/// }
///
/// #[async_trait]
/// impl FactSource<RelationshipQuery<Uuid, Uuid, String>> for ProjectRelationships {
///     async fn load_many(
///         &self,
///         keys: &[RelationshipQuery<Uuid, Uuid, String>],
///     ) -> Vec<FactLoadResult<bool>> {
///         keys.iter()
///             .map(|key| FactLoadResult::Found(self.grants.contains(key)))
///             .collect()
///     }
/// }
///
/// let manager = Employee { id: Uuid::new_v4() };
/// let project = Project { id: Uuid::new_v4() };
/// let relationship = "manager".to_string();
/// let grants = HashSet::from([RelationshipQuery {
///     subject_id: manager.id,
///     resource_id: project.id,
///     relation: relationship.clone(),
/// }]);
///
/// let session = EvaluationSession::new();
/// session.register::<RelationshipQuery<Uuid, Uuid, String>, _>(ProjectRelationships { grants });
///
/// let rebac_policy = RebacPolicy::new(
///     |employee: &Employee| employee.id,
///     |project: &Project| project.id,
///     relationship,
/// );
///
/// let mut checker = PermissionChecker::<Employee, Project, AccessAction, EmptyContext>::new();
/// checker.add_policy(rebac_policy);
///
/// # tokio_test::block_on(async {
/// assert!(checker
///     .evaluate_in_session(&session, &manager, &AccessAction, &project, &EmptyContext)
///     .await
///     .is_granted());
/// # });
/// ```
pub struct RebacPolicy<S, R, A, C, SubjectId, ResourceId, Relation> {
    subject_id: Arc<dyn Fn(&S) -> SubjectId + Send + Sync>,
    resource_id: Arc<dyn Fn(&R) -> ResourceId + Send + Sync>,
    relation: Relation,
    _marker: std::marker::PhantomData<(A, C)>,
}

impl<S, R, A, C, SubjectId, ResourceId, Relation>
    RebacPolicy<S, R, A, C, SubjectId, ResourceId, Relation>
{
    /// Creates a ReBAC policy from subject/resource ID extractors and a relation.
    pub fn new<SubjectIdFn, ResourceIdFn>(
        subject_id: SubjectIdFn,
        resource_id: ResourceIdFn,
        relation: Relation,
    ) -> Self
    where
        SubjectIdFn: Fn(&S) -> SubjectId + Send + Sync + 'static,
        ResourceIdFn: Fn(&R) -> ResourceId + Send + Sync + 'static,
    {
        Self {
            subject_id: Arc::new(subject_id),
            resource_id: Arc::new(resource_id),
            relation,
            _marker: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<S, R, A, C, SubjectId, ResourceId, Relation> Policy<S, R, A, C>
    for RebacPolicy<S, R, A, C, SubjectId, ResourceId, Relation>
where
    S: Sync + Send,
    R: Sync + Send,
    A: Sync + Send,
    C: Sync + Send,
    SubjectId: Eq + Hash + Clone + Send + Sync + fmt::Debug + 'static,
    ResourceId: Eq + Hash + Clone + Send + Sync + fmt::Debug + 'static,
    Relation: Eq + Hash + Clone + Send + Sync + fmt::Display + 'static,
{
    async fn evaluate(&self, ctx: &EvalCtx<'_, S, R, A, C>) -> PolicyEvalResult {
        // Capture the FactKey::NAME here so `result_from_fact` does not need
        // to carry the full FactKey trait bound on its impl block.
        let fact_name = <RelationshipQuery<SubjectId, ResourceId, Relation> as FactKey>::NAME;
        let key = RelationshipQuery {
            subject_id: (self.subject_id)(ctx.subject),
            resource_id: (self.resource_id)(ctx.resource),
            relation: self.relation.clone(),
        };
        let key_repr = Self::render_key(&key);
        self.result_from_fact(fact_name, &key_repr, ctx.session.get(key).await)
    }

    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, S, R, A, C>,
    ) -> Vec<PolicyEvalResult> {
        let fact_name = <RelationshipQuery<SubjectId, ResourceId, Relation> as FactKey>::NAME;
        let subject_id = (self.subject_id)(ctx.subject);
        let keys = ctx
            .items
            .iter()
            .map(|item| RelationshipQuery {
                subject_id: subject_id.clone(),
                resource_id: (self.resource_id)(item.resource),
                relation: self.relation.clone(),
            })
            .collect::<Vec<_>>();

        let facts = ctx.session.get_many(&keys).await;
        if facts.len() != ctx.items.len() {
            return ctx
                .items
                .iter()
                .map(|_| {
                    PolicyEvalResult::denied(
                        self.policy_type().to_string(),
                        "Relationship fact source returned the wrong number of results",
                    )
                })
                .collect();
        }

        keys.iter()
            .zip(facts)
            .map(|(key, fact)| self.result_from_fact(fact_name, &Self::render_key(key), fact))
            .collect()
    }

    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("RebacPolicy")
    }
}

impl<S, R, A, C, SubjectId, ResourceId, Relation>
    RebacPolicy<S, R, A, C, SubjectId, ResourceId, Relation>
where
    SubjectId: fmt::Debug,
    ResourceId: fmt::Debug,
    Relation: fmt::Display,
{
    /// Renders a relationship key for the [`FactProvenance`] attached to a
    /// decision node, e.g. `User(42) -[owner]-> Doc(7)`.
    fn render_key(key: &RelationshipQuery<SubjectId, ResourceId, Relation>) -> String {
        format!(
            "{:?} -[{}]-> {:?}",
            key.subject_id, key.relation, key.resource_id
        )
    }

    fn result_from_fact(
        &self,
        fact_name: &'static str,
        key_repr: &str,
        fact: FactLoadResult<bool>,
    ) -> PolicyEvalResult {
        let outcome = FactOutcome::from_load_result(&fact);
        let detail = match &fact {
            FactLoadResult::Error(error) => Some(error.to_string()),
            _ => None,
        };
        // `fact_name` is captured from `<RelationshipQuery as FactKey>::NAME`
        // at the Policy impl call site, so the provenance label tracks the
        // typed key rather than a hardcoded literal that could silently
        // drift if `RelationshipQuery::NAME` ever changes.
        let provenance = vec![FactProvenance::new(fact_name, key_repr, outcome, detail)];

        match fact {
            FactLoadResult::Found(true) => PolicyEvalResult::granted_with_facts(
                "RebacPolicy",
                Some(format!(
                    "Subject has '{}' relationship with resource",
                    self.relation
                )),
                provenance,
            ),
            FactLoadResult::Found(false) => PolicyEvalResult::denied_with_facts(
                "RebacPolicy",
                format!(
                    "Subject does not have '{}' relationship with resource",
                    self.relation
                ),
                provenance,
            ),
            FactLoadResult::Missing => PolicyEvalResult::denied_with_facts(
                "RebacPolicy",
                format!("Relationship '{}' fact is missing", self.relation),
                provenance,
            ),
            FactLoadResult::Error(error) => PolicyEvalResult::denied_with_facts(
                "RebacPolicy",
                format!("Relationship '{}' fact load failed: {error}", self.relation),
                provenance,
            ),
        }
    }
}
