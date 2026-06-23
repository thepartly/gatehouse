use crate::{
    BatchEvalCtx, EvalCtx, FactKey, FactLoadResult, FactOutcome, FactProvenance, Policy,
    PolicyDomain, PolicyEvalResult, RelationshipQuery,
};
use async_trait::async_trait;
use std::fmt;
use std::hash::Hash;
use std::marker::PhantomData;
use std::sync::Arc;

/// Relationship-based access control backed by request-scoped fact loading.
pub struct RebacPolicy<D: PolicyDomain, SubjectId, ResourceId, Relation> {
    subject_id: Arc<dyn Fn(&D::Subject) -> SubjectId + Send + Sync>,
    resource_id: Arc<dyn Fn(&D::Resource) -> ResourceId + Send + Sync>,
    relation: Relation,
    _domain: PhantomData<D>,
}

impl<D: PolicyDomain, SubjectId, ResourceId, Relation>
    RebacPolicy<D, SubjectId, ResourceId, Relation>
{
    /// Creates a ReBAC policy from subject/resource ID extractors and a relation.
    pub fn new<SubjectIdFn, ResourceIdFn>(
        subject_id: SubjectIdFn,
        resource_id: ResourceIdFn,
        relation: Relation,
    ) -> Self
    where
        SubjectIdFn: Fn(&D::Subject) -> SubjectId + Send + Sync + 'static,
        ResourceIdFn: Fn(&D::Resource) -> ResourceId + Send + Sync + 'static,
    {
        Self {
            subject_id: Arc::new(subject_id),
            resource_id: Arc::new(resource_id),
            relation,
            _domain: PhantomData,
        }
    }
}

#[async_trait]
impl<D, SubjectId, ResourceId, Relation> Policy<D>
    for RebacPolicy<D, SubjectId, ResourceId, Relation>
where
    D: PolicyDomain,
    SubjectId: Eq + Hash + Clone + Send + Sync + fmt::Debug + 'static,
    ResourceId: Eq + Hash + Clone + Send + Sync + fmt::Debug + 'static,
    Relation: Eq + Hash + Clone + Send + Sync + fmt::Display + 'static,
{
    async fn evaluate(&self, ctx: &EvalCtx<'_, D>) -> PolicyEvalResult {
        let fact_name = <RelationshipQuery<SubjectId, ResourceId, Relation> as FactKey>::NAME;
        let key = RelationshipQuery {
            subject_id: (self.subject_id)(ctx.subject),
            resource_id: (self.resource_id)(ctx.resource),
            relation: self.relation.clone(),
        };
        let key_repr = Self::render_key(&key);
        self.result_from_fact(fact_name, &key_repr, ctx.session.get(key).await)
    }

    async fn evaluate_batch<'item>(&self, ctx: &BatchEvalCtx<'item, D>) -> Vec<PolicyEvalResult> {
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
                    PolicyEvalResult::not_applicable(
                        self.policy_type(),
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

impl<D, SubjectId, ResourceId, Relation> RebacPolicy<D, SubjectId, ResourceId, Relation>
where
    D: PolicyDomain,
    SubjectId: fmt::Debug,
    ResourceId: fmt::Debug,
    Relation: fmt::Display,
{
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
            FactLoadResult::Found(false) => PolicyEvalResult::not_applicable_with_facts(
                "RebacPolicy",
                format!(
                    "Subject does not have '{}' relationship with resource",
                    self.relation
                ),
                provenance,
            ),
            FactLoadResult::Missing => PolicyEvalResult::not_applicable_with_facts(
                "RebacPolicy",
                format!("Relationship '{}' fact is missing", self.relation),
                provenance,
            ),
            FactLoadResult::Error(error) => PolicyEvalResult::not_applicable_with_facts(
                "RebacPolicy",
                format!("Relationship '{}' fact load failed: {error}", self.relation),
                provenance,
            ),
        }
    }
}
