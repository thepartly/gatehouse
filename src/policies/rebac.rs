use crate::{
    BatchEvalCtx, EvalCtx, FactLoadError, FactLoadResult, Policy, PolicyDomain, PolicyEvalResult,
    RelationshipQuery,
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
    Relation: Eq + Hash + Clone + Send + Sync + fmt::Display + fmt::Debug + 'static,
{
    async fn evaluate(&self, ctx: &EvalCtx<'_, D>) -> PolicyEvalResult {
        let key = RelationshipQuery {
            subject_id: (self.subject_id)(ctx.subject),
            resource_id: (self.resource_id)(ctx.resource),
            relation: self.relation.clone(),
        };
        // `ctx.fact` records provenance; the ctx result helpers attach it.
        match ctx.fact(key).await {
            FactLoadResult::Found(true) => ctx.grant(self.granted_reason()),
            FactLoadResult::Found(false) => ctx.not_applicable(self.no_relationship_reason()),
            FactLoadResult::Missing => ctx.not_applicable(self.missing_reason()),
            FactLoadResult::Error(error) => ctx.indeterminate(self.error_reason(&error)),
        }
    }

    async fn evaluate_batch<'item>(&self, ctx: &BatchEvalCtx<'item, D>) -> Vec<PolicyEvalResult> {
        let subject_id = (self.subject_id)(ctx.subject);
        // `facts_by` performs one deduplicated `get_many` and records
        // provenance against each originating item; the caller's
        // `BatchEvalCtx::finish` merges it into the per-item results below.
        let facts = ctx
            .facts_by(|resource| RelationshipQuery {
                subject_id: subject_id.clone(),
                resource_id: (self.resource_id)(resource),
                relation: self.relation.clone(),
            })
            .await;
        if facts.len() != ctx.items.len() {
            return ctx
                .items
                .iter()
                .map(|_| {
                    PolicyEvalResult::indeterminate(
                        self.policy_type(),
                        "Relationship fact source returned the wrong number of results",
                    )
                })
                .collect();
        }

        facts
            .into_iter()
            .map(|fact| self.result_from_fact(ctx.policy_type.clone(), fact))
            .collect()
    }

    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("RebacPolicy")
    }
}

impl<D, SubjectId, ResourceId, Relation> RebacPolicy<D, SubjectId, ResourceId, Relation>
where
    D: PolicyDomain,
    Relation: fmt::Display,
{
    fn granted_reason(&self) -> String {
        format!("Subject has '{}' relationship with resource", self.relation)
    }

    fn no_relationship_reason(&self) -> String {
        format!(
            "Subject does not have '{}' relationship with resource",
            self.relation
        )
    }

    fn missing_reason(&self) -> String {
        format!("Relationship '{}' fact is missing", self.relation)
    }

    fn error_reason(&self, error: &FactLoadError) -> String {
        format!("Relationship '{}' fact load failed: {error}", self.relation)
    }

    fn result_from_fact(
        &self,
        policy_type: std::borrow::Cow<'static, str>,
        fact: FactLoadResult<bool>,
    ) -> PolicyEvalResult {
        match fact {
            FactLoadResult::Found(true) => {
                PolicyEvalResult::granted(policy_type, Some(self.granted_reason()))
            }
            FactLoadResult::Found(false) => {
                PolicyEvalResult::not_applicable(policy_type, self.no_relationship_reason())
            }
            FactLoadResult::Missing => {
                PolicyEvalResult::not_applicable(policy_type, self.missing_reason())
            }
            // Fail closed, but structurally: the relationship could not be
            // loaded, so the policy could not decide. This surfaces as
            // `AccessEvaluation::Indeterminate` rather than an ordinary
            // denial, letting callers map an authorization-data outage to a
            // 5xx instead of a 403.
            FactLoadResult::Error(error) => {
                PolicyEvalResult::indeterminate(policy_type, self.error_reason(&error))
            }
        }
    }
}
