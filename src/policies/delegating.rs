use crate::{
    AccessEvaluation, BatchEvalCtx, CombineOp, Effect, EvalCtx, PermissionChecker, Policy,
    PolicyDomain, PolicyEvalResult, SecurityRuleMetadata, PERMISSION_CHECKER_POLICY_TYPE,
};
use async_trait::async_trait;
use std::sync::Arc;

fn delegated_evaluation_to_result(
    policy_type: std::borrow::Cow<'static, str>,
    evaluation: AccessEvaluation,
) -> PolicyEvalResult {
    match evaluation {
        AccessEvaluation::Granted {
            policy_type: child_policy_type,
            reason,
            trace,
        } => PolicyEvalResult::Combined {
            policy_type,
            operation: CombineOp::Delegate,
            children: vec![trace
                .root()
                .cloned()
                .unwrap_or(PolicyEvalResult::granted(child_policy_type, reason))],
            outcome: true,
        },
        AccessEvaluation::Denied { reason, trace } => PolicyEvalResult::Combined {
            policy_type,
            operation: CombineOp::Delegate,
            children: vec![trace
                .root()
                .cloned()
                .unwrap_or(PolicyEvalResult::not_applicable(
                    PERMISSION_CHECKER_POLICY_TYPE,
                    reason,
                ))],
            outcome: false,
        },
    }
}

/// A policy that maps the current domain into a child domain and delegates to
/// another [`PermissionChecker`].
pub struct DelegatingPolicy<ParentD: PolicyDomain, ChildD: PolicyDomain> {
    policy_type: std::borrow::Cow<'static, str>,
    security_rule: SecurityRuleMetadata,
    checker: PermissionChecker<ChildD>,
    subject: Arc<dyn Fn(&ParentD::Subject) -> ChildD::Subject + Send + Sync>,
    action: Arc<dyn Fn(&ParentD::Action) -> ChildD::Action + Send + Sync>,
    resource: Arc<
        dyn Fn(
                &ParentD::Subject,
                &ParentD::Action,
                &ParentD::Resource,
                &ParentD::Context,
            ) -> ChildD::Resource
            + Send
            + Sync,
    >,
    context: Arc<
        dyn Fn(&ParentD::Subject, &ParentD::Action, &ParentD::Context) -> ChildD::Context
            + Send
            + Sync,
    >,
}

impl<ParentD: PolicyDomain, ChildD: PolicyDomain> DelegatingPolicy<ParentD, ChildD> {
    /// Creates a delegating policy from a child checker and mapping functions.
    pub fn new<SubjectFn, ActionFn, ResourceFn, ContextFn>(
        policy_type: impl Into<std::borrow::Cow<'static, str>>,
        checker: PermissionChecker<ChildD>,
        subject: SubjectFn,
        action: ActionFn,
        resource: ResourceFn,
        context: ContextFn,
    ) -> Self
    where
        SubjectFn: Fn(&ParentD::Subject) -> ChildD::Subject + Send + Sync + 'static,
        ActionFn: Fn(&ParentD::Action) -> ChildD::Action + Send + Sync + 'static,
        ResourceFn: Fn(
                &ParentD::Subject,
                &ParentD::Action,
                &ParentD::Resource,
                &ParentD::Context,
            ) -> ChildD::Resource
            + Send
            + Sync
            + 'static,
        ContextFn: Fn(&ParentD::Subject, &ParentD::Action, &ParentD::Context) -> ChildD::Context
            + Send
            + Sync
            + 'static,
    {
        Self {
            policy_type: policy_type.into(),
            security_rule: SecurityRuleMetadata::default(),
            checker,
            subject: Arc::new(subject),
            action: Arc::new(action),
            resource: Arc::new(resource),
            context: Arc::new(context),
        }
    }

    /// Sets the telemetry metadata emitted for the delegating policy itself.
    pub fn with_security_rule(mut self, security_rule: SecurityRuleMetadata) -> Self {
        self.security_rule = security_rule;
        self
    }
}

#[async_trait]
impl<ParentD, ChildD> Policy<ParentD> for DelegatingPolicy<ParentD, ChildD>
where
    ParentD: PolicyDomain,
    ChildD: PolicyDomain,
{
    async fn evaluate(&self, ctx: &EvalCtx<'_, ParentD>) -> PolicyEvalResult {
        let child_subject = (self.subject)(ctx.subject);
        let child_action = (self.action)(ctx.action);
        let child_resource = (self.resource)(ctx.subject, ctx.action, ctx.resource, ctx.context);
        let child_context = (self.context)(ctx.subject, ctx.action, ctx.context);
        let evaluation = self
            .checker
            .bind(ctx.session, &child_subject, &child_action, &child_context)
            .check(&child_resource)
            .await;

        delegated_evaluation_to_result(self.policy_type.clone(), evaluation)
    }

    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, ParentD>,
    ) -> Vec<PolicyEvalResult> {
        if ctx.items.is_empty() {
            return Vec::new();
        }

        let child_subject = (self.subject)(ctx.subject);
        let child_action = (self.action)(ctx.action);
        let child_context = (self.context)(ctx.subject, ctx.action, ctx.context);
        let child_resources = ctx
            .items
            .iter()
            .map(|item| (self.resource)(ctx.subject, ctx.action, item.resource, ctx.context))
            .collect::<Vec<_>>();

        self.checker
            .bind(ctx.session, &child_subject, &child_action, &child_context)
            .evaluate(child_resources)
            .await
            .into_iter()
            .map(|(_resource, evaluation)| {
                delegated_evaluation_to_result(self.policy_type.clone(), evaluation)
            })
            .collect()
    }

    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        self.policy_type.clone()
    }

    fn effect(&self) -> Effect {
        self.checker.aggregate_effect()
    }

    fn security_rule(&self) -> SecurityRuleMetadata {
        self.security_rule.clone()
    }
}
