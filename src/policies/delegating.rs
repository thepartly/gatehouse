use crate::{
    AccessEvaluation, BatchEvalCtx, CombineOp, EvalCtx, PermissionChecker, Policy,
    PolicyEvalResult, SecurityRuleMetadata, PERMISSION_CHECKER_POLICY_TYPE,
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

/// A policy that delegates its decision to another [`PermissionChecker`].
///
/// Use this when one authorization domain needs to ask another domain's checker
/// for a decision while preserving the policy-layer trace. For example, a
/// messaging `ReadConversation` policy can map a conversation to the
/// procurement object it represents, then delegate to the procurement checker
/// using the same [`crate::EvaluationSession`].
///
/// The subject and action mappers run once per batch. Resource and context
/// mappers run once per item. Mapper closures return child-domain values; use
/// lightweight IDs, newtypes, or `Arc` values when mapping larger objects.
///
/// `DelegatingPolicy` does not detect cycles or self-delegation; avoid wiring a
/// child checker that can delegate back into the same decision path.
pub struct DelegatingPolicy<S, A, R, C, ChildSubject, ChildAction, ChildResource, ChildContext> {
    policy_type: std::borrow::Cow<'static, str>,
    security_rule: SecurityRuleMetadata,
    checker: PermissionChecker<ChildSubject, ChildAction, ChildResource, ChildContext>,
    subject: Arc<dyn Fn(&S) -> ChildSubject + Send + Sync>,
    action: Arc<dyn Fn(&A) -> ChildAction + Send + Sync>,
    resource: Arc<dyn Fn(&S, &A, &R, &C) -> ChildResource + Send + Sync>,
    context: Arc<dyn Fn(&S, &A, &R, &C) -> ChildContext + Send + Sync>,
}

impl<S, A, R, C, ChildSubject, ChildAction, ChildResource, ChildContext>
    DelegatingPolicy<S, A, R, C, ChildSubject, ChildAction, ChildResource, ChildContext>
{
    /// Creates a delegating policy from a child checker and mapping functions.
    pub fn new<SubjectFn, ActionFn, ResourceFn, ContextFn>(
        policy_type: impl Into<std::borrow::Cow<'static, str>>,
        checker: PermissionChecker<ChildSubject, ChildAction, ChildResource, ChildContext>,
        subject: SubjectFn,
        action: ActionFn,
        resource: ResourceFn,
        context: ContextFn,
    ) -> Self
    where
        SubjectFn: Fn(&S) -> ChildSubject + Send + Sync + 'static,
        ActionFn: Fn(&A) -> ChildAction + Send + Sync + 'static,
        ResourceFn: Fn(&S, &A, &R, &C) -> ChildResource + Send + Sync + 'static,
        ContextFn: Fn(&S, &A, &R, &C) -> ChildContext + Send + Sync + 'static,
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
impl<S, A, R, C, ChildSubject, ChildAction, ChildResource, ChildContext> Policy<S, A, R, C>
    for DelegatingPolicy<S, A, R, C, ChildSubject, ChildAction, ChildResource, ChildContext>
where
    S: Send + Sync,
    R: Send + Sync,
    A: Send + Sync,
    C: Send + Sync,
    ChildSubject: Send + Sync,
    ChildResource: Send + Sync,
    ChildAction: Send + Sync,
    ChildContext: Send + Sync,
{
    async fn evaluate(&self, ctx: &EvalCtx<'_, S, A, R, C>) -> PolicyEvalResult {
        let child_subject = (self.subject)(ctx.subject);
        let child_action = (self.action)(ctx.action);
        let child_resource = (self.resource)(ctx.subject, ctx.action, ctx.resource, ctx.context);
        let child_context = (self.context)(ctx.subject, ctx.action, ctx.resource, ctx.context);
        let evaluation = self
            .checker
            .evaluate_in_session(
                ctx.session,
                &child_subject,
                &child_action,
                &child_resource,
                &child_context,
            )
            .await;

        delegated_evaluation_to_result(self.policy_type.clone(), evaluation)
    }

    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, S, A, R, C>,
    ) -> Vec<PolicyEvalResult> {
        let child_subject = (self.subject)(ctx.subject);
        let child_action = (self.action)(ctx.action);
        let child_items = ctx
            .items
            .iter()
            .map(|item| {
                (
                    (self.resource)(ctx.subject, ctx.action, item.resource, item.context),
                    (self.context)(ctx.subject, ctx.action, item.resource, item.context),
                )
            })
            .collect::<Vec<_>>();

        self.checker
            .evaluate_batch_in_session(
                ctx.session,
                &child_subject,
                &child_action,
                child_items,
                |(resource, context)| (resource, context),
            )
            .await
            .into_iter()
            .map(|(_item, evaluation)| {
                delegated_evaluation_to_result(self.policy_type.clone(), evaluation)
            })
            .collect()
    }

    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        self.policy_type.clone()
    }

    fn security_rule(&self) -> SecurityRuleMetadata {
        self.security_rule.clone()
    }
}
