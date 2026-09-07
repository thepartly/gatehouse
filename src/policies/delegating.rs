use crate::capability::combined;
use crate::checker::{Phase, PhasePolicy, PhaseScope};
use crate::{
    BatchEvalCtx, CombineOp, EvalCtx, PermissionChecker, PolicyBatchItem, PolicyDomain,
    PolicyEvalResult, SecurityRuleMetadata,
};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

/// Maps inputs into a child checker. Install with [`PermissionChecker::add_delegate`].
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
    pub(crate) fn into_phases(
        self,
        registration: usize,
    ) -> (Arc<dyn PhasePolicy<ParentD>>, Arc<dyn PhasePolicy<ParentD>>) {
        let delegate = Arc::new(self);
        (
            Arc::new(DelegatePhase {
                delegate: delegate.clone(),
                phase: Phase::Veto,
                registration,
            }),
            Arc::new(DelegatePhase {
                delegate,
                phase: Phase::Grant,
                registration,
            }),
        )
    }
}

struct DelegatePhase<ParentD: PolicyDomain, ChildD: PolicyDomain> {
    delegate: Arc<DelegatingPolicy<ParentD, ChildD>>,
    phase: Phase,
    registration: usize,
}
struct PreparedInputs<D: PolicyDomain> {
    subject: D::Subject,
    action: D::Action,
    context: D::Context,
    resources: HashMap<usize, D::Resource>,
}
impl<ParentD: PolicyDomain, ChildD: PolicyDomain> DelegatePhase<ParentD, ChildD> {
    async fn run(
        &self,
        ctx: &BatchEvalCtx<'_, ParentD>,
        single: bool,
        scope: &mut PhaseScope<'_>,
    ) -> Vec<PolicyEvalResult> {
        let delegate = &self.delegate;
        let mut path = scope.path.to_vec();
        path.push(self.registration);
        let mut prepared = match scope.state.delegates.remove(&path) {
            Some(prepared) => prepared
                .downcast::<PreparedInputs<ChildD>>()
                .expect("delegate registration has one child domain"),
            None => Box::new(PreparedInputs::<ChildD> {
                subject: (delegate.subject)(ctx.subject),
                action: (delegate.action)(ctx.action),
                context: (delegate.context)(ctx.subject, ctx.action, ctx.context),
                resources: HashMap::new(),
            }),
        };
        for (&index, item) in scope.item_indices.iter().zip(ctx.items) {
            prepared.resources.entry(index).or_insert_with(|| {
                (delegate.resource)(ctx.subject, ctx.action, item.resource, ctx.context)
            });
        }
        let items: Vec<_> = scope
            .item_indices
            .iter()
            .map(|index| PolicyBatchItem {
                resource: &prepared.resources[index],
            })
            .collect();
        let inner = BatchEvalCtx::new(
            ctx.session(),
            &prepared.subject,
            &prepared.action,
            &prepared.context,
            &items,
            delegate.policy_type.clone(),
        );
        let mut child_scope = PhaseScope {
            state: scope.state,
            item_indices: scope.item_indices,
            path: &path,
        };
        let children = if single {
            let inner = EvalCtx::new(
                ctx.session(),
                &prepared.subject,
                &prepared.action,
                items[0].resource,
                &prepared.context,
                delegate.policy_type.clone(),
            );
            vec![
                delegate
                    .checker
                    .evaluate_phase_one(self.phase, &inner, &mut child_scope)
                    .await,
            ]
        } else {
            delegate
                .checker
                .evaluate_phase(self.phase, &inner, &mut child_scope)
                .await
        };
        let results = children
            .into_iter()
            .map(|child| {
                let decision = child.decision();
                combined(
                    delegate.policy_type.clone(),
                    CombineOp::Delegate,
                    vec![child],
                    decision,
                )
            })
            .collect();
        scope.state.delegates.insert(path, prepared);
        results
    }
}
#[async_trait]
impl<ParentD: PolicyDomain, ChildD: PolicyDomain> PhasePolicy<ParentD>
    for DelegatePhase<ParentD, ChildD>
{
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, ParentD>,
        scope: &mut PhaseScope<'_>,
    ) -> PolicyEvalResult {
        let items = [PolicyBatchItem {
            resource: ctx.resource,
        }];
        let batch = BatchEvalCtx::new(
            ctx.session(),
            ctx.subject,
            ctx.action,
            ctx.context,
            &items,
            ctx.policy_type.clone(),
        );
        self.run(&batch, true, scope).await.remove(0)
    }
    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, ParentD>,
        scope: &mut PhaseScope<'_>,
    ) -> Vec<PolicyEvalResult> {
        self.run(ctx, false, scope).await
    }
    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        self.delegate.policy_type.clone()
    }
    fn security_rule(&self) -> SecurityRuleMetadata {
        self.delegate.security_rule.clone()
    }
}
