use crate::{
    BatchEvalCtx, CombineOp, EvalCtx, Policy, PolicyBatchItem, PolicyDomain, PolicyEvalResult,
};
use async_trait::async_trait;
use std::sync::Arc;

fn arc_policy<D, P>(policy: P) -> Arc<dyn Policy<D>>
where
    D: PolicyDomain,
    P: Policy<D> + 'static,
{
    Arc::new(policy)
}

/// Fluent combinator helpers for policies.
pub trait PolicyExt<D>: Policy<D> + Sized + 'static
where
    D: PolicyDomain,
{
    /// Requires this policy and `other` to grant.
    fn and<P>(self, other: P) -> AndPolicy<D>
    where
        P: Policy<D> + 'static,
    {
        AndPolicy {
            policies: vec![arc_policy::<D, _>(self), arc_policy::<D, _>(other)],
        }
    }

    /// Grants when this policy or `other` grants.
    fn or<P>(self, other: P) -> OrPolicy<D>
    where
        P: Policy<D> + 'static,
    {
        OrPolicy {
            policies: vec![arc_policy::<D, _>(self), arc_policy::<D, _>(other)],
        }
    }

    /// Inverts this policy.
    fn not(self) -> NotPolicy<D> {
        NotPolicy {
            policy: arc_policy::<D, _>(self),
        }
    }

    /// Boxes this policy as a trait object.
    fn boxed(self) -> Box<dyn Policy<D>> {
        Box::new(self)
    }
}

impl<D, P> PolicyExt<D> for P
where
    D: PolicyDomain,
    P: Policy<D> + Sized + 'static,
{
}

/// Combines multiple policies with logical AND semantics.
pub struct AndPolicy<D: PolicyDomain> {
    policies: Vec<Arc<dyn Policy<D>>>,
}

/// Error returned when no policies are provided to a combinator policy.
#[derive(Debug, Copy, Clone)]
pub struct EmptyPoliciesError(pub &'static str);

impl std::fmt::Display for EmptyPoliciesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for EmptyPoliciesError {}

impl<D: PolicyDomain> AndPolicy<D> {
    /// Creates a new `AndPolicy` from a non-empty list of policies.
    pub fn try_new(policies: Vec<Arc<dyn Policy<D>>>) -> Result<Self, EmptyPoliciesError> {
        if policies.is_empty() {
            Err(EmptyPoliciesError(
                "AndPolicy must have at least one policy",
            ))
        } else {
            Ok(Self { policies })
        }
    }
}

#[async_trait]
impl<D: PolicyDomain> Policy<D> for AndPolicy<D> {
    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("AndPolicy")
    }

    async fn evaluate(&self, ctx: &EvalCtx<'_, D>) -> PolicyEvalResult {
        let mut children_results = Vec::with_capacity(self.policies.len());

        for policy in &self.policies {
            let inner_ctx = EvalCtx {
                session: ctx.session,
                subject: ctx.subject,
                action: ctx.action,
                resource: ctx.resource,
                context: ctx.context,
                policy_type: policy.policy_type(),
            };
            let result = policy.evaluate(&inner_ctx).await;
            let is_granted = result.is_granted();
            children_results.push(result);

            if !is_granted {
                return PolicyEvalResult::Combined {
                    policy_type: self.policy_type(),
                    operation: CombineOp::And,
                    children: children_results,
                    outcome: false,
                };
            }
        }

        PolicyEvalResult::Combined {
            policy_type: self.policy_type(),
            operation: CombineOp::And,
            children: children_results,
            outcome: true,
        }
    }

    async fn evaluate_batch<'item>(&self, ctx: &BatchEvalCtx<'item, D>) -> Vec<PolicyEvalResult> {
        let mut children_by_item = vec![Vec::new(); ctx.items.len()];
        let mut results = vec![None; ctx.items.len()];
        let mut pending = (0..ctx.items.len()).collect::<Vec<_>>();

        for policy in &self.policies {
            if pending.is_empty() {
                break;
            }

            let batch_items = pending
                .iter()
                .map(|&index| PolicyBatchItem {
                    resource: ctx.items[index].resource,
                })
                .collect::<Vec<_>>();
            let batch_ctx = BatchEvalCtx {
                session: ctx.session,
                subject: ctx.subject,
                action: ctx.action,
                context: ctx.context,
                items: &batch_items,
                policy_type: policy.policy_type(),
            };
            let child_results = policy.evaluate_batch(&batch_ctx).await;

            if child_results.len() != pending.len() {
                for index in pending.drain(..) {
                    children_by_item[index].push(PolicyEvalResult::not_applicable(
                        policy.policy_type(),
                        "Policy batch result count did not match input count",
                    ));
                    results[index] = Some(PolicyEvalResult::Combined {
                        policy_type: self.policy_type(),
                        operation: CombineOp::And,
                        children: std::mem::take(&mut children_by_item[index]),
                        outcome: false,
                    });
                }
                break;
            }

            let mut still_pending = Vec::new();
            for (index, child_result) in pending.into_iter().zip(child_results) {
                let is_granted = child_result.is_granted();
                children_by_item[index].push(child_result);

                if is_granted {
                    still_pending.push(index);
                } else {
                    results[index] = Some(PolicyEvalResult::Combined {
                        policy_type: self.policy_type(),
                        operation: CombineOp::And,
                        children: std::mem::take(&mut children_by_item[index]),
                        outcome: false,
                    });
                }
            }
            pending = still_pending;
        }

        for index in pending {
            results[index] = Some(PolicyEvalResult::Combined {
                policy_type: self.policy_type(),
                operation: CombineOp::And,
                children: std::mem::take(&mut children_by_item[index]),
                outcome: true,
            });
        }

        results
            .into_iter()
            .map(|result| {
                result.unwrap_or_else(|| {
                    PolicyEvalResult::not_applicable(
                        self.policy_type(),
                        "Batch item was not evaluated",
                    )
                })
            })
            .collect()
    }
}

/// Combines multiple policies with logical OR semantics.
pub struct OrPolicy<D: PolicyDomain> {
    policies: Vec<Arc<dyn Policy<D>>>,
}

impl<D: PolicyDomain> OrPolicy<D> {
    /// Creates a new `OrPolicy` from a non-empty list of policies.
    pub fn try_new(policies: Vec<Arc<dyn Policy<D>>>) -> Result<Self, EmptyPoliciesError> {
        if policies.is_empty() {
            Err(EmptyPoliciesError("OrPolicy must have at least one policy"))
        } else {
            Ok(Self { policies })
        }
    }
}

#[async_trait]
impl<D: PolicyDomain> Policy<D> for OrPolicy<D> {
    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("OrPolicy")
    }

    async fn evaluate(&self, ctx: &EvalCtx<'_, D>) -> PolicyEvalResult {
        let mut children_results = Vec::with_capacity(self.policies.len());

        for policy in &self.policies {
            let inner_ctx = EvalCtx {
                session: ctx.session,
                subject: ctx.subject,
                action: ctx.action,
                resource: ctx.resource,
                context: ctx.context,
                policy_type: policy.policy_type(),
            };
            let result = policy.evaluate(&inner_ctx).await;
            let is_granted = result.is_granted();
            children_results.push(result);

            if is_granted {
                return PolicyEvalResult::Combined {
                    policy_type: self.policy_type(),
                    operation: CombineOp::Or,
                    children: children_results,
                    outcome: true,
                };
            }
        }

        PolicyEvalResult::Combined {
            policy_type: self.policy_type(),
            operation: CombineOp::Or,
            children: children_results,
            outcome: false,
        }
    }

    async fn evaluate_batch<'item>(&self, ctx: &BatchEvalCtx<'item, D>) -> Vec<PolicyEvalResult> {
        let mut children_by_item = vec![Vec::new(); ctx.items.len()];
        let mut results = vec![None; ctx.items.len()];
        let mut pending = (0..ctx.items.len()).collect::<Vec<_>>();

        for policy in &self.policies {
            if pending.is_empty() {
                break;
            }

            let batch_items = pending
                .iter()
                .map(|&index| PolicyBatchItem {
                    resource: ctx.items[index].resource,
                })
                .collect::<Vec<_>>();
            let batch_ctx = BatchEvalCtx {
                session: ctx.session,
                subject: ctx.subject,
                action: ctx.action,
                context: ctx.context,
                items: &batch_items,
                policy_type: policy.policy_type(),
            };
            let child_results = policy.evaluate_batch(&batch_ctx).await;

            if child_results.len() != pending.len() {
                for index in pending.drain(..) {
                    children_by_item[index].push(PolicyEvalResult::not_applicable(
                        policy.policy_type(),
                        "Policy batch result count did not match input count",
                    ));
                    results[index] = Some(PolicyEvalResult::Combined {
                        policy_type: self.policy_type(),
                        operation: CombineOp::Or,
                        children: std::mem::take(&mut children_by_item[index]),
                        outcome: false,
                    });
                }
                break;
            }

            let mut still_pending = Vec::new();
            for (index, child_result) in pending.into_iter().zip(child_results) {
                let is_granted = child_result.is_granted();
                children_by_item[index].push(child_result);

                if is_granted {
                    results[index] = Some(PolicyEvalResult::Combined {
                        policy_type: self.policy_type(),
                        operation: CombineOp::Or,
                        children: std::mem::take(&mut children_by_item[index]),
                        outcome: true,
                    });
                } else {
                    still_pending.push(index);
                }
            }
            pending = still_pending;
        }

        for index in pending {
            results[index] = Some(PolicyEvalResult::Combined {
                policy_type: self.policy_type(),
                operation: CombineOp::Or,
                children: std::mem::take(&mut children_by_item[index]),
                outcome: false,
            });
        }

        results
            .into_iter()
            .map(|result| {
                result.unwrap_or_else(|| {
                    PolicyEvalResult::not_applicable(
                        self.policy_type(),
                        "Batch item was not evaluated",
                    )
                })
            })
            .collect()
    }
}

/// Inverts the decision of an inner policy.
pub struct NotPolicy<D: PolicyDomain> {
    policy: Arc<dyn Policy<D>>,
}

impl<D: PolicyDomain> NotPolicy<D> {
    /// Creates a new `NotPolicy` that inverts the given policy's decision.
    pub fn new(policy: impl Policy<D> + 'static) -> Self {
        Self {
            policy: Arc::new(policy),
        }
    }
}

#[async_trait]
impl<D: PolicyDomain> Policy<D> for NotPolicy<D> {
    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("NotPolicy")
    }

    async fn evaluate(&self, ctx: &EvalCtx<'_, D>) -> PolicyEvalResult {
        let inner_ctx = EvalCtx {
            session: ctx.session,
            subject: ctx.subject,
            action: ctx.action,
            resource: ctx.resource,
            context: ctx.context,
            policy_type: self.policy.policy_type(),
        };
        let inner_result = self.policy.evaluate(&inner_ctx).await;
        let is_granted = inner_result.is_granted();

        PolicyEvalResult::Combined {
            policy_type: Policy::<D>::policy_type(self),
            operation: CombineOp::Not,
            children: vec![inner_result],
            outcome: !is_granted,
        }
    }

    async fn evaluate_batch<'item>(&self, ctx: &BatchEvalCtx<'item, D>) -> Vec<PolicyEvalResult> {
        let inner_ctx = BatchEvalCtx {
            session: ctx.session,
            subject: ctx.subject,
            action: ctx.action,
            context: ctx.context,
            items: ctx.items,
            policy_type: self.policy.policy_type(),
        };
        let inner_results = self.policy.evaluate_batch(&inner_ctx).await;

        if inner_results.len() != ctx.items.len() {
            return ctx
                .items
                .iter()
                .map(|_| {
                    PolicyEvalResult::not_applicable(
                        self.policy_type(),
                        "Policy batch result count did not match input count",
                    )
                })
                .collect();
        }

        inner_results
            .into_iter()
            .map(|inner_result| {
                let is_granted = inner_result.is_granted();
                PolicyEvalResult::Combined {
                    policy_type: self.policy_type(),
                    operation: CombineOp::Not,
                    children: vec![inner_result],
                    outcome: !is_granted,
                }
            })
            .collect()
    }
}
