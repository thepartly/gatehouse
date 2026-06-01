use crate::{BatchEvalCtx, CombineOp, EvalCtx, Policy, PolicyBatchItem, PolicyEvalResult};
use async_trait::async_trait;
use std::sync::Arc;

/// ---
/// Policy Combinators
/// ---
///
/// AndPolicy
///
/// Combines multiple policies with a logical AND. Access is granted only if every
/// inner policy grants access.
pub struct AndPolicy<S, R, A, C> {
    policies: Vec<Arc<dyn Policy<S, R, A, C>>>,
}

/// Error returned when no policies are provided to a combinator policy.
#[derive(Debug, Copy, Clone)]
pub struct EmptyPoliciesError(pub &'static str);

impl<S, R, A, C> AndPolicy<S, R, A, C> {
    /// Creates a new `AndPolicy` from a non-empty list of policies.
    ///
    /// Returns [`EmptyPoliciesError`] if `policies` is empty.
    pub fn try_new(policies: Vec<Arc<dyn Policy<S, R, A, C>>>) -> Result<Self, EmptyPoliciesError> {
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
impl<S, R, A, C> Policy<S, R, A, C> for AndPolicy<S, R, A, C>
where
    S: Sync + Send,
    R: Sync + Send,
    A: Sync + Send,
    C: Sync + Send,
{
    // Override the default policy_type implementation
    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("AndPolicy")
    }

    async fn evaluate(&self, ctx: &EvalCtx<'_, S, R, A, C>) -> PolicyEvalResult {
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

            // Short-circuit on first denial
            if !is_granted {
                return PolicyEvalResult::Combined {
                    policy_type: std::borrow::Cow::Owned(self.policy_type().to_string()),
                    operation: CombineOp::And,
                    children: children_results,
                    outcome: false,
                };
            }
        }

        // All policies granted access
        PolicyEvalResult::Combined {
            policy_type: std::borrow::Cow::Owned(self.policy_type().to_string()),
            operation: CombineOp::And,
            children: children_results,
            outcome: true,
        }
    }

    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, S, R, A, C>,
    ) -> Vec<PolicyEvalResult> {
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
                    context: ctx.items[index].context,
                })
                .collect::<Vec<_>>();
            let batch_ctx = BatchEvalCtx {
                session: ctx.session,
                subject: ctx.subject,
                action: ctx.action,
                items: &batch_items,
                policy_type: policy.policy_type(),
            };
            let child_results = policy.evaluate_batch(&batch_ctx).await;

            if child_results.len() != pending.len() {
                for index in pending.drain(..) {
                    children_by_item[index].push(PolicyEvalResult::denied(
                        policy.policy_type().to_string(),
                        "Policy batch result count did not match input count",
                    ));
                    results[index] = Some(PolicyEvalResult::Combined {
                        policy_type: std::borrow::Cow::Owned(self.policy_type().to_string()),
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
                        policy_type: std::borrow::Cow::Owned(self.policy_type().to_string()),
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
                policy_type: std::borrow::Cow::Owned(self.policy_type().to_string()),
                operation: CombineOp::And,
                children: std::mem::take(&mut children_by_item[index]),
                outcome: true,
            });
        }

        results
            .into_iter()
            .map(|result| {
                result.unwrap_or_else(|| {
                    PolicyEvalResult::denied(
                        self.policy_type().to_string(),
                        "Batch item was not evaluated",
                    )
                })
            })
            .collect()
    }
}

/// OrPolicy
///
/// Combines multiple policies with a logical OR. Access is granted if any inner policy
/// grants access.
pub struct OrPolicy<S, R, A, C> {
    policies: Vec<Arc<dyn Policy<S, R, A, C>>>,
}

impl<S, R, A, C> OrPolicy<S, R, A, C> {
    /// Creates a new `OrPolicy` from a non-empty list of policies.
    ///
    /// Returns [`EmptyPoliciesError`] if `policies` is empty.
    pub fn try_new(policies: Vec<Arc<dyn Policy<S, R, A, C>>>) -> Result<Self, EmptyPoliciesError> {
        if policies.is_empty() {
            Err(EmptyPoliciesError("OrPolicy must have at least one policy"))
        } else {
            Ok(Self { policies })
        }
    }
}

#[async_trait]
impl<S, R, A, C> Policy<S, R, A, C> for OrPolicy<S, R, A, C>
where
    S: Sync + Send,
    R: Sync + Send,
    A: Sync + Send,
    C: Sync + Send,
{
    // Override the default policy_type implementation
    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("OrPolicy")
    }
    async fn evaluate(&self, ctx: &EvalCtx<'_, S, R, A, C>) -> PolicyEvalResult {
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

            // Short-circuit on first success
            if is_granted {
                return PolicyEvalResult::Combined {
                    policy_type: std::borrow::Cow::Owned(self.policy_type().to_string()),
                    operation: CombineOp::Or,
                    children: children_results,
                    outcome: true,
                };
            }
        }

        // All policies denied access
        PolicyEvalResult::Combined {
            policy_type: std::borrow::Cow::Owned(self.policy_type().to_string()),
            operation: CombineOp::Or,
            children: children_results,
            outcome: false,
        }
    }

    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, S, R, A, C>,
    ) -> Vec<PolicyEvalResult> {
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
                    context: ctx.items[index].context,
                })
                .collect::<Vec<_>>();
            let batch_ctx = BatchEvalCtx {
                session: ctx.session,
                subject: ctx.subject,
                action: ctx.action,
                items: &batch_items,
                policy_type: policy.policy_type(),
            };
            let child_results = policy.evaluate_batch(&batch_ctx).await;

            if child_results.len() != pending.len() {
                for index in pending.drain(..) {
                    children_by_item[index].push(PolicyEvalResult::denied(
                        policy.policy_type().to_string(),
                        "Policy batch result count did not match input count",
                    ));
                    results[index] = Some(PolicyEvalResult::Combined {
                        policy_type: std::borrow::Cow::Owned(self.policy_type().to_string()),
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
                        policy_type: std::borrow::Cow::Owned(self.policy_type().to_string()),
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
                policy_type: std::borrow::Cow::Owned(self.policy_type().to_string()),
                operation: CombineOp::Or,
                children: std::mem::take(&mut children_by_item[index]),
                outcome: false,
            });
        }

        results
            .into_iter()
            .map(|result| {
                result.unwrap_or_else(|| {
                    PolicyEvalResult::denied(
                        self.policy_type().to_string(),
                        "Batch item was not evaluated",
                    )
                })
            })
            .collect()
    }
}

/// NotPolicy
///
/// Inverts the result of an inner policy. If the inner policy allows access, then NotPolicy
/// denies it, and vice versa.
pub struct NotPolicy<S, R, A, C> {
    policy: Arc<dyn Policy<S, R, A, C>>,
}

impl<S, R, A, C> NotPolicy<S, R, A, C>
where
    S: Sync,
    R: Sync,
    A: Sync,
    C: Sync,
{
    /// Creates a new `NotPolicy` that inverts the given policy's decision.
    pub fn new(policy: impl Policy<S, R, A, C> + 'static) -> Self {
        Self {
            policy: Arc::new(policy),
        }
    }
}

#[async_trait]
impl<S, R, A, C> Policy<S, R, A, C> for NotPolicy<S, R, A, C>
where
    S: Sync + Send,
    R: Sync + Send,
    A: Sync + Send,
    C: Sync + Send,
{
    // Override the default policy_type implementation
    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("NotPolicy")
    }

    async fn evaluate(&self, ctx: &EvalCtx<'_, S, R, A, C>) -> PolicyEvalResult {
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
            policy_type: std::borrow::Cow::Owned(
                Policy::<S, R, A, C>::policy_type(self).to_string(),
            ),
            operation: CombineOp::Not,
            children: vec![inner_result],
            outcome: !is_granted,
        }
    }

    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, S, R, A, C>,
    ) -> Vec<PolicyEvalResult> {
        // Rebuild the BatchEvalCtx with the inner policy's name so any
        // result built via `ctx.grant`/`ctx.deny` (or the default
        // evaluate_batch impl, which forwards through per-item EvalCtx)
        // is tagged with the wrapped policy, not "NotPolicy". Matches the
        // single-item path and the AndPolicy/OrPolicy batch paths.
        let inner_ctx = BatchEvalCtx {
            session: ctx.session,
            subject: ctx.subject,
            action: ctx.action,
            items: ctx.items,
            policy_type: self.policy.policy_type(),
        };
        let inner_results = self.policy.evaluate_batch(&inner_ctx).await;

        if inner_results.len() != ctx.items.len() {
            return ctx
                .items
                .iter()
                .map(|_| {
                    PolicyEvalResult::denied(
                        self.policy_type().to_string(),
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
                    policy_type: std::borrow::Cow::Owned(self.policy_type().to_string()),
                    operation: CombineOp::Not,
                    children: vec![inner_result],
                    outcome: !is_granted,
                }
            })
            .collect()
    }
}
