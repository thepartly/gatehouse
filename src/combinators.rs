use crate::capability::combined;
use crate::{
    BatchEvalCtx, CombineOp, Decision, EvalCtx, GrantResult, Policy, PolicyBatchItem, PolicyDomain,
    VetoPolicy, VetoResult,
};
use async_trait::async_trait;
use std::{borrow::Cow, sync::Arc};

/// Error returned when no policies are provided to a combinator.
#[derive(Debug, Copy, Clone)]
pub struct EmptyPoliciesError(pub &'static str);
impl std::fmt::Display for EmptyPoliciesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for EmptyPoliciesError {}

/// Boolean composition for grant policies only.
///
/// ```compile_fail
/// use gatehouse::{PolicyDomain,PolicyBuilder,PolicyExt};
/// struct D;
/// impl PolicyDomain for D { type Subject=(); type Action=(); type Resource=(); type Context=(); }
/// let grant = PolicyBuilder::<D>::new("grant").build();
/// let veto = PolicyBuilder::<D>::new("veto").build_veto();
/// let invalid = grant.and(veto);
/// ```
pub trait PolicyExt<D: PolicyDomain>: Policy<D> + Sized + 'static {
    /// Requires both policies to grant.
    fn and<P: Policy<D> + 'static>(self, other: P) -> AndPolicy<D> {
        AndPolicy {
            policies: vec![Arc::new(self), Arc::new(other)],
        }
    }
    /// Grants if either policy grants.
    fn or<P: Policy<D> + 'static>(self, other: P) -> OrPolicy<D> {
        OrPolicy {
            policies: vec![Arc::new(self), Arc::new(other)],
        }
    }
    /// Inverts a definite grant or abstention; uncertainty remains uncertain.
    fn not(self) -> NotPolicy<D> {
        NotPolicy {
            policy: Arc::new(self),
        }
    }
    /// Boxes the policy.
    fn boxed(self) -> Box<dyn Policy<D>> {
        Box::new(self)
    }
}
impl<D: PolicyDomain, P: Policy<D> + Sized + 'static> PolicyExt<D> for P {}

/// Requires every child policy to grant.
pub struct AndPolicy<D: PolicyDomain> {
    policies: Vec<Arc<dyn Policy<D>>>,
}
/// Grants when any child policy grants.
pub struct OrPolicy<D: PolicyDomain> {
    policies: Vec<Arc<dyn Policy<D>>>,
}
/// Inverts a grant policy, preserving uncertainty.
pub struct NotPolicy<D: PolicyDomain> {
    policy: Arc<dyn Policy<D>>,
}

impl<D: PolicyDomain> NotPolicy<D> {
    /// Inverts the given grant policy, preserving indeterminate results.
    pub fn new<P: Policy<D> + 'static>(policy: P) -> Self {
        Self {
            policy: Arc::new(policy),
        }
    }
}

macro_rules! constructor {
    ($name:ident,$policy:ident) => {
        impl<D: PolicyDomain> $name<D> {
            /// Builds a combinator from a nonempty list.
            pub fn try_new(policies: Vec<Arc<dyn $policy<D>>>) -> Result<Self, EmptyPoliciesError> {
                if policies.is_empty() {
                    Err(EmptyPoliciesError(concat!(
                        stringify!($name),
                        " requires at least one policy"
                    )))
                } else {
                    Ok(Self { policies })
                }
            }
        }
    };
}
constructor!(AndPolicy, Policy);
constructor!(OrPolicy, Policy);

async fn grant_children<D: PolicyDomain>(
    policies: &[Arc<dyn Policy<D>>],
    ctx: &BatchEvalCtx<'_, D>,
    conjunction: bool,
    single: bool,
) -> Vec<GrantResult> {
    let mut children = vec![Vec::new(); ctx.items.len()];
    let mut pending: Vec<usize> = (0..ctx.items.len()).collect();
    for policy in policies {
        let items: Vec<_> = pending
            .iter()
            .map(|&index| PolicyBatchItem {
                resource: ctx.items[index].resource,
            })
            .collect();
        let results = if single {
            let inner = EvalCtx::new(
                ctx.session(),
                ctx.subject,
                ctx.action,
                items[0].resource,
                ctx.context,
                policy.policy_type(),
            );
            let result = policy.evaluate(&inner).await;
            vec![inner.finish(result)]
        } else {
            let inner = BatchEvalCtx::new(
                ctx.session(),
                ctx.subject,
                ctx.action,
                ctx.context,
                &items,
                policy.policy_type(),
            );
            let results = policy.evaluate_batch(&inner).await;
            inner.finish(results)
        };
        let results = if results.len() == pending.len() {
            results
        } else {
            pending
                .iter()
                .map(|_| {
                    GrantResult::indeterminate(
                        policy.policy_type(),
                        "Policy batch result count did not match input count",
                    )
                })
                .collect()
        };
        for (&index, result) in pending.iter().zip(results) {
            children[index].push(result);
        }
        pending.retain(|&index| {
            let decision = children[index].last().expect("evaluated child").decision();
            if conjunction {
                decision != Decision::NotApplicable
            } else {
                decision != Decision::Grant
            }
        });
        if pending.is_empty() {
            break;
        }
    }
    children
        .into_iter()
        .map(|children| {
            if conjunction {
                GrantResult::all("AndPolicy", children)
            } else {
                GrantResult::any("OrPolicy", children)
            }
        })
        .collect()
}
macro_rules! grant_combinator {
    ($name:ident,$conjunction:expr) => {
        #[async_trait]
        impl<D: PolicyDomain> Policy<D> for $name<D> {
            async fn evaluate(&self, ctx: &EvalCtx<'_, D>) -> GrantResult {
                let items = [PolicyBatchItem {
                    resource: ctx.resource,
                }];
                let inner = BatchEvalCtx::new(
                    ctx.session(),
                    ctx.subject,
                    ctx.action,
                    ctx.context,
                    &items,
                    self.policy_type(),
                );
                grant_children(&self.policies, &inner, $conjunction, true)
                    .await
                    .remove(0)
            }
            async fn evaluate_batch<'item>(
                &self,
                ctx: &BatchEvalCtx<'item, D>,
            ) -> Vec<GrantResult> {
                if ctx.items.is_empty() {
                    return Vec::new();
                }
                grant_children(&self.policies, ctx, $conjunction, false).await
            }
            fn policy_type(&self) -> Cow<'static, str> {
                Cow::Borrowed(stringify!($name))
            }
        }
    };
}
grant_combinator!(AndPolicy, true);
grant_combinator!(OrPolicy, false);

fn invert(result: GrantResult) -> GrantResult {
    let decision = match result.decision() {
        Decision::Grant => Decision::NotApplicable,
        Decision::NotApplicable if !has_fact_errors(result.trace()) => Decision::Grant,
        _ => Decision::Indeterminate,
    };
    GrantResult(combined(
        "NotPolicy",
        CombineOp::Not,
        vec![result.0],
        decision,
    ))
}
#[async_trait]
impl<D: PolicyDomain> Policy<D> for NotPolicy<D> {
    async fn evaluate(&self, ctx: &EvalCtx<'_, D>) -> GrantResult {
        let inner = EvalCtx::new(
            ctx.session(),
            ctx.subject,
            ctx.action,
            ctx.resource,
            ctx.context,
            self.policy.policy_type(),
        );
        let result = self.policy.evaluate(&inner).await;
        invert(inner.finish(result))
    }
    async fn evaluate_batch<'item>(&self, ctx: &BatchEvalCtx<'item, D>) -> Vec<GrantResult> {
        let inner = BatchEvalCtx::new(
            ctx.session(),
            ctx.subject,
            ctx.action,
            ctx.context,
            ctx.items,
            self.policy.policy_type(),
        );
        let results = self.policy.evaluate_batch(&inner).await;
        let results = inner.finish(results);
        if results.len() != ctx.items.len() {
            return ctx
                .items
                .iter()
                .map(|_| {
                    GrantResult::indeterminate(
                        self.policy_type(),
                        "Policy batch result count did not match input count",
                    )
                })
                .collect();
        }
        results.into_iter().map(invert).collect()
    }
    fn policy_type(&self) -> Cow<'static, str> {
        Cow::Borrowed("NotPolicy")
    }
}

/// Composition of veto predicates. Passing never grants permission.
pub trait VetoPolicyExt<D: PolicyDomain>: VetoPolicy<D> + Sized + 'static {
    /// Forbids only if both children forbid. A definite pass defeats uncertainty.
    fn all_of<P: VetoPolicy<D> + 'static>(self, other: P) -> AllOfVeto<D> {
        AllOfVeto {
            policies: vec![Arc::new(self), Arc::new(other)],
        }
    }
    /// Forbids if either child forbids. A definite veto defeats uncertainty.
    fn any_of<P: VetoPolicy<D> + 'static>(self, other: P) -> AnyOfVeto<D> {
        AnyOfVeto {
            policies: vec![Arc::new(self), Arc::new(other)],
        }
    }
    /// Boxes the veto policy.
    fn boxed(self) -> Box<dyn VetoPolicy<D>> {
        Box::new(self)
    }
}
impl<D: PolicyDomain, P: VetoPolicy<D> + Sized + 'static> VetoPolicyExt<D> for P {}
/// Forbids when all veto children forbid.
pub struct AllOfVeto<D: PolicyDomain> {
    policies: Vec<Arc<dyn VetoPolicy<D>>>,
}
/// Forbids when any veto child forbids.
pub struct AnyOfVeto<D: PolicyDomain> {
    policies: Vec<Arc<dyn VetoPolicy<D>>>,
}
constructor!(AllOfVeto, VetoPolicy);
constructor!(AnyOfVeto, VetoPolicy);

async fn veto_children<D: PolicyDomain>(
    policies: &[Arc<dyn VetoPolicy<D>>],
    ctx: &BatchEvalCtx<'_, D>,
    conjunction: bool,
    single: bool,
) -> Vec<VetoResult> {
    let mut children = vec![Vec::new(); ctx.items.len()];
    let mut pending: Vec<usize> = (0..ctx.items.len()).collect();
    for policy in policies {
        let items: Vec<_> = pending
            .iter()
            .map(|&index| PolicyBatchItem {
                resource: ctx.items[index].resource,
            })
            .collect();
        let results = if single {
            let inner = EvalCtx::new(
                ctx.session(),
                ctx.subject,
                ctx.action,
                items[0].resource,
                ctx.context,
                policy.policy_type(),
            );
            let result = policy.evaluate(&inner).await;
            vec![inner.finish(result)]
        } else {
            let inner = BatchEvalCtx::new(
                ctx.session(),
                ctx.subject,
                ctx.action,
                ctx.context,
                &items,
                policy.policy_type(),
            );
            let results = policy.evaluate_batch(&inner).await;
            inner.finish(results)
        };
        let results = if results.len() == pending.len() {
            results
        } else {
            pending
                .iter()
                .map(|_| {
                    VetoResult::indeterminate(
                        policy.policy_type(),
                        "Policy batch result count did not match input count",
                    )
                })
                .collect()
        };
        for (&index, result) in pending.iter().zip(results) {
            children[index].push(result);
        }
        pending.retain(|&index| {
            let decision = children[index].last().expect("evaluated child").decision();
            if conjunction {
                decision != Decision::NotApplicable
            } else {
                decision != Decision::Forbid
            }
        });
        if pending.is_empty() {
            break;
        }
    }
    children
        .into_iter()
        .map(|children| {
            let any_forbid = children.iter().any(VetoResult::is_forbidden);
            let any_pass = children
                .iter()
                .any(|child| child.decision() == Decision::NotApplicable);
            let any_unknown = children
                .iter()
                .any(|child| child.decision() == Decision::Indeterminate);
            let decision = if conjunction && any_pass {
                Decision::NotApplicable
            } else if !conjunction && any_forbid {
                Decision::Forbid
            } else if any_unknown {
                Decision::Indeterminate
            } else if conjunction && !children.is_empty() {
                Decision::Forbid
            } else {
                Decision::NotApplicable
            };
            VetoResult(combined(
                if conjunction {
                    "AllOfVeto"
                } else {
                    "AnyOfVeto"
                },
                if conjunction {
                    CombineOp::And
                } else {
                    CombineOp::Or
                },
                children.into_iter().map(|child| child.0).collect(),
                decision,
            ))
        })
        .collect()
}
macro_rules! veto_combinator {
    ($name:ident,$conjunction:expr) => {
        #[async_trait]
        impl<D: PolicyDomain> VetoPolicy<D> for $name<D> {
            async fn evaluate(&self, ctx: &EvalCtx<'_, D>) -> VetoResult {
                let items = [PolicyBatchItem {
                    resource: ctx.resource,
                }];
                let inner = BatchEvalCtx::new(
                    ctx.session(),
                    ctx.subject,
                    ctx.action,
                    ctx.context,
                    &items,
                    self.policy_type(),
                );
                veto_children(&self.policies, &inner, $conjunction, true)
                    .await
                    .remove(0)
            }
            async fn evaluate_batch<'item>(&self, ctx: &BatchEvalCtx<'item, D>) -> Vec<VetoResult> {
                if ctx.items.is_empty() {
                    return Vec::new();
                }
                veto_children(&self.policies, ctx, $conjunction, false).await
            }
            fn policy_type(&self) -> Cow<'static, str> {
                Cow::Borrowed(stringify!($name))
            }
        }
    };
}
veto_combinator!(AllOfVeto, true);
veto_combinator!(AnyOfVeto, false);

fn has_fact_errors(result: &crate::PolicyEvalResult) -> bool {
    result
        .provenance()
        .iter()
        .any(|fact| fact.outcome == crate::FactOutcome::Error)
        || match result {
            crate::PolicyEvalResult::Combined { children, .. } => {
                children.iter().any(has_fact_errors)
            }
            _ => false,
        }
}
