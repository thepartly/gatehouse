//! Real use of the `Context` generic: MFA-freshness for high-value
//! payment approvals.
//!
//! The decision "can Alice approve this $50,000 refund?" depends on
//! more than Alice's role and the refund's properties:
//!
//! - The user record (subject) knows Alice is a finance approver.
//! - The refund record (resource) knows the amount and the original
//!   payment.
//! - But "was MFA reasserted within the last 5 minutes on *this*
//!   request" is a property of the call, not of Alice or the refund.
//!   The session token records it; the user record does not.
//!
//! That last bit is what `Context` is for. We carry `mfa_verified_at`
//! and the request's wall-clock time on `ApprovalContext`. The
//! high-value policy short-circuits deny when MFA freshness has lapsed;
//! the role policy ignores the field entirely. Same subject, same
//! resource, different calls → different decisions.

use async_trait::async_trait;
use gatehouse::{AccessEvaluation, EvalCtx, PermissionChecker, Policy, PolicyEvalResult};
use std::borrow::Cow;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

#[derive(Debug, Clone)]
struct User {
    #[allow(dead_code)] // Carried for the audit trail; not consulted by these policies.
    id: Uuid,
    roles: Vec<String>,
}

#[derive(Debug, Clone)]
struct RefundRequest {
    #[allow(dead_code)]
    id: Uuid,
    amount_cents: u64,
}

#[derive(Debug, Clone)]
struct Approve;

/// Request-scoped inputs. Captured at request entry from the auth
/// middleware and the request's wall clock — not from the user
/// record, not from the resource.
#[derive(Debug, Clone)]
struct ApprovalContext {
    /// When this request hit the handler. Distinct from
    /// `SystemTime::now()` inside the policy body for two reasons:
    /// (1) it makes the policy deterministic under test, and (2) every
    /// policy in a single evaluation sees the same instant.
    current_time: SystemTime,
    /// `Some(t)` if the auth session presented an MFA assertion at
    /// time `t`; `None` if the request authenticated with a long-lived
    /// token (API key, password-only login) where MFA was never
    /// asserted on this session.
    mfa_verified_at: Option<SystemTime>,
}

/// Finance approvers can approve refunds. No MFA requirement at this
/// rule's level — the rule only checks the role on the subject and
/// ignores `Context` entirely.
struct FinanceCanApproveRefunds;

#[async_trait]
impl Policy<User, RefundRequest, Approve, ApprovalContext> for FinanceCanApproveRefunds {
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, User, RefundRequest, Approve, ApprovalContext>,
    ) -> PolicyEvalResult {
        if ctx.subject.roles.iter().any(|r| r == "finance") {
            ctx.grant("subject has the finance role")
        } else {
            ctx.deny("subject lacks the finance role")
        }
    }
    fn policy_type(&self) -> Cow<'static, str> {
        Cow::Borrowed("FinanceCanApproveRefunds")
    }
}

/// AND-gate: high-value refunds additionally require recent MFA.
///
/// This is the policy that *does* care about `Context`. It treats
/// "not a high-value refund" as granted (the rule doesn't apply), so
/// pairing it with [`FinanceCanApproveRefunds`] under [`AndPolicy`]
/// only adds the freshness check when it's relevant.
///
/// **DO NOT add this policy directly to a `PermissionChecker`** —
/// the checker uses `OR` semantics, so the "rule doesn't apply"
/// grant on every below-threshold call would grant *everyone* on
/// every small refund, regardless of role. This shape is only safe
/// inside an `AndPolicy` (or any `AND`-combining context) where the
/// sibling policies enforce the actual access decision. The pattern
/// is "augment an existing grant with an additional gate," not
/// "decide on its own."
struct HighValueRequiresFreshMfa {
    threshold_cents: u64,
    max_age: Duration,
}

#[async_trait]
impl Policy<User, RefundRequest, Approve, ApprovalContext> for HighValueRequiresFreshMfa {
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, User, RefundRequest, Approve, ApprovalContext>,
    ) -> PolicyEvalResult {
        // Rule doesn't apply below the threshold — grant. NOTE: this
        // only behaves correctly under AND. See the struct's docstring.
        if ctx.resource.amount_cents < self.threshold_cents {
            return ctx.grant("amount below high-value threshold");
        }

        let Some(verified_at) = ctx.context.mfa_verified_at else {
            return ctx.deny(format!(
                "high-value refund (>={} cents) requires recent MFA, but this session has none",
                self.threshold_cents,
            ));
        };

        let age = ctx
            .context
            .current_time
            .duration_since(verified_at)
            .unwrap_or_default();
        if age <= self.max_age {
            ctx.grant(format!(
                "MFA reasserted {}s ago, within freshness window",
                age.as_secs(),
            ))
        } else {
            ctx.deny(format!(
                "MFA reasserted {}s ago, exceeds freshness window of {}s",
                age.as_secs(),
                self.max_age.as_secs(),
            ))
        }
    }
    fn policy_type(&self) -> Cow<'static, str> {
        Cow::Borrowed("HighValueRequiresFreshMfa")
    }
}

fn build_checker() -> PermissionChecker<User, RefundRequest, Approve, ApprovalContext> {
    use gatehouse::AndPolicy;
    use std::sync::Arc;

    // Approval requires BOTH the role check AND the MFA-freshness
    // check. Both must grant — that's the AND.
    let combined = AndPolicy::try_new(vec![
        Arc::new(FinanceCanApproveRefunds)
            as Arc<dyn Policy<User, RefundRequest, Approve, ApprovalContext>>,
        Arc::new(HighValueRequiresFreshMfa {
            threshold_cents: 1_000_000, // $10,000
            max_age: Duration::from_secs(5 * 60),
        }),
    ])
    .expect("non-empty policy list");

    let mut checker = PermissionChecker::named("RefundApprovalChecker");
    checker.add_policy(combined);
    checker
}

#[tokio::main]
async fn main() {
    let alice = User {
        id: Uuid::new_v4(),
        roles: vec!["finance".into()],
    };
    let small_refund = RefundRequest {
        id: Uuid::new_v4(),
        amount_cents: 5_000, // $50
    };
    let large_refund = RefundRequest {
        id: Uuid::new_v4(),
        amount_cents: 5_000_000, // $50,000
    };

    let now = SystemTime::now();
    let checker = build_checker();

    // Case 1: small refund, no MFA at all. Granted — the high-value
    // rule doesn't apply below the threshold.
    let small_no_mfa = ApprovalContext {
        current_time: now,
        mfa_verified_at: None,
    };
    let r = checker
        .check(&alice, &Approve, &small_refund, &small_no_mfa)
        .await;
    report("small refund, no MFA", &r);
    assert!(r.is_granted());

    // Case 2: large refund, no MFA. Denied by the freshness rule.
    let r = checker
        .check(&alice, &Approve, &large_refund, &small_no_mfa)
        .await;
    report("large refund, no MFA", &r);
    assert!(!r.is_granted());

    // Case 3: large refund, MFA reasserted 8 minutes ago. Stale.
    let stale = ApprovalContext {
        current_time: now,
        mfa_verified_at: Some(now - Duration::from_secs(8 * 60)),
    };
    let r = checker.check(&alice, &Approve, &large_refund, &stale).await;
    report("large refund, MFA 8m old", &r);
    assert!(!r.is_granted());

    // Case 4: large refund, MFA reasserted 30 seconds ago. Granted.
    let fresh = ApprovalContext {
        current_time: now,
        mfa_verified_at: Some(now - Duration::from_secs(30)),
    };
    let r = checker.check(&alice, &Approve, &large_refund, &fresh).await;
    report("large refund, MFA 30s old", &r);
    assert!(r.is_granted());

    // The point: cases 2-4 all use the same subject and resource. The
    // only thing that varies is `ApprovalContext`. That's exactly the
    // signal that the rule belongs in `Context`, not on User or
    // RefundRequest.
}

/// Print the verdict and the decision trace. The trace is where the freshness
/// reason ("MFA reasserted 480s ago, exceeds freshness window of 300s") shows
/// up — the deciding policy puts it there, and it is the whole point of the
/// `Context` data flowing through.
fn report(label: &str, eval: &AccessEvaluation) {
    let trace = match eval {
        AccessEvaluation::Granted { trace, .. } | AccessEvaluation::Denied { trace, .. } => {
            trace.format()
        }
    };
    println!("{label} → {}\n{trace}", verdict(eval));
}

fn verdict(eval: &AccessEvaluation) -> &'static str {
    if eval.is_granted() {
        "GRANTED"
    } else {
        "DENIED"
    }
}
