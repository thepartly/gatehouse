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
//! high-value rule is a forbid-effect policy that **forbids** the approval
//! when MFA freshness has lapsed; the role policy ignores the field
//! entirely. Same subject, same resource, different calls → different
//! decisions.

use async_trait::async_trait;
use gatehouse::{
    AccessEvaluation, Effect, EvalCtx, EvaluationSession, PermissionChecker, Policy, PolicyDomain,
    PolicyEvalResult,
};
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

struct RefundApprovalDomain;

impl PolicyDomain for RefundApprovalDomain {
    type Subject = User;
    type Action = Approve;
    type Resource = RefundRequest;
    type Context = ApprovalContext;
}

/// Finance approvers can approve refunds. No MFA requirement at this
/// rule's level — the rule only checks the role on the subject and
/// ignores `Context` entirely.
struct FinanceCanApproveRefunds;

#[async_trait]
impl Policy<RefundApprovalDomain> for FinanceCanApproveRefunds {
    async fn evaluate(&self, ctx: &EvalCtx<'_, RefundApprovalDomain>) -> PolicyEvalResult {
        if ctx.subject.roles.iter().any(|r| r == "finance") {
            ctx.grant("subject has the finance role")
        } else {
            ctx.not_applicable("subject lacks the finance role")
        }
    }
    fn policy_type(&self) -> Cow<'static, str> {
        Cow::Borrowed("FinanceCanApproveRefunds")
    }
}

/// Deny rule: a high-value refund without fresh MFA is **forbidden**.
///
/// This is the policy that *does* care about `Context`, and it is a
/// forbid-effect policy in natural polarity: it matches exactly when the
/// approval must be blocked, and returns `ctx.forbid(...)` for that
/// case. Everything else — small refunds, fresh MFA — is "not
/// applicable" (`ctx.not_applicable`), which never blocks and never grants.
///
/// Registered flat on the [`PermissionChecker`], the forbid overrides
/// every grant under deny-overrides semantics. That is the right
/// strength for an MFA requirement: if an admin-override or
/// service-account grant path is added later, a stale session still
/// cannot approve a high-value refund through it.
///
/// Note the [`Policy::effect`] override below — a hand-written policy
/// that can forbid must declare [`Effect::Forbid`] so the checker
/// schedules it ahead of the grant short-circuit.
struct HighValueRequiresFreshMfa {
    threshold_cents: u64,
    max_age: Duration,
}

#[async_trait]
impl Policy<RefundApprovalDomain> for HighValueRequiresFreshMfa {
    async fn evaluate(&self, ctx: &EvalCtx<'_, RefundApprovalDomain>) -> PolicyEvalResult {
        // Rule doesn't apply below the threshold: not applicable, and a
        // non-matching forbid-effect policy blocks nothing.
        if ctx.resource.amount_cents < self.threshold_cents {
            return ctx.not_applicable("amount below high-value threshold; rule not applicable");
        }

        let Some(verified_at) = ctx.context.mfa_verified_at else {
            return ctx.forbid(format!(
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
            ctx.not_applicable(format!(
                "MFA reasserted {}s ago, within freshness window; rule not applicable",
                age.as_secs(),
            ))
        } else {
            ctx.forbid(format!(
                "MFA reasserted {}s ago, exceeds freshness window of {}s",
                age.as_secs(),
                self.max_age.as_secs(),
            ))
        }
    }
    fn policy_type(&self) -> Cow<'static, str> {
        Cow::Borrowed("HighValueRequiresFreshMfa")
    }
    fn effect(&self) -> Effect {
        Effect::Forbid
    }
}

fn build_checker() -> PermissionChecker<RefundApprovalDomain> {
    // Flat registration: the role grant and the MFA veto are siblings.
    // The checker's deny-overrides rule does the combining — any forbid
    // wins, otherwise any grant wins, otherwise default deny.
    let mut checker = PermissionChecker::named("RefundApprovalChecker");
    checker.add_policy(FinanceCanApproveRefunds);
    checker.add_policy(HighValueRequiresFreshMfa {
        threshold_cents: 1_000_000, // $10,000
        max_age: Duration::from_secs(5 * 60),
    });
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
    let session = EvaluationSession::empty();

    // Case 1: small refund, no MFA at all. Granted — the high-value
    // rule doesn't apply below the threshold, so the role grant decides.
    let small_no_mfa = ApprovalContext {
        current_time: now,
        mfa_verified_at: None,
    };
    let r = checker
        .bind(&session, &alice, &Approve, &small_no_mfa)
        .check(&small_refund)
        .await;
    report("small refund, no MFA", &r);
    r.assert_granted_by("FinanceCanApproveRefunds");

    // Case 2: large refund, no MFA. Forbidden by the freshness rule —
    // the veto overrides Alice's role grant.
    let r = checker
        .bind(&session, &alice, &Approve, &small_no_mfa)
        .check(&large_refund)
        .await;
    report("large refund, no MFA", &r);
    r.assert_forbidden_by("HighValueRequiresFreshMfa");

    // Case 3: large refund, MFA reasserted 8 minutes ago. Stale → forbidden.
    let stale = ApprovalContext {
        current_time: now,
        mfa_verified_at: Some(now - Duration::from_secs(8 * 60)),
    };
    let r = checker
        .bind(&session, &alice, &Approve, &stale)
        .check(&large_refund)
        .await;
    report("large refund, MFA 8m old", &r);
    r.assert_forbidden_by("HighValueRequiresFreshMfa");

    // Case 4: large refund, MFA reasserted 30 seconds ago. The deny rule
    // is not applicable, so the role grant decides.
    let fresh = ApprovalContext {
        current_time: now,
        mfa_verified_at: Some(now - Duration::from_secs(30)),
    };
    let r = checker
        .bind(&session, &alice, &Approve, &fresh)
        .check(&large_refund)
        .await;
    report("large refund, MFA 30s old", &r);
    r.assert_granted_by("FinanceCanApproveRefunds");

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
    println!("{label} → {}\n{}", verdict(eval), eval.trace().format());
}

fn verdict(eval: &AccessEvaluation) -> &'static str {
    if eval.is_granted() {
        "GRANTED"
    } else {
        "DENIED"
    }
}
