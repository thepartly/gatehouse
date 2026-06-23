//! Deny-overrides-allow: suspensions and legal holds that win over every grant.
//!
//! Almost every real authorization system eventually needs a rule that
//! overrides all the others: a suspended account is locked out regardless of
//! role, a document under legal hold is frozen even for its owner and for
//! admins. In gatehouse this is exactly what [`Effect::Forbid`] does: a policy
//! built with `.forbid()` **forbids** the request when its
//! predicate matches, and [`PermissionChecker`] honors a forbid over any
//! grant from sibling policies — deny-overrides semantics, in the style of
//! Cedar and AWS IAM.
//!
//! The shape is flat: block rules are ordinary policies registered with
//! `add_policy`, in natural polarity (predicate matches ⇒ forbidden), in any
//! order. The decision rule is fixed:
//!
//! 1. any matching `Effect::Forbid` policy ⇒ **denied** (the trace names it);
//! 2. otherwise any granting policy ⇒ **granted**;
//! 3. otherwise ⇒ **denied** (default deny).
//!
//! Active forbids propagate through combinators and delegation. See the
//! scoped-exclusion section at the bottom for the combinator shape that covers
//! "this exclusion should only gate one grant path" without creating a global
//! veto.
//!
//! Run with:
//!
//! ```text
//! cargo run --example deny_override
//! ```

use gatehouse::{
    AndPolicy, EvaluationSession, NotPolicy, PermissionChecker, Policy, PolicyBuilder, PolicyDomain,
};
use std::sync::Arc;
use uuid::Uuid;

// ---- domain --------------------------------------------------------

#[derive(Debug, Clone)]
struct User {
    id: Uuid,
    is_admin: bool,
    /// Account-level block. When set, no grant should let the user through.
    suspended: bool,
}

#[derive(Debug, Clone)]
struct Document {
    owner_id: Uuid,
    /// Resource-level block. A document under legal hold is frozen even for
    /// its owner and for admins.
    legal_hold: bool,
}

#[derive(Debug, Clone)]
struct Access;

// No request-scoped facts here, so the context is the unit type. (`()` is the
// idiomatic "no context" — reserve a context struct for data that genuinely
// varies per request, as in the mfa_freshness_context example.)
struct DocumentDomain;

impl PolicyDomain for DocumentDomain {
    type Subject = User;
    type Action = Access;
    type Resource = Document;
    type Context = ();
}

type DocPolicy = Box<dyn Policy<DocumentDomain>>;

// ---- the allow set -------------------------------------------------

fn admin_override() -> DocPolicy {
    PolicyBuilder::<DocumentDomain>::new("AdminOverride")
        .subjects(|user| user.is_admin)
        .build()
}

fn document_owner() -> DocPolicy {
    PolicyBuilder::<DocumentDomain>::new("DocumentOwner")
        .when(|user, _action, document, _ctx| user.id == document.owner_id)
        .build()
}

// ---- the block rules -----------------------------------------------

/// Account suspension: predicate matches ⇒ the request is forbidden. The
/// effect travels with the policy, so this reads exactly as it behaves —
/// no inverted polarity, no special registration call.
fn account_suspended() -> DocPolicy {
    PolicyBuilder::<DocumentDomain>::new("AccountSuspended")
        .subjects(|user| user.suspended)
        .forbid()
        .build()
}

/// Legal hold: a frozen document is blocked for everyone, owner and admin
/// included.
fn legal_hold() -> DocPolicy {
    PolicyBuilder::<DocumentDomain>::new("LegalHold")
        .resources(|document| document.legal_hold)
        .forbid()
        .build()
}

fn document_checker() -> PermissionChecker<DocumentDomain> {
    let mut checker = PermissionChecker::named("DocumentChecker");
    // Flat registration, any order: the deny policies' effect is declared
    // on the policies themselves, and the checker evaluates forbid-effect
    // policies first so a veto can never be raced by a grant.
    checker.add_policy(admin_override());
    checker.add_policy(document_owner());
    checker.add_policy(account_suspended());
    checker.add_policy(legal_hold());
    checker
}

// ---- driver --------------------------------------------------------

#[tokio::main]
async fn main() {
    let owner_id = Uuid::new_v4();
    let admin = User {
        id: Uuid::new_v4(),
        is_admin: true,
        suspended: false,
    };
    let suspended_owner = User {
        id: owner_id,
        is_admin: false,
        suspended: true,
    };
    let owner = User {
        id: owner_id,
        is_admin: false,
        suspended: false,
    };
    let stranger = User {
        id: Uuid::new_v4(),
        is_admin: false,
        suspended: false,
    };

    let normal_doc = Document {
        owner_id,
        legal_hold: false,
    };
    let held_doc = Document {
        owner_id,
        legal_hold: true,
    };

    let checker = document_checker();
    let session = EvaluationSession::empty();
    let action = Access;
    let context = ();

    // (subject, resource, label)
    let cases = [
        (&admin, &normal_doc, "admin, normal doc"),
        (&owner, &normal_doc, "owner, own normal doc"),
        (&admin, &held_doc, "admin, LEGAL-HOLD doc"),
        (&suspended_owner, &normal_doc, "SUSPENDED owner, own doc"),
        (&stranger, &normal_doc, "stranger, someone else's doc"),
    ];

    println!("{:<32} {:>10} forbidden by", "case", "decision");
    println!("{}", "-".repeat(60));
    for (subject, document, label) in cases {
        let decision = checker
            .bind(&session, subject, &action, &context)
            .check(document)
            .await;
        println!(
            "{label:<32} {:>10} {}",
            verdict(decision.is_granted()),
            decision.forbidden_by().unwrap_or("-"),
        );
    }

    // The grants still work where nothing blocks them.
    checker
        .bind(&session, &admin, &action, &context)
        .check(&normal_doc)
        .await
        .assert_granted_by("AdminOverride");
    checker
        .bind(&session, &owner, &action, &context)
        .check(&normal_doc)
        .await
        .assert_granted_by("DocumentOwner");

    // The block rules override every grant — even the admin override.
    checker
        .bind(&session, &admin, &action, &context)
        .check(&held_doc)
        .await
        .assert_forbidden_by("LegalHold");
    checker
        .bind(&session, &suspended_owner, &action, &context)
        .check(&normal_doc)
        .await
        .assert_forbidden_by("AccountSuspended");

    // Default deny is untouched: no grant, no access — and no forbid
    // either, which `forbidden_by()` distinguishes for the caller.
    let stranger_decision = checker
        .bind(&session, &stranger, &action, &context)
        .check(&normal_doc)
        .await;
    stranger_decision.assert_denied();
    assert_eq!(stranger_decision.forbidden_by(), None);

    // Show the mechanism on the headline case: the forbid-effect policy is
    // evaluated first and ends the evaluation; the allow set is never
    // consulted.
    println!("\nWhy 'admin, LEGAL-HOLD doc' is blocked:");
    let decision = checker
        .bind(&session, &admin, &action, &context)
        .check(&held_doc)
        .await;
    println!("{}", decision.display_trace());

    scoped_exclusion_demo().await;
}

// ---- scoped exclusion: a deny that gates only one grant path --------

/// `Effect::Forbid` is a *global* veto: it blocks every grant path in the
/// checker. When a block rule should only gate one grant path — here,
/// muted users lose collaborator access but owners and admins keep
/// theirs — scope it with combinators instead:
/// `AndPolicy[ grant_arm, NotPolicy(block) ]`. The block policy in this local
/// shape should be an ordinary grant-style predicate, not `.forbid()`;
/// `Forbidden` is active and would still veto globally.
async fn scoped_exclusion_demo() {
    #[derive(Debug, Clone)]
    struct Member {
        is_owner: bool,
        is_collaborator: bool,
        muted: bool,
    }
    #[derive(Debug, Clone)]
    struct Thread;

    struct ThreadDomain;

    impl PolicyDomain for ThreadDomain {
        type Subject = Member;
        type Action = Access;
        type Resource = Thread;
        type Context = ();
    }

    let owner_policy = PolicyBuilder::<ThreadDomain>::new("ThreadOwner")
        .subjects(|member| member.is_owner)
        .build();
    let collaborator_policy: Arc<dyn Policy<ThreadDomain>> = Arc::from(
        PolicyBuilder::<ThreadDomain>::new("Collaborator")
            .subjects(|member| member.is_collaborator)
            .build(),
    );
    // The block rule for the scoped case *grants when it matches* so that
    // `NotPolicy` can invert it into a local gate. Compare with the
    // checker-level rules above, where `Effect::Forbid` keeps natural
    // polarity — this inversion is the price of scoping, which is why a
    // global block should prefer `Effect::Forbid`.
    let muted = PolicyBuilder::<ThreadDomain>::new("Muted")
        .subjects(|member| member.muted)
        .build();

    let collaborator_unless_muted = AndPolicy::try_new(vec![
        collaborator_policy,
        Arc::new(NotPolicy::new(muted)) as Arc<dyn Policy<ThreadDomain>>,
    ])
    .expect("gate has the grant arm and the guard");

    let mut checker = PermissionChecker::<ThreadDomain>::named("ThreadChecker");
    checker.add_policy(owner_policy);
    checker.add_policy(collaborator_unless_muted);

    let muted_collaborator = Member {
        is_owner: false,
        is_collaborator: true,
        muted: true,
    };
    let muted_owner = Member {
        is_owner: true,
        is_collaborator: false,
        muted: true,
    };

    let session = EvaluationSession::empty();
    let action = Access;
    let context = ();

    // The mute only gates the collaborator path...
    checker
        .bind(&session, &muted_collaborator, &action, &context)
        .check(&Thread)
        .await
        .assert_denied();
    // ...the owner path is untouched, which a global Effect::Forbid mute
    // could not express.
    checker
        .bind(&session, &muted_owner, &action, &context)
        .check(&Thread)
        .await
        .assert_granted_by("ThreadOwner");

    println!("\nScoped exclusion: muted collaborator blocked, muted owner unaffected.");
}

fn verdict(granted: bool) -> &'static str {
    if granted {
        "GRANTED"
    } else {
        "DENIED"
    }
}
