//! Deny-overrides-allow: suspensions and legal holds that win over every grant.
//!
//! Almost every real authorization system eventually needs a rule that
//! overrides all the others: a suspended account is locked out regardless of
//! role, a document under legal hold is frozen even for its owner and for
//! admins. The obvious move — "add a deny policy to the `PermissionChecker`" —
//! does **not** do this. A `PermissionChecker` is `OR`: it grants on the first
//! policy that grants, so a deny result is just one more "no" among the
//! policies, and any sibling allow still wins. (`PolicyBuilder::effect(Deny)`
//! does not change this; see the Decision Semantics section of the README.)
//!
//! The shape that *does* work is to gate the whole allow set behind
//! `NOT(blocklist)` under `AND`:
//!
//! ```text
//! AndPolicy [ NotPolicy(OrPolicy[ ...block rules ]),  OrPolicy[ ...allow rules ] ]
//! ```
//!
//! `AndPolicy` denies if any arm denies, so a blocklist match (inverted by
//! `NotPolicy` into a denial) overrides every grant in the allow set.
//!
//! Run with:
//!
//! ```text
//! cargo run --example deny_override
//! ```

use gatehouse::{AndPolicy, Effect, NotPolicy, OrPolicy, PermissionChecker, Policy, PolicyBuilder};
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
type DocPolicy = Box<dyn Policy<User, Document, Access, ()>>;

// ---- the allow set -------------------------------------------------

/// The grants: an admin override OR document ownership. This is the part an
/// author writes first and is happy with — the bug only appears once a block
/// rule has to override it.
fn allow_set() -> DocPolicy {
    let admin = PolicyBuilder::<User, Document, Access, ()>::new("AdminOverride")
        .subjects(|user| user.is_admin)
        .build();
    let owner = PolicyBuilder::<User, Document, Access, ()>::new("DocumentOwner")
        .when(|user, _action, document, _ctx| user.id == document.owner_id)
        .build();

    Box::new(
        OrPolicy::try_new(vec![Arc::from(admin), Arc::from(owner)]).expect("allow set non-empty"),
    )
}

// ---- the blocklist -------------------------------------------------

/// The block rules. Each one **grants when its block condition matches** — it
/// reports "this request is on the blocklist". On its own that polarity looks
/// backwards; it only makes sense wrapped in `NotPolicy` below, which turns a
/// blocklist match into a denial.
fn blocklist() -> DocPolicy {
    let suspended = PolicyBuilder::<User, Document, Access, ()>::new("AccountSuspended")
        .subjects(|user| user.suspended)
        .build();
    let legal_hold = PolicyBuilder::<User, Document, Access, ()>::new("LegalHold")
        .resources(|document| document.legal_hold)
        .build();

    Box::new(
        OrPolicy::try_new(vec![Arc::from(suspended), Arc::from(legal_hold)])
            .expect("blocklist non-empty"),
    )
}

// ---- WRONG: a deny policy added straight to the checker ------------

/// The tempting mistake. Add the blocklist to the checker as a deny-effect
/// policy and assume it wins. It cannot: under `OR`, a deny is not a veto, and
/// the admin/owner grant still short-circuits to a grant. Order does not save
/// it either — the deny is listed first here and is still ignored.
fn naive_checker() -> PermissionChecker<User, Document, Access, ()> {
    let mut checker = PermissionChecker::named("NaiveDenyChecker");
    checker.add_policy(
        PolicyBuilder::<User, Document, Access, ()>::new("LegalHoldDeny")
            .resources(|document| document.legal_hold)
            .effect(Effect::Deny)
            .build(),
    );
    checker.add_policy(allow_set());
    checker
}

// ---- RIGHT: gate the allow set behind NOT(blocklist) ---------------

/// The shape that actually enforces deny-overrides-allow.
fn deny_override_checker() -> PermissionChecker<User, Document, Access, ()> {
    let not_blocked: Arc<dyn Policy<User, Document, Access, ()>> =
        Arc::new(NotPolicy::new(blocklist()));
    let gate = AndPolicy::try_new(vec![not_blocked, Arc::from(allow_set())])
        .expect("gate has the guard and the allow arm");

    let mut checker = PermissionChecker::named("DenyOverrideChecker");
    checker.add_policy(gate);
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

    let naive = naive_checker();
    let correct = deny_override_checker();

    // (subject, resource, label)
    let cases = [
        (&admin, &normal_doc, "admin, normal doc"),
        (&owner, &normal_doc, "owner, own normal doc"),
        (&admin, &held_doc, "admin, LEGAL-HOLD doc"),
        (&suspended_owner, &normal_doc, "SUSPENDED owner, own doc"),
        (&stranger, &normal_doc, "stranger, someone else's doc"),
    ];

    println!(
        "{:<32} {:>12} {:>12}",
        "case", "naive (OR)", "deny-override"
    );
    println!("{}", "-".repeat(58));
    for (subject, document, label) in cases {
        let naive_granted = naive
            .check(subject, &Access, document, &())
            .await
            .is_granted();
        let correct_granted = correct
            .check(subject, &Access, document, &())
            .await
            .is_granted();
        println!(
            "{label:<32} {:>12} {:>12}",
            verdict(naive_granted),
            verdict(correct_granted),
        );
    }

    // The two rows where the checkers disagree are the whole point: the naive
    // checker grants access it should have blocked.
    assert!(
        naive
            .check(&admin, &Access, &held_doc, &())
            .await
            .is_granted(),
        "naive OR checker leaks: admin is granted on a legal-hold document",
    );
    assert!(
        !correct
            .check(&admin, &Access, &held_doc, &())
            .await
            .is_granted(),
        "deny-override checker blocks the legal-hold document even for an admin",
    );
    assert!(
        !correct
            .check(&suspended_owner, &Access, &normal_doc, &())
            .await
            .is_granted(),
        "deny-override checker blocks a suspended account even on its own document",
    );
    // The allow set still gates everyone else: no grant, no access.
    assert!(
        !correct
            .check(&stranger, &Access, &normal_doc, &())
            .await
            .is_granted(),
        "a stranger with no grant is still denied",
    );

    // Show the mechanism on the headline case: NOT(blocklist) denies first, so
    // AND short-circuits before the allow arm is ever consulted.
    println!("\nWhy the deny-override checker blocks 'admin, LEGAL-HOLD doc':");
    let decision = correct.check(&admin, &Access, &held_doc, &()).await;
    println!("{}", decision.display_trace());
}

fn verdict(granted: bool) -> &'static str {
    if granted {
        "GRANTED"
    } else {
        "DENIED"
    }
}
