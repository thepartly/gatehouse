//! # PolicyBuilder Example — scoped admin permissions
//!
//! A staff user holds scoped permission grants like "edit_user_settings on
//! org-1". The organization being administered is the *resource*, the action
//! selects which scope is required, and `PolicyBuilder` chains the predicates
//! with AND logic. (The decision needs nothing call-specific, so the context
//! type is `()` — see `mfa_freshness_context` for when a real context earns
//! its place.)
//!
//! To run this example:
//! ```sh
//! cargo run --example policy_builder
//! ```
use gatehouse::*;

/// One grant: a permission scope applied to one entity.
#[derive(Debug, Clone)]
pub struct GroupPermission {
    /// The scope of the permission (e.g., `edit_user_settings`).
    pub scope: &'static str,
    /// The entity the permission applies to (an organization id).
    pub entity: String,
}

#[derive(Debug, Clone)]
pub struct StaffUser {
    pub name: &'static str,
    pub permissions: Vec<GroupPermission>,
}

/// The resource: the organization being administered.
#[derive(Debug, Clone)]
pub struct Organization {
    pub id: String,
}

#[derive(Debug, Clone, Copy)]
pub enum AdminAction {
    EditUserSettings,
    EditOrgSettings,
}

impl AdminAction {
    fn required_scope(self) -> &'static str {
        match self {
            Self::EditUserSettings => "edit_user_settings",
            Self::EditOrgSettings => "edit_org_settings",
        }
    }
}

/// Grants when the user holds the scope the action requires *on this
/// organization*. The predicate reads three axes (subject, action, resource),
/// which is exactly the cross-axis case `.when()` exists for.
fn scoped_permission_policy() -> Box<dyn Policy<StaffUser, Organization, AdminAction, ()>> {
    PolicyBuilder::new("ScopedPermission")
        .when(
            |user: &StaffUser, action: &AdminAction, org: &Organization, _ctx: &()| {
                user.permissions
                    .iter()
                    .any(|p| p.scope == action.required_scope() && p.entity == org.id)
            },
        )
        .build()
}

/// Grants on a single axis — the subject — so it uses `.subjects()` rather
/// than `.when()`: single-axis predicates batch better and read clearer.
fn global_admin_policy() -> Box<dyn Policy<StaffUser, Organization, AdminAction, ()>> {
    PolicyBuilder::new("GlobalAdmin")
        .subjects(|user: &StaffUser| user.permissions.iter().any(|p| p.scope == "global_admin"))
        .build()
}

#[tokio::main]
async fn main() {
    let mut checker = PermissionChecker::<StaffUser, Organization, AdminAction, ()>::new();
    checker.add_policy(scoped_permission_policy());
    checker.add_policy(global_admin_policy());

    let org1 = Organization { id: "org-1".into() };
    let org2 = Organization { id: "org-2".into() };

    let org1_admin = StaffUser {
        name: "org1-admin",
        permissions: vec![GroupPermission {
            scope: "edit_user_settings",
            entity: "org-1".into(),
        }],
    };
    let org2_admin = StaffUser {
        name: "org2-admin",
        permissions: vec![GroupPermission {
            scope: "edit_user_settings",
            entity: "org-2".into(),
        }],
    };
    let no_grants = StaffUser {
        name: "no-grants",
        permissions: vec![],
    };
    let global_admin = StaffUser {
        name: "global-admin",
        permissions: vec![GroupPermission {
            scope: "global_admin",
            entity: String::new(),
        }],
    };

    // (user, action, organization, expected outcome)
    let cases = [
        // Scoped grant matches its own org…
        (&org1_admin, AdminAction::EditUserSettings, &org1, true),
        // …but not another org, and not another scope on the same org.
        (&org2_admin, AdminAction::EditUserSettings, &org1, false),
        (&org1_admin, AdminAction::EditOrgSettings, &org1, false),
        (&org2_admin, AdminAction::EditUserSettings, &org2, true),
        (&no_grants, AdminAction::EditUserSettings, &org1, false),
        // The global admin passes via the subject-axis policy on any org.
        (&global_admin, AdminAction::EditOrgSettings, &org1, true),
    ];

    for (user, action, org, expected_granted) in cases {
        let decision = checker.check(user, &action, org, &()).await;
        println!(
            "{:<12} {:?} on {}: {}",
            user.name,
            action,
            org.id,
            if decision.is_granted() {
                "GRANTED"
            } else {
                "DENIED"
            }
        );
        assert_eq!(decision.is_granted(), expected_granted);
    }

    // The trace names the policy that decided; for a denial it shows every
    // policy that was consulted and why each said no.
    println!("\nWhy org2-admin cannot edit user settings on org-1:");
    let decision = checker
        .check(&org2_admin, &AdminAction::EditUserSettings, &org1, &())
        .await;
    println!("{}", decision.display_trace());
}
