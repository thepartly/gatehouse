//! # Edit User Settings Permission Example
//!
//! This example demonstrates creating a custom policy using the `PolicyBuilder`
//! to check if an organization's authorization details grant the "edit_user_settings"
//! permission for a specified target entity.
//!
//! To run this example:
//! ```sh
//! cargo run --package permissions --example policy_builder
//! ```
use permissions::*;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct GroupPermission {
    /// The scope of the permission (e.g., `edit_user_settings`).
    pub scope: String,
    /// The entity the permission applies to (e.g., an organization ID as string).
    pub entity: String,
}

#[derive(Debug, Clone)]
pub struct OrganizationAuthorizationDetails {
    /// Organization ID.
    pub id: Uuid,
    /// A vector of permissions associated with the organization.
    pub permissions: Vec<GroupPermission>,
}

// A helper function that creates a policy for checking permissions based on the scope.
fn org_has_permission(
    scope: String,
) -> Box<dyn Policy<OrganizationAuthorizationDetails, (), (), String>> {
    PolicyBuilder::new(scope.clone())
        .when(
            move |org: &OrganizationAuthorizationDetails, _action, _resource, target_entity| {
                // Check if the permission matches the scope and target entity.
                org.permissions
                    .iter()
                    .any(|p| p.scope == scope && p.entity == *target_entity)
            },
        )
        .build()
}

#[tokio::main]
async fn main() {
    // Build a PermissionChecker with two custom policies using the above helper.
    let mut checker = PermissionChecker::<OrganizationAuthorizationDetails, (), (), String>::new();
    checker.add_policy(org_has_permission("edit_user_settings".to_string()));
    checker.add_policy(org_has_permission("edit_org_settings".to_string()));

    checker.add_policy(
        PolicyBuilder::new("GlobalAdmin")
            .subjects(|org: &OrganizationAuthorizationDetails| {
                org.permissions.iter().any(|p| p.scope == "global_admin")
            })
            .build(),
    );

    // Create sample organization authorization details.
    // org1 has "edit_user_settings" for "org1".
    let org1 = OrganizationAuthorizationDetails {
        id: Uuid::new_v4(),
        permissions: vec![GroupPermission {
            scope: "edit_user_settings".to_string(),
            entity: "org1".to_string(),
        }],
    };

    // org2 has "edit_user_settings" for "org2".
    let org2 = OrganizationAuthorizationDetails {
        id: Uuid::new_v4(),
        permissions: vec![GroupPermission {
            scope: "edit_user_settings".to_string(),
            entity: "org2".to_string(),
        }],
    };

    // org3 has no permissions for any org
    let org3 = OrganizationAuthorizationDetails {
        id: Uuid::new_v4(),
        permissions: vec![],
    };
    // org4 has global admin permissions
    let org4 = OrganizationAuthorizationDetails {
        id: Uuid::new_v4(),
        permissions: vec![GroupPermission {
            scope: "global_admin".to_string(),
            entity: "".to_string(),
        }],
    };

    // Evaluate the policy with different target entities as context.
    // 1. org1 should be granted access when the target is "org1".
    let result1 = checker
        .evaluate_access(&org1, &(), &(), &"org1".to_string())
        .await;
    println!("Org1 on 'org1': {}", result1);
    assert_eq!(result1.is_granted(), true);

    // 2. org2 should be denied access when the target is "org1".
    let result2 = checker
        .evaluate_access(&org2, &(), &(), &"org1".to_string())
        .await;
    println!("Org2 on 'org1': {}", result2);
    assert_eq!(result2.is_granted(), false);

    // 3. org2 should be granted access when the target is "org2".
    let result3 = checker
        .evaluate_access(&org2, &(), &(), &"org2".to_string())
        .await;
    println!("Org2 on 'org2': {}", result3);
    assert_eq!(result3.is_granted(), true);

    // 4. org3 should be denied access regardless of the target since it doesn't have the correct permission.
    let result4 = checker
        .evaluate_access(&org3, &(), &(), &"org1".to_string())
        .await;
    println!("Org3 on 'org1': {}", result4);
    assert_eq!(result4.is_granted(), false);

    // 5. org4 should be granted access since it has global admin permissions
    let result5 = checker
        .evaluate_access(&org4, &(), &(), &"org1".to_string())
        .await;
    println!("Org4 on 'org1': {}", result5);
    assert_eq!(result5.is_granted(), true);
}
