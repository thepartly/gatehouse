//! Composing two custom policies (an org-admin shortcut and a per-permission
//! staff check) into a single `PermissionChecker` and reading the per-policy
//! reasons out of the evaluation trace.
//!
//! Demonstrates: custom `Policy` impls with the new
//! `PolicyEvalResult::granted` / `denied` constructors, OR semantics across
//! policies, and using `EvalTrace` to surface the reason chain.

use async_trait::async_trait;
use gatehouse::*;
use uuid::Uuid;

#[derive(Debug, Clone)]
struct OrganizationAuthorizationDetails {
    id: Uuid,
    is_org_admin: bool,
    permissions: Vec<Permission>,
}

#[derive(Debug, Clone)]
struct Permission {
    scope: String,
}

#[derive(Debug, Clone)]
struct SubjectV2 {
    id: Uuid,
    authorization_details: OrganizationAuthorizationDetails,
}

#[derive(Debug, Clone)]
struct Group {
    id: Uuid,
}

#[derive(Debug, Clone)]
struct GroupManagementAction;

#[derive(Debug, Clone)]
struct EmptyContext;

// Policy that grants access if the user is an organization admin.
struct OrgAdminPolicy;

#[async_trait]
impl Policy<SubjectV2, Group, GroupManagementAction, EmptyContext> for OrgAdminPolicy {
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, SubjectV2, Group, GroupManagementAction, EmptyContext>,
    ) -> PolicyEvalResult {
        if ctx.subject.authorization_details.is_org_admin {
            PolicyEvalResult::granted(
                self.policy_type().to_string(),
                Some("User is organization admin".to_string()),
            )
        } else {
            PolicyEvalResult::denied(
                self.policy_type().to_string(),
                "User is not organization admin",
            )
        }
    }

    fn policy_type(&self) -> &str {
        "OrgAdminPolicy"
    }
}

// Policy that grants access if the user has the `staff` permission.
struct StaffPolicy;

#[async_trait]
impl Policy<SubjectV2, Group, GroupManagementAction, EmptyContext> for StaffPolicy {
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, SubjectV2, Group, GroupManagementAction, EmptyContext>,
    ) -> PolicyEvalResult {
        if ctx
            .subject
            .authorization_details
            .permissions
            .iter()
            .any(|p| p.scope == "staff")
        {
            PolicyEvalResult::granted(
                self.policy_type().to_string(),
                Some("User has staff permission".to_string()),
            )
        } else {
            PolicyEvalResult::denied(
                self.policy_type().to_string(),
                "User lacks staff permission",
            )
        }
    }

    fn policy_type(&self) -> &str {
        "StaffPolicy"
    }
}

// Combine the policies into a permission checker - if either check passes, access is granted.
fn create_group_management_checker(
) -> PermissionChecker<SubjectV2, Group, GroupManagementAction, EmptyContext> {
    let mut checker = PermissionChecker::new();
    checker.add_policy(OrgAdminPolicy);
    checker.add_policy(StaffPolicy);
    checker
}

#[tokio::main]
async fn main() {
    // Example subject with staff but not org admin:
    let subject = SubjectV2 {
        id: Uuid::new_v4(),
        authorization_details: OrganizationAuthorizationDetails {
            id: Uuid::new_v4(),
            is_org_admin: false,
            permissions: vec![Permission {
                scope: "staff".to_string(),
            }],
        },
    };

    let group = Group { id: Uuid::new_v4() };
    let action = GroupManagementAction;
    let context = EmptyContext;

    let checker = create_group_management_checker();
    let session = EvaluationSession::empty();
    let result = checker
        .evaluate_in_session(&session, &subject, &action, &group, &context)
        .await;
    assert!(result.is_granted());
    println!(
        "Evaluating subject {} with org id {} and group {}",
        subject.id, subject.authorization_details.id, group.id
    );
    println!("{}", result.display_trace());

    // [GRANTED] by StaffPolicy - User has staff permission
    // Evaluation Trace:
    // ✔ PermissionChecker (OR)
    //   ✘ OrgAdminPolicy DENIED: User is not organization admin
    //   ✔ StaffPolicy GRANTED: User has staff permission
}
