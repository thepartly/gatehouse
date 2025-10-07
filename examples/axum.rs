// Axum service that authorizes multiple resource types (Invoices, Payments)
// using a single PermissionChecker. Demonstrates multiple policies and actions.

use axum::{
    extract::{Extension, FromRequestParts, Path},
    http::{request::Parts, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use gatehouse::*;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

// --------------------
// 1) Domain Modeling
// --------------------

#[derive(Debug, Clone)]
pub struct User {
    pub id: Uuid,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedUser(pub User);

impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let id = parts
            .headers
            .get("x-user-id")
            .and_then(|value| value.to_str().ok())
            .and_then(|raw| Uuid::parse_str(raw).ok())
            .unwrap_or_else(Uuid::nil);

        let roles = parts
            .headers
            .get("x-roles")
            .and_then(|value| value.to_str().ok())
            .map(|raw| {
                raw.split(',')
                    .map(|role| role.trim().to_ascii_lowercase())
                    .filter(|role| !role.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec!["viewer".to_string()]);

        Ok(AuthenticatedUser(User { id, roles }))
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" => Some(false),
        _ => None,
    }
}

#[derive(Debug, Default, Clone)]
pub struct InvoiceOverrides {
    locked: Option<bool>,
    age_days: Option<u64>,
}

impl InvoiceOverrides {
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let locked = headers
            .get("x-invoice-locked")
            .and_then(|value| value.to_str().ok())
            .and_then(parse_bool);

        let age_days = headers
            .get("x-invoice-age-days")
            .and_then(|value| value.to_str().ok())
            .and_then(|raw| raw.parse::<u64>().ok());

        Self { locked, age_days }
    }

    fn build_invoice(&self, invoice_id: Uuid) -> Invoice {
        Invoice {
            id: invoice_id,
            owner_id: Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap(),
            locked: self.locked.unwrap_or(false),
            created_at: SystemTime::now()
                - Duration::from_secs(self.age_days.unwrap_or(10) * 24 * 60 * 60),
        }
    }
}

impl<S> FromRequestParts<S> for InvoiceOverrides
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self::from_headers(&parts.headers))
    }
}

#[derive(Debug, Default, Clone)]
pub struct PaymentOverrides {
    refunded: Option<bool>,
    approved: Option<bool>,
}

impl PaymentOverrides {
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let refunded = headers
            .get("x-payment-refunded")
            .and_then(|value| value.to_str().ok())
            .and_then(parse_bool);

        let approved = headers
            .get("x-payment-approved")
            .and_then(|value| value.to_str().ok())
            .and_then(parse_bool);

        Self { refunded, approved }
    }

    fn build_payment(&self, payment_id: Uuid) -> Payment {
        Payment {
            id: payment_id,
            invoice_id: Uuid::parse_str("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap(),
            is_refunded: self.refunded.unwrap_or(false),
            approved: self.approved.unwrap_or(false),
        }
    }
}

impl<S> FromRequestParts<S> for PaymentOverrides
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self::from_headers(&parts.headers))
    }
}

/// Main "Action" enum. Your app might have more actions:
///   - Edit an invoice
///   - Approve a payment
///   - Refund a payment
///   - View a resource, etc.
#[derive(Debug, Clone)]
pub enum Action {
    Edit,           // e.g. editing an invoice
    ApprovePayment, // e.g. approving a payment resource
    RefundPayment,  // e.g. refunding a payment
    View,           // a generic "view" action
}

/// Two resource types in our app: invoices and payments. We wrap them
/// in a single enum to share one PermissionChecker across different routes/resources.
#[derive(Debug, Clone)]
pub enum Resource {
    Invoice(Invoice),
    Payment(Payment),
}

/// An invoice resource. For example, you can only edit it if it isn't locked and
/// it's within 30 days of creation (unless you're an admin, which overrides).
#[derive(Debug, Clone)]
pub struct Invoice {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub locked: bool,
    pub created_at: SystemTime,
}

/// A payment resource. Let’s suppose we can only approve or refund it if we have
/// certain roles (e.g., "finance_manager" or "admin").
#[derive(Debug, Clone)]
pub struct Payment {
    pub id: Uuid,
    pub invoice_id: Uuid,
    pub is_refunded: bool,
    pub approved: bool,
}

/// Extra context. Could include "current_time", "feature flags", "organization info", etc.
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub current_time: SystemTime,
}

/// --------------------------
/// 2) Building Our Policies
/// --------------------------
/// We'll create multiple policies that each handle a slice of the logic.
/// Then we combine them with OR or AND as needed.
///
/// (A) `AdminOverridePolicy`
///     Allows any action on any resource if user has the "admin" role.
fn admin_override_policy() -> Box<dyn Policy<User, Resource, Action, RequestContext>> {
    PolicyBuilder::<User, Resource, Action, RequestContext>::new("AdminOverridePolicy")
        .when(|user, _action, _resource, _ctx| user.roles.contains(&"admin".to_string()))
        .build()
}

/// (B) `InvoiceEditingPolicy`
///     Allows editing an invoice if:
///       - It's an `Invoice` resource and the requested action is `Action::Edit`,
///       - The user is the invoice owner,
///       - The invoice is NOT locked,
///       - The invoice is < 30 days old.
///     (If any of these fail, it denies.)
/// We do this by creating four separate sub-policies, `IsInvoiceAndEdit`, `IsOwnerOfInvoice`
/// `InvoiceNotLocked`, `InvoiceAgeUnder30Days`.
/// Then we AND them together. If any sub-policy fails, you’ll see which one did
/// in the evaluation trace (with its own reason).
fn invoice_editing_policy() -> Box<dyn Policy<User, Resource, Action, RequestContext>> {
    // Sub-policy #1: Check that (resource=Invoice) and (action=Edit).
    let is_invoice_and_edit =
        PolicyBuilder::<User, Resource, Action, RequestContext>::new("IsInvoiceAndEdit")
            .when(|_user, action, resource, _ctx| {
                matches!(action, Action::Edit) && matches!(resource, Resource::Invoice(_))
            })
            .build();

    // Sub-policy #2: Must be the owner of the invoice.
    // We must ensure we only run the check *if* it's an Invoice; else we treat it as failing.
    let is_owner = PolicyBuilder::<User, Resource, Action, RequestContext>::new("IsOwnerOfInvoice")
        .when(|user, _action, resource, _ctx| match resource {
            Resource::Invoice(inv) => user.id == inv.owner_id,
            _ => false,
        })
        .build();

    // Sub-policy #3: Invoice must not be locked
    let invoice_not_locked =
        PolicyBuilder::<User, Resource, Action, RequestContext>::new("InvoiceNotLocked")
            .when(|_user, _action, resource, _ctx| match resource {
                Resource::Invoice(inv) => !inv.locked,
                _ => false,
            })
            .build();

    // Sub-policy #4: Invoice must be < 30 days old
    const THIRTY_DAYS: u64 = 30 * 24 * 60 * 60;
    let invoice_age_under_30_days =
        PolicyBuilder::<User, Resource, Action, RequestContext>::new("InvoiceAgeUnder30Days")
            .when(move |_user, _action, resource, ctx| match resource {
                Resource::Invoice(inv) => {
                    let age_secs = ctx
                        .current_time
                        .duration_since(inv.created_at)
                        .unwrap_or_default()
                        .as_secs();
                    age_secs <= THIRTY_DAYS
                }
                _ => false,
            })
            .build();

    // Now AND them together:
    let and_policy = AndPolicy::try_new(vec![
        Arc::from(is_invoice_and_edit),
        Arc::from(is_owner),
        Arc::from(invoice_not_locked),
        Arc::from(invoice_age_under_30_days),
    ])
    .expect("Should have at least one policy in the AND set");

    // Return as a boxed dyn Policy
    Box::new(and_policy)
}

/// (C) `PaymentApprovePolicy`
///     Allows approving a payment if:
///       - It's a `Payment` resource
///       - Action is `Action::ApprovePayment`
///       - The user has "finance_manager" (or "admin", but we have AdminOverride separately)
///       - The payment has not been refunded (already-approved payments can be re-approved)
fn payment_approve_policy() -> Box<dyn Policy<User, Resource, Action, RequestContext>> {
    PolicyBuilder::<User, Resource, Action, RequestContext>::new("PaymentApprovePolicy")
        .when(|user, action, resource, _ctx| match resource {
            Resource::Payment(payment) => {
                matches!(action, Action::ApprovePayment)
                    && user.roles.contains(&"finance_manager".to_string())
                    && !payment.is_refunded
            }
            _ => false,
        })
        .build()
}

/// (D) `PaymentRefundPolicy`
///     Allows refunding a payment if:
///       - It's a `Payment` resource
///       - Action is `Action::RefundPayment`
///       - The user has "finance_manager"
///         OR some other "refund" special role.  (We’ll keep it simple.)
fn payment_refund_policy() -> Box<dyn Policy<User, Resource, Action, RequestContext>> {
    // Alternatively, we can just do a single condition for finance_manager,
    // or combine them. Here let's say "finance_manager" or "refund_specialist".
    Box::new(AbacPolicy::new(
        |user: &User, resource: &Resource, action: &Action, _ctx: &RequestContext| {
            if let Resource::Payment(_) = resource {
                if matches!(action, Action::RefundPayment) {
                    return user.roles.contains(&"finance_manager".into())
                        || user.roles.contains(&"refund_specialist".into());
                }
            }
            false
        },
    ))
}

/// (E) Combine all relevant policies into a single `PermissionChecker`.
///     The checker uses OR semantics by default: if ANY policy returns Granted,
///     the request is allowed.
pub fn build_permission_checker() -> PermissionChecker<User, Resource, Action, RequestContext> {
    let mut checker = PermissionChecker::new();

    // We add them in the order we want them to be evaluated,
    // but note that OR short-circuits on the first Granted. So
    // e.g. if "AdminOverridePolicy" passes, we never evaluate the others.
    checker.add_policy(admin_override_policy());
    checker.add_policy(invoice_editing_policy());
    checker.add_policy(payment_approve_policy());
    checker.add_policy(payment_refund_policy());

    checker
}

// ---------------------------------
// 3) Using in Axum Route Handlers
// ---------------------------------

pub async fn view_invoice_handler(
    Path(invoice_id): Path<Uuid>,
    Extension(checker): Extension<PermissionChecker<User, Resource, Action, RequestContext>>,
    AuthenticatedUser(user): AuthenticatedUser,
    overrides: InvoiceOverrides,
) -> impl IntoResponse {
    // Simulate DB fetch
    let invoice = overrides.build_invoice(invoice_id);

    if checker
        .evaluate_access(
            &user,
            &Action::View,
            &Resource::Invoice(invoice.clone()),
            &RequestContext {
                current_time: SystemTime::now(),
            },
        )
        .await
        .is_granted()
    {
        (StatusCode::OK, format!("{:?}", invoice)).into_response()
    } else {
        (
            StatusCode::FORBIDDEN,
            "You are not authorized to edit this invoice",
        )
            .into_response()
    }
}

pub async fn edit_invoice_handler(
    Path(invoice_id): Path<Uuid>,
    Extension(checker): Extension<PermissionChecker<User, Resource, Action, RequestContext>>,
    AuthenticatedUser(user): AuthenticatedUser,
    overrides: InvoiceOverrides,
) -> impl IntoResponse {
    // Simulate DB fetch
    let invoice = overrides.build_invoice(invoice_id);

    let resource = Resource::Invoice(invoice);
    let action = Action::Edit;
    let context = RequestContext {
        current_time: SystemTime::now(),
    };

    let decision = checker
        .evaluate_access(&user, &action, &resource, &context)
        .await;

    if decision.is_granted() {
        // do the editing...
        (StatusCode::OK, "Invoice edited successfully").into_response()
    } else {
        (
            StatusCode::FORBIDDEN,
            "You are not authorized to edit this invoice",
        )
            .into_response()
    }
}

pub async fn approve_payment_handler(
    Path(payment_id): Path<Uuid>,
    Extension(checker): Extension<PermissionChecker<User, Resource, Action, RequestContext>>,
    AuthenticatedUser(user): AuthenticatedUser,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Simulate DB fetch
    let overrides = PaymentOverrides::from_headers(&headers);
    let payment = overrides.build_payment(payment_id);

    let resource = Resource::Payment(payment);
    let action = Action::ApprovePayment;
    let context = RequestContext {
        current_time: SystemTime::now(),
    };

    let decision = checker
        .evaluate_access(&user, &action, &resource, &context)
        .await;

    if decision.is_granted() {
        // do the approval...
        (StatusCode::OK, "Payment approved").into_response()
    } else {
        (
            StatusCode::FORBIDDEN,
            "You are not authorized to approve this payment",
        )
            .into_response()
    }
}

// ----------------------------------------
// 4) The Axum App with Our PermissionChecker
// ----------------------------------------

#[tokio::main]
async fn main() {
    // Build our single permission checker and share it with handlers as Extension state.
    let checker = build_permission_checker();

    // Construct Axum Router
    let app = Router::new()
        .route("/invoices/{invoice_id}", get(view_invoice_handler))
        .route("/invoices/{invoice_id}/edit", post(edit_invoice_handler))
        .route(
            "/payments/{payment_id}/approve",
            post(approve_payment_handler),
        )
        .layer(Extension(checker));

    // Run Axum App
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await.unwrap();
    println!("Listening on http://0.0.0.0:8000");
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use gatehouse::AccessEvaluation;
    use std::time::{Duration, SystemTime};

    // Helper to quickly build an invoice with desired properties
    fn make_invoice(owner_id: Uuid, locked: bool, age_in_days: u64) -> Invoice {
        Invoice {
            id: Uuid::new_v4(),
            owner_id,
            locked,
            created_at: SystemTime::now() - Duration::from_secs(age_in_days * 24 * 60 * 60),
        }
    }

    // Helper to quickly build a payment
    fn make_payment(invoice_id: Uuid, is_refunded: bool, approved: bool) -> Payment {
        Payment {
            id: Uuid::new_v4(),
            invoice_id,
            is_refunded,
            approved,
        }
    }

    // Helper to build a RequestContext
    fn context_now() -> RequestContext {
        RequestContext {
            current_time: SystemTime::now(),
        }
    }

    #[tokio::test]
    async fn test_admin_override() {
        let checker = build_permission_checker();
        let admin_user = User {
            id: Uuid::new_v4(),
            roles: vec!["admin".to_string()],
        };

        // Attempt any action on any resource
        let invoice = make_invoice(
            admin_user.id,
            /*locked=*/ true,
            /*age_in_days=*/ 60,
        );
        let resource = Resource::Invoice(invoice);

        let result = checker
            .evaluate_access(&admin_user, &Action::Edit, &resource, &context_now())
            .await;

        assert!(
            result.is_granted(),
            "AdminOverridePolicy should allow admin to do anything"
        );

        match result {
            AccessEvaluation::Granted { policy_type, .. } => {
                assert_eq!(&policy_type, "AdminOverridePolicy");
            }
            _ => panic!("Expected admin override to be granted"),
        }
    }

    #[tokio::test]
    async fn test_invoice_editing_owner_unlocked_recent() {
        let checker = build_permission_checker();
        let owner_id = Uuid::new_v4();
        let user = User {
            id: owner_id,
            roles: vec!["user".to_string()],
        };

        // Invoice is not locked, 10 days old
        let invoice = make_invoice(owner_id, /*locked=*/ false, /*age_in_days=*/ 10);
        let resource = Resource::Invoice(invoice);

        // The user is the owner, the invoice is unlocked, <30 days old => should be granted
        let result = checker
            .evaluate_access(&user, &Action::Edit, &resource, &context_now())
            .await;

        assert!(
            result.is_granted(),
            "Invoice editing policy should allow owner if under 30 days, unlocked"
        );
    }

    #[tokio::test]
    async fn test_invoice_editing_denied_if_locked() {
        let checker = build_permission_checker();
        let owner_id = Uuid::new_v4();
        let user = User {
            id: owner_id,
            roles: vec!["user".to_string()],
        };

        // Invoice is locked, 10 days old
        let invoice = make_invoice(owner_id, /*locked=*/ true, /*age_in_days=*/ 10);
        let resource = Resource::Invoice(invoice);

        let result = checker
            .evaluate_access(&user, &Action::Edit, &resource, &context_now())
            .await;

        assert!(
            !result.is_granted(),
            "Should be denied if invoice is locked"
        );

        // We can also look at trace to see which sub-policy failed
        if let AccessEvaluation::Denied { trace, .. } = result {
            let trace_str = trace.format();
            assert!(
                trace_str.contains("InvoiceNotLocked"),
                "Expected InvoiceNotLocked sub-policy to fail in trace: \n{}",
                trace_str
            );
        }
    }

    #[tokio::test]
    async fn test_invoice_editing_denied_if_not_owner() {
        let checker = build_permission_checker();
        let actual_owner_id = Uuid::new_v4();
        let another_user_id = Uuid::new_v4();

        let user = User {
            id: another_user_id,
            roles: vec!["user".to_string()],
        };

        let invoice = make_invoice(
            actual_owner_id,
            /*locked=*/ false,
            /*age_in_days=*/ 10,
        );
        let resource = Resource::Invoice(invoice);

        let result = checker
            .evaluate_access(&user, &Action::Edit, &resource, &context_now())
            .await;

        assert!(
            !result.is_granted(),
            "Should be denied if user is not the owner"
        );

        if let AccessEvaluation::Denied { trace, .. } = result {
            let trace_str = trace.format();
            assert!(
                trace_str.contains("IsOwnerOfInvoice"),
                "Expected IsOwnerOfInvoice sub-policy to fail"
            );
        }
    }

    #[tokio::test]
    async fn test_invoice_editing_denied_if_too_old() {
        let checker = build_permission_checker();
        let owner_id = Uuid::new_v4();
        let user = User {
            id: owner_id,
            roles: vec!["user".to_string()],
        };

        // 31 days old => should fail the "InvoiceAgeUnder30Days" sub-policy
        let invoice = make_invoice(owner_id, /*locked=*/ false, /*age_in_days=*/ 31);
        let resource = Resource::Invoice(invoice);

        let result = checker
            .evaluate_access(&user, &Action::Edit, &resource, &context_now())
            .await;
        assert!(
            !result.is_granted(),
            "Should be denied if invoice is older than 30 days"
        );
    }

    #[tokio::test]
    async fn test_payment_approve_finance_manager() {
        let checker = build_permission_checker();

        // finance_manager role is allowed to ApprovePayment
        let user = User {
            id: Uuid::new_v4(),
            roles: vec!["finance_manager".to_string()],
        };
        let payment = make_payment(
            Uuid::new_v4(),
            /*is_refunded=*/ false,
            /*approved=*/ false,
        );
        let resource = Resource::Payment(payment);

        let result = checker
            .evaluate_access(&user, &Action::ApprovePayment, &resource, &context_now())
            .await;

        assert!(
            result.is_granted(),
            "PaymentApprovePolicy should allow finance_manager to approve"
        );
    }

    #[tokio::test]
    async fn test_payment_approve_finance_manager_idempotent() {
        let checker = build_permission_checker();

        let user = User {
            id: Uuid::new_v4(),
            roles: vec!["finance_manager".to_string()],
        };
        let payment = make_payment(
            Uuid::new_v4(),
            /*is_refunded=*/ false,
            /*approved=*/ true,
        );
        let resource = Resource::Payment(payment);

        let result = checker
            .evaluate_access(&user, &Action::ApprovePayment, &resource, &context_now())
            .await;

        assert!(
            result.is_granted(),
            "PaymentApprovePolicy should allow finance_manager to re-approve",
        );
    }

    #[tokio::test]
    async fn test_payment_approve_denied_for_regular_user() {
        let checker = build_permission_checker();

        let user = User {
            id: Uuid::new_v4(),
            roles: vec!["regular_user".to_string()],
        };
        let payment = make_payment(Uuid::new_v4(), false, false);
        let resource = Resource::Payment(payment);

        // Not finance_manager or admin => deny
        let result = checker
            .evaluate_access(&user, &Action::ApprovePayment, &resource, &context_now())
            .await;
        assert!(
            !result.is_granted(),
            "Regular user should not be able to approve"
        );
    }

    #[tokio::test]
    async fn test_payment_refund_finance_or_refund_specialist() {
        let checker = build_permission_checker();

        let user_finance = User {
            id: Uuid::new_v4(),
            roles: vec!["finance_manager".to_string()],
        };
        let user_refund_specialist = User {
            id: Uuid::new_v4(),
            roles: vec!["refund_specialist".to_string()],
        };

        let payment = make_payment(Uuid::new_v4(), false, false);
        let resource = Resource::Payment(payment);

        // 1) finance_manager can refund
        let res1 = checker
            .evaluate_access(
                &user_finance,
                &Action::RefundPayment,
                &resource,
                &context_now(),
            )
            .await;
        assert!(res1.is_granted(), "finance_manager is allowed to refund");

        // 2) refund_specialist can refund
        let res2 = checker
            .evaluate_access(
                &user_refund_specialist,
                &Action::RefundPayment,
                &resource,
                &context_now(),
            )
            .await;
        assert!(res2.is_granted(), "refund_specialist is allowed to refund");
    }

    #[tokio::test]
    async fn test_payment_refund_denied_for_regular_user() {
        let checker = build_permission_checker();

        let user = User {
            id: Uuid::new_v4(),
            roles: vec!["user".to_string()],
        };
        let payment = make_payment(Uuid::new_v4(), false, false);
        let resource = Resource::Payment(payment);

        // Should be denied
        let result = checker
            .evaluate_access(&user, &Action::RefundPayment, &resource, &context_now())
            .await;
        assert!(!result.is_granted(), "Regular user can't refund payment");
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        Router,
    };
    use tower::ServiceExt;

    fn test_app() -> Router {
        let checker = build_permission_checker();
        Router::new()
            .route("/invoices/{invoice_id}/edit", post(edit_invoice_handler))
            .layer(Extension(checker))
    }

    #[tokio::test]
    async fn test_edit_invoice_handler_allows_admin() {
        let app = test_app();

        // We'll pretend the path param is some random UUID
        let req = Request::builder()
            .method("POST")
            .uri("/invoices/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/edit")
            .header("x-roles", "admin")
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(req).await.unwrap();
        // With the admin role header set we expect 200 OK
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_edit_invoice_handler_denies_regular_user_if_locked() {
        let app = test_app();

        let req = Request::builder()
            .method("POST")
            .uri("/invoices/cccccccc-cccc-cccc-cccc-cccccccccccc/edit")
            .header("x-user-id", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
            .header("x-roles", "author")
            .header("x-invoice-locked", "true")
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(req).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
