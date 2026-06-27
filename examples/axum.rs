// Axum service showing how Gatehouse fits into extractors, shared app state,
// request-scoped sessions, and route handlers.
//
// The app authorizes one resource type — invoices — across a few actions and a
// batch list endpoint. Keeping it to a single resource type means a single
// `PermissionChecker` is the right shape here. A larger service with several
// unrelated resource types would use one checker per resource type and share
// cross-cutting policies (an admin override, say) across them, rather than
// widening one checker over a `Resource` enum.
//
// Authorization paths:
//   - an admin may do anything (cross-cutting override),
//   - the owner may edit an unlocked invoice that is under 30 days old,
//   - a user with a `viewer` relationship may view an invoice (the relationship
//     is loaded through a request-scoped `EvaluationSession` + `FactSource`).

use async_trait::async_trait;
use axum::{
    extract::{FromRequestParts, Path, State},
    http::{request::Parts, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use gatehouse::*;
use serde::Serialize;
use std::collections::HashSet;
use std::fmt;
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

/// Header overrides so a single demo invoice can be coerced into different
/// shapes (locked, older than the edit window) from `curl`.
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
            owner_id: demo_owner_id(),
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

/// Actions an invoice supports in this demo.
#[derive(Debug, Clone)]
pub enum Action {
    Edit,
    View,
}

/// An invoice. It can be edited only if it isn't locked and is within 30 days
/// of creation (unless you're an admin, which overrides).
#[derive(Debug, Clone)]
pub struct Invoice {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub locked: bool,
    pub created_at: SystemTime,
}

/// Extra request-scoped context. Could include feature flags, organization
/// info, etc.; here it carries the request's wall clock for the age check.
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub current_time: SystemTime,
}

impl RequestContext {
    fn now() -> Self {
        Self {
            current_time: SystemTime::now(),
        }
    }
}

pub struct InvoiceDomain;

impl PolicyDomain for InvoiceDomain {
    type Subject = User;
    type Action = Action;
    type Resource = Invoice;
    type Context = RequestContext;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Relation {
    Viewer,
}

impl fmt::Display for Relation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Viewer => f.write_str("viewer"),
        }
    }
}

type InvoiceRelationship = RelationshipQuery<Uuid, Uuid, Relation>;

#[derive(Clone)]
pub struct InMemoryRelationshipSource {
    grants: Arc<HashSet<InvoiceRelationship>>,
}

impl InMemoryRelationshipSource {
    fn new(grants: impl IntoIterator<Item = InvoiceRelationship>) -> Self {
        Self {
            grants: Arc::new(grants.into_iter().collect()),
        }
    }
}

#[async_trait]
impl FactSource<InvoiceRelationship> for InMemoryRelationshipSource {
    async fn load_many(&self, keys: &[InvoiceRelationship]) -> Vec<FactLoadResult<bool>> {
        keys.iter()
            .map(|key| FactLoadResult::Found(self.grants.contains(key)))
            .collect()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct InvoiceSummary {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub locked: bool,
}

impl From<Invoice> for InvoiceSummary {
    fn from(invoice: Invoice) -> Self {
        Self {
            id: invoice.id,
            owner_id: invoice.owner_id,
            locked: invoice.locked,
        }
    }
}

// --------------------------
// 2) Shared application state
// --------------------------

/// The long-lived pieces are built once at startup: the checker and fact
/// registry. Each request derives a fresh `EvaluationSession` from the
/// registry.
#[derive(Clone)]
pub struct AppState {
    checker: PermissionChecker<InvoiceDomain>,
    fact_registry: FactRegistry,
    invoices: Arc<Vec<Invoice>>,
}

impl AppState {
    pub fn demo() -> Self {
        let viewer_id = demo_viewer_id();
        let invoices = Arc::new(demo_invoices());
        // The demo viewer has a `viewer` relationship on every invoice they
        // don't already own.
        let grants = invoices
            .iter()
            .filter(|invoice| invoice.owner_id != demo_owner_id())
            .map(|invoice| InvoiceRelationship {
                subject_id: viewer_id,
                resource_id: invoice.id,
                relation: Relation::Viewer,
            });

        Self {
            checker: build_permission_checker(),
            fact_registry: FactRegistry::builder()
                .with_arc::<InvoiceRelationship>(Arc::new(InMemoryRelationshipSource::new(grants)))
                .build(),
            invoices,
        }
    }

    fn request_session(&self) -> EvaluationSession {
        self.fact_registry.session()
    }
}

fn demo_owner_id() -> Uuid {
    Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap()
}

fn demo_viewer_id() -> Uuid {
    Uuid::parse_str("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee").unwrap()
}

fn demo_invoices() -> Vec<Invoice> {
    vec![
        Invoice {
            id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            owner_id: demo_owner_id(),
            locked: false,
            created_at: SystemTime::now() - Duration::from_secs(10 * 24 * 60 * 60),
        },
        Invoice {
            id: Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
            owner_id: Uuid::parse_str("cccccccc-cccc-cccc-cccc-cccccccccccc").unwrap(),
            locked: false,
            created_at: SystemTime::now() - Duration::from_secs(5 * 24 * 60 * 60),
        },
        Invoice {
            id: Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap(),
            owner_id: Uuid::parse_str("dddddddd-dddd-dddd-dddd-dddddddddddd").unwrap(),
            locked: true,
            created_at: SystemTime::now() - Duration::from_secs(2 * 24 * 60 * 60),
        },
    ]
}

// --------------------------
// 3) Building Our Policies
// --------------------------
// Each policy handles a slice of the logic; the checker ORs them together.

/// (A) Admins may do anything — the cross-cutting override.
fn admin_override_policy() -> Box<dyn Policy<InvoiceDomain>> {
    PolicyBuilder::<InvoiceDomain>::new("AdminOverridePolicy")
        .when(|user, _action, _invoice, _ctx| user.roles.contains(&"admin".to_string()))
        .build()
}

/// (B) A user with a `viewer` relationship may view the invoice. The
/// relationship is loaded through the request-scoped `EvaluationSession`; in a
/// real service the source wraps a database pool or graph client.
fn invoice_viewer_policy() -> Box<dyn Policy<InvoiceDomain>> {
    let is_view: Arc<dyn Policy<InvoiceDomain>> = Arc::from(
        PolicyBuilder::<InvoiceDomain>::new("IsView")
            .when(|_user, action, _invoice, _ctx| matches!(action, Action::View))
            .build(),
    );
    let viewer_relationship: Arc<dyn Policy<InvoiceDomain>> =
        Arc::new(RebacPolicy::<InvoiceDomain, Uuid, Uuid, Relation>::new(
            |user: &User| user.id,
            |invoice: &Invoice| invoice.id,
            Relation::Viewer,
        ));

    Box::new(
        AndPolicy::try_new(vec![is_view, viewer_relationship])
            .expect("invoice viewer policy has the guard and relationship checks"),
    )
}

/// (C) The owner may edit the invoice if it is unlocked and under 30 days old.
/// Built from small sub-policies AND-ed together, so a denial trace names the
/// sub-policy that failed.
fn invoice_editing_policy() -> Box<dyn Policy<InvoiceDomain>> {
    let is_edit = PolicyBuilder::<InvoiceDomain>::new("IsEdit")
        .when(|_user, action, _invoice, _ctx| matches!(action, Action::Edit))
        .build();

    let is_owner = PolicyBuilder::<InvoiceDomain>::new("IsOwnerOfInvoice")
        .when(|user, _action, invoice, _ctx| user.id == invoice.owner_id)
        .build();

    let invoice_not_locked = PolicyBuilder::<InvoiceDomain>::new("InvoiceNotLocked")
        .when(|_user, _action, invoice, _ctx| !invoice.locked)
        .build();

    const THIRTY_DAYS: u64 = 30 * 24 * 60 * 60;
    let invoice_age_under_30_days = PolicyBuilder::<InvoiceDomain>::new("InvoiceAgeUnder30Days")
        .when(move |_user, _action, invoice, ctx| {
            ctx.current_time
                .duration_since(invoice.created_at)
                .unwrap_or_default()
                .as_secs()
                <= THIRTY_DAYS
        })
        .build();

    Box::new(
        AndPolicy::try_new(vec![
            Arc::from(is_edit),
            Arc::from(is_owner),
            Arc::from(invoice_not_locked),
            Arc::from(invoice_age_under_30_days),
        ])
        .expect("invoice editing policy has at least one rule"),
    )
}

/// (D) Combine the policies into a single `PermissionChecker`. With no
/// forbid-effect policies registered, deny-overrides reduces to OR semantics:
/// if any policy grants, access is allowed (and evaluation short-circuits).
pub fn build_permission_checker() -> PermissionChecker<InvoiceDomain> {
    let mut checker = PermissionChecker::named("InvoiceChecker");
    checker.add_policy(admin_override_policy());
    checker.add_policy(invoice_viewer_policy());
    checker.add_policy(invoice_editing_policy());
    checker
}

// ---------------------------------
// 4) Using in Axum Route Handlers
// ---------------------------------

pub async fn view_invoice_handler(
    Path(invoice_id): Path<Uuid>,
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    overrides: InvoiceOverrides,
) -> impl IntoResponse {
    // Simulate a DB fetch.
    let invoice = overrides.build_invoice(invoice_id);
    let session = state.request_session();
    let context = RequestContext::now();

    if state
        .checker
        .bind(&session, &user, &Action::View, &context)
        .check(&invoice)
        .await
        .is_granted()
    {
        (StatusCode::OK, format!("{invoice:?}")).into_response()
    } else {
        (
            StatusCode::FORBIDDEN,
            "You are not authorized to view this invoice",
        )
            .into_response()
    }
}

pub async fn list_invoices_handler(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
) -> impl IntoResponse {
    let session = state.request_session();
    let candidates = state.invoices.as_ref().clone();
    let context = RequestContext::now();

    // The session is request-scoped: app state owns the source, this request
    // registers it, and the batch authorization call uses it for every invoice
    // — relationship loads are batched and deduplicated.
    let visible = state
        .checker
        .bind(&session, &user, &Action::View, &context)
        .filter(candidates)
        .await
        .into_iter()
        .map(InvoiceSummary::from)
        .collect::<Vec<_>>();

    Json(visible).into_response()
}

pub async fn edit_invoice_handler(
    Path(invoice_id): Path<Uuid>,
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    overrides: InvoiceOverrides,
) -> impl IntoResponse {
    let invoice = overrides.build_invoice(invoice_id);
    let session = state.request_session();
    let context = RequestContext::now();

    if state
        .checker
        .bind(&session, &user, &Action::Edit, &context)
        .check(&invoice)
        .await
        .is_granted()
    {
        (StatusCode::OK, "Invoice edited successfully").into_response()
    } else {
        (
            StatusCode::FORBIDDEN,
            "You are not authorized to edit this invoice",
        )
            .into_response()
    }
}

// ----------------------------------------
// 5) The Axum App with Our PermissionChecker
// ----------------------------------------

#[tokio::main]
async fn main() {
    // Build the long-lived checker and relationship source once, then create a
    // fresh EvaluationSession inside each handler.
    let state = AppState::demo();

    let app = Router::new()
        .route("/invoices", get(list_invoices_handler))
        .route("/invoices/{invoice_id}", get(view_invoice_handler))
        .route("/invoices/{invoice_id}/edit", post(edit_invoice_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await.unwrap();
    println!("Listening on http://0.0.0.0:8000");
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use gatehouse::AccessEvaluation;
    use std::time::{Duration, SystemTime};

    fn make_invoice(owner_id: Uuid, locked: bool, age_in_days: u64) -> Invoice {
        Invoice {
            id: Uuid::new_v4(),
            owner_id,
            locked,
            created_at: SystemTime::now() - Duration::from_secs(age_in_days * 24 * 60 * 60),
        }
    }

    fn context_now() -> RequestContext {
        RequestContext {
            current_time: SystemTime::now(),
        }
    }

    #[tokio::test]
    async fn admin_override_allows_anything() {
        let checker = build_permission_checker();
        let admin = User {
            id: Uuid::new_v4(),
            roles: vec!["admin".to_string()],
        };

        // A locked, 60-day-old invoice the admin doesn't own.
        let invoice = make_invoice(
            Uuid::new_v4(),
            /*locked=*/ true,
            /*age_in_days=*/ 60,
        );

        let session = EvaluationSession::empty();
        let context = context_now();
        let result = checker
            .bind(&session, &admin, &Action::Edit, &context)
            .check(&invoice)
            .await;

        assert!(result.is_granted(), "admin override should allow anything");
        match result {
            AccessEvaluation::Granted { policy_type, .. } => {
                assert_eq!(&policy_type, "AdminOverridePolicy");
            }
            _ => panic!("expected admin override to grant"),
        }
    }

    #[tokio::test]
    async fn owner_can_edit_unlocked_recent_invoice() {
        let checker = build_permission_checker();
        let owner_id = Uuid::new_v4();
        let user = User {
            id: owner_id,
            roles: vec!["user".to_string()],
        };

        let invoice = make_invoice(owner_id, /*locked=*/ false, /*age_in_days=*/ 10);

        let session = EvaluationSession::empty();
        let context = context_now();
        let result = checker
            .bind(&session, &user, &Action::Edit, &context)
            .check(&invoice)
            .await;

        assert!(
            result.is_granted(),
            "owner should edit an unlocked invoice under 30 days old"
        );
    }

    #[tokio::test]
    async fn locked_invoice_cannot_be_edited() {
        let checker = build_permission_checker();
        let owner_id = Uuid::new_v4();
        let user = User {
            id: owner_id,
            roles: vec!["user".to_string()],
        };

        let invoice = make_invoice(owner_id, /*locked=*/ true, /*age_in_days=*/ 10);

        let session = EvaluationSession::empty();
        let context = context_now();
        let result = checker
            .bind(&session, &user, &Action::Edit, &context)
            .check(&invoice)
            .await;

        assert!(!result.is_granted(), "a locked invoice should be denied");

        if let AccessEvaluation::Denied { trace, .. } = result {
            let trace_str = trace.format();
            assert!(
                trace_str.contains("InvoiceNotLocked"),
                "expected InvoiceNotLocked to fail in trace:\n{trace_str}"
            );
        }
    }

    #[tokio::test]
    async fn non_owner_cannot_edit() {
        let checker = build_permission_checker();
        let user = User {
            id: Uuid::new_v4(),
            roles: vec!["user".to_string()],
        };

        let invoice = make_invoice(
            Uuid::new_v4(),
            /*locked=*/ false,
            /*age_in_days=*/ 10,
        );

        let session = EvaluationSession::empty();
        let context = context_now();
        let result = checker
            .bind(&session, &user, &Action::Edit, &context)
            .check(&invoice)
            .await;

        assert!(!result.is_granted(), "a non-owner should be denied");
        if let AccessEvaluation::Denied { trace, .. } = result {
            assert!(
                trace.format().contains("IsOwnerOfInvoice"),
                "expected IsOwnerOfInvoice to fail in trace"
            );
        }
    }

    #[tokio::test]
    async fn stale_invoice_cannot_be_edited() {
        let checker = build_permission_checker();
        let owner_id = Uuid::new_v4();
        let user = User {
            id: owner_id,
            roles: vec!["user".to_string()],
        };

        // 31 days old => fails InvoiceAgeUnder30Days.
        let invoice = make_invoice(owner_id, /*locked=*/ false, /*age_in_days=*/ 31);

        let session = EvaluationSession::empty();
        let context = context_now();
        let result = checker
            .bind(&session, &user, &Action::Edit, &context)
            .check(&invoice)
            .await;
        assert!(
            !result.is_granted(),
            "an invoice older than 30 days should be denied"
        );
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
        Router::new()
            .route("/invoices/{invoice_id}/edit", post(edit_invoice_handler))
            .with_state(AppState::demo())
    }

    #[tokio::test]
    async fn edit_invoice_handler_allows_admin() {
        let app = test_app();

        let req = Request::builder()
            .method("POST")
            .uri("/invoices/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/edit")
            .header("x-roles", "admin")
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn edit_invoice_handler_denies_regular_user_if_locked() {
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
