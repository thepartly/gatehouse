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
//
// The request supplies identity only: `x-user-id` and `x-roles` stand in for a
// real authentication layer. Everything the policies read about an invoice comes
// from `InvoiceStore` — the handler loads the row first and authorizes that
// snapshot, so a caller cannot describe the resource into a shape that passes.
//
// Routes:
//   GET  /invoices               invoices the caller may view (JSON array)
//   GET  /invoices/{id}          one invoice summary (JSON)
//   POST /invoices/{id}/edit     body {"amount_cents": N} -> updated summary (JSON)
//
// Fixtures:
//   11111111-…  owner aaaaaaaa-… (demo owner), unlocked, 10 days old
//   22222222-…  owner cccccccc-…,              unlocked,  5 days old
//   33333333-…  owner dddddddd-…,              locked,    2 days old
//   44444444-…  owner aaaaaaaa-… (demo owner), unlocked, 45 days old
//
// Try it:
//   # the owner edits their own invoice -> 200, body shows amount_cents 4200, version 2
//   curl -X POST localhost:8000/invoices/11111111-1111-1111-1111-111111111111/edit \
//     -H 'x-user-id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' \
//     -H 'content-type: application/json' -d '{"amount_cents":4200}'
//
//   # the same owner on 44444444-… (past the 30-day edit window), the demo owner on
//   # someone else's 22222222-…, or dddddddd-… on the locked 33333333-… -> 403
//   curl -i -X POST localhost:8000/invoices/44444444-4444-4444-4444-444444444444/edit \
//     -H 'x-user-id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' \
//     -H 'content-type: application/json' -d '{"amount_cents":4200}'
//
//   # an id the store does not hold -> 404, for admins too
//   curl -i localhost:8000/invoices/99999999-9999-9999-9999-999999999999 -H 'x-roles: admin'
//
//   # overlapping authorization snapshots can produce 409; sequential edits both get 200
//   # the guard protects the server's authorization snapshot, not a client-held version
//   for _ in 1 2; do curl -s -o /dev/null -w '%{http_code}\n' \
//     -X POST localhost:8000/invoices/11111111-1111-1111-1111-111111111111/edit \
//     -H 'x-user-id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' \
//     -H 'content-type: application/json' -d '{"amount_cents":4200}' & done; wait

use async_trait::async_trait;
use axum::{
    extract::{FromRequestParts, Path, State},
    http::{request::Parts, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use gatehouse::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::sync::{Arc, RwLock};
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

/// Demo-only identity from caller-supplied headers; performs no authentication.
#[derive(Debug, Clone)]
pub struct DemoUser(pub User);

impl<S> FromRequestParts<S> for DemoUser
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

        Ok(DemoUser(User { id, roles }))
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
///
/// `version` is the store's optimistic-concurrency token: it changes on every
/// accepted mutation, so a writer can name the revision it was authorized
/// against.
#[derive(Debug, Clone)]
pub struct Invoice {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub locked: bool,
    pub created_at: SystemTime,
    pub amount_cents: i64,
    pub version: u64,
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

/// What the API returns for an invoice.
#[derive(Debug, Clone, Serialize)]
pub struct InvoiceSummary {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub locked: bool,
    pub amount_cents: i64,
    pub version: u64,
}

impl From<Invoice> for InvoiceSummary {
    fn from(invoice: Invoice) -> Self {
        Self {
            id: invoice.id,
            owner_id: invoice.owner_id,
            locked: invoice.locked,
            amount_cents: invoice.amount_cents,
            version: invoice.version,
        }
    }
}

/// Body of `POST /invoices/{id}/edit`.
#[derive(Debug, Clone, Deserialize)]
pub struct EditInvoice {
    pub amount_cents: i64,
}

// -----------------------
// 2) The Invoice Store
// -----------------------

/// Why the store refused a mutation — as opposed to a policy refusing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateError {
    /// No invoice with that id.
    NotFound,
    /// The invoice moved on since the caller read it; `current` is where it is now.
    VersionConflict { current: u64 },
}

/// The one authoritative copy of the invoices, standing in for a database.
///
/// A `BTreeMap` keeps listing order deterministic, and a std `RwLock` is enough
/// because the guard is never held across an `.await`: each method takes the
/// lock, finishes its work, and hands back owned snapshots.
#[derive(Clone)]
pub struct InvoiceStore {
    invoices: Arc<RwLock<BTreeMap<Uuid, Invoice>>>,
}

impl InvoiceStore {
    /// Loads the store with its initial rows.
    pub fn new(invoices: Vec<Invoice>) -> Self {
        Self {
            invoices: Arc::new(RwLock::new(
                invoices
                    .into_iter()
                    .map(|invoice| (invoice.id, invoice))
                    .collect(),
            )),
        }
    }

    /// Reads one invoice, or `None` when the store does not hold it.
    pub fn get(&self, id: Uuid) -> Option<Invoice> {
        self.read().get(&id).cloned()
    }

    /// Reads every invoice, in id order.
    pub fn list(&self) -> Vec<Invoice> {
        self.read().values().cloned().collect()
    }

    /// Applies `apply` to the invoice only while it is still at
    /// `expected_version`, then bumps the version and returns the new snapshot.
    ///
    /// A mismatch changes nothing: the caller is holding a stale read and has to
    /// start over from the current row.
    pub fn update_if_version<F: FnOnce(&mut Invoice)>(
        &self,
        id: Uuid,
        expected_version: u64,
        apply: F,
    ) -> Result<Invoice, UpdateError> {
        let mut invoices = self
            .invoices
            .write()
            .expect("invoice store lock is poisoned");
        let invoice = invoices.get_mut(&id).ok_or(UpdateError::NotFound)?;
        if invoice.version != expected_version {
            return Err(UpdateError::VersionConflict {
                current: invoice.version,
            });
        }
        apply(invoice);
        invoice.version += 1;
        Ok(invoice.clone())
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, BTreeMap<Uuid, Invoice>> {
        self.invoices
            .read()
            .expect("invoice store lock is poisoned")
    }
}

// --------------------------
// 3) Shared application state
// --------------------------

/// The long-lived pieces are built once at startup: the checker, the fact
/// registry, and the invoice store. Each request derives a fresh
/// `EvaluationSession` from the registry.
#[derive(Clone)]
pub struct AppState {
    checker: PermissionChecker<InvoiceDomain>,
    fact_registry: FactRegistry,
    invoices: InvoiceStore,
    #[cfg(test)]
    edit_pause: Option<Arc<EditPause>>,
}

#[cfg(test)]
#[derive(Default)]
struct EditPause {
    authorized: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}

impl AppState {
    pub fn demo() -> Self {
        Self::with_invoices(demo_invoices())
    }

    /// The same wiring as [`AppState::demo`] over a caller-supplied set of
    /// invoices, for tests that need a fixture the demo data does not cover.
    pub fn with_invoices(invoices: Vec<Invoice>) -> Self {
        let viewer_id = demo_viewer_id();
        // The demo viewer has a `viewer` relationship on every invoice they
        // don't already own.
        let grants = invoices
            .iter()
            .filter(|invoice| invoice.owner_id != demo_owner_id())
            .map(|invoice| InvoiceRelationship {
                subject_id: viewer_id,
                resource_id: invoice.id,
                relation: Relation::Viewer,
            })
            .collect::<Vec<_>>();

        Self {
            checker: build_permission_checker(),
            fact_registry: FactRegistry::builder()
                .with_arc::<InvoiceRelationship>(Arc::new(InMemoryRelationshipSource::new(grants)))
                .build(),
            invoices: InvoiceStore::new(invoices),
            #[cfg(test)]
            edit_pause: None,
        }
    }

    /// Replaces the relationship backend while retaining the demo checker and resources.
    pub fn with_relationship_source<S: FactSource<InvoiceRelationship> + 'static>(
        mut self,
        source: S,
    ) -> Self {
        self.fact_registry = FactRegistry::builder()
            .with::<InvoiceRelationship, _>(source)
            .build();
        self
    }

    /// The store the handlers read and write.
    pub fn invoices(&self) -> &InvoiceStore {
        &self.invoices
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

fn days_ago(days: u64) -> SystemTime {
    SystemTime::now() - Duration::from_secs(days * 24 * 60 * 60)
}

/// Fixtures covering each outcome of the edit rules: the demo owner's editable
/// invoice, someone else's invoice, a locked one, and one that has aged out of
/// the edit window.
fn demo_invoices() -> Vec<Invoice> {
    vec![
        Invoice {
            id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            owner_id: demo_owner_id(),
            locked: false,
            created_at: days_ago(10),
            amount_cents: 10_000,
            version: 1,
        },
        Invoice {
            id: Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
            owner_id: Uuid::parse_str("cccccccc-cccc-cccc-cccc-cccccccccccc").unwrap(),
            locked: false,
            created_at: days_ago(5),
            amount_cents: 25_000,
            version: 1,
        },
        Invoice {
            id: Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap(),
            owner_id: Uuid::parse_str("dddddddd-dddd-dddd-dddd-dddddddddddd").unwrap(),
            locked: true,
            created_at: days_ago(2),
            amount_cents: 50_000,
            version: 1,
        },
        Invoice {
            id: Uuid::parse_str("44444444-4444-4444-4444-444444444444").unwrap(),
            owner_id: demo_owner_id(),
            locked: false,
            created_at: days_ago(45),
            amount_cents: 7_500,
            version: 1,
        },
    ]
}

// --------------------------
// 4) Building Our Policies
// --------------------------
// Each policy handles a slice of the logic; the checker ORs them together.
//
// A rule that reads a single input axis is written with that axis' setter —
// `.subjects`, `.actions`, `.resources`, `.context` — which also lets the batch
// path skip per-resource work. `.when` is reserved for rules that genuinely
// compare two axes, such as matching a subject against a resource's owner.

/// (A) Admins may do anything — the cross-cutting override. Subject-only.
fn admin_override_policy() -> Box<dyn Policy<InvoiceDomain>> {
    PolicyBuilder::<InvoiceDomain>::new("AdminOverridePolicy")
        .subjects(|user| user.roles.iter().any(|role| role == "admin"))
        .build()
}

/// (B) A user with a `viewer` relationship may view the invoice. The
/// relationship is loaded through the request-scoped `EvaluationSession`; in a
/// real service the source wraps a database pool or graph client.
///
/// `PolicyExt::and` composes the action guard with the relationship lookup, and
/// the conjunction stops at the first restriction that does not hold — so the
/// lookup only runs for view requests.
fn invoice_viewer_policy() -> Box<dyn Policy<InvoiceDomain>> {
    let is_view = PolicyBuilder::<InvoiceDomain>::new("IsView")
        .actions(|action| matches!(action, Action::View))
        .build();

    let viewer_relationship = RebacPolicy::<InvoiceDomain, Uuid, Uuid, Relation>::new(
        |user: &User| user.id,
        |invoice: &Invoice| invoice.id,
        Relation::Viewer,
    );

    is_view.and(viewer_relationship).boxed()
}

/// (C) The owner may edit the invoice if it is unlocked and under 30 days old.
/// Each restriction stays a policy with its own name and they are AND-ed with
/// `PolicyExt::and`, so a denial trace names the restriction that failed instead
/// of one opaque rule.
fn invoice_editing_policy() -> Box<dyn Policy<InvoiceDomain>> {
    let is_edit = PolicyBuilder::<InvoiceDomain>::new("IsEdit")
        .actions(|action| matches!(action, Action::Edit))
        .build();

    // Subject against resource: one of the two genuinely cross-axis rules here.
    let is_owner = PolicyBuilder::<InvoiceDomain>::new("IsOwnerOfInvoice")
        .when(|user, _action, invoice, _ctx| user.id == invoice.owner_id)
        .build();

    let invoice_not_locked = PolicyBuilder::<InvoiceDomain>::new("InvoiceNotLocked")
        .resources(|invoice| !invoice.locked)
        .build();

    // Resource against the request clock carried in the context.
    const THIRTY_DAYS: u64 = 30 * 24 * 60 * 60;
    let invoice_age_under_30_days = PolicyBuilder::<InvoiceDomain>::new("InvoiceAgeUnder30Days")
        .when(move |_user, _action, invoice, ctx: &RequestContext| {
            ctx.current_time
                .duration_since(invoice.created_at)
                .is_ok_and(|age| age < Duration::from_secs(THIRTY_DAYS))
        })
        .build();

    is_edit
        .and(is_owner)
        .and(invoice_not_locked)
        .and(invoice_age_under_30_days)
        .boxed()
}

/// (D) Combine the policies into a single `PermissionChecker`. With no
/// veto policies registered, deny-overrides reduces to OR semantics:
/// if any policy grants, access is allowed (and evaluation short-circuits).
pub fn build_permission_checker() -> PermissionChecker<InvoiceDomain> {
    let mut checker = PermissionChecker::named("InvoiceChecker");
    checker.add_policy(admin_override_policy());
    checker.add_policy(invoice_viewer_policy());
    checker.add_policy(invoice_editing_policy());
    checker
}

// ---------------------------------
// 5) Using in Axum Route Handlers
// ---------------------------------

fn authorization_error_response(error: AccessError) -> axum::response::Response {
    match error {
        AccessError::Denied { .. } => (StatusCode::FORBIDDEN, "Access denied").into_response(),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Authorization temporarily unavailable",
        )
            .into_response(),
    }
}

fn not_found_response() -> axum::response::Response {
    (StatusCode::NOT_FOUND, "Invoice not found").into_response()
}

pub async fn view_invoice_handler(
    Path(invoice_id): Path<Uuid>,
    State(state): State<AppState>,
    DemoUser(user): DemoUser,
) -> impl IntoResponse {
    // Load first, then authorize the row that was loaded. An id the store does
    // not hold is a 404 for every caller, admins included: there is no resource
    // to reason about. (A service that must not disclose which ids exist would
    // answer 404 for a denial too; this one keeps the two apart so the demo
    // shows which check refused.)
    let Some(invoice) = state.invoices.get(invoice_id) else {
        return not_found_response();
    };
    let session = state.request_session();
    let context = RequestContext::now();

    match state
        .checker
        .bind(&session, &user, &Action::View, &context)
        .authorize(&invoice)
        .await
    {
        Ok(()) => Json(InvoiceSummary::from(invoice)).into_response(),
        Err(error) => authorization_error_response(error),
    }
}

pub async fn list_invoices_handler(
    State(state): State<AppState>,
    DemoUser(user): DemoUser,
) -> impl IntoResponse {
    let session = state.request_session();
    let candidates = state.invoices.list();
    let context = RequestContext::now();

    // The session is request-scoped: app state owns the source, this request
    // registers it, and the batch authorization call uses it for every invoice
    // — relationship loads are batched and deduplicated.
    let visible = match state
        .checker
        .bind(&session, &user, &Action::View, &context)
        .try_filter(candidates)
        .await
    {
        Ok(visible) => visible,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Authorization temporarily unavailable",
            )
                .into_response()
        }
    };
    let visible = visible
        .into_iter()
        .map(InvoiceSummary::from)
        .collect::<Vec<_>>();

    Json(visible).into_response()
}

pub async fn edit_invoice_handler(
    Path(invoice_id): Path<Uuid>,
    State(state): State<AppState>,
    DemoUser(user): DemoUser,
    Json(edit): Json<EditInvoice>,
) -> impl IntoResponse {
    let Some(invoice) = state.invoices.get(invoice_id) else {
        return not_found_response();
    };
    let session = state.request_session();
    let context = RequestContext::now();

    if let Err(error) = state
        .checker
        .bind(&session, &user, &Action::Edit, &context)
        .authorize(&invoice)
        .await
    {
        return authorization_error_response(error);
    }

    #[cfg(test)]
    if let Some(pause) = &state.edit_pause {
        pause.authorized.notify_one();
        pause.resume.notified().await;
    }

    // The write must target the same version that was authorized.
    match state
        .invoices
        .update_if_version(invoice_id, invoice.version, |invoice| {
            invoice.amount_cents = edit.amount_cents;
        }) {
        Ok(updated) => Json(InvoiceSummary::from(updated)).into_response(),
        Err(UpdateError::NotFound) => not_found_response(),
        Err(UpdateError::VersionConflict { current }) => (
            StatusCode::CONFLICT,
            format!("Invoice changed since it was read (current version {current})"),
        )
            .into_response(),
    }
}

// ----------------------------------------
// 6) The Axum App with Our PermissionChecker
// ----------------------------------------

#[tokio::main]
async fn main() {
    // Build the long-lived checker, store, and relationship source once, then
    // create a fresh EvaluationSession inside each handler.
    let state = AppState::demo();

    let app = Router::new()
        .route("/invoices", get(list_invoices_handler))
        .route("/invoices/{invoice_id}", get(view_invoice_handler))
        .route("/invoices/{invoice_id}/edit", post(edit_invoice_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8000")
        .await
        .unwrap();
    println!("Listening on http://127.0.0.1:8000");
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
            amount_cents: 1_000,
            version: 1,
        }
    }

    fn context_now() -> RequestContext {
        RequestContext {
            current_time: SystemTime::now(),
        }
    }

    fn editable_invoice_id() -> Uuid {
        Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()
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
    async fn invoice_edit_age_uses_a_strict_duration_boundary() {
        let checker = build_permission_checker();
        let user = User {
            id: Uuid::new_v4(),
            roles: vec!["user".into()],
        };
        let current_time = SystemTime::UNIX_EPOCH + Duration::from_secs(60 * 24 * 60 * 60);
        let context = RequestContext { current_time };
        let boundary = current_time - Duration::from_secs(30 * 24 * 60 * 60);
        let tick = Duration::from_nanos(1);
        let session = EvaluationSession::empty();
        for (created_at, expected) in [
            (current_time + tick, false),
            (current_time, true),
            (boundary + tick, true),
            (boundary, false),
            (boundary - tick, false),
        ] {
            let invoice = Invoice {
                id: Uuid::new_v4(),
                owner_id: user.id,
                locked: false,
                created_at,
                amount_cents: 100,
                version: 1,
            };
            let decision = checker
                .bind(&session, &user, &Action::Edit, &context)
                .check(&invoice)
                .await;
            assert_eq!(decision.is_granted(), expected, "created_at={created_at:?}");
            let decisions = checker
                .bind(&session, &user, &Action::Edit, &context)
                .evaluate([invoice])
                .await;
            assert_eq!(
                decisions[0].1.is_granted(),
                expected,
                "batch created_at={created_at:?}"
            );
        }
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

    #[test]
    fn update_if_version_refuses_a_stale_expected_version() {
        let store = InvoiceStore::new(demo_invoices());
        let id = editable_invoice_id();

        let updated = store
            .update_if_version(id, 1, |invoice| invoice.amount_cents = 4_200)
            .expect("version 1 is current");
        assert_eq!(updated.version, 2);
        assert_eq!(updated.amount_cents, 4_200);

        // A caller still holding the version 1 snapshot it was authorized against.
        let conflict = store
            .update_if_version(id, 1, |invoice| invoice.amount_cents = 9_999)
            .expect_err("version 1 is stale now");
        assert_eq!(conflict, UpdateError::VersionConflict { current: 2 });

        let unchanged = store.get(id).expect("invoice is still there");
        assert_eq!(
            unchanged.amount_cents, 4_200,
            "a refused update changes nothing"
        );
        assert_eq!(unchanged.version, 2);

        // Re-reading and retrying against the current version succeeds.
        let retried = store
            .update_if_version(id, unchanged.version, |invoice| {
                invoice.amount_cents = 9_999
            })
            .expect("version 2 is current");
        assert_eq!(retried.amount_cents, 9_999);
        assert_eq!(retried.version, 3);
    }

    #[test]
    fn update_if_version_reports_unknown_ids() {
        let store = InvoiceStore::new(demo_invoices());
        assert_eq!(
            store
                .update_if_version(Uuid::new_v4(), 1, |invoice| invoice.amount_cents = 1)
                .expect_err("the store does not hold that id"),
            UpdateError::NotFound
        );
    }

    #[test]
    fn store_lists_every_fixture_in_id_order() {
        let store = InvoiceStore::new(demo_invoices());
        let ids = store
            .list()
            .into_iter()
            .map(|invoice| invoice.id)
            .collect::<Vec<_>>();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
        assert_eq!(ids.len(), 4);
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
        Router,
    };
    use tower::ServiceExt;

    const EDITABLE_INVOICE: &str = "11111111-1111-1111-1111-111111111111";
    const OTHER_OWNERS_INVOICE: &str = "22222222-2222-2222-2222-222222222222";
    const LOCKED_INVOICE: &str = "33333333-3333-3333-3333-333333333333";
    const STALE_INVOICE: &str = "44444444-4444-4444-4444-444444444444";
    const UNKNOWN_INVOICE: &str = "99999999-9999-9999-9999-999999999999";
    const OWNER: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    const LOCKED_INVOICE_OWNER: &str = "dddddddd-dddd-dddd-dddd-dddddddddddd";

    fn test_app() -> Router {
        app_with_state(AppState::demo())
    }

    fn app_with_state(state: AppState) -> Router {
        Router::new()
            .route("/invoices", get(list_invoices_handler))
            .route("/invoices/{invoice_id}", get(view_invoice_handler))
            .route("/invoices/{invoice_id}/edit", post(edit_invoice_handler))
            .with_state(state)
    }

    fn edit_request(invoice_id: &str, user_id: &str, amount_cents: i64) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(format!("/invoices/{invoice_id}/edit"))
            .header("x-user-id", user_id)
            .header("x-roles", "author")
            .header("content-type", "application/json")
            .body(Body::from(format!("{{\"amount_cents\":{amount_cents}}}")))
            .unwrap()
    }

    fn admin_edit_request(invoice_id: &str, amount_cents: i64) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(format!("/invoices/{invoice_id}/edit"))
            .header("x-roles", "admin")
            .header("content-type", "application/json")
            .body(Body::from(format!("{{\"amount_cents\":{amount_cents}}}")))
            .unwrap()
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).expect("handler returned JSON")
    }

    #[tokio::test]
    async fn edit_invoice_handler_rejects_a_lock_after_authorization() {
        let mut state = AppState::demo();
        let pause = Arc::new(EditPause::default());
        state.edit_pause = Some(pause.clone());
        let invoice_id = Uuid::parse_str(EDITABLE_INVOICE).unwrap();
        let original = state.invoices.get(invoice_id).unwrap();
        let app = app_with_state(state.clone());
        let pending = app
            .clone()
            .oneshot(edit_request(EDITABLE_INVOICE, OWNER, 9_999));
        tokio::pin!(pending);
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! {
                response = &mut pending => panic!("edit finished before pause: {:?}", response.unwrap().status()),
                () = pause.authorized.notified() => {}
            }
            state.invoices.update_if_version(invoice_id, original.version, |invoice| {
                invoice.locked = true;
            }).unwrap();
            pause.resume.notify_one();
            let response = pending.await.unwrap();
            assert_eq!(response.status(), StatusCode::CONFLICT);
            let stored = state.invoices.get(invoice_id).unwrap();
            assert_eq!(stored.amount_cents, original.amount_cents);
            assert!(stored.locked);
            assert_eq!(stored.version, original.version + 1);

            let response = app.oneshot(edit_request(EDITABLE_INVOICE, OWNER, 9_999)).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }).await.expect("edit race must finish without hanging");
    }

    #[tokio::test]
    async fn edit_invoice_handler_updates_the_stored_invoice_for_its_owner() {
        let app = test_app();

        let response = app
            .clone()
            .oneshot(edit_request(EDITABLE_INVOICE, OWNER, 4_200))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["amount_cents"], 4_200);
        assert_eq!(body["version"], 2);

        // The edit landed in the store, not just in the response.
        let request = Request::builder()
            .uri(format!("/invoices/{EDITABLE_INVOICE}"))
            .header("x-user-id", OWNER)
            .header("x-roles", "admin")
            .body(Body::empty())
            .unwrap();
        let body = body_json(app.oneshot(request).await.unwrap()).await;
        assert_eq!(body["amount_cents"], 4_200);
        assert_eq!(body["version"], 2);
    }

    #[tokio::test]
    async fn edit_invoice_handler_allows_admin() {
        let app = test_app();

        let response = app
            .oneshot(admin_edit_request(LOCKED_INVOICE, 12_345))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["amount_cents"], 12_345);
        assert_eq!(body["version"], 2);
    }

    #[tokio::test]
    async fn edit_invoice_handler_denies_another_owners_invoice() {
        let app = test_app();

        let response = app
            .oneshot(edit_request(OTHER_OWNERS_INVOICE, OWNER, 1))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn edit_invoice_handler_denies_regular_user_if_locked() {
        let app = test_app();

        // The owner of the locked invoice: only the lock stands in the way.
        let response = app
            .oneshot(edit_request(LOCKED_INVOICE, LOCKED_INVOICE_OWNER, 1))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn edit_invoice_handler_denies_an_invoice_past_the_edit_window() {
        let app = test_app();

        let response = app
            .oneshot(edit_request(STALE_INVOICE, OWNER, 1))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_denied_edit_leaves_the_invoice_untouched() {
        let state = AppState::demo();
        let app = app_with_state(state.clone());

        let response = app
            .oneshot(edit_request(STALE_INVOICE, OWNER, 1))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let stored = state
            .invoices()
            .get(Uuid::parse_str(STALE_INVOICE).unwrap())
            .expect("fixture is in the store");
        assert_eq!(stored.amount_cents, 7_500);
        assert_eq!(stored.version, 1);
    }

    #[tokio::test]
    async fn unknown_invoice_is_not_found_for_viewer_and_admin() {
        let app = test_app();

        for role in ["viewer", "admin"] {
            let request = Request::builder()
                .uri(format!("/invoices/{UNKNOWN_INVOICE}"))
                .header("x-user-id", OWNER)
                .header("x-roles", role)
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                app.clone().oneshot(request).await.unwrap().status(),
                StatusCode::NOT_FOUND,
                "GET as {role}"
            );

            let request = Request::builder()
                .method("POST")
                .uri(format!("/invoices/{UNKNOWN_INVOICE}/edit"))
                .header("x-user-id", OWNER)
                .header("x-roles", role)
                .header("content-type", "application/json")
                .body(Body::from("{\"amount_cents\":1}"))
                .unwrap();
            assert_eq!(
                app.clone().oneshot(request).await.unwrap().status(),
                StatusCode::NOT_FOUND,
                "POST as {role}"
            );
        }
    }

    #[tokio::test]
    async fn custom_fixtures_drive_the_handlers() {
        let id = Uuid::new_v4();
        let app = app_with_state(AppState::with_invoices(vec![Invoice {
            id,
            owner_id: Uuid::parse_str(OWNER).unwrap(),
            locked: false,
            created_at: days_ago(1),
            amount_cents: 500,
            version: 7,
        }]));

        let response = app
            .oneshot(edit_request(&id.to_string(), OWNER, 600))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["amount_cents"], 600);
        assert_eq!(body["version"], 8);
    }
}
