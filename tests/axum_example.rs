use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    routing::{get, post},
    Router,
};
use tower::ServiceExt;
use uuid::Uuid;

mod axum_example {
    #![allow(dead_code)]
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/axum.rs"));
}

use axum_example::{AppState, Invoice, UpdateError};

/// Demo fixtures, as `AppState::demo` loads them into the store.
const EDITABLE_INVOICE: &str = "11111111-1111-1111-1111-111111111111";
const OTHER_OWNERS_INVOICE: &str = "22222222-2222-2222-2222-222222222222";
const LOCKED_INVOICE: &str = "33333333-3333-3333-3333-333333333333";
const STALE_INVOICE: &str = "44444444-4444-4444-4444-444444444444";
const UNKNOWN_INVOICE: &str = "99999999-9999-9999-9999-999999999999";
const LOCKED_INVOICE_OWNER: &str = "dddddddd-dddd-dddd-dddd-dddddddddddd";

fn axum_app() -> Router {
    app_with_state(AppState::demo())
}

fn app_with_state(state: AppState) -> Router {
    Router::new()
        .route("/invoices", get(axum_example::list_invoices_handler))
        .route(
            "/invoices/{invoice_id}",
            get(axum_example::view_invoice_handler),
        )
        .route(
            "/invoices/{invoice_id}/edit",
            post(axum_example::edit_invoice_handler),
        )
        .with_state(state)
}

fn owner_id() -> Uuid {
    Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap()
}

fn viewer_id() -> Uuid {
    Uuid::parse_str("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee").unwrap()
}

fn get_request(invoice_id: &str, user_id: &str, role: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(format!("/invoices/{invoice_id}"))
        .header("x-user-id", user_id)
        .header("x-roles", role)
        .body(Body::empty())
        .unwrap()
}

/// `POST /invoices/{id}/edit` carries a JSON body, so both the content type and
/// the payload have to be set.
fn edit_request(invoice_id: &str, user_id: &str, role: &str, amount_cents: i64) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/invoices/{invoice_id}/edit"))
        .header("x-user-id", user_id)
        .header("x-roles", role)
        .header("content-type", "application/json")
        .body(Body::from(format!("{{\"amount_cents\":{amount_cents}}}")))
        .unwrap()
}

async fn body_text(response: axum::response::Response) -> String {
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    String::from_utf8(body.to_vec()).unwrap()
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).expect("handler returned JSON")
}

#[tokio::test]
async fn view_invoice_allows_admin() {
    let app = axum_app();

    let response = app
        .oneshot(get_request(
            EDITABLE_INVOICE,
            &Uuid::new_v4().to_string(),
            "admin",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = body_json(response).await;
    assert_eq!(body["id"], EDITABLE_INVOICE);
    assert_eq!(body["amount_cents"], 10_000);
    assert_eq!(body["version"], 1);
}

#[tokio::test]
async fn view_invoice_denied_without_admin() {
    let app = axum_app();

    // No `viewer` relationship on the demo owner's invoice, and viewing is not
    // an owner privilege here.
    let response = app
        .oneshot(get_request(
            EDITABLE_INVOICE,
            &Uuid::new_v4().to_string(),
            "viewer",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn view_invoice_handles_invalid_user_header() {
    let app = axum_app();

    let request = Request::builder()
        .method("GET")
        .uri(format!("/invoices/{EDITABLE_INVOICE}"))
        .header("x-user-id", "not-a-uuid")
        .header("x-roles", "viewer")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn unknown_invoice_is_not_found_for_viewer_and_admin() {
    let app = axum_app();

    for role in ["viewer", "admin"] {
        let response = app
            .clone()
            .oneshot(get_request(UNKNOWN_INVOICE, &owner_id().to_string(), role))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "GET as {role}");

        let response = app
            .clone()
            .oneshot(edit_request(
                UNKNOWN_INVOICE,
                &owner_id().to_string(),
                role,
                1,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "POST as {role}");
    }
}

#[tokio::test]
async fn list_invoices_uses_request_session_relationships() {
    let app = axum_app();

    let request = Request::builder()
        .method("GET")
        .uri("/invoices")
        .header("x-user-id", viewer_id().to_string())
        .header("x-roles", "viewer")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = body_text(response).await;
    assert!(body.contains(OTHER_OWNERS_INVOICE));
    assert!(body.contains(LOCKED_INVOICE));
    // Both of the demo owner's invoices are outside the viewer's relationships.
    assert!(!body.contains(EDITABLE_INVOICE));
    assert!(!body.contains(STALE_INVOICE));
}

#[tokio::test]
async fn list_invoices_allows_admin_all_candidates() {
    let app = axum_app();

    let request = Request::builder()
        .method("GET")
        .uri("/invoices")
        .header("x-roles", "admin")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = body_text(response).await;
    for invoice in [
        EDITABLE_INVOICE,
        OTHER_OWNERS_INVOICE,
        LOCKED_INVOICE,
        STALE_INVOICE,
    ] {
        assert!(body.contains(invoice), "admin should see {invoice}");
    }
}

#[tokio::test]
async fn edit_invoice_allows_owner_and_persists_the_change() {
    let app = axum_app();

    let response = app
        .clone()
        .oneshot(edit_request(
            EDITABLE_INVOICE,
            &owner_id().to_string(),
            "author",
            4_200,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = body_json(response).await;
    assert_eq!(body["amount_cents"], 4_200);
    assert_eq!(body["version"], 2);

    // Reading the invoice back shows the stored row, not the request's wishes.
    let response = app
        .oneshot(get_request(
            EDITABLE_INVOICE,
            &owner_id().to_string(),
            "admin",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["amount_cents"], 4_200);
    assert_eq!(body["version"], 2);
}

#[tokio::test]
async fn edit_invoice_denies_non_owner() {
    let app = axum_app();

    let response = app
        .oneshot(edit_request(
            OTHER_OWNERS_INVOICE,
            &owner_id().to_string(),
            "author",
            1,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn edit_invoice_denies_locked_invoice_for_its_owner() {
    let state = AppState::demo();
    let app = app_with_state(state.clone());

    let response = app
        .oneshot(edit_request(
            LOCKED_INVOICE,
            LOCKED_INVOICE_OWNER,
            "author",
            1,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let stored = state
        .invoices()
        .get(Uuid::parse_str(LOCKED_INVOICE).unwrap())
        .expect("fixture is in the store");
    assert_eq!(stored.amount_cents, 50_000);
    assert_eq!(stored.version, 1, "a denied edit writes nothing");
}

#[tokio::test]
async fn edit_invoice_denies_stale_invoice() {
    let app = axum_app();

    let response = app
        .oneshot(edit_request(
            STALE_INVOICE,
            &owner_id().to_string(),
            "author",
            1,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn edit_invoice_allows_admin_on_locked_invoice() {
    let app = axum_app();

    let response = app
        .oneshot(edit_request(
            LOCKED_INVOICE,
            &Uuid::new_v4().to_string(),
            "admin",
            12_345,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = body_json(response).await;
    assert_eq!(body["amount_cents"], 12_345);
    assert_eq!(body["version"], 2);
    assert_eq!(
        body["locked"], true,
        "the override does not unlock anything"
    );
}

#[tokio::test]
async fn injected_fixtures_are_authorized_like_any_other_row() {
    let id = Uuid::new_v4();
    let state = AppState::with_invoices(vec![Invoice {
        id,
        owner_id: owner_id(),
        locked: true,
        created_at: std::time::SystemTime::now(),
        amount_cents: 1,
        version: 3,
    }]);
    let app = app_with_state(state.clone());

    let response = app
        .oneshot(edit_request(
            &id.to_string(),
            &owner_id().to_string(),
            "author",
            2,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(state.invoices().get(id).unwrap().version, 3);
}

/// The store's version guard is what stands between "this snapshot was
/// authorized" and "this row was changed"; the handler maps its
/// `VersionConflict` onto `409 Conflict`.
#[test]
fn update_if_version_guards_the_write() {
    let state = AppState::demo();
    let store = state.invoices();
    let id = Uuid::parse_str(EDITABLE_INVOICE).unwrap();

    let updated = store
        .update_if_version(id, 1, |invoice| invoice.amount_cents = 4_200)
        .expect("version 1 is the current version");
    assert_eq!(updated.version, 2);
    assert_eq!(updated.amount_cents, 4_200);

    // A writer that was authorized against version 1 is now holding a stale read.
    assert_eq!(
        store
            .update_if_version(id, 1, |invoice| invoice.amount_cents = 9_999)
            .expect_err("version 1 is stale now"),
        UpdateError::VersionConflict { current: 2 }
    );
    let unchanged = store.get(id).expect("fixture is in the store");
    assert_eq!(
        unchanged.amount_cents, 4_200,
        "the refused write did nothing"
    );
    assert_eq!(unchanged.version, 2);

    // Re-reading and retrying against the current version succeeds.
    let retried = store
        .update_if_version(id, 2, |invoice| invoice.amount_cents = 9_999)
        .expect("version 2 is the current version");
    assert_eq!(retried.amount_cents, 9_999);
    assert_eq!(retried.version, 3);

    assert_eq!(
        store
            .update_if_version(Uuid::new_v4(), 1, |invoice| invoice.amount_cents = 1)
            .expect_err("the store does not hold that id"),
        UpdateError::NotFound
    );
}

struct UnavailableRelationships;

#[async_trait::async_trait]
impl<K: gatehouse::FactKey<Value = bool>> gatehouse::FactSource<K> for UnavailableRelationships {
    async fn load_many(&self, keys: &[K]) -> Vec<gatehouse::FactLoadResult<bool>> {
        keys.iter()
            .map(|_| {
                gatehouse::FactLoadResult::Error(gatehouse::FactLoadError::backend_message(
                    "injected outage",
                ))
            })
            .collect()
    }
}

#[tokio::test]
async fn authorization_outage_returns_503_for_single_and_list_but_admin_still_grants() {
    let state = AppState::demo().with_relationship_source(UnavailableRelationships);
    let app = Router::new()
        .route("/invoices", get(axum_example::list_invoices_handler))
        .route(
            "/invoices/{invoice_id}",
            get(axum_example::view_invoice_handler),
        )
        .with_state(state);
    let detail_uri = format!("/invoices/{EDITABLE_INVOICE}");
    for uri in ["/invoices", detail_uri.as_str()] {
        let request = Request::builder().uri(uri).body(Body::empty()).unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        assert!(!String::from_utf8_lossy(&body).contains("injected outage"));
        let request = Request::builder()
            .uri(uri)
            .header("x-roles", "admin")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::OK
        );
    }
}
