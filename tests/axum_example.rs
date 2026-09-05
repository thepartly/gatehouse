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

fn axum_app() -> Router {
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
        .with_state(axum_example::AppState::demo())
}

#[tokio::test]
async fn view_invoice_allows_admin() {
    let invoice_id = Uuid::new_v4();
    let app = axum_app();

    let request = Request::builder()
        .method("GET")
        .uri(format!("/invoices/{invoice_id}"))
        .header("x-roles", "admin")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn view_invoice_denied_without_admin() {
    let invoice_id = Uuid::new_v4();
    let app = axum_app();

    let request = Request::builder()
        .method("GET")
        .uri(format!("/invoices/{invoice_id}"))
        .header("x-roles", "viewer")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn view_invoice_handles_invalid_user_header() {
    let invoice_id = Uuid::new_v4();
    let app = axum_app();

    let request = Request::builder()
        .method("GET")
        .uri(format!("/invoices/{invoice_id}"))
        .header("x-user-id", "not-a-uuid")
        .header("x-roles", "viewer")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

fn owner_id() -> Uuid {
    Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap()
}

fn viewer_id() -> Uuid {
    Uuid::parse_str("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee").unwrap()
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

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(body.contains("22222222-2222-2222-2222-222222222222"));
    assert!(body.contains("33333333-3333-3333-3333-333333333333"));
    assert!(!body.contains("11111111-1111-1111-1111-111111111111"));
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

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(body.contains("11111111-1111-1111-1111-111111111111"));
    assert!(body.contains("22222222-2222-2222-2222-222222222222"));
    assert!(body.contains("33333333-3333-3333-3333-333333333333"));
}

#[tokio::test]
async fn edit_invoice_allows_owner() {
    let invoice_id = owner_id();
    let app = axum_app();

    let request = Request::builder()
        .method("POST")
        .uri(format!("/invoices/{invoice_id}/edit"))
        .header("x-user-id", invoice_id.to_string())
        .header("x-roles", "author")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn edit_invoice_denies_non_owner() {
    let invoice_id = owner_id();
    let app = axum_app();

    let request = Request::builder()
        .method("POST")
        .uri(format!("/invoices/{invoice_id}/edit"))
        .header("x-user-id", Uuid::new_v4().to_string())
        .header("x-roles", "author")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn edit_invoice_denies_stale_invoice() {
    let invoice_id = owner_id();
    let app = axum_app();

    let request = Request::builder()
        .method("POST")
        .uri(format!("/invoices/{invoice_id}/edit"))
        .header("x-user-id", invoice_id.to_string())
        .header("x-roles", "author")
        .header("x-invoice-age-days", "45")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
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
    let state = axum_example::AppState::demo().with_relationship_source(UnavailableRelationships);
    let app = Router::new()
        .route("/invoices", get(axum_example::list_invoices_handler))
        .route(
            "/invoices/{invoice_id}",
            get(axum_example::view_invoice_handler),
        )
        .with_state(state);
    for uri in [
        "/invoices",
        "/invoices/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    ] {
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
