use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::{get, post},
    Extension, Router,
};
use tower::ServiceExt;
use uuid::Uuid;

mod axum_example {
    #![allow(dead_code)]
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/axum.rs"));
}

fn axum_app() -> Router {
    let checker = axum_example::build_permission_checker();

    Router::new()
        .route(
            "/invoices/{invoice_id}",
            get(axum_example::view_invoice_handler),
        )
        .route(
            "/invoices/{invoice_id}/edit",
            post(axum_example::edit_invoice_handler),
        )
        .route(
            "/payments/{payment_id}/approve",
            post(axum_example::approve_payment_handler),
        )
        .layer(Extension(checker))
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

#[tokio::test]
async fn approve_payment_allows_finance_manager() {
    let payment_id = Uuid::new_v4();
    let app = axum_app();

    let request = Request::builder()
        .method("POST")
        .uri(format!("/payments/{payment_id}/approve"))
        .header("x-roles", "finance_manager")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn approve_payment_denies_regular_user() {
    let payment_id = Uuid::new_v4();
    let app = axum_app();

    let request = Request::builder()
        .method("POST")
        .uri(format!("/payments/{payment_id}/approve"))
        .header("x-roles", "viewer")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn approve_payment_denies_refunded_payment() {
    let payment_id = Uuid::new_v4();
    let app = axum_app();

    let request = Request::builder()
        .method("POST")
        .uri(format!("/payments/{payment_id}/approve"))
        .header("x-roles", "finance_manager")
        .header("x-payment-refunded", "true")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
