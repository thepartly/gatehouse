use actix_web::{http::StatusCode, test, web, App};
use uuid::Uuid;

mod actix_example {
    #![allow(dead_code)]
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/actix_web.rs"
    ));
}

macro_rules! init_actix_app {
    () => {{
        let checker = web::Data::new(actix_example::build_permission_checker());
        test::init_service(
            App::new()
                .app_data(checker.clone())
                .route("/posts/{id}", web::put().to(actix_example::edit_post))
                .route(
                    "/posts/{id}/publish",
                    web::post().to(actix_example::publish_post),
                )
                .route("/posts/{id}", web::get().to(actix_example::view_post)),
        )
    }};
}

fn author_id() -> Uuid {
    Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()
}

#[actix_web::test]
async fn edit_post_allows_author() {
    let app = init_actix_app!().await;
    let post_id = author_id();

    let req = test::TestRequest::put()
        .uri(&format!("/posts/{post_id}"))
        .insert_header(("x-user-id", post_id.to_string()))
        .insert_header(("x-roles", "author"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn edit_post_denies_non_author() {
    let app = init_actix_app!().await;
    let post_id = author_id();

    let req = test::TestRequest::put()
        .uri(&format!("/posts/{post_id}"))
        .insert_header(("x-user-id", Uuid::new_v4().to_string()))
        .insert_header(("x-roles", "author"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn edit_post_denies_locked_post() {
    let app = init_actix_app!().await;
    let post_id = author_id();

    let req = test::TestRequest::put()
        .uri(&format!("/posts/{post_id}"))
        .insert_header(("x-user-id", post_id.to_string()))
        .insert_header(("x-roles", "author"))
        .insert_header(("x-post-locked", "true"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn publish_post_allows_editor() {
    let app = init_actix_app!().await;
    let post_id = author_id();

    let req = test::TestRequest::post()
        .uri(&format!("/posts/{post_id}/publish"))
        .insert_header(("x-user-id", Uuid::new_v4().to_string()))
        .insert_header(("x-roles", "editor"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn publish_post_denies_non_editor() {
    let app = init_actix_app!().await;
    let post_id = author_id();

    let req = test::TestRequest::post()
        .uri(&format!("/posts/{post_id}/publish"))
        .insert_header(("x-user-id", Uuid::new_v4().to_string()))
        .insert_header(("x-roles", "author"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn publish_post_denies_locked_post() {
    let app = init_actix_app!().await;
    let post_id = author_id();

    let req = test::TestRequest::post()
        .uri(&format!("/posts/{post_id}/publish"))
        .insert_header(("x-user-id", Uuid::new_v4().to_string()))
        .insert_header(("x-roles", "editor"))
        .insert_header(("x-post-locked", "true"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn view_post_allows_published_post() {
    let app = init_actix_app!().await;
    let post_id = author_id();

    let req = test::TestRequest::get()
        .uri(&format!("/posts/{post_id}"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn view_post_denies_unpublished_anonymous() {
    let app = init_actix_app!().await;
    let post_id = author_id();

    let req = test::TestRequest::get()
        .uri(&format!("/posts/{post_id}"))
        .insert_header(("x-post-published", "false"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn view_post_allows_author_on_unpublished_post() {
    let app = init_actix_app!().await;
    let post_id = author_id();

    let req = test::TestRequest::get()
        .uri(&format!("/posts/{post_id}"))
        .insert_header(("x-user-id", post_id.to_string()))
        .insert_header(("x-roles", "author"))
        .insert_header(("x-post-published", "false"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}
