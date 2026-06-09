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
        let state = web::Data::new(actix_example::AppState::demo());
        test::init_service(
            App::new()
                .app_data(state.clone())
                .route("/posts", web::get().to(actix_example::list_posts))
                .route("/posts/{id}", web::get().to(actix_example::view_post))
                .route("/posts/{id}", web::put().to(actix_example::edit_post))
                .route(
                    "/posts/{id}/publish",
                    web::post().to(actix_example::publish_post),
                ),
        )
    }};
}

// Demo fixtures (see `AppState::demo` in the example).
fn author_id() -> Uuid {
    Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()
}

fn collaborator_id() -> Uuid {
    Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap()
}

fn draft_post_id() -> Uuid {
    Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap()
}

fn published_post_id() -> Uuid {
    Uuid::parse_str("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap()
}

#[actix_web::test]
async fn edit_post_allows_author() {
    let app = init_actix_app!().await;

    let req = test::TestRequest::put()
        .uri(&format!("/posts/{}", author_id()))
        .insert_header(("x-user-id", author_id().to_string()))
        .insert_header(("x-roles", "author"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn edit_post_allows_collaborator_via_relationship() {
    // The collaborator is not the author, but holds an `editor` relationship on
    // the demo draft, loaded through the request-scoped session.
    let app = init_actix_app!().await;

    let req = test::TestRequest::put()
        .uri(&format!("/posts/{}", draft_post_id()))
        .insert_header(("x-user-id", collaborator_id().to_string()))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn edit_post_denies_non_author() {
    let app = init_actix_app!().await;

    let req = test::TestRequest::put()
        .uri(&format!("/posts/{}", author_id()))
        .insert_header(("x-user-id", Uuid::new_v4().to_string()))
        .insert_header(("x-roles", "author"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn edit_post_denies_locked_post() {
    let app = init_actix_app!().await;

    let req = test::TestRequest::put()
        .uri(&format!("/posts/{}", author_id()))
        .insert_header(("x-user-id", author_id().to_string()))
        .insert_header(("x-roles", "author"))
        .insert_header(("x-post-locked", "true"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn publish_post_allows_editor() {
    let app = init_actix_app!().await;

    let req = test::TestRequest::post()
        .uri(&format!("/posts/{}/publish", author_id()))
        .insert_header(("x-user-id", Uuid::new_v4().to_string()))
        .insert_header(("x-roles", "editor"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn publish_post_denies_non_editor() {
    let app = init_actix_app!().await;

    let req = test::TestRequest::post()
        .uri(&format!("/posts/{}/publish", author_id()))
        .insert_header(("x-user-id", Uuid::new_v4().to_string()))
        .insert_header(("x-roles", "author"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn publish_post_denies_locked_post() {
    let app = init_actix_app!().await;

    let req = test::TestRequest::post()
        .uri(&format!("/posts/{}/publish", author_id()))
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

    // The published demo post is viewable by anyone.
    let req = test::TestRequest::get()
        .uri(&format!("/posts/{}", published_post_id()))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn view_post_denies_unpublished_anonymous() {
    let app = init_actix_app!().await;

    let req = test::TestRequest::get()
        .uri(&format!("/posts/{}", draft_post_id()))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn view_post_allows_author_on_unpublished_post() {
    let app = init_actix_app!().await;

    let req = test::TestRequest::get()
        .uri(&format!("/posts/{}", draft_post_id()))
        .insert_header(("x-user-id", author_id().to_string()))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn list_posts_filters_by_relationship() {
    let app = init_actix_app!().await;

    // The collaborator sees both posts (editor relationship on each).
    let req = test::TestRequest::get()
        .uri("/posts")
        .insert_header(("x-user-id", collaborator_id().to_string()))
        .to_request();
    let body = test::call_and_read_body(&app, req).await;
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        body.contains("draft roadmap"),
        "collaborator should see the draft: {body}"
    );
    assert!(body.contains("published announcement"));

    // An anonymous caller sees only the published post.
    let req = test::TestRequest::get()
        .uri("/posts")
        .insert_header(("x-user-id", Uuid::new_v4().to_string()))
        .to_request();
    let body = test::call_and_read_body(&app, req).await;
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        !body.contains("draft roadmap"),
        "anonymous must not see the draft: {body}"
    );
    assert!(body.contains("published announcement"));
}
