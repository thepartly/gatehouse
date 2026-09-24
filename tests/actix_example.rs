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

fn locked_post_id() -> Uuid {
    Uuid::parse_str("cccccccc-cccc-cccc-cccc-cccccccccccc").unwrap()
}

#[actix_web::test]
async fn edit_post_allows_author() {
    let app = init_actix_app!().await;

    let req = test::TestRequest::put()
        .uri(&format!("/posts/{}", draft_post_id()))
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
async fn collaborator_edit_is_bounded_by_the_author_draft_window() {
    // The collaborator holds an editor relationship on every demo post, so
    // only the draft window can refuse these edits. A collaborator must never
    // be able to edit a post its author cannot.
    let app = init_actix_app!().await;
    let old_draft = Uuid::parse_str("dddddddd-dddd-dddd-dddd-dddddddddddd").unwrap();

    for post_id in [published_post_id(), locked_post_id(), old_draft] {
        for user_id in [author_id(), collaborator_id()] {
            let req = test::TestRequest::put()
                .uri(&format!("/posts/{post_id}"))
                .insert_header(("x-user-id", user_id.to_string()))
                .to_request();
            let resp = test::call_service(&app, req).await;
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "user {user_id} editing post {post_id}"
            );
        }
    }
}

#[actix_web::test]
async fn edit_post_denies_non_author() {
    let app = init_actix_app!().await;

    let req = test::TestRequest::put()
        .uri(&format!("/posts/{}", draft_post_id()))
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
        .uri(&format!("/posts/{}", locked_post_id()))
        .insert_header(("x-user-id", author_id().to_string()))
        .insert_header(("x-roles", "author"))
        .insert_header(("x-post-locked", "false"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn publish_post_allows_editor() {
    let app = init_actix_app!().await;

    let req = test::TestRequest::post()
        .uri(&format!("/posts/{}/publish", draft_post_id()))
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
        .uri(&format!("/posts/{}/publish", draft_post_id()))
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
        .uri(&format!("/posts/{}/publish", locked_post_id()))
        .insert_header(("x-user-id", Uuid::new_v4().to_string()))
        .insert_header(("x-roles", "editor"))
        .insert_header(("x-post-locked", "false"))
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

    // An anonymous caller (no x-user-id; the extractor falls back to the nil
    // UUID) sees only the published post.
    let req = test::TestRequest::get().uri("/posts").to_request();
    let body = test::call_and_read_body(&app, req).await;
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        !body.contains("draft roadmap"),
        "anonymous must not see the draft: {body}"
    );
    assert!(body.contains("published announcement"));
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

#[actix_web::test]
async fn authorization_outage_returns_503_for_single_and_list_but_admin_still_grants() {
    let state = actix_example::AppState::demo().with_relationship_source(UnavailableRelationships);
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state))
            .route("/posts", web::get().to(actix_example::list_posts))
            .route("/posts/{id}", web::get().to(actix_example::view_post)),
    )
    .await;
    for uri in ["/posts", "/posts/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"] {
        let request = test::TestRequest::get().uri(uri).to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = test::read_body(response).await;
        assert!(!String::from_utf8_lossy(&body).contains("injected outage"));
        let request = test::TestRequest::get()
            .uri(uri)
            .insert_header(("x-roles", "admin"))
            .to_request();
        assert_eq!(
            test::call_service(&app, request).await.status(),
            StatusCode::OK
        );
    }
}

#[actix_web::test]
async fn resource_headers_cannot_change_authorization() {
    let app = init_actix_app!().await;
    for (method, post_id, user_id, expected) in [
        (
            actix_web::http::Method::GET,
            draft_post_id(),
            Uuid::nil(),
            StatusCode::FORBIDDEN,
        ),
        (
            actix_web::http::Method::GET,
            published_post_id(),
            Uuid::nil(),
            StatusCode::OK,
        ),
        (
            actix_web::http::Method::PUT,
            draft_post_id(),
            author_id(),
            StatusCode::OK,
        ),
        (
            actix_web::http::Method::PUT,
            locked_post_id(),
            collaborator_id(),
            StatusCode::FORBIDDEN,
        ),
        (
            actix_web::http::Method::PUT,
            Uuid::parse_str("dddddddd-dddd-dddd-dddd-dddddddddddd").unwrap(),
            author_id(),
            StatusCode::FORBIDDEN,
        ),
    ] {
        for spoof in [
            None,
            Some(("true", "false", "0")),
            Some(("false", "true", "999999")),
        ] {
            let request = test::TestRequest::default()
                .method(method.clone())
                .uri(&format!("/posts/{post_id}"))
                .insert_header(("x-user-id", user_id.to_string()));
            let request = if let Some((published, locked, age_days)) = spoof {
                request
                    .insert_header(("x-post-published", published))
                    .insert_header(("x-post-locked", locked))
                    .insert_header(("x-post-age-days", age_days))
            } else {
                request
            };
            let response = test::call_service(&app, request.to_request()).await;
            assert_eq!(
                response.status(),
                expected,
                "{method} {post_id}, spoof={spoof:?}"
            );
            if expected == StatusCode::FORBIDDEN {
                assert_eq!(test::read_body(response).await.as_ref(), b"Access denied");
            }
        }
    }
}

#[actix_web::test]
async fn unknown_posts_are_not_manufactured_even_for_admins() {
    let app = init_actix_app!().await;
    for (method, suffix) in [
        (actix_web::http::Method::GET, ""),
        (actix_web::http::Method::PUT, ""),
        (actix_web::http::Method::POST, "/publish"),
    ] {
        let request = test::TestRequest::default()
            .method(method)
            .uri(&format!("/posts/{}{suffix}", Uuid::nil()))
            .insert_header(("x-roles", "admin"))
            .insert_header(("x-post-published", "true"))
            .to_request();
        assert_eq!(
            test::call_service(&app, request).await.status(),
            StatusCode::NOT_FOUND
        );
    }
}

#[actix_web::test]
async fn list_and_point_reads_agree_on_stored_resources() {
    let app = init_actix_app!().await;
    for user_id in [Uuid::nil(), author_id(), collaborator_id()] {
        let request = test::TestRequest::get()
            .uri("/posts")
            .insert_header(("x-user-id", user_id.to_string()))
            .to_request();
        let posts: serde_json::Value = test::call_and_read_body_json(&app, request).await;
        for post_id in [
            draft_post_id(),
            published_post_id(),
            locked_post_id(),
            Uuid::parse_str("dddddddd-dddd-dddd-dddd-dddddddddddd").unwrap(),
        ] {
            let listed = posts
                .as_array()
                .unwrap()
                .iter()
                .any(|post| post["id"] == post_id.to_string());
            let request = test::TestRequest::get()
                .uri(&format!("/posts/{post_id}"))
                .insert_header(("x-user-id", user_id.to_string()))
                .to_request();
            assert_eq!(
                test::call_service(&app, request).await.status() == StatusCode::OK,
                listed
            );
        }
    }
}

#[actix_web::test]
async fn write_routes_explicitly_demonstrate_authorization_only() {
    let app = init_actix_app!().await;
    for (method, suffix, message) in [
        (
            actix_web::http::Method::PUT,
            "",
            "Edit authorized; no changes made",
        ),
        (
            actix_web::http::Method::POST,
            "/publish",
            "Publish authorized; no changes made",
        ),
    ] {
        let request = test::TestRequest::default()
            .method(method)
            .uri(&format!("/posts/{}{suffix}", draft_post_id()))
            .insert_header(("x-roles", "admin"))
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(test::read_body(response).await.as_ref(), message.as_bytes());
    }
    let request = test::TestRequest::get()
        .uri(&format!("/posts/{}", draft_post_id()))
        .to_request();
    assert_eq!(
        test::call_service(&app, request).await.status(),
        StatusCode::FORBIDDEN
    );
}

#[actix_web::test]
async fn author_edit_window_rejects_future_and_exact_thirty_day_ages() {
    use std::time::{Duration, SystemTime};

    struct NoRelationships;

    #[async_trait::async_trait]
    impl<K: gatehouse::FactKey<Value = bool>> gatehouse::FactSource<K> for NoRelationships {
        async fn load_many(&self, keys: &[K]) -> Vec<gatehouse::FactLoadResult<bool>> {
            vec![gatehouse::FactLoadResult::Found(false); keys.len()]
        }
    }

    let session = gatehouse::FactRegistry::builder()
        .with::<gatehouse::RelationshipQuery<Uuid, Uuid, actix_example::Relation>, _>(
            NoRelationships,
        )
        .build()
        .session();
    let current_time = SystemTime::UNIX_EPOCH + Duration::from_secs(60 * 24 * 60 * 60);
    let boundary = current_time - Duration::from_secs(30 * 24 * 60 * 60);
    let tick = Duration::from_nanos(1);
    let checker = actix_example::build_permission_checker();
    let user = actix_example::User {
        id: author_id(),
        roles: vec![],
    };
    let context = actix_example::RequestContext { current_time };
    for (created_at, allowed) in [
        (current_time + tick, false),
        (boundary + tick, true),
        (boundary, false),
        (boundary - tick, false),
    ] {
        let post = actix_example::BlogPost {
            id: draft_post_id(),
            title: "draft".into(),
            author_id: user.id,
            locked: false,
            published_at: None,
            created_at,
        };
        let decision = checker
            .bind(&session, &user, &actix_example::Action::Edit, &context)
            .check(&post)
            .await;
        assert_eq!(decision.is_granted(), allowed, "created_at={created_at:?}");
        if !allowed {
            assert!(
                matches!(decision, gatehouse::AccessEvaluation::Denied { .. }),
                "created_at={created_at:?}: {decision:?}"
            );
        }
    }
}
