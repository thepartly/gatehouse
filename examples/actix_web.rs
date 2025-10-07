//! Actix Web example showcasing how to plug Gatehouse policies into
//! request handlers. The server exposes three routes:
//!
//! - `PUT /posts/{id}` edits a blog post if the author is allowed.
//! - `POST /posts/{id}/publish` publishes a post for editors.
//! - `GET /posts/{id}` reads a post when it is public or the caller is privileged.
//!
//! Try it with curl:
//!
//! ```bash
//! # Author editing their own draft succeeds
//! curl -i -X PUT http://127.0.0.1:8080/posts/11111111-1111-1111-1111-111111111111 \
//!   -H "x-user-id: 11111111-1111-1111-1111-111111111111" \
//!   -H "x-roles: author"
//!
//! # Publishing requires the `editor` role
//! curl -i -X POST http://127.0.0.1:8080/posts/11111111-1111-1111-1111-111111111111 \
//!   -H "x-user-id: 22222222-2222-2222-2222-222222222222" \
//!   -H "x-roles: editor"
//!
//! # Viewing a published post works for anonymous users as well
//! curl -i http://127.0.0.1:8080/posts/00000000-0000-0000-0000-000000000000
//! ```
//!
//! The example uses the [`PolicyBuilder`] to compose a few policies and
//! stores them inside a shared [`PermissionChecker`]. Each handler pulls the
//! checker from Actix Web's `Data` extractor and evaluates the request before
//! continuing.

use actix_web::{
    dev::Payload,
    web, App, FromRequest, HttpRequest, HttpResponse, HttpServer, Responder,
};
use gatehouse::{AccessEvaluation, PermissionChecker, Policy, PolicyBuilder};
use std::future::{ready, Ready};
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

impl FromRequest for AuthenticatedUser {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let default_id = Uuid::nil();
        let id = req
            .headers()
            .get("x-user-id")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| Uuid::parse_str(value).ok())
            .unwrap_or(default_id);

        let roles = req
            .headers()
            .get("x-roles")
            .and_then(|value| value.to_str().ok())
            .map(|raw| {
                raw.split(',')
                    .map(|role| role.trim().to_lowercase())
                    .filter(|role| !role.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec!["author".to_string()]);

        let user = User { id, roles };
        ready(Ok(AuthenticatedUser(user)))
    }
}

#[derive(Debug, Clone)]
pub struct BlogPost {
    pub id: Uuid,
    pub author_id: Uuid,
    pub locked: bool,
    pub published_at: Option<SystemTime>,
    pub created_at: SystemTime,
}

#[derive(Debug, Clone)]
pub enum Action {
    Edit,
    Publish,
    View,
}

#[derive(Debug, Clone)]
pub enum Resource {
    Post(BlogPost),
}

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub current_time: SystemTime,
}

// --------------------------
// 2) Building Our Policies
// --------------------------

fn admin_override_policy() -> Box<dyn Policy<User, Resource, Action, RequestContext>> {
    PolicyBuilder::<User, Resource, Action, RequestContext>::new("AdminOverride")
        .when(|user, _action, _resource, _ctx| user.roles.iter().any(|r| r == "admin"))
        .build()
}

fn author_can_edit_policy() -> Box<dyn Policy<User, Resource, Action, RequestContext>> {
    PolicyBuilder::<User, Resource, Action, RequestContext>::new("AuthorCanEdit")
        .when(|user, action, resource, _ctx| match (action, resource) {
            (Action::Edit, Resource::Post(post)) => {
                user.id == post.author_id && !post.locked && post.published_at.is_none()
            }
            _ => false,
        })
        .build()
}

fn draft_recency_policy() -> Box<dyn Policy<User, Resource, Action, RequestContext>> {
    const MAX_AGE: u64 = 30 * 24 * 60 * 60; // 30 days
    PolicyBuilder::<User, Resource, Action, RequestContext>::new("DraftRecencyWindow")
        .when(move |_user, action, resource, ctx| match (action, resource) {
            (Action::Edit, Resource::Post(post)) => {
                if post.published_at.is_some() {
                    return false;
                }

                ctx.current_time
                    .duration_since(post.created_at)
                    .unwrap_or_default()
                    .as_secs()
                    <= MAX_AGE
            }
            _ => false,
        })
        .build()
}

fn editors_can_publish() -> Box<dyn Policy<User, Resource, Action, RequestContext>> {
    PolicyBuilder::<User, Resource, Action, RequestContext>::new("EditorsCanPublish")
        .when(|user, action, resource, _ctx| match (action, resource) {
            (Action::Publish, Resource::Post(post)) => {
                !post.locked
                    && user
                        .roles
                        .iter()
                        .any(|role| role == "editor" || role == "admin")
            }
            _ => false,
        })
        .build()
}

fn published_posts_are_public() -> Box<dyn Policy<User, Resource, Action, RequestContext>> {
    PolicyBuilder::<User, Resource, Action, RequestContext>::new("PublishedPostsArePublic")
        .when(|user, action, resource, _ctx| match (action, resource) {
            (Action::View, Resource::Post(post)) => {
                post.published_at.is_some() || user.id == post.author_id
            }
            _ => false,
        })
        .build()
}

fn build_permission_checker() -> PermissionChecker<User, Resource, Action, RequestContext> {
    let mut checker = PermissionChecker::new();
    checker.add_policy(admin_override_policy());
    checker.add_policy(author_can_edit_policy());
    checker.add_policy(draft_recency_policy());
    checker.add_policy(editors_can_publish());
    checker.add_policy(published_posts_are_public());
    checker
}

// -------------------------------
// 3) Helpers for Mocked Resources
// -------------------------------

fn load_post(post_id: Uuid) -> BlogPost {
    let created_at = SystemTime::now() - Duration::from_secs(7 * 24 * 60 * 60);
    BlogPost {
        id: post_id,
        author_id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
        locked: false,
        published_at: None,
        created_at,
    }
}

fn load_published_post(post_id: Uuid) -> BlogPost {
    BlogPost {
        published_at: Some(SystemTime::now() - Duration::from_secs(2 * 24 * 60 * 60)),
        ..load_post(post_id)
    }
}

// -------------------------
// 4) Actix Web Handlers
// -------------------------

async fn edit_post(
    path: web::Path<Uuid>,
    AuthenticatedUser(user): AuthenticatedUser,
    checker: web::Data<PermissionChecker<User, Resource, Action, RequestContext>>,
) -> impl Responder {
    let post = load_post(*path);
    let ctx = RequestContext {
        current_time: SystemTime::now(),
    };

    match checker
        .evaluate_access(&user, &Action::Edit, &Resource::Post(post), &ctx)
        .await
    {
        AccessEvaluation::Granted { .. } => HttpResponse::Ok().body("Post updated"),
        AccessEvaluation::Denied { reason, trace } => HttpResponse::Forbidden()
            .body(format!("Denied: {}\n{}", reason, trace.format())),
    }
}

async fn publish_post(
    path: web::Path<Uuid>,
    AuthenticatedUser(user): AuthenticatedUser,
    checker: web::Data<PermissionChecker<User, Resource, Action, RequestContext>>,
) -> impl Responder {
    let post = load_post(*path);
    let ctx = RequestContext {
        current_time: SystemTime::now(),
    };

    match checker
        .evaluate_access(&user, &Action::Publish, &Resource::Post(post), &ctx)
        .await
    {
        AccessEvaluation::Granted { .. } => HttpResponse::Ok().body("Post published"),
        AccessEvaluation::Denied { reason, trace } => HttpResponse::Forbidden()
            .body(format!("Denied: {}\n{}", reason, trace.format())),
    }
}

async fn view_post(
    path: web::Path<Uuid>,
    maybe_user: Option<AuthenticatedUser>,
    checker: web::Data<PermissionChecker<User, Resource, Action, RequestContext>>,
) -> impl Responder {
    let user = maybe_user
        .map(|AuthenticatedUser(user)| user)
        .unwrap_or(User {
            id: Uuid::nil(),
            roles: vec![],
        });

    let post = load_published_post(*path);
    let ctx = RequestContext {
        current_time: SystemTime::now(),
    };

    match checker
        .evaluate_access(&user, &Action::View, &Resource::Post(post), &ctx)
        .await
    {
        AccessEvaluation::Granted { .. } => HttpResponse::Ok().body("Here is your post"),
        AccessEvaluation::Denied { reason, trace } => HttpResponse::Forbidden()
            .body(format!("Denied: {}\n{}", reason, trace.format())),
    }
}

// -------------------------
// 5) Actix Web App Startup
// -------------------------

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let checker = web::Data::new(build_permission_checker());

    println!("🚪 Gatehouse with Actix Web running on http://127.0.0.1:8080");
    println!("Use curl commands from the top of this file to try it out.\n");

    HttpServer::new(move || {
        App::new()
            .app_data(checker.clone())
            .route("/posts/{id}", web::put().to(edit_post))
            .route("/posts/{id}/publish", web::post().to(publish_post))
            .route("/posts/{id}", web::get().to(view_post))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
