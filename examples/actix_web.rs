// Actix Web example showing Gatehouse in a fact-backed service: shared app
// state owns a long-lived `PermissionChecker` and a relationship `FactSource`,
// and each request builds its own `EvaluationSession`. A blog post is viewable
// or editable by its author, by a registered collaborator (an "editor"
// relationship loaded through the session), or by an admin.
//
// The server exposes four routes:
//
// - `GET  /posts`                 lists the posts the caller may view (batched).
// - `GET  /posts/{id}`            reads a post when it is published or the caller is privileged.
// - `PUT  /posts/{id}`            edits a post if the caller is allowed.
// - `POST /posts/{id}/publish`    publishes a post for editors.
//
// Try it with curl (the demo grants user 2222… an editor relationship on the
// demo posts, so they can view drafts and edit without being the author):
//
// ```bash
// # The author lists their posts
// curl -s http://127.0.0.1:8080/posts \
//   -H "x-user-id: 11111111-1111-1111-1111-111111111111"
//
// # A collaborator (editor relationship) edits a draft they did not author
// curl -i -X PUT http://127.0.0.1:8080/posts/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa \
//   -H "x-user-id: 22222222-2222-2222-2222-222222222222"
//
// # Anyone can view a published post
// curl -i http://127.0.0.1:8080/posts/00000000-0000-0000-0000-000000000000 \
//   -H "x-post-published: true"
// ```
//
// Each handler pulls the shared `AppState` from Actix Web's `Data` extractor,
// builds a request-scoped `EvaluationSession`, and evaluates with
// `evaluate_in_session` (single resource) or
// `filter_authorized_in_session_by_resource` (the list endpoint).
//
// Note: on denial these handlers echo the evaluation trace back in the HTTP
// response so you can see the decision from `curl`. That is a demo convenience,
// not a production pattern — see `forbidden` below.

use actix_web::{
    dev::Payload, web, App, FromRequest, HttpRequest, HttpResponse, HttpServer, Responder,
};
use async_trait::async_trait;
use gatehouse::{
    AccessEvaluation, AndPolicy, EvalTrace, EvaluationSession, FactLoadResult, FactSource,
    PermissionChecker, Policy, PolicyBuilder, RebacPolicy, RelationshipQuery,
};
use serde::Serialize;
use std::collections::HashSet;
use std::fmt;
use std::future::{ready, Ready};
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

impl FromRequest for AuthenticatedUser {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let id = req
            .headers()
            .get("x-user-id")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| Uuid::parse_str(value).ok())
            .unwrap_or_else(Uuid::nil);

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
            .unwrap_or_default();

        ready(Ok(AuthenticatedUser(User { id, roles })))
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" => Some(false),
        _ => None,
    }
}

/// Header overrides so a single demo post can be coerced into different shapes
/// (locked, published, older than the draft window) from `curl`.
#[derive(Debug, Clone, Default)]
pub struct PostOverrides {
    locked: Option<bool>,
    published: Option<bool>,
    age_days: Option<u64>,
}

impl PostOverrides {
    pub fn from_request(req: &HttpRequest) -> Self {
        let header_bool = |name: &str| {
            req.headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .and_then(parse_bool)
        };

        Self {
            locked: header_bool("x-post-locked"),
            published: header_bool("x-post-published"),
            age_days: req
                .headers()
                .get("x-post-age-days")
                .and_then(|value| value.to_str().ok())
                .and_then(|raw| raw.parse::<u64>().ok()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BlogPost {
    pub id: Uuid,
    pub title: String,
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

// A typed relation set, even though the in-memory store could use strings. The
// session deduplicates and caches by the typed `RelationshipQuery`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Relation {
    Editor,
}

impl fmt::Display for Relation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Editor => f.write_str("editor"),
        }
    }
}

type PostRelationship = RelationshipQuery<Uuid, Uuid, Relation>;

/// In-memory collaborator relationships. A real service would back this with a
/// database pool or graph client; the `FactSource` boundary is identical.
#[derive(Clone)]
pub struct InMemoryRelationshipSource {
    grants: Arc<HashSet<PostRelationship>>,
}

impl InMemoryRelationshipSource {
    fn new(grants: impl IntoIterator<Item = PostRelationship>) -> Self {
        Self {
            grants: Arc::new(grants.into_iter().collect()),
        }
    }
}

#[async_trait]
impl FactSource<PostRelationship> for InMemoryRelationshipSource {
    async fn load_many(&self, keys: &[PostRelationship]) -> Vec<FactLoadResult<bool>> {
        keys.iter()
            .map(|key| FactLoadResult::Found(self.grants.contains(key)))
            .collect()
    }
}

// --------------------------
// 2) Shared application state
// --------------------------

/// The long-lived pieces: the checker and the relationship source are built
/// once at startup and shared across requests. Each request derives a fresh
/// `EvaluationSession` from the source.
#[derive(Clone)]
pub struct AppState {
    checker: Arc<PermissionChecker<User, BlogPost, Action, RequestContext>>,
    relationships: Arc<dyn FactSource<PostRelationship>>,
    posts: Arc<Vec<BlogPost>>,
}

impl AppState {
    pub fn demo() -> Self {
        let author_id = demo_author_id();
        let collaborator_id = demo_collaborator_id();
        let posts = demo_posts(author_id);

        // The collaborator has an editor relationship on every demo post.
        let grants = posts.iter().map(|post| PostRelationship {
            subject_id: collaborator_id,
            resource_id: post.id,
            relation: Relation::Editor,
        });

        Self {
            checker: Arc::new(build_permission_checker()),
            relationships: Arc::new(InMemoryRelationshipSource::new(grants)),
            posts: Arc::new(posts),
        }
    }

    fn request_session(&self) -> EvaluationSession {
        EvaluationSession::builder()
            .with_arc::<PostRelationship>(Arc::clone(&self.relationships))
            .build()
    }
}

fn demo_author_id() -> Uuid {
    Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()
}

fn demo_collaborator_id() -> Uuid {
    Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap()
}

fn demo_posts(author_id: Uuid) -> Vec<BlogPost> {
    let now = SystemTime::now();
    vec![
        BlogPost {
            id: Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap(),
            title: "draft roadmap".into(),
            author_id,
            locked: false,
            published_at: None,
            created_at: now - Duration::from_secs(3 * 24 * 60 * 60),
        },
        BlogPost {
            id: Uuid::parse_str("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap(),
            title: "published announcement".into(),
            author_id,
            locked: false,
            published_at: Some(now - Duration::from_secs(2 * 24 * 60 * 60)),
            created_at: now - Duration::from_secs(10 * 24 * 60 * 60),
        },
    ]
}

// --------------------------
// 3) Building Our Policies
// --------------------------

fn admin_override_policy() -> Box<dyn Policy<User, BlogPost, Action, RequestContext>> {
    PolicyBuilder::<User, BlogPost, Action, RequestContext>::new("AdminOverride")
        .when(|user, _action, _post, _ctx| user.roles.iter().any(|role| role == "admin"))
        .build()
}

/// Editing rule for the author: edit your own unpublished, unlocked draft that
/// is still inside the 30-day window.
fn author_can_edit_policy() -> Box<dyn Policy<User, BlogPost, Action, RequestContext>> {
    const MAX_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);
    PolicyBuilder::<User, BlogPost, Action, RequestContext>::new("AuthorCanEdit")
        .when(|user, action, post, ctx| {
            matches!(action, Action::Edit)
                && user.id == post.author_id
                && !post.locked
                && post.published_at.is_none()
                && ctx
                    .current_time
                    .duration_since(post.created_at)
                    .unwrap_or_default()
                    <= MAX_AGE
        })
        .build()
}

/// The fact-backed rule: a registered collaborator (an "editor" relationship,
/// loaded through the session) may view and edit the post, author or not. The
/// guard restricts the relationship check to the View/Edit actions; publishing
/// stays role-gated below.
fn collaborator_policy() -> Box<dyn Policy<User, BlogPost, Action, RequestContext>> {
    let is_view_or_edit: Arc<dyn Policy<User, BlogPost, Action, RequestContext>> = Arc::from(
        PolicyBuilder::<User, BlogPost, Action, RequestContext>::new("IsViewOrEdit")
            .when(|_user, action, _post, _ctx| matches!(action, Action::View | Action::Edit))
            .build(),
    );
    let has_editor_relationship: Arc<dyn Policy<User, BlogPost, Action, RequestContext>> =
        Arc::new(RebacPolicy::new(
            |user: &User| user.id,
            |post: &BlogPost| post.id,
            Relation::Editor,
        ));

    Box::new(
        AndPolicy::try_new(vec![is_view_or_edit, has_editor_relationship])
            .expect("collaborator policy has a guard and a relationship check"),
    )
}

fn editors_can_publish_policy() -> Box<dyn Policy<User, BlogPost, Action, RequestContext>> {
    PolicyBuilder::<User, BlogPost, Action, RequestContext>::new("EditorsCanPublish")
        .when(|user, action, post, _ctx| {
            matches!(action, Action::Publish)
                && !post.locked
                && user
                    .roles
                    .iter()
                    .any(|role| role == "editor" || role == "admin")
        })
        .build()
}

fn published_posts_are_public_policy() -> Box<dyn Policy<User, BlogPost, Action, RequestContext>> {
    PolicyBuilder::<User, BlogPost, Action, RequestContext>::new("PublishedPostsArePublic")
        .when(|user, action, post, _ctx| {
            matches!(action, Action::View)
                && (post.published_at.is_some() || user.id == post.author_id)
        })
        .build()
}

pub fn build_permission_checker() -> PermissionChecker<User, BlogPost, Action, RequestContext> {
    let mut checker = PermissionChecker::named("BlogPostChecker");
    checker.add_policy(admin_override_policy());
    checker.add_policy(author_can_edit_policy());
    checker.add_policy(collaborator_policy());
    checker.add_policy(editors_can_publish_policy());
    checker.add_policy(published_posts_are_public_policy());
    checker
}

// -------------------------
// 4) Actix Web Handlers
// -------------------------

#[derive(Debug, Serialize)]
pub struct PostSummary {
    pub id: Uuid,
    pub title: String,
    pub published: bool,
}

impl From<&BlogPost> for PostSummary {
    fn from(post: &BlogPost) -> Self {
        Self {
            id: post.id,
            title: post.title.clone(),
            published: post.published_at.is_some(),
        }
    }
}

/// Build the 403 response for a denied request.
///
/// This demo echoes the full evaluation trace back to the caller so you can see
/// *why* a request was denied from `curl` alone. Don't do this in production:
/// the reason strings and trace are an internal audit surface (see the README's
/// "Tracing And Telemetry" section) and can expose policy structure or any data
/// a policy interpolates into a reason. In a real service, log the trace
/// server-side and return a generic message to the client.
fn forbidden(reason: &str, trace: &EvalTrace) -> HttpResponse {
    HttpResponse::Forbidden().body(format!("Denied: {}\n{}", reason, trace.format()))
}

/// Load a single post by id, applying any header overrides. A miss falls back
/// to a synthesized post so the demo works for arbitrary ids from `curl`.
fn load_post(state: &AppState, post_id: Uuid, overrides: &PostOverrides) -> BlogPost {
    if let Some(post) = state.posts.iter().find(|post| post.id == post_id) {
        let mut post = post.clone();
        if let Some(locked) = overrides.locked {
            post.locked = locked;
        }
        if let Some(published) = overrides.published {
            post.published_at =
                published.then(|| SystemTime::now() - Duration::from_secs(2 * 24 * 60 * 60));
        }
        if let Some(age_days) = overrides.age_days {
            post.created_at = SystemTime::now() - Duration::from_secs(age_days * 24 * 60 * 60);
        }
        return post;
    }

    BlogPost {
        id: post_id,
        title: "untitled".into(),
        author_id: demo_author_id(),
        locked: overrides.locked.unwrap_or(false),
        published_at: overrides
            .published
            .unwrap_or(false)
            .then(|| SystemTime::now() - Duration::from_secs(2 * 24 * 60 * 60)),
        created_at: SystemTime::now()
            - Duration::from_secs(overrides.age_days.unwrap_or(7) * 24 * 60 * 60),
    }
}

/// List the posts the caller is allowed to view. The relationship checks for
/// every candidate are batched and deduplicated through one request-scoped
/// session.
pub async fn list_posts(
    AuthenticatedUser(user): AuthenticatedUser,
    state: web::Data<AppState>,
) -> impl Responder {
    let session = state.request_session();
    let context = RequestContext::now();
    let candidates = state.posts.as_ref().clone();

    let visible = state
        .checker
        .filter_authorized_in_session_by_resource(
            &session,
            &user,
            &Action::View,
            candidates,
            &context,
            |post| post,
        )
        .await;

    let summaries = visible.iter().map(PostSummary::from).collect::<Vec<_>>();
    HttpResponse::Ok().json(summaries)
}

pub async fn view_post(
    path: web::Path<Uuid>,
    req: HttpRequest,
    AuthenticatedUser(user): AuthenticatedUser,
    state: web::Data<AppState>,
) -> impl Responder {
    let post = load_post(&state, *path, &PostOverrides::from_request(&req));
    let session = state.request_session();

    match state
        .checker
        .evaluate_in_session(
            &session,
            &user,
            &Action::View,
            &post,
            &RequestContext::now(),
        )
        .await
    {
        AccessEvaluation::Granted { .. } => {
            HttpResponse::Ok().body(format!("Viewing '{}'", post.title))
        }
        AccessEvaluation::Denied { reason, trace } => forbidden(&reason, &trace),
    }
}

pub async fn edit_post(
    path: web::Path<Uuid>,
    req: HttpRequest,
    AuthenticatedUser(user): AuthenticatedUser,
    state: web::Data<AppState>,
) -> impl Responder {
    let post = load_post(&state, *path, &PostOverrides::from_request(&req));
    let session = state.request_session();

    match state
        .checker
        .evaluate_in_session(
            &session,
            &user,
            &Action::Edit,
            &post,
            &RequestContext::now(),
        )
        .await
    {
        AccessEvaluation::Granted { .. } => HttpResponse::Ok().body("Post updated"),
        AccessEvaluation::Denied { reason, trace } => forbidden(&reason, &trace),
    }
}

pub async fn publish_post(
    path: web::Path<Uuid>,
    req: HttpRequest,
    AuthenticatedUser(user): AuthenticatedUser,
    state: web::Data<AppState>,
) -> impl Responder {
    let post = load_post(&state, *path, &PostOverrides::from_request(&req));
    let session = state.request_session();

    match state
        .checker
        .evaluate_in_session(
            &session,
            &user,
            &Action::Publish,
            &post,
            &RequestContext::now(),
        )
        .await
    {
        AccessEvaluation::Granted { .. } => HttpResponse::Ok().body("Post published"),
        AccessEvaluation::Denied { reason, trace } => forbidden(&reason, &trace),
    }
}

// -------------------------
// 5) Actix Web App Startup
// -------------------------

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let state = web::Data::new(AppState::demo());

    println!("🚪 Gatehouse with Actix Web running on http://127.0.0.1:8080");
    println!("Use the curl commands from the top of this file to try it out.\n");

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .route("/posts", web::get().to(list_posts))
            .route("/posts/{id}", web::get().to(view_post))
            .route("/posts/{id}", web::put().to(edit_post))
            .route("/posts/{id}/publish", web::post().to(publish_post))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
