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
// - `PUT  /posts/{id}`            checks whether editing would be allowed.
// - `POST /posts/{id}/publish`    checks whether publishing would be allowed.
//
// These are authorization-only demonstrations; the stored fixtures never change.
// Identity and roles come from unauthenticated demo headers. Run on loopback only.
//
// Try it with curl (the demo grants user 2222… an editor relationship on the
// demo posts, so they can view drafts and edit without being the author):
//
// ```bash
// # The author lists their posts
// curl -s http://127.0.0.1:8080/posts \
//   -H "x-user-id: 11111111-1111-1111-1111-111111111111"
//
// # Check whether a collaborator may edit a draft they did not author
// curl -i -X PUT http://127.0.0.1:8080/posts/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa \
//   -H "x-user-id: 22222222-2222-2222-2222-222222222222"
//
// # Anyone can view a published post
// curl -i http://127.0.0.1:8080/posts/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
// ```
//
// Each handler pulls the shared `AppState` from Actix Web's `Data` extractor,
// builds a request-scoped `EvaluationSession`, and evaluates with
// `bind(...).authorize(...)` (single resource) or
// `bind(...).try_filter(...)` (the list endpoint).
//

use actix_web::{
    dev::Payload, web, App, FromRequest, HttpRequest, HttpResponse, HttpServer, Responder,
};
use async_trait::async_trait;
use gatehouse::{
    AccessError, AndPolicy, EvaluationSession, FactLoadResult, FactRegistry, FactSource,
    PermissionChecker, Policy, PolicyBuilder, PolicyDomain, RebacPolicy, RelationshipQuery,
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

/// Unauthenticated identity supplied by the caller for this loopback demo.
#[derive(Debug, Clone)]
pub struct DemoUser(pub User);

impl FromRequest for DemoUser {
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

        ready(Ok(DemoUser(User { id, roles })))
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

pub struct BlogDomain;

impl PolicyDomain for BlogDomain {
    type Subject = User;
    type Action = Action;
    type Resource = BlogPost;
    type Context = RequestContext;
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

/// The long-lived pieces: the checker and fact registry are built once at
/// startup and shared across requests. Each request derives a fresh
/// `EvaluationSession` from the registry.
#[derive(Clone)]
pub struct AppState {
    checker: Arc<PermissionChecker<BlogDomain>>,
    fact_registry: FactRegistry,
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
            fact_registry: FactRegistry::builder()
                .with_arc::<PostRelationship>(Arc::new(InMemoryRelationshipSource::new(grants)))
                .build(),
            posts: Arc::new(posts),
        }
    }

    /// Replaces the relationship backend while retaining the demo checker and resources.
    pub fn with_relationship_source<S: FactSource<PostRelationship> + 'static>(
        mut self,
        source: S,
    ) -> Self {
        self.fact_registry = FactRegistry::builder()
            .with::<PostRelationship, _>(source)
            .build();
        self
    }

    fn request_session(&self) -> EvaluationSession {
        self.fact_registry.session()
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
        BlogPost {
            id: Uuid::parse_str("cccccccc-cccc-cccc-cccc-cccccccccccc").unwrap(),
            title: "locked draft".into(),
            author_id,
            locked: true,
            published_at: None,
            created_at: now - Duration::from_secs(3 * 24 * 60 * 60),
        },
        BlogPost {
            id: Uuid::parse_str("dddddddd-dddd-dddd-dddd-dddddddddddd").unwrap(),
            title: "old draft".into(),
            author_id,
            locked: false,
            published_at: None,
            created_at: now - Duration::from_secs(31 * 24 * 60 * 60),
        },
    ]
}

// --------------------------
// 3) Building Our Policies
// --------------------------

fn admin_override_policy() -> Box<dyn Policy<BlogDomain>> {
    PolicyBuilder::<BlogDomain>::new("AdminOverride")
        .when(|user, _action, _post, _ctx| user.roles.iter().any(|role| role == "admin"))
        .build()
}

/// Editing rule for the author: edit your own unpublished, unlocked draft that
/// is still inside the 30-day window.
fn author_can_edit_policy() -> Box<dyn Policy<BlogDomain>> {
    const MAX_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);
    PolicyBuilder::<BlogDomain>::new("AuthorCanEdit")
        .when(|user, action, post, ctx| {
            matches!(action, Action::Edit)
                && user.id == post.author_id
                && !post.locked
                && post.published_at.is_none()
                && ctx
                    .current_time
                    .duration_since(post.created_at)
                    .is_ok_and(|age| age < MAX_AGE)
        })
        .build()
}

/// The fact-backed rule: a registered collaborator (an "editor" relationship,
/// loaded through the session) may view and edit the post, author or not. The
/// guard restricts the relationship check to the View/Edit actions; publishing
/// stays role-gated below.
fn collaborator_policy() -> Box<dyn Policy<BlogDomain>> {
    let is_view_or_edit: Arc<dyn Policy<BlogDomain>> = Arc::from(
        PolicyBuilder::<BlogDomain>::new("IsViewOrEdit")
            .when(|_user, action, post, _ctx| {
                matches!(action, Action::View) || (matches!(action, Action::Edit) && !post.locked)
            })
            .build(),
    );
    let has_editor_relationship: Arc<dyn Policy<BlogDomain>> =
        Arc::new(RebacPolicy::<BlogDomain, Uuid, Uuid, Relation>::new(
            |user: &User| user.id,
            |post: &BlogPost| post.id,
            Relation::Editor,
        ));

    Box::new(
        AndPolicy::try_new(vec![is_view_or_edit, has_editor_relationship])
            .expect("collaborator policy has a guard and a relationship check"),
    )
}

fn editors_can_publish_policy() -> Box<dyn Policy<BlogDomain>> {
    PolicyBuilder::<BlogDomain>::new("EditorsCanPublish")
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

fn published_posts_are_public_policy() -> Box<dyn Policy<BlogDomain>> {
    PolicyBuilder::<BlogDomain>::new("PublishedPostsArePublic")
        .when(|user, action, post, _ctx| {
            matches!(action, Action::View)
                && (post.published_at.is_some() || user.id == post.author_id)
        })
        .build()
}

pub fn build_permission_checker() -> PermissionChecker<BlogDomain> {
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

fn load_post(state: &AppState, post_id: Uuid) -> Option<&BlogPost> {
    state.posts.iter().find(|post| post.id == post_id)
}

/// List the posts the caller is allowed to view. The relationship checks for
/// every candidate are batched and deduplicated through one request-scoped
/// session.
pub async fn list_posts(DemoUser(user): DemoUser, state: web::Data<AppState>) -> impl Responder {
    let session = state.request_session();
    let context = RequestContext::now();
    let candidates = state.posts.as_ref().clone();

    let visible = match state
        .checker
        .bind(&session, &user, &Action::View, &context)
        .try_filter(candidates)
        .await
    {
        Ok(visible) => visible,
        Err(_) => {
            return HttpResponse::ServiceUnavailable().body("Authorization temporarily unavailable")
        }
    };

    let summaries = visible.iter().map(PostSummary::from).collect::<Vec<_>>();
    HttpResponse::Ok().json(summaries)
}

pub async fn view_post(
    path: web::Path<Uuid>,
    DemoUser(user): DemoUser,
    state: web::Data<AppState>,
) -> impl Responder {
    let Some(post) = load_post(&state, *path) else {
        return HttpResponse::NotFound().body("Post not found");
    };
    let session = state.request_session();
    let context = RequestContext::now();

    match state
        .checker
        .bind(&session, &user, &Action::View, &context)
        .authorize(post)
        .await
    {
        Ok(()) => HttpResponse::Ok().body(format!("Viewing '{}'", post.title)),
        Err(AccessError::Denied { .. }) => HttpResponse::Forbidden().body("Access denied"),
        Err(_) => HttpResponse::ServiceUnavailable().body("Authorization temporarily unavailable"),
    }
}

pub async fn edit_post(
    path: web::Path<Uuid>,
    DemoUser(user): DemoUser,
    state: web::Data<AppState>,
) -> impl Responder {
    let Some(post) = load_post(&state, *path) else {
        return HttpResponse::NotFound().body("Post not found");
    };
    let session = state.request_session();
    let context = RequestContext::now();

    match state
        .checker
        .bind(&session, &user, &Action::Edit, &context)
        .authorize(post)
        .await
    {
        Ok(()) => HttpResponse::Ok().body("Edit authorized; no changes made"),
        Err(AccessError::Denied { .. }) => HttpResponse::Forbidden().body("Access denied"),
        Err(_) => HttpResponse::ServiceUnavailable().body("Authorization temporarily unavailable"),
    }
}

pub async fn publish_post(
    path: web::Path<Uuid>,
    DemoUser(user): DemoUser,
    state: web::Data<AppState>,
) -> impl Responder {
    let Some(post) = load_post(&state, *path) else {
        return HttpResponse::NotFound().body("Post not found");
    };
    let session = state.request_session();
    let context = RequestContext::now();

    match state
        .checker
        .bind(&session, &user, &Action::Publish, &context)
        .authorize(post)
        .await
    {
        Ok(()) => HttpResponse::Ok().body("Publish authorized; no changes made"),
        Err(AccessError::Denied { .. }) => HttpResponse::Forbidden().body("Access denied"),
        Err(_) => HttpResponse::ServiceUnavailable().body("Authorization temporarily unavailable"),
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
