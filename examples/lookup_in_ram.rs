//! Lookup-style authorization with an in-memory backend.
//!
//! Demonstrates `PermissionChecker::lookup_authorized*` against an in-RAM
//! `LookupSource` and a `Hydrator`, composed with a non-lookup policy
//! (admin override) — the production shape #24 was scoped to enable.
//!
//! Domain: a notebook app where a user can list "documents I can see."
//! Visibility paths:
//!   - the user is a registered viewer (a relationship, enumerable per user)
//!   - the user is a global admin (a non-lookup grant axis)
//!
//! The `LookupSource` enumerates the viewer relationship only. Admin
//! overrides are still authorized through the policy stack: an admin's
//! lookup-driven listing returns the viewer-visible subset, while a point
//! check on any document returns Granted by the admin axis. The example
//! prints both so the difference is visible.

use async_trait::async_trait;
use gatehouse::{
    EvalCtx, EvaluationSession, LookupPage, LookupSource, PermissionChecker, Policy,
    PolicyEvalResult,
};
use std::collections::HashMap;
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::Arc;
use uuid::Uuid;

// --- Domain ------------------------------------------------------------

#[derive(Clone, Debug)]
struct User {
    id: Uuid,
    is_admin: bool,
}

#[derive(Clone, Debug)]
struct Document {
    id: Uuid,
    title: String,
}

#[derive(Clone, Debug)]
struct View;

#[derive(Clone, Debug)]
struct RequestCtx;

// --- Policies ----------------------------------------------------------

/// Grants admins access to any document, regardless of relationships.
struct AdminPolicy;

#[async_trait]
impl Policy<User, Document, View, RequestCtx> for AdminPolicy {
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, User, Document, View, RequestCtx>,
    ) -> PolicyEvalResult {
        if ctx.subject.is_admin {
            PolicyEvalResult::granted(self.policy_type(), Some("admin override".into()))
        } else {
            PolicyEvalResult::denied(self.policy_type(), "not admin")
        }
    }
    fn policy_type(&self) -> &str {
        "AdminPolicy"
    }
}

/// Grants when the user is registered as a viewer of the document.
/// Matched against the same relationships the lookup source enumerates.
struct ViewerPolicy {
    viewers: HashMap<Uuid, Vec<Uuid>>, // doc_id -> users with viewer relation
}

#[async_trait]
impl Policy<User, Document, View, RequestCtx> for ViewerPolicy {
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, User, Document, View, RequestCtx>,
    ) -> PolicyEvalResult {
        let granted = self
            .viewers
            .get(&ctx.resource.id)
            .map(|users| users.contains(&ctx.subject.id))
            .unwrap_or(false);
        if granted {
            PolicyEvalResult::granted(self.policy_type(), Some("viewer relation".into()))
        } else {
            PolicyEvalResult::denied(self.policy_type(), "no viewer relation")
        }
    }
    fn policy_type(&self) -> &str {
        "ViewerPolicy"
    }
}

// --- LookupSource ------------------------------------------------------

/// Enumerates the documents `user` is registered as a viewer of, in a
/// stable per-subject order. Pages by offset; cursor is the next offset
/// rendered as ASCII bytes.
///
/// In a real backend this would be `SELECT doc_id FROM viewers WHERE
/// user_id = $1 ORDER BY doc_id LIMIT $2 OFFSET decode($3)`.
struct InMemoryViewerLookup {
    per_user: HashMap<Uuid, Vec<Uuid>>,
}

#[derive(Debug)]
struct ViewerLookupError(String);
impl fmt::Display for ViewerLookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ViewerLookupError {}

#[async_trait]
impl LookupSource for InMemoryViewerLookup {
    type Subject = User;
    type Id = Uuid;
    type Error = ViewerLookupError;

    async fn lookup_page(
        &self,
        subject: &User,
        cursor: Option<&[u8]>,
        limit: NonZeroUsize,
    ) -> Result<LookupPage<Uuid>, ViewerLookupError> {
        let offset = cursor
            .map(|c| {
                std::str::from_utf8(c)
                    .map_err(|_| ViewerLookupError("non-utf8 cursor".into()))
                    .and_then(|s| {
                        s.parse::<usize>()
                            .map_err(|_| ViewerLookupError("cursor not a number".into()))
                    })
            })
            .transpose()?
            .unwrap_or(0);

        let all = self.per_user.get(&subject.id).cloned().unwrap_or_default();

        if offset >= all.len() {
            return Ok(LookupPage {
                ids: Vec::new(),
                next_cursor: None,
            });
        }
        let end = (offset + limit.get()).min(all.len());
        let next_cursor = (end < all.len()).then(|| end.to_string().into_bytes());
        Ok(LookupPage {
            ids: all[offset..end].to_vec(),
            next_cursor,
        })
    }
}

// --- Wiring + main -----------------------------------------------------

#[tokio::main]
async fn main() {
    // Build a small population.
    let alice = User {
        id: Uuid::new_v4(),
        is_admin: false,
    };
    let admin = User {
        id: Uuid::new_v4(),
        is_admin: true,
    };
    let docs: Vec<Document> = (0..7)
        .map(|i| Document {
            id: Uuid::new_v4(),
            title: format!("doc-{i}"),
        })
        .collect();

    // Alice is a viewer of docs[1], docs[3], docs[5].
    let viewer_doc_ids: Vec<Uuid> = [&docs[1], &docs[3], &docs[5]]
        .into_iter()
        .map(|d| d.id)
        .collect();

    let viewers: HashMap<Uuid, Vec<Uuid>> = viewer_doc_ids
        .iter()
        .map(|doc_id| (*doc_id, vec![alice.id]))
        .collect();

    let viewer_lookup_index: HashMap<Uuid, Vec<Uuid>> =
        HashMap::from([(alice.id, viewer_doc_ids.clone())]);

    // Document catalog used by the hydrator. In production this is a
    // database call: `SELECT * FROM docs WHERE id = ANY($1)`.
    let catalog: Arc<HashMap<Uuid, Document>> =
        Arc::new(docs.iter().map(|d| (d.id, d.clone())).collect());

    let lookup = InMemoryViewerLookup {
        per_user: viewer_lookup_index,
    };

    // Hydrator closure: maps a slice of ids to `Vec<Option<Document>>`.
    // `None` would represent an id deleted between enumeration and the
    // catalog fetch; the in-memory catalog here always resolves.
    let hydrator = {
        let catalog = Arc::clone(&catalog);
        move |ids: &[Uuid]| {
            let catalog = Arc::clone(&catalog);
            let ids = ids.to_vec();
            async move {
                Ok::<_, std::convert::Infallible>(
                    ids.iter().map(|id| catalog.get(id).cloned()).collect(),
                )
            }
        }
    };

    // Compose policies: admin override OR viewer relation. The lookup
    // source only enumerates the viewer axis — admin overrides apply only
    // to point checks.
    let mut checker = PermissionChecker::<User, Document, View, RequestCtx>::new();
    checker.add_policy(AdminPolicy);
    checker.add_policy(ViewerPolicy { viewers });

    let session = EvaluationSession::empty();
    let page_size = NonZeroUsize::new(2).unwrap();

    // (1) Alice lists her visible documents via lookup_authorized.
    let alice_visible = checker
        .lookup_authorized(
            &session,
            &alice,
            &View,
            &RequestCtx,
            &lookup,
            page_size,
            &hydrator,
        )
        .await
        .expect("lookup ok");
    println!("Alice sees {} document(s):", alice_visible.len());
    for doc in &alice_visible {
        println!("  - {} ({})", doc.title, doc.id);
    }

    // (2) Admin lists "their visible documents" via the same lookup.
    // The viewer lookup does not enumerate documents for the admin (no
    // viewer relation), so this listing returns empty — correctly,
    // because lookup is bounded by what it enumerates. To enumerate
    // "everything an admin can see", the production code would either
    // route admin requests to a different source or simply skip the
    // lookup path and list directly.
    let admin_via_lookup = checker
        .lookup_authorized(
            &session,
            &admin,
            &View,
            &RequestCtx,
            &lookup,
            page_size,
            &hydrator,
        )
        .await
        .expect("lookup ok");
    println!(
        "\nAdmin via the viewer-lookup sees {} document(s) — this is bounded \
         by what the source enumerates; admin grants still apply at point checks.",
        admin_via_lookup.len()
    );

    // (3) Point check confirms the admin policy is alive: pick a document
    // the admin has no viewer relation on.
    let any_doc = &docs[0];
    let admin_point = checker
        .evaluate_in_session(&session, &admin, &View, any_doc, &RequestCtx)
        .await;
    println!(
        "\nAdmin point check on '{}': {}",
        any_doc.title,
        if admin_point.is_granted() {
            "Granted"
        } else {
            "Denied"
        }
    );

    // (4) Page-oriented streaming. Drive the lookup one candidate page at
    // a time — useful when you want to flush results to a response writer
    // as they are confirmed.
    println!("\nStreaming Alice's visible documents page-by-page:");
    let mut cursor: Option<Vec<u8>> = None;
    let mut page_index = 0;
    loop {
        let page = checker
            .lookup_authorized_page(
                &session,
                &alice,
                &View,
                &RequestCtx,
                &lookup,
                cursor.as_deref(),
                page_size,
                &hydrator,
            )
            .await
            .expect("lookup_authorized_page ok");
        println!("  page {page_index}: {} authorized", page.resources.len());
        page_index += 1;
        match page.next_cursor {
            None => break,
            Some(next) => cursor = Some(next),
        }
    }
}
