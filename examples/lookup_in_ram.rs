//! Lookup-style authorization with an in-memory backend.
//!
//! Demonstrates `BoundEvaluator::try_lookup_page` against an in-RAM
//! `LookupSource` and a `Hydrator`, composed with a non-lookup policy
//! (admin override) — the production shape #24 was scoped to enable.
//!
//! Domain: a notebook app where a user can list "documents I can see."
//! Visibility paths:
//!   - the user is a registered viewer (a relationship, enumerable per user)
//!   - the user is a global admin (a non-lookup grant axis)
//!
//! The `LookupSource` enumerates a complete candidate set for every grant
//! path: viewer documents for ordinary users, all documents for admins.
//! The checker then authorizes each candidate after hydration.

use async_trait::async_trait;
use gatehouse::{
    EvalCtx, EvaluationSession, GrantResult, LookupPage, LookupSource, PermissionChecker, Policy,
    PolicyDomain,
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

struct DocumentDomain;

impl PolicyDomain for DocumentDomain {
    type Subject = User;
    type Action = View;
    type Resource = Document;
    type Context = ();
}

// --- Policies ----------------------------------------------------------

/// Grants admins access to any document, regardless of relationships.
struct AdminPolicy;

#[async_trait]
impl Policy<DocumentDomain> for AdminPolicy {
    async fn evaluate(&self, ctx: &EvalCtx<'_, DocumentDomain>) -> GrantResult {
        if ctx.subject.is_admin {
            ctx.grant("admin override")
        } else {
            ctx.not_applicable("not admin")
        }
    }
    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("AdminPolicy")
    }
}

/// Grants when the user is registered as a viewer of the document.
/// Matched against the same relationships the lookup source enumerates.
struct ViewerPolicy {
    viewers: HashMap<Uuid, Vec<Uuid>>, // doc_id -> users with viewer relation
}

#[async_trait]
impl Policy<DocumentDomain> for ViewerPolicy {
    async fn evaluate(&self, ctx: &EvalCtx<'_, DocumentDomain>) -> GrantResult {
        let granted = self
            .viewers
            .get(&ctx.resource.id)
            .map(|users| users.contains(&ctx.subject.id))
            .unwrap_or(false);
        if granted {
            ctx.grant("viewer relation")
        } else {
            ctx.not_applicable("no viewer relation")
        }
    }
    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("ViewerPolicy")
    }
}

// --- LookupSource ------------------------------------------------------

/// Enumerates all documents for admins and viewer documents for other users,
/// in a stable order. Pages by offset; cursor is the next offset
/// rendered as ASCII bytes.
///
/// In a real backend this would be `SELECT doc_id FROM viewers WHERE
/// user_id = $1 ORDER BY doc_id LIMIT $2 OFFSET decode($3)`.
struct InMemoryViewerLookup {
    per_user: HashMap<Uuid, Vec<Uuid>>,
    all_documents: Vec<Uuid>,
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
impl LookupSource<DocumentDomain> for InMemoryViewerLookup {
    type Id = Uuid;
    type Error = ViewerLookupError;

    async fn lookup_page(
        &self,
        subject: &User,
        _action: &View,
        _context: &(),
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

        let all = if subject.is_admin {
            self.all_documents.as_slice()
        } else {
            self.per_user
                .get(&subject.id)
                .map(Vec::as_slice)
                .unwrap_or_default()
        };

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

async fn collect_authorized<H>(
    checker: &PermissionChecker<DocumentDomain>,
    session: &EvaluationSession,
    subject: &User,
    lookup: &InMemoryViewerLookup,
    page_size: NonZeroUsize,
    hydrator: &H,
) -> Result<Vec<Document>, gatehouse::LookupAuthorizedError<ViewerLookupError, H::Error, Document>>
where
    H: gatehouse::Hydrator<Uuid, Resource = Document>,
{
    let mut cursor: Option<Vec<u8>> = None;
    let mut authorized = Vec::new();
    let bound = checker.bind(session, subject, &View, &());
    loop {
        let page = bound
            .try_lookup_page(lookup, hydrator, cursor.as_deref(), page_size)
            .await?;
        authorized.extend(page.resources);
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => return Ok(authorized),
        }
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
        all_documents: docs.iter().map(|document| document.id).collect(),
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

    // The lookup source covers both grant paths: admin and viewer.
    let mut checker = PermissionChecker::<DocumentDomain>::new();
    checker.add_policy(AdminPolicy);
    checker.add_policy(ViewerPolicy { viewers });

    let session = EvaluationSession::empty();
    let page_size = NonZeroUsize::new(2).unwrap();

    // (1) Alice lists her visible documents by collecting lookup pages.
    let alice_visible =
        collect_authorized(&checker, &session, &alice, &lookup, page_size, &hydrator)
            .await
            .expect("lookup ok");
    println!("Alice sees {} document(s):", alice_visible.len());
    for doc in &alice_visible {
        println!("  - {} ({})", doc.title, doc.id);
    }
    let alice_visible_ids: Vec<Uuid> = alice_visible.iter().map(|doc| doc.id).collect();
    assert_eq!(
        alice_visible_ids, viewer_doc_ids,
        "the lookup + policy stack should authorize exactly the viewer-granted documents, in source order"
    );

    // (2) Admin lists all documents through the same complete candidate source.
    let admin_via_lookup =
        collect_authorized(&checker, &session, &admin, &lookup, page_size, &hydrator)
            .await
            .expect("lookup ok");
    println!("\nAdmin sees {} document(s).", admin_via_lookup.len());
    assert_eq!(
        admin_via_lookup
            .iter()
            .map(|document| document.id)
            .collect::<Vec<_>>(),
        docs.iter().map(|document| document.id).collect::<Vec<_>>(),
    );

    // (3) Point check confirms the admin policy is alive: pick a document
    // the admin has no viewer relation on.
    let any_doc = &docs[0];
    let admin_point = checker
        .bind(&session, &admin, &View, &())
        .check(any_doc)
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
    admin_point.assert_granted_by("AdminPolicy");

    // (4) Page-oriented streaming. Drive the lookup one candidate page at
    // a time — useful when you want to flush results to a response writer
    // as they are confirmed.
    println!("\nStreaming Alice's visible documents page-by-page:");
    let mut cursor: Option<Vec<u8>> = None;
    let mut page_index = 0;
    let mut streamed_total = 0;
    let alice_bound = checker.bind(&session, &alice, &View, &());
    loop {
        let page = alice_bound
            .try_lookup_page(&lookup, &hydrator, cursor.as_deref(), page_size)
            .await
            .expect("lookup and authorization must complete");
        println!("  page {page_index}: {} authorized", page.resources.len());
        page_index += 1;
        streamed_total += page.resources.len();
        match page.next_cursor {
            None => break,
            Some(next) => cursor = Some(next),
        }
    }
    // 3 candidate ids paged 2-at-a-time: two candidate pages, same total as
    // the helper loop above.
    assert_eq!(page_index, 2);
    assert_eq!(streamed_total, viewer_doc_ids.len());
}
