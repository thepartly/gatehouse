//! Cross-domain delegation with `DelegatingPolicy`.
//!
//! Sometimes a decision in one domain is really a decision in another. Comment
//! moderation is the classic case: you may edit a comment if you wrote it, OR
//! if you are allowed to edit the document it hangs off. That second clause is
//! not a comment rule at all — it is the *document* domain's decision.
//!
//! Rather than copy the document's owner/admin logic into the comment checker
//! (where the two copies will drift), `DelegatingPolicy` maps the comment
//! request into the document domain and asks the document checker, reusing the
//! same `EvaluationSession` and folding the child decision into the trace.
//!
//! Run with:
//!
//! ```text
//! cargo run --example delegating_policy
//! ```

use async_trait::async_trait;
use gatehouse::{
    DelegatingPolicy, EvalCtx, EvaluationSession, PermissionChecker, Policy, PolicyBuilder,
    PolicyDomain, PolicyEvalResult,
};
use std::borrow::Cow;
use uuid::Uuid;

// ---- child domain: documents --------------------------------------

#[derive(Debug, Clone)]
struct DocUser {
    id: Uuid,
    is_admin: bool,
}

#[derive(Debug, Clone)]
struct Document {
    owner_id: Uuid,
}

#[derive(Debug, Clone)]
struct EditDoc;

struct DocumentDomain;

impl PolicyDomain for DocumentDomain {
    type Subject = DocUser;
    type Action = EditDoc;
    type Resource = Document;
    type Context = ();
}

/// The document domain owns its own access rules — the owner can edit, and so
/// can an admin. This checker is the single source of truth for "can edit this
/// document"; the comment domain borrows it rather than reimplementing it.
fn document_checker() -> PermissionChecker<DocumentDomain> {
    let owner = PolicyBuilder::<DocumentDomain>::new("DocumentOwner")
        .when(|user, _action, document, _ctx| user.id == document.owner_id)
        .build();
    let admin = PolicyBuilder::<DocumentDomain>::new("DocumentAdmin")
        .subjects(|user| user.is_admin)
        .build();

    let mut checker = PermissionChecker::named("DocumentChecker");
    checker.add_policy(owner);
    checker.add_policy(admin);
    checker
}

// ---- parent domain: comments --------------------------------------

#[derive(Debug, Clone)]
struct Principal {
    user_id: Uuid,
    is_admin: bool,
}

#[derive(Debug, Clone)]
struct Comment {
    author_id: Uuid,
    /// The document this comment hangs off. A real app loads it alongside the
    /// comment; the delegating policy reads it to form the child request.
    document: Document,
}

#[derive(Debug, Clone)]
struct EditComment;

struct CommentDomain;

impl PolicyDomain for CommentDomain {
    type Subject = Principal;
    type Action = EditComment;
    type Resource = Comment;
    type Context = ();
}

/// Direct comment rule: you can always edit your own comment.
struct AuthorCanEditComment;

#[async_trait]
impl Policy<CommentDomain> for AuthorCanEditComment {
    async fn evaluate(&self, ctx: &EvalCtx<'_, CommentDomain>) -> PolicyEvalResult {
        if ctx.subject.user_id == ctx.resource.author_id {
            ctx.grant("subject is the comment author")
        } else {
            ctx.not_applicable("subject is not the comment author")
        }
    }
    fn policy_type(&self) -> Cow<'static, str> {
        Cow::Borrowed("AuthorCanEditComment")
    }
}

/// The comment checker: edit your own comment OR inherit edit rights from the
/// parent document via delegation.
fn comment_checker() -> PermissionChecker<CommentDomain> {
    // The four mappers are the entire bridge between the comment domain and the
    // document domain. Subject, action, and context map once per batch; resource
    // maps once per item.
    let inherit_from_document = DelegatingPolicy::new(
        "InheritDocumentEdit",
        document_checker(),
        |principal: &Principal| DocUser {
            id: principal.user_id,
            is_admin: principal.is_admin,
        },
        |_action: &EditComment| EditDoc,
        |_subject: &Principal, _action: &EditComment, comment: &Comment, _ctx: &()| {
            comment.document.clone()
        },
        |_subject, _action, _ctx| (),
    );

    let mut checker = PermissionChecker::named("CommentChecker");
    checker.add_policy(AuthorCanEditComment);
    checker.add_policy(inherit_from_document);
    checker
}

// ---- driver --------------------------------------------------------

#[tokio::main]
async fn main() {
    let owner_id = Uuid::new_v4();
    let author_id = Uuid::new_v4();

    let comment = Comment {
        author_id,
        document: Document { owner_id },
    };

    let author = Principal {
        user_id: author_id,
        is_admin: false,
    };
    let document_owner = Principal {
        user_id: owner_id,
        is_admin: false,
    };
    let admin = Principal {
        user_id: Uuid::new_v4(),
        is_admin: true,
    };
    let stranger = Principal {
        user_id: Uuid::new_v4(),
        is_admin: false,
    };

    let checker = comment_checker();
    let session = EvaluationSession::empty();
    let action = EditComment;
    let context = ();

    let cases = [
        ("author", &author),
        ("document owner (not author)", &document_owner),
        ("admin (not author/owner)", &admin),
        ("unrelated user", &stranger),
    ];
    for (who, principal) in cases {
        let granted = checker
            .bind(&session, principal, &action, &context)
            .check(&comment)
            .await
            .is_granted();
        println!(
            "{who:<28} can edit the comment? {}",
            if granted { "yes" } else { "no" }
        );
    }

    // The document owner is not the comment author, so the direct rule denies;
    // the delegating policy then asks the document checker, which grants. The
    // trace shows the decision crossing the domain boundary.
    println!("\nTrace — document owner (not the author) editing the comment:");
    let decision = checker
        .bind(&session, &document_owner, &action, &context)
        .check(&comment)
        .await;
    println!("{}", decision.display_trace());

    assert!(checker
        .bind(&session, &author, &action, &context)
        .check(&comment)
        .await
        .is_granted());
    assert!(checker
        .bind(&session, &document_owner, &action, &context)
        .check(&comment)
        .await
        .is_granted());
    assert!(checker
        .bind(&session, &admin, &action, &context)
        .check(&comment)
        .await
        .is_granted());
    assert!(!checker
        .bind(&session, &stranger, &action, &context)
        .check(&comment)
        .await
        .is_granted());
}
