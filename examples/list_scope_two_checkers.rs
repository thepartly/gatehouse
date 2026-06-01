//! Two-checker pattern for distinct "list" vs "view detail" scopes.
//!
//! A common shape in real apps: the same resource (here, `Document`) is
//! reachable through two endpoints with *different* authorization rules.
//!
//! - **List**: "show me the documents I can see at all." This is the
//!   broadest scope — anyone in the workspace can see *that* a document
//!   exists, but their view is filtered to stubs they're cleared to know
//!   about. Used to drive index pages, search results, and list
//!   endpoints.
//! - **View detail**: "open the document and see its body." This is the
//!   narrower per-item check. The user must additionally be an owner,
//!   an explicit collaborator, or an admin.
//!
//! Rather than encoding both rules inside a single tag-enum-of-actions
//! checker, we build *two* checkers, each
//! [`PermissionChecker::named`]'d so traces in audit logs say
//! `checker.name = "DocumentListChecker"` vs
//! `"DocumentDetailChecker"`. Each checker has its own policy set; the
//! list checker is the OR of "is admin" / "is in workspace"; the detail
//! checker is the OR of "is admin" / "is owner" / "is shared with".
//!
//! Why two checkers rather than two actions on one checker:
//! - The policy sets are genuinely different. The list checker
//!   doesn't load per-item share-list facts; the detail checker
//!   does. Sharing one checker forces every policy to handle both
//!   actions and clutters the trace with `match action { ... }`
//!   no-op arms.
//! - Naming each checker means audit telemetry can route list-page
//!   evaluations and view-detail evaluations to different alerts. A
//!   spike of `DocumentDetailChecker` denials is a very different
//!   signal from a spike of `DocumentListChecker` denials.
//! - The `R` and `A` generics stay tight: each checker has one resource
//!   type and one action type, so policies don't need to branch on a
//!   `match action { ... }` arm.

use async_trait::async_trait;
use gatehouse::{AccessEvaluation, EvalCtx, PermissionChecker, Policy, PolicyEvalResult};
use std::borrow::Cow;
use uuid::Uuid;

/// The shared resource. Same type across both checkers, since both
/// authorize on documents.
#[derive(Debug, Clone)]
struct Document {
    #[allow(dead_code)] // Held for downstream use; not consulted by either checker.
    id: Uuid,
    workspace_id: Uuid,
    owner_id: Uuid,
    /// User IDs the document has been explicitly shared with.
    shared_with: Vec<Uuid>,
}

/// The actor making the call. Same across both checkers.
#[derive(Debug, Clone)]
struct User {
    id: Uuid,
    workspace_id: Uuid,
    is_admin: bool,
}

/// Action for the list scope.
#[derive(Debug, Clone)]
struct ListDocuments;

/// Action for the detail scope.
#[derive(Debug, Clone)]
struct ViewDetail;

#[derive(Debug, Clone)]
struct EmptyCtx;

// ----- List-scope policies ---------------------------------------------

/// Admin override that applies in the list scope.
struct AdminCanList;

#[async_trait]
impl Policy<User, Document, ListDocuments, EmptyCtx> for AdminCanList {
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, User, Document, ListDocuments, EmptyCtx>,
    ) -> PolicyEvalResult {
        if ctx.subject.is_admin {
            ctx.grant("admin override")
        } else {
            ctx.deny("not admin")
        }
    }
    fn policy_type(&self) -> Cow<'static, str> {
        Cow::Borrowed("AdminCanList")
    }
}

/// "Same workspace" rule — broad, cheap, no fact loading needed.
struct InSameWorkspace;

#[async_trait]
impl Policy<User, Document, ListDocuments, EmptyCtx> for InSameWorkspace {
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, User, Document, ListDocuments, EmptyCtx>,
    ) -> PolicyEvalResult {
        if ctx.subject.workspace_id == ctx.resource.workspace_id {
            ctx.grant("subject is in the document's workspace")
        } else {
            ctx.deny("workspace mismatch")
        }
    }
    fn policy_type(&self) -> Cow<'static, str> {
        Cow::Borrowed("InSameWorkspace")
    }
}

// ----- Detail-scope policies -------------------------------------------

/// Admin override for the detail scope. Different action type → different
/// impl, even though the body is identical.
struct AdminCanViewDetail;

#[async_trait]
impl Policy<User, Document, ViewDetail, EmptyCtx> for AdminCanViewDetail {
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, User, Document, ViewDetail, EmptyCtx>,
    ) -> PolicyEvalResult {
        if ctx.subject.is_admin {
            ctx.grant("admin override")
        } else {
            ctx.deny("not admin")
        }
    }
    fn policy_type(&self) -> Cow<'static, str> {
        Cow::Borrowed("AdminCanViewDetail")
    }
}

struct IsOwner;

#[async_trait]
impl Policy<User, Document, ViewDetail, EmptyCtx> for IsOwner {
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, User, Document, ViewDetail, EmptyCtx>,
    ) -> PolicyEvalResult {
        if ctx.subject.id == ctx.resource.owner_id {
            ctx.grant("subject is the document owner")
        } else {
            ctx.deny("subject is not the document owner")
        }
    }
    fn policy_type(&self) -> Cow<'static, str> {
        Cow::Borrowed("IsOwner")
    }
}

struct IsExplicitlyShared;

#[async_trait]
impl Policy<User, Document, ViewDetail, EmptyCtx> for IsExplicitlyShared {
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, User, Document, ViewDetail, EmptyCtx>,
    ) -> PolicyEvalResult {
        if ctx.resource.shared_with.contains(&ctx.subject.id) {
            ctx.grant("subject is on the document's share list")
        } else {
            ctx.deny("subject is not on the share list")
        }
    }
    fn policy_type(&self) -> Cow<'static, str> {
        Cow::Borrowed("IsExplicitlyShared")
    }
}

// ----- Builder functions returning the two named checkers --------------

fn build_list_checker() -> PermissionChecker<User, Document, ListDocuments, EmptyCtx> {
    let mut checker = PermissionChecker::named("DocumentListChecker");
    checker.add_policy(AdminCanList);
    checker.add_policy(InSameWorkspace);
    checker
}

fn build_detail_checker() -> PermissionChecker<User, Document, ViewDetail, EmptyCtx> {
    let mut checker = PermissionChecker::named("DocumentDetailChecker");
    checker.add_policy(AdminCanViewDetail);
    checker.add_policy(IsOwner);
    checker.add_policy(IsExplicitlyShared);
    checker
}

#[tokio::main]
async fn main() {
    let workspace = Uuid::new_v4();
    let alice = User {
        id: Uuid::new_v4(),
        workspace_id: workspace,
        is_admin: false,
    };
    let bob = User {
        id: Uuid::new_v4(),
        workspace_id: workspace,
        is_admin: false,
    };

    let doc_owned_by_alice = Document {
        id: Uuid::new_v4(),
        workspace_id: workspace,
        owner_id: alice.id,
        shared_with: vec![],
    };
    let doc_owned_by_alice_shared_to_bob = Document {
        id: Uuid::new_v4(),
        workspace_id: workspace,
        owner_id: alice.id,
        shared_with: vec![bob.id],
    };
    let doc_in_other_workspace = Document {
        id: Uuid::new_v4(),
        workspace_id: Uuid::new_v4(),
        owner_id: alice.id,
        shared_with: vec![],
    };

    let list_checker = build_list_checker();
    let detail_checker = build_detail_checker();

    // List endpoint: "what can Bob see in the index?" — filter the
    // candidate set with the named list checker. Stubs only need
    // workspace membership.
    let candidates = vec![
        doc_owned_by_alice.clone(),
        doc_owned_by_alice_shared_to_bob.clone(),
        doc_in_other_workspace.clone(),
    ];
    let visible = list_checker
        .filter_authorized_in_session_by_resource(
            gatehouse::EvaluationSession::shared_empty(),
            &bob,
            &ListDocuments,
            candidates,
            &EmptyCtx,
            |doc| doc,
        )
        .await;
    println!("List scope: bob sees {} document(s)", visible.len());
    assert_eq!(
        visible.len(),
        2,
        "bob is workspace-mate, not workspace-mate of the third doc"
    );

    // Detail endpoint: even though Bob *sees* both in-workspace docs in
    // the list, the detail checker is stricter. He can only open the
    // one he was explicitly shared on.
    let owned_detail = detail_checker
        .check(&bob, &ViewDetail, &doc_owned_by_alice, &EmptyCtx)
        .await;
    let shared_detail = detail_checker
        .check(
            &bob,
            &ViewDetail,
            &doc_owned_by_alice_shared_to_bob,
            &EmptyCtx,
        )
        .await;

    println!(
        "Detail scope: bob on alice's private doc → {}",
        if owned_detail.is_granted() {
            "granted"
        } else {
            "denied"
        },
    );
    println!(
        "Detail scope: bob on shared doc → {}",
        if shared_detail.is_granted() {
            "granted"
        } else {
            "denied"
        },
    );
    assert!(matches!(owned_detail, AccessEvaluation::Denied { .. }));
    assert!(shared_detail.is_granted());

    // The named checkers tag every evaluation, so audit pipelines can
    // tell which scope produced each decision even when the resource
    // and subject types are identical.
    assert_eq!(list_checker.name(), Some("DocumentListChecker"));
    assert_eq!(detail_checker.name(), Some("DocumentDetailChecker"));
}
