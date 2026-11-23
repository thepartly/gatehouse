//! Scoped search: narrow in the data layer, then authorize the page.
//!
//! List and search endpoints usually cannot authorize every row in the
//! database, so the data layer narrows the candidates first. This example
//! shows the pattern and why the authorization step still runs afterwards:
//!
//! 1. The data layer narrows rows to a scope that is a subset of one policy
//!    grant arm (here: "comments in projects of the caller's tenant where
//!    the caller is a member").
//! 2. `try_filter` runs the `PermissionChecker` over the page. A scope bug
//!    that returns too much is refused rather than leaked.
//! 3. An indeterminate decision (a fact load failure) fails the request
//!    with a `FilterError` instead of silently shortening the page.
//! 4. Many comments share one project, so the page is deduplicated to its
//!    distinct projects. Each project is evaluated once, and the comments
//!    whose project was granted are kept.
//!
//! Domain: a project tracker. Tenants own projects, projects have members,
//! and comments belong to a project.
//!
//! Membership is loaded through a batched `FactSource`. The scope functions
//! below stand in for SQL and the store is in memory, so the example needs
//! no database.
//!
//! Run with:
//!
//! ```text
//! cargo run --example scoped_search
//! ```

use async_trait::async_trait;
use gatehouse::{
    BatchEvalCtx, EvalCtx, FactKey, FactLoadError, FactLoadResult, FactRegistry, GrantResult,
    PermissionChecker, Policy, PolicyDomain,
};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

// --- Domain ------------------------------------------------------------

type TenantId = u32;
type UserId = u32;
type ProjectId = u32;

#[derive(Clone, Debug)]
struct Caller {
    user_id: UserId,
    tenant_id: TenantId,
}

/// The authorization resource: the project a comment lives in.
#[derive(Clone, Debug)]
struct Project {
    id: ProjectId,
    tenant_id: TenantId,
}

/// A wide row from the search query. Authorization looks only at `project`.
#[derive(Clone, Debug)]
struct CommentRow {
    id: u32,
    project: Project,
}

#[derive(Clone, Debug)]
struct ReadComments;

struct ProjectDomain;

impl PolicyDomain for ProjectDomain {
    type Subject = Caller;
    type Action = ReadComments;
    type Resource = Project;
    type Context = ();
}

// --- Facts -------------------------------------------------------------

/// "Is this user a member of this project?"
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct ProjectMembership {
    user_id: UserId,
    project_id: ProjectId,
}

impl FactKey for ProjectMembership {
    const NAME: &'static str = "project_membership";
    type Value = bool;
}

/// In-memory stand-in for the `project_members` table.
///
/// `load_many` stands for one batched query:
///
/// ```sql
/// SELECT EXISTS (
///     SELECT 1 FROM project_members
///     WHERE user_id = k.user_id AND project_id = k.project_id
/// )
/// FROM unnest($1::int[], $2::int[]) WITH ORDINALITY AS k(user_id, project_id, ord)
/// ORDER BY k.ord
/// ```
struct MembershipSource {
    members: HashSet<(UserId, ProjectId)>,
    /// Simulates a backend outage.
    fail: Arc<AtomicBool>,
    /// Records the keys of every `load_many` call.
    calls: Arc<Mutex<Vec<Vec<ProjectMembership>>>>,
}

#[async_trait]
impl gatehouse::FactSource<ProjectMembership> for MembershipSource {
    async fn load_many(&self, keys: &[ProjectMembership]) -> Vec<FactLoadResult<bool>> {
        self.calls.lock().unwrap().push(keys.to_vec());
        keys.iter()
            .map(|key| {
                if self.fail.load(Ordering::SeqCst) {
                    FactLoadResult::Error(FactLoadError::backend_with_message(
                        "membership lookup failed",
                        Unavailable,
                    ))
                } else {
                    FactLoadResult::Found(self.members.contains(&(key.user_id, key.project_id)))
                }
            })
            .collect()
    }
}

#[derive(Debug)]
struct Unavailable;
impl fmt::Display for Unavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("backend unavailable")
    }
}
impl std::error::Error for Unavailable {}

// --- Policy ------------------------------------------------------------

/// What the policy decided for one project, before it becomes a `GrantResult`.
enum Decision {
    Grant(&'static str),
    Abstain(&'static str),
    /// An input the decision needs could not be loaded.
    Undecided(&'static str),
}

impl Decision {
    fn into_result(self, ctx: &EvalCtx<'_, ProjectDomain>) -> GrantResult {
        match self {
            Self::Grant(reason) => ctx.grant(reason),
            Self::Abstain(reason) => ctx.not_applicable(reason),
            Self::Undecided(reason) => ctx.indeterminate(reason),
        }
    }

    fn into_batch_result(self) -> GrantResult {
        match self {
            Self::Grant(reason) => {
                GrantResult::granted("ProjectMemberPolicy", Some(reason.to_owned()))
            }
            Self::Abstain(reason) => GrantResult::not_applicable("ProjectMemberPolicy", reason),
            Self::Undecided(reason) => GrantResult::indeterminate("ProjectMemberPolicy", reason),
        }
    }
}

/// Grants reading a project's comments to its members, within the caller's
/// own tenant. Membership in a project of another tenant grants nothing.
///
/// A membership load failure is `Undecided`, which becomes an indeterminate
/// result, so `try_filter` fails the request. `evaluate` checks the tenant
/// before loading membership. `evaluate_batch` loads one membership key per
/// project through a single `facts_by` call; without it, each project would
/// be a separate source call.
struct ProjectMemberPolicy;

impl ProjectMemberPolicy {
    fn membership_key(caller: &Caller, project: &Project) -> ProjectMembership {
        ProjectMembership {
            user_id: caller.user_id,
            project_id: project.id,
        }
    }

    /// Abstains for a project of another tenant; `None` means the tenant
    /// matches and membership decides.
    fn tenant_mismatch(caller: &Caller, project: &Project) -> Option<Decision> {
        (project.tenant_id != caller.tenant_id)
            .then_some(Decision::Abstain("project belongs to another tenant"))
    }

    fn membership_decision(membership: &FactLoadResult<bool>) -> Decision {
        match membership {
            FactLoadResult::Found(true) => Decision::Grant("member of the project"),
            FactLoadResult::Found(false) | FactLoadResult::Missing => {
                Decision::Abstain("not a member of the project")
            }
            FactLoadResult::Error(_) => Decision::Undecided("membership could not be loaded"),
            _ => Decision::Undecided("unrecognised membership load result"),
        }
    }
}

#[async_trait]
impl Policy<ProjectDomain> for ProjectMemberPolicy {
    async fn evaluate(&self, ctx: &EvalCtx<'_, ProjectDomain>) -> GrantResult {
        if let Some(decision) = Self::tenant_mismatch(ctx.subject, ctx.resource) {
            return decision.into_result(ctx);
        }
        let membership = ctx
            .fact(Self::membership_key(ctx.subject, ctx.resource))
            .await;
        Self::membership_decision(&membership).into_result(ctx)
    }

    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, ProjectDomain>,
    ) -> Vec<GrantResult> {
        let memberships = ctx
            .facts_by(|project| Self::membership_key(ctx.subject, project))
            .await;
        ctx.items
            .iter()
            .zip(&memberships)
            .map(|(item, membership)| {
                Self::tenant_mismatch(ctx.subject, item.resource)
                    .unwrap_or_else(|| Self::membership_decision(membership))
                    .into_batch_result()
            })
            .collect()
    }

    fn policy_type(&self) -> Cow<'static, str> {
        Cow::Borrowed("ProjectMemberPolicy")
    }
}

// --- Data layer --------------------------------------------------------

struct Store {
    comments: Vec<CommentRow>,
    members: HashSet<(UserId, ProjectId)>,
}

impl Store {
    /// Correct scope: comments in projects of the caller's tenant where the
    /// caller is a member. This is a subset of what `ProjectMemberPolicy`
    /// grants.
    ///
    /// ```sql
    /// SELECT c.* FROM comments c
    /// JOIN projects p ON p.id = c.project_id
    /// JOIN project_members m ON m.project_id = p.id AND m.user_id = $user
    /// WHERE p.tenant_id = $tenant
    /// ORDER BY c.id
    /// ```
    fn scope_correct(&self, caller: &Caller) -> Vec<CommentRow> {
        self.comments
            .iter()
            .filter(|row| {
                row.project.tenant_id == caller.tenant_id
                    && self.members.contains(&(caller.user_id, row.project.id))
            })
            .cloned()
            .collect()
    }

    /// Buggy scope: the tenant predicate was forgotten.
    ///
    /// ```sql
    /// SELECT c.* FROM comments c
    /// JOIN project_members m ON m.project_id = c.project_id AND m.user_id = $user
    /// ORDER BY c.id
    /// ```
    fn scope_missing_tenant(&self, caller: &Caller) -> Vec<CommentRow> {
        self.comments
            .iter()
            .filter(|row| self.members.contains(&(caller.user_id, row.project.id)))
            .cloned()
            .collect()
    }
}

// --- Authorizing a page ------------------------------------------------

/// Authorizes a page of comment rows, evaluating each distinct project once.
///
/// Returns an error if any project's decision is indeterminate. The page is
/// never returned shortened.
async fn authorize_page(
    checker: &PermissionChecker<ProjectDomain>,
    registry: &FactRegistry,
    caller: &Caller,
    rows: Vec<CommentRow>,
) -> Result<Vec<CommentRow>, gatehouse::FilterError<Project>> {
    let distinct_projects: BTreeMap<ProjectId, Project> = rows
        .iter()
        .map(|row| (row.project.id, row.project.clone()))
        .collect();

    // A fresh session per request: permission changes are seen by the next one.
    let session = registry.session();
    let granted_projects: BTreeSet<ProjectId> = checker
        .bind(&session, caller, &ReadComments, &())
        .try_filter(distinct_projects.into_values())
        .await?
        .into_iter()
        .map(|project| project.id)
        .collect();

    Ok(rows
        .into_iter()
        .filter(|row| granted_projects.contains(&row.project.id))
        .collect())
}

fn ids(rows: &[CommentRow]) -> Vec<u32> {
    rows.iter().map(|row| row.id).collect()
}

// --- Wiring + main -----------------------------------------------------

#[tokio::main]
async fn main() {
    const ACME: TenantId = 1;
    const GLOBEX: TenantId = 2;
    let alice = Caller {
        user_id: 1,
        tenant_id: ACME,
    };

    let project = |id, tenant_id| Project { id, tenant_id };
    let apollo = project(10, ACME);
    let borealis = project(11, ACME);
    let confidential = project(12, ACME); // alice is not a member
    let other_tenant = project(20, GLOBEX); // alice has a stale membership row

    // Comments 1-6 in apollo, 7-8 in borealis, 9-10 in confidential,
    // 11-12 in the other tenant's project.
    let comments: Vec<CommentRow> = [
        (1..=6, &apollo),
        (7..=8, &borealis),
        (9..=10, &confidential),
        (11..=12, &other_tenant),
    ]
    .into_iter()
    .flat_map(|(range, project)| {
        range.map(|id| CommentRow {
            id,
            project: project.clone(),
        })
    })
    .collect();

    let members: HashSet<(UserId, ProjectId)> = [
        (alice.user_id, apollo.id),
        (alice.user_id, borealis.id),
        (alice.user_id, other_tenant.id),
    ]
    .into_iter()
    .collect();

    let store = Store {
        comments,
        members: members.clone(),
    };

    let fail = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let registry = FactRegistry::builder()
        .with::<ProjectMembership, _>(MembershipSource {
            members,
            fail: Arc::clone(&fail),
            calls: Arc::clone(&calls),
        })
        .build();

    let mut checker = PermissionChecker::<ProjectDomain>::new();
    checker.add_policy(ProjectMemberPolicy);

    // (1) Correct scope: every row is granted. Eight rows in two projects
    // cost two membership keys in a single batched load.
    let page = authorize_page(&checker, &registry, &alice, store.scope_correct(&alice))
        .await
        .expect("authorization must complete");
    println!("[correct scope] returned {:?}", ids(&page));
    assert_eq!(ids(&page), (1..=8).collect::<Vec<_>>());
    {
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "one batched load for the whole page");
        assert_eq!(
            calls[0].len(),
            2,
            "one key per distinct project, not per row"
        );
    }

    // (2) Buggy scope: the tenant predicate is missing, so the data layer
    // also returns the other tenant's comments. The policy layer refuses them.
    let leaked_candidates = store.scope_missing_tenant(&alice);
    println!(
        "[buggy scope]   data layer returned {:?}",
        ids(&leaked_candidates)
    );
    assert!(
        ids(&leaked_candidates).contains(&11),
        "the buggy scope must leak a row for this demonstration"
    );
    let page = authorize_page(&checker, &registry, &alice, leaked_candidates)
        .await
        .expect("authorization must complete");
    println!("[buggy scope]   after policy filter {:?}", ids(&page));
    assert_eq!(
        ids(&page),
        (1..=8).collect::<Vec<_>>(),
        "rows from the other tenant must not survive the policy layer"
    );

    // (3) A fact load failure is indeterminate. The request fails instead of
    // returning a page with the unresolved projects dropped.
    fail.store(true, Ordering::SeqCst);
    let outcome = authorize_page(&checker, &registry, &alice, store.scope_correct(&alice)).await;
    match &outcome {
        Err(error) => {
            let unresolved: Vec<ProjectId> = error
                .indeterminate()
                .map(|(project, _)| project.id)
                .collect();
            println!("[outage]        request failed: {error}; unresolved projects {unresolved:?}");
            assert_eq!(unresolved, vec![apollo.id, borealis.id]);
        }
        Ok(page) => panic!("an outage must not produce a page, got {:?}", ids(page)),
    }
}
