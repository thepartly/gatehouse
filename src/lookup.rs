//! Lookup-style enumeration for "what can this subject see?" authorization.
//!
//! The point-check API (`evaluate_in_session`) and the batch filter
//! (`filter_authorized_with_context_in_session_by`) both require the caller
//! to already hold every candidate resource. That breaks down for list and
//! scope endpoints where the candidate population may be millions of rows
//! and the visible subset is tiny.
//!
//! [`LookupSource`] solves this by enumerating a *candidate superset* of
//! resources the subject may have access to, page by page; the consuming
//! [`PermissionChecker`] hydrates each page and routes the hydrated
//! resources through the existing policy stack. The lookup step is strictly
//! a **narrowing** of candidates — every policy in the checker still runs
//! on the hydrated subset, so authorization is still centralized in
//! gatehouse rather than smeared into the source's query.
//!
//! See [`LookupSource`] for the completeness contract.
//!
//! [`PermissionChecker`]: crate::PermissionChecker

use async_trait::async_trait;
use std::fmt;
use std::future::Future;
use std::num::NonZeroUsize;

/// Enumerates a candidate superset of resources for a subject.
///
/// # Completeness contract
///
/// A `LookupSource` **must** enumerate a superset of every resource that any
/// policy in the consuming [`PermissionChecker`] could grant for `subject`.
/// Gatehouse uses lookup only to narrow the candidate set; it then runs the
/// full policy stack on the hydrated subset. **If the source omits a grant
/// path** — admin overrides, sharing relationships, global/public resources,
/// secondary roles — **the result is incomplete, not denied.** There is no
/// out-of-band signal that completeness was broken: the caller will simply
/// see fewer resources than they should.
///
/// In particular, [`PermissionChecker`] uses OR semantics across policies.
/// If you compose policies whose grant axes are independent (for example,
/// "I own it" OR "it is public" OR "the admin override applies"), the
/// `LookupSource` must enumerate the union of every axis. Lookup is the
/// scaling story for the narrow case where one axis dominates; it is
/// **not** a way to express policy logic inside the data layer.
///
/// # Cursor contract
///
/// `cursor` is opaque to gatehouse. Implementations may use any encoding
/// (offset, last-seen ID, base64 of internal state). The contract:
///
/// * `None` cursor means "start from the beginning."
/// * Return `next_cursor = None` to signal exhaustion.
/// * `next_cursor` must strictly advance: returning the same cursor that
///   was just consumed signals a stuck source and is reported by
///   gatehouse as a cursor-progress contract violation.
/// * `limit` is an upper bound on page size; pages may be shorter, but
///   shorter does not mean "exhausted" unless `next_cursor` is `None`.
///
/// # Fail-closed behavior
///
/// Returning `Err` aborts the consuming pipeline; gatehouse does not yield
/// partial results from the page.
///
/// [`PermissionChecker`]: crate::PermissionChecker
#[async_trait]
pub trait LookupSource: Send + Sync {
    /// The subject domain type the source enumerates against.
    type Subject: Sync + ?Sized;
    /// The ID type the source enumerates. The caller-provided
    /// [`Hydrator`] resolves these to resources.
    type Id: Send + Sync + Clone;
    /// Backend error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Return one page of candidate IDs.
    async fn lookup_page(
        &self,
        subject: &Self::Subject,
        cursor: Option<&[u8]>,
        limit: NonZeroUsize,
    ) -> Result<LookupPage<Self::Id>, Self::Error>;
}

/// One page of enumerated candidate IDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupPage<Id> {
    /// Candidate IDs in this page. Order is source-defined and preserved
    /// through hydration and authorization.
    pub ids: Vec<Id>,
    /// Opaque cursor for the next page, or `None` if this page is the
    /// last.
    pub next_cursor: Option<Vec<u8>>,
}

/// Resolves enumerated IDs to caller-owned resources.
///
/// Hydration is separated from lookup so the same `LookupSource` can drive
/// different resource shapes (summary vs. full row, with or without
/// joins). The hydrator returns one `Option<Resource>` per input ID **in
/// input order**:
///
/// * `Some(resource)` — the ID resolved.
/// * `None` — the ID was enumerated by the source but no longer resolves
///   (deleted between enumeration and hydration). Gatehouse skips
///   `None` entries before running policies; this is not an error.
///
/// Returning a vector of length other than `ids.len()` is a contract
/// violation and is reported by gatehouse as a hydrator contract error.
/// Returning `Err` aborts the consuming pipeline.
///
/// Like [`crate::FactSource`], a `Hydrator` is a natural place to call an
/// existing DataLoader-style batch loader (`async-graphql::dataloader`,
/// `ultra-batch`, or a home-grown batcher). The hydrator receives a
/// candidate-page slice of IDs and returns one `Option<Resource>` per ID —
/// exactly the shape a DataLoader's `load_many` returns. Gatehouse
/// authorizes the resolved subset through the existing policy stack; the
/// underlying loader owns request-wide batching and caching.
#[async_trait]
pub trait Hydrator<Id>: Send + Sync {
    /// The resource type produced by the hydrator.
    type Resource: Send;
    /// Backend error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Resolve `ids` to resources in input order. See trait docs for the
    /// `Option` and length contract.
    async fn hydrate(&self, ids: &[Id]) -> Result<Vec<Option<Self::Resource>>, Self::Error>;
}

/// Blanket implementation over closures, so callers can pass an `async`
/// function or a `move |ids| async move { ... }` block directly.
#[async_trait]
impl<F, Fut, Id, R, E> Hydrator<Id> for F
where
    F: Fn(&[Id]) -> Fut + Send + Sync,
    Fut: Future<Output = Result<Vec<Option<R>>, E>> + Send,
    Id: Send + Sync,
    R: Send,
    E: std::error::Error + Send + Sync + 'static,
{
    type Resource = R;
    type Error = E;

    async fn hydrate(&self, ids: &[Id]) -> Result<Vec<Option<Self::Resource>>, Self::Error> {
        self(ids).await
    }
}

/// Failure modes for [`PermissionChecker::lookup_authorized`] and
/// [`PermissionChecker::lookup_authorized_page`].
///
/// The generic parameters carry the source's and hydrator's own error
/// types, so callers retain full backend context on the wrapped variants.
///
/// [`PermissionChecker::lookup_authorized`]: crate::PermissionChecker::lookup_authorized
/// [`PermissionChecker::lookup_authorized_page`]: crate::PermissionChecker::lookup_authorized_page
#[derive(Debug)]
pub enum LookupAuthorizedError<LookupErr, HydrateErr> {
    /// The [`LookupSource`] returned an error for the current page.
    Lookup(LookupErr),
    /// The [`Hydrator`] returned an error for the current page.
    Hydrate(HydrateErr),
    /// The hydrator returned a `Vec<Option<_>>` whose length did not match
    /// the input ID slice length. Treated as fail-closed.
    HydratorContractViolation {
        /// Number of IDs that were passed to the hydrator.
        expected: usize,
        /// Number of `Option<Resource>` entries the hydrator returned.
        actual: usize,
    },
    /// The lookup source returned a `next_cursor` equal to the cursor that
    /// was just consumed, indicating zero progress. Gatehouse aborts
    /// rather than loop forever.
    LookupCursorStuck,
}

impl<L, H> fmt::Display for LookupAuthorizedError<L, H>
where
    L: fmt::Display,
    H: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lookup(err) => write!(f, "lookup source error: {err}"),
            Self::Hydrate(err) => write!(f, "hydrator error: {err}"),
            Self::HydratorContractViolation { expected, actual } => write!(
                f,
                "hydrator returned {actual} entries for {expected} ids; \
                 the result must match the input length"
            ),
            Self::LookupCursorStuck => f.write_str(
                "lookup source returned the same cursor twice in a row; \
                 cursors must strictly advance or be None to signal exhaustion",
            ),
        }
    }
}

impl<L, H> std::error::Error for LookupAuthorizedError<L, H>
where
    L: std::error::Error + 'static,
    H: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Lookup(err) => Some(err),
            Self::Hydrate(err) => Some(err),
            Self::HydratorContractViolation { .. } | Self::LookupCursorStuck => None,
        }
    }
}

/// One page of *authorized* resources, paired with the next candidate-page
/// cursor.
///
/// Note that `next_cursor` paginates the **candidate** stream, not the
/// authorized output. A `Some(cursor)` value with `resources.is_empty()`
/// is normal: the source enumerated more IDs but the policy stack denied
/// every one in that page. Continue paging until `next_cursor` is `None`.
#[derive(Debug)]
pub struct LookupAuthorizedPage<R> {
    /// Resources from this page that the full policy stack authorized,
    /// in source-defined order.
    pub resources: Vec<R>,
    /// Cursor for the next candidate page, or `None` if exhausted.
    pub next_cursor: Option<Vec<u8>>,
}
