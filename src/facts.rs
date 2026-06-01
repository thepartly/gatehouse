use async_trait::async_trait;
use std::fmt;
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::sync::Arc;

/// A typed fact key that can be loaded through an [`crate::EvaluationSession`].
///
/// Keys are flat, cloneable, and hashable so the session can deduplicate and
/// cache fact loads for the lifetime of a single [`crate::EvaluationSession`].
///
/// Caching is scoped to that session, not the process. Gatehouse has no
/// built-in notion of a "request"; the caller decides how long a session lives
/// and, by convention, scopes it to one authorization pass (for an HTTP
/// service, typically one inbound request). Cached facts and cached errors are
/// dropped when the session is dropped, so permission revocations or backend
/// changes are observed by the next session rather than being held in a
/// process-global cache.
pub trait FactKey: Eq + Hash + Clone + Send + Sync + 'static {
    /// The value returned by a [`FactSource`] for this key.
    type Value: Clone + Send + Sync + 'static;

    /// Stable fact name used only in diagnostics and tracing.
    ///
    /// The session registry is keyed by [`std::any::TypeId`], not by this name, so two
    /// unrelated key types with the same name do not share a source or cache.
    const NAME: &'static str;
}

/// Private error type backing [`FactLoadError::backend_message`], so callers
/// can wrap a human-readable message without defining their own error type.
#[derive(Debug)]
struct MessageError(String);

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for MessageError {}

/// Error raised while loading a fact.
#[derive(Debug, Clone)]
pub enum FactLoadError {
    /// No source is registered for the requested fact key type.
    SourceNotRegistered {
        /// Diagnostic fact name from [`FactKey::NAME`].
        fact_name: &'static str,
    },
    /// A source violated the one-result-per-input-key contract.
    SourceContractViolation {
        /// Diagnostic fact name from [`FactKey::NAME`].
        fact_name: &'static str,
        /// Number of keys passed to the source.
        expected: usize,
        /// Number of results returned by the source.
        actual: usize,
    },
    /// The future driving a fact load was dropped before the load completed.
    ///
    /// When several evaluations await the same key, one of them drives the load
    /// and the others wait on its result. If that driving future is cancelled —
    /// for example, the surrounding request times out and its future is
    /// dropped — the load is reported as cancelled. The session caches this
    /// error for the affected keys and wakes any waiters, so the evaluation
    /// fails closed and the next session retries from scratch. For this reason a
    /// fact-loaded session should not be shared across independent requests: a
    /// cancellation in one would surface here for the others.
    LoaderCancelled {
        /// Diagnostic fact name from [`FactKey::NAME`].
        fact_name: &'static str,
    },
    /// The registered source reported a backend error.
    ///
    /// Backend errors are held behind [`Arc`], so cloned
    /// [`FactLoadResult::Error`] values share the same error object rather than
    /// requiring the backend error type itself to be cloneable.
    Backend(Arc<dyn std::error::Error + Send + Sync>),
}

impl FactLoadError {
    /// Wraps a backend error.
    pub fn backend(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Backend(Arc::new(error))
    }

    /// Wraps a human-readable backend error message.
    pub fn backend_message(message: impl Into<String>) -> Self {
        Self::backend(MessageError(message.into()))
    }
}

impl fmt::Display for FactLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceNotRegistered { fact_name } => {
                write!(f, "No fact source registered for '{fact_name}'")
            }
            Self::SourceContractViolation {
                fact_name,
                expected,
                actual,
            } => write!(
                f,
                "Fact source '{fact_name}' returned {actual} results for {expected} keys"
            ),
            Self::LoaderCancelled { fact_name } => {
                write!(f, "Fact load for '{fact_name}' was cancelled")
            }
            Self::Backend(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for FactLoadError {}

/// Result of loading one fact.
///
/// This is shaped like `Result<Option<V>, FactLoadError>` — `Found`, `Missing`,
/// and `Error` map onto `Ok(Some)`, `Ok(None)`, and `Err`. A dedicated enum is
/// used instead so the three outcomes read as domain concepts at policy call
/// sites (`FactLoadResult::Missing` rather than `Ok(None)`), so "the fact does
/// not exist" is never visually conflated with "the load failed" — a
/// distinction that matters for fail-closed authorization — and so the type can
/// gain variants later without breaking a `Result` alias callers rely on.
#[derive(Debug, Clone)]
pub enum FactLoadResult<V> {
    /// The fact exists and has the given value.
    Found(V),
    /// The fact source was reached, but no value exists for the key.
    Missing,
    /// Loading failed. Policies should map this to a denied decision.
    Error(FactLoadError),
}

/// A batched source for one fact key type.
///
/// Sources can be shared across many request sessions. The source owns
/// backend-specific serialization and I/O; the session owns per-request
/// deduplication, caching, chunking, and in-flight coalescing.
///
/// `FactSource` is gatehouse's request-scoped DataLoader-style primitive:
/// the session deduplicates inputs, holds a per-session cache, and joins
/// concurrent in-flight loads for the same key, then hands one or more
/// unique-key slices to [`Self::load_many`] (chunked by
/// [`Self::max_batch_size`]). If your application already runs a
/// DataLoader implementation — `async_graphql::dataloader` (from the
/// `async-graphql` crate), the `ultra-batch` crate, or any home-grown
/// batcher — call it directly from inside `load_many`. The two layers
/// compose: gatehouse owns the per-request fact graph for one
/// authorization pass; the underlying loader owns batching across the rest
/// of the request, request coalescing across many concurrent passes, and
/// any longer-lived caching.
///
/// # Beyond relationship facts: `(subject, scope) → resolved-id` lookups
///
/// `FactSource` is not relationship-shaped. Any per-request lookup whose
/// answer is fixed for the request — "what customer does this org map to",
/// "what tenant config applies to this caller", "what billing plan is in
/// force right now" — can be a fact key. Define a [`FactKey`] for the
/// question, register a source that resolves it, and have the policy ask
/// the session instead of calling the backing service directly. The session
/// then guarantees one round trip per unique key per request, regardless of
/// how many policies or items in a list endpoint consult it.
///
/// ```rust,ignore
/// use async_trait::async_trait;
/// use gatehouse::{FactKey, FactLoadResult, FactSource};
///
/// /// "Which customer is this org billed under?" — same answer for every
/// /// item in a list-of-invoices request.
/// #[derive(Debug, Clone, Hash, PartialEq, Eq)]
/// struct CustomerForOrg(uuid::Uuid);
///
/// impl FactKey for CustomerForOrg {
///     const NAME: &'static str = "customer_for_org";
///     type Value = Option<uuid::Uuid>;
/// }
///
/// struct HierarchyFacts(/* Arc<dyn HierarchyService> */);
///
/// #[async_trait]
/// impl FactSource<CustomerForOrg> for HierarchyFacts {
///     async fn load_many(
///         &self,
///         keys: &[CustomerForOrg],
///     ) -> Vec<FactLoadResult<Option<uuid::Uuid>>> {
///         // One backend call covering every unique org in the batch.
///         // Return one result per input key, in input order.
///         keys.iter()
///             .map(|_| FactLoadResult::Found(None))  // resolve from backend
///             .collect()
///     }
/// }
/// ```
///
/// Inside the policy, the canonical pattern is:
///
/// ```rust,ignore
/// async fn evaluate(
///     &self,
///     ctx: &EvalCtx<'_, OrgAuth, Invoice, Read, ()>,
/// ) -> PolicyEvalResult {
///     match ctx.session.get(CustomerForOrg(ctx.subject.org_id)).await {
///         FactLoadResult::Found(Some(customer_id)) if customer_id == ctx.resource.customer_id => {
///             ctx.grant("subject's org bills under the invoice's customer")
///         }
///         _ => ctx.deny("not the billing customer"),
///     }
/// }
/// ```
///
/// The built-in [`RebacPolicy`](crate::RebacPolicy) generalises this idiom
/// for relationship-shaped facts; the same plumbing handles arbitrary
/// `(subject, scope) → value` lookups when you define your own key.
#[async_trait]
pub trait FactSource<K>: Send + Sync
where
    K: FactKey,
{
    /// Loads one result per key, in input order.
    ///
    /// The session deduplicates before calling a source, so `keys` are unique
    /// within each call. Implementations must return exactly one
    /// [`FactLoadResult`] per input key, in the same order. The session expands
    /// results back to caller-visible order, including duplicate keys.
    async fn load_many(&self, keys: &[K]) -> Vec<FactLoadResult<K::Value>>;

    /// Maximum number of keys this source wants to load in one call.
    fn max_batch_size(&self) -> Option<NonZeroUsize> {
        None
    }
}

/// Error returned by non-panicking fact-source registration helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactSourceRegistrationError {
    /// The session is the process-wide empty session and cannot accept sources.
    SharedEmptySession {
        /// Diagnostic fact name from [`FactKey::NAME`].
        fact_name: &'static str,
    },
    /// A source is already registered for this exact fact key type.
    AlreadyRegistered {
        /// Diagnostic fact name from [`FactKey::NAME`].
        fact_name: &'static str,
    },
    /// Loads for this fact key type are currently in flight.
    InFlight {
        /// Diagnostic fact name from [`FactKey::NAME`].
        fact_name: &'static str,
    },
}

impl fmt::Display for FactSourceRegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SharedEmptySession { .. } => write!(
                f,
                "EvaluationSession::shared_empty() cannot register fact sources; use EvaluationSession::new() or EvaluationSession::builder()",
            ),
            Self::AlreadyRegistered { fact_name } => write!(
                f,
                "fact source for '{fact_name}' is already registered; use replace or replace_arc to overwrite it",
            ),
            Self::InFlight { .. } => write!(
                f,
                "fact sources should not be registered or replaced while loads for the same key type are in flight",
            ),
        }
    }
}

impl std::error::Error for FactSourceRegistrationError {}

/// Canonical fact key for relationship (ReBAC) lookups.
///
/// A `RelationshipQuery` encodes one yes/no question: does `subject_id` have
/// `relation` to `resource_id`? It is the [`FactKey`] used by the built-in
/// [`crate::RebacPolicy`], with [`FactKey::Value`] = `bool` — a registered
/// [`FactSource`] answers `true` when the relationship exists and `false`
/// otherwise.
///
/// The three identifier types are generic so callers can use their own
/// strongly-typed ids and relation enums rather than stringly-typed keys.
/// Because the session registry is keyed by the concrete Rust type (see
/// [`crate::EvaluationSession`]), two logically distinct relationship graphs
/// that share the same `RelationshipQuery<…>` instantiation resolve to the same
/// source; give them distinct id or relation types if they must be backed
/// separately.
///
/// For relationships that carry a payload (a rank, weight, or scope set) rather
/// than a plain boolean, define a custom [`FactKey`] with `Value =
/// YourPayload` instead of using this type.
///
/// # Example
///
/// ```rust
/// # use gatehouse::RelationshipQuery;
/// #[derive(Clone, PartialEq, Eq, Hash, Debug)]
/// enum Relation {
///     Owner,
///     Viewer,
/// }
///
/// let query = RelationshipQuery {
///     subject_id: "user:42".to_string(),
///     resource_id: "doc:7".to_string(),
///     relation: Relation::Owner,
/// };
/// assert_eq!(query.relation, Relation::Owner);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelationshipQuery<SubjectId, ResourceId, Relation> {
    /// Subject identifier.
    pub subject_id: SubjectId,
    /// Resource identifier.
    pub resource_id: ResourceId,
    /// Relationship being checked.
    pub relation: Relation,
}

impl<SubjectId, ResourceId, Relation> FactKey for RelationshipQuery<SubjectId, ResourceId, Relation>
where
    SubjectId: Eq + Hash + Clone + Send + Sync + 'static,
    ResourceId: Eq + Hash + Clone + Send + Sync + 'static,
    Relation: Eq + Hash + Clone + Send + Sync + 'static,
{
    type Value = bool;

    const NAME: &'static str = "relationship";
}
