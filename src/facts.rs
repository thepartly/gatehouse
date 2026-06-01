use async_trait::async_trait;
use std::fmt;
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::sync::Arc;

/// A typed fact key that can be loaded through an [`crate::EvaluationSession`].
///
/// Keys are flat, cloneable, and hashable so the session can deduplicate and
/// cache fact loads for the lifetime of one authorization request.
///
/// Session caching is deliberately request-scoped. Cached facts and cached
/// errors are dropped with the [`crate::EvaluationSession`], so permission revocations
/// or backend changes are observed by the next request's session rather than
/// being held in a process-global cache.
pub trait FactKey: Eq + Hash + Clone + Send + Sync + 'static {
    /// The value returned by a [`FactSource`] for this key.
    type Value: Clone + Send + Sync + 'static;

    /// Stable fact name used only in diagnostics and tracing.
    ///
    /// The session registry is keyed by [`std::any::TypeId`], not by this name, so two
    /// unrelated key types with the same name do not share a source or cache.
    const NAME: &'static str;
}

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
    /// The leader task for a fact load was cancelled before it completed.
    ///
    /// The session caches this error for the affected keys and wakes any
    /// waiters. This is correct for request-scoped sessions: the request fails
    /// closed and the next request builds a fresh session. Do not share a
    /// fact-loaded session across independent requests, because cancellation in
    /// one request would cache this error for the others.
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

/// Canonical ReBAC fact key.
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
