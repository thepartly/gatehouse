//! A flexible authorization library that combines role‐based (RBAC),
//! attribute‐based (ABAC), and relationship‐based (ReBAC) policies.
//! The library provides a generic `Policy` trait for defining custom policies,
//! a builder pattern for creating custom policies as well as several built-in
//! policies for common use cases, and combinators for composing complex
//! authorization logic.
//!
//! # Overview
//!
//! A *Policy* is an asynchronous decision unit that checks if a given subject may
//! perform an action on a resource within a given context. Policies implement the
//! [`Policy`] trait. A [`PermissionChecker`] aggregates multiple policies and uses OR
//! logic by default (i.e. if any policy grants access, then access is allowed).
//! The [`PolicyBuilder`] offers a builder pattern for creating custom policies.
//! Custom [`Policy`] implementations must provide both [`Policy::evaluate`]
//! and [`Policy::policy_type`].
//!
//! ## Decision Semantics
//!
//! `gatehouse` deliberately keeps decision semantics simple and explicit:
//!
//! - [`PermissionChecker`] evaluates policies sequentially with OR semantics and
//!   short-circuits on the first grant.
//! - An empty [`PermissionChecker`] denies access with the reason
//!   `"No policies configured"`.
//! - [`AndPolicy`] short-circuits on the first denial.
//! - [`OrPolicy`] short-circuits on the first grant.
//! - [`NotPolicy`] inverts the decision of its inner policy.
//! - [`PolicyBuilder`] combines all configured predicates with AND logic.
//! - [`PolicyBuilder::effect`] changes the result returned by that specific
//!   built policy when its combined predicate matches. A non-match is still
//!   treated as denied/non-applicable, and the effect does not create global
//!   deny-overrides-allow semantics when used inside [`PermissionChecker`].
//!
//! Denials from [`AccessEvaluation`] are intentionally summary-level. For example,
//! a failed [`PermissionChecker`] returns the top-level reason
//! `"All policies denied access"`. Use the attached [`EvalTrace`] to inspect the
//! individual policy reasons that led to that outcome.
//!
//! ## Trace Semantics
//!
//! [`EvalTrace`] records the policies and combinator branches that were actually
//! evaluated. Because [`PermissionChecker`], [`AndPolicy`], and [`OrPolicy`]
//! short-circuit, the trace tree does not include policies that were never run.
//!
//! ## Quick Start
//!
//! The fastest way to define a policy is with [`PolicyBuilder`]:
//!
//! ```rust
//! # use gatehouse::*;
//! #[derive(Debug, Clone)]
//! struct User { roles: Vec<String> }
//! #[derive(Debug, Clone)]
//! struct Document;
//! #[derive(Debug, Clone)]
//! struct ReadAction;
//! #[derive(Debug, Clone)]
//! struct AppContext;
//!
//! let policy = PolicyBuilder::<User, Document, ReadAction, AppContext>::new("AdminOnly")
//!     .subjects(|user: &User| user.roles.iter().any(|r| r == "admin"))
//!     .build();
//!
//! let mut checker = PermissionChecker::new();
//! checker.add_policy(policy);
//!
//! # tokio_test::block_on(async {
//! let session = EvaluationSession::empty();
//! let admin = User { roles: vec!["admin".into()] };
//! assert!(checker.evaluate_in_session(&session, &admin, &ReadAction, &Document, &AppContext).await.is_granted());
//!
//! let guest = User { roles: vec!["guest".into()] };
//! assert!(!checker.evaluate_in_session(&session, &guest, &ReadAction, &Document, &AppContext).await.is_granted());
//! # });
//! ```
//!
//! ## Built-in Policies
//!
//! The library provides several built-in policies:
//!  - [`RbacPolicy`]: A role-based access control policy.
//!  - [`AbacPolicy`]: An attribute-based access control policy.
//!  - [`RebacPolicy`]: A relationship-based access control policy.
//!
//! ## Custom Policies
//!
//! For full control, implement the [`Policy`] trait directly. Below we define a simple
//! system where a user may read a document if they are an admin (via a role-based policy)
//! or if they are the owner of the document (via an attribute-based policy).
//!
//! ```rust
//! # use uuid::Uuid;
//! # use async_trait::async_trait;
//! # use std::sync::Arc;
//! # use gatehouse::*;
//!
//! // Define our core types.
//! #[derive(Debug, Clone)]
//! pub struct User {
//!     pub id: Uuid,
//!     pub roles: Vec<String>,
//! }
//!
//! #[derive(Debug, Clone)]
//! pub struct Document {
//!     pub id: Uuid,
//!     pub owner_id: Uuid,
//! }
//!
//! #[derive(Debug, Clone)]
//! pub struct ReadAction;
//!
//! #[derive(Debug, Clone)]
//! pub struct EmptyContext;
//!
//! // A simple RBAC policy: grant access if the user has the "admin" role.
//! struct AdminPolicy;
//! #[async_trait]
//! impl Policy<User, Document, ReadAction, EmptyContext> for AdminPolicy {
//!     async fn evaluate(&self, ctx: &EvalCtx<'_, User, Document, ReadAction, EmptyContext>) -> PolicyEvalResult {
//!         if ctx.subject.roles.contains(&"admin".to_string()) {
//!             PolicyEvalResult::Granted {
//!                 policy_type: self.policy_type().to_string(),
//!                 reason: Some("User is admin".to_string()),
//!             }
//!         } else {
//!             PolicyEvalResult::Denied {
//!                 policy_type: self.policy_type().to_string(),
//!                 reason: "User is not admin".to_string(),
//!             }
//!         }
//!     }
//!     fn policy_type(&self) -> &str { "AdminPolicy" }
//! }
//!
//! // An ABAC policy: grant access if the user is the owner of the document.
//! struct OwnerPolicy;
//!
//! #[async_trait]
//! impl Policy<User, Document, ReadAction, EmptyContext> for OwnerPolicy {
//!     async fn evaluate(&self, ctx: &EvalCtx<'_, User, Document, ReadAction, EmptyContext>) -> PolicyEvalResult {
//!         if ctx.subject.id == ctx.resource.owner_id {
//!             PolicyEvalResult::Granted {
//!                 policy_type: self.policy_type().to_string(),
//!                 reason: Some("User is the owner".to_string()),
//!             }
//!         } else {
//!             PolicyEvalResult::Denied {
//!                policy_type: self.policy_type().to_string(),
//!                reason: "User is not the owner".to_string(),
//!            }
//!         }
//!     }
//!     fn policy_type(&self) -> &str {
//!         "OwnerPolicy"
//!     }
//! }
//!
//! // Create a PermissionChecker (which uses OR semantics by default) and add both policies.
//! fn create_document_checker() -> PermissionChecker<User, Document, ReadAction, EmptyContext> {
//!     let mut checker = PermissionChecker::new();
//!     checker.add_policy(AdminPolicy);
//!     checker.add_policy(OwnerPolicy);
//!     checker
//! }
//!
//! # tokio_test::block_on(async {
//! let admin_user = User {
//!     id: Uuid::new_v4(),
//!     roles: vec!["admin".into()],
//! };
//!
//! let owner_user = User {
//!     id: Uuid::new_v4(),
//!     roles: vec!["user".into()],
//! };
//!
//! let document = Document {
//!     id: Uuid::new_v4(),
//!     owner_id: owner_user.id,
//! };
//!
//! let checker = create_document_checker();
//! let session = EvaluationSession::empty();
//!
//! // An admin should have access.
//! assert!(checker.evaluate_in_session(&session, &admin_user, &ReadAction, &document, &EmptyContext).await.is_granted());
//!
//! // The owner should have access.
//! assert!(checker.evaluate_in_session(&session, &owner_user, &ReadAction, &document, &EmptyContext).await.is_granted());
//!
//! // A random user should be denied access.
//! let random_user = User {
//!     id: Uuid::new_v4(),
//!     roles: vec!["user".into()],
//! };
//! assert!(!checker.evaluate_in_session(&session, &random_user, &ReadAction, &document, &EmptyContext).await.is_granted());
//! # });
//! ```
//!
//! ## Evaluation Tracing
//!
//! The permission system provides detailed tracing of policy decisions, see [`AccessEvaluation`]
//! for an example.
//!
//! ## Tracing And Telemetry
//!
//! When trace-level events are enabled, [`PermissionChecker::evaluate_in_session`]
//! creates an instrumented span and each evaluated policy records a `trace!`
//! event on the `gatehouse::security` target. Batch evaluation records
//! aggregate item counts on [`PermissionChecker::evaluate_batch_in_session_by`]
//! and per-policy counts on nested `gatehouse.batch_policy` spans.
//!
//! Emitted fields:
//!
//! - `security_rule.name`
//! - `security_rule.category`
//! - `security_rule.description`
//! - `security_rule.reference`
//! - `security_rule.ruleset.name`
//! - `security_rule.uuid`
//! - `security_rule.version`
//! - `security_rule.license`
//! - `event.outcome`
//! - `policy.type`
//! - `policy.result.reason`
//!
//! When [`Policy::security_rule`] is not overridden, tracing falls back to:
//!
//! - `security_rule.name = policy_type()`
//! - `security_rule.category = "Access Control"`
//! - `security_rule.ruleset.name = "PermissionChecker"`
//!
//! ## Combinators
//!
//! Sometimes you may want to require that several policies pass (AND), require that
//! at least one passes (OR), or even invert a policy (NOT). `gatehouse` provides
//! combinators for this purpose:
//!
//! - [`AndPolicy`]: Grants access only if all inner policies allow access. Otherwise,
//!   returns a combined error.
//! - [`OrPolicy`]: Grants access if any inner policy allows access; otherwise returns a
//!   combined error.
//! - [`NotPolicy`]: Inverts the decision of an inner policy.
//!
//!

#![warn(missing_docs)]
#![allow(clippy::type_complexity)]
use async_trait::async_trait;
use futures_channel::oneshot;
use std::any::{Any, TypeId};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tracing::Instrument;

const DEFAULT_SECURITY_RULE_CATEGORY: &str = "Access Control";
const PERMISSION_CHECKER_POLICY_TYPE: &str = "PermissionChecker";

/// Metadata describing the security rule associated with a [`Policy`].
///
/// These fields follow the OpenTelemetry semantic conventions for security
/// rules: <https://opentelemetry.io/docs/specs/semconv/registry/attributes/security-rule/>.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecurityRuleMetadata {
    name: Option<String>,
    category: Option<String>,
    description: Option<String>,
    reference: Option<String>,
    ruleset_name: Option<String>,
    uuid: Option<String>,
    version: Option<String>,
    license: Option<String>,
}

impl SecurityRuleMetadata {
    /// Creates an empty metadata container.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the `security_rule.name` attribute.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the `security_rule.category` attribute.
    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.category = Some(category.into());
        self
    }

    /// Sets the `security_rule.description` attribute.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets the `security_rule.reference` attribute.
    pub fn with_reference(mut self, reference: impl Into<String>) -> Self {
        self.reference = Some(reference.into());
        self
    }

    /// Sets the `security_rule.ruleset.name` attribute.
    pub fn with_ruleset_name(mut self, ruleset_name: impl Into<String>) -> Self {
        self.ruleset_name = Some(ruleset_name.into());
        self
    }

    /// Sets the `security_rule.uuid` attribute.
    pub fn with_uuid(mut self, uuid: impl Into<String>) -> Self {
        self.uuid = Some(uuid.into());
        self
    }

    /// Sets the `security_rule.version` attribute.
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Sets the `security_rule.license` attribute.
    pub fn with_license(mut self, license: impl Into<String>) -> Self {
        self.license = Some(license.into());
        self
    }

    /// Returns the configured `security_rule.name` value.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Returns the configured `security_rule.category` value.
    pub fn category(&self) -> Option<&str> {
        self.category.as_deref()
    }

    /// Returns the configured `security_rule.description` value.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Returns the configured `security_rule.reference` value.
    pub fn reference(&self) -> Option<&str> {
        self.reference.as_deref()
    }

    /// Returns the configured `security_rule.ruleset.name` value.
    pub fn ruleset_name(&self) -> Option<&str> {
        self.ruleset_name.as_deref()
    }

    /// Returns the configured `security_rule.uuid` value.
    pub fn uuid(&self) -> Option<&str> {
        self.uuid.as_deref()
    }

    /// Returns the configured `security_rule.version` value.
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// Returns the configured `security_rule.license` value.
    pub fn license(&self) -> Option<&str> {
        self.license.as_deref()
    }
}

/// The type of boolean combining operation a policy might represent.
#[derive(Debug, PartialEq, Clone)]
pub enum CombineOp {
    /// All inner policies must grant access.
    And,
    /// At least one inner policy must grant access.
    Or,
    /// The inner policy's decision is inverted.
    Not,
}

impl fmt::Display for CombineOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CombineOp::And => write!(f, "AND"),
            CombineOp::Or => write!(f, "OR"),
            CombineOp::Not => write!(f, "NOT"),
        }
    }
}

/// The result of evaluating a single policy (or a combination).
///
/// This enum is used both by individual policies and by combinators to represent the
/// outcome of access evaluation.
///
/// - [`PolicyEvalResult::Granted`]: Indicates that access is granted, with an optional reason.
/// - [`PolicyEvalResult::Denied`]: Indicates that access is denied, along with an explanatory reason.
/// - [`PolicyEvalResult::Combined`]: Represents the aggregate result of combining multiple policies.
#[derive(Debug, Clone)]
pub enum PolicyEvalResult {
    /// Access granted. Contains the policy type and an optional reason.
    Granted {
        /// The name of the policy that granted access.
        policy_type: String,
        /// An optional human-readable reason for the grant.
        reason: Option<String>,
    },
    /// Access denied. Contains the policy type and a reason.
    Denied {
        /// The name of the policy that denied access.
        policy_type: String,
        /// A human-readable reason for the denial.
        reason: String,
    },
    /// Combined result from multiple policy evaluations.
    /// Contains the policy type, the combining operation ([`CombineOp`]),
    /// a list of child evaluation results, and the overall outcome.
    Combined {
        /// The name of the combinator policy (e.g. `"AndPolicy"`).
        policy_type: String,
        /// The boolean operation used to combine child results.
        operation: CombineOp,
        /// The individual results from each child policy.
        children: Vec<PolicyEvalResult>,
        /// The overall outcome after applying the combining operation.
        outcome: bool,
    },
}

/// A borrowed resource/context pair passed to batch policy evaluators.
///
/// Values are borrowed from caller-owned batch items, so policy implementations
/// can evaluate a batch without forcing resources or contexts to be cloned.
pub struct PolicyBatchItem<'a, Resource, Context> {
    /// The target resource for this item.
    pub resource: &'a Resource,
    /// Additional context for this item.
    pub context: &'a Context,
}

/// A typed fact key that can be loaded through an [`EvaluationSession`].
///
/// Keys are flat, cloneable, and hashable so the session can deduplicate and
/// cache fact loads for the lifetime of one authorization request.
pub trait FactKey: Eq + Hash + Clone + Send + Sync + 'static {
    /// The value returned by a [`FactSource`] for this key.
    type Value: Clone + Send + Sync + 'static;

    /// Stable fact name used only in diagnostics and tracing.
    ///
    /// The session registry is keyed by [`TypeId`], not by this name, so two
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
    LoaderCancelled {
        /// Diagnostic fact name from [`FactKey::NAME`].
        fact_name: &'static str,
    },
    /// The registered source reported a backend error.
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

#[derive(Default)]
struct EvaluationSessionInner {
    sources: Mutex<HashMap<TypeId, Box<dyn Any + Send + Sync>>>,
    caches: Mutex<HashMap<TypeId, Box<dyn Any + Send + Sync>>>,
    in_flight: Mutex<HashMap<TypeId, Box<dyn Any + Send>>>,
    next_load_id: AtomicU64,
}

/// Request-scoped fact loading and caching state.
///
/// A session is intended to live for one request or one authorization pass. It
/// owns registered fact sources and caches loaded facts by key type. The cache
/// is deliberately not process-global.
#[derive(Clone, Default)]
pub struct EvaluationSession {
    inner: Arc<EvaluationSessionInner>,
}

impl EvaluationSession {
    /// Creates an empty request-scoped session.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an explicitly empty request-scoped session.
    ///
    /// This is equivalent to [`Self::new`]. It can make call sites clearer when
    /// only RBAC/ABAC policies are expected and no fact sources are registered.
    pub fn empty() -> Self {
        Self::new()
    }

    /// Registers a fact source for one key type.
    pub fn register<K, S>(&self, source: S)
    where
        K: FactKey,
        S: FactSource<K> + 'static,
    {
        self.register_arc::<K>(Arc::new(source));
    }

    /// Registers a shared fact source for one key type.
    ///
    /// Re-registering a source clears any cached facts for that key type in
    /// this session. Register sources during session setup; replacing a source
    /// while loads for the same key type are in flight is not a supported
    /// operation.
    pub fn register_arc<K>(&self, source: Arc<dyn FactSource<K>>)
    where
        K: FactKey,
    {
        let type_id = TypeId::of::<K>();
        let in_flight_empty = {
            let mut in_flight = self
                .inner
                .in_flight
                .lock()
                .expect("fact in-flight registry mutex should not be poisoned");
            Self::in_flight_for::<K>(&mut in_flight).is_empty()
        };
        debug_assert!(
            in_flight_empty,
            "fact sources should not be replaced while loads for the same key type are in flight",
        );
        self.inner
            .sources
            .lock()
            .expect("fact source registry mutex should not be poisoned")
            .insert(type_id, Box::new(source));
        self.inner
            .caches
            .lock()
            .expect("fact cache mutex should not be poisoned")
            .remove(&type_id);
    }

    /// Loads one fact through the session cache.
    pub async fn get<K>(&self, key: K) -> FactLoadResult<K::Value>
    where
        K: FactKey,
    {
        self.get_many(&[key])
            .await
            .into_iter()
            .next()
            .unwrap_or_else(|| {
                FactLoadResult::Error(FactLoadError::SourceContractViolation {
                    fact_name: K::NAME,
                    expected: 1,
                    actual: 0,
                })
            })
    }

    /// Loads facts through the session cache.
    ///
    /// Results preserve input order and duplicate keys. Missing cache entries
    /// are deduplicated before they are loaded, then chunked according to the
    /// source's [`FactSource::max_batch_size`] hint.
    pub async fn get_many<K>(&self, keys: &[K]) -> Vec<FactLoadResult<K::Value>>
    where
        K: FactKey,
    {
        if keys.is_empty() {
            return Vec::new();
        }

        let source = self.source::<K>();
        let load_plan = self.plan_loads(keys);
        let mut in_flight_guard = InFlightGuard::new(self.clone(), load_plan.keys.clone());

        if !load_plan.keys.is_empty() {
            if let Some(source) = source {
                let chunk_size = source
                    .max_batch_size()
                    .map_or(load_plan.keys.len(), NonZeroUsize::get)
                    .max(1);

                for chunk in load_plan.keys.chunks(chunk_size) {
                    let load_id = self.inner.next_load_id.fetch_add(1, Ordering::Relaxed);
                    let load_span = tracing::debug_span!(
                        "gatehouse.fact_load",
                        fact.name = K::NAME,
                        fact.load_id = load_id,
                        fact.key_count = chunk.len(),
                        fact.unique_key_count = chunk.len(),
                    );
                    let loaded = source.load_many(chunk).instrument(load_span).await;
                    if loaded.len() == chunk.len() {
                        self.cache_loaded(chunk, loaded);
                    } else {
                        self.cache_loaded(
                            chunk,
                            chunk
                                .iter()
                                .map(|_| {
                                    FactLoadResult::Error(FactLoadError::SourceContractViolation {
                                        fact_name: K::NAME,
                                        expected: chunk.len(),
                                        actual: loaded.len(),
                                    })
                                })
                                .collect(),
                        );
                    }
                    // Keep this immediately after the cache write, with no await in between.
                    // The drop guard treats remaining keys as cancelled.
                    in_flight_guard.finish(chunk);
                }
            } else {
                self.cache_loaded(
                    &load_plan.keys,
                    load_plan
                        .keys
                        .iter()
                        .map(|_| {
                            FactLoadResult::Error(FactLoadError::SourceNotRegistered {
                                fact_name: K::NAME,
                            })
                        })
                        .collect(),
                );
                in_flight_guard.finish(&load_plan.keys);
            }
        }

        for waiter in load_plan.waiters {
            let _ = waiter.await;
        }

        self.results_from_cache(keys)
    }

    fn source<K>(&self) -> Option<Arc<dyn FactSource<K>>>
    where
        K: FactKey,
    {
        self.inner
            .sources
            .lock()
            .expect("fact source registry mutex should not be poisoned")
            .get(&TypeId::of::<K>())
            .and_then(|source| source.downcast_ref::<Arc<dyn FactSource<K>>>().cloned())
    }

    fn plan_loads<K>(&self, keys: &[K]) -> LoadPlan<K>
    where
        K: FactKey,
    {
        let mut seen = HashSet::new();
        let mut missing = Vec::new();
        let mut caches = self
            .inner
            .caches
            .lock()
            .expect("fact cache mutex should not be poisoned");
        let cache = Self::cache_for::<K>(&mut caches);

        let mut in_flight = self
            .inner
            .in_flight
            .lock()
            .expect("fact in-flight registry mutex should not be poisoned");
        let in_flight = Self::in_flight_for::<K>(&mut in_flight);
        let mut waiters = Vec::new();

        for key in keys.iter().filter(|key| seen.insert((*key).clone())) {
            if cache.contains_key(key) {
                continue;
            }

            if let Some(existing_waiters) = in_flight.get_mut(key) {
                let (sender, receiver) = oneshot::channel();
                existing_waiters.push(sender);
                waiters.push(receiver);
            } else {
                in_flight.insert(key.clone(), Vec::new());
                missing.push(key.clone());
            }
        }

        LoadPlan {
            keys: missing,
            waiters,
        }
    }

    fn finish_in_flight<K>(&self, keys: &[K])
    where
        K: FactKey,
    {
        let mut in_flight = self
            .inner
            .in_flight
            .lock()
            .expect("fact in-flight registry mutex should not be poisoned");
        let in_flight = Self::in_flight_for::<K>(&mut in_flight);

        for key in keys {
            if let Some(waiters) = in_flight.remove(key) {
                for waiter in waiters {
                    let _ = waiter.send(());
                }
            }
        }
    }

    fn cache_loaded<K>(&self, keys: &[K], results: Vec<FactLoadResult<K::Value>>)
    where
        K: FactKey,
    {
        let mut caches = self
            .inner
            .caches
            .lock()
            .expect("fact cache mutex should not be poisoned");
        let cache = Self::cache_for::<K>(&mut caches);

        for (key, result) in keys.iter().cloned().zip(results) {
            cache.insert(key, result);
        }
    }

    fn results_from_cache<K>(&self, keys: &[K]) -> Vec<FactLoadResult<K::Value>>
    where
        K: FactKey,
    {
        let mut caches = self
            .inner
            .caches
            .lock()
            .expect("fact cache mutex should not be poisoned");
        let cache = Self::cache_for::<K>(&mut caches);
        keys.iter()
            .map(|key| {
                cache.get(key).cloned().unwrap_or_else(|| {
                    FactLoadResult::Error(FactLoadError::SourceContractViolation {
                        fact_name: K::NAME,
                        expected: 1,
                        actual: 0,
                    })
                })
            })
            .collect()
    }

    fn cache_for<K>(
        caches: &mut HashMap<TypeId, Box<dyn Any + Send + Sync>>,
    ) -> &mut HashMap<K, FactLoadResult<K::Value>>
    where
        K: FactKey,
    {
        caches
            .entry(TypeId::of::<K>())
            .or_insert_with(|| Box::new(HashMap::<K, FactLoadResult<K::Value>>::new()))
            .downcast_mut::<HashMap<K, FactLoadResult<K::Value>>>()
            .expect("fact cache type should match registry key")
    }

    fn in_flight_for<K>(
        in_flight: &mut HashMap<TypeId, Box<dyn Any + Send>>,
    ) -> &mut HashMap<K, Vec<oneshot::Sender<()>>>
    where
        K: FactKey,
    {
        in_flight
            .entry(TypeId::of::<K>())
            .or_insert_with(|| Box::new(HashMap::<K, Vec<oneshot::Sender<()>>>::new()))
            .downcast_mut::<HashMap<K, Vec<oneshot::Sender<()>>>>()
            .expect("fact in-flight type should match registry key")
    }
}

struct LoadPlan<K> {
    keys: Vec<K>,
    waiters: Vec<oneshot::Receiver<()>>,
}

struct InFlightGuard<K>
where
    K: FactKey,
{
    session: EvaluationSession,
    remaining: Vec<K>,
}

impl<K> InFlightGuard<K>
where
    K: FactKey,
{
    fn new(session: EvaluationSession, keys: Vec<K>) -> Self {
        Self {
            session,
            remaining: keys,
        }
    }

    fn finish(&mut self, keys: &[K]) {
        self.session.finish_in_flight(keys);
        if self.remaining.is_empty() {
            return;
        }

        let finished = keys.iter().cloned().collect::<HashSet<_>>();
        self.remaining.retain(|key| !finished.contains(key));
    }
}

impl<K> Drop for InFlightGuard<K>
where
    K: FactKey,
{
    fn drop(&mut self) {
        if self.remaining.is_empty() {
            return;
        }

        self.session.cache_loaded(
            &self.remaining,
            self.remaining
                .iter()
                .map(|_| {
                    FactLoadResult::Error(FactLoadError::LoaderCancelled { fact_name: K::NAME })
                })
                .collect(),
        );
        self.session.finish_in_flight(&self.remaining);
    }
}

/// Per-item policy evaluation context.
pub struct EvalCtx<'a, Subject, Resource, Action, Context> {
    /// Request-scoped fact session.
    pub session: &'a EvaluationSession,
    /// Entity requesting access.
    pub subject: &'a Subject,
    /// Action being performed.
    pub action: &'a Action,
    /// Target resource.
    pub resource: &'a Resource,
    /// Additional evaluation context.
    pub context: &'a Context,
}

/// Batch policy evaluation context.
pub struct BatchEvalCtx<'a, Subject, Resource, Action, Context> {
    /// Request-scoped fact session.
    pub session: &'a EvaluationSession,
    /// Entity requesting access.
    pub subject: &'a Subject,
    /// Action being performed.
    pub action: &'a Action,
    /// Borrowed resource/context pairs.
    pub items: &'a [PolicyBatchItem<'a, Resource, Context>],
}

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

/// Error returned by lookup-oriented relationship sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupError {
    message: String,
}

impl LookupError {
    /// Creates a lookup error with a human-readable message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for LookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for LookupError {}

/// One page of lookup-oriented relationship results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupPage<ResourceId, Cursor> {
    /// Resources visible in this page.
    pub resources: Vec<ResourceId>,
    /// Cursor to request the next page, if more resources are available.
    pub next_cursor: Option<Cursor>,
}

/// Optional graph-style relationship lookup source.
#[async_trait]
pub trait LookupSource<SubjectId, ResourceId, Relation>:
    FactSource<RelationshipQuery<SubjectId, ResourceId, Relation>>
where
    SubjectId: Eq + Hash + Clone + Send + Sync + 'static,
    ResourceId: Eq + Hash + Clone + Send + Sync + 'static,
    Relation: Eq + Hash + Clone + Send + Sync + 'static,
{
    /// Opaque pagination cursor type used by this source.
    type Cursor: Clone + Send + Sync + 'static;

    /// Looks up one page of resources related to the subject by `relation`.
    async fn lookup_resources(
        &self,
        subject: &SubjectId,
        relation: &Relation,
        cursor: Option<Self::Cursor>,
        limit: Option<NonZeroUsize>,
    ) -> Result<LookupPage<ResourceId, Self::Cursor>, LookupError>;
}

/// The complete result of a permission evaluation.
/// Contains both the final decision and a detailed trace for debugging.
///
/// ### Evaluation Tracing
///
/// The permission system provides detailed tracing of policy decisions:
/// ```rust
/// # use gatehouse::*;
/// # use uuid::Uuid;
/// #
/// # // Define simple types for the example
/// # #[derive(Debug, Clone)]
/// # struct User { id: Uuid }
/// # #[derive(Debug, Clone)]
/// # struct Document { id: Uuid }
/// # #[derive(Debug, Clone)]
/// # struct ReadAction;
/// # #[derive(Debug, Clone)]
/// # struct EmptyContext;
/// #
/// # async fn example() -> AccessEvaluation {
/// #     let mut checker = PermissionChecker::<User, Document, ReadAction, EmptyContext>::new();
/// #     let user = User { id: Uuid::new_v4() };
/// #     let document = Document { id: Uuid::new_v4() };
/// #     let session = EvaluationSession::empty();
/// #     checker.evaluate_in_session(&session, &user, &ReadAction, &document, &EmptyContext).await
/// # }
/// #
/// # tokio_test::block_on(async {
/// let result = example().await;
///
/// match result {
///     AccessEvaluation::Granted { policy_type, reason, trace } => {
///         println!("Access granted by {}: {:?}", policy_type, reason);
///         println!("Full evaluation trace:\n{}", trace.format());
///     }
///     AccessEvaluation::Denied { reason, trace } => {
///         println!("Access denied: {}", reason);
///         println!("Full evaluation trace:\n{}", trace.format());
///     }
/// }
/// # });
/// ```
#[derive(Debug, Clone)]
pub enum AccessEvaluation {
    /// Access was granted.
    Granted {
        /// The policy that granted access
        policy_type: String,
        /// Optional reason for granting
        reason: Option<String>,
        /// Full evaluation trace including any rejected policies
        trace: EvalTrace,
    },
    /// Access was denied.
    Denied {
        /// The complete evaluation trace showing all policy decisions
        trace: EvalTrace,
        /// Summary reason for denial
        reason: String,
    },
}

impl AccessEvaluation {
    /// Whether access was granted
    pub fn is_granted(&self) -> bool {
        matches!(self, Self::Granted { .. })
    }

    /// Converts the evaluation into a `Result`, mapping a denial into an error.
    ///
    /// `error_fn` receives the denial reason string and should return your
    /// application's error type.
    ///
    /// Note that this uses the summary denial reason stored on
    /// [`AccessEvaluation::Denied`], not the individual child policy reasons from the
    /// trace tree. If you need the per-policy reasons, inspect [`EvalTrace`] first.
    ///
    /// ```rust
    /// # use gatehouse::*;
    /// # #[derive(Debug, Clone)]
    /// # struct User;
    /// # #[derive(Debug, Clone)]
    /// # struct Resource;
    /// # #[derive(Debug, Clone)]
    /// # struct Action;
    /// # #[derive(Debug, Clone)]
    /// # struct Ctx;
    /// # tokio_test::block_on(async {
    /// let checker = PermissionChecker::<User, Resource, Action, Ctx>::new();
    /// let session = EvaluationSession::empty();
    /// let result = checker.evaluate_in_session(&session, &User, &Action, &Resource, &Ctx).await;
    ///
    /// // Map a denial into a standard error:
    /// let outcome: Result<(), String> = result.to_result(|reason| reason.to_string());
    /// assert!(outcome.is_err());
    /// # });
    /// ```
    pub fn to_result<E>(&self, error_fn: impl FnOnce(&str) -> E) -> Result<(), E> {
        match self {
            Self::Granted { .. } => Ok(()),
            Self::Denied { reason, .. } => Err(error_fn(reason)),
        }
    }

    /// Returns a human-readable string containing both the decision headline
    /// and the full evaluation trace tree.
    ///
    /// Useful for logging or debugging. The output includes the `Display`
    /// representation (e.g. `[GRANTED] by AdminPolicy - User is admin`)
    /// followed by the indented trace from [`EvalTrace::format`].
    pub fn display_trace(&self) -> String {
        let trace = match self {
            AccessEvaluation::Granted {
                policy_type: _,
                reason: _,
                trace,
            } => trace,
            AccessEvaluation::Denied { reason: _, trace } => trace,
        };

        // If there's an actual tree to show, add it. Otherwise, fallback.
        let trace_str = trace.format();
        if trace_str == "No evaluation trace available" {
            format!("{}\n(No evaluation trace available)", self)
        } else {
            format!("{}\nEvaluation Trace:\n{}", self, trace_str)
        }
    }
}

/// A concise line about the final decision.
impl fmt::Display for AccessEvaluation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Granted {
                policy_type,
                reason,
                trace: _,
            } => {
                // Headline
                match reason {
                    Some(r) => write!(f, "[GRANTED] by {} - {}", policy_type, r),
                    None => write!(f, "[GRANTED] by {}", policy_type),
                }
            }
            Self::Denied { reason, trace: _ } => {
                write!(f, "[Denied] - {}", reason)
            }
        }
    }
}

/// A tree of [`PolicyEvalResult`] nodes capturing every policy decision made
/// during an access evaluation.
///
/// Returned as part of [`AccessEvaluation`]. Use [`EvalTrace::format`] to render
/// a human-readable tree, useful for debugging and audit logging.
///
/// # Example
///
/// ```rust
/// # use gatehouse::*;
/// // An empty trace produces a fallback message:
/// let empty = EvalTrace::new();
/// assert_eq!(empty.format(), "No evaluation trace available");
///
/// // A trace built from a policy result renders a decision tree:
/// let trace = EvalTrace::with_root(PolicyEvalResult::Granted {
///     policy_type: "AdminPolicy".into(),
///     reason: Some("User is admin".into()),
/// });
/// assert!(trace.format().contains("AdminPolicy GRANTED"));
/// ```
#[derive(Debug, Clone, Default)]
pub struct EvalTrace {
    root: Option<PolicyEvalResult>,
}

impl EvalTrace {
    /// Creates an empty trace with no evaluation results.
    pub fn new() -> Self {
        Self { root: None }
    }

    /// Creates a trace with the given [`PolicyEvalResult`] as the root node.
    pub fn with_root(result: PolicyEvalResult) -> Self {
        Self { root: Some(result) }
    }

    /// Sets (or replaces) the root node of the evaluation tree.
    pub fn set_root(&mut self, result: PolicyEvalResult) {
        self.root = Some(result);
    }

    /// Returns a reference to the root [`PolicyEvalResult`], if present.
    pub fn root(&self) -> Option<&PolicyEvalResult> {
        self.root.as_ref()
    }

    /// Returns a formatted, indented representation of the evaluation tree.
    ///
    /// Each node shows a `✔` or `✘` prefix, the policy name, and the reason.
    /// Combined nodes indent their children for readability.
    pub fn format(&self) -> String {
        match &self.root {
            Some(root) => root.format(0),
            None => "No evaluation trace available".to_string(),
        }
    }
}

impl PolicyEvalResult {
    /// Returns whether this evaluation resulted in access being granted
    pub fn is_granted(&self) -> bool {
        match self {
            Self::Granted { .. } => true,
            Self::Denied { .. } => false,
            Self::Combined { outcome, .. } => *outcome,
        }
    }

    /// Returns the reason string if available
    pub fn reason(&self) -> Option<String> {
        match self {
            Self::Granted { reason, .. } => reason.clone(),
            Self::Denied { reason, .. } => Some(reason.clone()),
            Self::Combined { .. } => None,
        }
    }

    /// Formats the evaluation tree with indentation for readability
    pub fn format(&self, indent: usize) -> String {
        let indent_str = " ".repeat(indent);

        match self {
            Self::Granted {
                policy_type,
                reason,
            } => {
                let reason_text = reason
                    .as_ref()
                    .map_or("".to_string(), |r| format!(": {}", r));
                format!("{}✔ {} GRANTED{}", indent_str, policy_type, reason_text)
            }
            Self::Denied {
                policy_type,
                reason,
            } => {
                format!("{}✘ {} DENIED: {}", indent_str, policy_type, reason)
            }
            Self::Combined {
                policy_type,
                operation,
                children,
                outcome,
            } => {
                let outcome_char = if *outcome { "✔" } else { "✘" };
                let mut result = format!(
                    "{}{} {} ({})",
                    indent_str, outcome_char, policy_type, operation
                );

                for child in children {
                    result.push_str(&format!("\n{}", child.format(indent + 2)));
                }
                result
            }
        }
    }
}

impl fmt::Display for PolicyEvalResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tree = self.format(0);
        write!(f, "{}", tree)
    }
}

/// A generic async trait representing a single authorization policy.
/// A policy determines if a subject is allowed to perform an action on
/// a resource within a given context.
#[async_trait]
pub trait Policy<Subject, Resource, Action, Context>: Send + Sync
where
    Subject: Sync,
    Resource: Sync,
    Action: Sync,
    Context: Sync,
{
    /// Evaluates whether access should be granted.
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, Subject, Resource, Action, Context>,
    ) -> PolicyEvalResult;

    /// Evaluates access for a batch of resource/context pairs.
    ///
    /// The default implementation preserves single-item semantics by evaluating
    /// each item sequentially. Policies with set-oriented backends can override
    /// this method to reduce round trips while returning one result per input
    /// item in the same order.
    ///
    /// The checker still evaluates policies in policy order, so batched
    /// evaluation can differ from a naive item-outer loop when later policies
    /// have side effects or observe mutable external state. Prefer pure policy
    /// predicates and use traces to audit the policy-ordered batch behavior.
    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, Subject, Resource, Action, Context>,
    ) -> Vec<PolicyEvalResult> {
        let mut results = Vec::with_capacity(ctx.items.len());
        for item in ctx.items {
            let item_ctx = EvalCtx {
                session: ctx.session,
                subject: ctx.subject,
                action: ctx.action,
                resource: item.resource,
                context: item.context,
            };
            results.push(self.evaluate(&item_ctx).await);
        }
        results
    }

    /// Policy name for debugging, trace trees, and telemetry fallbacks.
    fn policy_type(&self) -> &str;

    /// Metadata describing the security rule that backs this policy.
    ///
    /// Implementors can override this method to surface additional semantic
    /// information. The default implementation returns empty metadata which
    /// still allows downstream telemetry to fall back to the policy type.
    fn security_rule(&self) -> SecurityRuleMetadata {
        SecurityRuleMetadata::default()
    }
}

/// A container for multiple policies, applied in an "OR" fashion.
/// (If any policy returns Ok, access is granted)
/// **Important**:
/// If no policies are added, access is always denied.
#[derive(Clone)]
pub struct PermissionChecker<S, R, A, C> {
    policies: Vec<Arc<dyn Policy<S, R, A, C>>>,
    max_batch_size: Option<NonZeroUsize>,
}

impl<S, R, A, C> Default for PermissionChecker<S, R, A, C>
where
    S: Sync,
    R: Sync,
    A: Sync,
    C: Sync,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<S, R, A, C> PermissionChecker<S, R, A, C>
where
    S: Sync,
    R: Sync,
    A: Sync,
    C: Sync,
{
    /// Creates a new `PermissionChecker` with no policies.
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
            max_batch_size: None,
        }
    }

    /// Sets the maximum number of pending items passed to a policy batch call.
    ///
    /// By default, batch evaluation passes all pending items to each policy in a
    /// single call. Configure this when backend limits, query planner behavior,
    /// or remote service constraints require smaller chunks.
    pub fn with_max_batch_size(mut self, max_batch_size: NonZeroUsize) -> Self {
        self.max_batch_size = Some(max_batch_size);
        self
    }

    /// Adds a policy to the checker.
    ///
    /// # Arguments
    ///
    /// * `policy` - A type implementing [`Policy`]. It is stored as an `Arc` for shared ownership.
    pub fn add_policy<P: Policy<S, R, A, C> + 'static>(&mut self, policy: P) {
        self.policies.push(Arc::new(policy));
    }

    /// Evaluates all policies against the given parameters using a caller-owned
    /// request session.
    ///
    /// Policies are evaluated sequentially with OR semantics and short-circuit
    /// on the first success. The returned [`AccessEvaluation`] contains a
    /// trace tree for the policies that were actually evaluated before
    /// short-circuiting.
    ///
    /// If every policy denies access, the top-level denial reason is the
    /// summary string `"All policies denied access"`. Inspect the trace for
    /// individual policy reasons.
    #[tracing::instrument(skip_all, fields(policy_count = self.policies.len(), outcome = tracing::field::Empty, policy.type = tracing::field::Empty))]
    pub async fn evaluate_in_session(
        &self,
        session: &EvaluationSession,
        subject: &S,
        action: &A,
        resource: &R,
        context: &C,
    ) -> AccessEvaluation {
        if self.policies.is_empty() {
            tracing::Span::current().record("outcome", "denied");
            tracing::debug!("No policies configured");
            let result = PolicyEvalResult::Denied {
                policy_type: PERMISSION_CHECKER_POLICY_TYPE.to_string(),
                reason: "No policies configured".to_string(),
            };

            return AccessEvaluation::Denied {
                trace: EvalTrace::with_root(result),
                reason: "No policies configured".to_string(),
            };
        }
        tracing::trace!(num_policies = self.policies.len(), "Checking access");

        let mut policy_results = Vec::with_capacity(self.policies.len());

        // Evaluate each policy
        for policy in &self.policies {
            let ctx = EvalCtx {
                session,
                subject,
                action,
                resource,
                context,
            };
            let result = policy.evaluate(&ctx).await;
            let result_passes = result.is_granted();

            // Extract metadata for tracing (always needed for security audit)
            let policy_type = policy.policy_type();
            let policy_type_str = policy_type;
            let metadata = policy.security_rule();
            let reason = result.reason();
            let reason_str = reason.as_deref();
            let rule_name = metadata.name().unwrap_or(policy_type_str);
            let category = metadata
                .category()
                .unwrap_or(DEFAULT_SECURITY_RULE_CATEGORY);
            let ruleset_name = metadata
                .ruleset_name()
                .unwrap_or(PERMISSION_CHECKER_POLICY_TYPE);
            let event_outcome = if result_passes { "success" } else { "failure" };

            tracing::trace!(
                target: "gatehouse::security",
                {
                    security_rule.name = rule_name,
                    security_rule.category = category,
                    security_rule.description = metadata.description(),
                    security_rule.reference = metadata.reference(),
                    security_rule.ruleset.name = ruleset_name,
                    security_rule.uuid = metadata.uuid(),
                    security_rule.version = metadata.version(),
                    security_rule.license = metadata.license(),
                    event.outcome = event_outcome,
                    policy.type = policy_type_str,
                    policy.result.reason = reason_str,
                },
                "Security rule evaluated"
            );

            policy_results.push(result);

            // If any policy allows access, return immediately
            if result_passes {
                tracing::Span::current().record("outcome", "granted");
                tracing::Span::current().record("policy.type", policy_type);
                let combined = PolicyEvalResult::Combined {
                    policy_type: PERMISSION_CHECKER_POLICY_TYPE.to_string(),
                    operation: CombineOp::Or,
                    children: policy_results,
                    outcome: true,
                };

                return AccessEvaluation::Granted {
                    policy_type: policy_type.to_string(),
                    reason,
                    trace: EvalTrace::with_root(combined),
                };
            }
        }

        // If all policies denied access
        tracing::Span::current().record("outcome", "denied");
        tracing::trace!("No policies allowed access, returning Forbidden");
        let combined = PolicyEvalResult::Combined {
            policy_type: PERMISSION_CHECKER_POLICY_TYPE.to_string(),
            operation: CombineOp::Or,
            children: policy_results,
            outcome: false,
        };

        AccessEvaluation::Denied {
            trace: EvalTrace::with_root(combined),
            reason: "All policies denied access".to_string(),
        }
    }

    /// Evaluates a batch of caller-owned items using a caller-owned session.
    ///
    /// The `parts` callback tells gatehouse how to borrow the resource and
    /// context from each caller-owned item. Returned results preserve input
    /// order, including duplicate resources. Policy evaluation still uses the
    /// same OR semantics as [`Self::evaluate_in_session`], but the checker evaluates
    /// each policy across the still-pending batch before moving to the next
    /// policy. This lets policies with set-oriented backends override
    /// [`Policy::evaluate_batch`] and collapse many point lookups into
    /// one backend call.
    ///
    /// The loop is intentionally policy-outer/items-inner, not a naive
    /// item-outer loop. OR short-circuiting is preserved per item and policy
    /// order is preserved globally, but callers should avoid relying on
    /// side effects from interleaving one item through every policy before the
    /// next item starts.
    ///
    /// If a policy returns the wrong number of batch results, affected items are
    /// denied rather than accidentally granted.
    ///
    /// ```rust
    /// # use gatehouse::*;
    /// # use async_trait::async_trait;
    /// # #[derive(Clone)]
    /// # struct User { id: u64 }
    /// # #[derive(Clone)]
    /// # struct Document { owner_id: u64 }
    /// # struct Read;
    /// # #[derive(Clone)]
    /// # struct RequestContext;
    /// # tokio_test::block_on(async {
    /// let user = User { id: 7 };
    /// let context = RequestContext;
    /// let session = EvaluationSession::empty();
    /// let documents = vec![
    ///     Document { owner_id: 7 },
    ///     Document { owner_id: 42 },
    /// ];
    ///
    /// let mut checker = PermissionChecker::new();
    /// checker.add_policy(AbacPolicy::new(
    ///     |user: &User, document: &Document, _action: &Read, _context: &RequestContext| {
    ///         user.id == document.owner_id
    ///     },
    /// ));
    ///
    /// let visible = checker
    ///     .filter_authorized_with_context_in_session_by(&session, &user, &Read, documents, &context, |document| {
    ///         document
    ///     })
    ///     .await;
    ///
    /// assert_eq!(visible.len(), 1);
    /// # });
    /// ```
    #[tracing::instrument(skip_all, fields(item_count, granted_count, denied_count, max_batch_size, policy_count = self.policies.len()))]
    pub async fn evaluate_batch_in_session_by<I, F>(
        &self,
        session: &EvaluationSession,
        subject: &S,
        action: &A,
        items: I,
        parts: F,
    ) -> Vec<(I::Item, AccessEvaluation)>
    where
        I: IntoIterator,
        F: for<'item> Fn(&'item I::Item) -> (&'item R, &'item C),
    {
        let items: Vec<I::Item> = items.into_iter().collect();
        let item_count = items.len();
        tracing::Span::current().record("item_count", item_count);
        if let Some(max_batch_size) = self.max_batch_size {
            tracing::Span::current().record("max_batch_size", max_batch_size.get());
        }

        let mut traces = vec![Vec::new(); item_count];
        let mut evaluations: Vec<Option<AccessEvaluation>> = vec![None; item_count];

        if self.policies.is_empty() {
            let mut denied_count = 0usize;
            let results = items
                .into_iter()
                .map(|item| {
                    denied_count += 1;
                    let result = PolicyEvalResult::Denied {
                        policy_type: PERMISSION_CHECKER_POLICY_TYPE.to_string(),
                        reason: "No policies configured".to_string(),
                    };
                    (
                        item,
                        AccessEvaluation::Denied {
                            trace: EvalTrace::with_root(result),
                            reason: "No policies configured".to_string(),
                        },
                    )
                })
                .collect();
            tracing::Span::current().record("granted_count", 0usize);
            tracing::Span::current().record("denied_count", denied_count);
            return results;
        }

        let item_parts = items
            .iter()
            .map(|item| {
                let (resource, context) = parts(item);
                PolicyBatchItem { resource, context }
            })
            .collect::<Vec<_>>();

        let mut pending: Vec<usize> = (0..item_count).collect();

        for policy in &self.policies {
            if pending.is_empty() {
                break;
            }

            let policy_type = policy.policy_type();
            let policy_span = tracing::debug_span!(
                "gatehouse.batch_policy",
                policy.type = policy_type,
                policy.pending_count = pending.len(),
                policy.granted_count = tracing::field::Empty,
                policy.denied_count = tracing::field::Empty,
            );

            let mut still_pending = Vec::new();
            let mut policy_granted_count = 0usize;
            let mut policy_denied_count = 0usize;
            let chunk_size = self
                .max_batch_size
                .map_or(pending.len(), NonZeroUsize::get)
                .max(1);

            for pending_chunk in pending.chunks(chunk_size) {
                let batch_items: Vec<_> = pending_chunk
                    .iter()
                    .map(|&index| PolicyBatchItem {
                        resource: item_parts[index].resource,
                        context: item_parts[index].context,
                    })
                    .collect();

                let batch_ctx = BatchEvalCtx {
                    session,
                    subject,
                    action,
                    items: &batch_items,
                };
                let policy_results = policy
                    .evaluate_batch(&batch_ctx)
                    .instrument(policy_span.clone())
                    .await;

                if policy_results.len() != pending_chunk.len() {
                    for &index in pending_chunk {
                        policy_denied_count += 1;
                        let policy_result = PolicyEvalResult::Denied {
                            policy_type: policy_type.to_string(),
                            reason: "Policy batch result count did not match input count"
                                .to_string(),
                        };
                        traces[index].push(policy_result);
                        let combined = PolicyEvalResult::Combined {
                            policy_type: PERMISSION_CHECKER_POLICY_TYPE.to_string(),
                            operation: CombineOp::Or,
                            children: std::mem::take(&mut traces[index]),
                            outcome: false,
                        };
                        evaluations[index] = Some(AccessEvaluation::Denied {
                            trace: EvalTrace::with_root(combined),
                            reason: "Policy batch result count did not match input count"
                                .to_string(),
                        });
                    }
                    continue;
                }

                for (&index, result) in pending_chunk.iter().zip(policy_results) {
                    let result_passes = result.is_granted();
                    let reason = result.reason();

                    traces[index].push(result);

                    if result_passes {
                        policy_granted_count += 1;
                        let combined = PolicyEvalResult::Combined {
                            policy_type: PERMISSION_CHECKER_POLICY_TYPE.to_string(),
                            operation: CombineOp::Or,
                            children: std::mem::take(&mut traces[index]),
                            outcome: true,
                        };
                        evaluations[index] = Some(AccessEvaluation::Granted {
                            policy_type: policy_type.to_string(),
                            reason,
                            trace: EvalTrace::with_root(combined),
                        });
                    } else {
                        policy_denied_count += 1;
                        still_pending.push(index);
                    }
                }
            }
            policy_span.record("policy.granted_count", policy_granted_count);
            policy_span.record("policy.denied_count", policy_denied_count);
            pending = still_pending;
        }

        for index in pending {
            let combined = PolicyEvalResult::Combined {
                policy_type: PERMISSION_CHECKER_POLICY_TYPE.to_string(),
                operation: CombineOp::Or,
                children: std::mem::take(&mut traces[index]),
                outcome: false,
            };
            evaluations[index] = Some(AccessEvaluation::Denied {
                trace: EvalTrace::with_root(combined),
                reason: "All policies denied access".to_string(),
            });
        }

        drop(item_parts);

        let mut granted_count = 0usize;
        let results = items
            .into_iter()
            .zip(evaluations.into_iter())
            .map(|(item, evaluation)| {
                let evaluation = evaluation.unwrap_or_else(|| {
                    let result = PolicyEvalResult::Denied {
                        policy_type: PERMISSION_CHECKER_POLICY_TYPE.to_string(),
                        reason: "Batch item was not evaluated".to_string(),
                    };
                    AccessEvaluation::Denied {
                        trace: EvalTrace::with_root(result),
                        reason: "Batch item was not evaluated".to_string(),
                    }
                });
                if evaluation.is_granted() {
                    granted_count += 1;
                }
                (item, evaluation)
            })
            .collect::<Vec<_>>();
        let denied_count = item_count - granted_count;
        tracing::Span::current().record("granted_count", granted_count);
        tracing::Span::current().record("denied_count", denied_count);
        results
    }

    /// Returns only the items granted by [`Self::evaluate_batch_in_session_by`].
    pub async fn filter_authorized_in_session_by<I, F>(
        &self,
        session: &EvaluationSession,
        subject: &S,
        action: &A,
        items: I,
        parts: F,
    ) -> Vec<I::Item>
    where
        I: IntoIterator,
        F: for<'item> Fn(&'item I::Item) -> (&'item R, &'item C),
    {
        self.evaluate_batch_in_session_by(session, subject, action, items, parts)
            .await
            .into_iter()
            .filter_map(|(item, evaluation)| evaluation.is_granted().then_some(item))
            .collect()
    }

    /// Evaluates caller-owned items that all share one context value, using a
    /// caller-owned session.
    pub async fn evaluate_batch_with_context_in_session_by<I, F>(
        &self,
        session: &EvaluationSession,
        subject: &S,
        action: &A,
        items: I,
        context: &C,
        resource: F,
    ) -> Vec<(I::Item, AccessEvaluation)>
    where
        I: IntoIterator,
        F: for<'item> Fn(&'item I::Item) -> &'item R,
    {
        let wrapped_items = items
            .into_iter()
            .map(|item| (item, context))
            .collect::<Vec<_>>();

        self.evaluate_batch_in_session_by(
            session,
            subject,
            action,
            wrapped_items,
            |(item, context)| (resource(item), *context),
        )
        .await
        .into_iter()
        .map(|((item, _context), evaluation)| (item, evaluation))
        .collect()
    }

    /// Returns only authorized items with a shared context and caller-owned session.
    pub async fn filter_authorized_with_context_in_session_by<I, F>(
        &self,
        session: &EvaluationSession,
        subject: &S,
        action: &A,
        items: I,
        context: &C,
        resource: F,
    ) -> Vec<I::Item>
    where
        I: IntoIterator,
        F: for<'item> Fn(&'item I::Item) -> &'item R,
    {
        self.evaluate_batch_with_context_in_session_by(
            session, subject, action, items, context, resource,
        )
        .await
        .into_iter()
        .filter_map(|(item, evaluation)| evaluation.is_granted().then_some(item))
        .collect()
    }
}

/// Represents the intended effect of a policy.
///
/// `Allow` means the policy grants access; `Deny` means it denies access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// The policy grants access when its predicates pass.
    Allow,
    /// The policy denies access when its predicates pass.
    Deny,
}

/// An internal policy type (not exposed to API users) that is constructed via the builder.
struct InternalPolicy<S, R, A, C> {
    name: String,
    effect: Effect,
    // The predicate returns true if all conditions pass.
    predicate: Box<dyn Fn(&S, &A, &R, &C) -> bool + Send + Sync>,
}

#[async_trait]
impl<S, R, A, C> Policy<S, R, A, C> for InternalPolicy<S, R, A, C>
where
    S: Send + Sync,
    R: Send + Sync,
    A: Send + Sync,
    C: Send + Sync,
{
    async fn evaluate(&self, ctx: &EvalCtx<'_, S, R, A, C>) -> PolicyEvalResult {
        if (self.predicate)(ctx.subject, ctx.action, ctx.resource, ctx.context) {
            match self.effect {
                Effect::Allow => PolicyEvalResult::Granted {
                    policy_type: self.name.clone(),
                    reason: Some("Policy allowed access".into()),
                },
                Effect::Deny => PolicyEvalResult::Denied {
                    policy_type: self.name.clone(),
                    reason: "Policy denied access".into(),
                },
            }
        } else {
            // Predicate didn't match – treat as non-applicable (denied).
            PolicyEvalResult::Denied {
                policy_type: self.name.clone(),
                reason: "Policy predicate did not match".into(),
            }
        }
    }
    fn policy_type(&self) -> &str {
        &self.name
    }
}

// Tell the compiler that a Box<dyn Policy> implements the Policy trait so we can keep
// our internal policy type private.
#[async_trait]
impl<S, R, A, C> Policy<S, R, A, C> for Box<dyn Policy<S, R, A, C>>
where
    S: Send + Sync,
    R: Send + Sync,
    A: Send + Sync,
    C: Send + Sync,
{
    async fn evaluate(&self, ctx: &EvalCtx<'_, S, R, A, C>) -> PolicyEvalResult {
        (**self).evaluate(ctx).await
    }

    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, S, R, A, C>,
    ) -> Vec<PolicyEvalResult> {
        (**self).evaluate_batch(ctx).await
    }

    fn policy_type(&self) -> &str {
        (**self).policy_type()
    }

    fn security_rule(&self) -> SecurityRuleMetadata {
        (**self).security_rule()
    }
}

/// A builder API for creating custom policies.
///
/// A fluent interface to combine predicate functions on the subject, action, resource,
/// and context. All predicates are combined with AND logic — every predicate must pass
/// for the policy to grant access. Use [`PolicyBuilder::build`] to produce a boxed
/// [`Policy`] that can be added to a [`PermissionChecker`].
///
/// [`PolicyBuilder`] is designed for synchronous predicate logic. If your policy
/// needs to perform async I/O or external lookups, implement [`Policy`] directly.
///
/// [`PolicyBuilder::effect`] controls the result returned when the combined
/// predicate matches. In particular, `Effect::Deny` means "this built policy
/// returns [`PolicyEvalResult::Denied`] when it matches". A non-match is still
/// treated as denied/non-applicable, and this does not introduce a global
/// deny-overrides-allow rule when combined with other policies.
///
/// # Example
///
/// ```rust
/// # use gatehouse::*;
/// # use uuid::Uuid;
/// #[derive(Debug, Clone)]
/// struct User { id: Uuid, roles: Vec<String> }
/// #[derive(Debug, Clone)]
/// struct Document { owner_id: Uuid, classification: String }
/// #[derive(Debug, Clone)]
/// struct Action(String);
/// #[derive(Debug, Clone)]
/// struct Ctx;
///
/// let policy = PolicyBuilder::<User, Document, Action, Ctx>::new("OwnerEditors")
///     .subjects(|user: &User| user.roles.iter().any(|r| r == "editor"))
///     .actions(|action: &Action| action.0 == "edit")
///     .resources(|doc: &Document| doc.classification != "top-secret")
///     // Use `when` when a predicate needs to compare multiple inputs:
///     .when(|user: &User, _action: &Action, doc: &Document, _ctx: &Ctx| {
///         user.id == doc.owner_id
///     })
///     .build();
///
/// let mut checker = PermissionChecker::new();
/// checker.add_policy(policy);
///
/// # tokio_test::block_on(async {
/// let user_id = Uuid::new_v4();
/// let user = User { id: user_id, roles: vec!["editor".into()] };
/// let doc = Document { owner_id: user_id, classification: "internal".into() };
/// let session = EvaluationSession::empty();
///
/// // User is an editor, action is "edit", doc is not top-secret, and user owns it:
/// assert!(checker.evaluate_in_session(&session, &user, &Action("edit".into()), &doc, &Ctx).await.is_granted());
///
/// // Wrong action — predicate fails:
/// assert!(!checker.evaluate_in_session(&session, &user, &Action("delete".into()), &doc, &Ctx).await.is_granted());
/// # });
/// ```
pub struct PolicyBuilder<S, R, A, C>
where
    S: Send + Sync + 'static,
    R: Send + Sync + 'static,
    A: Send + Sync + 'static,
    C: Send + Sync + 'static,
{
    name: String,
    effect: Effect,
    subject_pred: Option<Box<dyn Fn(&S) -> bool + Send + Sync>>,
    action_pred: Option<Box<dyn Fn(&A) -> bool + Send + Sync>>,
    resource_pred: Option<Box<dyn Fn(&R) -> bool + Send + Sync>>,
    context_pred: Option<Box<dyn Fn(&C) -> bool + Send + Sync>>,
    // Note the order here matches the EvalCtx fields used by Policy::evaluate.
    extra_condition: Option<Box<dyn Fn(&S, &A, &R, &C) -> bool + Send + Sync>>,
}

impl<Subject, Resource, Action, Context> PolicyBuilder<Subject, Resource, Action, Context>
where
    Subject: Send + Sync + 'static,
    Resource: Send + Sync + 'static,
    Action: Send + Sync + 'static,
    Context: Send + Sync + 'static,
{
    /// Creates a new policy builder with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            effect: Effect::Allow,
            subject_pred: None,
            action_pred: None,
            resource_pred: None,
            context_pred: None,
            extra_condition: None,
        }
    }

    /// Sets the effect (Allow or Deny) for the policy.
    ///
    /// Defaults to [`Effect::Allow`].
    ///
    /// `Effect::Deny` causes the built policy to return
    /// [`PolicyEvalResult::Denied`] when its combined predicate matches. A
    /// non-match is still treated as denied/non-applicable, and this does not
    /// override grants from other policies evaluated by [`PermissionChecker`].
    pub fn effect(mut self, effect: Effect) -> Self {
        self.effect = effect;
        self
    }

    /// Adds a predicate that tests the subject.
    pub fn subjects<F>(mut self, pred: F) -> Self
    where
        F: Fn(&Subject) -> bool + Send + Sync + 'static,
    {
        self.subject_pred = Some(Box::new(pred));
        self
    }

    /// Adds a predicate that tests the action.
    pub fn actions<F>(mut self, pred: F) -> Self
    where
        F: Fn(&Action) -> bool + Send + Sync + 'static,
    {
        self.action_pred = Some(Box::new(pred));
        self
    }

    /// Adds a predicate that tests the resource.
    pub fn resources<F>(mut self, pred: F) -> Self
    where
        F: Fn(&Resource) -> bool + Send + Sync + 'static,
    {
        self.resource_pred = Some(Box::new(pred));
        self
    }

    /// Add a predicate that validates the context.
    pub fn context<F>(mut self, pred: F) -> Self
    where
        F: Fn(&Context) -> bool + Send + Sync + 'static,
    {
        self.context_pred = Some(Box::new(pred));
        self
    }

    /// Add a condition that considers all four inputs.
    pub fn when<F>(mut self, pred: F) -> Self
    where
        F: Fn(&Subject, &Action, &Resource, &Context) -> bool + Send + Sync + 'static,
    {
        self.extra_condition = Some(Box::new(pred));
        self
    }

    /// Build the policy. Returns a boxed policy that can be added to a PermissionChecker.
    pub fn build(self) -> Box<dyn Policy<Subject, Resource, Action, Context>> {
        let effect = self.effect;
        let subject_pred = self.subject_pred;
        let action_pred = self.action_pred;
        let resource_pred = self.resource_pred;
        let context_pred = self.context_pred;
        let extra_condition = self.extra_condition;

        let predicate = Box::new(move |s: &Subject, a: &Action, r: &Resource, c: &Context| {
            subject_pred.as_ref().is_none_or(|f| f(s))
                && action_pred.as_ref().is_none_or(|f| f(a))
                && resource_pred.as_ref().is_none_or(|f| f(r))
                && context_pred.as_ref().is_none_or(|f| f(c))
                && extra_condition.as_ref().is_none_or(|f| f(s, a, r, c))
        });

        Box::new(InternalPolicy {
            name: self.name,
            effect,
            predicate,
        })
    }
}

/// A role-based access control policy.
///
/// `required_roles_resolver` is a closure that determines which roles are required
/// for the given (resource, action). `user_roles_resolver` extracts the subject's roles.
/// Access is granted if the subject holds at least one of the required roles.
///
/// Roles are identified by [`Uuid`](uuid::Uuid), allowing integration with external
/// identity systems without relying on string matching.
///
/// # Example
///
/// ```rust
/// # use gatehouse::*;
/// # use uuid::Uuid;
/// #[derive(Debug, Clone)]
/// struct User { role_ids: Vec<Uuid> }
/// #[derive(Debug, Clone)]
/// struct Resource;
/// #[derive(Debug, Clone)]
/// struct Action;
/// #[derive(Debug, Clone)]
/// struct Ctx;
///
/// let editor_role = Uuid::new_v4();
///
/// let rbac = RbacPolicy::new(
///     // required_roles_resolver: which roles can access this resource/action?
///     move |_resource: &Resource, _action: &Action| vec![editor_role],
///     // user_roles_resolver: which roles does this user have?
///     |user: &User| user.role_ids.clone(),
/// );
///
/// let mut checker = PermissionChecker::new();
/// checker.add_policy(rbac);
///
/// # tokio_test::block_on(async {
/// let session = EvaluationSession::empty();
/// let authorised = User { role_ids: vec![editor_role] };
/// assert!(checker.evaluate_in_session(&session, &authorised, &Action, &Resource, &Ctx).await.is_granted());
///
/// let unauthorised = User { role_ids: vec![Uuid::new_v4()] };
/// assert!(!checker.evaluate_in_session(&session, &unauthorised, &Action, &Resource, &Ctx).await.is_granted());
/// # });
/// ```
pub struct RbacPolicy<S, F1, F2> {
    required_roles_resolver: F1,
    user_roles_resolver: F2,
    _marker: std::marker::PhantomData<S>,
}

impl<S, F1, F2> RbacPolicy<S, F1, F2> {
    /// Creates a new RBAC policy from two resolver closures.
    pub fn new(required_roles_resolver: F1, user_roles_resolver: F2) -> Self {
        Self {
            required_roles_resolver,
            user_roles_resolver,
            _marker: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<S, R, A, C, F1, F2> Policy<S, R, A, C> for RbacPolicy<S, F1, F2>
where
    S: Sync + Send,
    R: Sync + Send,
    A: Sync + Send,
    C: Sync + Send,
    F1: Fn(&R, &A) -> Vec<uuid::Uuid> + Sync + Send,
    F2: Fn(&S) -> Vec<uuid::Uuid> + Sync + Send,
{
    async fn evaluate(&self, ctx: &EvalCtx<'_, S, R, A, C>) -> PolicyEvalResult {
        let required_roles = (self.required_roles_resolver)(ctx.resource, ctx.action);
        let user_roles = (self.user_roles_resolver)(ctx.subject);
        let has_role = required_roles.iter().any(|role| user_roles.contains(role));

        if has_role {
            PolicyEvalResult::Granted {
                policy_type: Policy::<S, R, A, C>::policy_type(self).to_string(),
                reason: Some("User has required role".to_string()),
            }
        } else {
            PolicyEvalResult::Denied {
                policy_type: Policy::<S, R, A, C>::policy_type(self).to_string(),
                reason: "User doesn't have required role".to_string(),
            }
        }
    }

    fn policy_type(&self) -> &str {
        "RbacPolicy"
    }
}

/// An attribute-based access control policy.
/// Define a `condition` closure that determines whether a subject is allowed to
/// perform an action on a resource, given the additional context. If it returns
/// true, access is granted. Otherwise, access is denied.
///
/// ## Example
///
/// We define simple types for a user, a resource, an action, and a context.
/// We then create a built-in ABAC policy that grants access if the user "owns"
/// a resource as determined by the resource's owner_id.
///
/// ```rust
/// # use async_trait::async_trait;
/// # use std::sync::Arc;
/// # use uuid::Uuid;
/// # use gatehouse::*;
///
/// // Define our core types.
/// #[derive(Debug, Clone)]
/// struct User {
///     id: Uuid,
/// }
///
/// #[derive(Debug, Clone)]
/// struct Resource {
///     owner_id: Uuid,
/// }
///
/// #[derive(Debug, Clone)]
/// struct Action;
///
/// #[derive(Debug, Clone)]
/// struct EmptyContext;
///
/// // Create an ABAC policy.
/// // This policy grants access if the user's ID matches the resource's owner.
/// let abac_policy = AbacPolicy::new(
///     |user: &User, resource: &Resource, _action: &Action, _context: &EmptyContext| {
///         user.id == resource.owner_id
///     },
/// );
///
/// // Create a PermissionChecker and add the ABAC policy.
/// let mut checker = PermissionChecker::<User, Resource, Action, EmptyContext>::new();
/// checker.add_policy(abac_policy);
///
/// // Create a sample user
/// let user = User {
///     id: Uuid::new_v4(),
/// };
///
/// // Create a resource owned by the user, and one that is not
/// let owned_resource = Resource { owner_id: user.id };
/// let other_resource = Resource { owner_id: Uuid::new_v4() };
/// let context = EmptyContext;
/// let session = EvaluationSession::empty();
///
/// # tokio_test::block_on(async {
/// // This check should succeed because the user is the owner:
/// assert!(checker.evaluate_in_session(&session, &user, &Action, &owned_resource, &context).await.is_granted());
///
/// // This check should fail because the user is not the owner:
/// assert!(!checker.evaluate_in_session(&session, &user, &Action, &other_resource, &context).await.is_granted());
/// # });
/// ```
///
pub struct AbacPolicy<S, R, A, C, F> {
    condition: F,
    _marker: std::marker::PhantomData<(S, R, A, C)>,
}

impl<S, R, A, C, F> AbacPolicy<S, R, A, C, F> {
    /// Creates a new ABAC policy from a condition closure.
    pub fn new(condition: F) -> Self {
        Self {
            condition,
            _marker: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<S, R, A, C, F> Policy<S, R, A, C> for AbacPolicy<S, R, A, C, F>
where
    S: Sync + Send,
    R: Sync + Send,
    A: Sync + Send,
    C: Sync + Send,
    F: Fn(&S, &R, &A, &C) -> bool + Sync + Send,
{
    async fn evaluate(&self, ctx: &EvalCtx<'_, S, R, A, C>) -> PolicyEvalResult {
        let condition_met = (self.condition)(ctx.subject, ctx.resource, ctx.action, ctx.context);

        if condition_met {
            PolicyEvalResult::Granted {
                policy_type: self.policy_type().to_string(),
                reason: Some("Condition evaluated to true".to_string()),
            }
        } else {
            PolicyEvalResult::Denied {
                policy_type: self.policy_type().to_string(),
                reason: "Condition evaluated to false".to_string(),
            }
        }
    }

    fn policy_type(&self) -> &str {
        "AbacPolicy"
    }
}

/// ### ReBAC Policy
///
/// ReBAC is backed by [`FactSource`] in v0.3. A policy extracts flat,
/// hashable IDs from the subject and resource, builds a [`RelationshipQuery`],
/// then loads relationship facts through the request-scoped
/// [`EvaluationSession`].
///
/// ```rust
/// use async_trait::async_trait;
/// use std::collections::HashSet;
/// use uuid::Uuid;
/// use gatehouse::*;
///
/// #[derive(Debug, Clone)]
/// pub struct Employee { pub id: Uuid }
///
/// #[derive(Debug, Clone)]
/// pub struct Project { pub id: Uuid }
///
/// #[derive(Debug, Clone)]
/// pub struct AccessAction;
///
/// #[derive(Debug, Clone)]
/// pub struct EmptyContext;
///
/// struct ProjectRelationships {
///     grants: HashSet<RelationshipQuery<Uuid, Uuid, String>>,
/// }
///
/// #[async_trait]
/// impl FactSource<RelationshipQuery<Uuid, Uuid, String>> for ProjectRelationships {
///     async fn load_many(
///         &self,
///         keys: &[RelationshipQuery<Uuid, Uuid, String>],
///     ) -> Vec<FactLoadResult<bool>> {
///         keys.iter()
///             .map(|key| FactLoadResult::Found(self.grants.contains(key)))
///             .collect()
///     }
/// }
///
/// let manager = Employee { id: Uuid::new_v4() };
/// let project = Project { id: Uuid::new_v4() };
/// let relationship = "manager".to_string();
/// let grants = HashSet::from([RelationshipQuery {
///     subject_id: manager.id,
///     resource_id: project.id,
///     relation: relationship.clone(),
/// }]);
///
/// let session = EvaluationSession::new();
/// session.register::<RelationshipQuery<Uuid, Uuid, String>, _>(ProjectRelationships { grants });
///
/// let rebac_policy = RebacPolicy::new(
///     |employee: &Employee| employee.id,
///     |project: &Project| project.id,
///     relationship,
/// );
///
/// let mut checker = PermissionChecker::<Employee, Project, AccessAction, EmptyContext>::new();
/// checker.add_policy(rebac_policy);
///
/// # tokio_test::block_on(async {
/// assert!(checker
///     .evaluate_in_session(&session, &manager, &AccessAction, &project, &EmptyContext)
///     .await
///     .is_granted());
/// # });
/// ```
pub struct RebacPolicy<S, R, A, C, SubjectId, ResourceId, Relation> {
    subject_id: Arc<dyn Fn(&S) -> SubjectId + Send + Sync>,
    resource_id: Arc<dyn Fn(&R) -> ResourceId + Send + Sync>,
    relation: Relation,
    _marker: std::marker::PhantomData<(A, C)>,
}

impl<S, R, A, C, SubjectId, ResourceId, Relation>
    RebacPolicy<S, R, A, C, SubjectId, ResourceId, Relation>
{
    /// Creates a ReBAC policy from subject/resource ID extractors and a relation.
    pub fn new<SubjectIdFn, ResourceIdFn>(
        subject_id: SubjectIdFn,
        resource_id: ResourceIdFn,
        relation: Relation,
    ) -> Self
    where
        SubjectIdFn: Fn(&S) -> SubjectId + Send + Sync + 'static,
        ResourceIdFn: Fn(&R) -> ResourceId + Send + Sync + 'static,
    {
        Self {
            subject_id: Arc::new(subject_id),
            resource_id: Arc::new(resource_id),
            relation,
            _marker: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<S, R, A, C, SubjectId, ResourceId, Relation> Policy<S, R, A, C>
    for RebacPolicy<S, R, A, C, SubjectId, ResourceId, Relation>
where
    S: Sync + Send,
    R: Sync + Send,
    A: Sync + Send,
    C: Sync + Send,
    SubjectId: Eq + Hash + Clone + Send + Sync + 'static,
    ResourceId: Eq + Hash + Clone + Send + Sync + 'static,
    Relation: Eq + Hash + Clone + Send + Sync + fmt::Display + 'static,
{
    async fn evaluate(&self, ctx: &EvalCtx<'_, S, R, A, C>) -> PolicyEvalResult {
        let key = RelationshipQuery {
            subject_id: (self.subject_id)(ctx.subject),
            resource_id: (self.resource_id)(ctx.resource),
            relation: self.relation.clone(),
        };
        self.result_from_fact(ctx.session.get(key).await)
    }

    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, S, R, A, C>,
    ) -> Vec<PolicyEvalResult> {
        let keys = ctx
            .items
            .iter()
            .map(|item| RelationshipQuery {
                subject_id: (self.subject_id)(ctx.subject),
                resource_id: (self.resource_id)(item.resource),
                relation: self.relation.clone(),
            })
            .collect::<Vec<_>>();

        let facts = ctx.session.get_many(&keys).await;
        if facts.len() != ctx.items.len() {
            return ctx
                .items
                .iter()
                .map(|_| PolicyEvalResult::Denied {
                    policy_type: self.policy_type().to_string(),
                    reason: "Relationship fact source returned the wrong number of results"
                        .to_string(),
                })
                .collect();
        }

        facts
            .into_iter()
            .map(|fact| self.result_from_fact(fact))
            .collect()
    }

    fn policy_type(&self) -> &str {
        "RebacPolicy"
    }
}

impl<S, R, A, C, SubjectId, ResourceId, Relation>
    RebacPolicy<S, R, A, C, SubjectId, ResourceId, Relation>
where
    Relation: fmt::Display,
{
    fn result_from_fact(&self, fact: FactLoadResult<bool>) -> PolicyEvalResult {
        match fact {
            FactLoadResult::Found(true) => PolicyEvalResult::Granted {
                policy_type: "RebacPolicy".to_string(),
                reason: Some(format!(
                    "Subject has '{}' relationship with resource",
                    self.relation
                )),
            },
            FactLoadResult::Found(false) => PolicyEvalResult::Denied {
                policy_type: "RebacPolicy".to_string(),
                reason: format!(
                    "Subject does not have '{}' relationship with resource",
                    self.relation
                ),
            },
            FactLoadResult::Missing => PolicyEvalResult::Denied {
                policy_type: "RebacPolicy".to_string(),
                reason: format!("Relationship '{}' fact is missing", self.relation),
            },
            FactLoadResult::Error(error) => PolicyEvalResult::Denied {
                policy_type: "RebacPolicy".to_string(),
                reason: format!("Relationship '{}' fact load failed: {error}", self.relation),
            },
        }
    }
}

/// ---
/// Policy Combinators
/// ---
///
/// AndPolicy
///
/// Combines multiple policies with a logical AND. Access is granted only if every
/// inner policy grants access.
pub struct AndPolicy<S, R, A, C> {
    policies: Vec<Arc<dyn Policy<S, R, A, C>>>,
}

/// Error returned when no policies are provided to a combinator policy.
#[derive(Debug, Copy, Clone)]
pub struct EmptyPoliciesError(pub &'static str);

impl<S, R, A, C> AndPolicy<S, R, A, C> {
    /// Creates a new `AndPolicy` from a non-empty list of policies.
    ///
    /// Returns [`EmptyPoliciesError`] if `policies` is empty.
    pub fn try_new(policies: Vec<Arc<dyn Policy<S, R, A, C>>>) -> Result<Self, EmptyPoliciesError> {
        if policies.is_empty() {
            Err(EmptyPoliciesError(
                "AndPolicy must have at least one policy",
            ))
        } else {
            Ok(Self { policies })
        }
    }
}

#[async_trait]
impl<S, R, A, C> Policy<S, R, A, C> for AndPolicy<S, R, A, C>
where
    S: Sync + Send,
    R: Sync + Send,
    A: Sync + Send,
    C: Sync + Send,
{
    // Override the default policy_type implementation
    fn policy_type(&self) -> &str {
        "AndPolicy"
    }

    async fn evaluate(&self, ctx: &EvalCtx<'_, S, R, A, C>) -> PolicyEvalResult {
        let mut children_results = Vec::with_capacity(self.policies.len());

        for policy in &self.policies {
            let result = policy.evaluate(ctx).await;
            let is_granted = result.is_granted();
            children_results.push(result);

            // Short-circuit on first denial
            if !is_granted {
                return PolicyEvalResult::Combined {
                    policy_type: self.policy_type().to_string(),
                    operation: CombineOp::And,
                    children: children_results,
                    outcome: false,
                };
            }
        }

        // All policies granted access
        PolicyEvalResult::Combined {
            policy_type: self.policy_type().to_string(),
            operation: CombineOp::And,
            children: children_results,
            outcome: true,
        }
    }

    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, S, R, A, C>,
    ) -> Vec<PolicyEvalResult> {
        let mut children_by_item = vec![Vec::new(); ctx.items.len()];
        let mut results = vec![None; ctx.items.len()];
        let mut pending = (0..ctx.items.len()).collect::<Vec<_>>();

        for policy in &self.policies {
            if pending.is_empty() {
                break;
            }

            let batch_items = pending
                .iter()
                .map(|&index| PolicyBatchItem {
                    resource: ctx.items[index].resource,
                    context: ctx.items[index].context,
                })
                .collect::<Vec<_>>();
            let batch_ctx = BatchEvalCtx {
                session: ctx.session,
                subject: ctx.subject,
                action: ctx.action,
                items: &batch_items,
            };
            let child_results = policy.evaluate_batch(&batch_ctx).await;

            if child_results.len() != pending.len() {
                for index in pending.drain(..) {
                    children_by_item[index].push(PolicyEvalResult::Denied {
                        policy_type: policy.policy_type().to_string(),
                        reason: "Policy batch result count did not match input count".to_string(),
                    });
                    results[index] = Some(PolicyEvalResult::Combined {
                        policy_type: self.policy_type().to_string(),
                        operation: CombineOp::And,
                        children: std::mem::take(&mut children_by_item[index]),
                        outcome: false,
                    });
                }
                break;
            }

            let mut still_pending = Vec::new();
            for (index, child_result) in pending.into_iter().zip(child_results) {
                let is_granted = child_result.is_granted();
                children_by_item[index].push(child_result);

                if is_granted {
                    still_pending.push(index);
                } else {
                    results[index] = Some(PolicyEvalResult::Combined {
                        policy_type: self.policy_type().to_string(),
                        operation: CombineOp::And,
                        children: std::mem::take(&mut children_by_item[index]),
                        outcome: false,
                    });
                }
            }
            pending = still_pending;
        }

        for index in pending {
            results[index] = Some(PolicyEvalResult::Combined {
                policy_type: self.policy_type().to_string(),
                operation: CombineOp::And,
                children: std::mem::take(&mut children_by_item[index]),
                outcome: true,
            });
        }

        results
            .into_iter()
            .map(|result| {
                result.unwrap_or_else(|| PolicyEvalResult::Denied {
                    policy_type: self.policy_type().to_string(),
                    reason: "Batch item was not evaluated".to_string(),
                })
            })
            .collect()
    }
}

/// OrPolicy
///
/// Combines multiple policies with a logical OR. Access is granted if any inner policy
/// grants access.
pub struct OrPolicy<S, R, A, C> {
    policies: Vec<Arc<dyn Policy<S, R, A, C>>>,
}

impl<S, R, A, C> OrPolicy<S, R, A, C> {
    /// Creates a new `OrPolicy` from a non-empty list of policies.
    ///
    /// Returns [`EmptyPoliciesError`] if `policies` is empty.
    pub fn try_new(policies: Vec<Arc<dyn Policy<S, R, A, C>>>) -> Result<Self, EmptyPoliciesError> {
        if policies.is_empty() {
            Err(EmptyPoliciesError("OrPolicy must have at least one policy"))
        } else {
            Ok(Self { policies })
        }
    }
}

#[async_trait]
impl<S, R, A, C> Policy<S, R, A, C> for OrPolicy<S, R, A, C>
where
    S: Sync + Send,
    R: Sync + Send,
    A: Sync + Send,
    C: Sync + Send,
{
    // Override the default policy_type implementation
    fn policy_type(&self) -> &str {
        "OrPolicy"
    }
    async fn evaluate(&self, ctx: &EvalCtx<'_, S, R, A, C>) -> PolicyEvalResult {
        let mut children_results = Vec::with_capacity(self.policies.len());

        for policy in &self.policies {
            let result = policy.evaluate(ctx).await;
            let is_granted = result.is_granted();
            children_results.push(result);

            // Short-circuit on first success
            if is_granted {
                return PolicyEvalResult::Combined {
                    policy_type: self.policy_type().to_string(),
                    operation: CombineOp::Or,
                    children: children_results,
                    outcome: true,
                };
            }
        }

        // All policies denied access
        PolicyEvalResult::Combined {
            policy_type: self.policy_type().to_string(),
            operation: CombineOp::Or,
            children: children_results,
            outcome: false,
        }
    }

    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, S, R, A, C>,
    ) -> Vec<PolicyEvalResult> {
        let mut children_by_item = vec![Vec::new(); ctx.items.len()];
        let mut results = vec![None; ctx.items.len()];
        let mut pending = (0..ctx.items.len()).collect::<Vec<_>>();

        for policy in &self.policies {
            if pending.is_empty() {
                break;
            }

            let batch_items = pending
                .iter()
                .map(|&index| PolicyBatchItem {
                    resource: ctx.items[index].resource,
                    context: ctx.items[index].context,
                })
                .collect::<Vec<_>>();
            let batch_ctx = BatchEvalCtx {
                session: ctx.session,
                subject: ctx.subject,
                action: ctx.action,
                items: &batch_items,
            };
            let child_results = policy.evaluate_batch(&batch_ctx).await;

            if child_results.len() != pending.len() {
                for index in pending.drain(..) {
                    children_by_item[index].push(PolicyEvalResult::Denied {
                        policy_type: policy.policy_type().to_string(),
                        reason: "Policy batch result count did not match input count".to_string(),
                    });
                    results[index] = Some(PolicyEvalResult::Combined {
                        policy_type: self.policy_type().to_string(),
                        operation: CombineOp::Or,
                        children: std::mem::take(&mut children_by_item[index]),
                        outcome: false,
                    });
                }
                break;
            }

            let mut still_pending = Vec::new();
            for (index, child_result) in pending.into_iter().zip(child_results) {
                let is_granted = child_result.is_granted();
                children_by_item[index].push(child_result);

                if is_granted {
                    results[index] = Some(PolicyEvalResult::Combined {
                        policy_type: self.policy_type().to_string(),
                        operation: CombineOp::Or,
                        children: std::mem::take(&mut children_by_item[index]),
                        outcome: true,
                    });
                } else {
                    still_pending.push(index);
                }
            }
            pending = still_pending;
        }

        for index in pending {
            results[index] = Some(PolicyEvalResult::Combined {
                policy_type: self.policy_type().to_string(),
                operation: CombineOp::Or,
                children: std::mem::take(&mut children_by_item[index]),
                outcome: false,
            });
        }

        results
            .into_iter()
            .map(|result| {
                result.unwrap_or_else(|| PolicyEvalResult::Denied {
                    policy_type: self.policy_type().to_string(),
                    reason: "Batch item was not evaluated".to_string(),
                })
            })
            .collect()
    }
}

/// NotPolicy
///
/// Inverts the result of an inner policy. If the inner policy allows access, then NotPolicy
/// denies it, and vice versa.
pub struct NotPolicy<S, R, A, C> {
    policy: Arc<dyn Policy<S, R, A, C>>,
}

impl<S, R, A, C> NotPolicy<S, R, A, C>
where
    S: Sync,
    R: Sync,
    A: Sync,
    C: Sync,
{
    /// Creates a new `NotPolicy` that inverts the given policy's decision.
    pub fn new(policy: impl Policy<S, R, A, C> + 'static) -> Self {
        Self {
            policy: Arc::new(policy),
        }
    }
}

#[async_trait]
impl<S, R, A, C> Policy<S, R, A, C> for NotPolicy<S, R, A, C>
where
    S: Sync + Send,
    R: Sync + Send,
    A: Sync + Send,
    C: Sync + Send,
{
    // Override the default policy_type implementation
    fn policy_type(&self) -> &str {
        "NotPolicy"
    }

    async fn evaluate(&self, ctx: &EvalCtx<'_, S, R, A, C>) -> PolicyEvalResult {
        let inner_result = self.policy.evaluate(ctx).await;
        let is_granted = inner_result.is_granted();

        PolicyEvalResult::Combined {
            policy_type: Policy::<S, R, A, C>::policy_type(self).to_string(),
            operation: CombineOp::Not,
            children: vec![inner_result],
            outcome: !is_granted,
        }
    }

    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, S, R, A, C>,
    ) -> Vec<PolicyEvalResult> {
        let inner_results = self.policy.evaluate_batch(ctx).await;

        if inner_results.len() != ctx.items.len() {
            return ctx
                .items
                .iter()
                .map(|_| PolicyEvalResult::Denied {
                    policy_type: self.policy_type().to_string(),
                    reason: "Policy batch result count did not match input count".to_string(),
                })
                .collect();
        }

        inner_results
            .into_iter()
            .map(|inner_result| {
                let is_granted = inner_result.is_granted();
                PolicyEvalResult::Combined {
                    policy_type: self.policy_type().to_string(),
                    operation: CombineOp::Not,
                    children: vec![inner_result],
                    outcome: !is_granted,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashSet};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc as StdArc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing::{Event, Subscriber};
    use tracing_subscriber::layer::{Context, Layer};
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::Registry;

    trait TestPolicyExt<S, R, A, C>: Policy<S, R, A, C>
    where
        S: Send + Sync,
        R: Send + Sync,
        A: Send + Sync,
        C: Send + Sync,
    {
        fn evaluate_access<'a>(
            &'a self,
            subject: &'a S,
            action: &'a A,
            resource: &'a R,
            context: &'a C,
        ) -> Pin<Box<dyn Future<Output = PolicyEvalResult> + Send + 'a>>;

        fn evaluate_access_batch<'a>(
            &'a self,
            subject: &'a S,
            action: &'a A,
            items: &'a [PolicyBatchItem<'a, R, C>],
        ) -> Pin<Box<dyn Future<Output = Vec<PolicyEvalResult>> + Send + 'a>>;
    }

    impl<T, S, R, A, C> TestPolicyExt<S, R, A, C> for T
    where
        T: Policy<S, R, A, C>,
        S: Send + Sync,
        R: Send + Sync,
        A: Send + Sync,
        C: Send + Sync,
    {
        fn evaluate_access<'a>(
            &'a self,
            subject: &'a S,
            action: &'a A,
            resource: &'a R,
            context: &'a C,
        ) -> Pin<Box<dyn Future<Output = PolicyEvalResult> + Send + 'a>> {
            Box::pin(async move {
                let session = EvaluationSession::new();
                let ctx = EvalCtx {
                    session: &session,
                    subject,
                    action,
                    resource,
                    context,
                };
                self.evaluate(&ctx).await
            })
        }

        fn evaluate_access_batch<'a>(
            &'a self,
            subject: &'a S,
            action: &'a A,
            items: &'a [PolicyBatchItem<'a, R, C>],
        ) -> Pin<Box<dyn Future<Output = Vec<PolicyEvalResult>> + Send + 'a>> {
            Box::pin(async move {
                let session = EvaluationSession::new();
                let ctx = BatchEvalCtx {
                    session: &session,
                    subject,
                    action,
                    items,
                };
                self.evaluate_batch(&ctx).await
            })
        }
    }

    trait TestCheckerExt<S, R, A, C>
    where
        S: Sync,
        R: Sync,
        A: Sync,
        C: Sync,
    {
        fn evaluate_access<'a>(
            &'a self,
            subject: &'a S,
            action: &'a A,
            resource: &'a R,
            context: &'a C,
        ) -> Pin<Box<dyn Future<Output = AccessEvaluation> + Send + 'a>>;

        fn evaluate_batch_by<'a, I, F>(
            &'a self,
            subject: &'a S,
            action: &'a A,
            items: I,
            parts: F,
        ) -> Pin<Box<dyn Future<Output = Vec<(I::Item, AccessEvaluation)>> + Send + 'a>>
        where
            I: IntoIterator + Send + 'a,
            I::Item: Send + 'a,
            F: for<'item> Fn(&'item I::Item) -> (&'item R, &'item C) + Send + 'a;

        fn filter_authorized_by<'a, I, F>(
            &'a self,
            subject: &'a S,
            action: &'a A,
            items: I,
            parts: F,
        ) -> Pin<Box<dyn Future<Output = Vec<I::Item>> + Send + 'a>>
        where
            I: IntoIterator + Send + 'a,
            I::Item: Send + 'a,
            F: for<'item> Fn(&'item I::Item) -> (&'item R, &'item C) + Send + 'a;
    }

    impl<S, R, A, C> TestCheckerExt<S, R, A, C> for PermissionChecker<S, R, A, C>
    where
        S: Sync,
        R: Sync,
        A: Sync,
        C: Sync,
    {
        fn evaluate_access<'a>(
            &'a self,
            subject: &'a S,
            action: &'a A,
            resource: &'a R,
            context: &'a C,
        ) -> Pin<Box<dyn Future<Output = AccessEvaluation> + Send + 'a>> {
            Box::pin(async move {
                let session = EvaluationSession::empty();
                self.evaluate_in_session(&session, subject, action, resource, context)
                    .await
            })
        }

        fn evaluate_batch_by<'a, I, F>(
            &'a self,
            subject: &'a S,
            action: &'a A,
            items: I,
            parts: F,
        ) -> Pin<Box<dyn Future<Output = Vec<(I::Item, AccessEvaluation)>> + Send + 'a>>
        where
            I: IntoIterator + Send + 'a,
            I::Item: Send + 'a,
            F: for<'item> Fn(&'item I::Item) -> (&'item R, &'item C) + Send + 'a,
        {
            Box::pin(async move {
                let session = EvaluationSession::empty();
                self.evaluate_batch_in_session_by(&session, subject, action, items, parts)
                    .await
            })
        }

        fn filter_authorized_by<'a, I, F>(
            &'a self,
            subject: &'a S,
            action: &'a A,
            items: I,
            parts: F,
        ) -> Pin<Box<dyn Future<Output = Vec<I::Item>> + Send + 'a>>
        where
            I: IntoIterator + Send + 'a,
            I::Item: Send + 'a,
            F: for<'item> Fn(&'item I::Item) -> (&'item R, &'item C) + Send + 'a,
        {
            Box::pin(async move {
                let session = EvaluationSession::empty();
                self.filter_authorized_in_session_by(&session, subject, action, items, parts)
                    .await
            })
        }
    }
    // Dummy resource/action/context types for testing
    #[derive(Debug, Clone)]
    pub struct TestSubject {
        pub id: uuid::Uuid,
    }

    #[derive(Debug, Clone)]
    pub struct TestResource {
        pub id: uuid::Uuid,
    }

    #[derive(Debug, Clone)]
    pub struct TestAction;

    #[derive(Debug, Clone)]
    pub struct TestContext;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RecordedEvent {
        target: String,
        fields: BTreeMap<String, String>,
    }

    #[derive(Default)]
    struct FieldRecorder {
        fields: BTreeMap<String, String>,
    }

    impl Visit for FieldRecorder {
        fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
            self.fields
                .insert(field.name().to_string(), format!("{value:?}"));
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_bool(&mut self, field: &Field, value: bool) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_i64(&mut self, field: &Field, value: i64) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_u64(&mut self, field: &Field, value: u64) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }
    }

    #[derive(Clone, Default)]
    struct EventRecorder {
        events: StdArc<Mutex<Vec<RecordedEvent>>>,
    }

    impl<S> Layer<S> for EventRecorder
    where
        S: Subscriber,
    {
        fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
            let mut visitor = FieldRecorder::default();
            event.record(&mut visitor);

            self.events
                .lock()
                .expect("events mutex poisoned")
                .push(RecordedEvent {
                    target: event.metadata().target().to_string(),
                    fields: visitor.fields,
                });
        }
    }

    fn with_recorded_events<T>(f: impl FnOnce() -> T) -> (T, Vec<RecordedEvent>) {
        let recorder = EventRecorder::default();
        let events = recorder.events.clone();
        let subscriber = Registry::default().with(recorder);
        let result = tracing::subscriber::with_default(subscriber, f);
        let events = events.lock().expect("events mutex poisoned").clone();
        (result, events)
    }

    fn security_events(events: &[RecordedEvent]) -> Vec<&RecordedEvent> {
        events
            .iter()
            .filter(|event| event.target == "gatehouse::security")
            .collect()
    }

    #[test]
    fn security_rule_metadata_builder_sets_fields() {
        let metadata = SecurityRuleMetadata::new()
            .with_name("Example")
            .with_category("Access Control")
            .with_description("Example description")
            .with_reference("https://example.com/rule")
            .with_ruleset_name("ExampleRuleset")
            .with_uuid("1234")
            .with_version("1.0.0")
            .with_license("Apache-2.0");

        assert_eq!(metadata.name(), Some("Example"));
        assert_eq!(metadata.category(), Some("Access Control"));
        assert_eq!(metadata.description(), Some("Example description"));
        assert_eq!(metadata.reference(), Some("https://example.com/rule"));
        assert_eq!(metadata.ruleset_name(), Some("ExampleRuleset"));
        assert_eq!(metadata.uuid(), Some("1234"));
        assert_eq!(metadata.version(), Some("1.0.0"));
        assert_eq!(metadata.license(), Some("Apache-2.0"));
    }

    // A policy that always allows
    struct AlwaysAllowPolicy;

    #[async_trait]
    impl Policy<TestSubject, TestResource, TestAction, TestContext> for AlwaysAllowPolicy {
        async fn evaluate(
            &self,
            _ctx: &EvalCtx<'_, TestSubject, TestResource, TestAction, TestContext>,
        ) -> PolicyEvalResult {
            PolicyEvalResult::Granted {
                policy_type: self.policy_type().to_string(),
                reason: Some("Always allow policy".to_string()),
            }
        }

        fn policy_type(&self) -> &str {
            "AlwaysAllowPolicy"
        }
    }

    // A policy that always denies, with a custom reason
    struct AlwaysDenyPolicy(&'static str);

    #[async_trait]
    impl Policy<TestSubject, TestResource, TestAction, TestContext> for AlwaysDenyPolicy {
        async fn evaluate(
            &self,
            _ctx: &EvalCtx<'_, TestSubject, TestResource, TestAction, TestContext>,
        ) -> PolicyEvalResult {
            PolicyEvalResult::Denied {
                policy_type: self.policy_type().to_string(),
                reason: self.0.to_string(),
            }
        }

        fn policy_type(&self) -> &str {
            "AlwaysDenyPolicy"
        }
    }

    struct EvenResourceBatchPolicy {
        batch_calls: Arc<AtomicUsize>,
        single_calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Policy<TestSubject, TestResource, TestAction, TestContext> for EvenResourceBatchPolicy {
        async fn evaluate(
            &self,
            ctx: &EvalCtx<'_, TestSubject, TestResource, TestAction, TestContext>,
        ) -> PolicyEvalResult {
            self.single_calls.fetch_add(1, Ordering::SeqCst);
            if ctx.resource.id.as_u128().is_multiple_of(2) {
                PolicyEvalResult::Granted {
                    policy_type: self.policy_type().to_string(),
                    reason: Some("even resource".to_string()),
                }
            } else {
                PolicyEvalResult::Denied {
                    policy_type: self.policy_type().to_string(),
                    reason: "odd resource".to_string(),
                }
            }
        }

        async fn evaluate_batch<'item>(
            &self,
            ctx: &BatchEvalCtx<'item, TestSubject, TestResource, TestAction, TestContext>,
        ) -> Vec<PolicyEvalResult> {
            self.batch_calls.fetch_add(1, Ordering::SeqCst);
            let mut results = Vec::with_capacity(ctx.items.len());
            for item in ctx.items {
                let item_ctx = EvalCtx {
                    session: ctx.session,
                    subject: ctx.subject,
                    action: ctx.action,
                    resource: item.resource,
                    context: item.context,
                };
                results.push(self.evaluate(&item_ctx).await);
            }
            results
        }

        fn policy_type(&self) -> &str {
            "EvenResourceBatchPolicy"
        }
    }

    struct MismatchedBatchPolicy;

    #[async_trait]
    impl Policy<TestSubject, TestResource, TestAction, TestContext> for MismatchedBatchPolicy {
        async fn evaluate(
            &self,
            _ctx: &EvalCtx<'_, TestSubject, TestResource, TestAction, TestContext>,
        ) -> PolicyEvalResult {
            PolicyEvalResult::Granted {
                policy_type: self.policy_type().to_string(),
                reason: Some("single item fallback".to_string()),
            }
        }

        async fn evaluate_batch<'item>(
            &self,
            ctx: &BatchEvalCtx<'item, TestSubject, TestResource, TestAction, TestContext>,
        ) -> Vec<PolicyEvalResult> {
            ctx.items
                .iter()
                .skip(1)
                .map(|_| PolicyEvalResult::Granted {
                    policy_type: self.policy_type().to_string(),
                    reason: Some("wrong batch length".to_string()),
                })
                .collect()
        }

        fn policy_type(&self) -> &str {
            "MismatchedBatchPolicy"
        }
    }

    struct CustomMetadataDenyPolicy;

    #[async_trait]
    impl Policy<TestSubject, TestResource, TestAction, TestContext> for CustomMetadataDenyPolicy {
        async fn evaluate(
            &self,
            _ctx: &EvalCtx<'_, TestSubject, TestResource, TestAction, TestContext>,
        ) -> PolicyEvalResult {
            PolicyEvalResult::Denied {
                policy_type: self.policy_type().to_string(),
                reason: "Blocked by custom rule".to_string(),
            }
        }

        fn policy_type(&self) -> &str {
            "CustomMetadataDenyPolicy"
        }

        fn security_rule(&self) -> SecurityRuleMetadata {
            SecurityRuleMetadata::new()
                .with_name("CustomRuleName")
                .with_category("Policy")
                .with_description("Description from metadata")
                .with_reference("https://example.com/rule")
                .with_ruleset_name("CustomRuleset")
                .with_uuid("rule-123")
                .with_version("2026.03")
                .with_license("MIT")
        }
    }

    #[tokio::test]
    async fn test_no_policies() {
        let checker =
            PermissionChecker::<TestSubject, TestResource, TestAction, TestContext>::new();

        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };
        let result = checker
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;

        match result {
            AccessEvaluation::Denied { reason, trace: _ } => {
                assert!(reason.contains("No policies configured"));
            }
            _ => panic!("Expected Denied(No policies configured), got {:?}", result),
        }
    }

    #[tokio::test]
    async fn test_evaluate_batch_by_matches_single_item_loop() {
        let batch_calls = Arc::new(AtomicUsize::new(0));
        let single_calls = Arc::new(AtomicUsize::new(0));
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resources = (0..8)
            .map(|value| TestResource {
                id: uuid::Uuid::from_u128(value),
            })
            .collect::<Vec<_>>();

        let mut checker = PermissionChecker::new();
        checker.add_policy(EvenResourceBatchPolicy {
            batch_calls: Arc::clone(&batch_calls),
            single_calls: Arc::clone(&single_calls),
        });

        let mut loop_results = Vec::new();
        for resource in &resources {
            loop_results.push(
                checker
                    .evaluate_access(&subject, &TestAction, resource, &TestContext)
                    .await
                    .is_granted(),
            );
        }

        let batch_items = resources
            .clone()
            .into_iter()
            .map(|resource| (resource, TestContext))
            .collect::<Vec<_>>();
        let batch_results = checker
            .evaluate_batch_by(&subject, &TestAction, batch_items, |item| {
                (&item.0, &item.1)
            })
            .await
            .into_iter()
            .map(|(_item, evaluation)| evaluation.is_granted())
            .collect::<Vec<_>>();

        assert_eq!(loop_results, batch_results);
        assert_eq!(batch_calls.load(Ordering::SeqCst), 1);
        assert_eq!(single_calls.load(Ordering::SeqCst), 16);
    }

    #[tokio::test]
    async fn test_filter_authorized_by_preserves_authorized_items_in_order() {
        let batch_calls = Arc::new(AtomicUsize::new(0));
        let single_calls = Arc::new(AtomicUsize::new(0));
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resources = vec![
            TestResource {
                id: uuid::Uuid::from_u128(3),
            },
            TestResource {
                id: uuid::Uuid::from_u128(2),
            },
            TestResource {
                id: uuid::Uuid::from_u128(4),
            },
            TestResource {
                id: uuid::Uuid::from_u128(5),
            },
        ];

        let mut checker = PermissionChecker::new();
        checker.add_policy(EvenResourceBatchPolicy {
            batch_calls,
            single_calls,
        });

        let batch_items = resources
            .into_iter()
            .map(|resource| (resource, TestContext))
            .collect::<Vec<_>>();
        let authorized = checker
            .filter_authorized_by(&subject, &TestAction, batch_items, |item| {
                (&item.0, &item.1)
            })
            .await;

        assert_eq!(
            authorized
                .into_iter()
                .map(|(resource, _context)| resource.id.as_u128())
                .collect::<Vec<_>>(),
            vec![2, 4]
        );
    }

    #[tokio::test]
    async fn test_evaluate_batch_by_respects_max_batch_size() {
        let batch_calls = Arc::new(AtomicUsize::new(0));
        let single_calls = Arc::new(AtomicUsize::new(0));
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resources = (0..8)
            .map(|value| {
                (
                    TestResource {
                        id: uuid::Uuid::from_u128(value),
                    },
                    TestContext,
                )
            })
            .collect::<Vec<_>>();

        let mut checker =
            PermissionChecker::new().with_max_batch_size(NonZeroUsize::new(3).unwrap());
        checker.add_policy(EvenResourceBatchPolicy {
            batch_calls: Arc::clone(&batch_calls),
            single_calls: Arc::clone(&single_calls),
        });

        let results = checker
            .filter_authorized_by(&subject, &TestAction, resources, |item| (&item.0, &item.1))
            .await;

        assert_eq!(
            results
                .into_iter()
                .map(|(resource, _context)| resource.id.as_u128())
                .collect::<Vec<_>>(),
            vec![0, 2, 4, 6]
        );
        assert_eq!(batch_calls.load(Ordering::SeqCst), 3);
        assert_eq!(single_calls.load(Ordering::SeqCst), 8);
    }

    #[tokio::test]
    async fn test_evaluate_batch_by_invokes_parts_once_per_item() {
        let parts_calls = Arc::new(AtomicUsize::new(0));
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resources = (0..4)
            .map(|value| {
                (
                    TestResource {
                        id: uuid::Uuid::from_u128(value),
                    },
                    TestContext,
                )
            })
            .collect::<Vec<_>>();

        let mut checker = PermissionChecker::new();
        checker.add_policy(AlwaysDenyPolicy("first denial"));
        checker.add_policy(AlwaysDenyPolicy("second denial"));

        let results = checker
            .evaluate_batch_by(&subject, &TestAction, resources, |item| {
                parts_calls.fetch_add(1, Ordering::SeqCst);
                (&item.0, &item.1)
            })
            .await;

        assert_eq!(results.len(), 4);
        assert!(results
            .iter()
            .all(|(_item, evaluation)| !evaluation.is_granted()));
        assert_eq!(parts_calls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn test_evaluate_batch_by_fails_closed_on_policy_length_mismatch() {
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resources = (0..3)
            .map(|value| {
                (
                    TestResource {
                        id: uuid::Uuid::from_u128(value),
                    },
                    TestContext,
                )
            })
            .collect::<Vec<_>>();

        let mut checker = PermissionChecker::new();
        checker.add_policy(MismatchedBatchPolicy);
        checker.add_policy(AlwaysAllowPolicy);

        let results = checker
            .evaluate_batch_by(&subject, &TestAction, resources, |item| (&item.0, &item.1))
            .await;

        assert_eq!(results.len(), 3);
        for (_item, evaluation) in results {
            assert!(!evaluation.is_granted());
            match evaluation {
                AccessEvaluation::Denied { reason, trace } => {
                    assert_eq!(
                        reason,
                        "Policy batch result count did not match input count"
                    );
                    assert!(trace.format().contains("MismatchedBatchPolicy"));
                }
                AccessEvaluation::Granted { .. } => {
                    panic!("mismatched batch result should fail closed");
                }
            }
        }
    }

    #[tokio::test]
    async fn test_and_policy_batch_uses_inner_batch_hook() {
        let batch_calls = Arc::new(AtomicUsize::new(0));
        let single_calls = Arc::new(AtomicUsize::new(0));
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resources = (0..4)
            .map(|value| {
                (
                    TestResource {
                        id: uuid::Uuid::from_u128(value),
                    },
                    TestContext,
                )
            })
            .collect::<Vec<_>>();
        let inner: Arc<dyn Policy<TestSubject, TestResource, TestAction, TestContext>> =
            Arc::new(EvenResourceBatchPolicy {
                batch_calls: Arc::clone(&batch_calls),
                single_calls: Arc::clone(&single_calls),
            });
        let policy = AndPolicy::try_new(vec![inner]).unwrap();
        let mut checker = PermissionChecker::new();
        checker.add_policy(policy);

        let authorized = checker
            .filter_authorized_by(&subject, &TestAction, resources, |item| (&item.0, &item.1))
            .await;

        assert_eq!(authorized.len(), 2);
        assert_eq!(batch_calls.load(Ordering::SeqCst), 1);
        assert_eq!(single_calls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn test_and_policy_batch_fails_closed_on_inner_length_mismatch() {
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let owned_items = (0..2)
            .map(|value| {
                (
                    TestResource {
                        id: uuid::Uuid::from_u128(value),
                    },
                    TestContext,
                )
            })
            .collect::<Vec<_>>();
        let batch_items = owned_items
            .iter()
            .map(|(resource, context)| PolicyBatchItem { resource, context })
            .collect::<Vec<_>>();
        let inner: Arc<dyn Policy<TestSubject, TestResource, TestAction, TestContext>> =
            Arc::new(MismatchedBatchPolicy);
        let policy = AndPolicy::try_new(vec![inner]).unwrap();

        let results = policy
            .evaluate_access_batch(&subject, &TestAction, &batch_items)
            .await;

        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|result| !result.is_granted()));
        assert!(results
            .iter()
            .all(|result| result.format(0).contains("MismatchedBatchPolicy")));
    }

    #[tokio::test]
    async fn test_or_policy_batch_uses_inner_batch_hook() {
        let batch_calls = Arc::new(AtomicUsize::new(0));
        let single_calls = Arc::new(AtomicUsize::new(0));
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resources = (0..4)
            .map(|value| {
                (
                    TestResource {
                        id: uuid::Uuid::from_u128(value),
                    },
                    TestContext,
                )
            })
            .collect::<Vec<_>>();
        let inner: Arc<dyn Policy<TestSubject, TestResource, TestAction, TestContext>> =
            Arc::new(EvenResourceBatchPolicy {
                batch_calls: Arc::clone(&batch_calls),
                single_calls: Arc::clone(&single_calls),
            });
        let policy = OrPolicy::try_new(vec![inner]).unwrap();
        let mut checker = PermissionChecker::new();
        checker.add_policy(policy);

        let authorized = checker
            .filter_authorized_by(&subject, &TestAction, resources, |item| (&item.0, &item.1))
            .await;

        assert_eq!(authorized.len(), 2);
        assert_eq!(batch_calls.load(Ordering::SeqCst), 1);
        assert_eq!(single_calls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn test_or_policy_batch_fails_closed_on_inner_length_mismatch() {
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let owned_items = (0..2)
            .map(|value| {
                (
                    TestResource {
                        id: uuid::Uuid::from_u128(value),
                    },
                    TestContext,
                )
            })
            .collect::<Vec<_>>();
        let batch_items = owned_items
            .iter()
            .map(|(resource, context)| PolicyBatchItem { resource, context })
            .collect::<Vec<_>>();
        let inner: Arc<dyn Policy<TestSubject, TestResource, TestAction, TestContext>> =
            Arc::new(MismatchedBatchPolicy);
        let policy = OrPolicy::try_new(vec![inner]).unwrap();

        let results = policy
            .evaluate_access_batch(&subject, &TestAction, &batch_items)
            .await;

        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|result| !result.is_granted()));
        assert!(results
            .iter()
            .all(|result| result.format(0).contains("MismatchedBatchPolicy")));
    }

    #[tokio::test]
    async fn test_not_policy_batch_uses_inner_batch_hook() {
        let batch_calls = Arc::new(AtomicUsize::new(0));
        let single_calls = Arc::new(AtomicUsize::new(0));
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resources = (0..4)
            .map(|value| {
                (
                    TestResource {
                        id: uuid::Uuid::from_u128(value),
                    },
                    TestContext,
                )
            })
            .collect::<Vec<_>>();
        let policy = NotPolicy::new(EvenResourceBatchPolicy {
            batch_calls: Arc::clone(&batch_calls),
            single_calls: Arc::clone(&single_calls),
        });
        let mut checker = PermissionChecker::new();
        checker.add_policy(policy);

        let authorized = checker
            .filter_authorized_by(&subject, &TestAction, resources, |item| (&item.0, &item.1))
            .await;

        assert_eq!(authorized.len(), 2);
        assert_eq!(batch_calls.load(Ordering::SeqCst), 1);
        assert_eq!(single_calls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn test_not_policy_batch_fails_closed_on_inner_length_mismatch() {
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let owned_items = (0..2)
            .map(|value| {
                (
                    TestResource {
                        id: uuid::Uuid::from_u128(value),
                    },
                    TestContext,
                )
            })
            .collect::<Vec<_>>();
        let batch_items = owned_items
            .iter()
            .map(|(resource, context)| PolicyBatchItem { resource, context })
            .collect::<Vec<_>>();
        let policy = NotPolicy::new(MismatchedBatchPolicy);

        let results = policy
            .evaluate_access_batch(&subject, &TestAction, &batch_items)
            .await;

        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|result| !result.is_granted()));
        assert!(results.iter().all(|result| {
            result
                .reason()
                .as_deref()
                .is_some_and(|reason| reason.contains("batch result count"))
        }));
    }

    #[tokio::test]
    async fn test_one_policy_allow() {
        let mut checker = PermissionChecker::new();
        checker.add_policy(AlwaysAllowPolicy);

        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        let result = checker
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;

        if let AccessEvaluation::Granted {
            policy_type,
            reason,
            trace,
        } = result
        {
            assert_eq!(policy_type, "AlwaysAllowPolicy");
            assert_eq!(reason, Some("Always allow policy".to_string()));
            // Check the trace to ensure the policy was evaluated
            let trace_str = trace.format();
            assert!(trace_str.contains("AlwaysAllowPolicy"));
        } else {
            panic!("Expected AccessEvaluation::Granted, got {:?}", result);
        }
    }

    #[tokio::test]
    async fn test_one_policy_deny() {
        let mut checker = PermissionChecker::new();
        checker.add_policy(AlwaysDenyPolicy("DeniedByPolicy"));

        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        let result = checker
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;

        assert!(!result.is_granted());
        if let AccessEvaluation::Denied { reason, trace } = result {
            assert!(reason.contains("All policies denied access"));
            let trace_str = trace.format();
            assert!(trace_str.contains("DeniedByPolicy"));
        } else {
            panic!("Expected AccessEvaluation::Denied, got {:?}", result);
        }
    }

    #[tokio::test]
    async fn test_multiple_policies_or_success() {
        // First policy denies, second allows. Checker should return Ok, short-circuiting on second.
        let mut checker = PermissionChecker::new();
        checker.add_policy(AlwaysDenyPolicy("DenyPolicy"));
        checker.add_policy(AlwaysAllowPolicy);

        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };
        let result = checker
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;
        if let AccessEvaluation::Granted {
            policy_type,
            trace,
            reason: _,
        } = result
        {
            assert_eq!(policy_type, "AlwaysAllowPolicy");
            let trace_str = trace.format();
            assert!(trace_str.contains("DenyPolicy"));
        } else {
            panic!("Expected AccessEvaluation::Granted, got {:?}", result);
        }
    }

    #[tokio::test]
    async fn test_multiple_policies_all_deny_collect_reasons() {
        // Both policies deny, so we expect a Forbidden
        let mut checker = PermissionChecker::new();
        checker.add_policy(AlwaysDenyPolicy("DenyPolicy1"));
        checker.add_policy(AlwaysDenyPolicy("DenyPolicy2"));

        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };
        let result = checker
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;

        if let AccessEvaluation::Denied { trace, reason } = result {
            let trace_str = trace.format();
            assert!(trace_str.contains("DenyPolicy1"));
            assert!(trace_str.contains("DenyPolicy2"));
            assert_eq!(reason, "All policies denied access");
        } else {
            panic!("Expected AccessEvaluation::Denied, got {:?}", result);
        }
    }

    #[tokio::test]
    async fn test_permission_checker_trace_omits_unevaluated_policies_after_grant() {
        let mut checker = PermissionChecker::new();
        checker.add_policy(AlwaysAllowPolicy);
        checker.add_policy(AlwaysDenyPolicy("ShouldNotAppear"));

        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        let result = checker
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;

        let trace = match result {
            AccessEvaluation::Granted { trace, .. } => trace,
            other => panic!("Expected granted evaluation, got {other:?}"),
        };

        let root = trace.root().expect("trace should have a root result");
        match root {
            PolicyEvalResult::Combined { children, .. } => {
                assert_eq!(
                    children.len(),
                    1,
                    "Only the granting policy should be traced"
                );
                assert_eq!(
                    children[0].reason(),
                    Some("Always allow policy".to_string()),
                    "The granting policy should be the only recorded child"
                );
            }
            other => panic!("Expected combined root result, got {other:?}"),
        }

        let formatted = trace.format();
        assert!(formatted.contains("AlwaysAllowPolicy"));
        assert!(
            !formatted.contains("ShouldNotAppear"),
            "Trace should not mention policies that were never evaluated"
        );
    }

    #[test]
    fn test_tracing_uses_default_security_rule_fallbacks() {
        let mut checker = PermissionChecker::new();
        checker.add_policy(AlwaysAllowPolicy);

        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        let (_result, events) = with_recorded_events(|| {
            tokio_test::block_on(async {
                checker
                    .evaluate_access(&subject, &TestAction, &resource, &TestContext)
                    .await
            })
        });

        let security_events = security_events(&events);
        assert_eq!(
            security_events.len(),
            1,
            "Exactly one security event should be emitted for one evaluated policy"
        );

        let event = security_events[0];
        assert_eq!(
            event.fields.get("security_rule.name").map(String::as_str),
            Some("AlwaysAllowPolicy")
        );
        assert_eq!(
            event
                .fields
                .get("security_rule.category")
                .map(String::as_str),
            Some("Access Control")
        );
        assert_eq!(
            event
                .fields
                .get("security_rule.ruleset.name")
                .map(String::as_str),
            Some("PermissionChecker")
        );
        assert_eq!(
            event.fields.get("event.outcome").map(String::as_str),
            Some("success")
        );
        assert_eq!(
            event.fields.get("policy.type").map(String::as_str),
            Some("AlwaysAllowPolicy")
        );

        let reason = event
            .fields
            .get("policy.result.reason")
            .expect("policy.result.reason should be recorded");
        assert!(
            reason.contains("Always allow policy"),
            "recorded reason should contain the policy reason, got {reason}"
        );
    }

    #[test]
    fn test_tracing_uses_custom_security_rule_metadata() {
        let mut checker = PermissionChecker::new();
        checker.add_policy(CustomMetadataDenyPolicy);

        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        let (_result, events) = with_recorded_events(|| {
            tokio_test::block_on(async {
                checker
                    .evaluate_access(&subject, &TestAction, &resource, &TestContext)
                    .await
            })
        });

        let security_events = security_events(&events);
        assert_eq!(security_events.len(), 1);

        let event = security_events[0];
        assert_eq!(
            event.fields.get("security_rule.name").map(String::as_str),
            Some("CustomRuleName")
        );
        assert_eq!(
            event
                .fields
                .get("security_rule.category")
                .map(String::as_str),
            Some("Policy")
        );
        assert_eq!(
            event
                .fields
                .get("security_rule.ruleset.name")
                .map(String::as_str),
            Some("CustomRuleset")
        );
        assert_eq!(
            event.fields.get("event.outcome").map(String::as_str),
            Some("failure")
        );
        assert_eq!(
            event.fields.get("policy.type").map(String::as_str),
            Some("CustomMetadataDenyPolicy")
        );

        for (field_name, expected_substring) in [
            ("security_rule.description", "Description from metadata"),
            ("security_rule.reference", "https://example.com/rule"),
            ("security_rule.uuid", "rule-123"),
            ("security_rule.version", "2026.03"),
            ("security_rule.license", "MIT"),
            ("policy.result.reason", "Blocked by custom rule"),
        ] {
            let value = event
                .fields
                .get(field_name)
                .unwrap_or_else(|| panic!("{field_name} should be recorded"));
            assert!(
                value.contains(expected_substring),
                "{field_name} should contain {expected_substring:?}, got {value:?}"
            );
        }
    }

    // RebacPolicy tests with fact-backed relationship sources.

    struct TestRelationshipSource {
        grants: HashSet<RelationshipQuery<uuid::Uuid, uuid::Uuid, String>>,
        batch_sizes: Arc<Mutex<Vec<usize>>>,
        max_batch_size: Option<NonZeroUsize>,
    }

    #[async_trait]
    impl FactSource<RelationshipQuery<uuid::Uuid, uuid::Uuid, String>> for TestRelationshipSource {
        async fn load_many(
            &self,
            keys: &[RelationshipQuery<uuid::Uuid, uuid::Uuid, String>],
        ) -> Vec<FactLoadResult<bool>> {
            self.batch_sizes.lock().unwrap().push(keys.len());
            keys.iter()
                .map(|key| FactLoadResult::Found(self.grants.contains(key)))
                .collect()
        }

        fn max_batch_size(&self) -> Option<NonZeroUsize> {
            self.max_batch_size
        }
    }

    struct MismatchedRelationshipSource;

    #[async_trait]
    impl FactSource<RelationshipQuery<uuid::Uuid, uuid::Uuid, String>>
        for MismatchedRelationshipSource
    {
        async fn load_many(
            &self,
            keys: &[RelationshipQuery<uuid::Uuid, uuid::Uuid, String>],
        ) -> Vec<FactLoadResult<bool>> {
            keys.iter()
                .skip(1)
                .map(|_| FactLoadResult::Found(true))
                .collect()
        }
    }

    struct MissingRelationshipSource;

    #[async_trait]
    impl FactSource<RelationshipQuery<uuid::Uuid, uuid::Uuid, String>> for MissingRelationshipSource {
        async fn load_many(
            &self,
            keys: &[RelationshipQuery<uuid::Uuid, uuid::Uuid, String>],
        ) -> Vec<FactLoadResult<bool>> {
            keys.iter().map(|_| FactLoadResult::Missing).collect()
        }
    }

    struct ErrorRelationshipSource;

    #[async_trait]
    impl FactSource<RelationshipQuery<uuid::Uuid, uuid::Uuid, String>> for ErrorRelationshipSource {
        async fn load_many(
            &self,
            keys: &[RelationshipQuery<uuid::Uuid, uuid::Uuid, String>],
        ) -> Vec<FactLoadResult<bool>> {
            keys.iter()
                .map(|_| {
                    FactLoadResult::Error(FactLoadError::backend_message("database unavailable"))
                })
                .collect()
        }
    }

    struct BlockingRelationshipSource {
        calls: Arc<AtomicUsize>,
        started: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    #[async_trait]
    impl FactSource<RelationshipQuery<uuid::Uuid, uuid::Uuid, String>> for BlockingRelationshipSource {
        async fn load_many(
            &self,
            keys: &[RelationshipQuery<uuid::Uuid, uuid::Uuid, String>],
        ) -> Vec<FactLoadResult<bool>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(keys.len(), 1);
            self.started.notify_one();
            self.release.notified().await;
            keys.iter().map(|_| FactLoadResult::Found(true)).collect()
        }
    }

    fn relationship_policy(
        relationship: String,
    ) -> RebacPolicy<
        TestSubject,
        TestResource,
        TestAction,
        TestContext,
        uuid::Uuid,
        uuid::Uuid,
        String,
    > {
        RebacPolicy::new(
            |subject: &TestSubject| subject.id,
            |resource: &TestResource| resource.id,
            relationship,
        )
    }

    #[tokio::test]
    async fn test_rebac_policy_allows_when_relationship_exists() {
        let subject_id = uuid::Uuid::new_v4();
        let resource_id = uuid::Uuid::new_v4();
        let relationship = "manager".to_string();
        let subject = TestSubject { id: subject_id };
        let resource = TestResource { id: resource_id };
        let session = EvaluationSession::new();
        session.register::<RelationshipQuery<uuid::Uuid, uuid::Uuid, String>, _>(
            TestRelationshipSource {
                grants: HashSet::from([RelationshipQuery {
                    subject_id,
                    resource_id,
                    relation: relationship.clone(),
                }]),
                batch_sizes: Arc::new(Mutex::new(Vec::new())),
                max_batch_size: None,
            },
        );
        let policy = relationship_policy(relationship);

        let ctx = EvalCtx {
            session: &session,
            subject: &subject,
            action: &TestAction,
            resource: &resource,
            context: &TestContext,
        };
        let result = policy.evaluate(&ctx).await;

        assert!(result.is_granted());
    }

    #[tokio::test]
    async fn test_rebac_policy_denies_without_registered_source() {
        let policy = relationship_policy("manager".to_string());
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };
        let session = EvaluationSession::new();
        let ctx = EvalCtx {
            session: &session,
            subject: &subject,
            action: &TestAction,
            resource: &resource,
            context: &TestContext,
        };

        let result = policy.evaluate(&ctx).await;

        assert!(!result.is_granted());
        assert!(result
            .reason()
            .as_deref()
            .is_some_and(|reason| reason.contains("No fact source registered")));
    }

    #[tokio::test]
    async fn test_rebac_policy_batch_uses_session_dedup_and_source_chunking() {
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let relationship = "viewer".to_string();
        let batch_sizes = Arc::new(Mutex::new(Vec::new()));
        let resources = (0..5)
            .map(|value| TestResource {
                id: uuid::Uuid::from_u128(value),
            })
            .collect::<Vec<_>>();
        let grants = resources
            .iter()
            .filter(|resource| resource.id.as_u128().is_multiple_of(2))
            .map(|resource| RelationshipQuery {
                subject_id: subject.id,
                resource_id: resource.id,
                relation: relationship.clone(),
            })
            .collect::<HashSet<_>>();
        let session = EvaluationSession::new();
        session.register::<RelationshipQuery<uuid::Uuid, uuid::Uuid, String>, _>(
            TestRelationshipSource {
                grants,
                batch_sizes: Arc::clone(&batch_sizes),
                max_batch_size: NonZeroUsize::new(2),
            },
        );
        let owned_items = [
            (resources[0].clone(), TestContext),
            (resources[1].clone(), TestContext),
            (resources[0].clone(), TestContext),
            (resources[2].clone(), TestContext),
            (resources[3].clone(), TestContext),
        ];
        let batch_items = owned_items
            .iter()
            .map(|(resource, context)| PolicyBatchItem { resource, context })
            .collect::<Vec<_>>();
        let policy = relationship_policy(relationship);
        let ctx = BatchEvalCtx {
            session: &session,
            subject: &subject,
            action: &TestAction,
            items: &batch_items,
        };

        let results = policy.evaluate_batch(&ctx).await;

        assert_eq!(*batch_sizes.lock().unwrap(), vec![2, 2]);
        assert_eq!(
            results
                .iter()
                .map(PolicyEvalResult::is_granted)
                .collect::<Vec<_>>(),
            vec![true, false, true, true, false]
        );

        let _ = policy.evaluate_batch(&ctx).await;
        assert_eq!(*batch_sizes.lock().unwrap(), vec![2, 2]);
    }

    #[tokio::test]
    async fn test_session_joins_concurrent_get_for_in_flight_key() {
        let calls = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let session = EvaluationSession::new();
        session.register::<RelationshipQuery<uuid::Uuid, uuid::Uuid, String>, _>(
            BlockingRelationshipSource {
                calls: Arc::clone(&calls),
                started: Arc::clone(&started),
                release: Arc::clone(&release),
            },
        );
        let key = RelationshipQuery {
            subject_id: uuid::Uuid::new_v4(),
            resource_id: uuid::Uuid::new_v4(),
            relation: "viewer".to_string(),
        };

        let first_session = session.clone();
        let first_key = key.clone();
        let first = tokio::spawn(async move { first_session.get(first_key).await });

        started.notified().await;

        let second_session = session.clone();
        let second = tokio::spawn(async move { second_session.get(key).await });
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        release.notify_one();
        for result in [first.await.unwrap(), second.await.unwrap()] {
            assert!(matches!(result, FactLoadResult::Found(true)));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_rebac_policy_fails_closed_on_missing_error_and_mismatch() {
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };
        let policy = relationship_policy("viewer".to_string());

        for (session, expected_reason) in [
            {
                let session = EvaluationSession::new();
                session.register::<RelationshipQuery<uuid::Uuid, uuid::Uuid, String>, _>(
                    MissingRelationshipSource,
                );
                (session, "fact is missing")
            },
            {
                let session = EvaluationSession::new();
                session.register::<RelationshipQuery<uuid::Uuid, uuid::Uuid, String>, _>(
                    ErrorRelationshipSource,
                );
                (session, "database unavailable")
            },
            {
                let session = EvaluationSession::new();
                session.register::<RelationshipQuery<uuid::Uuid, uuid::Uuid, String>, _>(
                    MismatchedRelationshipSource,
                );
                (session, "returned")
            },
        ] {
            let ctx = EvalCtx {
                session: &session,
                subject: &subject,
                action: &TestAction,
                resource: &resource,
                context: &TestContext,
            };
            let result = policy.evaluate(&ctx).await;
            assert!(!result.is_granted());
            assert!(result
                .reason()
                .as_deref()
                .is_some_and(|reason| reason.contains(expected_reason)));
        }
    }

    // RebacPolicy test with enum relationship type.

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    enum TestRelation {
        Manager,
        Viewer,
    }

    impl fmt::Display for TestRelation {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                TestRelation::Manager => write!(f, "manager"),
                TestRelation::Viewer => write!(f, "viewer"),
            }
        }
    }

    struct EnumRelationshipSource {
        grants: HashSet<RelationshipQuery<uuid::Uuid, uuid::Uuid, TestRelation>>,
    }

    #[async_trait]
    impl FactSource<RelationshipQuery<uuid::Uuid, uuid::Uuid, TestRelation>>
        for EnumRelationshipSource
    {
        async fn load_many(
            &self,
            keys: &[RelationshipQuery<uuid::Uuid, uuid::Uuid, TestRelation>],
        ) -> Vec<FactLoadResult<bool>> {
            keys.iter()
                .map(|key| FactLoadResult::Found(self.grants.contains(key)))
                .collect()
        }
    }

    #[tokio::test]
    async fn test_rebac_policy_with_enum_relationship() {
        let subject_id = uuid::Uuid::new_v4();
        let resource_id = uuid::Uuid::new_v4();

        let subject = TestSubject { id: subject_id };
        let resource = TestResource { id: resource_id };

        let session = EvaluationSession::new();
        session.register::<RelationshipQuery<uuid::Uuid, uuid::Uuid, TestRelation>, _>(
            EnumRelationshipSource {
                grants: HashSet::from([RelationshipQuery {
                    subject_id,
                    resource_id,
                    relation: TestRelation::Manager,
                }]),
            },
        );

        let policy = RebacPolicy::new(
            |subject: &TestSubject| subject.id,
            |resource: &TestResource| resource.id,
            TestRelation::Manager,
        );

        // Manager relationship exists — should be granted.
        let ctx = EvalCtx {
            session: &session,
            subject: &subject,
            action: &TestAction,
            resource: &resource,
            context: &TestContext,
        };
        let result = policy.evaluate(&ctx).await;
        assert!(
            result.is_granted(),
            "Access should be granted for matching enum relationship"
        );

        let viewer_policy = RebacPolicy::new(
            |subject: &TestSubject| subject.id,
            |resource: &TestResource| resource.id,
            TestRelation::Viewer,
        );
        let result = viewer_policy.evaluate(&ctx).await;
        assert!(
            !result.is_granted(),
            "Access should be denied when enum relationship does not match"
        );
    }

    // Combinator tests.
    #[tokio::test]
    async fn test_and_policy_allows_when_all_allow() {
        let policy = AndPolicy::try_new(vec![
            Arc::new(AlwaysAllowPolicy),
            Arc::new(AlwaysAllowPolicy),
        ])
        .expect("Unable to create and-policy policy");
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };
        let result = policy
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;
        assert!(
            result.is_granted(),
            "AndPolicy should allow access when all inner policies allow"
        );
    }
    #[tokio::test]
    async fn test_and_policy_denies_when_one_denies() {
        let policy = AndPolicy::try_new(vec![
            Arc::new(AlwaysAllowPolicy),
            Arc::new(AlwaysDenyPolicy("DenyInAnd")),
        ])
        .expect("Unable to create and-policy policy");
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };
        let result = policy
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;
        match result {
            PolicyEvalResult::Combined {
                policy_type,
                operation,
                children,
                outcome,
            } => {
                assert_eq!(operation, CombineOp::And);
                assert!(!outcome);
                assert_eq!(children.len(), 2);
                assert!(children[1].format(0).contains("DenyInAnd"));
                assert_eq!(policy_type, "AndPolicy");
            }
            _ => panic!("Expected Combined result from AndPolicy, got {:?}", result),
        }
    }
    #[tokio::test]
    async fn test_or_policy_allows_when_one_allows() {
        let policy = OrPolicy::try_new(vec![
            Arc::new(AlwaysDenyPolicy("Deny1")),
            Arc::new(AlwaysAllowPolicy),
        ])
        .expect("Unable to create or-policy policy");
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };
        let result = policy
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;
        assert!(
            result.is_granted(),
            "OrPolicy should allow access when at least one inner policy allows"
        );
    }
    #[tokio::test]
    async fn test_or_policy_denies_when_all_deny() {
        let policy = OrPolicy::try_new(vec![
            Arc::new(AlwaysDenyPolicy("Deny1")),
            Arc::new(AlwaysDenyPolicy("Deny2")),
        ])
        .expect("Unable to create or-policy policy");
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };
        let result = policy
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;
        match result {
            PolicyEvalResult::Combined {
                policy_type,
                operation,
                children,
                outcome,
            } => {
                assert_eq!(operation, CombineOp::Or);
                assert!(!outcome);
                assert_eq!(children.len(), 2);
                assert!(children[0].format(0).contains("Deny1"));
                assert!(children[1].format(0).contains("Deny2"));
                assert_eq!(policy_type, "OrPolicy");
            }
            _ => panic!("Expected Combined result from OrPolicy, got {:?}", result),
        }
    }
    #[tokio::test]
    async fn test_not_policy_allows_when_inner_denies() {
        let policy = NotPolicy::new(AlwaysDenyPolicy("AlwaysDeny"));
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };
        let result = policy
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;
        assert!(
            result.is_granted(),
            "NotPolicy should allow access when inner policy denies"
        );
    }
    #[tokio::test]
    async fn test_not_policy_denies_when_inner_allows() {
        let policy = NotPolicy::new(AlwaysAllowPolicy);
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };
        let result = policy
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;
        match result {
            PolicyEvalResult::Combined {
                policy_type,
                operation,
                children,
                outcome,
            } => {
                assert_eq!(operation, CombineOp::Not);
                assert!(!outcome);
                assert_eq!(children.len(), 1);
                assert!(children[0].format(0).contains("AlwaysAllowPolicy"));
                assert_eq!(policy_type, "NotPolicy");
            }
            _ => panic!("Expected Combined result from NotPolicy, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn test_empty_policies_in_combinators() {
        // Test AndPolicy with no policies
        let and_policy_result =
            AndPolicy::<TestSubject, TestResource, TestAction, TestContext>::try_new(vec![]);

        assert!(and_policy_result.is_err());

        // Test OrPolicy with no policies
        let or_policy_result =
            OrPolicy::<TestSubject, TestResource, TestAction, TestContext>::try_new(vec![]);
        assert!(or_policy_result.is_err());
    }

    #[tokio::test]
    async fn test_deeply_nested_combinators() {
        // Create a complex policy structure: NOT(AND(Allow, OR(Deny, NOT(Deny))))
        let inner_not = NotPolicy::new(AlwaysDenyPolicy("InnerDeny"));

        let inner_or = OrPolicy::try_new(vec![
            Arc::new(AlwaysDenyPolicy("MidDeny")),
            Arc::new(inner_not),
        ])
        .expect("Unable to create or-policy policy");

        let inner_and = AndPolicy::try_new(vec![Arc::new(AlwaysAllowPolicy), Arc::new(inner_or)])
            .expect("Unable to create and-policy policy");

        let outer_not = NotPolicy::new(inner_and);

        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        let result = outer_not
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;

        // This complex structure should result in a denial
        assert!(!result.is_granted());

        // Verify the correct structure of the trace
        let trace_str = result.format(0);
        assert!(trace_str.contains("NOT"));
        assert!(trace_str.contains("AND"));
        assert!(trace_str.contains("OR"));
        assert!(trace_str.contains("InnerDeny"));
    }

    #[derive(Debug, Clone)]
    struct FeatureFlagContext {
        feature_enabled: bool,
    }

    struct FeatureFlagPolicy;

    #[async_trait]
    impl Policy<TestSubject, TestResource, TestAction, FeatureFlagContext> for FeatureFlagPolicy {
        async fn evaluate(
            &self,
            ctx: &EvalCtx<'_, TestSubject, TestResource, TestAction, FeatureFlagContext>,
        ) -> PolicyEvalResult {
            if ctx.context.feature_enabled {
                PolicyEvalResult::Granted {
                    policy_type: self.policy_type().to_string(),
                    reason: Some("Feature flag enabled".to_string()),
                }
            } else {
                PolicyEvalResult::Denied {
                    policy_type: self.policy_type().to_string(),
                    reason: "Feature flag disabled".to_string(),
                }
            }
        }

        fn policy_type(&self) -> &str {
            "FeatureFlagPolicy"
        }
    }

    #[tokio::test]
    async fn test_context_sensitive_policy() {
        let policy = FeatureFlagPolicy;
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        // Test with flag enabled
        let context_enabled = FeatureFlagContext {
            feature_enabled: true,
        };
        let result = policy
            .evaluate_access(&subject, &TestAction, &resource, &context_enabled)
            .await;
        assert!(result.is_granted());

        // Test with flag disabled
        let context_disabled = FeatureFlagContext {
            feature_enabled: false,
        };
        let result = policy
            .evaluate_access(&subject, &TestAction, &resource, &context_disabled)
            .await;
        assert!(!result.is_granted());
    }

    // ==================== AbacPolicy Tests ====================

    #[tokio::test]
    async fn test_abac_policy_grants_when_condition_true() {
        let policy = AbacPolicy::new(
            |_subject: &TestSubject,
             _resource: &TestResource,
             _action: &TestAction,
             _context: &TestContext| { true },
        );

        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        let result = policy
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;

        assert!(
            result.is_granted(),
            "AbacPolicy should grant when condition returns true"
        );
        assert_eq!(policy.policy_type(), "AbacPolicy");
    }

    #[tokio::test]
    async fn test_abac_policy_denies_when_condition_false() {
        let policy = AbacPolicy::new(
            |_subject: &TestSubject,
             _resource: &TestResource,
             _action: &TestAction,
             _context: &TestContext| { false },
        );

        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        let result = policy
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;

        assert!(
            !result.is_granted(),
            "AbacPolicy should deny when condition returns false"
        );
        match result {
            PolicyEvalResult::Denied {
                policy_type,
                reason,
            } => {
                assert_eq!(policy_type, "AbacPolicy");
                assert!(reason.contains("false"));
            }
            _ => panic!("Expected Denied result, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn test_abac_policy_with_attribute_check() {
        // Policy that checks if the subject owns the resource
        let policy = AbacPolicy::new(
            |subject: &TestSubject,
             resource: &TestResource,
             _action: &TestAction,
             _context: &TestContext| { subject.id == resource.id },
        );

        let owner_id = uuid::Uuid::new_v4();
        let owner = TestSubject { id: owner_id };
        let owned_resource = TestResource { id: owner_id };
        let other_resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        // Owner should have access to owned resource
        let result = policy
            .evaluate_access(&owner, &TestAction, &owned_resource, &TestContext)
            .await;
        assert!(
            result.is_granted(),
            "Owner should have access to owned resource"
        );

        // Owner should not have access to other resource
        let result = policy
            .evaluate_access(&owner, &TestAction, &other_resource, &TestContext)
            .await;
        assert!(
            !result.is_granted(),
            "Owner should not have access to other resource"
        );
    }

    // ==================== RbacPolicy Tests ====================

    #[tokio::test]
    async fn test_rbac_policy_grants_when_user_has_required_role() {
        let admin_role = uuid::Uuid::new_v4();
        let user_role = uuid::Uuid::new_v4();

        #[derive(Debug, Clone)]
        struct RbacUser {
            roles: Vec<uuid::Uuid>,
        }

        let policy = RbacPolicy::new(
            |_resource: &TestResource, _action: &TestAction| vec![admin_role],
            |subject: &RbacUser| subject.roles.clone(),
        );

        let admin_user = RbacUser {
            roles: vec![admin_role, user_role],
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        let result: PolicyEvalResult = TestPolicyExt::<
            RbacUser,
            TestResource,
            TestAction,
            TestContext,
        >::evaluate_access(
            &policy, &admin_user, &TestAction, &resource, &TestContext
        )
        .await;

        assert!(
            result.is_granted(),
            "User with required role should be granted access"
        );
        assert_eq!(
            Policy::<RbacUser, TestResource, TestAction, TestContext>::policy_type(&policy),
            "RbacPolicy"
        );
    }

    #[tokio::test]
    async fn test_rbac_policy_denies_when_user_lacks_required_role() {
        let admin_role = uuid::Uuid::new_v4();
        let user_role = uuid::Uuid::new_v4();

        #[derive(Debug, Clone)]
        struct RbacUser {
            roles: Vec<uuid::Uuid>,
        }

        let policy = RbacPolicy::new(
            |_resource: &TestResource, _action: &TestAction| vec![admin_role],
            |subject: &RbacUser| subject.roles.clone(),
        );

        let regular_user = RbacUser {
            roles: vec![user_role],
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        let result: PolicyEvalResult =
            TestPolicyExt::<RbacUser, TestResource, TestAction, TestContext>::evaluate_access(
                &policy,
                &regular_user,
                &TestAction,
                &resource,
                &TestContext,
            )
            .await;

        assert!(
            !result.is_granted(),
            "User without required role should be denied"
        );
        match result {
            PolicyEvalResult::Denied {
                policy_type,
                reason,
            } => {
                assert_eq!(policy_type, "RbacPolicy");
                assert!(reason.contains("doesn't have required role"));
            }
            _ => panic!("Expected Denied result, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn test_rbac_policy_grants_with_any_matching_role() {
        let role1 = uuid::Uuid::new_v4();
        let role2 = uuid::Uuid::new_v4();
        let role3 = uuid::Uuid::new_v4();

        #[derive(Debug, Clone)]
        struct RbacUser {
            roles: Vec<uuid::Uuid>,
        }

        // Policy requires either role1 or role2
        let policy = RbacPolicy::new(
            |_resource: &TestResource, _action: &TestAction| vec![role1, role2],
            |subject: &RbacUser| subject.roles.clone(),
        );

        // User has role2 (one of the required roles)
        let user = RbacUser {
            roles: vec![role2, role3],
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        let result: PolicyEvalResult = TestPolicyExt::<
            RbacUser,
            TestResource,
            TestAction,
            TestContext,
        >::evaluate_access(
            &policy, &user, &TestAction, &resource, &TestContext
        )
        .await;

        assert!(
            result.is_granted(),
            "User with any required role should be granted access"
        );
    }

    #[tokio::test]
    async fn test_rbac_policy_denies_with_empty_user_roles() {
        let admin_role = uuid::Uuid::new_v4();

        #[derive(Debug, Clone)]
        struct RbacUser {
            roles: Vec<uuid::Uuid>,
        }

        let policy = RbacPolicy::new(
            |_resource: &TestResource, _action: &TestAction| vec![admin_role],
            |subject: &RbacUser| subject.roles.clone(),
        );

        let user_no_roles = RbacUser { roles: vec![] };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        let result: PolicyEvalResult =
            TestPolicyExt::<RbacUser, TestResource, TestAction, TestContext>::evaluate_access(
                &policy,
                &user_no_roles,
                &TestAction,
                &resource,
                &TestContext,
            )
            .await;

        assert!(!result.is_granted(), "User with no roles should be denied");
    }

    #[tokio::test]
    async fn test_rbac_policy_denies_with_empty_required_roles() {
        let user_role = uuid::Uuid::new_v4();

        #[derive(Debug, Clone)]
        struct RbacUser {
            roles: Vec<uuid::Uuid>,
        }

        // No roles are required (empty list)
        let policy = RbacPolicy::new(
            |_resource: &TestResource, _action: &TestAction| vec![],
            |subject: &RbacUser| subject.roles.clone(),
        );

        let user = RbacUser {
            roles: vec![user_role],
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        let result: PolicyEvalResult = TestPolicyExt::<
            RbacUser,
            TestResource,
            TestAction,
            TestContext,
        >::evaluate_access(
            &policy, &user, &TestAction, &resource, &TestContext
        )
        .await;

        // With empty required roles, no role can match, so access is denied
        assert!(
            !result.is_granted(),
            "Empty required roles means no match is possible"
        );
    }

    #[tokio::test]
    async fn test_short_circuit_evaluation() {
        // Create a counter to track policy evaluation
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc as StdArc;

        let evaluation_count = StdArc::new(AtomicUsize::new(0));

        struct CountingPolicy {
            result: bool,
            counter: StdArc<AtomicUsize>,
        }

        #[async_trait]
        impl Policy<TestSubject, TestResource, TestAction, TestContext> for CountingPolicy {
            async fn evaluate(
                &self,
                _ctx: &EvalCtx<'_, TestSubject, TestResource, TestAction, TestContext>,
            ) -> PolicyEvalResult {
                self.counter.fetch_add(1, Ordering::SeqCst);

                if self.result {
                    PolicyEvalResult::Granted {
                        policy_type: self.policy_type().to_string(),
                        reason: Some("Counting policy granted".to_string()),
                    }
                } else {
                    PolicyEvalResult::Denied {
                        policy_type: self.policy_type().to_string(),
                        reason: "Counting policy denied".to_string(),
                    }
                }
            }

            fn policy_type(&self) -> &str {
                "CountingPolicy"
            }
        }

        // Test AND short circuit on first deny
        let count_clone = evaluation_count.clone();
        evaluation_count.store(0, Ordering::SeqCst);

        let and_policy = AndPolicy::try_new(vec![
            Arc::new(CountingPolicy {
                result: false,
                counter: count_clone.clone(),
            }),
            Arc::new(CountingPolicy {
                result: true,
                counter: count_clone,
            }),
        ])
        .expect("Unable to create 'and' policy");

        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };
        and_policy
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;

        assert_eq!(
            evaluation_count.load(Ordering::SeqCst),
            1,
            "AND policy should short-circuit after first deny"
        );

        // Test OR short circuit on first allow
        let count_clone = evaluation_count.clone();
        evaluation_count.store(0, Ordering::SeqCst);

        let or_policy = OrPolicy::try_new(vec![
            Arc::new(CountingPolicy {
                result: true,
                counter: count_clone.clone(),
            }),
            Arc::new(CountingPolicy {
                result: false,
                counter: count_clone,
            }),
        ])
        .unwrap();

        or_policy
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;

        assert_eq!(
            evaluation_count.load(Ordering::SeqCst),
            1,
            "OR policy should short-circuit after first allow"
        );
    }

    // ==================== AccessEvaluation Tests ====================

    #[tokio::test]
    async fn test_access_evaluation_to_result_granted() {
        let mut checker = PermissionChecker::new();
        checker.add_policy(AlwaysAllowPolicy);

        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        let result = checker
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;

        // to_result should return Ok for granted access
        let converted: Result<(), String> = result.to_result(|reason| reason.to_string());
        assert!(
            converted.is_ok(),
            "to_result should return Ok for granted access"
        );
    }

    #[tokio::test]
    async fn test_access_evaluation_to_result_denied() {
        let mut checker = PermissionChecker::new();
        checker.add_policy(AlwaysDenyPolicy("Access denied"));

        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        let result = checker
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;

        // to_result should return Err for denied access
        let converted: Result<(), String> = result.to_result(|reason| reason.to_string());
        assert!(
            converted.is_err(),
            "to_result should return Err for denied access"
        );
        assert!(converted.unwrap_err().contains("denied"));
    }

    #[tokio::test]
    async fn test_access_evaluation_to_result_uses_summary_denial_reason() {
        let mut checker = PermissionChecker::new();
        checker.add_policy(AlwaysDenyPolicy("First policy reason"));
        checker.add_policy(AlwaysDenyPolicy("Second policy reason"));

        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        let result = checker
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;

        let converted: Result<(), String> = result.to_result(|reason| reason.to_string());
        assert_eq!(
            converted.unwrap_err(),
            "All policies denied access",
            "to_result should use the top-level summary denial reason"
        );
    }

    #[tokio::test]
    async fn test_access_evaluation_display_trace_granted() {
        let mut checker = PermissionChecker::new();
        checker.add_policy(AlwaysAllowPolicy);

        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        let result = checker
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;

        let trace_display = result.display_trace();
        assert!(
            trace_display.contains("GRANTED"),
            "Trace should show GRANTED"
        );
        assert!(
            trace_display.contains("AlwaysAllowPolicy"),
            "Trace should show policy name"
        );
        assert!(
            trace_display.contains("Evaluation Trace"),
            "Trace should include trace section"
        );
    }

    #[tokio::test]
    async fn test_access_evaluation_display_trace_denied() {
        let mut checker = PermissionChecker::new();
        checker.add_policy(AlwaysDenyPolicy("Test denial"));

        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        let result = checker
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;

        let trace_display = result.display_trace();
        assert!(trace_display.contains("Denied"), "Trace should show Denied");
        assert!(
            trace_display.contains("Test denial"),
            "Trace should show denial reason"
        );
    }

    #[tokio::test]
    async fn test_access_evaluation_display_impl() {
        let mut checker = PermissionChecker::new();
        checker.add_policy(AlwaysAllowPolicy);

        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        let result = checker
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;

        // Test Display trait
        let display_str = format!("{}", result);
        assert!(
            display_str.contains("GRANTED"),
            "Display should show GRANTED"
        );
        assert!(
            display_str.contains("AlwaysAllowPolicy"),
            "Display should show policy name"
        );
    }

    // ==================== EvalTrace Tests ====================

    #[test]
    fn test_eval_trace_new_creates_empty() {
        let trace = EvalTrace::new();
        assert!(trace.root().is_none(), "New trace should have no root");
        assert_eq!(
            trace.format(),
            "No evaluation trace available",
            "Empty trace should format as 'No evaluation trace available'"
        );
    }

    #[test]
    fn test_eval_trace_with_root() {
        let result = PolicyEvalResult::Granted {
            policy_type: "TestPolicy".to_string(),
            reason: Some("Test reason".to_string()),
        };
        let trace = EvalTrace::with_root(result);

        assert!(trace.root().is_some(), "Trace with root should have a root");
        let formatted = trace.format();
        assert!(
            formatted.contains("TestPolicy"),
            "Formatted trace should contain policy name"
        );
        assert!(
            formatted.contains("GRANTED"),
            "Formatted trace should contain GRANTED"
        );
    }

    #[test]
    fn test_eval_trace_set_root() {
        let mut trace = EvalTrace::new();
        assert!(trace.root().is_none());

        let result = PolicyEvalResult::Denied {
            policy_type: "DenyPolicy".to_string(),
            reason: "Denied for testing".to_string(),
        };
        trace.set_root(result);

        assert!(
            trace.root().is_some(),
            "After set_root, trace should have a root"
        );
        let formatted = trace.format();
        assert!(formatted.contains("DenyPolicy"));
        assert!(formatted.contains("DENIED"));
    }

    #[test]
    fn test_eval_trace_default() {
        let trace = EvalTrace::default();
        assert!(trace.root().is_none(), "Default trace should have no root");
    }

    // ==================== PolicyEvalResult Tests ====================

    #[test]
    fn test_policy_eval_result_reason_granted() {
        let result = PolicyEvalResult::Granted {
            policy_type: "TestPolicy".to_string(),
            reason: Some("Grant reason".to_string()),
        };
        assert_eq!(result.reason(), Some("Grant reason".to_string()));

        // Test with None reason
        let result_no_reason = PolicyEvalResult::Granted {
            policy_type: "TestPolicy".to_string(),
            reason: None,
        };
        assert_eq!(result_no_reason.reason(), None);
    }

    #[test]
    fn test_policy_eval_result_reason_denied() {
        let result = PolicyEvalResult::Denied {
            policy_type: "TestPolicy".to_string(),
            reason: "Deny reason".to_string(),
        };
        assert_eq!(result.reason(), Some("Deny reason".to_string()));
    }

    #[test]
    fn test_policy_eval_result_reason_combined() {
        let result = PolicyEvalResult::Combined {
            policy_type: "CombinedPolicy".to_string(),
            operation: CombineOp::And,
            children: vec![],
            outcome: true,
        };
        assert_eq!(
            result.reason(),
            None,
            "Combined result should have no reason"
        );
    }

    #[test]
    fn test_policy_eval_result_format_indentation() {
        let result = PolicyEvalResult::Granted {
            policy_type: "TestPolicy".to_string(),
            reason: Some("Test".to_string()),
        };

        let formatted_0 = result.format(0);
        let formatted_4 = result.format(4);

        assert!(
            formatted_0.starts_with("✔"),
            "Indent 0 should start with checkmark"
        );
        assert!(
            formatted_4.starts_with("    ✔"),
            "Indent 4 should have 4 spaces before checkmark"
        );
    }

    #[test]
    fn test_policy_eval_result_display() {
        let result = PolicyEvalResult::Denied {
            policy_type: "TestPolicy".to_string(),
            reason: "Test denial".to_string(),
        };

        let display_str = format!("{}", result);
        assert!(display_str.contains("TestPolicy"));
        assert!(display_str.contains("DENIED"));
        assert!(display_str.contains("Test denial"));
    }

    // ==================== CombineOp Display Tests ====================

    #[test]
    fn test_combine_op_display() {
        assert_eq!(format!("{}", CombineOp::And), "AND");
        assert_eq!(format!("{}", CombineOp::Or), "OR");
        assert_eq!(format!("{}", CombineOp::Not), "NOT");
    }

    // ==================== PermissionChecker Default Tests ====================

    #[tokio::test]
    async fn test_permission_checker_default() {
        let checker =
            PermissionChecker::<TestSubject, TestResource, TestAction, TestContext>::default();

        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        let result = checker
            .evaluate_access(&subject, &TestAction, &resource, &TestContext)
            .await;

        // Default checker has no policies, so should deny
        assert!(
            !result.is_granted(),
            "Default checker with no policies should deny"
        );
    }

    // ==================== SecurityRuleMetadata Tests ====================

    #[test]
    fn test_security_rule_metadata_default_values() {
        let metadata = SecurityRuleMetadata::default();

        assert_eq!(metadata.name(), None);
        assert_eq!(metadata.category(), None);
        assert_eq!(metadata.description(), None);
        assert_eq!(metadata.reference(), None);
        assert_eq!(metadata.ruleset_name(), None);
        assert_eq!(metadata.uuid(), None);
        assert_eq!(metadata.version(), None);
        assert_eq!(metadata.license(), None);
    }

    #[test]
    fn test_security_rule_metadata_new_equals_default() {
        let new_metadata = SecurityRuleMetadata::new();
        let default_metadata = SecurityRuleMetadata::default();

        assert_eq!(new_metadata, default_metadata);
    }

    #[test]
    fn test_security_rule_metadata_partial_builder() {
        // Test that we can set only some fields
        let metadata = SecurityRuleMetadata::new()
            .with_name("TestRule")
            .with_category("TestCategory");

        assert_eq!(metadata.name(), Some("TestRule"));
        assert_eq!(metadata.category(), Some("TestCategory"));
        assert_eq!(metadata.description(), None);
        assert_eq!(metadata.reference(), None);
    }

    #[tokio::test]
    async fn test_policy_default_security_rule() {
        // Test that the default security_rule implementation returns empty metadata
        let policy = AlwaysAllowPolicy;
        let metadata =
            Policy::<TestSubject, TestResource, TestAction, TestContext>::security_rule(&policy);

        assert_eq!(metadata, SecurityRuleMetadata::default());
    }

    // ==================== EmptyPoliciesError Tests ====================

    #[test]
    fn test_empty_policies_error_debug() {
        let error = EmptyPoliciesError("Test error message");
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("Test error message"));
    }

    #[test]
    #[allow(clippy::clone_on_copy)] // intentionally testing both Copy and Clone
    fn test_empty_policies_error_copy_clone() {
        let error = EmptyPoliciesError("Test");
        let copied = error;
        let cloned = error.clone();

        assert_eq!(copied.0, "Test");
        assert_eq!(cloned.0, "Test");
    }
}

#[cfg(test)]
mod policy_builder_tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use uuid::Uuid;

    trait PolicyBoxExt<S, R, A, C>
    where
        S: Send + Sync,
        R: Send + Sync,
        A: Send + Sync,
        C: Send + Sync,
    {
        fn evaluate_access<'a>(
            &'a self,
            subject: &'a S,
            action: &'a A,
            resource: &'a R,
            context: &'a C,
        ) -> Pin<Box<dyn Future<Output = PolicyEvalResult> + Send + 'a>>;
    }

    impl<S, R, A, C> PolicyBoxExt<S, R, A, C> for Box<dyn Policy<S, R, A, C>>
    where
        S: Send + Sync,
        R: Send + Sync,
        A: Send + Sync,
        C: Send + Sync,
    {
        fn evaluate_access<'a>(
            &'a self,
            subject: &'a S,
            action: &'a A,
            resource: &'a R,
            context: &'a C,
        ) -> Pin<Box<dyn Future<Output = PolicyEvalResult> + Send + 'a>> {
            Box::pin(async move {
                let session = EvaluationSession::new();
                let ctx = EvalCtx {
                    session: &session,
                    subject,
                    action,
                    resource,
                    context,
                };
                self.evaluate(&ctx).await
            })
        }
    }

    // Define simple test types
    #[derive(Debug, Clone)]
    struct TestSubject {
        pub name: String,
    }
    #[derive(Debug, Clone)]
    struct TestAction;
    #[derive(Debug, Clone)]
    struct TestResource;
    #[derive(Debug, Clone)]
    struct TestContext;

    // Test that with no predicates the builder returns a policy that always "matches"
    #[tokio::test]
    async fn test_policy_builder_allows_when_no_predicates() {
        let policy = PolicyBuilder::<TestSubject, TestResource, TestAction, TestContext>::new(
            "NoPredicatesPolicy",
        )
        .build();

        let result = policy
            .evaluate_access(
                &TestSubject { name: "Any".into() },
                &TestAction,
                &TestResource,
                &TestContext,
            )
            .await;
        assert!(
            result.is_granted(),
            "Policy built with no predicates should allow access (default true)"
        );
    }

    // Test that a subject predicate is applied correctly.
    #[tokio::test]
    async fn test_policy_builder_with_subject_predicate() {
        let policy = PolicyBuilder::<TestSubject, TestResource, TestAction, TestContext>::new(
            "SubjectPolicy",
        )
        .subjects(|s: &TestSubject| s.name == "Alice")
        .build();

        // Should allow if the subject's name is "Alice"
        let result1 = policy
            .evaluate_access(
                &TestSubject {
                    name: "Alice".into(),
                },
                &TestAction,
                &TestResource,
                &TestContext,
            )
            .await;
        assert!(
            result1.is_granted(),
            "Policy should allow access for subject 'Alice'"
        );

        // Otherwise, it should deny
        let result2 = policy
            .evaluate_access(
                &TestSubject { name: "Bob".into() },
                &TestAction,
                &TestResource,
                &TestContext,
            )
            .await;
        assert!(
            !result2.is_granted(),
            "Policy should deny access for subject not named 'Alice'"
        );
    }

    // Test that setting the effect to Deny overrides an otherwise matching predicate.
    #[tokio::test]
    async fn test_policy_builder_effect_deny() {
        let policy =
            PolicyBuilder::<TestSubject, TestResource, TestAction, TestContext>::new("DenyPolicy")
                .effect(Effect::Deny)
                .build();

        // Even though no predicate fails (so predicate returns true),
        // the effect should result in a Denied outcome.
        let result = policy
            .evaluate_access(
                &TestSubject {
                    name: "Anyone".into(),
                },
                &TestAction,
                &TestResource,
                &TestContext,
            )
            .await;
        assert!(
            !result.is_granted(),
            "Policy with effect Deny should result in denial even if the predicate passes"
        );
    }

    #[tokio::test]
    async fn test_policy_builder_effect_deny_does_not_override_other_grants() {
        let deny_policy = PolicyBuilder::<TestSubject, TestResource, TestAction, TestContext>::new(
            "ExplicitDenyLikePolicy",
        )
        .effect(Effect::Deny)
        .subjects(|subject| subject.name == "Alice")
        .build();

        let allow_policy =
            PolicyBuilder::<TestSubject, TestResource, TestAction, TestContext>::new(
                "AllowAlicePolicy",
            )
            .subjects(|subject| subject.name == "Alice")
            .build();

        let mut checker = PermissionChecker::new();
        checker.add_policy(deny_policy);
        checker.add_policy(allow_policy);

        let session = EvaluationSession::empty();
        let result = checker
            .evaluate_in_session(
                &session,
                &TestSubject {
                    name: "Alice".into(),
                },
                &TestAction,
                &TestResource,
                &TestContext,
            )
            .await;

        assert!(
            result.is_granted(),
            "A deny-effect builder policy should not override a later allow under PermissionChecker OR semantics"
        );
    }

    // Test that extra conditions (combining multiple inputs) work correctly.
    #[tokio::test]
    async fn test_policy_builder_with_extra_condition() {
        #[derive(Debug, Clone)]
        struct ExtendedSubject {
            pub id: Uuid,
            pub name: String,
        }
        #[derive(Debug, Clone)]
        struct ExtendedResource {
            pub owner_id: Uuid,
        }
        #[derive(Debug, Clone)]
        struct ExtendedAction;
        #[derive(Debug, Clone)]
        struct ExtendedContext;

        // Build a policy that checks:
        //   1. Subject's name is "Alice"
        //   2. And that subject.id == resource.owner_id (via extra condition)
        let subject_id = Uuid::new_v4();
        let policy = PolicyBuilder::<
            ExtendedSubject,
            ExtendedResource,
            ExtendedAction,
            ExtendedContext,
        >::new("AliceOwnerPolicy")
        .subjects(|s: &ExtendedSubject| s.name == "Alice")
        .when(|s, _a, r, _c| s.id == r.owner_id)
        .build();

        // Case where both conditions are met.
        let result1 = policy
            .evaluate_access(
                &ExtendedSubject {
                    id: subject_id,
                    name: "Alice".into(),
                },
                &ExtendedAction,
                &ExtendedResource {
                    owner_id: subject_id,
                },
                &ExtendedContext,
            )
            .await;
        assert!(
            result1.is_granted(),
            "Policy should allow access when conditions are met"
        );

        // Case where extra condition fails (different id)
        let result2 = policy
            .evaluate_access(
                &ExtendedSubject {
                    id: subject_id,
                    name: "Alice".into(),
                },
                &ExtendedAction,
                &ExtendedResource {
                    owner_id: Uuid::new_v4(),
                },
                &ExtendedContext,
            )
            .await;
        assert!(
            !result2.is_granted(),
            "Policy should deny access when extra condition fails"
        );
    }

    // Test action predicate
    #[tokio::test]
    async fn test_policy_builder_with_action_predicate() {
        #[derive(Debug, Clone)]
        struct ActionType {
            pub name: String,
        }

        let policy = PolicyBuilder::<TestSubject, TestResource, ActionType, TestContext>::new(
            "ActionPolicy",
        )
        .actions(|a: &ActionType| a.name == "read")
        .build();

        // Should allow for "read" action
        let result = policy
            .evaluate_access(
                &TestSubject {
                    name: "Anyone".into(),
                },
                &ActionType {
                    name: "read".into(),
                },
                &TestResource,
                &TestContext,
            )
            .await;
        assert!(result.is_granted(), "Policy should allow 'read' action");

        // Should deny for "write" action
        let result = policy
            .evaluate_access(
                &TestSubject {
                    name: "Anyone".into(),
                },
                &ActionType {
                    name: "write".into(),
                },
                &TestResource,
                &TestContext,
            )
            .await;
        assert!(!result.is_granted(), "Policy should deny 'write' action");
    }

    // Test resource predicate
    #[tokio::test]
    async fn test_policy_builder_with_resource_predicate() {
        #[derive(Debug, Clone)]
        struct ResourceType {
            pub public: bool,
        }

        let policy = PolicyBuilder::<TestSubject, ResourceType, TestAction, TestContext>::new(
            "ResourcePolicy",
        )
        .resources(|r: &ResourceType| r.public)
        .build();

        // Should allow access to public resource
        let result = policy
            .evaluate_access(
                &TestSubject {
                    name: "Anyone".into(),
                },
                &TestAction,
                &ResourceType { public: true },
                &TestContext,
            )
            .await;
        assert!(result.is_granted(), "Policy should allow public resource");

        // Should deny access to private resource
        let result = policy
            .evaluate_access(
                &TestSubject {
                    name: "Anyone".into(),
                },
                &TestAction,
                &ResourceType { public: false },
                &TestContext,
            )
            .await;
        assert!(!result.is_granted(), "Policy should deny private resource");
    }

    // Test context predicate
    #[tokio::test]
    async fn test_policy_builder_with_context_predicate() {
        #[derive(Debug, Clone)]
        struct RequestContext {
            pub is_internal: bool,
        }

        let policy = PolicyBuilder::<TestSubject, TestResource, TestAction, RequestContext>::new(
            "ContextPolicy",
        )
        .context(|c: &RequestContext| c.is_internal)
        .build();

        // Should allow for internal requests
        let result = policy
            .evaluate_access(
                &TestSubject {
                    name: "Anyone".into(),
                },
                &TestAction,
                &TestResource,
                &RequestContext { is_internal: true },
            )
            .await;
        assert!(result.is_granted(), "Policy should allow internal requests");

        // Should deny for external requests
        let result = policy
            .evaluate_access(
                &TestSubject {
                    name: "Anyone".into(),
                },
                &TestAction,
                &TestResource,
                &RequestContext { is_internal: false },
            )
            .await;
        assert!(!result.is_granted(), "Policy should deny external requests");
    }

    // Test combining all predicates
    #[tokio::test]
    async fn test_policy_builder_with_all_predicates_combined() {
        #[derive(Debug, Clone)]
        struct FullSubject {
            pub role: String,
        }
        #[derive(Debug, Clone)]
        struct FullAction {
            pub name: String,
        }
        #[derive(Debug, Clone)]
        struct FullResource {
            pub category: String,
        }
        #[derive(Debug, Clone)]
        struct FullContext {
            pub time_of_day: String,
        }

        // Policy: admin can read documents during business hours
        let policy =
            PolicyBuilder::<FullSubject, FullResource, FullAction, FullContext>::new("FullPolicy")
                .subjects(|s: &FullSubject| s.role == "admin")
                .actions(|a: &FullAction| a.name == "read")
                .resources(|r: &FullResource| r.category == "document")
                .context(|c: &FullContext| c.time_of_day == "business_hours")
                .build();

        // All conditions met - should allow
        let result = policy
            .evaluate_access(
                &FullSubject {
                    role: "admin".into(),
                },
                &FullAction {
                    name: "read".into(),
                },
                &FullResource {
                    category: "document".into(),
                },
                &FullContext {
                    time_of_day: "business_hours".into(),
                },
            )
            .await;
        assert!(
            result.is_granted(),
            "Policy should allow when all conditions are met"
        );

        // Wrong role - should deny
        let result = policy
            .evaluate_access(
                &FullSubject {
                    role: "user".into(),
                },
                &FullAction {
                    name: "read".into(),
                },
                &FullResource {
                    category: "document".into(),
                },
                &FullContext {
                    time_of_day: "business_hours".into(),
                },
            )
            .await;
        assert!(!result.is_granted(), "Policy should deny wrong role");

        // Wrong action - should deny
        let result = policy
            .evaluate_access(
                &FullSubject {
                    role: "admin".into(),
                },
                &FullAction {
                    name: "write".into(),
                },
                &FullResource {
                    category: "document".into(),
                },
                &FullContext {
                    time_of_day: "business_hours".into(),
                },
            )
            .await;
        assert!(!result.is_granted(), "Policy should deny wrong action");

        // Wrong resource - should deny
        let result = policy
            .evaluate_access(
                &FullSubject {
                    role: "admin".into(),
                },
                &FullAction {
                    name: "read".into(),
                },
                &FullResource {
                    category: "video".into(),
                },
                &FullContext {
                    time_of_day: "business_hours".into(),
                },
            )
            .await;
        assert!(!result.is_granted(), "Policy should deny wrong resource");

        // Wrong context - should deny
        let result = policy
            .evaluate_access(
                &FullSubject {
                    role: "admin".into(),
                },
                &FullAction {
                    name: "read".into(),
                },
                &FullResource {
                    category: "document".into(),
                },
                &FullContext {
                    time_of_day: "after_hours".into(),
                },
            )
            .await;
        assert!(!result.is_granted(), "Policy should deny wrong context");
    }
}
