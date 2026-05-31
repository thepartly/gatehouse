mod core;

use self::core::{FactStripeCore, Registration};
use crate::{FactKey, FactLoadError, FactLoadResult, FactSource, FactSourceRegistrationError};
use futures_channel::oneshot;
use std::any::{Any, TypeId};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::Hasher;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use tracing::Instrument;

const FACT_STATE_STRIPES: usize = 64;

/// Production waiter type. The core stores these and the adapter signals
/// them by sending `()` after releasing the surrounding stripe lock.
type StripeWaiter = oneshot::Sender<()>;
/// Receiver type returned to the joining caller. The caller awaits it after
/// all stripe locks are released.
type StripeReceiver = oneshot::Receiver<()>;
/// Concrete instantiation of [`FactStripeCore`] used by the async adapter.
type StripeCore<K> = FactStripeCore<K, StripeWaiter>;

#[derive(Default)]
struct EvaluationSessionInner {
    states: Mutex<HashMap<TypeId, Box<dyn Any + Send + Sync>>>,
    next_load_id: AtomicU64,
    shared_empty: bool,
}

struct FactState<K>
where
    K: FactKey,
{
    source: Mutex<Option<Arc<dyn FactSource<K>>>>,
    stripes: Box<[Mutex<StripeCore<K>>]>,
}

impl<K> FactState<K>
where
    K: FactKey,
{
    fn new(source: Option<Arc<dyn FactSource<K>>>) -> Self {
        let stripes = (0..FACT_STATE_STRIPES)
            .map(|_| Mutex::new(StripeCore::<K>::new()))
            .collect();

        Self {
            source: Mutex::new(source),
            stripes,
        }
    }

    // LOCK ORDER: source -> stripes (in index order).
    //
    // Source registration and replacement acquire the source mutex first,
    // then all stripe mutexes in index order, before checking in-flight
    // state, swapping the source, and clearing per-stripe caches. The whole
    // sequence is one critical section. This is the invariant from #18 / #26:
    // a concurrent planner holding the source mutex cannot observe
    // new-source-with-stale-cache, and a replacement is rejected while any
    // stripe still has in-flight loaders.
    //
    // Readers (`plan_loads`) acquire the source mutex first, then one stripe
    // at a time. Single-stripe operations (`finish_keys`, `results_from_cache`)
    // take no source lock. The core itself holds no locks and contains no
    // `.await`; signaling happens outside the stripe lock.
    fn insert_source(
        &self,
        source: Arc<dyn FactSource<K>>,
        replace: bool,
    ) -> Result<(), FactSourceRegistrationError> {
        let mut source_guard = self
            .source
            .lock()
            .expect("fact source mutex should not be poisoned");
        let mut stripes = self.lock_stripes();

        if !replace && source_guard.is_some() {
            return Err(FactSourceRegistrationError::AlreadyRegistered { fact_name: K::NAME });
        }

        if stripes.iter().any(|stripe| !stripe.is_idle()) {
            return Err(FactSourceRegistrationError::InFlight { fact_name: K::NAME });
        }

        *source_guard = Some(source);
        for stripe in &mut stripes {
            stripe.clear_cache();
        }
        Ok(())
    }

    fn lock_stripes(&self) -> Vec<MutexGuard<'_, StripeCore<K>>> {
        self.stripes
            .iter()
            .map(|stripe| {
                stripe
                    .lock()
                    .expect("fact state stripe mutex should not be poisoned")
            })
            .collect()
    }

    fn stripe_index(&self, key: &K) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % self.stripes.len()
    }

    fn plan_loads(&self, keys: &[K]) -> LoadPlan<K> {
        // Precompute stripe indices BEFORE acquiring any locks. `K::hash` may
        // be user code with arbitrary cost; computing it outside the critical
        // section preserves the invariant that an expensive or blocking hash
        // for one key does not contend with planning for unrelated keys.
        let key_stripes = keys
            .iter()
            .map(|key| self.stripe_index(key))
            .collect::<Vec<_>>();

        // Source mutex is held across the whole planning step so that source
        // resolution, cache lookup, and in-flight registration are atomic
        // relative to a concurrent `insert_source` (see LOCK ORDER above).
        let source_guard = self
            .source
            .lock()
            .expect("fact source mutex should not be poisoned");
        let source = source_guard.clone();

        // Fast path: every input key already cached.
        let cached_results = keys
            .iter()
            .zip(key_stripes.iter().copied())
            .map(|(key, stripe_index)| {
                let stripe = self.stripes[stripe_index]
                    .lock()
                    .expect("fact state stripe mutex should not be poisoned");
                stripe.peek_cache(key)
            })
            .collect::<Option<Vec<_>>>();

        if let Some(results) = cached_results {
            return LoadPlan {
                source,
                cached_results: Some(results),
                keys: Vec::new(),
                waiters: Vec::new(),
            };
        }

        // Slow path: dedupe and register interest per unique key.
        let mut seen = std::collections::HashSet::new();
        let mut leader_keys = Vec::new();
        let mut waiters = Vec::new();

        for (key, stripe_index) in keys.iter().zip(key_stripes.iter().copied()) {
            if !seen.insert(key.clone()) {
                continue;
            }
            let mut stripe = self.stripes[stripe_index]
                .lock()
                .expect("fact state stripe mutex should not be poisoned");
            match stripe.try_register::<_, StripeReceiver>(key, || {
                let (sender, receiver) = oneshot::channel();
                (sender, receiver)
            }) {
                Registration::Cached(_) => {
                    // Already cached; `results_from_cache` will pick it up at
                    // the end of `get_many`.
                }
                Registration::Leading => leader_keys.push(key.clone()),
                Registration::Joined(receiver) => waiters.push(receiver),
            }
        }

        LoadPlan {
            source,
            cached_results: None,
            keys: leader_keys,
            waiters,
        }
    }

    /// Cache results for `keys` and signal any registered waiters.
    ///
    /// Cache writes and waiter removal happen under per-stripe locks; signals
    /// fire after all stripe locks have been released, matching the prior
    /// behavior of separate `cache_loaded` + `finish_in_flight` calls.
    fn finish_keys(&self, keys: &[K], results: Vec<FactLoadResult<K::Value>>) {
        debug_assert_eq!(keys.len(), results.len());
        let mut all_waiters = Vec::new();
        for (key, result) in keys.iter().cloned().zip(results.into_iter()) {
            let stripe_index = self.stripe_index(&key);
            let waiters = {
                let mut stripe = self.stripes[stripe_index]
                    .lock()
                    .expect("fact state stripe mutex should not be poisoned");
                stripe.finish(key, result)
            };
            all_waiters.extend(waiters);
        }
        for waiter in all_waiters {
            let _ = waiter.send(());
        }
    }

    fn results_from_cache(&self, keys: &[K]) -> Vec<FactLoadResult<K::Value>> {
        keys.iter()
            .map(|key| {
                let stripe_index = self.stripe_index(key);
                let stripe = self.stripes[stripe_index]
                    .lock()
                    .expect("fact state stripe mutex should not be poisoned");
                stripe.peek_cache(key).unwrap_or_else(|| {
                    FactLoadResult::Error(FactLoadError::SourceContractViolation {
                        fact_name: K::NAME,
                        expected: 1,
                        actual: 0,
                    })
                })
            })
            .collect()
    }
}

/// Request-scoped fact loading and caching state.
///
/// A session is intended to live for one request or one authorization pass. It
/// owns registered fact sources and caches loaded facts by key type. The cache
/// is deliberately not process-global. Cached facts and cached errors are
/// dropped with the session, so permission revocations or backend changes are
/// observed by the next request's session rather than being held process-wide.
///
/// There is intentionally no time-based (TTL) cache: freshness is governed by
/// session lifetime — drop the session to drop its cache. If you need caching
/// that outlives a single session (a process-wide cache with a TTL, say), layer
/// it inside a [`FactSource`] implementation. A source can hold its own
/// expiring cache and be shared across sessions via [`Self::register_arc`],
/// which keeps the session a simple request-scoped layer on top.
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
    /// For very hot RBAC/ABAC-only loops, use [`Self::shared_empty`] to avoid
    /// allocating a new empty session per call.
    pub fn empty() -> Self {
        Self::new()
    }

    /// Returns a process-wide empty session for hot paths that never use fact
    /// sources.
    ///
    /// This avoids allocating a new empty session for RBAC/ABAC-only checks in
    /// tight loops. It is only safe when no fact-backed policies are expected:
    /// calling [`Self::register`], [`Self::register_arc`], [`Self::replace`], or
    /// [`Self::replace_arc`] on this session panics.
    ///
    /// The panic is deliberate. Registering on the shared handle is a
    /// programming error, not a runtime condition — code that registers sources
    /// should own a [`Self::new`] session, and this handle exists only for
    /// fact-free hot paths. The non-panicking [`Self::try_register`] /
    /// [`Self::try_replace`] family still returns
    /// [`FactSourceRegistrationError::SharedEmptySession`] here rather than
    /// panicking, for callers that want to handle it. A type-state split (a
    /// separate "registrable" type) was considered but would push that
    /// distinction into every signature that accepts a `&EvaluationSession`,
    /// defeating the drop-in substitutability that makes this handle useful.
    pub fn shared_empty() -> &'static Self {
        static SHARED_EMPTY: OnceLock<EvaluationSession> = OnceLock::new();
        SHARED_EMPTY.get_or_init(|| EvaluationSession {
            inner: Arc::new(EvaluationSessionInner {
                shared_empty: true,
                ..EvaluationSessionInner::default()
            }),
        })
    }

    /// Starts building a request-scoped session with all fact sources declared
    /// in one place.
    pub fn builder() -> EvaluationSessionBuilder {
        EvaluationSessionBuilder::new()
    }

    /// Registers a fact source for one key type.
    ///
    /// Panics if a source for `K` is already registered. Use [`Self::replace`]
    /// when replacing a source is intentional. Register sources during session
    /// setup; registering while loads for the same key type are in flight is
    /// not a supported operation and will panic.
    ///
    /// This panicking form is meant for session setup, where a failed
    /// registration (a duplicate source, or a load already in flight) is a
    /// configuration bug that should fail loudly and immediately. Use
    /// [`Self::try_register`] when registration is driven by runtime input and
    /// you want to handle [`FactSourceRegistrationError`] rather than panic.
    pub fn register<K, S>(&self, source: S)
    where
        K: FactKey,
        S: FactSource<K> + 'static,
    {
        self.register_arc::<K>(Arc::new(source));
    }

    /// Registers a shared fact source for one key type.
    ///
    /// Panics if a source for `K` is already registered. Register sources
    /// during session setup; use [`Self::replace_arc`] only when overwriting is
    /// deliberate. Registering while loads for the same key type are in flight
    /// is not a supported operation and will panic.
    ///
    /// Use this form to share one source instance across many sessions: build
    /// the `Arc` once and `Arc::clone` it into each request's session (see
    /// [`EvaluationSessionBuilder::with_arc`]). [`Self::register`] takes the
    /// source by value and wraps it in a fresh `Arc` per call, so it cannot
    /// share a single instance; reach for `register_arc` when the source holds
    /// expensive shared state such as a connection pool or its own cache. Like
    /// [`Self::register`], it panics on invalid registration; use
    /// [`Self::try_register_arc`] to handle the error instead.
    ///
    /// The registry is keyed by the exact Rust fact key type. If two production
    /// backends serve the same logical shape, such as the same
    /// `RelationshipQuery<UserId, ConversationId, ParticipantRelation>`, they
    /// cannot both be registered under that exact type in one session. Wrap one
    /// ID/relation type or define distinct fact keys so each backend has a
    /// separate registry entry.
    pub fn register_arc<K>(&self, source: Arc<dyn FactSource<K>>)
    where
        K: FactKey,
    {
        self.try_register_arc::<K>(source)
            .unwrap_or_else(|error| panic!("{error}"));
    }

    /// Registers a fact source for one key type, returning an error instead of
    /// panicking if registration is invalid.
    pub fn try_register<K, S>(&self, source: S) -> Result<(), FactSourceRegistrationError>
    where
        K: FactKey,
        S: FactSource<K> + 'static,
    {
        self.try_register_arc::<K>(Arc::new(source))
    }

    /// Registers a shared fact source for one key type, returning an error
    /// instead of panicking if registration is invalid.
    pub fn try_register_arc<K>(
        &self,
        source: Arc<dyn FactSource<K>>,
    ) -> Result<(), FactSourceRegistrationError>
    where
        K: FactKey,
    {
        self.insert_source::<K>(source, false)
    }

    /// Explicitly replaces a fact source for one key type.
    ///
    /// Replacing a source clears any cached facts for that key type in this
    /// session. Replacing while loads for the same key type are in flight is
    /// not a supported operation and will panic.
    pub fn replace<K, S>(&self, source: S)
    where
        K: FactKey,
        S: FactSource<K> + 'static,
    {
        self.replace_arc::<K>(Arc::new(source));
    }

    /// Explicitly replaces a shared fact source for one key type.
    ///
    /// Replacing a source clears any cached facts for that key type in this
    /// session. Replacing while loads for the same key type are in flight is
    /// not a supported operation and will panic.
    pub fn replace_arc<K>(&self, source: Arc<dyn FactSource<K>>)
    where
        K: FactKey,
    {
        self.try_replace_arc::<K>(source)
            .unwrap_or_else(|error| panic!("{error}"));
    }

    /// Explicitly replaces a fact source for one key type, returning an error
    /// instead of panicking if replacement is invalid.
    pub fn try_replace<K, S>(&self, source: S) -> Result<(), FactSourceRegistrationError>
    where
        K: FactKey,
        S: FactSource<K> + 'static,
    {
        self.try_replace_arc::<K>(Arc::new(source))
    }

    /// Explicitly replaces a shared fact source for one key type, returning an
    /// error instead of panicking if replacement is invalid.
    pub fn try_replace_arc<K>(
        &self,
        source: Arc<dyn FactSource<K>>,
    ) -> Result<(), FactSourceRegistrationError>
    where
        K: FactKey,
    {
        self.insert_source::<K>(source, true)
    }

    fn insert_source<K>(
        &self,
        source: Arc<dyn FactSource<K>>,
        replace: bool,
    ) -> Result<(), FactSourceRegistrationError>
    where
        K: FactKey,
    {
        if self.inner.shared_empty {
            return Err(FactSourceRegistrationError::SharedEmptySession { fact_name: K::NAME });
        }

        let type_id = TypeId::of::<K>();
        let state = {
            let mut states = self
                .inner
                .states
                .lock()
                .expect("fact state registry mutex should not be poisoned");

            if let Some(existing) = states
                .get(&type_id)
                .and_then(|state| state.downcast_ref::<Arc<FactState<K>>>())
            {
                Arc::clone(existing)
            } else {
                let state = Arc::new(FactState::new(None));
                states.insert(type_id, Box::new(Arc::clone(&state)));
                state
            }
        };

        state.insert_source(source, replace)
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

        let state = self.state::<K>();
        let load_plan = state.plan_loads(keys);
        if let Some(results) = load_plan.cached_results {
            return results;
        }

        let mut in_flight_guard = InFlightGuard::new(Arc::clone(&state), load_plan.keys.clone());

        if !load_plan.keys.is_empty() {
            if let Some(source) = load_plan.source.as_ref() {
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
                    let results = if loaded.len() == chunk.len() {
                        loaded
                    } else {
                        chunk
                            .iter()
                            .map(|_| {
                                FactLoadResult::Error(FactLoadError::SourceContractViolation {
                                    fact_name: K::NAME,
                                    expected: chunk.len(),
                                    actual: loaded.len(),
                                })
                            })
                            .collect()
                    };
                    // Cache writes + waiter wake-ups happen synchronously under
                    // per-stripe locks via `finish_keys`. There is no `.await`
                    // between the cache write and the waiter signal, so the
                    // drop guard's cancellation cleanup only fires for keys
                    // that have not yet been finished.
                    state.finish_keys(chunk, results);
                    in_flight_guard.mark_finished(chunk);
                }
            } else {
                let results = load_plan
                    .keys
                    .iter()
                    .map(|_| {
                        FactLoadResult::Error(FactLoadError::SourceNotRegistered {
                            fact_name: K::NAME,
                        })
                    })
                    .collect();
                state.finish_keys(&load_plan.keys, results);
                in_flight_guard.mark_finished(&load_plan.keys);
            }
        }

        for waiter in load_plan.waiters {
            let _ = waiter.await;
        }

        state.results_from_cache(keys)
    }

    fn state<K>(&self) -> Arc<FactState<K>>
    where
        K: FactKey,
    {
        let mut states = self
            .inner
            .states
            .lock()
            .expect("fact state registry mutex should not be poisoned");
        states
            .entry(TypeId::of::<K>())
            .or_insert_with(|| Box::new(Arc::new(FactState::<K>::new(None))))
            .downcast_ref::<Arc<FactState<K>>>()
            .expect("fact state type should match registry key")
            .clone()
    }
}

/// Builder for declaring all fact sources needed by a request-scoped
/// [`EvaluationSession`].
pub struct EvaluationSessionBuilder {
    session: EvaluationSession,
}

impl EvaluationSessionBuilder {
    fn new() -> Self {
        Self {
            session: EvaluationSession::new(),
        }
    }

    /// Registers a source for one fact key type.
    ///
    /// Panics if the same fact key type is registered twice.
    pub fn with<K, S>(self, source: S) -> Self
    where
        K: FactKey,
        S: FactSource<K> + 'static,
    {
        self.session.register::<K, _>(source);
        self
    }

    /// Registers a shared source for one fact key type.
    ///
    /// Panics if the same fact key type is registered twice.
    pub fn with_arc<K>(self, source: Arc<dyn FactSource<K>>) -> Self
    where
        K: FactKey,
    {
        self.session.register_arc::<K>(source);
        self
    }

    /// Finishes the session.
    pub fn build(self) -> EvaluationSession {
        self.session
    }
}

struct LoadPlan<K>
where
    K: FactKey,
{
    source: Option<Arc<dyn FactSource<K>>>,
    cached_results: Option<Vec<FactLoadResult<K::Value>>>,
    keys: Vec<K>,
    waiters: Vec<oneshot::Receiver<()>>,
}

struct InFlightGuard<K>
where
    K: FactKey,
{
    state: Arc<FactState<K>>,
    remaining: Vec<K>,
}

impl<K> InFlightGuard<K>
where
    K: FactKey,
{
    fn new(state: Arc<FactState<K>>, keys: Vec<K>) -> Self {
        Self {
            state,
            remaining: keys,
        }
    }

    /// Mark `keys` as finished by the leader so the drop guard does not
    /// re-finish them with `LoaderCancelled` on cancellation.
    fn mark_finished(&mut self, keys: &[K]) {
        if self.remaining.is_empty() {
            return;
        }
        let finished = keys
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<_>>();
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
        let cancelled = std::mem::take(&mut self.remaining);
        let results = cancelled
            .iter()
            .map(|_| FactLoadResult::Error(FactLoadError::LoaderCancelled { fact_name: K::NAME }))
            .collect();
        self.state.finish_keys(&cancelled, results);
    }
}
