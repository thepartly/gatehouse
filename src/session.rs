use crate::{FactKey, FactLoadError, FactLoadResult, FactSource, FactSourceRegistrationError};
use futures_channel::oneshot;
use std::any::{Any, TypeId};
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::Hasher;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use tracing::Instrument;

const FACT_STATE_STRIPES: usize = 64;

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
    stripes: Box<[Mutex<FactStripe<K>>]>,
}

struct FactStripe<K>
where
    K: FactKey,
{
    cache: HashMap<K, FactLoadResult<K::Value>>,
    in_flight: HashMap<K, Vec<oneshot::Sender<()>>>,
}

impl<K> Default for FactStripe<K>
where
    K: FactKey,
{
    fn default() -> Self {
        Self {
            cache: HashMap::new(),
            in_flight: HashMap::new(),
        }
    }
}

impl<K> FactState<K>
where
    K: FactKey,
{
    fn new(source: Option<Arc<dyn FactSource<K>>>) -> Self {
        let stripes = (0..FACT_STATE_STRIPES)
            .map(|_| Mutex::new(FactStripe::default()))
            .collect();

        Self {
            source: Mutex::new(source),
            stripes,
        }
    }

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

        if stripes.iter().any(|stripe| !stripe.in_flight.is_empty()) {
            return Err(FactSourceRegistrationError::InFlight { fact_name: K::NAME });
        }

        *source_guard = Some(source);
        for stripe in &mut stripes {
            stripe.cache.clear();
        }
        Ok(())
    }

    fn lock_stripes(&self) -> Vec<MutexGuard<'_, FactStripe<K>>> {
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
        let key_stripes = keys
            .iter()
            .map(|key| self.stripe_index(key))
            .collect::<Vec<_>>();
        let mut seen = HashSet::new();
        let unique_keys = keys
            .iter()
            .zip(key_stripes.iter().copied())
            .filter(|(key, _)| seen.insert((*key).clone()))
            .map(|(key, stripe_index)| (key.clone(), stripe_index))
            .collect::<Vec<_>>();

        let source_guard = self
            .source
            .lock()
            .expect("fact source mutex should not be poisoned");
        let source = source_guard.clone();

        let cached_results = keys
            .iter()
            .zip(key_stripes.iter().copied())
            .map(|(key, stripe_index)| {
                let stripe = self.stripes[stripe_index]
                    .lock()
                    .expect("fact state stripe mutex should not be poisoned");
                stripe.cache.get(key).cloned()
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

        let mut missing = Vec::new();
        let mut waiters = Vec::new();

        for (key, stripe_index) in unique_keys {
            let mut stripe = self.stripes[stripe_index]
                .lock()
                .expect("fact state stripe mutex should not be poisoned");

            if stripe.cache.contains_key(&key) {
                continue;
            }

            if let Some(existing_waiters) = stripe.in_flight.get_mut(&key) {
                let (sender, receiver) = oneshot::channel();
                existing_waiters.push(sender);
                waiters.push(receiver);
            } else {
                stripe.in_flight.insert(key.clone(), Vec::new());
                missing.push(key.clone());
            }
        }

        LoadPlan {
            source,
            cached_results: None,
            keys: missing,
            waiters,
        }
    }

    fn finish_in_flight(&self, keys: &[K]) {
        let mut waiters = Vec::new();

        for key in keys {
            let stripe_index = self.stripe_index(key);
            let mut stripe = self.stripes[stripe_index]
                .lock()
                .expect("fact state stripe mutex should not be poisoned");
            if let Some(key_waiters) = stripe.in_flight.remove(key) {
                waiters.extend(key_waiters);
            }
        }

        for waiter in waiters {
            let _ = waiter.send(());
        }
    }

    fn cache_loaded(&self, keys: &[K], results: Vec<FactLoadResult<K::Value>>) {
        for (key, result) in keys.iter().cloned().zip(results) {
            let stripe_index = self.stripe_index(&key);
            let mut stripe = self.stripes[stripe_index]
                .lock()
                .expect("fact state stripe mutex should not be poisoned");
            stripe.cache.insert(key, result);
        }
    }

    fn results_from_cache(&self, keys: &[K]) -> Vec<FactLoadResult<K::Value>> {
        keys.iter()
            .map(|key| {
                let stripe_index = self.stripe_index(key);
                let stripe = self.stripes[stripe_index]
                    .lock()
                    .expect("fact state stripe mutex should not be poisoned");
                stripe.cache.get(key).cloned().unwrap_or_else(|| {
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
    /// tight loops such as fanout or SSE frame authorization. It is only safe
    /// when no fact-backed policies are expected. Calling [`Self::register`],
    /// [`Self::register_arc`], [`Self::replace`], or [`Self::replace_arc`] on
    /// this session will panic.
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
                    if loaded.len() == chunk.len() {
                        state.cache_loaded(chunk, loaded);
                    } else {
                        state.cache_loaded(
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
                state.cache_loaded(
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

    fn finish(&mut self, keys: &[K]) {
        self.state.finish_in_flight(keys);
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

        self.state.cache_loaded(
            &self.remaining,
            self.remaining
                .iter()
                .map(|_| {
                    FactLoadResult::Error(FactLoadError::LoaderCancelled { fact_name: K::NAME })
                })
                .collect(),
        );
        self.state.finish_in_flight(&self.remaining);
    }
}
