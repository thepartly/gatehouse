//! Synchronous core of the session fact-load state machine.
//!
//! This module owns the per-stripe cache and in-flight state and the state
//! transitions that act on them. It is intentionally side-effect-light:
//!
//! * No `async`, no `.await`, no Tokio.
//! * No `FactSource`, no I/O.
//! * No concrete channel type. The waiter payload `W` is a fully abstract
//!   storable that the adapter knows how to signal.
//! * No tracing. The adapter wraps load I/O with spans.
//!
//! The async adapter (`super::FactState`) owns the locks that serialize these
//! transitions, the source mutex, the runtime-specific waiter type
//! (`oneshot::Sender<()>` in production), and the tracing spans around
//! `FactSource::load_many(...).await`. This split keeps the protocol
//! invariants (leader election, waiter wake-up, cancellation, replacement
//! atomicity) deterministically testable without needing to induce precise
//! Tokio timing.

use crate::{FactKey, FactLoadResult};
use std::collections::hash_map::Entry;
use std::collections::HashMap;

/// Per-stripe synchronous state for one fact key type.
///
/// `W` is the waiter payload type. The core stores `W` values and returns them
/// from `finish` so the adapter can signal them outside the lock.
pub(super) struct FactStripeCore<K, W>
where
    K: FactKey,
{
    cache: HashMap<K, FactLoadResult<K::Value>>,
    in_flight: HashMap<K, Vec<W>>,
}

/// Outcome of [`FactStripeCore::try_register`].
#[derive(Debug)]
pub(super) enum Registration<V, R> {
    /// The key was already cached. The cached value is returned.
    Cached(FactLoadResult<V>),
    /// No load was in flight for this key. The caller is now the leader and
    /// owns an empty in-flight slot for the key.
    Leading,
    /// A load was already in flight. The `make_pair` closure was invoked to
    /// create a (waiter, receiver) pair; the waiter is stored on the
    /// in-flight entry and the receiver is returned to the caller.
    Joined(R),
}

impl<K, W> FactStripeCore<K, W>
where
    K: FactKey,
{
    pub(super) fn new() -> Self {
        Self {
            cache: HashMap::new(),
            in_flight: HashMap::new(),
        }
    }

    /// Snapshot a cached entry, if any. Used by the all-cached fast path in
    /// the planner.
    pub(super) fn peek_cache(&self, key: &K) -> Option<FactLoadResult<K::Value>> {
        self.cache.get(key).cloned()
    }

    /// Register interest in `key`.
    ///
    /// Returns [`Registration::Cached`] if the value is already cached;
    /// [`Registration::Leading`] if no load was in flight and the caller is
    /// now responsible for driving the load; [`Registration::Joined`] if a
    /// load was already in flight and the caller is joining as a waiter.
    ///
    /// `make_pair` is invoked only on the `Joined` branch. The waiter is
    /// stored on the in-flight entry; the receiver is returned in the
    /// [`Registration::Joined`] variant.
    pub(super) fn try_register<F, R>(&mut self, key: &K, make_pair: F) -> Registration<K::Value, R>
    where
        F: FnOnce() -> (W, R),
    {
        if let Some(cached) = self.cache.get(key) {
            return Registration::Cached(cached.clone());
        }
        match self.in_flight.entry(key.clone()) {
            Entry::Occupied(mut existing) => {
                let (waiter, receiver) = make_pair();
                existing.get_mut().push(waiter);
                Registration::Joined(receiver)
            }
            Entry::Vacant(slot) => {
                slot.insert(Vec::new());
                Registration::Leading
            }
        }
    }

    /// Cache `result` for `key` and return any registered waiters.
    ///
    /// The cache write and the waiter removal happen in one synchronous
    /// transition; the caller signals the returned waiters after releasing
    /// the surrounding lock. Used for successful loads, source contract
    /// violations, missing-source errors, and loader cancellation.
    pub(super) fn finish(&mut self, key: K, result: FactLoadResult<K::Value>) -> Vec<W> {
        let waiters = self.in_flight.remove(&key).unwrap_or_default();
        self.cache.insert(key, result);
        waiters
    }

    /// True iff this stripe has no in-flight loads.
    ///
    /// Used by source registration/replacement to decide whether a swap is
    /// safe.
    pub(super) fn is_idle(&self) -> bool {
        self.in_flight.is_empty()
    }

    /// Clear all cached results. Used by source replacement once every
    /// stripe has been observed idle under the registry lock.
    pub(super) fn clear_cache(&mut self) {
        self.cache.clear();
    }
}

impl<K, W> Default for FactStripeCore<K, W>
where
    K: FactKey,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FactLoadError;

    #[derive(Clone, Debug, Eq, Hash, PartialEq)]
    struct K(u32);

    impl FactKey for K {
        type Value = u32;
        const NAME: &'static str = "test";
    }

    // Simple opaque waiter ID for deterministic tests.
    type Wid = u32;

    fn assert_found(result: &FactLoadResult<u32>, expected: u32) {
        match result {
            FactLoadResult::Found(value) => assert_eq!(*value, expected),
            other => panic!("expected Found({expected}), got {other:?}"),
        }
    }

    fn assert_cancelled(result: &FactLoadResult<u32>) {
        match result {
            FactLoadResult::Error(FactLoadError::LoaderCancelled { fact_name }) => {
                assert_eq!(*fact_name, K::NAME);
            }
            other => panic!("expected LoaderCancelled, got {other:?}"),
        }
    }

    fn expect_leading<R: std::fmt::Debug>(reg: Registration<u32, R>) {
        match reg {
            Registration::Leading => {}
            other => panic!("expected Leading, got {other:?}"),
        }
    }

    fn expect_joined<R>(reg: Registration<u32, R>) -> R {
        match reg {
            Registration::Joined(r) => r,
            Registration::Leading => panic!("expected Joined, got Leading"),
            Registration::Cached(_) => panic!("expected Joined, got Cached"),
        }
    }

    fn lead<W>(core: &mut FactStripeCore<K, W>, key: K) {
        expect_leading(
            core.try_register::<_, ()>(&key, || panic!("make_pair should not run on Leading")),
        );
    }

    #[test]
    fn peek_cache_empty_is_none() {
        let core = FactStripeCore::<K, Wid>::new();
        assert!(core.peek_cache(&K(1)).is_none());
    }

    #[test]
    fn finish_caches_value_and_extracts_waiters_in_order() {
        let mut core = FactStripeCore::<K, Wid>::new();
        lead(&mut core, K(1));

        let r0 = expect_joined(core.try_register(&K(1), || (10u32, "r0")));
        let r1 = expect_joined(core.try_register(&K(1), || (11u32, "r1")));
        assert_eq!(r0, "r0");
        assert_eq!(r1, "r1");

        let waiters = core.finish(K(1), FactLoadResult::Found(42));
        assert_eq!(
            waiters,
            vec![10u32, 11u32],
            "waiters returned in join order"
        );
        assert_found(&core.peek_cache(&K(1)).expect("cached"), 42);
        assert!(core.is_idle(), "in-flight entry removed");
    }

    #[test]
    fn second_finish_for_same_key_returns_no_waiters() {
        let mut core = FactStripeCore::<K, Wid>::new();
        lead(&mut core, K(7));
        let _ = core.finish(K(7), FactLoadResult::Found(7));

        let waiters = core.finish(K(7), FactLoadResult::Found(8));
        assert!(waiters.is_empty(), "no waiters on a second finish");
        assert_found(&core.peek_cache(&K(7)).expect("cached"), 8);
    }

    #[test]
    fn try_register_returns_cached_when_present() {
        let mut core = FactStripeCore::<K, Wid>::new();
        lead(&mut core, K(3));
        let _ = core.finish(K(3), FactLoadResult::Found(30));

        match core.try_register::<_, ()>(&K(3), || panic!("closure must not fire on Cached")) {
            Registration::Cached(value) => assert_found(&value, 30),
            other => panic!("expected Cached, got {other:?}"),
        }
    }

    #[test]
    fn cancellation_caches_loader_cancelled_and_wakes_waiters() {
        let mut core = FactStripeCore::<K, Wid>::new();
        lead(&mut core, K(9));
        expect_joined(core.try_register(&K(9), || (1u32, ())));
        expect_joined(core.try_register(&K(9), || (2u32, ())));

        // Adapter-side cancellation: finish with LoaderCancelled.
        let waiters = core.finish(
            K(9),
            FactLoadResult::Error(FactLoadError::LoaderCancelled { fact_name: K::NAME }),
        );
        assert_eq!(waiters, vec![1u32, 2u32]);
        assert_cancelled(&core.peek_cache(&K(9)).expect("cached"));
        assert!(core.is_idle());
    }

    #[test]
    fn unrelated_keys_are_independent() {
        let mut core = FactStripeCore::<K, Wid>::new();
        lead(&mut core, K(1));
        lead(&mut core, K(2));
        assert!(!core.is_idle(), "two in-flight entries");

        let waiters_for_1 = core.finish(K(1), FactLoadResult::Found(100));
        assert!(waiters_for_1.is_empty());
        assert_found(&core.peek_cache(&K(1)).expect("cached"), 100);
        assert!(core.peek_cache(&K(2)).is_none(), "K(2) still loading");
        assert!(!core.is_idle(), "K(2) still in flight");

        let _ = core.finish(K(2), FactLoadResult::Found(200));
        assert!(core.is_idle());
    }

    #[test]
    fn is_idle_reflects_in_flight_state() {
        let mut core = FactStripeCore::<K, Wid>::new();
        assert!(core.is_idle());
        lead(&mut core, K(1));
        assert!(!core.is_idle());
        let _ = core.finish(K(1), FactLoadResult::Found(1));
        assert!(core.is_idle());
    }

    #[test]
    fn clear_cache_drops_cached_entries() {
        let mut core = FactStripeCore::<K, Wid>::new();
        lead(&mut core, K(1));
        let _ = core.finish(K(1), FactLoadResult::Found(100));
        assert_found(&core.peek_cache(&K(1)).expect("cached"), 100);

        core.clear_cache();
        assert!(core.peek_cache(&K(1)).is_none());
        assert!(core.is_idle(), "clear_cache does not touch in-flight");
    }

    #[test]
    fn clear_cache_with_active_in_flight_keeps_in_flight() {
        // Defensive: clear_cache should never be called while in-flight exists
        // (the adapter checks is_idle first). Verify the core does not corrupt
        // state if it is misused.
        let mut core = FactStripeCore::<K, Wid>::new();
        lead(&mut core, K(1));
        expect_joined(core.try_register(&K(1), || (5u32, ())));
        core.clear_cache();
        let waiters = core.finish(K(1), FactLoadResult::Found(11));
        assert_eq!(waiters, vec![5u32]);
        assert_found(&core.peek_cache(&K(1)).expect("cached"), 11);
    }
}

// =============================================================================
// Loom permutation-test harness.
//
// Enabled with `RUSTFLAGS="--cfg loom" cargo test --lib --release`. Loom runs
// each `loom::model { ... }` block under a bounded model of every legal thread
// interleaving and asserts the invariant holds for all of them.
//
// What loom covers here:
// * Leader election uniqueness for one key under concurrent registrations.
// * Waiter wake-up on `finish`, exactly once per waiter.
// * Fail-closed cancellation: dropping the leader caches `LoaderCancelled`
//   and wakes every registered waiter.
// * Cache writes published by `finish` are visible to a concurrent
//   `peek_cache` reader.
// * Source replacement is atomic w.r.t. planning: a reader never observes a
//   new source paired with the old cache.
// * Idle replacement clears cache atomically.
//
// What loom does NOT cover here:
// * The async adapter end-to-end. Loom cannot model `tokio::sync::oneshot`
//   or the async runtime; the harness substitutes a loom-friendly waiter.
// * Tracing spans, fact-load IDs, or chunking. Those are exercised by the
//   normal async integration tests.
// * Deep preemption sequences. Models bound thread count to 2 and run the
//   smallest scenario that exercises each invariant.
//
// Adding a new model: keep it tight (2 threads, 1-2 keys), assert one
// invariant explicitly, and prefer `loom::sync::Arc<loom::sync::Mutex<_>>`
// around the core over building a richer adapter.
// =============================================================================
// Gated on `cfg(all(test, loom))` because `loom` is a `cfg(loom)`-only
// dev-dependency. Without the `test` gate, `cargo check --lib --cfg loom`
// would fail to resolve `loom::*` since dev-deps are only linked into the
// test build.
#[cfg(all(test, loom))]
mod loom_tests {
    use super::*;
    use crate::FactLoadError;
    use loom::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use loom::sync::{Arc, Mutex};
    use loom::thread;

    #[derive(Clone, Debug, Eq, Hash, PartialEq)]
    struct K(u32);

    impl FactKey for K {
        type Value = u32;
        const NAME: &'static str = "loom";
    }

    /// Loom-compatible waiter. The leader/canceller calls `signal` after the
    /// cache is committed; waiters read `signal_count` to observe wake-up.
    ///
    /// Counts rather than flags so models can assert "exactly once" rather
    /// than "at least once". A double-signal is detectable as count > 1.
    #[derive(Clone)]
    struct LoomWaiter {
        count: Arc<AtomicUsize>,
    }

    impl LoomWaiter {
        fn new() -> Self {
            Self {
                count: Arc::new(AtomicUsize::new(0)),
            }
        }
        fn signal(&self) {
            self.count.fetch_add(1, Ordering::Release);
        }
        fn signal_count(&self) -> usize {
            self.count.load(Ordering::Acquire)
        }
        fn is_signaled(&self) -> bool {
            self.signal_count() > 0
        }
    }

    /// Drain `finish`-returned waiters and signal each. Always called after
    /// releasing the surrounding stripe lock, matching the production
    /// adapter's discipline.
    fn signal_all(waiters: Vec<LoomWaiter>) {
        for w in waiters {
            w.signal();
        }
    }

    type Stripe = Arc<Mutex<FactStripeCore<K, LoomWaiter>>>;

    fn new_stripe() -> Stripe {
        Arc::new(Mutex::new(FactStripeCore::<K, LoomWaiter>::new()))
    }

    // Model 1: leader election uniqueness.
    // Two threads concurrently `try_register` the same key on an empty
    // stripe. Exactly one must become Leading; the other becomes Joined.
    #[test]
    fn loom_leader_election_is_unique() {
        loom::model(|| {
            let stripe = new_stripe();

            let s1 = stripe.clone();
            let t1 = thread::spawn(move || {
                let w = LoomWaiter::new();
                let stored = w.clone();
                let mut g = s1.lock().unwrap();
                g.try_register::<_, LoomWaiter>(&K(1), || (stored, w))
            });

            let s2 = stripe.clone();
            let t2 = thread::spawn(move || {
                let w = LoomWaiter::new();
                let stored = w.clone();
                let mut g = s2.lock().unwrap();
                g.try_register::<_, LoomWaiter>(&K(1), || (stored, w))
            });

            let r1 = t1.join().unwrap();
            let r2 = t2.join().unwrap();

            let leading = matches!(r1, Registration::Leading) as u8
                + matches!(r2, Registration::Leading) as u8;
            assert_eq!(
                leading, 1,
                "exactly one of the two registrations must become Leading"
            );
        });
    }

    // Model 2: waiters are woken exactly once on finish.
    // The main thread pre-claims leader so the waiter thread always sees
    // Joined or Cached (this isolates the wake-up invariant from leader
    // election, which model 1 covers). If the joiner registers before the
    // finisher runs, finish must wake its waiter exactly once — counted
    // via `LoomWaiter::signal_count` to detect both lost and double wakes.
    #[test]
    fn loom_waiters_woken_exactly_once_on_finish() {
        loom::model(|| {
            let stripe = new_stripe();
            {
                let mut g = stripe.lock().unwrap();
                let outcome = g.try_register::<_, LoomWaiter>(&K(1), || {
                    unreachable!("first try_register must be Leading")
                });
                assert!(matches!(outcome, Registration::Leading));
            }

            let s1 = stripe.clone();
            let waiter = LoomWaiter::new();
            let waiter_for_thread = waiter.clone();
            let joined = Arc::new(AtomicBool::new(false));
            let joined_for_thread = joined.clone();
            let t1 = thread::spawn(move || {
                let stored = waiter_for_thread.clone();
                let receiver = waiter_for_thread.clone();
                let mut g = s1.lock().unwrap();
                let outcome = g.try_register::<_, LoomWaiter>(&K(1), || (stored, receiver));
                if matches!(outcome, Registration::Joined(_)) {
                    joined_for_thread.store(true, Ordering::Release);
                }
            });

            let s2 = stripe.clone();
            let t2 = thread::spawn(move || {
                let waiters = {
                    let mut g = s2.lock().unwrap();
                    g.finish(K(1), FactLoadResult::Found(7))
                };
                signal_all(waiters);
            });

            t1.join().unwrap();
            t2.join().unwrap();

            if joined.load(Ordering::Acquire) {
                assert_eq!(
                    waiter.signal_count(),
                    1,
                    "a waiter that registered before finish must be signaled exactly once \
                     (lost wake -> 0, double wake -> >1)"
                );
            } else {
                // Joiner ran after finish: it saw Cached and was never
                // stored as a waiter, so the signal count stays 0.
                assert_eq!(
                    waiter.signal_count(),
                    0,
                    "a joiner that saw Cached must never receive a signal"
                );
                // The joiner ran after finish: it saw Cached and was not
                // stored as a waiter. The cache holds the value.
                let cached = stripe
                    .lock()
                    .unwrap()
                    .peek_cache(&K(1))
                    .expect("finish writes cache");
                match cached {
                    FactLoadResult::Found(v) => assert_eq!(v, 7),
                    other => panic!("expected Found(7), got {other:?}"),
                }
            }
        });
    }

    // Model 3: cancellation is fail-closed.
    // Leader pre-claimed; one thread joins, another finishes with
    // LoaderCancelled (simulating `InFlightGuard::drop`). If the joiner
    // registered first, its waiter is signaled. The cache holds
    // LoaderCancelled either way.
    #[test]
    fn loom_cancellation_is_fail_closed() {
        loom::model(|| {
            let stripe = new_stripe();
            {
                let mut g = stripe.lock().unwrap();
                let outcome = g.try_register::<_, LoomWaiter>(&K(1), || unreachable!());
                assert!(matches!(outcome, Registration::Leading));
            }

            let s1 = stripe.clone();
            let waiter = LoomWaiter::new();
            let waiter_for_thread = waiter.clone();
            let joined = Arc::new(AtomicBool::new(false));
            let joined_for_thread = joined.clone();
            let t1 = thread::spawn(move || {
                let stored = waiter_for_thread.clone();
                let receiver = waiter_for_thread.clone();
                let mut g = s1.lock().unwrap();
                let outcome = g.try_register::<_, LoomWaiter>(&K(1), || (stored, receiver));
                if matches!(outcome, Registration::Joined(_)) {
                    joined_for_thread.store(true, Ordering::Release);
                }
            });

            let s2 = stripe.clone();
            let t2 = thread::spawn(move || {
                let waiters = {
                    let mut g = s2.lock().unwrap();
                    g.finish(
                        K(1),
                        FactLoadResult::Error(FactLoadError::LoaderCancelled {
                            fact_name: K::NAME,
                        }),
                    )
                };
                signal_all(waiters);
            });

            t1.join().unwrap();
            t2.join().unwrap();

            if joined.load(Ordering::Acquire) {
                assert_eq!(
                    waiter.signal_count(),
                    1,
                    "a waiter that joined before cancellation must be signaled exactly once"
                );
            } else {
                assert_eq!(
                    waiter.signal_count(),
                    0,
                    "a joiner that saw Cached after cancellation must never receive a signal"
                );
            }
            let cached = stripe
                .lock()
                .unwrap()
                .peek_cache(&K(1))
                .expect("finish writes cache");
            match cached {
                FactLoadResult::Error(FactLoadError::LoaderCancelled { .. }) => {}
                other => panic!("expected LoaderCancelled, got {other:?}"),
            }
        });
    }

    // Model 4: cache write is visible to a concurrent peek.
    // One thread finishes (cache write under the mutex). Another peeks.
    // Either order is legal; the observation is never a torn read.
    #[test]
    fn loom_cache_write_is_visible_to_concurrent_peek() {
        loom::model(|| {
            let stripe = new_stripe();

            let s1 = stripe.clone();
            let t1 = thread::spawn(move || {
                let waiters = {
                    let mut g = s1.lock().unwrap();
                    g.finish(K(1), FactLoadResult::Found(99))
                };
                signal_all(waiters);
            });

            let s2 = stripe.clone();
            let t2 = thread::spawn(move || -> Option<FactLoadResult<u32>> {
                let g = s2.lock().unwrap();
                g.peek_cache(&K(1))
            });

            t1.join().unwrap();
            let observed = t2.join().unwrap();
            match observed {
                None => {}
                Some(FactLoadResult::Found(v)) => assert_eq!(v, 99),
                other => panic!("unexpected cache observation: {other:?}"),
            }
        });
    }

    /// Tiny adapter mirroring `FactState::insert_source` / `plan_loads` for
    /// the source-vs-planner models below. One stripe is enough to exercise
    /// the source-held-across-planning discipline; production has 64.
    struct LoomAdapter {
        source: Mutex<Option<u32>>,
        stripe: Mutex<FactStripeCore<K, LoomWaiter>>,
    }

    impl LoomAdapter {
        fn new(initial_source: Option<u32>) -> Self {
            Self {
                source: Mutex::new(initial_source),
                stripe: Mutex::new(FactStripeCore::new()),
            }
        }

        /// Plan-equivalent: snapshot source, peek cache. The source lock is
        /// held while peeking — the same discipline as
        /// `FactState::plan_loads` — so replacement either fully precedes
        /// or fully follows the planning observation.
        fn plan(&self, key: &K) -> (Option<u32>, Option<FactLoadResult<u32>>) {
            let source_guard = self.source.lock().unwrap();
            let source = *source_guard;
            let stripe = self.stripe.lock().unwrap();
            let cached = stripe.peek_cache(key);
            (source, cached)
        }

        /// Replace-equivalent: acquire source, then stripe, check idle, swap,
        /// clear cache, atomically.
        fn replace(&self, new_source: u32) -> bool {
            let mut source_guard = self.source.lock().unwrap();
            let mut stripe_guard = self.stripe.lock().unwrap();
            if !stripe_guard.is_idle() {
                return false;
            }
            *source_guard = Some(new_source);
            stripe_guard.clear_cache();
            true
        }

        /// Single-threaded test setup helper. Not part of the modeled
        /// protocol; runs before any thread is spawned.
        fn seed_cache(&self, key: K, value: u32) {
            let mut stripe = self.stripe.lock().unwrap();
            let outcome = stripe.try_register::<_, LoomWaiter>(&key, || unreachable!());
            assert!(matches!(outcome, Registration::Leading));
            stripe.finish(key, FactLoadResult::Found(value));
        }
    }

    // Model 5: replacement is atomic w.r.t. planning.
    // Setup: source = Some(1), cache has K(1) -> Found(100).
    // Thread A plans; thread B replaces source with 2 (clearing cache).
    // The only legal observations from A are:
    //   * (Some(1), Some(Found(100))) — plan ran first
    //   * (Some(2), None)             — replace ran first
    // FORBIDDEN: (Some(2), Some(Found(100))) — new source + stale cache.
    #[test]
    fn loom_replacement_is_atomic_with_respect_to_planning() {
        loom::model(|| {
            let adapter = Arc::new(LoomAdapter::new(Some(1)));
            adapter.seed_cache(K(1), 100);

            let a1 = adapter.clone();
            let t1 = thread::spawn(move || a1.plan(&K(1)));

            let a2 = adapter.clone();
            let t2 = thread::spawn(move || {
                assert!(a2.replace(2));
            });

            let (source_seen, cached_seen) = t1.join().unwrap();
            t2.join().unwrap();

            match (source_seen, cached_seen) {
                (Some(1), Some(FactLoadResult::Found(100))) => {}
                (Some(2), None) => {}
                other => panic!(
                    "atomicity violation: planner observed {other:?}; \
                     new source must never be paired with stale cache"
                ),
            }
        });
    }

    // Model 6: idle replacement clears cache atomically.
    // Same shape as model 5 but spelled out as "the cache is never a stale
    // hit under the new source." Kept distinct so a regression to the
    // clear_cache step is immediately attributable.
    #[test]
    fn loom_idle_replacement_clears_cache() {
        loom::model(|| {
            let adapter = Arc::new(LoomAdapter::new(Some(1)));
            adapter.seed_cache(K(1), 200);

            let a1 = adapter.clone();
            let t1 = thread::spawn(move || {
                assert!(a1.replace(2));
            });

            let a2 = adapter.clone();
            let t2 = thread::spawn(move || a2.plan(&K(1)));

            t1.join().unwrap();
            let (source_seen, cached_seen) = t2.join().unwrap();

            match (source_seen, cached_seen) {
                (Some(2), None) => {}
                (Some(1), Some(FactLoadResult::Found(200))) => {}
                (Some(1), None) => {}
                other => panic!("idle replacement broke atomicity: observed {other:?}"),
            }
        });
    }
}
