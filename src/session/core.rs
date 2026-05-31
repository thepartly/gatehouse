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
    /// the source-vs-planner models below. Uses `LOOM_STRIPES = 2` so
    /// multi-stripe interleavings are reachable; production has 64. The
    /// keying is `K(n).0 % LOOM_STRIPES` so `K(0)` and `K(1)` land on
    /// different stripes.
    ///
    /// Drift hazard: this adapter mirrors the production `FactState` lock
    /// discipline. If `FactState::insert_source` or `plan_loads` change their
    /// lock ordering, this mirror must follow.
    const LOOM_STRIPES: usize = 2;

    struct LoomAdapter {
        source: Mutex<Option<u32>>,
        stripes: [Mutex<FactStripeCore<K, LoomWaiter>>; LOOM_STRIPES],
    }

    impl LoomAdapter {
        fn new(initial_source: Option<u32>) -> Self {
            Self {
                source: Mutex::new(initial_source),
                stripes: [
                    Mutex::new(FactStripeCore::new()),
                    Mutex::new(FactStripeCore::new()),
                ],
            }
        }

        fn stripe_index(key: &K) -> usize {
            (key.0 as usize) % LOOM_STRIPES
        }

        /// Plan-equivalent: snapshot source, peek cache. The source lock is
        /// held across the stripe peek — the same discipline as
        /// `FactState::plan_loads` — so replacement either fully precedes
        /// or fully follows the planning observation.
        fn plan(&self, key: &K) -> (Option<u32>, Option<FactLoadResult<u32>>) {
            let source_guard = self.source.lock().unwrap();
            let source = *source_guard;
            let stripe = self.stripes[Self::stripe_index(key)].lock().unwrap();
            let cached = stripe.peek_cache(key);
            (source, cached)
        }

        /// Replace-equivalent: acquire source, then ALL stripes (in index
        /// order), check idle, swap, clear caches, atomically.
        fn replace(&self, new_source: u32) -> bool {
            let mut source_guard = self.source.lock().unwrap();
            let mut s0 = self.stripes[0].lock().unwrap();
            let mut s1 = self.stripes[1].lock().unwrap();
            if !s0.is_idle() || !s1.is_idle() {
                return false;
            }
            *source_guard = Some(new_source);
            s0.clear_cache();
            s1.clear_cache();
            true
        }

        /// Single-threaded helper: claim leader and finish in one call.
        fn seed_cache(&self, key: K, value: u32) {
            let mut stripe = self.stripes[Self::stripe_index(&key)].lock().unwrap();
            let outcome = stripe.try_register::<_, LoomWaiter>(&key, || unreachable!());
            assert!(matches!(outcome, Registration::Leading));
            stripe.finish(key, FactLoadResult::Found(value));
        }

        /// Single-threaded helper: claim leader only. The caller is then
        /// responsible for calling `finish_leader` later (possibly from
        /// another thread).
        fn lead(&self, key: &K) {
            let mut stripe = self.stripes[Self::stripe_index(key)].lock().unwrap();
            let outcome = stripe.try_register::<_, LoomWaiter>(key, || unreachable!());
            assert!(matches!(outcome, Registration::Leading));
        }

        /// Finish a previously-claimed leader. Signals any joined waiters
        /// outside the stripe lock.
        fn finish_leader(&self, key: K, value: u32) {
            let waiters = {
                let mut stripe = self.stripes[Self::stripe_index(&key)].lock().unwrap();
                stripe.finish(key, FactLoadResult::Found(value))
            };
            signal_all(waiters);
        }
    }

    // Model 5: replacement is atomic w.r.t. planning.
    // Setup: source = Some(1), cache has K(1) -> Found(100).
    // Thread A plans; thread B replaces source with 2 (clearing cache).
    // Loom explores both orderings; the only legal observations are:
    //   * (Some(1), Some(Found(100))) — plan ran first
    //   * (Some(2), None)             — replace ran first
    // FORBIDDEN: (Some(2), Some(Found(100))) — new source + stale cache.
    //
    // (The reverse-order framing — thread B plans, thread A replaces — is
    // the same loom model under thread-spawn renaming. Loom permutes
    // schedules already; we don't need a second test to express it.)
    #[test]
    fn loom_replacement_is_atomic_with_respect_to_planning() {
        loom::model(|| {
            let adapter = Arc::new(LoomAdapter::new(Some(1)));
            adapter.seed_cache(K(1), 100);

            let a1 = adapter.clone();
            let t1 = thread::spawn(move || a1.plan(&K(1)));

            let a2 = adapter.clone();
            let t2 = thread::spawn(move || a2.replace(2));

            let (source_seen, cached_seen) = t1.join().unwrap();
            let replaced = t2.join().unwrap();
            assert!(
                replaced,
                "stripe is idle (seed_cache finished); replace must succeed under every schedule"
            );

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

    // Model 6: unrelated keys on different stripes do not interfere.
    // Setup: K(0) and K(1) route to stripe 0 and stripe 1 respectively.
    // Two threads concurrently claim+finish their key. After both join,
    // each stripe contains exactly its own cached value — no cross-stripe
    // state leak under any schedule.
    #[test]
    fn loom_unrelated_stripes_are_independent() {
        loom::model(|| {
            let adapter = Arc::new(LoomAdapter::new(None));
            assert_ne!(
                LoomAdapter::stripe_index(&K(0)),
                LoomAdapter::stripe_index(&K(1)),
                "test setup requires K(0) and K(1) on different stripes"
            );

            let a1 = adapter.clone();
            let t1 = thread::spawn(move || {
                a1.lead(&K(0));
                a1.finish_leader(K(0), 10);
            });

            let a2 = adapter.clone();
            let t2 = thread::spawn(move || {
                a2.lead(&K(1));
                a2.finish_leader(K(1), 20);
            });

            t1.join().unwrap();
            t2.join().unwrap();

            match adapter.plan(&K(0)).1 {
                Some(FactLoadResult::Found(10)) => {}
                other => panic!("K(0) cache: expected Found(10), got {other:?}"),
            }
            match adapter.plan(&K(1)).1 {
                Some(FactLoadResult::Found(20)) => {}
                other => panic!("K(1) cache: expected Found(20), got {other:?}"),
            }
        });
    }

    // Model 7: replacement is rejected while a leader is in flight.
    // Setup: source = Some(1), K(1)'s stripe has a claimed-but-unfinished
    // leader. Thread A finishes the leader; thread B tries replace.
    // Legal observations:
    //   * B saw in-flight (ran before A's finish): returned false, source
    //     stays Some(1), K(1) cached at the finish value.
    //   * B saw idle (ran after A's finish): returned true, source becomes
    //     Some(2), cache cleared.
    // FORBIDDEN: replace returned true AND K(1) is still cached at the
    // old value — that would mean clear_cache was skipped, or replace
    // succeeded while the leader's finish hadn't yet committed.
    #[test]
    fn loom_replacement_rejected_while_in_flight() {
        loom::model(|| {
            let adapter = Arc::new(LoomAdapter::new(Some(1)));
            adapter.lead(&K(1));

            let a1 = adapter.clone();
            let t_finish = thread::spawn(move || a1.finish_leader(K(1), 77));

            let a2 = adapter.clone();
            let t_replace = thread::spawn(move || a2.replace(2));

            t_finish.join().unwrap();
            let replaced = t_replace.join().unwrap();
            let (source, cached) = adapter.plan(&K(1));

            match (replaced, source, cached) {
                // B rejected: A's finish stands.
                (false, Some(1), Some(FactLoadResult::Found(77))) => {}
                // B succeeded after A's finish: cache cleared.
                (true, Some(2), None) => {}
                other => panic!(
                    "in-flight replacement invariant violated: (replaced, source, cached) = {other:?}"
                ),
            }
        });
    }
}
