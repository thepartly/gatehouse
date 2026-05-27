use async_trait::async_trait;
use gatehouse::{
    EvaluationSession, FactKey, FactLoadError, FactLoadResult, FactSource,
    FactSourceRegistrationError,
};
use proptest::prelude::*;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
use tokio::sync::Notify;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TestKey(u16);

impl FactKey for TestKey {
    type Value = u16;

    const NAME: &'static str = "test";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct OtherKey(u16);

impl FactKey for OtherKey {
    type Value = u16;

    const NAME: &'static str = "other";
}

#[derive(Clone)]
struct BlockingHashKey {
    value: u16,
    blocker: Option<Arc<HashBlocker>>,
}

impl BlockingHashKey {
    fn plain(value: u16) -> Self {
        Self {
            value,
            blocker: None,
        }
    }

    fn blocking(value: u16, blocker: Arc<HashBlocker>) -> Self {
        Self {
            value,
            blocker: Some(blocker),
        }
    }
}

impl std::fmt::Debug for BlockingHashKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("BlockingHashKey").field(&self.value).finish()
    }
}

impl PartialEq for BlockingHashKey {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Eq for BlockingHashKey {}

impl Hash for BlockingHashKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.value.hash(state);
        if let Some(blocker) = &self.blocker {
            blocker.block_once();
        }
    }
}

impl FactKey for BlockingHashKey {
    type Value = u16;

    const NAME: &'static str = "blocking_hash";
}

struct HashBlocker {
    should_block: AtomicBool,
    entered: AtomicBool,
    released: Mutex<bool>,
    released_changed: Condvar,
}

impl HashBlocker {
    fn new() -> Self {
        Self {
            should_block: AtomicBool::new(true),
            entered: AtomicBool::new(false),
            released: Mutex::new(false),
            released_changed: Condvar::new(),
        }
    }

    fn block_once(&self) {
        if !self.should_block.swap(false, Ordering::SeqCst) {
            return;
        }

        self.entered.store(true, Ordering::SeqCst);
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.released_changed.wait(released).unwrap();
        }
    }

    async fn wait_until_entered(&self) {
        while !self.entered.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    }

    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.released_changed.notify_all();
    }
}

type TestCalls = Arc<Mutex<Vec<Vec<TestKey>>>>;
type TestResponse = Arc<dyn Fn(&[TestKey]) -> Vec<FactLoadResult<u16>> + Send + Sync>;

#[derive(Clone)]
struct RecordingSource {
    calls: TestCalls,
    max_batch_size: Option<NonZeroUsize>,
    response: TestResponse,
}

impl RecordingSource {
    fn echo(calls: TestCalls) -> Self {
        Self::new(calls, None, |keys| {
            keys.iter()
                .map(|key| FactLoadResult::Found(key.0))
                .collect()
        })
    }

    fn new(
        calls: TestCalls,
        max_batch_size: Option<NonZeroUsize>,
        response: impl Fn(&[TestKey]) -> Vec<FactLoadResult<u16>> + Send + Sync + 'static,
    ) -> Self {
        Self {
            calls,
            max_batch_size,
            response: Arc::new(response),
        }
    }
}

#[async_trait]
impl FactSource<TestKey> for RecordingSource {
    async fn load_many(&self, keys: &[TestKey]) -> Vec<FactLoadResult<u16>> {
        self.calls.lock().unwrap().push(keys.to_vec());
        (self.response)(keys)
    }

    fn max_batch_size(&self) -> Option<NonZeroUsize> {
        self.max_batch_size
    }
}

struct OtherSource;

#[async_trait]
impl FactSource<OtherKey> for OtherSource {
    async fn load_many(&self, keys: &[OtherKey]) -> Vec<FactLoadResult<u16>> {
        keys.iter()
            .map(|key| FactLoadResult::Found(key.0))
            .collect()
    }
}

struct BlockingHashSource;

#[async_trait]
impl FactSource<BlockingHashKey> for BlockingHashSource {
    async fn load_many(&self, keys: &[BlockingHashKey]) -> Vec<FactLoadResult<u16>> {
        keys.iter()
            .map(|key| FactLoadResult::Found(key.value))
            .collect()
    }
}

struct NeverCompletesSource {
    calls: Arc<AtomicUsize>,
    started: Arc<Notify>,
}

#[async_trait]
impl FactSource<TestKey> for NeverCompletesSource {
    async fn load_many(&self, keys: &[TestKey]) -> Vec<FactLoadResult<u16>> {
        assert_eq!(keys, &[TestKey(7)]);
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.started.notify_one();
        std::future::pending().await
    }
}

struct PartiallyBlockingSource {
    blocked_calls: Arc<AtomicUsize>,
    started: Arc<Notify>,
}

#[async_trait]
impl FactSource<TestKey> for PartiallyBlockingSource {
    async fn load_many(&self, keys: &[TestKey]) -> Vec<FactLoadResult<u16>> {
        if keys == [TestKey(7)] {
            self.blocked_calls.fetch_add(1, Ordering::SeqCst);
            self.started.notify_one();
            std::future::pending().await
        } else {
            keys.iter()
                .map(|key| FactLoadResult::Found(key.0))
                .collect()
        }
    }
}

struct BlockingErrorSource {
    calls: Arc<AtomicUsize>,
    started: Arc<Notify>,
    release: Arc<Notify>,
}

#[async_trait]
impl FactSource<TestKey> for BlockingErrorSource {
    async fn load_many(&self, keys: &[TestKey]) -> Vec<FactLoadResult<u16>> {
        assert_eq!(keys, &[TestKey(8)]);
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.started.notify_one();
        self.release.notified().await;
        vec![FactLoadResult::Error(FactLoadError::backend_message(
            "down",
        ))]
    }
}

struct PanicSource {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl FactSource<TestKey> for PanicSource {
    async fn load_many(&self, _keys: &[TestKey]) -> Vec<FactLoadResult<u16>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        panic!("source panic");
    }
}

fn new_calls() -> TestCalls {
    Arc::new(Mutex::new(Vec::new()))
}

fn session_with_source(source: impl FactSource<TestKey> + 'static) -> EvaluationSession {
    let session = EvaluationSession::new();
    session.register::<TestKey, _>(source);
    session
}

fn assert_found(result: &FactLoadResult<u16>, expected: u16) {
    match result {
        FactLoadResult::Found(actual) => assert_eq!(*actual, expected),
        other => panic!("expected Found({expected}), got {other:?}"),
    }
}

fn assert_missing(result: &FactLoadResult<u16>) {
    assert!(
        matches!(result, FactLoadResult::Missing),
        "expected Missing, got {result:?}"
    );
}

fn assert_backend_error_contains(result: &FactLoadResult<u16>, expected: &str) {
    match result {
        FactLoadResult::Error(FactLoadError::Backend(error)) => {
            assert!(
                error.to_string().contains(expected),
                "expected backend error to contain {expected:?}, got {error}"
            );
        }
        other => panic!("expected backend Error, got {other:?}"),
    }
}

fn assert_source_not_registered(result: &FactLoadResult<u16>, fact_name: &'static str) {
    match result {
        FactLoadResult::Error(FactLoadError::SourceNotRegistered { fact_name: actual }) => {
            assert_eq!(*actual, fact_name);
        }
        other => panic!("expected SourceNotRegistered, got {other:?}"),
    }
}

fn assert_contract_violation(result: &FactLoadResult<u16>, expected: usize, actual: usize) {
    match result {
        FactLoadResult::Error(FactLoadError::SourceContractViolation {
            fact_name,
            expected: got_expected,
            actual: got_actual,
        }) => {
            assert_eq!(*fact_name, TestKey::NAME);
            assert_eq!(*got_expected, expected);
            assert_eq!(*got_actual, actual);
        }
        other => panic!("expected SourceContractViolation, got {other:?}"),
    }
}

fn assert_load_cancelled(result: &FactLoadResult<u16>) {
    match result {
        FactLoadResult::Error(FactLoadError::LoaderCancelled { fact_name }) => {
            assert_eq!(*fact_name, TestKey::NAME);
        }
        other => panic!("expected LoaderCancelled, got {other:?}"),
    }
}

fn panic_message(panic: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = panic.downcast_ref::<String>() {
        message.clone()
    } else if let Some(message) = panic.downcast_ref::<&'static str>() {
        message.to_string()
    } else {
        "<non-string panic>".to_string()
    }
}

fn first_unique(keys: &[TestKey]) -> Vec<TestKey> {
    let mut seen = HashSet::new();
    keys.iter()
        .copied()
        .filter(|key| seen.insert(*key))
        .collect()
}

#[tokio::test]
async fn get_many_preserves_order_duplicates_and_empty_batches() {
    let calls = new_calls();
    let session = session_with_source(RecordingSource::echo(Arc::clone(&calls)));

    let empty = session.get_many::<TestKey>(&[]).await;
    assert!(empty.is_empty());
    assert!(calls.lock().unwrap().is_empty());

    let single = session.get_many(&[TestKey(1)]).await;
    assert_found(&single[0], 1);
    assert_eq!(*calls.lock().unwrap(), vec![vec![TestKey(1)]]);

    let ordered = session
        .get_many(&[TestKey(1), TestKey(2), TestKey(3)])
        .await;
    assert_eq!(ordered.len(), 3);
    assert_found(&ordered[0], 1);
    assert_found(&ordered[1], 2);
    assert_found(&ordered[2], 3);
    assert_eq!(
        *calls.lock().unwrap(),
        vec![vec![TestKey(1)], vec![TestKey(2), TestKey(3)]]
    );

    let calls = new_calls();
    let session = session_with_source(RecordingSource::echo(Arc::clone(&calls)));
    let duplicated = session
        .get_many(&[TestKey(1), TestKey(2), TestKey(1), TestKey(1)])
        .await;
    assert_eq!(duplicated.len(), 4);
    for index in [0, 2, 3] {
        assert_found(&duplicated[index], 1);
    }
    assert_found(&duplicated[1], 2);
    assert_eq!(*calls.lock().unwrap(), vec![vec![TestKey(1), TestKey(2)]]);

    let calls = new_calls();
    let session = session_with_source(RecordingSource::echo(Arc::clone(&calls)));
    let thousand = vec![TestKey(9); 1_000];
    let results = session.get_many(&thousand).await;
    assert_eq!(results.len(), 1_000);
    assert!(results
        .iter()
        .all(|result| { matches!(result, FactLoadResult::Found(value) if *value == 9) }));
    assert_eq!(*calls.lock().unwrap(), vec![vec![TestKey(9)]]);
}

#[tokio::test]
async fn session_deduplicates_across_calls() {
    let calls = new_calls();
    let session = session_with_source(RecordingSource::echo(Arc::clone(&calls)));

    let first = session.get_many(&[TestKey(1), TestKey(2)]).await;
    assert_found(&first[0], 1);
    assert_found(&first[1], 2);

    let second = session.get_many(&[TestKey(2), TestKey(3)]).await;
    assert_found(&second[0], 2);
    assert_found(&second[1], 3);

    assert_eq!(
        *calls.lock().unwrap(),
        vec![vec![TestKey(1), TestKey(2)], vec![TestKey(3)]]
    );

    let _ = session.get(TestKey(1)).await;
    let _ = session.get(TestKey(1)).await;
    assert_eq!(calls.lock().unwrap().len(), 2);

    let third = session.get_many(&[TestKey(1), TestKey(4)]).await;
    assert_found(&third[0], 1);
    assert_found(&third[1], 4);
    assert_eq!(
        *calls.lock().unwrap(),
        vec![
            vec![TestKey(1), TestKey(2)],
            vec![TestKey(3)],
            vec![TestKey(4)]
        ]
    );
}

#[tokio::test]
async fn shared_source_serves_concurrent_sessions_with_separate_caches() {
    let calls = new_calls();
    let source: Arc<dyn FactSource<TestKey>> = Arc::new(RecordingSource::echo(Arc::clone(&calls)));
    let keys = vec![TestKey(1), TestKey(2), TestKey(1)];

    let sessions = (0..3)
        .map(|_| {
            EvaluationSession::builder()
                .with_arc::<TestKey>(Arc::clone(&source))
                .build()
        })
        .collect::<Vec<_>>();

    let handles = sessions
        .clone()
        .into_iter()
        .map(|session| {
            let keys = keys.clone();
            tokio::spawn(async move { session.get_many(&keys).await })
        })
        .collect::<Vec<_>>();

    for handle in handles {
        let results = handle.await.unwrap();
        assert_eq!(results.len(), 3);
        assert_found(&results[0], 1);
        assert_found(&results[1], 2);
        assert_found(&results[2], 1);
    }

    assert_eq!(
        calls.lock().unwrap().len(),
        3,
        "in-flight coalescing is per session, not global across shared sources"
    );

    for session in &sessions {
        let cached = session.get_many(&keys).await;
        assert_found(&cached[0], 1);
        assert_found(&cached[1], 2);
        assert_found(&cached[2], 1);
    }
    assert_eq!(
        calls.lock().unwrap().len(),
        3,
        "each session should reuse only its own request-scoped cache"
    );
}

#[tokio::test]
async fn fact_load_result_variants_round_trip_and_cache() {
    let calls = new_calls();
    let mut responses = HashMap::new();
    responses.insert(TestKey(1), FactLoadResult::Found(11));
    responses.insert(TestKey(2), FactLoadResult::Missing);
    responses.insert(
        TestKey(3),
        FactLoadResult::Error(FactLoadError::backend_message("boom")),
    );
    responses.insert(TestKey(4), FactLoadResult::Found(44));

    let session = session_with_source(RecordingSource::new(
        Arc::clone(&calls),
        None,
        move |keys| {
            keys.iter()
                .map(|key| responses.get(key).cloned().unwrap())
                .collect()
        },
    ));

    let results = session
        .get_many(&[TestKey(1), TestKey(2), TestKey(3), TestKey(4)])
        .await;
    assert_found(&results[0], 11);
    assert_missing(&results[1]);
    assert_backend_error_contains(&results[2], "boom");
    assert_found(&results[3], 44);
    assert_eq!(calls.lock().unwrap().len(), 1);

    let cached = session.get_many(&[TestKey(2), TestKey(3)]).await;
    assert_missing(&cached[0]);
    assert_backend_error_contains(&cached[1], "boom");
    assert_eq!(
        calls.lock().unwrap().len(),
        1,
        "Missing and Error should both be cached for the session"
    );
}

#[tokio::test]
async fn length_mismatch_fails_closed_and_is_cached() {
    for (actual_count, response) in [
        (2, vec![FactLoadResult::Found(1), FactLoadResult::Found(2)]),
        (
            4,
            vec![
                FactLoadResult::Found(1),
                FactLoadResult::Found(2),
                FactLoadResult::Found(3),
                FactLoadResult::Found(4),
            ],
        ),
    ] {
        let calls = new_calls();
        let response = response.clone();
        let session = session_with_source(RecordingSource::new(
            Arc::clone(&calls),
            None,
            move |_keys| response.clone(),
        ));

        let results = session
            .get_many(&[TestKey(1), TestKey(2), TestKey(3)])
            .await;
        assert_eq!(results.len(), 3);
        for result in &results {
            assert_contract_violation(result, 3, actual_count);
        }

        let cached = session.get(TestKey(1)).await;
        assert_contract_violation(&cached, 3, actual_count);
        assert_eq!(
            calls.lock().unwrap().len(),
            1,
            "contract errors should be cached for every affected key"
        );
    }
}

#[test]
fn source_panics_propagate_but_clean_in_flight_state() {
    let calls = Arc::new(AtomicUsize::new(0));
    let session = session_with_source(PanicSource {
        calls: Arc::clone(&calls),
    });
    let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        tokio_test::block_on(session.get(TestKey(1)));
    }));

    assert!(panic_result.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let cached = tokio_test::block_on(session.get(TestKey(1)));
    assert_load_cancelled(&cached);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn missing_sources_fail_closed_and_source_registration_is_explicit() {
    let empty = EvaluationSession::new();
    let missing = empty.get(TestKey(1)).await;
    assert_source_not_registered(&missing, TestKey::NAME);

    let session = EvaluationSession::new();
    let cached_missing = session.get(TestKey(1)).await;
    assert_source_not_registered(&cached_missing, TestKey::NAME);
    session.register::<TestKey, _>(RecordingSource::echo(new_calls()));
    assert_found(&session.get(TestKey(1)).await, 1);
    let missing_other = session.get(OtherKey(1)).await;
    assert_source_not_registered(&missing_other, OtherKey::NAME);

    let first_calls = new_calls();
    let second_calls = new_calls();
    let session = session_with_source(RecordingSource::new(
        Arc::clone(&first_calls),
        None,
        |_keys| vec![FactLoadResult::Found(1)],
    ));
    assert_found(&session.get(TestKey(1)).await, 1);

    let duplicate = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        session.register::<TestKey, _>(RecordingSource::new(
            Arc::clone(&second_calls),
            None,
            |_keys| vec![FactLoadResult::Found(2)],
        ));
    }));
    assert!(
        duplicate.is_err(),
        "duplicate registration should fail fast"
    );
    assert!(matches!(
        session.try_register::<TestKey, _>(RecordingSource::new(
            Arc::clone(&second_calls),
            None,
            |_keys| vec![FactLoadResult::Found(2)],
        )),
        Err(FactSourceRegistrationError::AlreadyRegistered {
            fact_name: TestKey::NAME
        })
    ));
    assert_found(&session.get(TestKey(1)).await, 1);
    assert_eq!(second_calls.lock().unwrap().len(), 0);

    session.replace::<TestKey, _>(RecordingSource::new(
        Arc::clone(&second_calls),
        None,
        |_keys| vec![FactLoadResult::Found(2)],
    ));
    assert_found(&session.get(TestKey(1)).await, 2);
    assert_eq!(first_calls.lock().unwrap().len(), 1);
    assert_eq!(second_calls.lock().unwrap().len(), 1);

    let other_session = EvaluationSession::builder()
        .with::<OtherKey, _>(OtherSource)
        .build();
    assert_found(&other_session.get(OtherKey(5)).await, 5);
}

#[tokio::test]
async fn source_registration_and_replacement_reject_in_flight_loads() {
    let calls = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let session = session_with_source(BlockingErrorSource {
        calls: Arc::clone(&calls),
        started: Arc::clone(&started),
        release: Arc::clone(&release),
    });

    let leader_session = session.clone();
    let leader = tokio::spawn(async move { leader_session.get(TestKey(8)).await });
    started.notified().await;

    let duplicate = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        session.register::<TestKey, _>(RecordingSource::echo(new_calls()));
    }))
    .expect_err("duplicate registration should panic before inspecting in-flight loads");
    assert!(
        panic_message(duplicate).contains("already registered"),
        "duplicate registration should keep the actionable duplicate-source message"
    );

    let replacement = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        session.replace::<TestKey, _>(RecordingSource::echo(new_calls()));
    }))
    .expect_err("replacement during in-flight load should panic");
    assert!(
        panic_message(replacement).contains("registered or replaced while loads"),
        "replacement panic should describe both public source-registration verbs"
    );
    assert!(matches!(
        session.try_replace::<TestKey, _>(RecordingSource::echo(new_calls())),
        Err(FactSourceRegistrationError::InFlight {
            fact_name: TestKey::NAME
        })
    ));

    release.notify_one();
    let leader_result = leader.await.unwrap();
    assert_backend_error_contains(&leader_result, "down");
}

#[test]
fn shared_empty_session_is_static_and_rejects_source_registration() {
    let first = EvaluationSession::shared_empty() as *const EvaluationSession;
    let second = EvaluationSession::shared_empty() as *const EvaluationSession;
    assert_eq!(first, second);

    let duplicate = std::panic::catch_unwind(|| {
        EvaluationSession::shared_empty()
            .register::<TestKey, _>(RecordingSource::echo(new_calls()));
    });
    assert!(
        duplicate.is_err(),
        "shared empty sessions must not become mutable source registries"
    );
    assert!(matches!(
        EvaluationSession::shared_empty()
            .try_register::<TestKey, _>(RecordingSource::echo(new_calls())),
        Err(FactSourceRegistrationError::SharedEmptySession {
            fact_name: TestKey::NAME
        })
    ));
}

#[tokio::test]
async fn source_max_batch_size_chunks_after_dedup_without_reordering() {
    let calls = new_calls();
    let session = session_with_source(RecordingSource::new(
        Arc::clone(&calls),
        NonZeroUsize::new(3),
        |keys| {
            keys.iter()
                .map(|key| FactLoadResult::Found(key.0))
                .collect()
        },
    ));
    let keys = (0..10).map(TestKey).collect::<Vec<_>>();
    let results = session.get_many(&keys).await;
    for (result, key) in results.iter().zip(&keys) {
        assert_found(result, key.0);
    }
    assert_eq!(
        *calls.lock().unwrap(),
        vec![
            vec![TestKey(0), TestKey(1), TestKey(2)],
            vec![TestKey(3), TestKey(4), TestKey(5)],
            vec![TestKey(6), TestKey(7), TestKey(8)],
            vec![TestKey(9)]
        ]
    );

    let calls = new_calls();
    let session = session_with_source(RecordingSource::new(
        Arc::clone(&calls),
        NonZeroUsize::new(1),
        |keys| {
            keys.iter()
                .map(|key| FactLoadResult::Found(key.0))
                .collect()
        },
    ));
    let keys = (0..5).map(TestKey).collect::<Vec<_>>();
    let _ = session.get_many(&keys).await;
    assert_eq!(calls.lock().unwrap().len(), 5);

    let calls = new_calls();
    let session = session_with_source(RecordingSource::echo(Arc::clone(&calls)));
    let keys = (0..1_000).map(TestKey).collect::<Vec<_>>();
    let _ = session.get_many(&keys).await;
    assert_eq!(calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn chunking_with_duplicates_expands_to_original_positions() {
    let calls = new_calls();
    let session = session_with_source(RecordingSource::new(
        Arc::clone(&calls),
        NonZeroUsize::new(2),
        |keys| {
            keys.iter()
                .map(|key| FactLoadResult::Found(key.0))
                .collect()
        },
    ));

    let results = session
        .get_many(&[TestKey(1), TestKey(2), TestKey(1), TestKey(3), TestKey(1)])
        .await;
    assert_eq!(
        results
            .iter()
            .map(|result| match result {
                FactLoadResult::Found(value) => *value,
                other => panic!("expected Found, got {other:?}"),
            })
            .collect::<Vec<_>>(),
        vec![1, 2, 1, 3, 1]
    );
    assert_eq!(
        *calls.lock().unwrap(),
        vec![vec![TestKey(1), TestKey(2)], vec![TestKey(3)]]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unrelated_fact_keys_do_not_contend_on_one_session_lock() {
    let blocker = Arc::new(HashBlocker::new());
    let session = EvaluationSession::builder()
        .with::<BlockingHashKey, _>(BlockingHashSource)
        .build();

    let leader_session = session.clone();
    let leader_blocker = Arc::clone(&blocker);
    let leader = tokio::spawn(async move {
        leader_session
            .get(BlockingHashKey::blocking(7, leader_blocker))
            .await
    });

    tokio::time::timeout(Duration::from_secs(1), blocker.wait_until_entered())
        .await
        .expect("leader should reach the intentionally blocked hash");

    let unrelated = tokio::time::timeout(
        Duration::from_millis(100),
        session.get(BlockingHashKey::plain(8)),
    )
    .await
    .expect("unrelated key should not wait on the blocked key's planning lock");
    assert_found(&unrelated, 8);

    blocker.release();
    let leader_result = leader.await.unwrap();
    assert_found(&leader_result, 7);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unrelated_fact_types_do_not_contend_on_one_session_lock() {
    let blocker = Arc::new(HashBlocker::new());
    let session = EvaluationSession::builder()
        .with::<BlockingHashKey, _>(BlockingHashSource)
        .with::<OtherKey, _>(OtherSource)
        .build();

    let leader_session = session.clone();
    let leader_blocker = Arc::clone(&blocker);
    let leader = tokio::spawn(async move {
        leader_session
            .get(BlockingHashKey::blocking(7, leader_blocker))
            .await
    });

    tokio::time::timeout(Duration::from_secs(1), blocker.wait_until_entered())
        .await
        .expect("leader should reach the intentionally blocked hash");

    let unrelated = tokio::time::timeout(Duration::from_millis(100), session.get(OtherKey(8)))
        .await
        .expect("unrelated fact type should not wait on the blocked key's planning lock");
    assert_found(&unrelated, 8);

    blocker.release();
    let leader_result = leader.await.unwrap();
    assert_found(&leader_result, 7);
}

#[tokio::test]
async fn cancelling_leader_get_cleans_in_flight_entry() {
    let calls = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(Notify::new());
    let session = session_with_source(NeverCompletesSource {
        calls: Arc::clone(&calls),
        started: Arc::clone(&started),
    });

    let leader_session = session.clone();
    let leader = tokio::spawn(async move { leader_session.get(TestKey(7)).await });
    started.notified().await;
    leader.abort();
    assert!(leader.await.unwrap_err().is_cancelled());

    let result = tokio::time::timeout(Duration::from_millis(100), session.get(TestKey(7)))
        .await
        .expect("follow-up get should not wait forever");
    assert_load_cancelled(&result);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_parallel_loader_wakes_waiters_and_preserves_unrelated_keys() {
    let blocked_calls = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(Notify::new());
    let session = session_with_source(PartiallyBlockingSource {
        blocked_calls: Arc::clone(&blocked_calls),
        started: Arc::clone(&started),
    });

    let leader_session = session.clone();
    let leader = tokio::spawn(async move { leader_session.get(TestKey(7)).await });
    started.notified().await;

    let waiter_session = session.clone();
    let waiter = tokio::spawn(async move { waiter_session.get(TestKey(7)).await });
    tokio::task::yield_now().await;

    leader.abort();
    assert!(leader.await.unwrap_err().is_cancelled());

    let waiter_result = tokio::time::timeout(Duration::from_millis(100), waiter)
        .await
        .expect("waiter should be woken when the leader is cancelled")
        .unwrap();
    assert_load_cancelled(&waiter_result);

    let unrelated = tokio::time::timeout(Duration::from_millis(100), session.get(TestKey(8)))
        .await
        .expect("unrelated key should still be loadable after cancellation");
    assert_found(&unrelated, 8);
    assert_eq!(blocked_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn concurrent_waiters_observe_same_source_error() {
    let calls = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let session = session_with_source(BlockingErrorSource {
        calls: Arc::clone(&calls),
        started: Arc::clone(&started),
        release: Arc::clone(&release),
    });

    let leader_session = session.clone();
    let leader = tokio::spawn(async move { leader_session.get(TestKey(8)).await });
    started.notified().await;

    let waiter_session = session.clone();
    let waiter = tokio::spawn(async move { waiter_session.get(TestKey(8)).await });
    tokio::task::yield_now().await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    release.notify_one();
    let leader_result = leader.await.unwrap();
    let waiter_result = waiter.await.unwrap();
    assert_backend_error_contains(&leader_result, "down");
    assert_backend_error_contains(&waiter_result, "down");

    let cached = session.get(TestKey(8)).await;
    assert_backend_error_contains(&cached, "down");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

proptest! {
    #[test]
    fn get_many_preserves_input_order_for_arbitrary_duplicate_keys(raw_keys in prop::collection::vec(0u16..32, 0..200)) {
        let keys = raw_keys.iter().copied().map(TestKey).collect::<Vec<_>>();
        let calls = new_calls();
        let session = session_with_source(RecordingSource::echo(Arc::clone(&calls)));

        let results = tokio_test::block_on(session.get_many(&keys));
        prop_assert_eq!(results.len(), keys.len());
        for (result, key) in results.iter().zip(&keys) {
            match result {
                FactLoadResult::Found(value) => prop_assert_eq!(*value, key.0),
                other => prop_assert!(false, "expected Found for {key:?}, got {other:?}"),
            }
        }

        let expected_unique = first_unique(&keys);
        let recorded = calls.lock().unwrap().clone();
        if expected_unique.is_empty() {
            prop_assert!(recorded.is_empty());
        } else {
            prop_assert_eq!(recorded, vec![expected_unique]);
        }
    }

    #[test]
    fn chunking_preserves_input_order_for_arbitrary_duplicate_keys(
        raw_keys in prop::collection::vec(0u16..64, 0..300),
        max in prop::option::of(1usize..8),
    ) {
        let keys = raw_keys.iter().copied().map(TestKey).collect::<Vec<_>>();
        let calls = new_calls();
        let max_batch_size = max.and_then(NonZeroUsize::new);
        let session = session_with_source(RecordingSource::new(
            Arc::clone(&calls),
            max_batch_size,
            |keys| keys.iter().map(|key| FactLoadResult::Found(key.0)).collect(),
        ));

        let results = tokio_test::block_on(session.get_many(&keys));
        prop_assert_eq!(results.len(), keys.len());
        for (result, key) in results.iter().zip(&keys) {
            match result {
                FactLoadResult::Found(value) => prop_assert_eq!(*value, key.0),
                other => prop_assert!(false, "expected Found for {key:?}, got {other:?}"),
            }
        }

        let expected_unique = first_unique(&keys);
        let expected_unique_is_empty = expected_unique.is_empty();
        let recorded = calls.lock().unwrap().clone();
        let flattened = recorded.iter().flatten().copied().collect::<Vec<_>>();
        prop_assert_eq!(flattened, expected_unique);
        if let Some(max) = max_batch_size {
            prop_assert!(recorded.iter().all(|chunk| chunk.len() <= max.get()));
        } else if !expected_unique_is_empty {
            prop_assert_eq!(recorded.len(), 1);
        }
    }
}
