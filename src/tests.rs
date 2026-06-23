use super::*;
use async_trait::async_trait;
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::Arc;

mod core_tests {
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

    trait TestPolicyExt<S, A, R, C>: Policy<S, A, R, C>
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

    impl<T, S, A, R, C> TestPolicyExt<S, A, R, C> for T
    where
        T: Policy<S, A, R, C>,
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
                let policy_type = self.policy_type();
                let ctx = EvalCtx {
                    session: &session,
                    subject,
                    action,
                    resource,
                    context,
                    policy_type,
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
                let policy_type = self.policy_type();
                let ctx = BatchEvalCtx {
                    session: &session,
                    subject,
                    action,
                    items,
                    policy_type,
                };
                self.evaluate_batch(&ctx).await
            })
        }
    }

    trait TestCheckerExt<S, A, R, C>
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

    impl<S, A, R, C> TestCheckerExt<S, A, R, C> for PermissionChecker<S, A, R, C>
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
                self.evaluate_batch_in_session(&session, subject, action, items, parts)
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
                self.filter_authorized_in_session(&session, subject, action, items, parts)
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

    /// Permissive no-op global subscriber. Installed once on first use so the
    /// process-wide tracing callsite cache locks in `Interest::sometimes` for
    /// every callsite. Without this, a parallel test thread that hits a
    /// tracing callsite before any subscriber is installed will poison the
    /// cache with `Interest::never`, and later threads using
    /// `with_default(...)` see zero events. This is the standard flake in
    /// tracing tests under parallel execution.
    struct PermissiveNoop;
    impl Subscriber for PermissiveNoop {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, _: &Event<'_>) {}
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    fn install_permissive_global() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            // Ignore the result: another crate may have already installed a
            // global. In that case the existing one is responsible for the
            // callsite-cache behavior; if it is also permissive, all good.
            let _ = tracing::subscriber::set_global_default(PermissiveNoop);
        });
    }

    fn with_recorded_events<T>(f: impl FnOnce() -> T) -> (T, Vec<RecordedEvent>) {
        install_permissive_global();
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
    impl Policy<TestSubject, TestAction, TestResource, TestContext> for AlwaysAllowPolicy {
        async fn evaluate(
            &self,
            _ctx: &EvalCtx<'_, TestSubject, TestAction, TestResource, TestContext>,
        ) -> PolicyEvalResult {
            PolicyEvalResult::granted(
                self.policy_type().to_string(),
                Some("Always allow policy".to_string()),
            )
        }

        fn policy_type(&self) -> std::borrow::Cow<'static, str> {
            std::borrow::Cow::Borrowed("AlwaysAllowPolicy")
        }
    }

    // A policy that always denies, with a custom reason
    struct AlwaysDenyPolicy(&'static str);

    #[async_trait]
    impl Policy<TestSubject, TestAction, TestResource, TestContext> for AlwaysDenyPolicy {
        async fn evaluate(
            &self,
            _ctx: &EvalCtx<'_, TestSubject, TestAction, TestResource, TestContext>,
        ) -> PolicyEvalResult {
            PolicyEvalResult::not_applicable(self.policy_type().to_string(), self.0)
        }

        fn policy_type(&self) -> std::borrow::Cow<'static, str> {
            std::borrow::Cow::Borrowed("AlwaysDenyPolicy")
        }
    }

    struct EvenResourceBatchPolicy {
        batch_calls: Arc<AtomicUsize>,
        single_calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Policy<TestSubject, TestAction, TestResource, TestContext> for EvenResourceBatchPolicy {
        async fn evaluate(
            &self,
            ctx: &EvalCtx<'_, TestSubject, TestAction, TestResource, TestContext>,
        ) -> PolicyEvalResult {
            self.single_calls.fetch_add(1, Ordering::SeqCst);
            if ctx.resource.id.as_u128() % 2 == 0 {
                PolicyEvalResult::granted(
                    self.policy_type().to_string(),
                    Some("even resource".to_string()),
                )
            } else {
                PolicyEvalResult::not_applicable(self.policy_type().to_string(), "odd resource")
            }
        }

        async fn evaluate_batch<'item>(
            &self,
            ctx: &BatchEvalCtx<'item, TestSubject, TestAction, TestResource, TestContext>,
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
                    policy_type: ctx.policy_type.clone(),
                };
                results.push(self.evaluate(&item_ctx).await);
            }
            results
        }

        fn policy_type(&self) -> std::borrow::Cow<'static, str> {
            std::borrow::Cow::Borrowed("EvenResourceBatchPolicy")
        }
    }

    struct MismatchedBatchPolicy;

    #[async_trait]
    impl Policy<TestSubject, TestAction, TestResource, TestContext> for MismatchedBatchPolicy {
        async fn evaluate(
            &self,
            _ctx: &EvalCtx<'_, TestSubject, TestAction, TestResource, TestContext>,
        ) -> PolicyEvalResult {
            PolicyEvalResult::granted(
                self.policy_type().to_string(),
                Some("single item fallback".to_string()),
            )
        }

        async fn evaluate_batch<'item>(
            &self,
            ctx: &BatchEvalCtx<'item, TestSubject, TestAction, TestResource, TestContext>,
        ) -> Vec<PolicyEvalResult> {
            ctx.items
                .iter()
                .skip(1)
                .map(|_| {
                    PolicyEvalResult::granted(
                        self.policy_type().to_string(),
                        Some("wrong batch length".to_string()),
                    )
                })
                .collect()
        }

        fn policy_type(&self) -> std::borrow::Cow<'static, str> {
            std::borrow::Cow::Borrowed("MismatchedBatchPolicy")
        }
    }

    struct CustomMetadataDenyPolicy;

    #[async_trait]
    impl Policy<TestSubject, TestAction, TestResource, TestContext> for CustomMetadataDenyPolicy {
        async fn evaluate(
            &self,
            _ctx: &EvalCtx<'_, TestSubject, TestAction, TestResource, TestContext>,
        ) -> PolicyEvalResult {
            PolicyEvalResult::not_applicable(
                self.policy_type().to_string(),
                "Blocked by custom rule",
            )
        }

        fn policy_type(&self) -> std::borrow::Cow<'static, str> {
            std::borrow::Cow::Borrowed("CustomMetadataDenyPolicy")
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
            PermissionChecker::<TestSubject, TestAction, TestResource, TestContext>::new();

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
        let inner: Arc<dyn Policy<TestSubject, TestAction, TestResource, TestContext>> =
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
        let inner: Arc<dyn Policy<TestSubject, TestAction, TestResource, TestContext>> =
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
        let inner: Arc<dyn Policy<TestSubject, TestAction, TestResource, TestContext>> =
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
        let inner: Arc<dyn Policy<TestSubject, TestAction, TestResource, TestContext>> =
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
    async fn test_not_policy_batch_tags_inner_leaves_with_inner_name() {
        // Regression test: NotPolicy::evaluate_batch must construct a fresh
        // BatchEvalCtx with the inner policy's policy_type before
        // forwarding, so any leaf the inner policy produces via
        // `ctx.grant` / `ctx.not_applicable` (or via the default evaluate_batch
        // that fans out per-item EvalCtx) is tagged with the inner's
        // name, not "NotPolicy".
        //
        // We pair NotPolicy with a local policy that builds its result via
        // `ctx.not_applicable(...)` — i.e. it reads ctx.policy_type. The inner
        // leaf in the resulting trace tree must be tagged with the inner policy,
        // not "NotPolicy".

        struct OddResourcePolicy;
        #[async_trait]
        impl Policy<TestSubject, TestAction, TestResource, TestContext> for OddResourcePolicy {
            async fn evaluate(
                &self,
                ctx: &EvalCtx<'_, TestSubject, TestAction, TestResource, TestContext>,
            ) -> PolicyEvalResult {
                if ctx.resource.id.as_u128() % 2 == 1 {
                    ctx.grant("odd id")
                } else {
                    ctx.not_applicable("even id")
                }
            }
            fn policy_type(&self) -> std::borrow::Cow<'static, str> {
                std::borrow::Cow::Borrowed("OddResourcePolicy")
            }
        }

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
        let policy = NotPolicy::new(OddResourcePolicy);

        let results = policy
            .evaluate_access_batch(&subject, &TestAction, &batch_items)
            .await;

        assert_eq!(results.len(), 2);
        // Drill into each Combined result, find the inner leaf, and
        // assert it carries the inner policy's name.
        for result in &results {
            match result {
                PolicyEvalResult::Combined { children, .. } => {
                    assert_eq!(children.len(), 1, "NotPolicy wraps exactly one child");
                    match &children[0] {
                        PolicyEvalResult::Granted { policy_type, .. }
                        | PolicyEvalResult::NotApplicable { policy_type, .. } => {
                            assert_eq!(
                                policy_type.as_ref(),
                                "OddResourcePolicy",
                                "inner leaf must be tagged with the wrapped policy's name, \
                                 not 'NotPolicy'"
                            );
                        }
                        other => panic!("expected leaf child, got {other:?}"),
                    }
                }
                other => panic!("expected Combined NotPolicy result, got {other:?}"),
            }
        }
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
        TestAction,
        TestResource,
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
        let session = FactRegistry::builder()
            .with::<RelationshipQuery<uuid::Uuid, uuid::Uuid, String>, _>(TestRelationshipSource {
                grants: HashSet::from([RelationshipQuery {
                    subject_id,
                    resource_id,
                    relation: relationship.clone(),
                }]),
                batch_sizes: Arc::new(Mutex::new(Vec::new())),
                max_batch_size: None,
            })
            .build()
            .session();
        let policy = relationship_policy(relationship);

        let ctx = EvalCtx {
            session: &session,
            subject: &subject,
            action: &TestAction,
            resource: &resource,
            context: &TestContext,
            policy_type: std::borrow::Cow::Borrowed("TestPolicy"),
        };
        let result = policy.evaluate(&ctx).await;

        assert!(result.is_granted());
        // A fact-backed grant records the consulted relationship as provenance.
        let provenance = result.provenance();
        assert_eq!(provenance.len(), 1);
        assert_eq!(provenance[0].fact_name, "relationship");
        assert_eq!(provenance[0].outcome, FactOutcome::Found);
        assert!(provenance[0].detail.is_none());
        // The rendered trace surfaces the fact inline.
        assert!(result.format(0).contains("↳ fact relationship [found]"));
    }

    #[tokio::test]
    async fn test_rebac_policy_records_provenance_on_load_error() {
        let policy = relationship_policy("manager".to_string());
        let subject = TestSubject {
            id: uuid::Uuid::new_v4(),
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };
        let session = FactRegistry::builder()
            .with::<RelationshipQuery<uuid::Uuid, uuid::Uuid, String>, _>(ErrorRelationshipSource)
            .build()
            .session();
        let ctx = EvalCtx {
            session: &session,
            subject: &subject,
            action: &TestAction,
            resource: &resource,
            context: &TestContext,
            policy_type: std::borrow::Cow::Borrowed("TestPolicy"),
        };

        let result = policy.evaluate(&ctx).await;

        assert!(!result.is_granted());
        let provenance = result.provenance();
        assert_eq!(provenance.len(), 1);
        assert_eq!(provenance[0].outcome, FactOutcome::Error);
        // The backend error message is carried as provenance detail.
        assert!(provenance[0].detail.is_some());
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
            policy_type: std::borrow::Cow::Borrowed("TestPolicy"),
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
            .filter(|resource| resource.id.as_u128() % 2 == 0)
            .map(|resource| RelationshipQuery {
                subject_id: subject.id,
                resource_id: resource.id,
                relation: relationship.clone(),
            })
            .collect::<HashSet<_>>();
        let session = FactRegistry::builder()
            .with::<RelationshipQuery<uuid::Uuid, uuid::Uuid, String>, _>(TestRelationshipSource {
                grants,
                batch_sizes: Arc::clone(&batch_sizes),
                max_batch_size: NonZeroUsize::new(2),
            })
            .build()
            .session();
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
            policy_type: policy.policy_type(),
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
        let session = FactRegistry::builder()
            .with::<RelationshipQuery<uuid::Uuid, uuid::Uuid, String>, _>(
                BlockingRelationshipSource {
                    calls: Arc::clone(&calls),
                    started: Arc::clone(&started),
                    release: Arc::clone(&release),
                },
            )
            .build()
            .session();
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
                let session = FactRegistry::builder()
                    .with::<RelationshipQuery<uuid::Uuid, uuid::Uuid, String>, _>(
                        MissingRelationshipSource,
                    )
                    .build()
                    .session();
                (session, "fact is missing")
            },
            {
                let session = FactRegistry::builder()
                    .with::<RelationshipQuery<uuid::Uuid, uuid::Uuid, String>, _>(
                        ErrorRelationshipSource,
                    )
                    .build()
                    .session();
                (session, "database unavailable")
            },
            {
                let session = FactRegistry::builder()
                    .with::<RelationshipQuery<uuid::Uuid, uuid::Uuid, String>, _>(
                        MismatchedRelationshipSource,
                    )
                    .build()
                    .session();
                (session, "returned")
            },
        ] {
            let ctx = EvalCtx {
                session: &session,
                subject: &subject,
                action: &TestAction,
                resource: &resource,
                context: &TestContext,
                policy_type: std::borrow::Cow::Borrowed("TestPolicy"),
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

        let session = FactRegistry::builder()
            .with::<RelationshipQuery<uuid::Uuid, uuid::Uuid, TestRelation>, _>(
                EnumRelationshipSource {
                    grants: HashSet::from([RelationshipQuery {
                        subject_id,
                        resource_id,
                        relation: TestRelation::Manager,
                    }]),
                },
            )
            .build()
            .session();

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
            policy_type: std::borrow::Cow::Borrowed("TestPolicy"),
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
            AndPolicy::<TestSubject, TestAction, TestResource, TestContext>::try_new(vec![]);

        assert!(and_policy_result.is_err());

        // Test OrPolicy with no policies
        let or_policy_result =
            OrPolicy::<TestSubject, TestAction, TestResource, TestContext>::try_new(vec![]);
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
    impl Policy<TestSubject, TestAction, TestResource, FeatureFlagContext> for FeatureFlagPolicy {
        async fn evaluate(
            &self,
            ctx: &EvalCtx<'_, TestSubject, TestAction, TestResource, FeatureFlagContext>,
        ) -> PolicyEvalResult {
            if ctx.context.feature_enabled {
                PolicyEvalResult::granted(
                    self.policy_type().to_string(),
                    Some("Feature flag enabled".to_string()),
                )
            } else {
                PolicyEvalResult::not_applicable(
                    self.policy_type().to_string(),
                    "Feature flag disabled",
                )
            }
        }

        fn policy_type(&self) -> std::borrow::Cow<'static, str> {
            std::borrow::Cow::Borrowed("FeatureFlagPolicy")
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

    // ==================== PolicyBuilder Closure Tests ====================

    #[tokio::test]
    async fn test_builder_when_grants_when_condition_true() {
        let policy =
            PolicyBuilder::<TestSubject, TestAction, TestResource, TestContext>::new("WhenPolicy")
                .when(
                    |_subject: &TestSubject,
                     _action: &TestAction,
                     _resource: &TestResource,
                     _context: &TestContext| { true },
                )
                .build();

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
            "PolicyBuilder::when should grant when condition returns true"
        );
        assert_eq!(policy.policy_type(), "WhenPolicy");
    }

    #[tokio::test]
    async fn test_builder_when_is_not_applicable_when_condition_false() {
        let policy =
            PolicyBuilder::<TestSubject, TestAction, TestResource, TestContext>::new("WhenPolicy")
                .when(
                    |_subject: &TestSubject,
                     _action: &TestAction,
                     _resource: &TestResource,
                     _context: &TestContext| { false },
                )
                .build();

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
            "PolicyBuilder::when should not apply when condition returns false"
        );
        match result {
            PolicyEvalResult::NotApplicable {
                policy_type,
                reason,
                ..
            } => {
                assert_eq!(policy_type, "WhenPolicy");
                assert_eq!(reason, "Policy predicate did not match");
            }
            _ => panic!("Expected NotApplicable result, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn test_builder_when_with_attribute_check() {
        // Policy that checks if the subject owns the resource
        let policy =
            PolicyBuilder::<TestSubject, TestAction, TestResource, TestContext>::new("OwnerPolicy")
                .when(
                    |subject: &TestSubject,
                     _action: &TestAction,
                     resource: &TestResource,
                     _context: &TestContext| { subject.id == resource.id },
                )
                .build();

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
            |_action: &TestAction, _resource: &TestResource| vec![admin_role],
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
            TestAction,
            TestResource,
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
            Policy::<RbacUser, TestAction, TestResource, TestContext>::policy_type(&policy),
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
            |_action: &TestAction, _resource: &TestResource| vec![admin_role],
            |subject: &RbacUser| subject.roles.clone(),
        );

        let regular_user = RbacUser {
            roles: vec![user_role],
        };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        let result: PolicyEvalResult =
            TestPolicyExt::<RbacUser, TestAction, TestResource, TestContext>::evaluate_access(
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
            PolicyEvalResult::NotApplicable {
                policy_type,
                reason,
                ..
            } => {
                assert_eq!(policy_type, "RbacPolicy");
                assert!(reason.contains("doesn't have required role"));
            }
            _ => panic!("Expected NotApplicable result, got {:?}", result),
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
            |_action: &TestAction, _resource: &TestResource| vec![role1, role2],
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
            TestAction,
            TestResource,
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
            |_action: &TestAction, _resource: &TestResource| vec![admin_role],
            |subject: &RbacUser| subject.roles.clone(),
        );

        let user_no_roles = RbacUser { roles: vec![] };
        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        let result: PolicyEvalResult =
            TestPolicyExt::<RbacUser, TestAction, TestResource, TestContext>::evaluate_access(
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
            |_action: &TestAction, _resource: &TestResource| vec![],
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
            TestAction,
            TestResource,
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
    async fn test_rbac_policy_with_non_uuid_role_type() {
        // The role identifier type is generic over any `PartialEq` type,
        // inferred from the resolver closures — here a domain enum.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum Role {
            Admin,
            Editor,
        }

        #[derive(Debug, Clone)]
        struct RbacUser {
            roles: Vec<Role>,
        }

        let policy = RbacPolicy::new(
            |_action: &TestAction, _resource: &TestResource| vec![Role::Admin],
            |subject: &RbacUser| subject.roles.clone(),
        );

        let resource = TestResource {
            id: uuid::Uuid::new_v4(),
        };

        let admin = RbacUser {
            roles: vec![Role::Admin, Role::Editor],
        };
        let result: PolicyEvalResult = TestPolicyExt::<
            RbacUser,
            TestAction,
            TestResource,
            TestContext,
        >::evaluate_access(
            &policy, &admin, &TestAction, &resource, &TestContext
        )
        .await;
        assert!(result.is_granted(), "enum role should match");

        let editor_only = RbacUser {
            roles: vec![Role::Editor],
        };
        let result: PolicyEvalResult =
            TestPolicyExt::<RbacUser, TestAction, TestResource, TestContext>::evaluate_access(
                &policy,
                &editor_only,
                &TestAction,
                &resource,
                &TestContext,
            )
            .await;
        assert!(!result.is_granted(), "missing enum role should deny");
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
        impl Policy<TestSubject, TestAction, TestResource, TestContext> for CountingPolicy {
            async fn evaluate(
                &self,
                _ctx: &EvalCtx<'_, TestSubject, TestAction, TestResource, TestContext>,
            ) -> PolicyEvalResult {
                self.counter.fetch_add(1, Ordering::SeqCst);

                if self.result {
                    PolicyEvalResult::granted(
                        self.policy_type().to_string(),
                        Some("Counting policy granted".to_string()),
                    )
                } else {
                    PolicyEvalResult::not_applicable(
                        self.policy_type().to_string(),
                        "Counting policy denied",
                    )
                }
            }

            fn policy_type(&self) -> std::borrow::Cow<'static, str> {
                std::borrow::Cow::Borrowed("CountingPolicy")
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
        let result = PolicyEvalResult::granted("TestPolicy", Some("Test reason".to_string()));
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

        let result = PolicyEvalResult::not_applicable("DenyPolicy", "Denied for testing");
        trace.set_root(result);

        assert!(
            trace.root().is_some(),
            "After set_root, trace should have a root"
        );
        let formatted = trace.format();
        assert!(formatted.contains("DenyPolicy"));
        assert!(formatted.contains("NOT_APPLICABLE"));
    }

    #[test]
    fn test_eval_trace_default() {
        let trace = EvalTrace::default();
        assert!(trace.root().is_none(), "Default trace should have no root");
    }

    // ==================== PolicyEvalResult Tests ====================

    #[test]
    fn test_policy_eval_result_reason_granted() {
        let result = PolicyEvalResult::granted("TestPolicy", Some("Grant reason".to_string()));
        assert_eq!(result.reason(), Some("Grant reason".to_string()));

        // Test with None reason
        let result_no_reason = PolicyEvalResult::granted("TestPolicy", None);
        assert_eq!(result_no_reason.reason(), None);
    }

    #[test]
    fn test_policy_eval_result_reason_denied() {
        let result = PolicyEvalResult::not_applicable("TestPolicy", "Deny reason");
        assert_eq!(result.reason(), Some("Deny reason".to_string()));
    }

    #[test]
    fn test_policy_eval_result_reason_combined() {
        let result = PolicyEvalResult::Combined {
            policy_type: std::borrow::Cow::Borrowed("CombinedPolicy"),
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
        let result = PolicyEvalResult::granted("TestPolicy", Some("Test".to_string()));

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
        let result = PolicyEvalResult::not_applicable("TestPolicy", "Test denial");

        let display_str = format!("{}", result);
        assert!(display_str.contains("TestPolicy"));
        assert!(display_str.contains("NOT_APPLICABLE"));
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
            PermissionChecker::<TestSubject, TestAction, TestResource, TestContext>::default();

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
            Policy::<TestSubject, TestAction, TestResource, TestContext>::security_rule(&policy);

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

    #[test]
    fn test_empty_policies_error_display_and_source() {
        let error = EmptyPoliciesError("AndPolicy must have at least one policy");
        assert_eq!(error.to_string(), "AndPolicy must have at least one policy");

        // The whole point of the Error impl: propagation into a boxed error.
        let boxed: Box<dyn std::error::Error> = Box::new(error);
        assert!(boxed.source().is_none());
    }

    // --- AccessEvaluation test helpers ----------------------------------

    fn allow_checker() -> PermissionChecker<TestSubject, TestAction, TestResource, TestContext> {
        let mut checker = PermissionChecker::new();
        checker.add_policy(AlwaysAllowPolicy);
        checker
    }

    fn deny_checker() -> PermissionChecker<TestSubject, TestAction, TestResource, TestContext> {
        let mut checker = PermissionChecker::new();
        checker.add_policy(AlwaysDenyPolicy("always denied"));
        checker
    }

    fn test_subject() -> TestSubject {
        TestSubject {
            id: uuid::Uuid::new_v4(),
        }
    }

    fn test_resource() -> TestResource {
        TestResource {
            id: uuid::Uuid::new_v4(),
        }
    }

    #[tokio::test]
    async fn assert_granted_by_passes_on_matching_grant() {
        let evaluation = allow_checker()
            .check(&test_subject(), &TestAction, &test_resource(), &TestContext)
            .await;
        evaluation.assert_granted_by("AlwaysAllowPolicy");
    }

    #[tokio::test]
    #[should_panic(expected = "expected grant by policy `Other`")]
    async fn assert_granted_by_panics_on_wrong_grantor() {
        let evaluation = allow_checker()
            .check(&test_subject(), &TestAction, &test_resource(), &TestContext)
            .await;
        evaluation.assert_granted_by("Other");
    }

    #[tokio::test]
    #[should_panic(expected = "but access was denied")]
    async fn assert_granted_by_panics_on_denial() {
        let evaluation = deny_checker()
            .check(&test_subject(), &TestAction, &test_resource(), &TestContext)
            .await;
        evaluation.assert_granted_by("AlwaysAllowPolicy");
    }

    #[tokio::test]
    async fn assert_denied_with_reason_containing_substring_match() {
        let evaluation = deny_checker()
            .check(&test_subject(), &TestAction, &test_resource(), &TestContext)
            .await;
        // Checker's summary is "All policies denied access".
        evaluation.assert_denied_with_reason_containing("denied");
    }

    #[tokio::test]
    #[should_panic(expected = "expected denial containing")]
    async fn assert_denied_with_reason_containing_panics_on_grant() {
        let evaluation = allow_checker()
            .check(&test_subject(), &TestAction, &test_resource(), &TestContext)
            .await;
        evaluation.assert_denied_with_reason_containing("anything");
    }

    #[tokio::test]
    async fn trace_accessor_returns_tree_for_both_outcomes() {
        let grant = allow_checker()
            .check(&test_subject(), &TestAction, &test_resource(), &TestContext)
            .await;
        assert!(grant.trace().format().contains("AlwaysAllowPolicy"));

        let deny = deny_checker()
            .check(&test_subject(), &TestAction, &test_resource(), &TestContext)
            .await;
        assert!(deny.trace().format().contains("AlwaysDenyPolicy"));
    }

    #[test]
    fn reason_str_borrows_the_reason() {
        let granted = PolicyEvalResult::granted("P", Some("ok".into()));
        assert_eq!(granted.reason_str(), Some("ok"));
        assert_eq!(granted.reason(), Some("ok".to_string()));

        let granted_no_reason = PolicyEvalResult::granted("P", None);
        assert_eq!(granted_no_reason.reason_str(), None);

        let denied = PolicyEvalResult::not_applicable("P", "nope");
        assert_eq!(denied.reason_str(), Some("nope"));

        let combined = PolicyEvalResult::Combined {
            policy_type: "C".into(),
            operation: CombineOp::Or,
            children: vec![],
            outcome: false,
        };
        assert_eq!(combined.reason_str(), None);
    }

    #[tokio::test]
    async fn granted_policy_type_and_denied_reason_accessors() {
        let grant = allow_checker()
            .check(&test_subject(), &TestAction, &test_resource(), &TestContext)
            .await;
        assert_eq!(grant.granted_policy_type(), Some("AlwaysAllowPolicy"));
        assert_eq!(grant.denied_reason(), None);

        let deny = deny_checker()
            .check(&test_subject(), &TestAction, &test_resource(), &TestContext)
            .await;
        assert_eq!(deny.granted_policy_type(), None);
        assert!(
            deny.denied_reason().is_some_and(|r| r.contains("denied")),
            "denied_reason should return the summary reason"
        );
    }

    // --- Trace-aware helpers (assert_not_applicable_by / assert_trace_contains) -

    /// Checker with two denying policies so we can assert against a
    /// specific one in the trace tree (the top-level summary won't
    /// distinguish them).
    fn multi_deny_checker() -> PermissionChecker<TestSubject, TestAction, TestResource, TestContext>
    {
        let mut checker = PermissionChecker::new();
        checker.add_policy(AlwaysDenyPolicy("first denial reason"));
        // A second denying policy with a different name and reason. Its
        // forbid-effect predicate never matches, so it lands in the trace as
        // a not-applicable `Denied` leaf rather than vetoing the whole
        // evaluation before the first policy is consulted. (The
        // tree-walker checks policy_type, not reason — what we're pinning
        // is that it finds *any* matching leaf.)
        let custom = PolicyBuilder::<TestSubject, TestAction, TestResource, TestContext>::new(
            "SupplierBlock",
        )
        .forbid()
        .subjects(|_subject| false)
        .build();
        checker.add_policy(custom);
        checker
    }

    #[tokio::test]
    async fn assert_not_applicable_by_finds_specific_leaf_in_multi_policy_trace() {
        let evaluation = multi_deny_checker()
            .check(&test_subject(), &TestAction, &test_resource(), &TestContext)
            .await;
        // Both child policies denied; either name should match.
        evaluation.assert_not_applicable_by("AlwaysDenyPolicy");
        evaluation.assert_not_applicable_by("SupplierBlock");
    }

    #[tokio::test]
    #[should_panic(expected = "expected a non-grant leaf for policy `NeverConsulted`")]
    async fn assert_not_applicable_by_panics_when_no_matching_leaf() {
        let evaluation = multi_deny_checker()
            .check(&test_subject(), &TestAction, &test_resource(), &TestContext)
            .await;
        evaluation.assert_not_applicable_by("NeverConsulted");
    }

    #[tokio::test]
    #[should_panic(expected = "but access was granted")]
    async fn assert_not_applicable_by_panics_on_grant() {
        let evaluation = allow_checker()
            .check(&test_subject(), &TestAction, &test_resource(), &TestContext)
            .await;
        evaluation.assert_not_applicable_by("AlwaysDenyPolicy");
    }

    #[tokio::test]
    async fn assert_trace_contains_matches_per_policy_reason() {
        // The summary reason is "All policies denied access"; the
        // per-policy reason "always denied" lives only in the trace
        // tree. `assert_trace_contains` is the right hammer for that
        // assertion.
        let evaluation = deny_checker()
            .check(&test_subject(), &TestAction, &test_resource(), &TestContext)
            .await;
        evaluation.assert_trace_contains("always denied");
    }

    #[tokio::test]
    #[should_panic(expected = "expected evaluation trace to contain")]
    async fn assert_trace_contains_panics_when_substring_absent() {
        let evaluation = deny_checker()
            .check(&test_subject(), &TestAction, &test_resource(), &TestContext)
            .await;
        evaluation.assert_trace_contains("this string is not in the trace");
    }
}

mod policy_builder_tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use uuid::Uuid;

    trait PolicyBoxExt<S, A, R, C>
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

    impl<S, A, R, C> PolicyBoxExt<S, A, R, C> for Box<dyn Policy<S, A, R, C>>
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
                let policy_type = self.policy_type();
                let ctx = EvalCtx {
                    session: &session,
                    subject,
                    action,
                    resource,
                    context,
                    policy_type,
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
        let policy = PolicyBuilder::<TestSubject, TestAction, TestResource, TestContext>::new(
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
        let policy = PolicyBuilder::<TestSubject, TestAction, TestResource, TestContext>::new(
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
            PolicyBuilder::<TestSubject, TestAction, TestResource, TestContext>::new("DenyPolicy")
                .forbid()
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

    /// The headline deny-overrides behavior: a matched `Effect::Forbid` policy
    /// vetoes a sibling grant, regardless of registration order.
    #[tokio::test]
    async fn test_policy_builder_effect_deny_overrides_other_grants() {
        for deny_registered_first in [true, false] {
            let deny_policy =
                PolicyBuilder::<TestSubject, TestAction, TestResource, TestContext>::new(
                    "BlockAlicePolicy",
                )
                .forbid()
                .subjects(|subject| subject.name == "Alice")
                .build();

            let allow_policy =
                PolicyBuilder::<TestSubject, TestAction, TestResource, TestContext>::new(
                    "AllowAlicePolicy",
                )
                .subjects(|subject| subject.name == "Alice")
                .build();

            let mut checker = PermissionChecker::new();
            if deny_registered_first {
                checker.add_policy(deny_policy);
                checker.add_policy(allow_policy);
            } else {
                checker.add_policy(allow_policy);
                checker.add_policy(deny_policy);
            }

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

            result.assert_forbidden_by("BlockAlicePolicy");
            assert_eq!(
                result.denied_reason(),
                Some("Forbidden by BlockAlicePolicy: Policy forbids access"),
                "summary reason should name the forbidding policy"
            );

            // A subject the deny predicate does not match is unaffected:
            // a non-matching forbid policy is "not applicable", never a veto.
            let bob_result = checker
                .evaluate_in_session(
                    &session,
                    &TestSubject { name: "Bob".into() },
                    &TestAction,
                    &TestResource,
                    &TestContext,
                )
                .await;
            assert!(
                !bob_result.is_granted(),
                "Bob has no grant (AllowAlicePolicy does not match him)"
            );
            assert_eq!(bob_result.forbidden_by(), None);
        }
    }

    /// A non-matching `Effect::Forbid` policy contributes nothing: the allow
    /// set still decides, and the trace root reflects deny-overrides.
    #[tokio::test]
    async fn test_non_matching_deny_policy_does_not_block_grants() {
        let deny_policy = PolicyBuilder::<TestSubject, TestAction, TestResource, TestContext>::new(
            "BlockNobodyPolicy",
        )
        .forbid()
        .subjects(|_subject| false)
        .build();

        let allow_policy =
            PolicyBuilder::<TestSubject, TestAction, TestResource, TestContext>::new(
                "AllowAlicePolicy",
            )
            .subjects(|subject| subject.name == "Alice")
            .build();

        let mut checker = PermissionChecker::new();
        checker.add_policy(allow_policy);
        checker.add_policy(deny_policy);

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

        result.assert_granted_by("AllowAlicePolicy");
        result.assert_trace_contains("DENY_OVERRIDES");
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
            ExtendedAction,
            ExtendedResource,
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

        let policy = PolicyBuilder::<TestSubject, ActionType, TestResource, TestContext>::new(
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

        let policy = PolicyBuilder::<TestSubject, TestAction, ResourceType, TestContext>::new(
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

        let policy = PolicyBuilder::<TestSubject, TestAction, TestResource, RequestContext>::new(
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
            PolicyBuilder::<FullSubject, FullAction, FullResource, FullContext>::new("FullPolicy")
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

    // ----- per-axis batch shortcut --------------------------------------

    use crate::{BatchEvalCtx, PolicyBatchItem};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[derive(Debug, Clone)]
    struct BatchSubject {
        role: String,
    }
    #[derive(Debug, Clone)]
    struct BatchAction;
    #[derive(Debug, Clone)]
    struct BatchResource {
        category: String,
    }
    #[derive(Debug, Clone)]
    struct BatchContext;

    fn make_items<'a>(
        resources: &'a [BatchResource],
        ctx: &'a BatchContext,
    ) -> Vec<PolicyBatchItem<'a, BatchResource, BatchContext>> {
        resources
            .iter()
            .map(|r| PolicyBatchItem {
                resource: r,
                context: ctx,
            })
            .collect()
    }

    fn batch_ctx<'a>(
        session: &'a EvaluationSession,
        subject: &'a BatchSubject,
        action: &'a BatchAction,
        items: &'a [PolicyBatchItem<'a, BatchResource, BatchContext>],
    ) -> BatchEvalCtx<'a, BatchSubject, BatchAction, BatchResource, BatchContext> {
        BatchEvalCtx {
            session,
            subject,
            action,
            items,
            policy_type: std::borrow::Cow::Borrowed("test"),
        }
    }

    #[tokio::test]
    async fn subject_only_policy_evaluates_subject_predicate_once_per_batch() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_inner = Arc::clone(&calls);

        let policy = PolicyBuilder::<BatchSubject, BatchAction, BatchResource, BatchContext>::new(
            "StaffOnly",
        )
        .subjects(move |s: &BatchSubject| {
            calls_inner.fetch_add(1, Ordering::SeqCst);
            s.role == "staff"
        })
        .build();

        let staff = BatchSubject {
            role: "staff".into(),
        };
        let action = BatchAction;
        let resources: Vec<BatchResource> = (0..25)
            .map(|i| BatchResource {
                category: format!("doc-{i}"),
            })
            .collect();
        let ctx = BatchContext;
        let items = make_items(&resources, &ctx);

        let session = EvaluationSession::new();
        let bctx = batch_ctx(&session, &staff, &action, &items);
        let results = policy.evaluate_batch(&bctx).await;

        assert_eq!(results.len(), 25, "one result per batch item");
        assert!(
            results.iter().all(|r| r.is_granted()),
            "subject passes => all items granted",
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "subject-only predicate runs once per batch, not per item",
        );
    }

    #[tokio::test]
    async fn subject_only_denial_broadcasts_without_running_per_item_predicates() {
        let subject_calls = Arc::new(AtomicUsize::new(0));
        let resource_calls = Arc::new(AtomicUsize::new(0));
        let subject_inner = Arc::clone(&subject_calls);
        let resource_inner = Arc::clone(&resource_calls);

        let policy = PolicyBuilder::<BatchSubject, BatchAction, BatchResource, BatchContext>::new(
            "StaffOnly",
        )
        .subjects(move |s: &BatchSubject| {
            subject_inner.fetch_add(1, Ordering::SeqCst);
            s.role == "staff"
        })
        .resources(move |_r: &BatchResource| {
            resource_inner.fetch_add(1, Ordering::SeqCst);
            true
        })
        .build();

        let guest = BatchSubject {
            role: "guest".into(),
        };
        let action = BatchAction;
        let resources: Vec<BatchResource> = (0..10)
            .map(|i| BatchResource {
                category: format!("doc-{i}"),
            })
            .collect();
        let ctx = BatchContext;
        let items = make_items(&resources, &ctx);

        let session = EvaluationSession::new();
        let bctx = batch_ctx(&session, &guest, &action, &items);
        let results = policy.evaluate_batch(&bctx).await;

        assert_eq!(results.len(), 10);
        assert!(
            results.iter().all(|r| !r.is_granted()),
            "subject denial broadcasts to every item",
        );
        assert_eq!(
            subject_calls.load(Ordering::SeqCst),
            1,
            "subject predicate runs once even though there are per-item predicates",
        );
        assert_eq!(
            resource_calls.load(Ordering::SeqCst),
            0,
            "resource predicate is skipped when subject already denied the batch",
        );
    }

    #[tokio::test]
    async fn mixed_axis_policy_still_runs_resource_per_item() {
        let subject_calls = Arc::new(AtomicUsize::new(0));
        let resource_calls = Arc::new(AtomicUsize::new(0));
        let subject_inner = Arc::clone(&subject_calls);
        let resource_inner = Arc::clone(&resource_calls);

        let policy = PolicyBuilder::<BatchSubject, BatchAction, BatchResource, BatchContext>::new(
            "StaffOnDocuments",
        )
        .subjects(move |s: &BatchSubject| {
            subject_inner.fetch_add(1, Ordering::SeqCst);
            s.role == "staff"
        })
        .resources(move |r: &BatchResource| {
            resource_inner.fetch_add(1, Ordering::SeqCst);
            r.category.starts_with("doc")
        })
        .build();

        let staff = BatchSubject {
            role: "staff".into(),
        };
        let action = BatchAction;
        // Half "doc-N" (will pass resource check), half "img-N" (will fail).
        let resources: Vec<BatchResource> = (0..10)
            .map(|i| BatchResource {
                category: if i % 2 == 0 {
                    format!("doc-{i}")
                } else {
                    format!("img-{i}")
                },
            })
            .collect();
        let ctx = BatchContext;
        let items = make_items(&resources, &ctx);

        let session = EvaluationSession::new();
        let bctx = batch_ctx(&session, &staff, &action, &items);
        let results = policy.evaluate_batch(&bctx).await;

        assert_eq!(results.len(), 10);
        let granted = results.iter().filter(|r| r.is_granted()).count();
        assert_eq!(granted, 5, "half the items pass the resource check");
        assert_eq!(
            subject_calls.load(Ordering::SeqCst),
            1,
            "subject predicate batched to one call",
        );
        assert_eq!(
            resource_calls.load(Ordering::SeqCst),
            10,
            "resource predicate runs per item",
        );
    }

    #[tokio::test]
    async fn empty_batch_returns_empty_results() {
        let policy = PolicyBuilder::<BatchSubject, BatchAction, BatchResource, BatchContext>::new(
            "AnyStaff",
        )
        .subjects(|s: &BatchSubject| s.role == "staff")
        .build();

        let staff = BatchSubject {
            role: "staff".into(),
        };
        let action = BatchAction;
        let items: Vec<PolicyBatchItem<'_, BatchResource, BatchContext>> = Vec::new();

        let session = EvaluationSession::new();
        let bctx = batch_ctx(&session, &staff, &action, &items);
        let results = policy.evaluate_batch(&bctx).await;

        assert!(results.is_empty());
    }
}
