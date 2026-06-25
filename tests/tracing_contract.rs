use async_trait::async_trait;
use gatehouse::{
    BatchEvalCtx, EvalCtx, EvaluationSession, PermissionChecker, Policy, PolicyBuilder,
    PolicyDomain, PolicyEvalResult,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Record};
use tracing::{Id, Subscriber};
use tracing_subscriber::layer::{Context as LayerContext, SubscriberExt};
use tracing_subscriber::registry::{LookupSpan, Registry};
use tracing_subscriber::Layer;

#[derive(Clone)]
struct Subject;

#[derive(Clone)]
struct Action;

#[derive(Clone)]
struct Ctx;

#[derive(Clone)]
struct Resource {
    allowed: bool,
}

struct Domain;

impl PolicyDomain for Domain {
    type Subject = Subject;
    type Action = Action;
    type Resource = Resource;
    type Context = Ctx;
}

struct TracePolicy;

#[async_trait]
impl Policy<Domain> for TracePolicy {
    async fn evaluate(&self, ctx: &EvalCtx<'_, Domain>) -> PolicyEvalResult {
        result_for(ctx.resource.allowed)
    }

    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, Domain>,
    ) -> Vec<PolicyEvalResult> {
        ctx.items
            .iter()
            .map(|item| result_for(item.resource.allowed))
            .collect()
    }

    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("TracePolicy")
    }
}

struct GrantingForbidPolicy;

#[async_trait]
impl Policy<Domain> for GrantingForbidPolicy {
    async fn evaluate(&self, ctx: &EvalCtx<'_, Domain>) -> PolicyEvalResult {
        ctx.grant("misbehaving forbid grant")
    }

    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, Domain>,
    ) -> Vec<PolicyEvalResult> {
        ctx.items
            .iter()
            .map(|_| PolicyEvalResult::granted(self.policy_type(), Some("misbehaving".into())))
            .collect()
    }

    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("GrantingForbidPolicy")
    }

    fn effect(&self) -> gatehouse::Effect {
        gatehouse::Effect::Forbid
    }
}

struct ForbiddingAllowPolicy;

#[async_trait]
impl Policy<Domain> for ForbiddingAllowPolicy {
    async fn evaluate(&self, ctx: &EvalCtx<'_, Domain>) -> PolicyEvalResult {
        ctx.forbid("forbid without declaring an effect")
    }

    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, Domain>,
    ) -> Vec<PolicyEvalResult> {
        ctx.items
            .iter()
            .map(|_| {
                PolicyEvalResult::forbidden(
                    self.policy_type(),
                    "forbid without declaring an effect",
                )
            })
            .collect()
    }

    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("ForbiddingAllowPolicy")
    }

    // Intentionally no `effect()` override: defaults to `Effect::Allow`, so
    // forbidding here is the contract violation the checker should warn about.
}

struct WrongLengthTracePolicy;

#[async_trait]
impl Policy<Domain> for WrongLengthTracePolicy {
    async fn evaluate(&self, ctx: &EvalCtx<'_, Domain>) -> PolicyEvalResult {
        ctx.not_applicable("not applicable")
    }

    async fn evaluate_batch<'item>(
        &self,
        _ctx: &BatchEvalCtx<'item, Domain>,
    ) -> Vec<PolicyEvalResult> {
        Vec::new()
    }

    fn policy_type(&self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("WrongLengthTracePolicy")
    }

    fn effect(&self) -> gatehouse::Effect {
        gatehouse::Effect::Forbid
    }
}

fn result_for(allowed: bool) -> PolicyEvalResult {
    if allowed {
        PolicyEvalResult::granted("TracePolicy", Some("allowed".to_string()))
    } else {
        PolicyEvalResult::not_applicable("TracePolicy", "denied")
    }
}

#[derive(Clone, Debug)]
struct CapturedSpan {
    name: String,
    fields: BTreeSet<String>,
    values: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
struct CapturedEvent {
    target: String,
    level: String,
    values: BTreeMap<String, String>,
}

#[derive(Clone, Default)]
struct CapturedTelemetry {
    spans: Arc<Mutex<Vec<Arc<Mutex<CapturedSpan>>>>>,
    events: Arc<Mutex<Vec<CapturedEvent>>>,
}

impl CapturedTelemetry {
    fn span_snapshot(&self) -> Vec<CapturedSpan> {
        self.spans
            .lock()
            .unwrap()
            .iter()
            .map(|span| span.lock().unwrap().clone())
            .collect()
    }

    fn event_snapshot(&self) -> Vec<CapturedEvent> {
        self.events.lock().unwrap().clone()
    }
}

struct CaptureLayer {
    captured: CapturedTelemetry,
}

impl<S> Layer<S> for CaptureLayer
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: LayerContext<'_, S>) {
        let mut visitor = FieldValues::default();
        attrs.record(&mut visitor);
        let span = Arc::new(Mutex::new(CapturedSpan {
            name: attrs.metadata().name().to_string(),
            fields: attrs
                .metadata()
                .fields()
                .iter()
                .map(|field| field.name().to_string())
                .collect(),
            values: visitor.values,
        }));

        if let Some(ctx_span) = ctx.span(id) {
            ctx_span.extensions_mut().insert(Arc::clone(&span));
        }
        self.captured.spans.lock().unwrap().push(span);
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: LayerContext<'_, S>) {
        let Some(ctx_span) = ctx.span(id) else {
            return;
        };
        let Some(span) = ctx_span
            .extensions()
            .get::<Arc<Mutex<CapturedSpan>>>()
            .cloned()
        else {
            return;
        };

        let mut visitor = FieldValues::default();
        values.record(&mut visitor);
        span.lock().unwrap().values.extend(visitor.values);
    }

    fn on_event(&self, event: &tracing::Event<'_>, _ctx: LayerContext<'_, S>) {
        let mut visitor = FieldValues::default();
        event.record(&mut visitor);
        self.captured.events.lock().unwrap().push(CapturedEvent {
            target: event.metadata().target().to_string(),
            level: event.metadata().level().to_string(),
            values: visitor.values,
        });
    }
}

#[derive(Default)]
struct FieldValues {
    values: BTreeMap<String, String>,
}

impl FieldValues {
    fn insert(&mut self, field: &Field, value: impl Into<String>) {
        self.values.insert(field.name().to_string(), value.into());
    }
}

impl Visit for FieldValues {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.insert(field, value);
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.insert(field, value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.insert(field, value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.insert(field, value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.insert(field, format!("{value:?}"));
    }
}

/// Permissive no-op global subscriber. Installed once on first call to
/// `capture_async` so the process-wide tracing callsite cache locks in
/// `Interest::sometimes` for every callsite. Without this, a parallel test
/// thread that hits a tracing callsite before any subscriber is installed
/// will poison the cache with `Interest::never`, and later threads using
/// `with_default(...)` see zero spans/events.
struct PermissiveNoop;
impl Subscriber for PermissiveNoop {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, _: &tracing::Event<'_>) {}
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

fn install_permissive_global() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = tracing::subscriber::set_global_default(PermissiveNoop);
    });
}

fn capture_async<F, Fut, T>(f: F) -> (T, Vec<CapturedSpan>)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
{
    let (output, spans, _events) = capture_async_with_events(f);
    (output, spans)
}

fn capture_async_with_events<F, Fut, T>(f: F) -> (T, Vec<CapturedSpan>, Vec<CapturedEvent>)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
{
    install_permissive_global();
    let captured = CapturedTelemetry::default();
    let subscriber = Registry::default().with(CaptureLayer {
        captured: captured.clone(),
    });
    let output = tracing::subscriber::with_default(subscriber, || tokio_test::block_on(f()));
    (output, captured.span_snapshot(), captured.event_snapshot())
}

fn span<'a>(spans: &'a [CapturedSpan], name: &str) -> &'a CapturedSpan {
    spans
        .iter()
        .find(|span| span.name == name)
        .unwrap_or_else(|| panic!("missing span {name}; captured spans: {spans:#?}"))
}

fn assert_fields(span: &CapturedSpan, expected: &[&str]) {
    for field in expected {
        assert!(
            span.fields.contains(*field),
            "span {} missing field {field}; fields: {:?}",
            span.name,
            span.fields
        );
    }
}

fn assert_value(span: &CapturedSpan, field: &str, expected: &str) {
    assert_eq!(
        span.values.get(field).map(String::as_str),
        Some(expected),
        "span {} field {field}; values: {:?}",
        span.name,
        span.values
    );
}

fn assert_event_value(event: &CapturedEvent, field: &str, expected: &str) {
    assert_eq!(
        event.values.get(field).map(String::as_str),
        Some(expected),
        "event {} field {field}; values: {:?}",
        event.target,
        event.values
    );
}

fn checker_with_policy() -> PermissionChecker<Domain> {
    let mut checker = PermissionChecker::new().with_max_batch_size(NonZeroUsize::new(2).unwrap());
    checker.add_policy(TracePolicy);
    checker
}

#[test]
fn tracing_fields_are_recorded_for_granted_decisions() {
    let checker = checker_with_policy();
    let session = EvaluationSession::empty();
    let (_result, spans) = capture_async(|| async {
        checker
            .bind(&session, &Subject, &Action, &Ctx)
            .check(&Resource { allowed: true })
            .await
    });

    let single = span(&spans, "evaluate_one");
    assert_fields(single, &["policy_count", "outcome", "policy.type"]);
    assert_value(single, "policy_count", "1");
    assert_value(single, "outcome", "granted");
    assert_value(single, "policy.type", "TracePolicy");

    let checker = checker_with_policy();
    let session = EvaluationSession::empty();
    let (_result, spans) = capture_async(|| async {
        checker
            .bind(&session, &Subject, &Action, &Ctx)
            .evaluate(vec![Resource { allowed: true }])
            .await
    });

    let batch = span(&spans, "evaluate_batch");
    assert_fields(
        batch,
        &[
            "item_count",
            "granted_count",
            "denied_count",
            "max_batch_size",
            "policy_count",
        ],
    );
    assert_value(batch, "policy_count", "1");
    assert_value(batch, "item_count", "1");
    assert_value(batch, "granted_count", "1");
    assert_value(batch, "denied_count", "0");
    assert_value(batch, "max_batch_size", "2");

    let policy = span(&spans, "gatehouse.batch_policy");
    assert_fields(
        policy,
        &[
            "policy.type",
            "policy.pending_count",
            "policy.chunk_index",
            "policy.chunk_count",
            "policy.granted_count",
            "policy.denied_count",
        ],
    );
    assert_value(policy, "policy.type", "TracePolicy");
    assert_value(policy, "policy.pending_count", "1");
    assert_value(policy, "policy.chunk_index", "0");
    assert_value(policy, "policy.chunk_count", "1");
    assert_value(policy, "policy.granted_count", "1");
    assert_value(policy, "policy.denied_count", "0");
}

#[test]
fn tracing_records_one_batch_policy_span_per_chunk() {
    let checker = checker_with_policy();
    let session = EvaluationSession::empty();
    let (_result, spans) = capture_async(|| async {
        checker
            .bind(&session, &Subject, &Action, &Ctx)
            .evaluate(vec![
                Resource { allowed: true },
                Resource { allowed: false },
                Resource { allowed: true },
            ])
            .await
    });

    let policy_spans = spans
        .iter()
        .filter(|span| span.name == "gatehouse.batch_policy")
        .collect::<Vec<_>>();
    assert_eq!(policy_spans.len(), 2, "expected one span per policy chunk");

    assert_value(policy_spans[0], "policy.pending_count", "2");
    assert_value(policy_spans[0], "policy.chunk_index", "0");
    assert_value(policy_spans[0], "policy.chunk_count", "2");
    assert_value(policy_spans[0], "policy.granted_count", "1");
    assert_value(policy_spans[0], "policy.denied_count", "1");

    assert_value(policy_spans[1], "policy.pending_count", "1");
    assert_value(policy_spans[1], "policy.chunk_index", "1");
    assert_value(policy_spans[1], "policy.chunk_count", "2");
    assert_value(policy_spans[1], "policy.granted_count", "1");
    assert_value(policy_spans[1], "policy.denied_count", "0");
}

#[test]
fn tracing_fields_are_recorded_for_denied_decisions() {
    let checker = checker_with_policy();
    let session = EvaluationSession::empty();
    let (_result, spans) = capture_async(|| async {
        checker
            .bind(&session, &Subject, &Action, &Ctx)
            .check(&Resource { allowed: false })
            .await
    });

    let single = span(&spans, "evaluate_one");
    assert_fields(single, &["policy_count", "outcome", "policy.type"]);
    assert_value(single, "policy_count", "1");
    assert_value(single, "outcome", "denied");

    let checker = checker_with_policy();
    let session = EvaluationSession::empty();
    let (_result, spans) = capture_async(|| async {
        checker
            .bind(&session, &Subject, &Action, &Ctx)
            .evaluate(vec![Resource { allowed: false }])
            .await
    });

    let batch = span(&spans, "evaluate_batch");
    assert_fields(
        batch,
        &[
            "item_count",
            "granted_count",
            "denied_count",
            "max_batch_size",
            "policy_count",
        ],
    );
    assert_value(batch, "policy_count", "1");
    assert_value(batch, "item_count", "1");
    assert_value(batch, "granted_count", "0");
    assert_value(batch, "denied_count", "1");
    assert_value(batch, "max_batch_size", "2");
}

#[test]
fn tracing_fields_are_recorded_for_empty_policy_decisions() {
    let checker = PermissionChecker::<Domain>::new();
    let session = EvaluationSession::empty();
    let (_result, spans) = capture_async(|| async {
        checker
            .bind(&session, &Subject, &Action, &Ctx)
            .check(&Resource { allowed: true })
            .await
    });

    let single = span(&spans, "evaluate_one");
    assert_fields(single, &["policy_count", "outcome", "policy.type"]);
    assert_value(single, "policy_count", "0");
    assert_value(single, "outcome", "denied");

    let checker =
        PermissionChecker::<Domain>::new().with_max_batch_size(NonZeroUsize::new(2).unwrap());
    let session = EvaluationSession::empty();
    let (_result, spans) = capture_async(|| async {
        checker
            .bind(&session, &Subject, &Action, &Ctx)
            .evaluate(vec![Resource { allowed: true }])
            .await
    });

    let batch = span(&spans, "evaluate_batch");
    assert_fields(
        batch,
        &[
            "item_count",
            "granted_count",
            "denied_count",
            "max_batch_size",
            "policy_count",
        ],
    );
    assert_value(batch, "policy_count", "0");
    assert_value(batch, "item_count", "1");
    assert_value(batch, "granted_count", "0");
    assert_value(batch, "denied_count", "1");
    assert_value(batch, "max_batch_size", "2");
}

#[test]
fn named_checker_records_name_on_evaluate_span() {
    let mut checker = PermissionChecker::<Domain>::named("InvoiceItemChecker");
    checker.add_policy(TracePolicy);
    let session = EvaluationSession::empty();
    let (_result, spans) = capture_async(|| async {
        checker
            .bind(&session, &Subject, &Action, &Ctx)
            .check(&Resource { allowed: true })
            .await
    });

    let single = span(&spans, "evaluate_one");
    assert_value(single, "checker.name", "InvoiceItemChecker");
}

#[test]
fn unnamed_checker_omits_checker_name_field() {
    let checker = checker_with_policy();
    let session = EvaluationSession::empty();
    let (_result, spans) = capture_async(|| async {
        checker
            .bind(&session, &Subject, &Action, &Ctx)
            .check(&Resource { allowed: true })
            .await
    });

    let single = span(&spans, "evaluate_one");
    // Span declares the field but does not record a value when the checker
    // has no name.
    assert!(
        !single.values.contains_key("checker.name"),
        "checker.name should be unrecorded on an unnamed checker; values: {:?}",
        single.values
    );
}

#[test]
fn named_checker_records_name_on_batch_span() {
    let mut checker = PermissionChecker::<Domain>::named("InvoiceItemChecker");
    checker.add_policy(TracePolicy);
    let session = EvaluationSession::empty();
    let (_result, spans) = capture_async(|| async {
        checker
            .bind(&session, &Subject, &Action, &Ctx)
            .evaluate(vec![Resource { allowed: true }])
            .await
    });

    let batch = span(&spans, "evaluate_batch");
    assert_value(batch, "checker.name", "InvoiceItemChecker");
}

#[test]
fn tracing_fields_are_recorded_for_forbidden_decisions() {
    // An allow policy that would grant, vetoed by a forbid-effect policy.
    let mut checker = PermissionChecker::new();
    checker.add_policy(TracePolicy);
    checker.add_policy(
        PolicyBuilder::<Domain>::new("GlobalFreeze")
            .forbid()
            .build(),
    );

    let session = EvaluationSession::empty();
    let (result, spans) = capture_async(|| async {
        checker
            .bind(&session, &Subject, &Action, &Ctx)
            .check(&Resource { allowed: true })
            .await
    });
    assert!(!result.is_granted());

    // The single-evaluation span attributes the denial to the forbid.
    let single = span(&spans, "evaluate_one");
    assert_value(single, "outcome", "denied");
    assert_value(single, "policy.type", "GlobalFreeze");

    // The batch policy span carries the declared effect and the forbid count.
    let (_results, spans) = capture_async(|| async {
        checker
            .bind(&session, &Subject, &Action, &Ctx)
            .evaluate(vec![Resource { allowed: true }])
            .await
    });

    // Forbid-first scheduling: the first batch_policy span is the forbid policy.
    let policy = span(&spans, "gatehouse.batch_policy");
    assert_value(policy, "policy.type", "GlobalFreeze");
    assert_value(policy, "policy.effect", "deny");
    assert_value(policy, "policy.forbidden_count", "1");
    assert_value(policy, "policy.granted_count", "0");
}

#[test]
fn tracing_records_wrong_length_batch_policy_denials() {
    let mut checker = PermissionChecker::new();
    checker.add_policy(WrongLengthTracePolicy);
    let session = EvaluationSession::empty();
    let (_results, spans) = capture_async(|| async {
        checker
            .bind(&session, &Subject, &Action, &Ctx)
            .evaluate(vec![
                Resource { allowed: true },
                Resource { allowed: false },
            ])
            .await
    });

    let policy = span(&spans, "gatehouse.batch_policy");
    assert_value(policy, "policy.type", "WrongLengthTracePolicy");
    assert_value(policy, "policy.denied_count", "2");
    assert_value(policy, "policy.granted_count", "0");
    assert_value(policy, "policy.forbidden_count", "0");
}

#[test]
fn tracing_records_forbid_effect_contract_violation_warning() {
    let mut checker = PermissionChecker::new();
    checker.add_policy(GrantingForbidPolicy);
    let session = EvaluationSession::empty();
    let (_results, spans, events) = capture_async_with_events(|| async {
        checker
            .bind(&session, &Subject, &Action, &Ctx)
            .evaluate(vec![Resource { allowed: true }])
            .await
    });

    let policy = span(&spans, "gatehouse.batch_policy");
    assert_value(policy, "policy.type", "GrantingForbidPolicy");
    assert_value(policy, "policy.denied_count", "1");
    assert_value(policy, "policy.granted_count", "0");

    let warning = events
        .iter()
        .find(|event| {
            event.level == "WARN"
                && event.values.get("message").is_some_and(|message| {
                    message.contains("Forbid-effect policy returned a grant")
                })
        })
        .unwrap_or_else(|| panic!("missing contract-violation warning; events: {events:#?}"));
    assert_event_value(warning, "policy.type", "GrantingForbidPolicy");
    assert_event_value(warning, "item_count", "1");

    let mut clean_checker = PermissionChecker::new();
    clean_checker.add_policy(PolicyBuilder::<Domain>::new("CleanForbid").forbid().build());
    let (_results, _spans, clean_events) = capture_async_with_events(|| async {
        clean_checker
            .bind(&session, &Subject, &Action, &Ctx)
            .evaluate(vec![Resource { allowed: true }])
            .await
    });
    assert!(
        clean_events.iter().all(|event| {
            !event
                .values
                .get("message")
                .is_some_and(|message| message.contains("Forbid-effect policy returned a grant"))
        }),
        "well-behaved forbid policies must not emit contract-violation warnings: {clean_events:#?}"
    );
}

#[test]
fn tracing_records_allow_effect_contract_violation_warning() {
    let mut checker = PermissionChecker::new();
    checker.add_policy(ForbiddingAllowPolicy);
    let session = EvaluationSession::empty();

    // Batch path: the veto is still honored (fail-safe, not silently dropped)
    // and a single warning records the contract violation with its count.
    let (results, _spans, events) = capture_async_with_events(|| async {
        checker
            .bind(&session, &Subject, &Action, &Ctx)
            .evaluate(vec![Resource { allowed: true }])
            .await
    });
    assert!(!results[0].1.is_granted());

    let warning = events
        .iter()
        .find(|event| {
            event.level == "WARN"
                && event.values.get("message").is_some_and(|message| {
                    message.contains("Allow-effect policy returned a forbid")
                })
        })
        .unwrap_or_else(|| panic!("missing contract-violation warning; events: {events:#?}"));
    assert_event_value(warning, "policy.type", "ForbiddingAllowPolicy");
    assert_event_value(warning, "item_count", "1");

    // Single path: the same warning fires, and access is still denied.
    let (single, _spans, single_events) = capture_async_with_events(|| async {
        checker
            .bind(&session, &Subject, &Action, &Ctx)
            .check(&Resource { allowed: true })
            .await
    });
    assert!(!single.is_granted());
    assert!(
        single_events.iter().any(|event| {
            event.level == "WARN"
                && event.values.get("message").is_some_and(|message| {
                    message.contains("Allow-effect policy returned a forbid")
                })
        }),
        "single-path evaluation must emit the contract-violation warning: {single_events:#?}"
    );

    // A policy that declares its forbid effect is well-behaved: no warning.
    let mut clean_checker = PermissionChecker::new();
    clean_checker.add_policy(PolicyBuilder::<Domain>::new("CleanForbid").forbid().build());
    let (_results, _spans, clean_events) = capture_async_with_events(|| async {
        clean_checker
            .bind(&session, &Subject, &Action, &Ctx)
            .evaluate(vec![Resource { allowed: true }])
            .await
    });
    assert!(
        clean_events.iter().all(|event| {
            !event
                .values
                .get("message")
                .is_some_and(|message| message.contains("Allow-effect policy returned a forbid"))
        }),
        "policies declaring their forbid effect must not emit contract-violation warnings: {clean_events:#?}"
    );
}
