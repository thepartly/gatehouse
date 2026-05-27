use async_trait::async_trait;
use gatehouse::{
    BatchEvalCtx, EvalCtx, EvaluationSession, PermissionChecker, Policy, PolicyEvalResult,
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

struct TracePolicy;

#[async_trait]
impl Policy<Subject, Resource, Action, Ctx> for TracePolicy {
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, Subject, Resource, Action, Ctx>,
    ) -> PolicyEvalResult {
        result_for(ctx.resource.allowed)
    }

    async fn evaluate_batch<'item>(
        &self,
        ctx: &BatchEvalCtx<'item, Subject, Resource, Action, Ctx>,
    ) -> Vec<PolicyEvalResult> {
        ctx.items
            .iter()
            .map(|item| result_for(item.resource.allowed))
            .collect()
    }

    fn policy_type(&self) -> &str {
        "TracePolicy"
    }
}

fn result_for(allowed: bool) -> PolicyEvalResult {
    if allowed {
        PolicyEvalResult::Granted {
            policy_type: "TracePolicy".to_string(),
            reason: Some("allowed".to_string()),
        }
    } else {
        PolicyEvalResult::Denied {
            policy_type: "TracePolicy".to_string(),
            reason: "denied".to_string(),
        }
    }
}

#[derive(Clone, Debug)]
struct CapturedSpan {
    name: String,
    fields: BTreeSet<String>,
    values: BTreeMap<String, String>,
}

#[derive(Clone, Default)]
struct CapturedSpans(Arc<Mutex<Vec<Arc<Mutex<CapturedSpan>>>>>);

impl CapturedSpans {
    fn snapshot(&self) -> Vec<CapturedSpan> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .map(|span| span.lock().unwrap().clone())
            .collect()
    }
}

struct CaptureLayer {
    spans: CapturedSpans,
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
        self.spans.0.lock().unwrap().push(span);
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

fn capture_async<F, Fut, T>(f: F) -> (T, Vec<CapturedSpan>)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
{
    let captured = CapturedSpans::default();
    let subscriber = Registry::default().with(CaptureLayer {
        spans: captured.clone(),
    });
    let output = tracing::subscriber::with_default(subscriber, || tokio_test::block_on(f()));
    (output, captured.snapshot())
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

fn checker_with_policy() -> PermissionChecker<Subject, Resource, Action, Ctx> {
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
            .evaluate_in_session(
                &session,
                &Subject,
                &Action,
                &Resource { allowed: true },
                &Ctx,
            )
            .await
    });

    let single = span(&spans, "evaluate_in_session");
    assert_fields(single, &["policy_count", "outcome", "policy.type"]);
    assert_value(single, "policy_count", "1");
    assert_value(single, "outcome", "granted");
    assert_value(single, "policy.type", "TracePolicy");

    let checker = checker_with_policy();
    let session = EvaluationSession::empty();
    let (_result, spans) = capture_async(|| async {
        checker
            .evaluate_batch_in_session_by(
                &session,
                &Subject,
                &Action,
                vec![(Resource { allowed: true }, Ctx)],
                |item| (&item.0, &item.1),
            )
            .await
    });

    let batch = span(&spans, "evaluate_batch_in_session_by");
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
            .evaluate_batch_in_session_by(
                &session,
                &Subject,
                &Action,
                vec![
                    (Resource { allowed: true }, Ctx),
                    (Resource { allowed: false }, Ctx),
                    (Resource { allowed: true }, Ctx),
                ],
                |item| (&item.0, &item.1),
            )
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
            .evaluate_in_session(
                &session,
                &Subject,
                &Action,
                &Resource { allowed: false },
                &Ctx,
            )
            .await
    });

    let single = span(&spans, "evaluate_in_session");
    assert_fields(single, &["policy_count", "outcome", "policy.type"]);
    assert_value(single, "policy_count", "1");
    assert_value(single, "outcome", "denied");

    let checker = checker_with_policy();
    let session = EvaluationSession::empty();
    let (_result, spans) = capture_async(|| async {
        checker
            .evaluate_batch_in_session_by(
                &session,
                &Subject,
                &Action,
                vec![(Resource { allowed: false }, Ctx)],
                |item| (&item.0, &item.1),
            )
            .await
    });

    let batch = span(&spans, "evaluate_batch_in_session_by");
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
    let checker = PermissionChecker::<Subject, Resource, Action, Ctx>::new();
    let session = EvaluationSession::empty();
    let (_result, spans) = capture_async(|| async {
        checker
            .evaluate_in_session(
                &session,
                &Subject,
                &Action,
                &Resource { allowed: true },
                &Ctx,
            )
            .await
    });

    let single = span(&spans, "evaluate_in_session");
    assert_fields(single, &["policy_count", "outcome", "policy.type"]);
    assert_value(single, "policy_count", "0");
    assert_value(single, "outcome", "denied");

    let checker = PermissionChecker::<Subject, Resource, Action, Ctx>::new()
        .with_max_batch_size(NonZeroUsize::new(2).unwrap());
    let session = EvaluationSession::empty();
    let (_result, spans) = capture_async(|| async {
        checker
            .evaluate_batch_in_session_by(
                &session,
                &Subject,
                &Action,
                vec![(Resource { allowed: true }, Ctx)],
                |item| (&item.0, &item.1),
            )
            .await
    });

    let batch = span(&spans, "evaluate_batch_in_session_by");
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
