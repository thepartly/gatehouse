# Migrating from 0.5 to 0.6

Gatehouse 0.6 adds a public `error_kind` field to `FactProvenance`. Code using
`FactProvenance::new(...)` needs no change, but direct struct literals must
initialize the new field:

```rust,ignore
FactProvenance {
    fact_name: "membership",
    key: "Member(42)".to_string(),
    outcome: FactOutcome::Found,
    detail: None,
    error_kind: None,
}
```

When provenance comes from a fact load, prefer
`FactProvenance::from_load_result(...)`; it records the outcome, diagnostic
detail, and structured `FactLoadErrorKind` together.

## First-class `Indeterminate` decisions

0.6 makes "the policy could not be evaluated" a structural outcome instead of
a convention over provenance:

- `PolicyEvalResult` gains an `Indeterminate` leaf variant (constructors
  `PolicyEvalResult::indeterminate` / `indeterminate_with_facts`, plus
  `ctx.indeterminate(...)` inside policy bodies).
- Every node now carries a four-valued `Decision`, exposed via
  `PolicyEvalResult::decision()`.
- `AccessEvaluation` gains an `Indeterminate` variant, with
  `is_indeterminate()` and `indeterminate_reason()`.

### `Combined.outcome` is now `Combined.decision`

Code that constructed or matched `PolicyEvalResult::Combined` must switch
from the boolean to the `Decision` enum:

```rust,ignore
// Before
PolicyEvalResult::Combined { policy_type, operation, children, outcome: true }

// After
PolicyEvalResult::Combined { policy_type, operation, children, decision: Decision::Grant }
```

Custom combinators must keep `decision` consistent with their children — in
particular, never report `Decision::Grant` while a `Forbidden` leaf survives
in `children`. (`is_forbidden()` still runs a recursive leaf scan as a
fail-closed backstop, so an inconsistent node is treated as forbidding, but
do not rely on that.)

### HTTP mapping

The 403-vs-5xx split is now structural rather than provenance-scraping:

```rust,ignore
if evaluation.is_granted() {
    // 200
} else if evaluation.forbidden_by().is_some() {
    // 403: active veto
} else if evaluation.is_indeterminate() {
    // 503: authorization inputs unavailable — inspect
    // evaluation.fact_load_errors() / FactProvenance::error_kind
} else {
    // 403: ordinary denial
}
```

`denied_due_to_fact_load_error()` remains as the coarser any-error-in-trace
scan for policies that still record failed loads on `NotApplicable` results.

## Recording evaluation contexts

Fact provenance is no longer opt-in. `EvalCtx` owns a recorder, and fact
access goes through the context:

```rust,ignore
// Before: six lines of ceremony per fact, silently wrong if skipped.
let key = IsMember(ctx.subject.id);
let result = ctx.session.get(key.clone()).await;
let provenance = vec![FactProvenance::from_load_result(
    IsMember::NAME,
    format!("{key:?}"),
    &result,
)];
match result {
    FactLoadResult::Found(true) => ctx.grant_with_facts("is a member", provenance),
    _ => ctx.not_applicable_with_facts("not a member", provenance),
}

// After: recording is a side effect of the load; the helpers attach it.
match ctx.fact(IsMember(ctx.subject.id)).await {
    FactLoadResult::Found(true) => ctx.grant("is a member"),
    _ => ctx.not_applicable("not a member"),
}
```

Batch policies use `ctx.facts_by(|resource| Key(...))` for one key per item
(one deduplicated `get_many`, provenance recorded against the originating
item) and `ctx.fact(key)` for a per-subject fact shared by every item.

Mechanical changes:

- `EvalCtx` / `BatchEvalCtx` can no longer be built with struct literals.
  Use `EvalCtx::new(session, subject, action, resource, context,
  policy_type)` and `BatchEvalCtx::new(session, subject, action, context,
  items, policy_type)` — typically only in policy unit tests and custom
  combinators.
- `ctx.session` is now a method: `ctx.session()`. Loads made directly on
  the session are invisible to recording; treat it as an escape hatch.
- Callers that invoke `Policy::evaluate` / `Policy::evaluate_batch`
  directly (tests, custom combinators) should pass the results through
  `ctx.finish(result)` / `batch_ctx.finish(results)` so facts a policy
  recorded but did not attach still reach the trace. The checker and the
  built-in combinators do this for you.
- `FactKey` gains a `fmt::Debug` supertrait and a defaulted
  `render(&self) -> String` (the provenance key string, defaulting to the
  `Debug` representation). Every practical key already derives `Debug`;
  override `render` when the key has an established audit form.
  `RelationshipQuery` does exactly that, so its recorded key string keeps
  the pre-0.6 `subject -[relation]-> resource` form unchanged.
  `RebacPolicy` consequently requires `Relation: fmt::Debug` in addition to
  `fmt::Display`.
- The `FactKey` impl for `RelationshipQuery` itself now requires
  `Relation: fmt::Display` (its `render` override uses it) and `fmt::Debug`
  on all three id types. Policies that build `RelationshipQuery` keys and
  load them directly — without `RebacPolicy`, which always required
  `Display` — need a `Display` impl on relation types that only derived
  `Debug`.
- Loading a fact through some other loader? Record it explicitly:
  `ctx.record(FactProvenance::from_load_result(NAME, key_repr, &result))`.
- The `*_with_facts` helpers remain for provenance computed from something
  other than a context load, and now *append* to whatever was recorded.

Because the context witnesses every recorded load,
`ctx.not_applicable(...)` after a failed load now returns an
`Indeterminate` result instead of silently looking like an ordinary
non-match — the 403-vs-503 signal no longer depends on the policy author
remembering `*_with_facts`.

### Behavior changes to audit

- `RebacPolicy` now returns `Indeterminate` when a relationship fact **load
  fails** (backend error, unregistered source, source contract violation).
  A checker that previously answered `Denied` for those cases now answers
  `AccessEvaluation::Indeterminate`. `Found(false)` and `Missing` are still
  ordinary non-grants. If your HTTP layer treated every non-grant as 403,
  add an `Indeterminate` branch (or keep treating it as a denial — it is
  still fail-closed and `to_result` still maps it to an error).
- A policy whose `evaluate_batch` returns the wrong number of results now
  fails closed as `Indeterminate` instead of a plain denial.
- An indeterminate veto-capable policy blocks sibling grants; an
  indeterminate allow-only policy does not, but with no grant the checker
  returns `Indeterminate` instead of `"All policies denied access"`.
- With the `serde` feature, `Combined` nodes serialize a `decision` field
  instead of `outcome`, and the new variants appear in serialized traces —
  update audit-log consumers.
- Matches on `AccessEvaluation` / `PolicyEvalResult` with wildcard arms keep
  compiling (`#[non_exhaustive]`), but review them: treating `Indeterminate`
  as an ordinary denial is safe (fail-closed), just less informative.
- **Test suites:** `AccessEvaluation::assert_denied` (and the other
  `assert_*` helpers) now panic on an `Indeterminate` evaluation instead of
  accepting it as a denial. Downstream tests that asserted a denial on a
  `RebacPolicy` (or other fact-backed) load failure will start failing in
  CI — switch them to the new `assert_indeterminate()`.
- `denied_due_to_fact_load_error()` is deprecated. Use `is_indeterminate()`
  for the structural 403-vs-5xx split and `fact_load_errors()` to inspect
  the failed loads; the any-error-in-trace scan will be removed in 0.7.

# Migrating from 0.4 to 0.5

Gatehouse 0.5 intentionally breaks the public API to make the authorization surface smaller and harder to misuse. The main changes are:

- policies are parameterized by one `PolicyDomain` instead of four repeated generics;
- every checker call goes through a session-bound evaluator;
- policy-level non-grants are now `NotApplicable`;
- explicit veto policies use `forbid` / `Effect::Forbid`;
- forbids propagate through combinators and delegation;
- built-in ABAC is removed in favor of `PolicyBuilder::when`.

If you are upgrading from 0.2 or 0.3, first read the release notes for 0.3 and 0.4 in `CHANGELOG.md`, then apply this guide.

## Migration checklist

1. Define one `PolicyDomain` marker per authorization domain.
2. Change `Policy<S, A, R, C>` impls to `Policy<Domain>`.
3. Change `EvalCtx<'_, S, A, R, C>` to `EvalCtx<'_, Domain>`.
4. Replace `ctx.deny(...)` with `ctx.not_applicable(...)`.
5. Replace `PolicyEvalResult::Denied` with `PolicyEvalResult::NotApplicable`.
6. Replace `PolicyBuilder::<S, A, R, C>` with `PolicyBuilder::<Domain>`.
7. Replace `checker.check(...)`, `evaluate_in_session(...)`, batch, filter, and lookup checker methods with `checker.bind(...).check(...)`, `.evaluate(...)`, `.filter(...)`, or `.lookup_page(...)`.
8. Build request sessions through `FactRegistry` for fact-backed policies.
9. Replace `AbacPolicy` with `PolicyBuilder::when` or a hand-written `Policy`.
10. Update direct `BatchEvalCtx` / `PolicyBatchItem` construction in tests.
11. Add wildcard arms to matches on public gatehouse enums; they are now `#[non_exhaustive]`.

## Policy domains

Before, the same four generic parameters appeared on every policy, builder, and checker:

```rust,ignore
type DocumentChecker = PermissionChecker<User, ReadAction, Document, RequestContext>;

impl Policy<User, ReadAction, Document, RequestContext> for OwnerPolicy {
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, User, ReadAction, Document, RequestContext>,
    ) -> PolicyEvalResult {
        // ...
    }
}
```

Now define a domain marker once:

```rust
use gatehouse::PolicyDomain;

# struct User;
# struct ReadAction;
# struct Document;
# struct RequestContext;
struct Documents;

impl PolicyDomain for Documents {
    type Subject = User;
    type Action = ReadAction;
    type Resource = Document;
    type Context = RequestContext;
}
```

Then use that domain everywhere:

```rust,ignore
type DocumentChecker = PermissionChecker<Documents>;

impl Policy<Documents> for OwnerPolicy {
    async fn evaluate(&self, ctx: &EvalCtx<'_, Documents>) -> PolicyEvalResult {
        // ...
    }
}
```

The associated types are always read in `Subject`, `Action`, `Resource`, `Context` order.

## Policy results

`PolicyEvalResult::Denied` used to mean "this policy did not grant". That was too easy to confuse with the final top-level `AccessEvaluation::Denied`.

Policy-level non-grants are now `PolicyEvalResult::NotApplicable`:

```rust,ignore
// Before
if ctx.subject.id == ctx.resource.owner_id {
    ctx.grant("owner")
} else {
    ctx.deny("not owner")
}

// After
if ctx.subject.id == ctx.resource.owner_id {
    ctx.grant("owner")
} else {
    ctx.not_applicable("not owner")
}
```

For direct constructors:

```rust,ignore
// Before
PolicyEvalResult::denied("OwnerPolicy", "not owner")

// After
PolicyEvalResult::not_applicable("OwnerPolicy", "not owner")
```

`AccessEvaluation::Denied` still exists. It is the final result returned by the checker when no policy grants or a forbid policy vetoes.

## Forbid policies

Explicit veto rules use `Effect::Forbid` and `PolicyEvalResult::Forbidden`. `PolicyBuilder` has a direct `.forbid()` helper:

```rust,ignore
let suspended_account = PolicyBuilder::<Documents>::new("SuspendedAccount")
    .when(|user, _action, _doc, _ctx| user.is_suspended)
    .forbid()
    .build();
```

A hand-written policy that can veto should return `ctx.forbid(...)` and declare its effect:

```rust,ignore
impl Policy<Documents> for LegalHold {
    async fn evaluate(&self, ctx: &EvalCtx<'_, Documents>) -> PolicyEvalResult {
        if ctx.resource.legal_hold {
            ctx.forbid("document is under legal hold")
        } else {
            ctx.not_applicable("no legal hold")
        }
    }

    fn effect(&self) -> Effect {
        Effect::Forbid
    }
}
```

Forbid-effect policies are evaluated before allow-only policies, so their result is not skipped by the grant short-circuit. If a hand-written policy can return `Forbidden` but does not declare `Effect::Forbid` or `Effect::AllowOrForbid`, the checker can only honor the veto if evaluation reaches that policy before a grant.

`Forbidden` now propagates through `AndPolicy`, `OrPolicy`, `NotPolicy`, and `DelegatingPolicy`. If you previously placed a forbid policy inside a combinator expecting it to behave like an ordinary non-grant, change that local guard into a normal grant-style predicate and wrap it with `not()`:

```rust,ignore
let muted = PolicyBuilder::<Threads>::new("Muted")
    .subjects(|member| member.muted)
    .build();

let collaborator_unless_muted = collaborator.and(muted.not());
```

Use `.forbid()` only when a match should actively veto every grant path in the composed decision.

`not()` cannot cancel an active veto. A policy like `admin.or(blocked.not())` still denies if `blocked` returns `Forbidden`; this is the intended absolute-veto behavior. Similarly, `grant.and(forbid_only)` can never grant because a forbid-only child never satisfies AND's "all children grant" rule. For a scoped "grant unless blocked" condition, make `blocked` a normal allow-style predicate and compose `grant.and(blocked.not())`.

## PolicyBuilder

`PolicyBuilder` is now domain-parameterized:

```rust,ignore
// Before
let owner = PolicyBuilder::<User, ReadAction, Document, RequestContext>::new("Owner")
    .when(|user, _action, doc, _ctx| user.id == doc.owner_id)
    .build();

// After
let owner = PolicyBuilder::<Documents>::new("Owner")
    .when(|user, _action, doc, _ctx| user.id == doc.owner_id)
    .build();
```

Use `.subjects`, `.actions`, `.resources`, and `.context` for single-axis predicates. Use `.when` when the predicate compares multiple inputs. The generated batch path evaluates subject, action, and context predicates once per batch and resource / cross-axis predicates per item.

`PolicyBuilder::new` accepts `impl Into<Cow<'static, str>>`: a `'static` literal (`new("Owner")`) is zero-allocation on the trace path; runtime names (`new(format!(...))`) remain owned. Existing `new("literal")` call sites pick up the zero-alloc path with no source change.

## Checker calls

The old API had several entry points:

```rust,ignore
checker.check(&user, &Read, &document, &request_context).await;

checker
    .evaluate_in_session(&session, &user, &Read, &document, &request_context)
    .await;

checker
    .filter_authorized_in_session_by_resource(
        &session,
        &user,
        &Read,
        documents,
        &request_context,
        |document| document,
    )
    .await;
```

The new API binds request-wide inputs once:

```rust,ignore
let session = EvaluationSession::empty();
let bound = checker.bind(&session, &user, &Read, &request_context);

let decision = bound.check(&document).await;
let decisions = bound.evaluate(documents.clone()).await;
let visible = bound.filter(documents).await;
```

When the list item is a wider row than the authorization resource, use the extractor variants and keep returning the original rows:

```rust,ignore
let decisions = bound
    .evaluate_by(invoice_rows.clone(), |row| &row.authz_resource)
    .await;

let visible_rows = bound
    .filter_by(invoice_rows, |row| &row.authz_resource)
    .await;
```

For fact-backed policies, create the session from a registry:

```rust,ignore
let registry = FactRegistry::builder()
    .with_arc::<RelationshipQuery<UserId, DocumentId, Relation>>(relationships)
    .build();

let session = registry.session();
let decision = checker
    .bind(&session, &user, &Read, &request_context)
    .check(&document)
    .await;
```

`EvaluationSession::empty()` and `EvaluationSession::shared_empty()` remain available for fact-free policy stacks, but every evaluation now receives a session explicitly. This removes the old "fact-backed checker accidentally used the no-session `check` path" footgun.

## Batch evaluation

`BoundEvaluator::evaluate` and `BoundEvaluator::filter` accept caller-owned resources. Items only need to borrow as `D::Resource`:

```rust,ignore
let results: Vec<(Document, AccessEvaluation)> = bound.evaluate(documents).await;
```

If you constructed `BatchEvalCtx` directly in tests or custom combinators, note the shape changed:

```rust,ignore
let items = docs
    .iter()
    .map(|resource| PolicyBatchItem::<Documents> { resource })
    .collect::<Vec<_>>();

let ctx = BatchEvalCtx {
    session: &session,
    subject: &user,
    action: &Read,
    context: &request_context,
    items: &items,
    policy_type: policy.policy_type(),
};
```

`PolicyBatchItem` no longer carries a per-item context. Batch evaluation is one subject, one action, one request context, and many resources. If you need different contexts, group the inputs and evaluate one bound batch per context.

## Long-lived streams

`EvaluationSession` is still scoped to one authorization pass. For SSE, WebSocket, and other long-lived streams, do not keep one fact-backed session for the stream lifetime.

If your product contract authorizes once at stream open, create a fresh session, compute the visible ID set with `filter` / `filter_by`, drop the session, and only emit frames for that set. If the stream must observe mid-stream permission revocation, run periodic reauthorization with a fresh `registry.session()` each tick and re-bind the checker for that pass.

## Lookup APIs

`LookupSource` is now domain-parameterized:

```rust,ignore
#[async_trait]
impl LookupSource<Documents> for DocumentLookup {
    type Id = DocumentId;
    type Error = LookupError;

    async fn lookup_page(
        &self,
        subject: &User,
        action: &ReadAction,
        context: &RequestContext,
        cursor: Option<&[u8]>,
        limit: NonZeroUsize,
    ) -> Result<LookupPage<DocumentId>, LookupError> {
        // ...
    }
}
```

Call lookup through the bound evaluator:

```rust,ignore
let page = checker
    .bind(&session, &user, &Read, &request_context)
    .lookup_page(&lookup, &hydrator, cursor.as_deref(), limit)
    .await?;
```

The lookup source still must enumerate a superset of every resource any policy could grant. Gatehouse only narrows and authorizes the hydrated subset; it does not discover grant paths the lookup source omitted.

## Built-in policy changes

### RbacPolicy

`RbacPolicy` now takes the domain as its first generic parameter:

```rust,ignore
let policy = RbacPolicy::<Documents, _, _>::new(required_roles, subject_roles);
```

Inference often fills the closure types once the policy is added to a `PermissionChecker<Documents>`.

### RebacPolicy

`RebacPolicy` also takes the domain:

```rust,ignore
let policy = RebacPolicy::<Documents, UserId, DocumentId, Relation>::new(
    |user| user.id,
    |document| document.id,
    Relation::Viewer,
);
```

Relationship facts are still loaded through `RelationshipQuery<UserId, DocumentId, Relation>` registered in the request session.

### DelegatingPolicy

`DelegatingPolicy` maps from one domain to another:

```rust,ignore
let delegate = DelegatingPolicy::<Comments, Documents>::new(
    "DocumentEditAllowsCommentModeration",
    document_checker,
    |comment_user| comment_user.clone(),
    |_action| DocumentAction::Edit,
    |_subject, _action, comment, _ctx| comment.document.clone(),
    |_subject, _action, ctx| ctx.document_context.clone(),
);
```

The context mapper runs once per bound batch. The resource mapper still runs per resource.

## AbacPolicy removal

`AbacPolicy` is removed. Use `PolicyBuilder::when` for synchronous attribute-style checks:

```rust,ignore
let owner = PolicyBuilder::<Documents>::new("Owner")
    .when(|user, _action, document, _ctx| user.id == document.owner_id)
    .build();
```

Use a hand-written `Policy<Domain>` when the rule needs async work, custom batching, custom telemetry metadata, or explicit forbid behavior.

## Tests and assertions

Tests that asserted policy-level denials should now assert not-applicability:

```rust,ignore
evaluation.assert_not_applicable_by("Owner");
```

Use `assert_forbidden_by` for active vetoes and `assert_denied` / `assert_denied_with_reason_containing` for final access denials.

## Public enum matching

Public gatehouse enums are now `#[non_exhaustive]`, including `AccessEvaluation`, `PolicyEvalResult`, `Effect`, `FactLoadResult`, `FactLoadError`, and lookup errors. Add wildcard arms and fail closed for unknown access decisions:

```rust,ignore
match evaluation {
    AccessEvaluation::Granted { .. } => Ok(()),
    AccessEvaluation::Denied { reason, .. } => Err(reason),
    _ => Err("unknown access decision".into()),
}
```

## Dependency changes

`uuid` moved out of normal dependencies; it is only used by examples, tests, and doctests. If your application used gatehouse's transitive `uuid`, add `uuid` to your own `Cargo.toml`.

The new optional `serde` feature derives `Serialize` for decision and trace types (`AccessEvaluation`, `EvalTrace`, `PolicyEvalResult`, `FactProvenance`, and related value enums) for audit logging pipelines.

## Mechanical search hints

These searches catch most migration work:

```shell
rg "Policy<[^>]*,[^>]*,[^>]*,[^>]*"
rg "PolicyBuilder::<[^>]*,[^>]*,[^>]*,[^>]*"
rg "EvalCtx<'_, [^>]*,[^>]*"
rg "ctx\\.deny|PolicyEvalResult::Denied|PolicyEvalResult::denied"
rg "evaluate_in_session|filter_authorized|lookup_authorized|\\.check\\(&"
rg "AbacPolicy|Effect::Deny"
rg "AccessEvaluation::|PolicyEvalResult::|FactLoadResult::|LookupAuthorizedError::"
```
