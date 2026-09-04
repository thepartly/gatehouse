# Migrating from 0.5.1 to the 0.6 prerelease

This guide describes the unreleased 0.6 API, including typed grant and veto
capabilities. The intended first prerelease is `0.6.0-alpha.1`; it is not yet
published. Rust 1.82 remains the minimum supported compiler. The historical
0.4 → 0.5 guide follows at the end and describes that older API only.

## Separate grants from vetoes

`Policy<D>::evaluate` now returns `GrantResult`, and `evaluate_batch` returns
`Vec<GrantResult>`. These results can grant, abstain, or be indeterminate;
they cannot veto. Existing grant policies generally need only to change their
return type and replace `PolicyEvalResult` constructors with `GrantResult`
constructors. Context helpers (`ctx.grant`, `ctx.not_applicable`, and
`ctx.indeterminate`) already return the correct type.

Veto rules implement `VetoPolicy<D>` and return `VetoResult`. Use
`ctx.forbid`, `ctx.pass`, or `ctx.veto_indeterminate`. Register them with
`checker.add_veto(...)`. A passing veto never grants access. `Effect`,
`Policy::effect`, `add_forbid_policy`, and `PolicyBuilder::forbid` are removed.
For predicates, replace `.forbid().build()` with `.build_veto()`:

```rust
use gatehouse::*;

struct Account { suspended: bool }
struct Accounts;
impl PolicyDomain for Accounts {
    type Subject = Account;
    type Action = ();
    type Resource = ();
    type Context = ();
}

let mut checker = PermissionChecker::<Accounts>::new();
checker.add_policy(PolicyBuilder::<Accounts>::new("Member").build());
checker.add_veto(
    PolicyBuilder::<Accounts>::new("Suspended")
        .subjects(|account| account.suspended)
        .build_veto(),
);
# tokio_test::block_on(async {
let session = EvaluationSession::empty();
let evaluation = checker
    .bind(&session, &Account { suspended: true }, &(), &())
    .check(&()).await;
evaluation.assert_forbidden_by("Suspended");
# });
```

For a custom rule that previously both granted and vetoed, split it into
separate grant and veto policies and register both. Share backend inputs
through a request-scoped fact session. The type checker now rejects a grant
policy returning a veto, rather than relying on a correctly declared effect.

## Composition and delegation

`PolicyExt::and`, `or`, and `not` accept grant policies only. For a local
exclusion, use `grant.and(blocked.not())`, where `blocked` is an ordinary
predicate grant. A veto cannot be embedded in this expression.

Use `AllOfVeto` / `VetoPolicyExt::all_of` when every child must veto to block,
and `AnyOfVeto` / `VetoPolicyExt::any_of` when any child veto should block.
A definite pass settles an all-of veto; a definite veto settles an any-of
veto. Otherwise uncertainty remains indeterminate. There is no veto negation.
Dynamic policy combinators reject empty collections.

Custom grant result composition uses `GrantResult::all` / `any`. Empty
result collections abstain. Their aggregate decisions are computed by the
constructors; compose veto policies with `AllOfVeto` / `AnyOfVeto`. `PolicyEvalResult`
remains the inspectable audit tree, including `Combined { decision,
provenance, children, .. }`; policies cannot return it or convert an arbitrary
raw tree into an authority-bearing result. Use `result.trace()` to inspect
and `PolicyResult::into_trace()` to consume a typed result into its audit tree.

Register a `DelegatingPolicy` with **`checker.add_delegate(delegate)`**, not
`add_policy`. That one call installs both capabilities atomically. Child veto
uncertainty blocks parent grants; a child grant failure does not block an
independent parent grant after the child's vetoes pass. Each child capability
phase runs at most once for each parent evaluation; delegation retains batch
execution and nested evidence.

## Preserve outages at application boundaries

`AccessEvaluation` has three outcomes: `Granted`, `Denied`, and
`Indeterminate`. A definite veto wins over uncertainty. An unresolved veto
blocks grants. A failed grant policy can be superseded by an independent
grant; without a grant, its failure makes the evaluation indeterminate.

Replace reason-only `to_result(...)` conversion or blanket 403 responses with
`into_result()` and classify `AccessError`:

```rust
use gatehouse::{AccessError, AccessEvaluation, EvalTrace};

fn status(evaluation: AccessEvaluation) -> u16 {
    match evaluation.into_result() {
        Ok(()) => 200,
        Err(AccessError::Denied { .. }) => 403,
        Err(_) => 503,
    }
}
assert_eq!(status(AccessEvaluation::Indeterminate {
    reason: "authorization input unavailable".into(),
    trace: EvalTrace::new(),
}), 503);
```

`AccessError` retains the full trace and exposes `fact_load_errors()` for
structured classification. Applications can implement `From<AccessError>`
for their own error type and then use `check(...).await.into_result()?`.
Inspect `FactProvenance::error_kind` to distinguish backend failures,
unregistered sources, contract violations, and cancelled loaders. Keep
trace details in internal diagnostics rather than HTTP response bodies.

For complete lists, migrate:

| Previous call | Strict replacement |
| --- | --- |
| `filter(resources).await` | `try_filter(resources).await?` |
| `filter_by(rows, projection).await` | `try_filter_by(rows, projection).await?` |
| `lookup_page(...).await?` | `try_lookup_page(...).await?` |

Strict filtering excludes definite denials but returns `FilterError<Item>`
if any final decision is indeterminate. The error owns **all** original items
and evaluations in input order; `indeterminate()` selects unresolved items.
A grant that supersedes an irrelevant failure succeeds normally. No partial
list is returned as success.

`try_lookup_page` returns `LookupAuthorizedError<LookupErr, HydrateErr,
Resource>`. Its `Evaluation` variant retains hydrated resources and their
decisions; source, hydration, and contract errors remain distinct variants.
An authorization failure returns no next cursor: retry the same input cursor
with a fresh session after recovery. Previously returned pages cannot be
retracted, so an endpoint requiring an atomic multi-page response must collect
all pages before sending it.

The original `filter`, `filter_by`, and `lookup_page` remain deliberately
lossy: they exclude both denials and indeterminate items. The old `to_result`
also merges both outcomes into one reason-only error callback.
`denied_due_to_fact_load_error()` is deprecated; it detects any error in the
trace, which may be irrelevant to the final decision.

## Record consulted facts

Use `ctx.fact(key)` / `ctx.facts(keys)` instead of raw session loads. Batch
policies use `ctx.facts_by(key_of)` or `ctx.fact(shared_key)`. These APIs load
through the session and record successful, missing, and failed facts. The
checker and built-in combinators attach the recorded evidence automatically.

```rust
use async_trait::async_trait;
use gatehouse::*;
use std::borrow::Cow;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct Membership(u64);
impl FactKey for Membership {
    type Value = bool;
    const NAME: &'static str = "membership";
}
struct Documents;
impl PolicyDomain for Documents {
    type Subject = u64;
    type Action = ();
    type Resource = ();
    type Context = ();
}
struct Member;
#[async_trait]
impl Policy<Documents> for Member {
    async fn evaluate(&self, ctx: &EvalCtx<'_, Documents>) -> GrantResult {
        match ctx.fact(Membership(*ctx.subject)).await {
            FactLoadResult::Found(true) => ctx.grant("member"),
            _ => ctx.not_applicable("membership not established"),
        }
    }
    fn policy_type(&self) -> Cow<'static, str> { "Member".into() }
}
```

A recorded failure upgrades abstention or veto pass to `Indeterminate`.
Decisive grants and vetoes retain their decisions even if an optional recorded
load failed. This rule is the same for leaf and aggregate results. `Combined`
now stores its own provenance; child evidence remains on child nodes. There
are no synthetic failure children and no shape-dependent loss of evidence.

When invoking a policy directly, call `ctx.finish(result)` or
`batch_ctx.finish(results)`. Construct contexts with `EvalCtx::new` /
`BatchEvalCtx::new`; their recorders and session fields are private.
`ctx.session()` remains an explicit non-recording escape hatch. Use
`ctx.record(FactProvenance::from_load_result(...))` for externally loaded facts.

Other source and behavior changes:

- `FactKey` requires `Debug` and has a default `render()` for audit keys.
  `RelationshipQuery` requires `Debug` on IDs and relations, plus `Display`
  on the relation. Override `render()` to control diagnostic key text.
- `FactProvenance` gains `error_kind`. Add `error_kind: None` to old struct
  literals, or prefer `from_load_result`. `new` produces unclassified evidence.
- `RebacPolicy` returns indeterminate for failed loads. `Missing` and
  `Found(false)` still abstain. Backend detail stays in provenance.
- Wrong-length policy batches produce indeterminate results. Veto failures
  block grants; grant failures can be superseded by a later grant.
- `NotPolicy` preserves uncertainty, including explicit failed-load evidence
  on an abstaining result. Never disguise an unrecorded failure as abstention.
- `assert_denied()` no longer accepts indeterminate evaluations. Use
  `assert_indeterminate()` for outage tests.
- Serialized audit nodes gain `decision` and aggregate `provenance` fields;
  update consumers that previously expected `Combined.outcome`.

## Optional instrumentation

`tracing` is a default-enabled Cargo feature. Set `default-features = false`
to remove tracing instrumentation and its dependency. Decisions, returned
`EvalTrace`, and fact provenance remain available and have the same semantics;
telemetry spans, security events, and contract warnings are absent. `serde`
is independent and can be enabled without tracing.

Before adopting the prerelease, run custom policy and batch tests, inject fact
backend failures into single and list endpoints, and check every wildcard
match on `AccessEvaluation`. Create a fresh session for retries and each
reauthorization pass so cached failures or stale permissions are not reused.

---

# Historical: migrating from 0.4 to 0.5

This section describes the released 0.5 API. Its Effect declarations, raw policy
results, and mixed combinators are superseded by the 0.6 guide above.

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
