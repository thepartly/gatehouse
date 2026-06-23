# Migrating from 0.4 to the next major release

The next major Gatehouse release intentionally breaks the public API to make the authorization surface smaller and harder to misuse. The main changes are:

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
