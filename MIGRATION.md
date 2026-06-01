# Migrating from 0.2 to 0.3

Gatehouse 0.3 is a breaking release. The main shift is that relationship data is now loaded through request-scoped `EvaluationSession` instances and typed `FactSource`s instead of policy-owned `RelationshipResolver`s.

Three sentence-level changes apply across the codebase before you touch any specific section:

- **`Policy::evaluate_access` is renamed to `Policy::evaluate`** and takes a single `EvalCtx<'_, S, R, A, C>` reference instead of four positional borrows. Every existing `impl Policy` will need this rewrite.
- **`Subject`, `Resource`, `Action`, and `Context` must be `Sync`.** Batch evaluation borrows these across `.await` points. Types that hold `Rc`, `RefCell`, raw pointers, or other `!Sync` interior state will need to be reworked or wrapped (`Arc<Mutex<_>>` / `Arc<RwLock<_>>` if interior mutability is genuinely required).
- **Construct `PolicyEvalResult` through the new constructors**, not struct literals. The `Granted` and `Denied` variants gained a `provenance: Vec<FactProvenance>` field, so any direct `PolicyEvalResult::Granted { … }` / `PolicyEvalResult::Denied { … }` literal stops compiling. Use `PolicyEvalResult::granted(name, Some(reason))` and `PolicyEvalResult::denied(name, reason)` (or the `_with_facts` variants when recording provenance) — or, in policy bodies, prefer `ctx.grant(reason)` / `ctx.deny(reason)`.

## Policy Implementations

The `Policy` trait now receives an evaluation context rather than separate arguments. `policy_type` returns `Cow<'static, str>` so static names stay zero-allocation, and policies build results through the `ctx.grant` / `ctx.deny` shortcuts rather than struct literals.

```rust
// 0.2
#[async_trait]
impl Policy<User, Document, Read, RequestContext> for OwnerPolicy {
    async fn evaluate_access(
        &self,
        user: &User,
        _action: &Read,
        document: &Document,
        _context: &RequestContext,
    ) -> PolicyEvalResult {
        if user.id == document.owner_id {
            PolicyEvalResult::Granted {
                policy_type: "OwnerPolicy".to_string(),
                reason: Some("owner".to_string()),
            }
        } else {
            PolicyEvalResult::Denied {
                policy_type: "OwnerPolicy".to_string(),
                reason: "not owner".to_string(),
            }
        }
    }

    fn policy_type(&self) -> String {
        "OwnerPolicy".to_string()
    }
}

// 0.3
use std::borrow::Cow;

#[async_trait]
impl Policy<User, Document, Read, RequestContext> for OwnerPolicy {
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, User, Document, Read, RequestContext>,
    ) -> PolicyEvalResult {
        if ctx.subject.id == ctx.resource.owner_id {
            ctx.grant("owner")
        } else {
            ctx.deny("not owner")
        }
    }

    fn policy_type(&self) -> Cow<'static, str> {
        Cow::Borrowed("OwnerPolicy")
    }
}
```

`ctx.grant` / `ctx.deny` tag the resulting `PolicyEvalResult` with the policy's name (captured once by the checker into `ctx.policy_type`), so the body never re-passes `self.policy_type()`.

For dynamic policy names, store an owned name on the policy and return `Cow::Owned` from `policy_type`. The shortcuts still work; the result will carry the dynamic name. Dynamic names pay extra allocations per evaluation (see `EvalCtx::policy_type` rustdoc) — prefer a `'static` name when you can.

```rust
struct NamedPolicy {
    name: String,
}

impl NamedPolicy {
    fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

#[async_trait]
impl Policy<User, Document, Read, RequestContext> for NamedPolicy {
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, User, Document, Read, RequestContext>,
    ) -> PolicyEvalResult {
        ctx.deny("not implemented")
    }

    fn policy_type(&self) -> Cow<'static, str> {
        Cow::Owned(self.name.clone())
    }
}
```

A note on `PolicyBuilder`: `PolicyBuilder::new(name)` stores the name as an owned `String`, so every builder-built policy is a dynamic-name policy under the trace-path allocation accounting (one allocation per evaluation, plus another on the `ctx.grant`/`ctx.deny` helper path). If you're migrating a policy whose name is a `'static` string literal and you want the zero-allocation path, switch from `PolicyBuilder` to a small hand-written `impl Policy<…>` that returns `Cow::Borrowed("MyPolicy")`. The builder is the right tool for ergonomics and dynamic names; hand-written impls are the right tool for hot paths with fixed names.

## Checker Calls

All checker evaluation now takes an explicit session. For RBAC/ABAC-only paths, the simplest migration is `PermissionChecker::check`, which wraps `evaluate_in_session(EvaluationSession::shared_empty(), …)`:

```rust
// 0.2
let decision = checker
    .evaluate_access(&user, &Read, &document, &request_context)
    .await;

// 0.3 (RBAC/ABAC only — no fact-backed policies)
let decision = checker
    .check(&user, &Read, &document, &request_context)
    .await;
```

For checkers with any fact-backed policy (ReBAC, lookup, or any policy that reads from an `EvaluationSession`), build a session per request and call `evaluate_in_session`:

```rust
// 0.3 (fact-backed)
let session = EvaluationSession::builder()
    .with_arc::<RelationshipQuery<Uuid, Uuid, Relation>>(Arc::clone(&relationships))
    .build();
let decision = checker
    .evaluate_in_session(&session, &user, &Read, &document, &request_context)
    .await;
```

## ReBAC

`RelationshipResolver` has been removed. Use `RelationshipQuery` as the fact key, implement `FactSource`, and register the source in the request session.

The `RebacPolicy::new` signature changes accordingly:

- **The `resolver` first argument is gone.** The relationship source is now registered on the `EvaluationSession`, not on the policy.
- **The relation argument shifts from `String` (or `impl Into<String>`) to a typed value** — typically a `Copy` enum like `Relation::Viewer`. The `FactSource` implementation is responsible for converting the typed value to whatever its backend uses (a SQL `text` column, a string-keyed lookup table, etc.).

So a 0.2 call like `RebacPolicy::new(resolver, sid_fn, rid_fn, "viewer".to_string())` becomes a 0.3 call like `RebacPolicy::new(sid_fn, rid_fn, Relation::Viewer)`, plus a session-side `with_arc::<RelationshipQuery<Sid, Rid, Relation>>(source)` registration.

```rust
// 0.2
let policy = RebacPolicy::new(
    resolver,
    |user: &User| user.id,
    |document: &Document| document.id,
    "viewer".to_string(),
);
checker.add_policy(policy);

// 0.3
#[async_trait]
impl FactSource<RelationshipQuery<Uuid, Uuid, Relation>> for RelationshipStore {
    async fn load_many(
        &self,
        keys: &[RelationshipQuery<Uuid, Uuid, Relation>],
    ) -> Vec<FactLoadResult<bool>> {
        // Load all keys in one backend call and return one result per key.
        todo!()
    }
}

let relationships: Arc<dyn FactSource<RelationshipQuery<Uuid, Uuid, Relation>>> =
    Arc::new(RelationshipStore::new(pool));
let session = EvaluationSession::builder()
    .with_arc::<RelationshipQuery<Uuid, Uuid, Relation>>(Arc::clone(&relationships))
    .build();

checker.add_policy(RebacPolicy::new(
    |user: &User| user.id,
    |document: &Document| document.id,
    Relation::Viewer,
));

let decision = checker
    .evaluate_in_session(&session, &user, &Read, &document, &request_context)
    .await;
```

`FactSource::load_many` receives unique keys and must return exactly one result per key in the same order. Missing sources, backend errors, wrong result counts, and cancelled leader loads fail closed.

## Batch List Endpoints

Use the batch helpers for list endpoints instead of looping manually. The shared-context-per-page entrypoint is `filter_authorized_in_session_by_resource` (renamed from the 0.3-alpha `filter_authorized_with_context_in_session_by`):

```rust
let visible = checker
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

For per-item `(R, C)` pairs (each item carries its own context), use `filter_authorized_in_session_by`. For full per-item evaluations (item + decision pairs returned for both grants and denials), use `evaluate_batch_in_session_by_resource` or `evaluate_batch_in_session_by` respectively.

`PermissionChecker` still evaluates policies in order with `OR` semantics. Policies such as `RebacPolicy` can collapse backend work inside `Policy::evaluate_batch`.

## Session Setup and Cancellation

Prefer `EvaluationSession::builder()` so all request-scoped fact sources are declared together. `register` and `register_arc` still panic on duplicate source registration; use `try_register` or `try_register_arc` if setup should return an error. Use `replace`, `replace_arc`, `try_replace`, or `try_replace_arc` only when overwriting a source is intentional.

If a leader task for an in-flight fact load is cancelled or panics, the session caches `FactLoadError::LoaderCancelled` for the affected keys. This poisons those keys for the rest of that request-scoped session so authorization fails closed and waiters do not hang. Retry with a fresh session.
