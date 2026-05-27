# Migrating from 0.2 to 0.3

Gatehouse 0.3 is a breaking release. The main shift is that relationship data is now loaded through request-scoped `EvaluationSession` instances and typed `FactSource`s instead of policy-owned `RelationshipResolver`s.

## Policy Implementations

The `Policy` trait now receives an evaluation context rather than separate arguments, and `policy_type` returns `&str`.

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
#[async_trait]
impl Policy<User, Document, Read, RequestContext> for OwnerPolicy {
    async fn evaluate(
        &self,
        ctx: &EvalCtx<'_, User, Document, Read, RequestContext>,
    ) -> PolicyEvalResult {
        if ctx.subject.id == ctx.resource.owner_id {
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

    fn policy_type(&self) -> &str {
        "OwnerPolicy"
    }
}
```

For dynamic policy names, store the name in the policy and return a borrowed string:

```rust
struct NamedPolicy {
    name: Box<str>,
}

impl NamedPolicy {
    fn new(name: impl Into<Box<str>>) -> Self {
        Self { name: name.into() }
    }
}

#[async_trait]
impl Policy<User, Document, Read, RequestContext> for NamedPolicy {
    async fn evaluate(
        &self,
        _ctx: &EvalCtx<'_, User, Document, Read, RequestContext>,
    ) -> PolicyEvalResult {
        PolicyEvalResult::Denied {
            policy_type: self.policy_type().to_string(),
            reason: "not implemented".to_string(),
        }
    }

    fn policy_type(&self) -> &str {
        self.name.as_ref()
    }
}
```

## Checker Calls

All checker evaluation now takes an explicit session. For RBAC/ABAC-only paths, use `EvaluationSession::empty()` or `EvaluationSession::shared_empty()`.

```rust
// 0.2
let decision = checker
    .evaluate_access(&user, &Read, &document, &request_context)
    .await;

// 0.3
let session = EvaluationSession::empty();
let decision = checker
    .evaluate_in_session(&session, &user, &Read, &document, &request_context)
    .await;
```

Use `EvaluationSession::shared_empty()` only when no fact-backed policies are expected. It is a process-wide empty session and rejects source registration.

## ReBAC

`RelationshipResolver` has been removed. Use `RelationshipQuery` as the fact key, implement `FactSource`, and register the source in the request session.

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

Use the batch helpers for list endpoints instead of looping manually:

```rust
let visible = checker
    .filter_authorized_with_context_in_session_by(
        &session,
        &user,
        &Read,
        documents,
        &request_context,
        |document| document,
    )
    .await;
```

`PermissionChecker` still evaluates policies in order with `OR` semantics. Policies such as `RebacPolicy` can collapse backend work inside `Policy::evaluate_batch`.

## Session Setup and Cancellation

Prefer `EvaluationSession::builder()` so all request-scoped fact sources are declared together. `register` and `register_arc` still panic on duplicate source registration; use `try_register` or `try_register_arc` if setup should return an error. Use `replace`, `replace_arc`, `try_replace`, or `try_replace_arc` only when overwriting a source is intentional.

If a leader task for an in-flight fact load is cancelled or panics, the session caches `FactLoadError::LoaderCancelled` for the affected keys. This poisons those keys for the rest of that request-scoped session so authorization fails closed and waiters do not hang. Retry with a fresh session.
