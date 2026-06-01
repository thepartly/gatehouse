# Changelog

## [Unreleased]

### Breaking

- `PolicyEvalResult::Granted` / `Denied` / `Combined` (and `AccessEvaluation::Granted`) now store `policy_type` as `Cow<'static, str>` instead of `String`. The `granted` / `denied` / `granted_with_facts` / `denied_with_facts` constructors accept `impl Into<Cow<'static, str>>`. Combined with the trait change below, static-name policies are **zero-allocation end-to-end** — direct constructor calls and the new `EvalCtx::grant` / `deny` shortcuts both go through `Cow::Borrowed`.
- `Policy::policy_type` return type changed from `&str` to `Cow<'static, str>`. Built-in policies return `Cow::Borrowed("Name")` and pay zero allocations. Migrate downstream policies with one line per impl: `fn policy_type(&self) -> Cow<'static, str> { Cow::Borrowed("MyPolicy") }`. Dynamic-name policies return `Cow::Owned(self.name.clone())` and pay one allocation per `policy_type()` call (where the previous `&str` API let them return `&self.name` without allocating), plus one more on the single-item `ctx.grant` / `ctx.deny` helper path. The batch path additionally clones the name into each `BatchEvalCtx` chunk. See the `EvalCtx::policy_type` rustdoc for the full accounting and prefer a `'static` name when you can.
- `EvalCtx` and `BatchEvalCtx` gain a `policy_type: Cow<'static, str>` field, captured once per evaluation by the checker (and by combinators when they fan out). Custom `Policy` impls and tests that build these directly need to populate it.
- `PermissionChecker::evaluate_batch_with_context_in_session_by` renamed to `evaluate_batch_in_session_by_resource`; `filter_authorized_with_context_in_session_by` renamed to `filter_authorized_in_session_by_resource`. The new `_by_resource` suffix mirrors the existing `_by` (per-item `(R, C)`) and makes the distinguishing axis explicit. Old names are removed; migrate with:

  ```
  s/evaluate_batch_with_context_in_session_by/evaluate_batch_in_session_by_resource/g
  s/filter_authorized_with_context_in_session_by/filter_authorized_in_session_by_resource/g
  ```
- `DelegatingPolicy` constructor `policy_type` parameter changed from `impl Into<String>` to `impl Into<Cow<'static, str>>` to match the trait return type.

### Added

- `PermissionChecker::check(subject, action, resource, context)` — convenience wrapper for RBAC/ABAC-only callers that internally uses `EvaluationSession::shared_empty()`. For checkers with any fact-backed policy, call `evaluate_in_session` directly so the session can carry registered `FactSource`s.
- `PermissionChecker::named(name)` constructor and `name()` accessor. The name is recorded on the `evaluate_in_session` and `evaluate_batch_in_session_*` tracing spans as `checker.name` so multi-checker audit pipelines can disambiguate which checker produced each evaluation when policy names are shared. `Cow<'static, str>`, so static literals are zero-allocation.
- `EvalCtx::grant` / `deny` / `grant_with_facts` / `deny_with_facts` shortcut methods that build a `PolicyEvalResult` tagged with `ctx.policy_type`, so policy bodies no longer have to re-pass `self.policy_type()`. Both `grant` and `deny` take the reason as `impl Into<String>` for symmetry; the rare no-reason grant case can still use `PolicyEvalResult::granted(name, None)` directly.
- `AccessEvaluation` test helpers: `assert_granted_by`, `assert_denied`, `assert_denied_with_reason_containing`, plus non-panicking `granted_policy_type()` and `denied_reason()` accessors. Cuts the boilerplate of pattern-matching the evaluation in policy unit tests.
- Trace-aware test helpers `AccessEvaluation::assert_denied_by(policy_type)` (symmetric with `assert_granted_by`) and `assert_trace_contains(needle)`. `assert_denied_with_reason_containing` matches only the top-level summary reason — which is hardcoded to `"All policies denied access"` when no policy granted, so per-policy denial reasons live only in the trace tree. The new helpers walk the trace and substring-match `display_trace()` respectively for the multi-policy case.

### Changed

- Built-in `AbacPolicy` and `RbacPolicy` migrated to the new `ctx.grant` / `ctx.deny` shortcuts. Combinators populate the inner `EvalCtx` / `BatchEvalCtx` with the inner policy's name when dispatching, including the `NotPolicy::evaluate_batch` path that previously forwarded the outer ctx unchanged (and would have tagged any wrapped policy's batch leaves as `NotPolicy`).
- README, lib.rs Quick Start/Custom Policies doctests, and the RBAC/ABAC-only examples (`rbac_policy`, `policy_builder`, `groups_policy`, `actix_web`) migrated to `checker.check(...)`; custom-policy examples (`groups_policy`, `combinator_policy`, `lookup_in_ram`) migrated to `ctx.grant`/`ctx.deny`. The `axum` example's `TestCheckerExt` test helper is deleted in favor of `check` directly. Combinator implementations drop the redundant `Cow::Owned(self.policy_type().to_string())` wrapping now that `policy_type()` already returns `Cow<'static, str>`.
- `PermissionChecker` docs gain a "One checker per resource type" recipe naming the idiomatic shape and the tag-enum anti-pattern, plus a sibling "Modeling list/scope endpoints" recipe showing how to compose a scope checker (`OrgScope` × `ListAction`) with a per-item checker driven by `lookup_authorized_*` without resorting to `enum Resource { Item, Listing }` discriminators.
- `PolicyBuilder` docs gain a "Type-inference notes" section listing the three patterns that anchor `<S, R, A, C>` (typed predicate closures, bind-site annotation, turbofish) and calling out the misleading "type annotations needed for `&_`" closure error that actually points at `::new`.
- Crate-level, `FactSource`, and `Hydrator` rustdoc now frame these traits as gatehouse's request-scoped DataLoader-style primitives, and call out that callers may invoke an existing DataLoader implementation (`async_graphql::dataloader` from the `async-graphql` crate, the `ultra-batch` crate, or a home-grown batcher) directly from inside `FactSource::load_many` or `Hydrator::hydrate`. Gatehouse owns the per-request fact graph; the underlying loader owns batching across the rest of the request and any longer-lived caching. The `Hydrator` docs also call out that gatehouse expects `Vec<Option<Resource>>` in input order, so a hydrator wrapping a map-returning DataLoader re-orders the loader's output back into the slice shape.
- Examples polished for v0.3 idiom: `combinator_policy` uses `EvaluationSession::empty()` for its RBAC/ABAC-only setup; `groups_policy` gained a `//!` file header. (The `axum` test helper formerly named `evaluate_access` was subsequently removed entirely — see the migration bullet above — once `PermissionChecker::check` landed.)
- `PolicyBuilder`-built policies now override `Policy::evaluate_batch` to short-circuit the batch-shared axes once: the `.subjects()` and `.actions()` predicates are evaluated at most once per batch rather than once per item, and the closures are skipped entirely if an earlier axis short-circuits the batch. Per-item axes (`.resources()`, `.context()`, `.when()`) still run per item, since they can vary across the batch. The win is two-fold: (a) reduced trace volume in `PermissionChecker::evaluate_batch_in_session_by` for policies whose discriminator is subject- or action-only (the per-item `gatehouse::security` events collapse to one outcome), and (b) measurable throughput, growing with batch size — Criterion benches show the optimized PolicyBuilder path is **13% faster at N=1, 18% at N=10, 32% at N=100** compared to a hand-written dynamic-name policy using the serial-loop default. Static-name hand-written policies still beat both; adopters who can use a `'static` name table should.
- `PermissionChecker::evaluate_in_session` (single-item path) now moves the policy's `policy_type` straight into the constructed `EvalCtx` instead of cloning, and destructures it back out on the grant branch. Static-name policies are unchanged (the clone was already free for `Cow::Borrowed`); dynamic-name policies pay one allocation per evaluation here instead of two.
- `Policy::evaluate` rustdoc now signposts the "register a `FactSource` instead of calling the backing service directly" pattern for I/O whose result depends on subject-derived data but not resource. `FactSource` rustdoc gains a `(subject, scope) → resolved-id` example showing that the trait isn't limited to relationship-shaped facts.
- `Policy::evaluate_batch` rustdoc now names the design intent: serial-by-default because the trait can't know your concurrency budget, with explicit guidance on the override shapes (`join_all`, `FuturesUnordered`, semaphore-bounded) for callers who can.

## [0.3.0-alpha.2] - 2026-06-01

### Breaking

- `PolicyEvalResult::Granted` and `PolicyEvalResult::Denied` gain a `provenance: Vec<FactProvenance>` field recording the facts a policy consulted to reach its decision. Construct results via the new `PolicyEvalResult::granted`/`denied` (or `granted_with_facts`/`denied_with_facts`) constructors instead of struct literals.
- `RebacPolicy` now requires its subject and resource ID types to implement `Debug` so the consulted relationship can be rendered into decision provenance.

### Added

- `LookupSource` and `Hydrator` traits plus `PermissionChecker::lookup_authorized` and `lookup_authorized_page` for "what can this subject see?" list endpoints. The source enumerates a candidate superset; the hydrator resolves IDs to caller-owned resources (with explicit "no longer exists" via `Option<Resource>`); the full policy stack still authorizes each hydrated candidate. Cursor-progress is enforced (no infinite loops on stuck sources). See `examples/lookup_in_ram.rs`. (#24)
- `FactProvenance` and `FactOutcome`: per-decision fact provenance attached to `PolicyEvalResult` leaf nodes and rendered inline by `EvalTrace::format`. `RebacPolicy` records the relationship it consulted, the load outcome, and any backend error detail. Operational fact-load telemetry remains on the `gatehouse.fact_load` tracing span.
- `PolicyEvalResult::granted`, `denied`, `granted_with_facts`, and `denied_with_facts` constructors and a `provenance()` accessor.

### Changed

- Internal refactor: the per-stripe session state machine is now a private synchronous core (`FactStripeCore<K, W>`) with no async, no tracing, and a generic waiter type. `FactState<K>` remains the async adapter that owns locks, the source, and tracing. No public API change. (#28)
- Expanded and clarified docs: `RelationshipQuery`, `FactLoadResult` (rationale vs `Result<Option<V>, FactLoadError>`), `BatchEvalCtx` single-action design and escape hatches, `EvaluationSession` (no TTL; layer longer-lived caching inside a `FactSource`), the `shared_empty`/`register` panic rationale, and the `LoaderCancelled` error.

### Tests

- Loom permutation-test harness for the session fact-load state machine. Seven models cover leader-election uniqueness, exactly-once waiter wake-up on finish, fail-closed cancellation, cache-write visibility, replacement atomicity w.r.t. planning, multi-stripe independence, and replacement rejection while a leader is in flight. Run under `RUSTFLAGS="--cfg loom" cargo test --lib --release` and as a separate CI job. (#29)

## [0.3.0-alpha.1] - 2026-05-27

### Breaking

- **FactSource-backed ReBAC**: `RelationshipResolver` has been removed. `RebacPolicy` now extracts subject/resource IDs, builds `RelationshipQuery` keys, and loads relationship facts through a request-scoped `EvaluationSession` registered with a `FactSource`. (#20)
- **Session-aware policy API**: `Policy::evaluate_access(...)` has been replaced by `Policy::evaluate(&EvalCtx)` and `Policy::evaluate_batch(&BatchEvalCtx)`. `PermissionChecker` evaluation now takes an explicit `EvaluationSession`; RBAC/ABAC-only callers can use `EvaluationSession::empty()`.
- **Borrowed policy type names**: `Policy::policy_type` now returns `&str` instead of allocating a `String`.
- **Sync policy inputs**: `Policy` and `PermissionChecker` now require `Subject`, `Resource`, `Action`, and `Context` to be `Sync` so batch contexts can borrow them across async evaluation.

### Added

- Batch authorization APIs for evaluating or filtering caller-owned resource/context pairs while preserving input order and duplicate resources. (#17)
- `FactKey`, `FactLoadResult`, `FactLoadError`, `FactSource`, and `RelationshipQuery` as the new fact-loading layer for ReBAC and future fact-backed policies.
- Request-scoped fact caching, duplicate-key expansion, source-level chunking via `FactSource::max_batch_size`, and in-flight load coalescing.
- `EvaluationSession::builder()` for declaring all request-scoped fact sources in one place.
- `EvaluationSession::shared_empty()` for hot RBAC/ABAC-only paths that should not allocate a fresh empty session per call.
- `EvaluationSession::try_register`, `try_register_arc`, `try_replace`, and `try_replace_arc` for non-panicking fact-source setup.
- `DelegatingPolicy` for cross-domain authorization delegation through a child `PermissionChecker` while preserving child batch evaluation and trace output.
- `PermissionChecker::evaluate_batch_resources_in_session` and `filter_authorized_resources_in_session` for resource-only batches with unit context.
- `PermissionChecker::with_max_batch_size` as a defensive cap for policy batch calls.
- PostgreSQL 18 bulk ReBAC example demonstrating an in-memory public-post policy composed with SQL-backed relationship facts, ordered `unnest ... WITH ORDINALITY` loading, and point-vs-bulk behavior.
- Axum example bulk invoice listing endpoint demonstrating app-state fact sources and request-scoped `EvaluationSession` registration.
- In-RAM ReBAC example and Criterion benchmarks for shared in-process `FactSource` usage, session overhead, latency-injected batching, and in-flight coalescing.

### Changed

- `AndPolicy`, `OrPolicy`, `NotPolicy`, boxed `dyn Policy`, and `RebacPolicy` now preserve batching through their batch evaluation paths.
- `EvaluationSession::register` and `register_arc` now fail fast on duplicate fact-source registration; use `replace` or `replace_arc` when overwriting is intentional, or the `try_*` variants when setup should return errors instead.
- Evaluation tracing now records single-item outcome fields, batch item/grant/deny counts, and per-policy chunk pending/grant/deny counts for batch evaluation.
- README and rustdocs now frame Gatehouse as an in-process authorization engine with request-scoped fact loading, and document decision semantics, short-circuit trace behavior, batch authorization, fact-backed ReBAC, and telemetry fields.
- README and rustdocs now document batch tracing fields and the typed-relation-to-backend-storage boundary for SQL-backed ReBAC sources.

### Fixed

- Fact sources that return the wrong number of results now fail closed with `FactLoadError::SourceContractViolation` instead of panicking or producing partial results.
- Cancelled or panicking leader tasks for in-flight fact loads now wake waiters with `FactLoadError::LoaderCancelled` instead of leaving them pending forever.
- Source replacement now checks in-flight loads, installs the new source, and clears cached facts while holding the same session registry lock, so readers cannot observe old cached facts after a replacement is installed.
- SQL-backed example fact sources now map backend errors to fail-closed `FactLoadResult::Error` values instead of panicking.

## [0.2.0] - 2026-02-17

### Breaking

- **Generic relationship types for ReBAC**: `RelationshipResolver<S, R>` is now `RelationshipResolver<S, R, Re>` and `RebacPolicy` gains a `Re` type parameter. This allows using enums or other domain-specific types instead of `&str` for compile-time safety. `Re` must implement `Display` for human-readable policy evaluation messages. (#10, #14)

### Added

- `#![warn(missing_docs)]` lint enforced — all public items now have documentation. (#13)
- Quick Start section in module-level docs showing `PolicyBuilder` usage.
- Standalone doc examples for `PolicyBuilder`, `RbacPolicy`, `EvalTrace`, and `AccessEvaluation::to_result`.
- Enum-based relationship example in `examples/rebac_policy.rs`.

### Changed

- Updated dependencies. (#12)

## [0.1.4] - 2025-10-21

- Add benchmarks.
- Refined the security rule telemetry to reuse cached policy metadata and emit structured `tracing::trace!` events.
