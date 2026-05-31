# Changelog

## [Unreleased]

### Added

- `LookupSource` and `Hydrator` traits plus `PermissionChecker::lookup_authorized` and `lookup_authorized_page` for "what can this subject see?" list endpoints. The source enumerates a candidate superset; the hydrator resolves IDs to caller-owned resources (with explicit "no longer exists" via `Option<Resource>`); the full policy stack still authorizes each hydrated candidate. Cursor-progress is enforced (no infinite loops on stuck sources). See `examples/lookup_in_ram.rs`. (#24)

### Changed

- Internal refactor: the per-stripe session state machine is now a private synchronous core (`FactStripeCore<K, W>`) with no async, no tracing, and a generic waiter type. `FactState<K>` remains the async adapter that owns locks, the source, and tracing. No public API change. (#28)

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
