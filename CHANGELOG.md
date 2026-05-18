# Changelog

## [0.3.0] - 2026-05-18

### Breaking

- **FactSource-backed ReBAC**: `RelationshipResolver` has been removed. `RebacPolicy` now extracts subject/resource IDs, builds `RelationshipQuery` keys, and loads relationship facts through a request-scoped `EvaluationSession` registered with a `FactSource`. (#20)
- **Session-aware policy API**: `Policy::evaluate_access(...)` has been replaced by `Policy::evaluate(&EvalCtx)` and `Policy::evaluate_batch(&BatchEvalCtx)`. `PermissionChecker` evaluation now takes an explicit `EvaluationSession`; RBAC/ABAC-only callers can use `EvaluationSession::empty()`.
- **Borrowed policy type names**: `Policy::policy_type` now returns `&str` instead of allocating a `String`.

### Added

- Batch authorization APIs for evaluating or filtering caller-owned resource/context pairs while preserving input order and duplicate resources. (#17)
- `FactKey`, `FactLoadResult`, `FactLoadError`, `FactSource`, `RelationshipQuery`, and `LookupSource` as the new fact-loading layer for ReBAC and future fact-backed policies.
- Request-scoped fact caching, duplicate-key expansion, source-level chunking via `FactSource::max_batch_size`, and in-flight load coalescing.
- `PermissionChecker::with_max_batch_size` as a defensive cap for policy batch calls.
- PostgreSQL 18 bulk ReBAC example demonstrating an in-memory public-post policy composed with SQL-backed relationship facts, ordered `unnest ... WITH ORDINALITY` loading, and point-vs-bulk behavior.
- Axum example bulk invoice listing endpoint demonstrating app-state fact sources and request-scoped `EvaluationSession` registration.

### Changed

- `AndPolicy`, `OrPolicy`, `NotPolicy`, boxed `dyn Policy`, and `RebacPolicy` now preserve batching through their batch evaluation paths.
- Evaluation tracing now records single-item outcome fields, batch item/grant/deny counts, and per-policy pending/grant/deny counts for batch evaluation.
- README and rustdocs now frame Gatehouse as an in-process authorization engine with request-scoped fact loading, and document decision semantics, short-circuit trace behavior, batch authorization, fact-backed ReBAC, and telemetry fields.
- README and rustdocs now document batch tracing fields and the typed-relation-to-backend-storage boundary for SQL-backed ReBAC sources.

### Fixed

- Fact sources that return the wrong number of results now fail closed with `FactLoadError::SourceContractViolation` instead of panicking or producing partial results.
- Cancelled or panicking leader tasks for in-flight fact loads now wake waiters with `FactLoadError::LoaderCancelled` instead of leaving them pending forever.
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
