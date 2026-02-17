# Changelog

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
