# AGENTS.md

Guidance for AI coding agents working in this repository.

## Commands

```bash
cargo build                                                    # build
cargo fmt --all                                                # format
cargo clippy --all-targets --all-features -- -D warnings       # lint (CI uses -D warnings)
cargo test --all-targets --all-features                        # all tests
cargo test <test_name>                                         # single test
cargo mutants --in-place --file src/checker.rs --file src/combinators.rs --all-features -- --test checker_contract
cargo bench                                                    # criterion benchmarks
cargo run --example axum                                       # HTTP server on :8000
cargo run --example actix_web                                  # HTTP server on :8080
```

CI order: build → clippy → doc → test → focused mutation tests. Always `fmt` + `clippy` before committing.

## Architecture

Single-crate library split across `src/*.rs` modules and re-exported from
`src/lib.rs`. Unit tests are in `src/tests.rs`; integration tests in `tests/`
include examples via `include!(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/..."))`.

Core abstraction is `Policy<D: PolicyDomain>` (async `evaluate()` →
`PolicyEvalResult`). `PolicyDomain` names `Subject`, `Action`, `Resource`, and
`Context`. `PermissionChecker` is bound per request with
`checker.bind(&session, &subject, &action, &context)`, producing a
`BoundEvaluator` for `check`, `evaluate`, `evaluate_by`, `filter`, `filter_by`,
and `lookup_page`.

Built-in policies: `RbacPolicy`, `RebacPolicy`, `DelegatingPolicy`. Use
`PolicyBuilder::when` for ABAC-style predicates. Combinators: `AndPolicy`,
`OrPolicy`, `NotPolicy`, plus fluent `PolicyExt`.

All policy closures require `Send + Sync + 'static`. No `Result` error types
for decisions: policy outcomes are `PolicyEvalResult` variants (`Granted`,
`NotApplicable`, `Forbidden`, `Combined`), and final checker outcomes are
`AccessEvaluation::{Granted, Denied}`. Telemetry uses `tracing` with
OpenTelemetry semantic conventions.
