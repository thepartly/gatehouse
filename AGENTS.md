# AGENTS.md

Notes for coding agents. Assumes you know Rust tooling — this covers only what is specific or non-obvious to this repo.

## Project-specific commands

```bash
cargo run --example axum        # HTTP server on :8000
cargo run --example actix_web   # HTTP server on :8080

# Reproduce the PR mutation gate locally (see "CI gates" below)
git diff origin/main...HEAD -- src/checker.rs src/combinators.rs src/capability.rs src/policies/delegating.rs > mutants.diff
cargo mutants --in-place --in-diff=mutants.diff \
  --file src/checker.rs --file src/combinators.rs --file src/capability.rs \
  --file src/policies/delegating.rs \
  --baseline=skip --timeout=60 --build-timeout=300 --all-features \
  -- --test checker_contract --test tracing_contract --test outcome_contract
```

## CI gates that bite

- Clippy runs with `-D warnings`; any warning fails CI. `fmt` + `clippy` before committing.
- A **diff-scoped `cargo-mutants` gate** covers `src/checker.rs`, `src/combinators.rs`, `src/capability.rs`, and `src/policies/delegating.rs`. When changing decisions or short-circuit logic, add a test that distinguishes the mutation (for example, inputs where `&&` and `||` diverge).
- `main` is governed by a require-approval ruleset: PRs need an approving review (you cannot self-approve); repo/org admins can bypass.
- Pushing a `v*` tag triggers irreversible crates.io publication, followed by creation of the GitHub Release. The tag must match the Cargo version and point to a commit with successful main CI. Prepare and validate the exact candidate before requesting publication approval; see `.github/workflows/release.yml`.

## Architecture

One library crate, split across `src/*.rs` and re-exported from `src/lib.rs`. Unit tests are in `src/tests.rs`; integration tests in `tests/` — and the examples are `include!`d into those tests, so a broken example breaks the test build.

`Policy<D>` returns `GrantResult`; `VetoPolicy<D>` returns `VetoResult`. Both have single and batch evaluation; batches return one result per input in order. `PolicyDomain` names `Subject`/`Action`/`Resource`/`Context`. Bind request inputs once with `checker.bind(...)`. Use `try_filter`, `try_filter_by`, or `try_lookup_page` when an indeterminate item must fail the list operation; the non-fallible variants deliberately omit indeterminate items.

`PolicyEvalResult` is the inspectable audit tree, not a custom policy's return type. Controlled `GrantResult` and `VetoResult` constructors enforce authority boundaries. `AccessEvaluation::{Granted, Denied, Indeterminate}` is the top-level decision; `into_result` preserves denied versus indeterminate in `AccessError`. Context fact-loading helpers record provenance; aggregate nodes retain their own facts. Public enums are `#[non_exhaustive]`. The default-enabled `tracing` feature controls instrumentation independently of returned audit evidence. Reasons and fact details are audit surfaces; exclude secrets.

## Load-bearing invariants (read before editing evaluator or capability code)

- **Vetoes precede grants.** Every applicable veto must pass before grants can authorize. A definite veto outranks uncertainty; unresolved vetoes block grants. An unresolved grant never defeats an independent grant. Single and batch results must agree per item, including nested delegation.
- **Authority is typed.** Keep raw audit-tree construction separate from grant/veto return values. A public conversion from an arbitrary `PolicyEvalResult` into a capability result would defeat this boundary.
- **Aggregate decisions govern audit descendants.** An `AllOfVeto` can pass while retaining a matched child veto in its trace. `is_forbidden()` reads the node decision; veto attribution follows only active veto branches. A recursive search for any forbidden leaf would change authorization semantics.
- **Delegation is atomic.** `add_delegate` installs both child capabilities. Child grant uncertainty remains grant uncertainty in the parent. Both phases must use the same mapped inputs, and each child policy runs at most once per resource in its phase.
- **Adversarial validation.** Preserve recursive oracle tests, capability compile-fail tests, malformed-batch tests, and mutation coverage when simplifying code. A shorter evaluator still needs these guarantees.
