# AGENTS.md

Notes for coding agents. Assumes you know Rust tooling — this covers only what is specific or non-obvious to this repo.

## Project-specific commands

```bash
cargo run --example axum        # HTTP server on :8000
cargo run --example actix_web   # HTTP server on :8080

# Reproduce the PR mutation gate locally (see "CI gates" below)
git diff origin/main...HEAD -- src/checker.rs src/combinators.rs > mutants.diff
cargo mutants --in-place --in-diff=mutants.diff \
  --file src/checker.rs --file src/combinators.rs \
  --baseline=skip --timeout=60 --build-timeout=300 --all-features
```

## CI gates that bite

- Clippy runs with `-D warnings`; any warning fails CI. `fmt` + `clippy` before committing.
- A **diff-scoped `cargo-mutants` gate** mutates the PR's changes to `src/checker.rs` and `src/combinators.rs` only. Every new/changed line there must be killed by a test or CI fails (~20 min run). When you touch veto/short-circuit logic, add a test that *distinguishes the mutation* (e.g. a case where `&&` vs `||` actually diverge), not just a happy-path assertion — a green test that survives the mutant is the usual failure mode here.
- `main` is governed by a require-approval ruleset: PRs need an approving review (you cannot self-approve); repo/org admins can bypass.
- Publishing a GitHub Release for tag `vX.Y.Z` triggers `cargo publish` to crates.io — irreversible. Releases finalize `CHANGELOG.md` (`[Unreleased]` → `[X.Y.Z] - <date>`) in a small "Release vX.Y.Z" PR; `Cargo.toml`/`Cargo.lock` are bumped in the feature PR.

## Architecture

One library crate, split across `src/*.rs` and re-exported from `src/lib.rs`. Unit tests are in `src/tests.rs`; integration tests in `tests/` — and the examples are `include!`d into those tests, so a broken example breaks the test build.

`Policy<D: PolicyDomain>` is the core trait: async `evaluate` → `PolicyEvalResult`, plus `evaluate_batch` (must return one result per input, in order). `PolicyDomain` names `Subject`/`Action`/`Resource`/`Context` once. `PermissionChecker<D>` is bound per request — `checker.bind(&session, &subject, &action, &context)` yields a `BoundEvaluator` with `check` / `evaluate` / `evaluate_by` / `filter` / `filter_by` / `lookup_page`.

Built-ins: `RbacPolicy`, `RebacPolicy`, `DelegatingPolicy`; `PolicyBuilder::when` for ABAC-style predicates; combinators `AndPolicy` / `OrPolicy` / `NotPolicy` plus fluent `PolicyExt`. Closures are `Send + Sync + 'static`. Decisions are never `Result`: `PolicyEvalResult::{Granted, NotApplicable, Forbidden, Combined}` at the policy level, `AccessEvaluation::{Granted, Denied}` at the top. Public enums are `#[non_exhaustive]`. Telemetry is `tracing` (OpenTelemetry semantic conventions); reason strings and `FactProvenance.detail` reach subscribers — treat them as audit surface, no secrets.

## Load-bearing invariants (read before editing `checker.rs` / `combinators.rs`)

- **Deny-overrides via veto-prefix ordering.** Veto-capable policies (`effect().can_forbid()`) are scheduled ahead of allow-only ones, and a grant is never returned until *every* veto-capable policy has been evaluated — so a `Forbidden` is always observed before a grant can short-circuit. `evaluate_one` (single) and `evaluate_batch_by` (batch) implement this independently and **must agree per item**; differential proptests against a deny-overrides oracle in `tests/checker_contract.rs` enforce it.
- **Forbid detection is whole-tree.** `is_forbidden()` is `forbidden_leaf().is_some()`, which recurses through `Combined` children unconditionally; `is_granted()` on a `Combined` reads only `outcome`. Soundness rests on one invariant: **no combinator returns `outcome: true` while keeping a `Forbidden` leaf in its children.** Preserve it when adding or altering a combinator.
- **`effect()` is a security contract.** A policy that can return `Forbidden` must declare `Effect::Forbid` or `Effect::AllowOrForbid`, or its veto can be short-circuited by an earlier grant. The checker emits a `WARN` when an `Effect::Allow` policy returns `Forbidden` (it honors the veto where observed, but cannot reorder it).
