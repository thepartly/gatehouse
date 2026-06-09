# Changelog

## [Unreleased]

### Added

- `AccessEvaluation::trace()` — returns the `EvalTrace` regardless of outcome. Both variants carry a trace; callers (including several examples) previously had to hand-roll the same two-arm `match` to render it.
- `PolicyEvalResult::reason_str()` — borrowing analogue of `reason()`, for callers that only need to inspect or render the reason without cloning.
- `EmptyPoliciesError` now implements `Display` and `std::error::Error`, matching every other public error type in the crate, so `AndPolicy::try_new` / `OrPolicy::try_new` failures can be printed with `{}` and propagated with `?` into boxed errors.
- `CombineOp` now derives `Copy` and `Eq`.
- `examples/deny_override.rs` — demonstrates "deny overrides allow" (account suspensions, legal holds). Contrasts the tempting mistake (adding a deny policy to the `OR`-based `PermissionChecker`, which never vetoes) against the working shape: gating the allow set behind `NotPolicy(blocklist)` under `AndPolicy`. Prints a wrong/right verdict table and the decision trace.
- `examples/delegating_policy.rs` — demonstrates `DelegatingPolicy` cross-domain delegation: a comment-moderation rule defers to the document domain's `PermissionChecker` ("you may edit a comment if you may edit its document"), with the trace crossing the domain boundary.

### Changed

- Renamed the `pg18_bulk_rebac` example to `postgres_bulk_rebac`. The SQL is ordinary PostgreSQL (`unnest … WITH ORDINALITY`, `bool_or`, an unlogged table); it was developed and benchmarked against PostgreSQL 18 but does not require it. README references and the example progression updated to match.
- Reworked `examples/actix_web.rs` into a fact-backed integration: shared `AppState` owns a relationship `FactSource`, each request builds its own `EvaluationSession`, a collaborator (`editor`) relationship gates view/edit, and a batched `GET /posts` list endpoint demonstrates `filter_authorized_in_session_by_resource`. Denials route through a documented `forbidden` helper flagging trace echo as demo-only.
- Trimmed `examples/axum.rs` to a single resource type (invoices), removing the payments half and the `Resource` enum. One resource type means one checker is the correct shape, so the example no longer models the multi-type-behind-one-enum arrangement the docs caution against. Integration tests updated accordingly.
- `examples/combinator_policy.rs` now drives its `AndPolicy` / `OrPolicy` combinators through `PermissionChecker::check` instead of hand-building an `EvalCtx`, matching the public RBAC/ABAC entry point used by the other examples. Short-circuit assertions are unchanged.
- `examples/in_ram_rebac.rs` now prints the single-resource denial and the per-request results of the concurrent batch (previously silent assertions), so `cargo run` shows what the example verifies.
- `examples/mfa_freshness_context.rs` now prints the decision trace per case, surfacing the freshness reason strings ("MFA reasserted 480s ago, exceeds freshness window") that the policy builds.
- `examples/factsource_n_plus_one.rs` now counts and asserts `load_many` invocations (one batched source call), making the batching lesson explicit alongside the existing backend-call (dedup) count.
- Standardized the genuinely-empty `Context` generic on `()` across `rbac_policy`, `combinator_policy`, `rebac_policy`, `in_ram_rebac`, and `lookup_in_ram` (previously a mix of `EmptyContext`, `RequestContext`, and `RequestCtx`); examples with real per-request data keep a context struct.

### Removed

- `examples/groups_policy.rs`, whose policy-composition and trace-reading concepts are already covered by `combinator_policy` and `policy_builder`.

## [0.3.0] - 2026-06-02

First stable release of the v0.3 line. v0.3 consolidates around request-scoped fact loading: relationship data is loaded through an `EvaluationSession` registered with a `FactSource` instead of policy-owned `RelationshipResolver`s, list endpoints batch and deduplicate without leaking policy logic into the data layer, and the trait surface tightens around `Cow<'static, str>` policy names with `ctx.grant` / `ctx.deny` shortcuts.

Beyond the request-scoped fact-loading model, three v0.3 capabilities are worth surfacing for adopters evaluating the release:

- **Per-decision audit provenance.** Every `PolicyEvalResult` leaf carries a `Vec<FactProvenance>` recording the facts the policy consulted, the load outcome, and any backend error detail — rendered inline by `EvalTrace::format` and separate from the operational `gatehouse.fact_load` tracing span used for latencies and cache-hit telemetry.
- **Multi-checker audit disambiguation.** `PermissionChecker::named(...)` records a `checker.name` field on the `evaluate_in_session` / `evaluate_batch_in_session_*` tracing spans, so audit pipelines running several checkers with overlapping policy names (an `Invoice` checker and a `Product` checker both reusing a shared `AdminOverride` policy, for example) can route by source.
- **Loom-verified session state machine.** The per-stripe fact-load coordinator is a Sans-I/O synchronous core with a loom permutation-test harness covering leader-election uniqueness, exactly-once waiter wake-up, fail-closed cancellation, multi-stripe independence, and replacement-while-in-flight. Runs as a separate CI job under `RUSTFLAGS="--cfg loom"`.

If you are upgrading from 0.2, the diff is substantial — start with `MIGRATION.md`, then read the `[0.3.0-alpha.1]`, `[0.3.0-alpha.2]`, and `[0.3.0-alpha.3]` sections below for the full breakdown of breaking changes that landed during the alpha cycle.

The diff since `[0.3.0-alpha.3]` is small:

### Added

- `examples/factsource_n_plus_one.rs` — contrastive teaching artifact pairing a "wrong" supplier policy that holds `Arc<HierarchyService>` and fires N redundant backend calls per batch against a "right" version that registers a `FactSource` and consumes via `ctx.session.get(...)`. The example reports actual backend call counts (25 vs 1 for a 25-invoice batch) so the N+1 lesson is visible at `cargo run --example`.
- `benches/README.md` cataloguing what each Criterion bench protects, with explicit callouts for the `naive_per_item_sessions` vs `checker_batch_one_session` pair (the N+1 → batched regression test) and the `policy_builder_subject_only_batch` group (per-axis shortcut throughput numbers).

### Changed

- `PolicyBuilder::when` rustdoc now telegraphs that it's the cross-axis escape hatch, not the default predicate setter. Calls out the batch-shortcut implication (axis-specific predicates participate in the subject/action once-per-batch shortcut; `.when()` always runs per-item) and offers a rule-of-thumb: if the closure ignores two or more of `(subject, action, resource, context)`, the corresponding axis-specific helper is the better fit. No API change.
- `PolicyBuilder` rustdoc now explicitly names the dynamic-name allocation footnote: builder-built policies are dynamic-name policies under the trace-path accounting; the "zero-allocation end-to-end" framing applies to hand-written `impl Policy` with a `'static` literal name. `MIGRATION.md` gains the same note.
- `PermissionChecker`'s "One checker per resource type" recipe gains a one-paragraph pointer acknowledging that downstream projects with many resource types typically wrap their per-resource checkers in a thin dispatching service trait or macro, and that gatehouse intentionally stays out of that organizational layer (downstream patterns vary widely; prescribing one shape would lock in a specific dispatching style).
- `FactSource::load_many` rustdoc now names the silent-misattribution failure mode: a result vector with the right length but the wrong order has no detection path, since the session can't re-key against the inputs. Documents the standard fixes (`WITH ORDINALITY` for SQL, re-index for map-returning DataLoaders).
- README's Tracing and Telemetry section warns that `policy.result.reason` and `FactProvenance.detail` are emitted verbatim to every subscriber; treat reason strings as part of the public audit surface and keep credentials, tokens, and unredacted PII out of them.
- README's Batch Authorization section now names the `PolicyBuilder`-specific scope of the per-axis `.subjects()`/`.actions()` short-circuit win: hand-written `Policy::evaluate_batch` impls that don't override get nothing for free.
- `examples/mfa_freshness_context.rs`'s `HighValueRequiresFreshMfa` carries a "DO NOT add this policy directly to a `PermissionChecker`" warning at the struct level and at the grant site. The "rule doesn't apply → grant" pattern is correct under `AndPolicy` (the example's intended composition) but would grant every below-threshold call under the checker's default OR semantics — a real footgun for an example file readers copy from.

### Fixed

- `impl<S, R, A, C> Policy<S, R, A, C> for Box<dyn Policy<S, R, A, C>>` had `Send + Sync` bounds on each type parameter, over-constraining relative to the trait declaration (`Sync` only). Adopters with `!Send` subject/resource/action/context types can now box their policies. No code change for the common case; the previous bounds were strictly stricter than the trait required.

## [0.3.0-alpha.3] - 2026-06-01

API ergonomics + performance consolidation. The headline changes:

- `PermissionChecker::check`, `PermissionChecker::named`, `EvalCtx::grant` / `deny` shortcuts, and trace-aware test helpers — adopters write less boilerplate in policy bodies and unit tests.
- `Policy::policy_type` returns `Cow<'static, str>`; **static-name** policies (those that return `Cow::Borrowed("MyPolicy")` from a literal) are zero-allocation end-to-end on the helper path. Dynamic-name policies — including everything built via `PolicyBuilder::new(name)`, since the builder stores its name as an owned `String` — pay one allocation per call (down from a `String` round trip in earlier alphas).
- `PolicyBuilder`-built policies short-circuit batch-shared axes (`.subjects()`, `.actions()`) once per batch — bench-measured 13–32% throughput improvement, growing with batch size.
- The two `*_with_context_in_session_by` batch methods are renamed `*_in_session_by_resource`. Old names are removed (no deprecation alias).

### Breaking

- `PolicyEvalResult::Granted` / `Denied` / `Combined` (and `AccessEvaluation::Granted`) now store `policy_type` as `Cow<'static, str>` instead of `String`. The `granted` / `denied` / `granted_with_facts` / `denied_with_facts` constructors accept `impl Into<Cow<'static, str>>`. Combined with the trait change below, static-name policies are zero-allocation end-to-end (direct constructor calls and the new `EvalCtx::grant` / `deny` shortcuts both go through `Cow::Borrowed`). Dynamic-name policies still pay per call — see the next bullet and the `EvalCtx::policy_type` rustdoc for the full accounting.
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
- README, lib.rs Quick Start/Custom Policies doctests, and the RBAC/ABAC-only examples (`rbac_policy`, `policy_builder`, `groups_policy`, `actix_web`) migrated to `checker.check(...)` for the everyday RBAC/ABAC path.
- Custom-policy examples (`groups_policy`, `combinator_policy`, `lookup_in_ram`) migrated to the `ctx.grant` / `ctx.deny` shortcuts.
- `axum` example's `TestCheckerExt` test helper deleted now that `PermissionChecker::check` is the supported entry point.
- Combinator implementations drop the redundant `Cow::Owned(self.policy_type().to_string())` wrapping now that `policy_type()` already returns `Cow<'static, str>`.
- `PermissionChecker` docs gain a "One checker per resource type" recipe naming the idiomatic shape and the tag-enum anti-pattern, plus a sibling "Modeling list/scope endpoints" recipe showing how to compose a scope checker (`OrgScope` × `ListAction`) with a per-item checker driven by `lookup_authorized_*` without resorting to `enum Resource { Item, Listing }` discriminators.
- `PolicyBuilder` docs gain a "Type-inference notes" section listing the three patterns that anchor `<S, R, A, C>` (typed predicate closures, bind-site annotation, turbofish) and calling out the misleading "type annotations needed for `&_`" closure error that actually points at `::new`.
- Crate-level, `FactSource`, and `Hydrator` rustdoc now frame these traits as gatehouse's request-scoped DataLoader-style primitives, and call out that callers may invoke an existing DataLoader implementation (`async_graphql::dataloader` from the `async-graphql` crate, the `ultra-batch` crate, or a home-grown batcher) directly from inside `FactSource::load_many` or `Hydrator::hydrate`. Gatehouse owns the per-request fact graph; the underlying loader owns batching across the rest of the request and any longer-lived caching. The `Hydrator` docs also call out that gatehouse expects `Vec<Option<Resource>>` in input order, so a hydrator wrapping a map-returning DataLoader re-orders the loader's output back into the slice shape.
- Examples polished for v0.3 idiom: `combinator_policy` uses `EvaluationSession::empty()` for its RBAC/ABAC-only setup; `groups_policy` gained a `//!` file header. (The `axum` test helper formerly named `evaluate_access` was subsequently removed entirely — see the migration bullet above — once `PermissionChecker::check` landed.)
- `PolicyBuilder`-built policies override `Policy::evaluate_batch` to short-circuit the batch-shared axes. The `.subjects()` and `.actions()` predicates are evaluated at most once per batch instead of once per item; per-item axes (`.resources()`, `.context()`, `.when()`) still run per item. Two wins:
  - **Reduced trace volume** in `PermissionChecker::evaluate_batch_in_session_by` for policies whose discriminator is subject- or action-only — the per-item `gatehouse::security` events collapse to one outcome for the batch.
  - **Measurable throughput**, growing with batch size. Criterion benches show 13% faster at N=1, 18% at N=10, 32% at N=100 vs the same shape through the serial-loop default. Static-name hand-written policies still beat both; prefer a `'static` name table when you can.
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
