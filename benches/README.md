# Benchmarks

Criterion benches live in `benches/permission_checker.rs`. Run the full suite with `cargo bench`, or one group with `cargo bench --bench permission_checker -- <group_name>`. Use `--quick` for a fast smoke check that skips Criterion's full statistical analysis.

Each bench protects a load-bearing property of the public API. Adding a regression here is the cheapest signal that something we promise in `CHANGELOG.md` or rustdoc no longer holds. The catalogue below names the property each bench locks in, so a future contributor can decide whether a change is expected to move a number.

## `permission_checker_bound_check`

Single-item bound `check` throughput, varying policy count.

- **`trailing_allow / {1,4,16,64}`** — `OR`-short-circuit on the last policy. Protects: the checker doesn't pay quadratically for unrelated policies; the cost grows linearly with the number of evaluated policies before a grant.
- **`all_deny / {1,4,16,64}`** — all policies deny. Protects: the full denial path (build the combined trace, return the summary `AccessEvaluation::Denied`) is linear in policy count, not super-linear.

## `in_ram_fact_source`

`EvaluationSession::get` against an in-RAM `FactSource`, varying the number of distinct keys requested.

- **`session_get_many_uncached / N`** — cold fetch of `N` distinct keys through the session in one call. Protects: the session's deduplication + the source's batch path don't add overhead proportional to anything other than `N`.
- **`session_get_many_cached / N`** — second call with the same keys hits the request-scoped cache. Protects: the cache is free on repeat lookups (the cost should be far below `session_get_many_uncached`).
- **`checker_batch_uncached / N`** — the checker's batched filter path against a cold session. Baseline for the latency-injected comparison below.

## `latency_fact_source` — the N+1 vs batched protection

This group injects a fixed async delay per source call so the gap between per-item and batched loading is visible. **The pair below is the regression test for the FactSource N→1 win.** If a refactor accidentally reverts to per-item fact loads, `checker_batch_one_session` regresses toward the `naive_per_item_sessions` baseline.

- **`naive_per_item_sessions / N`** — `N` separate `EvaluationSession`s, one per resource, each running its own checker evaluation. Models the failure mode where an author calls `Arc<dyn HierarchyService>` directly from `Policy::evaluate` and pays one round trip per item.
- **`checker_batch_one_session / N`** — one session, one bound `filter` call. The session deduplicates and the fact source sees one `load_many` covering all `N` keys.
- **`independent_same_keys_4_tasks / N`** — four parallel tasks each building their own session and requesting the same `N` keys. Models the worst case where coalescing across tasks doesn't help.
- **`coalesced_same_keys_4_tasks / N`** — four parallel tasks sharing one session, requesting the same `N` keys. Protects: when keys collide, the second loader joins the in-flight load instead of issuing a redundant call.

The expected gap between `naive_per_item_sessions` and `checker_batch_one_session` widens with `N` (the naive shape grows linearly with the per-call overhead; the batched shape grows mostly with the source's `load_many` work). Keep that gap as a CI smoke check, not just a property test.

## `parallel_in_ram_fact_state`

Concurrent loaders sharing one or more sessions against a hot in-RAM source. Protects the sharding paths used under read-mostly contention.

- **`coarse_reference_cached_4_tasks / N`** — sanity reference for fully-cached reads under contention. Protects: hot-path reads do not serialise behind the load-coordination state.
- **`sharded_session_cached_4_tasks / N`** — sharded session under the same workload. Protects: the per-stripe sharding actually reduces contention vs the coarse reference.

## `policy_builder_subject_only_batch` — protects the per-axis batch shortcut

Direct measurement of the optimization that `PolicyBuilder::build` enables (subject/action axes evaluated once per batch instead of once per item). Three shapes on the same input:

- **`builder_overridden / N`** — a `PolicyBuilder`-built policy whose only predicate is `.subjects(...)`. Uses the overridden `evaluate_batch` that broadcasts the subject result.
- **`manual_dynamic_serial_default / N`** — apples-to-apples comparison: a hand-written `Policy` impl with the same predicate body and the same `Cow::Owned` dynamic name, but no `evaluate_batch` override, so it falls through to the serial-loop default. Isolates the cost of the per-axis shortcut from the cost of dynamic naming.
- **`manual_static_serial_default / N`** — the floor: a hand-written `Policy` with a `'static` name. Sets the bar for what's achievable without dynamic-name allocations.

Current (`cargo bench --bench permission_checker -- policy_builder_subject_only_batch --quick`) on a Mac M-series:

| N | `builder_overridden` | `manual_dynamic_serial_default` | `manual_static_serial_default` |
|---|---:|---:|---:|
| 1   | ~486 ns   | ~558 ns   | ~483 ns  |
| 10  | ~1.65 µs  | ~2.01 µs  | ~1.33 µs |
| 25  | ~3.49 µs  | ~3.70 µs  | ~2.64 µs |
| 100 | ~11.30 µs | ~16.55 µs | ~9.69 µs |

The optimization wins 13–32% over the same shape through the serial default, growing with batch size. Static-name hand-written policies remain fastest; adopters who can use a `'static` name table should.
