# Benchmarks

Criterion benches live in `benches/permission_checker.rs`. Run the full suite with `cargo bench`, or one group with `cargo bench --bench permission_checker -- <group_name>`. Use `--quick` for a fast smoke check that skips Criterion's full statistical analysis.

Each benchmark measures a property of the public API. The catalogue below describes the intended scaling behavior so contributors can interpret changes in measured timings. A successful smoke run establishes that the workload executes, not that its performance is unchanged.

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

The expected gap between `naive_per_item_sessions` and `checker_batch_one_session` widens with `N` (the naive shape grows linearly with the per-call overhead; the batched shape grows mostly with the source's `load_many` work). Compare that gap in measured runs; the CI smoke check does not assert it.

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
| 1   | ~484 ns   | ~476 ns   | ~406 ns  |
| 10  | ~1.46 µs  | ~1.65 µs  | ~1.18 µs |
| 25  | ~2.85 µs  | ~3.45 µs  | ~2.35 µs |
| 100 | ~10.31 µs | ~13.07 µs | ~8.30 µs |

At batch size 1 the shortcut and the serial default are a wash — there is nothing to amortize across a single item. From N=10 the shortcut pulls ahead, winning ~11–21% over the same shape through the serial default and growing with batch size. Static-name hand-written policies remain fastest; adopters who can use a `'static` name table should.

## `recording`

`benches/recording.rs` measures successful and failed fact loads through the raw session, recording contexts, and the checker. Cache-hit cases reuse a warmed session; batch cases create a fresh session and evaluate 100, 1,000, or 10,000 distinct resources. The recorded batch policy overrides `evaluate_batch` and uses `facts_by`, so these measurements include provenance construction and per-item decision traces without introducing per-item source calls.

Compare builds with and without instrumentation using:

```bash
cargo bench --bench recording -- --save-baseline tracing
cargo bench --bench recording --no-default-features -- --save-baseline disabled
```

The tracing build measures no subscriber and a registry-only subscriber. The latter tracks spans but performs no event formatting or I/O; it is not an estimate of production logging cost. Returned provenance remains enabled in both builds.

CI runs benchmarks as smoke tests only. It does not compare timing baselines or enforce performance thresholds. Use Criterion measurements on a quiet, consistent host to assess regressions; use deterministic source-call-count contract tests to enforce batching behavior.

### Pre-typed recording measurements

Measured 2026-09-05 on Linux x86_64, Ryzen 9 5900X, Rust 1.95.0, upstream `878b4df` plus the optional-tracing change. Each run used 20 samples, 1 second warm-up, and 1 second measurement (`--sample-size 20 --measurement-time 1 --warm-up-time 1`). Other development builds were active on this host, so these wide confidence intervals are an exploratory baseline, not evidence of a tracing speedup or a release regression threshold. Rerun on an idle host before drawing performance conclusions.

Criterion's reported time intervals:

| Workload | Tracing, no subscriber | Tracing disabled |
|---|---:|---:|
| Raw cached fact, found | 255–288 ns | 273–344 ns |
| Recorded cached fact, found | 530–886 ns | 417–550 ns |
| Recorded cached fact, error | 673–1,004 ns | 403–548 ns |
| Checker cached fact, found | 1.49–2.07 µs | 0.84–0.94 µs |
| Batch 1,000, found | 0.96–1.49 ms | 0.54–0.73 ms |
| Batch 10,000, found | 50.8–67.1 ms | 15.4–19.2 ms |
| Batch 10,000, error | 21.7–29.8 ms | 11.8–14.8 ms |

The registry-only subscriber measured 1.37–1.45 µs for a cached successful checker evaluation and 1.59–1.72 µs for a cached failure. These overlap or undercut no-subscriber measurements in this noisy run, reinforcing that these are not controlled subscriber-overhead comparisons. Large-batch scaling deserves a dedicated quiet-host profile; timings here do not establish linear scaling.


## Typed scalar evaluation baseline

Measured 2026-09-05 on the same Linux/Ryzen 9 5900X host using Rust 1.95.0, default tracing enabled, no subscriber, 30 samples, 1 second warm-up, and 2 seconds measurement. The original is upstream `878b4df`; the revised implementation uses separate typed grant/veto phases and a scalar evaluation path. The original was rerun immediately after the scalar measurement to check for host-load drift. These are Criterion time intervals, not CI thresholds.

| Single check, trailing grant | Original repeated baseline | Typed scalar evaluator |
|---|---:|---:|
| 1 policy | 445–545 ns | 414–434 ns |
| 4 policies | 1.089–1.289 µs | 824–865 ns |
| 16 policies | 3.511–4.204 µs | 2.764–2.858 µs |
| 64 policies | 14.598–17.624 µs | 10.331–11.432 µs |

One-policy all-deny intervals overlap: original 387–440 ns, typed scalar 417–440 ns. An earlier version routed scalar calls through batch vectors and measured 1.385–1.499 µs for a one-policy grant. That regression is removed. Changing host load still prevents a strong speedup claim.

A separate allocation counter used a warmed current-thread runtime/session, static policy names, and a single resource with a trailing grant. The returned evaluation stayed alive until counters were read. Counts include allocation and reallocation requests; requested bytes measure total allocation traffic, not peak live memory.

| Policy count | Original requests / bytes | Typed scalar requests / bytes |
|---|---:|---:|
| 1 | 6 / 226 | 7 / 247 |
| 4 | 21 / 958 | 22 / 979 |
| 16 | 81 / 3,886 | 82 / 3,907 |
| 64 | 321 / 15,598 | 322 / 15,619 |

The final scalar path adds one allocation request and 21 requested bytes at these sizes; the discarded vector-based scalar path required 21 requests and 1,289 bytes for one policy. No wall-clock threshold is enforced by CI.
