# BOFuzz Inprocess Fuzzer

A singlethreaded libfuzzer-like fuzzer with static-feature weight scheduling, built on LibAFL.

## Required Schema File

BOFuzz requires a feature schema at:
```
BOFuzz/static_analysis/features_schema.json
```

The schema defines 16 canonical features (I00–I07 instruction-level, S00–S07 structural-level)
with `schema_version: 4`.

## Build

```shell
cd fuzzers/inprocess/bofuzz
cargo build --profile release-bofuzz --features no_link_main

# Build the stub runtime (provides main() and cmplog stubs for linking)
clang -c stub_rt.c -o stub_rt.o
ar r stub_rt.a stub_rt.o
```

## Feature Map Format

The feature map must be a JSON dict keyed by canonical feature names:
```json
{
  "bb_instruction_count": [...],
  "numeric_immediate_count": [...],
  ...
  "centrality": [...]
}
```

Each feature array must have length equal to `sancov_sites`. Legacy 8-key maps
(`imme`, `strc`, `mem`, `arith`, `indeg`, `offsp`, `btw`, `depth`) are **not** accepted.

## `--vec-mask`

Controls the feature coordinate space, aligned to `features_schema.json` order.

Accepted fixed-mask formats:
```bash
--vec-mask='[1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0]'
--vec-mask='1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0'
--vec-mask='1111111100000000'
```

If absent, BOFuzz uses full-schema mode. An explicit mask is immutable for the full run: Explore credits, runtime credits, and TPE vectors use only enabled dimensions, with inactive schema dimensions omitted. All-zero masks are fatal.

Adaptive mode is enabled with:
```bash
--vec-mask auto-credit --credit-top-k 8
```

Auto-credit explores with all schema features, then selects up to `--credit-top-k` strictly positive frontier-credit features at the Explore/TPE boundary. If fewer than `k` features have positive credit, only those features remain active. If no feature has positive credit, BOFuzz falls back to full-schema TPE initialized from an equal-simplex vector.

## TPE Vector Format

Every runtime TPE vector is `[active_weight_0, ..., active_weight_{active_dim-1}]`.
There are no alpha entries and no placeholder entries for disabled dimensions.
Credit-based initialization enqueues the exact normalized Explore-credit vector first, followed by random neighboring samples.

## Candidate File Format

`{target}_v_candidates.json` must contain weights-only vectors of length `active_dim`:
```json
[
  [0.125, 0.125, 0.125, 0.125, 0.125, 0.125, 0.125, 0.125]
]
```

For full-schema and explicit-mask modes, a valid candidate file keeps priority over Explore-credit initialization; the credit vector is still recorded in `runtime_data.json`. For auto-credit mode, candidate files are always ignored and are not parsed or validated.

If an explicit `--vec-mask` changes, candidate files must be regenerated.

## Runtime Data

BOFuzz writes `<output_root>/runtime_data.json` atomically. The file records mask policy, selected features, initialization source, Explore credits, post-Explore runtime credits, and TPE history with separate coordinate feature names for each vector space.

## CLI Options

| Option | Default | Description |
|---|---|---|
| `--features-schema` | `BOFuzz/static_analysis/features_schema.json` | Path to schema |
| `--features-map` | `{exe}_features_map.json` | Path to feature map |
| `--vec-mask` | all enabled | Feature mask or `auto-credit` |
| `--feat-mode` | `1` | 0=off, 1=weight, 2=power, 3=both |
| `--explore-time-secs` | `43200` | Explore time in seconds |
| `--tpe-period-secs` | `600` | TPE period in seconds |
| `--alpha` | `0.2` | Alpha parameter |
| `--beta` | `0.6` | Beta parameter |
| `--credit-top-k` | `8` | Maximum positive-credit features selected by `--vec-mask auto-credit` |

## Example

All features enabled:
```bash
./target_fuzzer \
  --features-schema BOFuzz/static_analysis/features_schema.json \
  --features-map ./target_features_map.json \
  --feat-mode 1 \
  --vec-mask='1111111111111111' \
  -i seeds -o findings
```

Instruction-only:
```bash
./target_fuzzer \
  --features-schema BOFuzz/static_analysis/features_schema.json \
  --features-map ./target_features_map.json \
  --feat-mode 1 \
  --vec-mask='1111111100000000' \
  -i seeds -o findings
```

Auto-credit:
```bash
./target_fuzzer \
  --features-schema BOFuzz/static_analysis/features_schema.json \
  --features-map ./target_features_map.json \
  --feat-mode 1 \
  --vec-mask auto-credit \
  --credit-top-k 8 \
  -i seeds -o findings
```
