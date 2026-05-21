# BOFuzz Inprocess Fuzzer

A singlethreaded libfuzzer-like fuzzer with static-feature weight scheduling, built on LibAFL.

## Required Schema File

BOFuzz requires a feature schema at:
```
BOFuzz/static_analysis/features_schema.json
```

The schema defines 16 canonical features (I00–I07 instruction-level, S00–S07 structural-level)
with `schema_version: 3`.

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

Controls which features are active. Aligned to `features_schema.json` order.

Accepted formats:
```bash
--vec-mask='[1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0]'
--vec-mask='1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0'
--vec-mask='1111111100000000'
```

If absent, all features are enabled. All-zero mask is fatal.

## TPE Vector Format

Every runtime TPE vector is `[alpha, active_weight_0, ..., active_weight_{active_dim-1}]`.
There are no placeholder entries for disabled dimensions.

## Candidate File Format

`{target}_v_candidates.json` must contain vectors of length `1 + active_dim`:
```json
[
  [0.5, 0.354, 0.354, 0.354, 0.354, 0.354, 0.354, 0.354, 0.354]
]
```

If `--vec-mask` changes, candidate files must be regenerated.

## Default Candidate Order

BOFuzz no longer accepts user prior-order files. Default candidate order is
deterministic: uniform first, then one-hot candidates in active schema order.

## CLI Options

| Option | Default | Description |
|---|---|---|
| `--features-schema` | `BOFuzz/static_analysis/features_schema.json` | Path to schema |
| `--features-map` | `{exe}_features_map.json` | Path to feature map |
| `--vec-mask` | all enabled | Feature mask |
| `--feat-mode` | `1` | 0=off, 1=weight, 2=power, 3=both |
| `--explore-time-secs` | `43200` | Explore time in seconds |
| `--tpe-period-secs` | `600` | TPE period in seconds |
| `--alpha` | `0.2` | Alpha parameter |
| `--beta` | `0.6` | Beta parameter |

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
