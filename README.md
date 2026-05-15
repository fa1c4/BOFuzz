# BOFuzz

BOFuzz (v3.0+) is a coverage-guided fuzzer with static-feature weight scheduling, based on LibAFL 0.15.0.

## Setup

Dependencies: LLVM-15+, rustc 1.89.0, cargo 1.89.0
```shell
sudo apt install rustup
# or
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustup toolchain install 1.89.0
```

## Required Schema File

BOFuzz requires a feature schema at:
```
BOFuzz/static_analysis/features_schema.json
```

This file defines the 16 canonical features (I00–I07 instruction-level, S00–S07 structural-level)
with `schema_version: 3`. The runtime will not start without it.

## Build

```shell
cd fuzzers/inprocess/bofuzz

cargo clean && cargo build --profile release-bofuzz --features no_link_main

# Build the stub runtime (provides main() and cmplog stubs)
clang -c stub_rt.c -o stub_rt.o
ar r stub_rt.a stub_rt.o
```

## Feature Schema (16 features)

| ID  | Name | Group |
|-----|------|-------|
| I00 | bb_instruction_count | instruction |
| I01 | numeric_immediate_count | instruction |
| I02 | string_literal_ref_count | instruction |
| I03 | const_data_ref_count | instruction |
| I04 | cmp_inst_count | instruction |
| I05 | arith_bitwise_count | instruction |
| I06 | mem_inst_count | instruction |
| I07 | call_count | instruction |
| S00 | cfg_in_degree | structural |
| S01 | cfg_out_degree | structural |
| S02 | static_descendant_count | structural |
| S03 | static_ancestor_count | structural |
| S04 | entry_depth | structural |
| S05 | loop_nesting_depth | structural |
| S06 | loop_boundary_flag | structural |
| S07 | centrality | structural |

S07 `centrality` has accepted alias `betweenness` (declared in schema). The old key `btw` is rejected.

## Feature Map Format

The feature map (`{target}_features_map.json`) must be a JSON dictionary keyed by canonical feature names:
```json
{
  "bb_instruction_count": [0.1, 0.2, ...],
  "numeric_immediate_count": [0.0, 0.1, ...],
  ...
  "centrality": [0.5, 0.3, ...]
}
```

Each feature array must have length equal to `sancov_sites`. Legacy 8-key maps are **not** supported.

**Failure behavior:**
- If no feature map is configured or found: falls back to cold fuzzing.
- If a feature map is present but invalid (wrong format, wrong keys, bad values, length mismatch): **fails fast** with a clear error.

## `--vec-mask`

Controls which features are active, aligned to `features_schema.json` order.

```bash
--vec-mask='1111111111111111'   # all 16 enabled
--vec-mask='1111111100000000'   # instruction-only (8 active)
--vec-mask='0000000011111111'   # structural-only (8 active)
--vec-mask='1111111111111110'   # disable centrality (15 active)
```

Mask length must equal `features_schema.json.features.len()`. All-zero mask is fatal.

## Active-Dim TPE Vector Format

Every TPE vector is `[alpha, active_weight_0, ..., active_weight_{active_dim-1}]`.
No placeholder zeros for disabled dimensions.

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

## Usage

1. Build the fuzzer (see Build section above).
2. Compile your target with the BOFuzz instrumentor (`libafl_cc`/`libafl_cxx`) to get an instrumented binary.
3. Run the static analysis script to extract `{target}_features_map.json`. Dependencies: IDA Pro.
   Place the features map in the same directory as the target binary.
4. Run:

```shell
./your_target_fuzzer \
  --features-schema BOFuzz/static_analysis/features_schema.json \
  --features-map ./your_target_features_map.json \
  --feat-mode 1 \
  --explore-time-secs 43200 \
  --tpe-period-secs 600 \
  -i /path/to/corpus \
  -o /path/to/findings
```

### Example: zlib

```shell
cd example
chmod +x zlib_uncompress_demo.sh
./zlib_uncompress_demo.sh
```

## CLI Options

| Option | Default | Description |
|---|---|---|
| `--features-schema` | auto-detected | Path to `features_schema.json` |
| `--features-map` | `{exe}_features_map.json` | Path to feature map |
| `--vec-mask` | all enabled | Feature mask (bitstring, bracketed, or comma-separated) |
| `--feat-mode` | `1` | 0=off, 1=weight scheduling, 2=power scheduling, 3=both |
| `--explore-time-secs` | `43200` | Cold start explore time in **seconds** |
| `--tpe-period-secs` | `600` | TPE iteration period in **seconds** |
| `--alpha` | `0.2` | Alpha factor parameter |
| `--beta` | `0.6` | Beta factor parameter |
| `--gmin` | `0.5` | Factor range minimum |
| `--gmax` | `3.0` | Factor range maximum |
| `--tanh` | `false` | Use tanh mapping instead of exp |

## Strict Failure Behavior

- Missing `features_schema.json` → fatal
- Schema validation failure → fatal
- `--vec-mask` length mismatch → fatal
- All-zero mask → fatal
- Feature map present but invalid → fatal
- Feature map missing → cold fuzzing fallback
- Candidate file present but wrong format → fatal
- Prior-order index out of range or duplicate → fatal
