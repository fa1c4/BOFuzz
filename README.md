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
with `schema_version: 4`. The runtime will not start without it.

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

Controls the feature coordinate space, aligned to `features_schema.json` order.

```bash
--vec-mask='1111111111111111'   # all 16 enabled
--vec-mask='1111111100000000'   # instruction-only (8 active)
--vec-mask='0000000011111111'   # structural-only (8 active)
--vec-mask='1111111111111110'   # disable centrality (15 active)
--vec-mask auto-credit --credit-top-k 8
```

Mask length must equal `features_schema.json.features.len()`. All-zero masks are fatal. Explicit masks are immutable for the full run, and inactive dimensions are omitted from Explore credits, runtime credits, and TPE vectors.

Auto-credit explores with the full schema, selects at most `--credit-top-k` strictly positive frontier-credit features before the first TPE vector, and freezes that selected mask. If fewer than `k` features have positive credit, only those positive features are selected. If all credits are zero, BOFuzz falls back to full schema with an equal-simplex initialization.

## Active-Dim TPE Vector Format

Every TPE vector is `[active_weight_0, ..., active_weight_{active_dim-1}]`.
No alpha entries and no placeholder zeros for disabled dimensions. Credit-based initialization enqueues the exact normalized Explore-credit vector first, then random neighboring samples.

## Candidate File Format

`{target}_v_candidates.json` must contain weights-only vectors of length `active_dim`:
```json
[
  [0.125, 0.125, 0.125, 0.125, 0.125, 0.125, 0.125, 0.125]
]
```
For full-schema and explicit-mask modes, a valid candidate file keeps priority over Explore-credit initialization. For auto-credit mode, candidate files are always ignored and are not parsed or validated. If an explicit `--vec-mask` changes, candidate files must be regenerated.

## Runtime Data

BOFuzz writes `<output_root>/runtime_data.json` atomically. It records mask policy, selected features, initialization source, Explore credits, post-Explore runtime credits, and TPE history with coordinate feature names kept separate for each vector space.

## Usage

1. Build the fuzzer (see Build section above).
2. Compile your target with the BOFuzz instrumentor (`libafl_cc`/`libafl_cxx`) to get an instrumented binary.
3. Run the static analysis script to extract the feature artifacts (see [Static Feature Extraction](#static-feature-extraction)).
   Place the artifacts in the same directory as the target binary.
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

The demo rebuilds the latest BOFuzz engine, clones zlib, compiles the fuzzer,
runs `static_analysis/features_extractor.py` with IDA/IDALIB from
`IDA_DIR` (default `~/ida-pro-9.3`), then fuzzes with `--vec-mask auto-credit`,
10 minutes of Explore, and a 5-minute TPE period.

## Static Feature Extraction

`static_analysis/features_extractor.py` builds the target-only ACFG, computes
ACFG-RDS feature statistics, partitions the ACFG into directed-successor
Voronoi regions around sancov sites, and emits the sancov-aligned runtime
feature map.

**Prerequisites**

- IDA Pro 9.x with IDALIB enabled (run `py-activate-idalib.py` once to install
  the PyPI `idapro` shim).
- Pure Python stdlib only — no `numpy` / `scipy` / `networkx` / `pandas`.

### Run on a single bench target

The extractor writes outputs into `dirname(--input-file)` by default, so omit
`--output-dir` if you want the artifacts to land next to the binary.

```shell
# Outputs land in benchs/lcms/ alongside cms_transform_fuzzer
python3 static_analysis/features_extractor.py \
    --idapro --ida-dir /path/to/ida-pro-9.3 \
    --input-file benchs/lcms/cms_transform_fuzzer
```

Pass an explicit `--output-dir` to redirect artifacts elsewhere:

```shell
python3 static_analysis/features_extractor.py \
    --idapro --ida-dir /path/to/ida-pro-9.3 \
    --input-file benchs/lcms/cms_transform_fuzzer \
    --output-dir /tmp/cms_features
```

### Run on every bench target

The benchs/ canonical targets (one per directory) are:

```
benchs/bloaty/fuzz_target
benchs/curl/curl_fuzzer_http
benchs/freetype2/ftfuzzer
benchs/harfbuzz/hb-shape-fuzzer
benchs/lcms/cms_transform_fuzzer
benchs/libpng/libpng_read_fuzzer
benchs/libxml2/xml
benchs/mbedtls/fuzz_dtlsclient
benchs/openssl/x509
benchs/openthread/ot-ip6-send-fuzzer
benchs/proj4/proj_crs_to_crs_fuzzer
benchs/re2/fuzzer
benchs/vorbis/decode_fuzzer
benchs/zlib/zlib_uncompress_fuzzer
```

The following loop extracts features for all of them, storing each target's
outputs in its own `benchs/<bench>/` directory (i.e. next to the binary):

```shell
declare -A TARGETS=(
    [bloaty]=fuzz_target
    [curl]=curl_fuzzer_http
    [freetype2]=ftfuzzer
    [harfbuzz]=hb-shape-fuzzer
    [lcms]=cms_transform_fuzzer
    [libpng]=libpng_read_fuzzer
    [libxml2]=xml
    [mbedtls]=fuzz_dtlsclient
    [openssl]=x509
    [openthread]=ot-ip6-send-fuzzer
    [proj4]=proj_crs_to_crs_fuzzer
    [re2]=fuzzer
    [vorbis]=decode_fuzzer
    [zlib]=zlib_uncompress_fuzzer
)

for bench in "${!TARGETS[@]}"; do
    tgt="${TARGETS[$bench]}"
    bin="benchs/${bench}/${tgt}"
    [ -f "$bin" ] || { echo "SKIP $bin"; continue; }

    echo "=== Extracting $bench/$tgt ==="
    python3 static_analysis/features_extractor.py \
        --idapro --ida-dir /path/to/ida-pro-9.3 \
        --input-file "$bin"
done
```

### Artifacts produced per target

For target `<base>` (e.g. `cms_transform_fuzzer`) the extractor writes to the
binary's directory:

| File | Purpose |
|---|---|
| `<base>_features_map.json` | **Runtime input.** 16-key map; each value is an array of length `sancov_sites` (directed-successor Voronoi weighted-mean of normalized features, γ=0.5) |
| `<base>_features_map_<name>.json` | Per-feature copy of the above (one file per `name` in `ATTR_NAMES`) |
| `<base>_features_map_default.json` | Per-sancov `directional_weight` over the aggregated 16-D vector |
| `<base>_features_map.debug.json` | Per-sancov debug record with seed-node, Voronoi region size, aggregated norm vector |
| `<base>_acfg.json` | Full target-only ACFG: stable node indexes, raw/norm attrs, directed edges |
| `<base>_acfg_voronoi.json` | Per-region listing: seed PC, seed node, region nodes, max/mean distance, unassigned counts |
| `<base>_statistics.json` | Per-feature ACFG-RDS = MoranI(rank(z)) · Gini(z); ranking by `abs(acfg_rds)` and `gini_strength`; three ablation selection views (`top6_abs_acfg_rds`, `top6_gini`, `random6`) plus legacy `top4`; runtime aggregation metadata |
| `<base>_acfg_rds_top4_vec_mask.txt` | 16-char `0/1` mask of the four top-clustered features (largest `abs(acfg_rds)`) |
| `<base>_top6_abs_acfg_rds_vec_mask.txt` | 16-char mask: top 6 by `abs(acfg_rds)` (ACFG-RDS ablation baseline) |
| `<base>_top6_gini_vec_mask.txt` | 16-char mask: top 6 by `gini_strength` only (Gini-only ablation view) |
| `<base>_random6_vec_mask.txt` | 16-char mask: deterministic uniform random 6 from all schema features (seeded by `--random-feature-seed`, default `0xfa1c4`) |
| `<base>_acfg_feature_ranking.txt` | Human-readable per-feature ranking table with both `rank_abs` and `rank_gini` columns |
| `<base>_features_schema.json` | Target-side schema with execution metadata |
| `features_schema.json` | Canonical runtime schema (same content as `static_analysis/features_schema.json`) |

The runtime fuzzer only needs `<base>_features_map.json` + `features_schema.json`;
the rest support feature-ranking analysis and reproducibility.

### Key extractor flags

| Flag | Default | Purpose |
|---|---|---|
| `--idapro` | off | Use PyPI `idapro` / IDALIB instead of running inside IDA |
| `--ida-dir` | `$IDADIR` | IDA install directory (sets `IDADIR` before `import idapro`) |
| `--input-file` | required for `--idapro` | Path to the target binary |
| `--output-dir` | `dirname(--input-file)` | Where to write artifacts |
| `--feature-mode` | `both` | `both` / `semantic` / `graph` — which feature groups to keep before normalization |
| `--acfg-edge-mode` | `directed` | Moran's I adjacency: `directed` (w_uv=1, w_vu=0) or `undirected` (symmetrized) |
| `--acfg-stats-eps` | `1e-8` | Near-zero strength threshold for `z = |x|` |
| `--acfg-stats-signal` | `norm` | Statistics signal source: `norm` (z-scored) or `raw` |
| `--random-feature-seed` | `0xfa1c4` | Base seed for the deterministic `random6` feature baseline; accepts decimal or `0x`-prefixed hex |
| `--sancov-agg-mode` | `voronoi-weighted-mean` | Runtime aggregation; `none` falls back to direct seed values (ablation only) |
| `--sancov-voronoi-distance` | `directed-successor` | Graph distance for Voronoi assignment |
| `--sancov-voronoi-gamma` | `0.5` | Distance decay γ for weighted mean |
| `--no-acfg-stats` | off | Skip `<base>_statistics.json` and top-k masks |
| `--self-test-acfg-stats` | off | Run pure-Python self-tests for MoranI / Gini / Voronoi and exit (no IDA required) |

### Sanity check without IDA

```shell
python3 static_analysis/features_extractor.py --self-test-acfg-stats
```

Validates Gini / Moran's I sign on directed clustered vs. alternating chains,
directed-successor Voronoi partition + tie-break + unassigned blocks,
duplicate-seed fatal path, weighted-mean closed-form (γ=0.5 ⇒
`(1·10 + ½·20) / 1.5 = 13.333…`), and the full 4-node feature pipeline.
Exits 0 on success.

## CLI Options

| Option | Default | Description |
|---|---|---|
| `--features-schema` | auto-detected | Path to `features_schema.json` |
| `--features-map` | `{exe}_features_map.json` | Path to feature map |
| `--vec-mask` | all enabled | Feature mask (bitstring, bracketed, comma-separated) or `auto-credit` |
| `--feat-mode` | `1` | 0=off, 1=weight scheduling, 2=power scheduling, 3=both |
| `--explore-time-secs` | `43200` | Cold start explore time in **seconds** |
| `--tpe-period-secs` | `600` | TPE iteration period in **seconds** |
| `--alpha` | `0.2` | Alpha factor parameter |
| `--beta` | `0.6` | Beta factor parameter |
| `--gmin` | `0.5` | Factor range minimum |
| `--gmax` | `3.0` | Factor range maximum |
| `--tanh` | `false` | Use tanh mapping instead of exp |
| `--credit-top-k` | `8` | Maximum positive-credit features selected by `--vec-mask auto-credit` |

## Strict Failure Behavior

- Missing `features_schema.json` → fatal
- Schema validation failure → fatal
- `--vec-mask` length mismatch → fatal
- All-zero mask → fatal
- Feature map present but invalid → fatal
- Feature map missing → cold fuzzing fallback
- Candidate file present but wrong format → fatal in full/explicit modes; ignored in auto-credit mode
- Prior-order index out of range or duplicate → fatal
