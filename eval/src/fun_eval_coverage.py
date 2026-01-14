'''
script to paint the plot of funafl coverage evaluation resutls
need libs:
numpy
pandas
matplotlib
'''
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg") 
import matplotlib.pyplot as plt
from typing import Optional, List
from pathlib import Path
import math

# =========================
# Config
# =========================
figure_save_name = "fuzzer_coverage_evaluation"

colors = {
    "mopt": "#ff7f0e",
    "aflplusplus": "#2ca02c",
    "aflplusplus_406_dipri_ah": "#e377c2",
    "aflplusplus_406_dipri_vh": "#9467bd",
    "bazzafl": "#17becf",
    "libfuzzer": "#1f77b4",
    "libafl": "#8c564b",
    "libfun": "#d62728",
}

fuzzer_whitelist = ["aflplusplus", "aflplusplus_406_dipri_ah", "bazzafl", "libfuzzer", "libafl", "libfun"]
ordered_fuzzers = list(fuzzer_whitelist)

# (1) marker per fuzzer (line style统一为 '-')
markers = {
    "aflplusplus": "o",
    "aflplusplus_406_dipri_ah": "x",
    "bazzafl": "*",
    "libfuzzer": "^",
    "libafl": "s",
    "libfun": "D",
}

mapping_norm_names = {
    "fairfuzz": "FairFuzz",
    "mopt": "MOpt",
    "aflplusplus": "AFL++",
    "aflplusplus_406_dipri_ah": "DiPri",
    "aflplusplus_406_dipri_vh": "DiPri-VH",
    "aflplusplus_406_z": "DiPri-Z",
    "bazzafl": "BazzAFL",
    "funafl": "FunAFL",
    "libfuzzer": "libFuzzer",
    "libafl": "LibAFL",
    "libfun": "FunAFL",
}

benchmark_whitelist = [
    "bloaty_fuzz_target",
    "curl_curl_fuzzer_http",
    "mbedtls_fuzz_dtlsclient",
    "freetype2_ftfuzzer",
    "harfbuzz_hb-shape-fuzzer",
    "proj4_proj_crs_to_crs_fuzzer",
    "lcms_cms_transform_fuzzer",
    "openthread_ot-ip6-send-fuzzer",
    "zlib_zlib_uncompress_fuzzer",
    "re2_fuzzer",
    "sqlite3_ossfuzz",
    "vorbis_decode_fuzzer",
]

report_data_paths = [
    "../data/merged_report_data.csv"
]

MIN_X_HOURS = 0.25   # 15min
MAX_X_HOURS = 24.25  # 24h15min

# (3) sample points every 1 hour
PLOT_STEP_HOURS = 1.0
PLOT_STEP_SEC = int(PLOT_STEP_HOURS * 3600)


# =========================
# Helpers
# =========================
def calculate_fuzzer_stats(data: pd.DataFrame) -> pd.DataFrame:
    """
    Group by integer seconds 'time' to avoid float artifacts.
    Compute mean/std per timepoint across trials/datasets.
    """
    stats = (
        data.groupby("time")["edges_covered"]
        .agg(mean="mean", std="std")
        .reset_index()
        .sort_values("time")
    )
    stats["std"] = stats["std"].fillna(0.0)
    stats["time_hours"] = stats["time"] / 3600.0
    return stats


def downsample_stats_every_1h(stats: pd.DataFrame, min_hours: float, max_hours: float) -> pd.DataFrame:
    """
    Keep one point per 1h bucket.
    - Ensure the first point >= min_hours is kept (so 15min baseline still appears)
    - Then bucket by 1h grid using floor(time/3600)*3600, keep the last point in each bucket.
    """
    if stats.empty:
        return stats

    min_sec = int(round(min_hours * 3600))
    max_sec = int(round(max_hours * 3600))

    s = stats[(stats["time"] >= min_sec) & (stats["time"] <= max_sec)].copy()
    if s.empty:
        return s

    # first point >= min_sec
    times = s["time"].to_numpy()
    first_pos = np.searchsorted(times, min_sec, side="left")
    first_row = s.iloc[[first_pos]] if first_pos < len(s) else s.iloc[[0]]

    # bucket by 1h
    s["bucket"] = (s["time"] // PLOT_STEP_SEC) * PLOT_STEP_SEC
    ds = s.sort_values("time").groupby("bucket", as_index=False).tail(1)

    out = (
        pd.concat([first_row, ds], ignore_index=True)
        .drop_duplicates(subset=["time"])
        .sort_values("time")
    )
    out["time_hours"] = out["time"] / 3600.0
    return out


def baseline_y_at_15min(target_df: pd.DataFrame, fuzzers: List[str], t0_hours: float = MIN_X_HOURS) -> float:
    vals = []
    t0_sec = int(round(t0_hours * 3600))
    for f in fuzzers:
        fdf = target_df[target_df["fuzzer"] == f]
        if fdf.empty:
            continue
        stats = calculate_fuzzer_stats(fdf)
        times = stats["time"].to_numpy()
        pos = np.searchsorted(times, t0_sec, side="left")
        if pos < len(times):
            vals.append(float(stats["mean"].iloc[pos]))
    return float(np.nanmin(vals)) if vals else 0.0


# =========================
# Load + merge
# =========================
dataframes = []
successful_loads = 0
failed_loads = 0

print("Loading CSV files...")
for i, path in enumerate(report_data_paths):
    try:
        temp_df = pd.read_csv(path)
        temp_df["data_source"] = f"dataset_{i+1}"
        temp_df["source_path"] = path
        dataframes.append(temp_df)
        successful_loads += 1
        print(f"✓ Loaded {path} - Shape: {temp_df.shape}")
    except Exception as e:
        failed_loads += 1
        print(f"✗ Failed to load {path}: {e}")

if not dataframes:
    raise SystemExit("No CSV files could be loaded!")

df = pd.concat(dataframes, ignore_index=True)

required_cols = {"fuzzer", "benchmark", "time", "edges_covered"}
missing = required_cols - set(df.columns)
if missing:
    raise SystemExit(f"Missing required columns in input CSV(s): {sorted(missing)}")

df_filtered = df[df["fuzzer"].isin(fuzzer_whitelist)].copy()
if df_filtered.empty:
    raise SystemExit("No data found for the specified fuzzers!")

df_filtered = df_filtered[df_filtered["benchmark"].isin(benchmark_whitelist)].copy()
if df_filtered.empty:
    raise SystemExit("No data found for the specified benchmarks!")

targets = sorted(df_filtered["benchmark"].unique())
print(f"Targets to plot: {targets}")

# =========================
# Plot
# =========================
n_targets = len(targets)
n_cols = 4
n_rows = (n_targets + n_cols - 1) // n_cols

fig, axes = plt.subplots(n_rows, n_cols, figsize=(16, 4 * n_rows))
if n_rows == 1:
    axes = axes.reshape(1, -1)

for idx, target in enumerate(targets):
    row = idx // n_cols
    col = idx % n_cols
    ax = axes[row, col]

    target_data = df_filtered[df_filtered["benchmark"] == target]
    if target_data.empty:
        ax.set_title(f"({chr(97+idx)}) {target}", fontsize=14, fontweight="bold")
        ax.text(0.5, 0.5, "No data available", transform=ax.transAxes,
                ha="center", va="center", fontsize=14)
        continue

    for fuzzer in ordered_fuzzers:
        fuzzer_data = target_data[target_data["fuzzer"] == fuzzer]
        if fuzzer_data.empty:
            continue

        stats = calculate_fuzzer_stats(fuzzer_data)
        stats_ds = downsample_stats_every_1h(stats, MIN_X_HOURS, MAX_X_HOURS)
        if stats_ds.empty:
            continue

        mk = markers.get(fuzzer, "o")
        ax.plot(
            stats_ds["time_hours"],
            stats_ds["mean"],
            color=colors.get(fuzzer, "black"),
            linestyle="-",
            marker=mk,
            label=mapping_norm_names.get(fuzzer, fuzzer),
            markersize=4,
            linewidth=1.5
        )

        ax.fill_between(
            stats_ds["time_hours"],
            stats_ds["mean"] - stats_ds["std"],
            stats_ds["mean"] + stats_ds["std"],
            color=colors.get(fuzzer, "black"),
            alpha=0.2
        )

    ax.set_title(f"({chr(97+idx)}) {target}", fontsize=14, fontweight="bold")

    if row == n_rows - 1:
        ax.set_xlabel("Time (hours)", fontsize=14)
    if col == 0:
        ax.set_ylabel("Edges Covered", fontsize=14)

    ax.grid(True, alpha=0.3)
    ax.set_xlim(MIN_X_HOURS, MAX_X_HOURS)

    # x ticks: mark every 4 hours (reduce density)
    start_tick = int(math.ceil(MIN_X_HOURS))          # e.g. 0.25 -> 1
    end_tick = int(math.floor(MAX_X_HOURS))           # e.g. 24.25 -> 24

    first_4h = int(math.ceil(start_tick / 4.0) * 4)

    ticks = np.arange(first_4h, end_tick + 1, 4)

    # ticks = np.unique(np.concatenate(([start_tick], ticks)))

    if len(ticks) == 0 or ticks[-1] != end_tick:
        ticks = np.unique(np.append(ticks, end_tick))

    ax.set_xticks(ticks)
    ax.set_xticklabels([str(int(t)) for t in ticks])

    # y-limits: bottom=min(mean@15min); top=max visible (>=15min)
    y_bottom = baseline_y_at_15min(target_data, ordered_fuzzers, MIN_X_HOURS)
    visible = target_data[(target_data["time"] >= int(round(MIN_X_HOURS * 3600))) &
                          (target_data["time"] <= int(round(MAX_X_HOURS * 3600)))]
    if not visible.empty:
        y_top = float(visible["edges_covered"].max())
        if y_top <= y_bottom:
            ax.set_ylim(bottom=y_bottom)
        else:
            ax.set_ylim(y_bottom, y_top * 1.02)
    else:
        ax.set_ylim(bottom=max(0.0, y_bottom))

# Hide unused subplots
for idx in range(n_targets, n_rows * n_cols):
    r = idx // n_cols
    c = idx % n_cols
    axes[r, c].set_visible(False)

# Figure-level legend (top)
handles, labels = None, None
for idx in range(n_targets):
    r = idx // n_cols
    c = idx % n_cols
    h, l = axes[r, c].get_legend_handles_labels()
    if h:
        handles, labels = h, l
        break

if handles:
    fig.legend(
        handles,
        labels,
        loc="upper center",
        bbox_to_anchor=(0.5, 0.985),
        ncol=len(ordered_fuzzers),
        fontsize=20,
        frameon=False,
        markerscale=2,
    )

# Leave a small space for legend (not too large)
plt.tight_layout(rect=[0, 0, 1, 0.94])

# =========================
# Save (pdf/svg only)
# =========================
out_dir = Path("../results")
out_dir.mkdir(parents=True, exist_ok=True)

pdf_path = out_dir / f"{figure_save_name}.pdf"
svg_path = out_dir / f"{figure_save_name}.svg"

plt.savefig(pdf_path, dpi=800, bbox_inches="tight", pad_inches=0.1, format="pdf",
            facecolor="white", edgecolor="none")
plt.savefig(svg_path, bbox_inches="tight", pad_inches=0.1, format="svg",
            facecolor="white", edgecolor="none")

print(f"Figure saved to:\n  {pdf_path}\n  {svg_path}")

print("Figure generated successfully!")
