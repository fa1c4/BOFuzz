"""
Paint thermodynamic heatmaps from BOFuzz per-target statistics JSON files.

Input:
    eval/statistics/*_statistics.json

Output:
    eval/results/moranI_gini_thermodynamic.{svg,pdf}
    eval/results/gini_only_thermodynamic.{svg,pdf}
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

import matplotlib
import numpy as np
from matplotlib.colors import LinearSegmentedColormap, TwoSlopeNorm

matplotlib.use("Agg")
import matplotlib.pyplot as plt


EVAL_DIR = Path(__file__).resolve().parents[1]
STATISTICS_DIR = EVAL_DIR / "statistics"
RESULTS_DIR = EVAL_DIR / "results"

TARGETS = [
    "bloaty_fuzz_target",
    "curl_curl_fuzzer_http",
    "freetype2_ftfuzzer",
    "harfbuzz_hb-shape-fuzzer",
    "lcms_cms_transform_fuzzer",
    "mbedtls_fuzz_dtlsclient",
    "openthread_ot-ip6-send-fuzzer",
    "proj4_proj_crs_to_crs_fuzzer",
    "re2_fuzzer",
    "sqlite3_ossfuzz",
    "vorbis_decode_fuzzer",
    "zlib_zlib_uncompress_fuzzer",
]

FEATURE_LABELS = [f"I{i}" for i in range(8)] + [f"S{i}" for i in range(8)]
FEATURE_INDEX = {label: idx for idx, label in enumerate(FEATURE_LABELS)}
TARGET_LABELS = [f"T{i}" for i in range(1, len(TARGETS) + 1)]


def normalize_feature_id(feature_id: str) -> str:
    """Convert feature IDs from JSON form like I00/S07 to axis labels I0/S7."""
    if len(feature_id) >= 2 and feature_id[0] in {"I", "S"}:
        try:
            return f"{feature_id[0]}{int(feature_id[1:])}"
        except ValueError:
            return feature_id
    return feature_id


def finite_abs_max(values: np.ndarray) -> float:
    finite = values[np.isfinite(values)]
    if finite.size == 0:
        return 1.0
    vmax = float(np.max(np.abs(finite)))
    return vmax if vmax > 0 else 1.0


def finite_max(values: np.ndarray) -> float:
    finite = values[np.isfinite(values)]
    if finite.size == 0:
        return 1.0
    vmax = float(np.max(finite))
    return vmax if vmax > 0 else 1.0


def iter_features(data: dict, target: str) -> Iterable[dict]:
    features = data.get("features")
    if not isinstance(features, list):
        print(f"Warning: {target} has no top-level 'features' list; row will be blank.")
        return []
    return features


def load_matrix() -> tuple[np.ndarray, np.ndarray, list[str]]:
    moran_gini = np.full((len(TARGETS), len(FEATURE_LABELS)), np.nan, dtype=float)
    gini_only = np.full_like(moran_gini, np.nan)
    warnings: list[str] = []

    for row, target in enumerate(TARGETS):
        stats_path = STATISTICS_DIR / f"{target}_statistics.json"
        if not stats_path.exists():
            warnings.append(f"missing statistics file for {target}: {stats_path}")
            continue

        with stats_path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        seen_features: set[str] = set()
        for feature in iter_features(data, target):
            label = normalize_feature_id(str(feature.get("feature_id", "")))
            col = FEATURE_INDEX.get(label)
            if col is None:
                continue

            seen_features.add(label)
            moran_i = float(feature.get("moran_i_rank_strength", 0.0))
            gini = float(feature.get("gini_strength", 0.0))
            moran_gini[row, col] = float(feature.get("acfg_rds", moran_i * gini))
            gini_only[row, col] = gini

        missing_features = sorted(set(FEATURE_LABELS) - seen_features)
        if missing_features:
            warnings.append(f"{target} missing features: {', '.join(missing_features)}")

    return moran_gini, gini_only, warnings


def configure_axes(ax: plt.Axes) -> None:
    ax.set_xticks(np.arange(len(FEATURE_LABELS)))
    ax.set_xticklabels(FEATURE_LABELS, fontsize=10)
    ax.set_yticks(np.arange(len(TARGET_LABELS)))
    ax.set_yticklabels(TARGET_LABELS, fontsize=10)
    ax.set_xlabel("Feature", fontsize=15, fontweight="bold")
    ax.set_ylabel("Target", fontsize=15, fontweight="bold")

    ax.set_xticks(np.arange(-0.5, len(FEATURE_LABELS), 1), minor=True)
    ax.set_yticks(np.arange(-0.5, len(TARGET_LABELS), 1), minor=True)
    ax.grid(which="minor", color="#ffffff", linewidth=0.8)
    ax.tick_params(which="minor", bottom=False, left=False)
    for spine in ax.spines.values():
        spine.set_visible(False)


def save_heatmap(
    values: np.ndarray,
    title: str,
    colorbar_label: str,
    stem: str,
    cmap: LinearSegmentedColormap,
    norm: TwoSlopeNorm | None = None,
) -> None:
    masked = np.ma.masked_invalid(values)
    cmap = cmap.copy()
    cmap.set_bad("#f2f2f2")

    fig, ax = plt.subplots(figsize=(11.5, 7.2))
    image = ax.imshow(masked, cmap=cmap, norm=norm, aspect="auto")
    configure_axes(ax)
    ax.set_title(title, fontsize=14, fontweight="bold", pad=12)

    cbar = fig.colorbar(image, ax=ax, fraction=0.035, pad=0.025)
    cbar.set_label(colorbar_label, fontsize=15, fontweight="bold")
    cbar.ax.tick_params(labelsize=11)

    fig.tight_layout()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    for suffix in ("svg", "pdf"):
        out_path = RESULTS_DIR / f"{stem}.{suffix}"
        fig.savefig(out_path, bbox_inches="tight")
        print(f"Saved {out_path}")
    plt.close(fig)


def main() -> None:
    if not STATISTICS_DIR.exists():
        raise SystemExit(f"Statistics directory does not exist: {STATISTICS_DIR}")

    moran_gini, gini_only, warnings = load_matrix()
    for warning in warnings:
        print(f"Warning: {warning}")

    signed_cmap = LinearSegmentedColormap.from_list(
        "grey_red_blue",
        ["#a95f63", "#eeeeee", "#5f7f9c"],
    )
    gini_cmap = LinearSegmentedColormap.from_list(
        "grey_blue",
        ["#eeeeee", "#5f7f9c"],
    )

    max_abs = finite_abs_max(moran_gini)
    save_heatmap(
        moran_gini,
        "MoranI & Gini Thermodynamic Statistics",
        "ACFG-RDS",
        "moranI_gini_thermodynamic",
        signed_cmap,
        TwoSlopeNorm(vmin=-max_abs, vcenter=0.0, vmax=max_abs),
    )

    save_heatmap(
        gini_only,
        "Gini-Only Thermodynamic Statistics",
        "Gini strength",
        "gini_only_thermodynamic",
        gini_cmap,
        None,
    )

    print(f"Gini max: {finite_max(gini_only):.6g}")


if __name__ == "__main__":
    main()
