#!/usr/bin/env python3
'''
python3 scripts/copy_features_maps.py --src-path ~/BOFuzz/benchs --dest-path /tmp/test_feature_maps
'''

import argparse
import shutil
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description="Copy *_features_map*.json and *_sancov_acfg.json from target subdirs into a flat dest dir."
    )
    parser.add_argument("--src-path", required=True, help="Directory containing per-target subdirectories")
    parser.add_argument("--dest-path", required=True, help="Flat output directory for copied files")
    args = parser.parse_args()

    src = Path(args.src_path)
    dest = Path(args.dest_path)
    dest.mkdir(parents=True, exist_ok=True)

    if not src.is_dir():
        print(f"ERROR: --src-path is not a directory: {src}")
        return 1

    patterns = ["*_features_map.json", "*_sancov_acfg.json"]
    total_copied = 0
    total_targets = 0

    for target_dir in sorted(src.iterdir()):
        if not target_dir.is_dir():
            continue

        target_name = target_dir.name
        total_targets += 1
        target_copied = 0

        for pattern in patterns:
            files = list(target_dir.glob(pattern))
            if not files:
                print(f"WARNING: {target_name}: no files matching '{pattern}'")
                continue

            for f in files:
                shutil.copy2(f, dest / f.name)
                print(f"  {f.name}")
                target_copied += 1

        if target_copied:
            print(f"  -> {target_name}: {target_copied} file(s) copied")
        total_copied += target_copied

    print(f"\nDone: {total_copied} file(s) from {total_targets} target(s) copied to {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
