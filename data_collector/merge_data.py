#!/usr/bin/env python3
"""
Merge normal and attack CSV datasets into a single labeled dataset.

Usage:
    python3 merge_data.py --output-dir collected_data
    python3 merge_data.py --normal normal.csv --attack attack.csv -o merged.csv
"""

import argparse
import csv
import glob
import os
import sys
from datetime import datetime


def find_csvs(directory, label):
    """Find CSV files matching a label pattern in the given directory."""
    pattern = os.path.join(directory, f"syscalls_{label}_*.csv")
    files = sorted(glob.glob(pattern))
    return files


def merge(normal_files, attack_files, output_path):
    """Merge CSV files, enforcing correct labels."""
    total_normal = 0
    total_attack = 0
    headers = None

    with open(output_path, "w", newline="") as out_f:
        writer = csv.writer(out_f)

        # Process normal files (force label=0)
        for fpath in normal_files:
            print(f"  Reading (normal): {fpath}")
            with open(fpath, "r") as f:
                reader = csv.reader(f)
                file_headers = next(reader)
                if headers is None:
                    headers = file_headers
                    label_idx = headers.index("label")
                    writer.writerow(headers)
                for row in reader:
                    row[label_idx] = "0"
                    writer.writerow(row)
                    total_normal += 1

        # Process attack files (force label=1)
        for fpath in attack_files:
            print(f"  Reading (attack): {fpath}")
            with open(fpath, "r") as f:
                reader = csv.reader(f)
                next(reader)  # skip header
                for row in reader:
                    row[label_idx] = "1"
                    writer.writerow(row)
                    total_attack += 1

    print(f"\n  Merged dataset written to: {output_path}")
    print(f"  Normal events: {total_normal}")
    print(f"  Attack events: {total_attack}")
    print(f"  Total events:  {total_normal + total_attack}")
    print(f"  Attack ratio:  {total_attack / max(total_normal + total_attack, 1) * 100:.1f}%")


def main():
    parser = argparse.ArgumentParser(description="Merge normal + attack CSVs")
    parser.add_argument("--output-dir", default="collected_data",
                        help="Directory containing collected CSVs")
    parser.add_argument("--normal", nargs="*",
                        help="Specific normal CSV file(s)")
    parser.add_argument("--attack", nargs="*",
                        help="Specific attack CSV file(s)")
    parser.add_argument("-o", "--output", default=None,
                        help="Output merged CSV path")
    args = parser.parse_args()

    # Find files
    if args.normal:
        normal_files = args.normal
    else:
        normal_files = find_csvs(args.output_dir, "normal")

    if args.attack:
        attack_files = args.attack
    else:
        attack_files = find_csvs(args.output_dir, "attack")

    if not normal_files and not attack_files:
        print("[ERROR] No CSV files found. Run collector.py first.")
        sys.exit(1)

    print("=" * 55)
    print("  Dataset Merger")
    print("=" * 55)
    print(f"  Normal files: {len(normal_files)}")
    print(f"  Attack files: {len(attack_files)}")
    print()

    # Output path
    if args.output:
        out_path = args.output
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = os.path.join(args.output_dir, f"merged_dataset_{ts}.csv")

    merge(normal_files, attack_files, out_path)

    print()
    print("  Ready for ML pipeline (Part 2).")
    print("=" * 55)


if __name__ == "__main__":
    main()
