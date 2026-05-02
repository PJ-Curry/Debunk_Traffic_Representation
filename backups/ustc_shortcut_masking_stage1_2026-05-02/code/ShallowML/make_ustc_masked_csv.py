#!/usr/bin/env python3
"""Create masked USTC-binary raw CSV variants without changing the baseline."""

from __future__ import annotations

import argparse
import csv
import re
from collections import Counter
from pathlib import Path


CSV_FILES = (
    Path("test.csv"),
    Path("train_val_split_0/train.csv"),
    Path("train_val_split_0/val.csv"),
    Path("train_val_split_1/train.csv"),
    Path("train_val_split_1/val.csv"),
    Path("train_val_split_2/train.csv"),
    Path("train_val_split_2/val.csv"),
)


def parse_mask_cols(value: str) -> list[str]:
    cols: list[str] = []
    for raw_col in value.split(","):
        col = raw_col.strip()
        if not col:
            continue
        if not col.isdigit():
            raise argparse.ArgumentTypeError(
                f"mask column must be a non-negative integer, got {raw_col!r}"
            )
        cols.append(str(int(col)))

    if not cols:
        raise argparse.ArgumentTypeError("at least one mask column is required")

    # Preserve user order while removing duplicates.
    return list(dict.fromkeys(cols))


def validate_name(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        raise argparse.ArgumentTypeError(
            "--name may only contain letters, digits, '.', '_' and '-'"
        )
    if name in {".", "..", "raw"}:
        raise argparse.ArgumentTypeError("--name must not be '.', '..' or 'raw'")
    return name


def format_counts(counts: Counter[str]) -> str:
    return ", ".join(f"{label}={counts[label]}" for label in sorted(counts))


def write_masked_csv(src: Path, dst: Path, mask_cols: list[str], mask_value: str) -> tuple[int, Counter[str]]:
    counts: Counter[str] = Counter()
    rows = 0

    dst.parent.mkdir(parents=True, exist_ok=True)

    with src.open("r", newline="") as src_file, dst.open("w", newline="") as dst_file:
        reader = csv.reader(src_file)
        writer = csv.writer(dst_file)

        header = next(reader)
        if "class" not in header:
            raise ValueError(f"{src} has no class column")

        missing = [col for col in mask_cols if col not in header]
        if missing:
            raise ValueError(f"{src} is missing mask columns: {','.join(missing)}")
        if "class" in mask_cols:
            raise ValueError("class column must not be masked")

        mask_indexes = [header.index(col) for col in mask_cols]
        class_index = header.index("class")

        writer.writerow(header)
        for row in reader:
            label = row[class_index]
            counts[label] += 1
            for index in mask_indexes:
                row[index] = mask_value
            writer.writerow(row)
            rows += 1

    return rows, counts


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create USTC-binary masked CSV variants from outputs/ustc-binary/raw."
    )
    parser.add_argument("--name", required=True, type=validate_name, help="experiment output directory name")
    parser.add_argument("--mask-cols", required=True, type=parse_mask_cols, help="comma-separated column numbers, e.g. 4,16,17")
    parser.add_argument("--mask-value", default="-1", help="value assigned to masked columns")
    args = parser.parse_args()

    shallowml_dir = Path(__file__).resolve().parent
    output_root = shallowml_dir / "outputs" / "ustc-binary"
    raw_dir = output_root / "raw"
    target_dir = output_root / args.name

    if not raw_dir.is_dir():
        raise SystemExit(f"raw input directory does not exist: {raw_dir}")
    if target_dir.exists():
        raise SystemExit(f"refusing to overwrite existing output directory: {target_dir}")

    print(f"input_dir={raw_dir}")
    print(f"output_dir={target_dir}")
    print(f"mask_cols={','.join(args.mask_cols)}")
    print(f"mask_value={args.mask_value}")
    print("file\trows\tclass_counts")

    for rel_path in CSV_FILES:
        src = raw_dir / rel_path
        dst = target_dir / rel_path
        if not src.is_file():
            raise SystemExit(f"missing input CSV: {src}")

        rows, counts = write_masked_csv(src, dst, args.mask_cols, args.mask_value)
        print(f"{rel_path.as_posix()}\t{rows}\t{format_counts(counts)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
