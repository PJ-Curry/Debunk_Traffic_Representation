#!/usr/bin/env python3
"""Summarize USTC-binary AutoGluon leaderboard CSV files."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import scipy.stats as stats


NUM_SPLITS = 3
MODELS = ["RandomForestGini", "XGBoost", "LightGBM", "NeuralNetTorch"]
METRICS = ["score_test", "f1_macro", "f1_micro", "pred_time_test"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Summarize three USTC-binary AutoGluon leaderboard CSV files."
    )
    parser.add_argument("--name", required=True, help="Experiment name, for example mask_col4.")
    return parser.parse_args()


def ci95(values: list[float]) -> tuple[float, float]:
    data = np.asarray(values, dtype=float)
    mean = float(np.mean(data))
    if len(data) < 2:
        return mean, 0.0
    sem = stats.sem(data)
    interval = stats.t.interval(0.95, len(data) - 1, loc=mean, scale=sem)
    return mean, float((interval[1] - interval[0]) / 2)


def find_result_files(result_dir: Path, name: str) -> list[Path]:
    named_files = [result_dir / f"{name}_{split_id}.csv" for split_id in range(NUM_SPLITS)]
    if all(path.is_file() for path in named_files):
        return named_files

    raw_files = [result_dir / f"ustc-binary_{split_id}.csv" for split_id in range(NUM_SPLITS)]
    if name == "raw" and all(path.is_file() for path in raw_files):
        return raw_files

    missing = [path for path in named_files if not path.is_file()]
    if name == "raw":
        missing.extend(path for path in raw_files if not path.is_file())
    missing_text = "\n".join(f"- {path}" for path in missing)
    raise FileNotFoundError(f"Missing expected result CSV files:\n{missing_text}")


def summarize(name: str) -> pd.DataFrame:
    script_dir = Path(__file__).resolve().parent
    result_root = script_dir / "results" / "ustc-binary"
    result_dir = result_root / name
    resolved_result_dir = result_dir.resolve()
    resolved_result_root = result_root.resolve()
    if (
        resolved_result_dir != resolved_result_root
        and resolved_result_root not in resolved_result_dir.parents
    ):
        raise ValueError(f"Refusing to read outside {resolved_result_root}: {resolved_result_dir}")

    files = find_result_files(result_dir, name)
    rows = []

    for model in MODELS:
        values = {metric: [] for metric in METRICS}
        for path in files:
            df = pd.read_csv(path)
            model_rows = df[df["model"] == model]
            if model_rows.empty:
                raise ValueError(f"Model {model} not found in {path}")
            row = model_rows.iloc[0]
            for metric in METRICS:
                values[metric].append(float(row[metric]))

        for metric in METRICS:
            mean, margin = ci95(values[metric])
            rows.append(
                {
                    "experiment": name,
                    "model": model,
                    "metric": metric,
                    "mean": mean,
                    "ci95": margin,
                    "formatted": f"{mean:.6f} ± {margin:.6f}",
                }
            )

    return pd.DataFrame(rows)


def main() -> int:
    args = parse_args()
    try:
        summary = summarize(args.name)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(summary.to_string(index=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
