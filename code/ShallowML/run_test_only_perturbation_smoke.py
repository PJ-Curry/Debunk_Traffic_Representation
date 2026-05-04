#!/usr/bin/env python3
"""Run a lightweight test-only perturbation smoke for USTC-binary ShallowML."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Iterable

try:
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import accuracy_score, f1_score
except ImportError as exc:  # pragma: no cover - environment guard.
    raise SystemExit(
        "Missing pandas/numpy/sklearn. Run with the ShallowML environment, for example:\n"
        "  conda run -n shallowml python code/ShallowML/run_test_only_perturbation_smoke.py"
    ) from exc

from ustc_field_mask_utils import (
    default_group_config_path,
    default_raw_csv_root,
    feature_columns_from_header,
    groups_by_name,
    infer_encoded_zero_value,
    load_group_config,
    resolve_group_columns,
    shallowml_dir,
)


DEFAULT_GROUPS = [
    "ip_ttl_protocol",
    "tcp_flags_window",
    "tcp_options",
    "current_mask_top_shortcut_columns",
    "random_same_size",
]
DEFAULT_MODES = ["zero", "permute"]


def stratified_sample(frame: pd.DataFrame, max_rows: int, seed: int) -> pd.DataFrame:
    if len(frame) <= max_rows:
        return frame.reset_index(drop=True)
    label = "class"
    pieces = []
    counts = frame[label].value_counts()
    per_class = {klass: max(1, int(max_rows * count / len(frame))) for klass, count in counts.items()}
    while sum(per_class.values()) > max_rows:
        largest = max(per_class, key=per_class.get)
        per_class[largest] -= 1
    remainders = sorted(
        counts.index,
        key=lambda klass: (max_rows * counts[klass] / len(frame)) - int(max_rows * counts[klass] / len(frame)),
        reverse=True,
    )
    while sum(per_class.values()) < max_rows:
        changed = False
        for klass in remainders:
            if per_class[klass] < counts[klass]:
                per_class[klass] += 1
                changed = True
                break
        if not changed:
            break
    for klass, count in counts.items():
        pieces.append(frame[frame[label] == klass].sample(n=min(per_class[klass], count), random_state=seed))
    sampled = pd.concat(pieces, ignore_index=True)
    if len(sampled) > max_rows:
        sampled = sampled.sample(n=max_rows, random_state=seed)
    return sampled.sample(frac=1.0, random_state=seed).reset_index(drop=True)


def perturb(frame: pd.DataFrame, columns: list[str], mode: str, encoded_zero_value: str, seed: int) -> pd.DataFrame:
    output = frame.copy()
    rng = np.random.default_rng(seed)
    if mode == "zero":
        output.loc[:, columns] = int(encoded_zero_value)
    elif mode == "permute":
        for col in columns:
            values = output[col].to_numpy(copy=True)
            rng.shuffle(values)
            output[col] = values
    else:
        raise ValueError(f"unsupported perturb mode: {mode}")
    return output


def write_report(output_md: Path, results: pd.DataFrame, args: argparse.Namespace, top_row: dict[str, object] | None) -> None:
    lines = [
        "# Test-only Perturbation Smoke",
        "",
        "生成日期：2026-05-04",
        "",
        "## 1. 设置",
        "",
        f"- split：`{args.split_id}`",
        f"- train sample：`{args.max_train}`",
        f"- test sample：`{args.max_test}`",
        f"- 模型：RandomForest(n_estimators={args.n_estimators}, max_depth={args.max_depth})",
        f"- groups：`{','.join(args.groups)}`",
        f"- perturb modes：`{','.join(args.modes)}`",
        "- 未运行 AutoGluon、Pcap-Encoder、Denoiser、QA 或 accelerate。",
        "",
        "## 2. 结果",
        "",
        "| group | mode | columns | raw macro F1 | perturbed macro F1 | drop |",
        "|---|---|---|---:|---:|---:|",
    ]
    for row in results.sort_values("macro_f1_drop", ascending=False).to_dict("records"):
        lines.append(
            f"| `{row['group_name']}` | `{row['mode']}` | `{row['columns']}` | "
            f"{row['raw_macro_f1']:.4f} | {row['perturbed_macro_f1']:.4f} | {row['macro_f1_drop']:.4f} |"
        )
    lines.extend(
        [
            "",
            "## 3. 解释",
            "",
            "这个 smoke 不重新训练 masked 模型，而是在 raw-trained lightweight RF 上只扰动 test。drop 越大，说明 raw 模型推理时越依赖该 group；random_same_size 用来检查这种敏感性是否只是“随便遮 9 列都会掉”。",
        ]
    )
    if top_row is not None:
        lines.append(f"本次 smoke 中最敏感的是 `{top_row['group_name']}` / `{top_row['mode']}`，macro F1 drop={top_row['macro_f1_drop']:.4f}。")
    output_md.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-root", type=Path, default=default_raw_csv_root())
    parser.add_argument("--config", type=Path, default=default_group_config_path())
    parser.add_argument("--output-csv", type=Path, default=shallowml_dir() / "test_only_perturbation_smoke_results.csv")
    parser.add_argument("--output-md", type=Path, default=shallowml_dir() / "notes_test_only_perturbation_smoke.md")
    parser.add_argument("--split-id", type=int, default=0)
    parser.add_argument("--max-train", type=int, default=20000)
    parser.add_argument("--max-test", type=int, default=20000)
    parser.add_argument("--groups", default=",".join(DEFAULT_GROUPS))
    parser.add_argument("--modes", default=",".join(DEFAULT_MODES))
    parser.add_argument("--seed", type=int, default=43)
    parser.add_argument("--n-estimators", type=int, default=80)
    parser.add_argument("--max-depth", type=int, default=14)
    parser.add_argument("--n-jobs", type=int, default=2)
    parser.add_argument("--time-budget-minutes", type=float, default=30.0)
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    raw_root = args.raw_root.resolve()
    if not raw_root.is_dir():
        print(f"raw CSV root does not exist: {raw_root}", file=sys.stderr)
        return 2

    args.groups = [value.strip() for value in args.groups.split(",") if value.strip()]
    args.modes = [value.strip() for value in args.modes.split(",") if value.strip()]
    config = load_group_config(args.config)
    groups = groups_by_name(config)
    missing = [name for name in args.groups if name not in groups]
    if missing:
        print(f"unknown groups: {','.join(missing)}", file=sys.stderr)
        return 2

    train = pd.read_csv(raw_root / f"train_val_split_{args.split_id}" / "train.csv")
    test = pd.read_csv(raw_root / "test.csv")
    train = stratified_sample(train, args.max_train, args.seed + args.split_id)
    test = stratified_sample(test, args.max_test, args.seed + 100)

    feature_ints = feature_columns_from_header(list(train.columns))
    feature_cols = [str(col) for col in feature_ints]
    encoded_zero_value = infer_encoded_zero_value(raw_root / "test.csv")

    model = RandomForestClassifier(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        min_samples_leaf=2,
        random_state=args.seed,
        n_jobs=args.n_jobs,
        class_weight="balanced_subsample",
    )
    model.fit(train[feature_cols], train["class"])
    raw_pred = model.predict(test[feature_cols])
    raw_accuracy = accuracy_score(test["class"], raw_pred)
    raw_macro_f1 = f1_score(test["class"], raw_pred, average="macro")

    started = time.monotonic()
    rows: list[dict[str, object]] = []
    for group_name in args.groups:
        elapsed_minutes = (time.monotonic() - started) / 60.0
        if elapsed_minutes > args.time_budget_minutes:
            print(f"time budget exceeded after {elapsed_minutes:.1f} minutes; stopping before remaining groups", file=sys.stderr)
            break
        columns = resolve_group_columns(groups[group_name], feature_ints)
        column_names = [str(col) for col in columns if str(col) in feature_cols]
        for mode in args.modes:
            perturbed = perturb(test[feature_cols], column_names, mode, encoded_zero_value, args.seed + len(rows))
            pred = model.predict(perturbed[feature_cols])
            accuracy = accuracy_score(test["class"], pred)
            macro_f1 = f1_score(test["class"], pred, average="macro")
            rows.append(
                {
                    "split": args.split_id,
                    "group_name": group_name,
                    "mode": mode,
                    "columns": ",".join(str(col) for col in columns),
                    "raw_accuracy": raw_accuracy,
                    "raw_macro_f1": raw_macro_f1,
                    "perturbed_accuracy": accuracy,
                    "perturbed_macro_f1": macro_f1,
                    "accuracy_drop": max(0.0, raw_accuracy - accuracy),
                    "macro_f1_drop": max(0.0, raw_macro_f1 - macro_f1),
                    "train_rows": len(train),
                    "test_rows": len(test),
                }
            )

    result = pd.DataFrame(rows)
    args.output_csv.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(args.output_csv, index=False)
    top_row = None
    if not result.empty:
        top_row = result.sort_values("macro_f1_drop", ascending=False).iloc[0].to_dict()
    write_report(args.output_md, result, args, top_row)
    print(json.dumps({"csv": str(args.output_csv), "report": str(args.output_md), "top": top_row}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
