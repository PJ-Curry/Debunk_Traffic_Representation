#!/usr/bin/env python3
"""Score USTC-binary shortcut candidate feature groups with lightweight models."""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

try:
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import accuracy_score, f1_score
    from sklearn.tree import DecisionTreeClassifier
except ImportError as exc:  # pragma: no cover - environment guard.
    raise SystemExit(
        "Missing pandas/numpy/sklearn. Run with the ShallowML environment, for example:\n"
        "  conda run -n shallowml python code/ShallowML/score_shortcut_groups.py"
    ) from exc

from ustc_field_mask_utils import (
    default_group_config_path,
    default_raw_csv_root,
    feature_columns_from_header,
    groups_by_name,
    infer_encoded_zero_value,
    load_group_config,
    load_retrain_mask_drops,
    resolve_group_columns,
    semantic_risk_score,
    shallowml_dir,
)


def stratified_sample(frame: pd.DataFrame, max_rows: int | None, seed: int) -> pd.DataFrame:
    if max_rows is None or len(frame) <= max_rows:
        return frame.reset_index(drop=True)
    label = "class"
    counts = frame[label].value_counts()
    per_class = {klass: max(1, int(max_rows * count / len(frame))) for klass, count in counts.items()}
    # Correct rounding so the final size does not exceed max_rows.
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
    sampled = []
    for klass, count in per_class.items():
        subset = frame[frame[label] == klass]
        sampled.append(subset.sample(n=min(count, len(subset)), random_state=seed))
    return pd.concat(sampled, ignore_index=True).sample(frac=1.0, random_state=seed).reset_index(drop=True)


def read_split(raw_root: Path, split_id: int, max_train: int, max_test: int, seed: int) -> tuple[pd.DataFrame, pd.DataFrame]:
    train_path = raw_root / f"train_val_split_{split_id}" / "train.csv"
    test_path = raw_root / "test.csv"
    train = pd.read_csv(train_path)
    test = pd.read_csv(test_path)
    train = stratified_sample(train, max_train, seed + split_id)
    test = stratified_sample(test, max_test, seed + 100 + split_id)
    return train, test


def majority_rule_predict(
    train_values: np.ndarray,
    train_labels: np.ndarray,
    test_values: np.ndarray,
) -> np.ndarray:
    label_counts = Counter(train_labels)
    default_label = label_counts.most_common(1)[0][0]
    mapping: dict[tuple[int, ...], Counter[str]] = defaultdict(Counter)
    for values, label in zip(train_values, train_labels):
        mapping[tuple(int(value) for value in values)][str(label)] += 1
    majority = {key: counts.most_common(1)[0][0] for key, counts in mapping.items()}
    return np.array([majority.get(tuple(int(value) for value in values), default_label) for values in test_values])


def perturb_frame(
    frame: pd.DataFrame,
    columns: list[str],
    mode: str,
    encoded_zero_value: str,
    seed: int,
) -> pd.DataFrame:
    perturbed = frame.copy()
    rng = np.random.default_rng(seed)
    if not columns:
        return perturbed
    if mode == "zero":
        perturbed.loc[:, columns] = int(encoded_zero_value)
    elif mode == "permute":
        for col in columns:
            values = perturbed[col].to_numpy(copy=True)
            rng.shuffle(values)
            perturbed[col] = values
    elif mode == "randomize":
        for col in columns:
            values = frame[col].to_numpy()
            perturbed[col] = rng.choice(values, size=len(values), replace=True)
    else:
        raise ValueError(f"unknown perturb mode: {mode}")
    return perturbed


def train_raw_model(
    train: pd.DataFrame,
    feature_cols: list[str],
    seed: int,
    n_estimators: int,
    max_depth: int | None,
    n_jobs: int,
) -> RandomForestClassifier:
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        min_samples_leaf=2,
        random_state=seed,
        n_jobs=n_jobs,
        class_weight="balanced_subsample",
    )
    model.fit(train[feature_cols], train["class"])
    return model


def score_split(
    split_id: int,
    train: pd.DataFrame,
    test: pd.DataFrame,
    groups: dict[str, dict[str, object]],
    encoded_zero_value: str,
    seed: int,
    n_estimators: int,
    max_depth: int | None,
    predict_depth: int | None,
    n_jobs: int,
) -> list[dict[str, object]]:
    feature_ints = feature_columns_from_header(list(train.columns))
    feature_cols = [str(col) for col in feature_ints]
    y_train = train["class"].to_numpy()
    y_test = test["class"].to_numpy()

    raw_model = train_raw_model(train, feature_cols, seed + split_id, n_estimators, max_depth, n_jobs)
    raw_pred = raw_model.predict(test[feature_cols])
    raw_accuracy = accuracy_score(y_test, raw_pred)
    raw_macro_f1 = f1_score(y_test, raw_pred, average="macro")
    importances = dict(zip(feature_ints, raw_model.feature_importances_))

    rows: list[dict[str, object]] = []
    for group_name, group in groups.items():
        columns = resolve_group_columns(group, feature_ints)
        column_names = [str(col) for col in columns if str(col) in train.columns]
        if not column_names:
            rows.append(
                {
                    "split": split_id,
                    "group_name": group_name,
                    "columns": "",
                    "raw_accuracy": raw_accuracy,
                    "raw_macro_f1": raw_macro_f1,
                    "predictability_accuracy": math.nan,
                    "predictability_macro_f1": math.nan,
                    "majority_accuracy": math.nan,
                    "majority_macro_f1": math.nan,
                    "importance_sum": 0.0,
                    "perturb_zero_drop": 0.0,
                    "perturb_permute_drop": 0.0,
                }
            )
            continue

        group_tree = DecisionTreeClassifier(max_depth=predict_depth, min_samples_leaf=2, random_state=seed + 1000 + split_id)
        group_tree.fit(train[column_names], y_train)
        group_pred = group_tree.predict(test[column_names])

        majority_pred = majority_rule_predict(
            train[column_names].to_numpy(),
            y_train,
            test[column_names].to_numpy(),
        )

        perturb_drops = {}
        for mode in ("zero", "permute"):
            perturbed = perturb_frame(test[feature_cols], column_names, mode, encoded_zero_value, seed + 2000 + split_id)
            pred = raw_model.predict(perturbed[feature_cols])
            macro_f1 = f1_score(y_test, pred, average="macro")
            perturb_drops[mode] = max(0.0, raw_macro_f1 - macro_f1)

        rows.append(
            {
                "split": split_id,
                "group_name": group_name,
                "columns": ",".join(str(col) for col in columns),
                "raw_accuracy": raw_accuracy,
                "raw_macro_f1": raw_macro_f1,
                "predictability_accuracy": accuracy_score(y_test, group_pred),
                "predictability_macro_f1": f1_score(y_test, group_pred, average="macro"),
                "majority_accuracy": accuracy_score(y_test, majority_pred),
                "majority_macro_f1": f1_score(y_test, majority_pred, average="macro"),
                "importance_sum": float(sum(importances.get(col, 0.0) for col in columns)),
                "perturb_zero_drop": perturb_drops["zero"],
                "perturb_permute_drop": perturb_drops["permute"],
            }
        )
    return rows


def mean_std(values: list[float]) -> tuple[float, float]:
    clean = [float(value) for value in values if not pd.isna(value)]
    if not clean:
        return math.nan, math.nan
    if len(clean) == 1:
        return clean[0], 0.0
    return float(np.mean(clean)), float(np.std(clean, ddof=1))


def minmax_normalize(values: dict[str, float]) -> dict[str, float]:
    finite = [value for value in values.values() if math.isfinite(value)]
    if not finite:
        return {key: 0.0 for key in values}
    low = min(finite)
    high = max(finite)
    if math.isclose(low, high):
        return {key: 1.0 if math.isfinite(value) and value > 0 else 0.0 for key, value in values.items()}
    return {
        key: 0.0 if not math.isfinite(value) else (value - low) / (high - low)
        for key, value in values.items()
    }


def aggregate_scores(
    split_rows: list[dict[str, object]],
    groups: dict[str, dict[str, object]],
    retrain_drops: dict[str, float],
) -> list[dict[str, object]]:
    by_group: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in split_rows:
        by_group[str(row["group_name"])].append(row)

    aggregated: list[dict[str, object]] = []
    for group_name, rows in by_group.items():
        predict_mean, predict_std = mean_std([float(row["predictability_macro_f1"]) for row in rows])
        predict_acc_mean, predict_acc_std = mean_std([float(row["predictability_accuracy"]) for row in rows])
        majority_mean, majority_std = mean_std([float(row["majority_macro_f1"]) for row in rows])
        importance_mean, importance_std = mean_std([float(row["importance_sum"]) for row in rows])
        zero_drop_mean, zero_drop_std = mean_std([float(row["perturb_zero_drop"]) for row in rows])
        permute_drop_mean, permute_drop_std = mean_std([float(row["perturb_permute_drop"]) for row in rows])
        raw_f1_mean, raw_f1_std = mean_std([float(row["raw_macro_f1"]) for row in rows])
        perturb_drop_mean = float(np.nanmean([zero_drop_mean, permute_drop_mean]))
        stability_penalty = float(np.nanmean([predict_std, importance_std, zero_drop_std, permute_drop_std]))
        columns = rows[0]["columns"]
        group = groups[group_name]
        aggregated.append(
            {
                "group_name": group_name,
                "columns": columns,
                "predictability_accuracy_mean": predict_acc_mean,
                "predictability_accuracy_std": predict_acc_std,
                "predictability_macro_f1_mean": predict_mean,
                "predictability_macro_f1_std": predict_std,
                "majority_macro_f1_mean": majority_mean,
                "majority_macro_f1_std": majority_std,
                "importance_sum_mean": importance_mean,
                "importance_sum_std": importance_std,
                "raw_macro_f1_mean": raw_f1_mean,
                "raw_macro_f1_std": raw_f1_std,
                "perturb_zero_drop_mean": zero_drop_mean,
                "perturb_zero_drop_std": zero_drop_std,
                "perturb_permute_drop_mean": permute_drop_mean,
                "perturb_permute_drop_std": permute_drop_std,
                "perturb_drop_mean": perturb_drop_mean,
                "stability_penalty": stability_penalty,
                "semantic_risk": semantic_risk_score(group),
                "retrain_mask_drop_pp": retrain_drops.get(group_name, math.nan),
                "note": group.get("note", ""),
            }
        )

    predict_norm = minmax_normalize({row["group_name"]: row["predictability_macro_f1_mean"] for row in aggregated})
    importance_norm = minmax_normalize({row["group_name"]: row["importance_sum_mean"] for row in aggregated})
    perturb_norm = minmax_normalize({row["group_name"]: row["perturb_drop_mean"] for row in aggregated})
    stability_penalty_norm = minmax_normalize({row["group_name"]: row["stability_penalty"] for row in aggregated})

    for row in aggregated:
        name = row["group_name"]
        stability_score = 1.0 - stability_penalty_norm[name]
        row["normalized_predictability"] = predict_norm[name]
        row["normalized_importance"] = importance_norm[name]
        row["normalized_perturb_drop"] = perturb_norm[name]
        row["stability_score"] = stability_score
        row["shortcut_score"] = (
            0.25 * predict_norm[name]
            + 0.25 * importance_norm[name]
            + 0.25 * perturb_norm[name]
            + 0.15 * stability_score
            + 0.10 * float(row["semantic_risk"])
        )

    aggregated.sort(key=lambda row: row["shortcut_score"], reverse=True)
    for rank, row in enumerate(aggregated, start=1):
        row["rank"] = rank
    return aggregated


def write_report(
    output_md: Path,
    aggregated: list[dict[str, object]],
    split_rows: list[dict[str, object]],
    args: argparse.Namespace,
) -> None:
    current_rank = next((row["rank"] for row in aggregated if row["group_name"] == "current_mask_top_shortcut_columns"), "missing")
    top = aggregated[0] if aggregated else None
    lines = [
        "# Shortcut Group Scoring Report",
        "",
        "生成日期：2026-05-04",
        "",
        "## 1. 设置",
        "",
        f"- raw CSV：`{args.raw_root}`",
        f"- train sample / split：`{args.max_train}`",
        f"- test sample / split：`{args.max_test}`",
        f"- model：RandomForest(n_estimators={args.n_estimators}, max_depth={args.max_depth}) + group-only DecisionTree(max_depth={args.predict_depth})",
        "- 未运行 AutoGluon、Pcap-Encoder、Denoiser、QA 或 accelerate。",
        "",
        "## 2. ShortcutScore 公式",
        "",
        "本轮使用可解释加权公式：",
        "",
        "`ShortcutScore = 0.25 * normalized_predictability + 0.25 * normalized_importance + 0.25 * normalized_perturb_drop + 0.15 * stability_score + 0.10 * semantic_risk`",
        "",
        "其中 `PerturbSensitivity` 来自 raw-trained lightweight RF 在 test-only zero/permute 后的 macro F1 drop；`stability_score` 越高表示跨 split 方差越低。",
        "",
        "## 3. 排名",
        "",
        "| rank | group | columns | score | predict F1 | importance | perturb drop | stability | retrain drop |",
        "|---:|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in aggregated:
        retrain = row["retrain_mask_drop_pp"]
        retrain_text = "missing" if pd.isna(retrain) else f"{retrain:.3f} pp"
        lines.append(
            f"| {row['rank']} | `{row['group_name']}` | `{row['columns']}` | {row['shortcut_score']:.4f} | "
            f"{row['predictability_macro_f1_mean']:.4f} | {row['importance_sum_mean']:.4f} | "
            f"{row['perturb_drop_mean']:.4f} | {row['stability_score']:.4f} | {retrain_text} |"
        )
    lines.extend(
        [
            "",
            "## 4. 解释",
            "",
            "“遮掉下降”不等于 shortcut。一个字段被遮掉后下降，可能只是因为它包含合法任务信号，例如 packet length 或协议状态；也可能因为训练分布和测试分布都共享同一个 artifact。必须结合语义风险、只用该 group 的可预测性、模型 importance、跨 split 稳定性和 test-only perturbation 一起看。",
            "",
            "test-only perturbation 更接近 shortcut 证据，因为训练模型先在 raw 表示上学习；随后只扰动 test 的某个 group。如果性能明显下降，说明 raw-trained model 在推理时确实依赖该 group。它比“重新训练 masked 数据后下降”更少受到 retraining optimization、容量补偿和替代特征学习的影响。",
            "",
            f"当前自动评分中，`current_mask_top_shortcut_columns` 排名：{current_rank}。",
        ]
    )
    if top:
        lines.append(f"当前最可疑 group：`{top['group_name']}`，score={top['shortcut_score']:.4f}。")
    lines.extend(
        [
            "",
            "是否需要更新 mask_top_shortcut：如果 top group 或前几名与 current_mask_top_shortcut 高度重合，可以继续把旧 mask 作为 manual baseline；如果自动 top group 稳定指向更小或更语义清晰的字段组，下一步应在远程 GPU 上加入 auto-selected mask 与 random mask 对照。",
            "",
            "## 5. 限制",
            "",
            "本脚本只做轻量 ShallowML scoring。UDP group 在当前 TCP-heavy/possibly TCP-only 样本中可能没有 pcap-aware gating；它的 CSV 默认 columns 只适合作为粗略 sanity signal。正式 field-level CSV 生成应使用 `make_ustc_field_masked_csv.py` 的 Scapy 动态定位。",
        ]
    )
    output_md.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-root", type=Path, default=default_raw_csv_root())
    parser.add_argument("--config", type=Path, default=default_group_config_path())
    parser.add_argument("--output-csv", type=Path, default=shallowml_dir() / "shortcut_group_scores.csv")
    parser.add_argument("--output-json", type=Path, default=shallowml_dir() / "shortcut_group_scores.json")
    parser.add_argument("--output-md", type=Path, default=shallowml_dir() / "notes_shortcut_group_scoring_report.md")
    parser.add_argument("--max-train", type=int, default=20000)
    parser.add_argument("--max-test", type=int, default=20000)
    parser.add_argument("--splits", default="0,1,2")
    parser.add_argument("--seed", type=int, default=43)
    parser.add_argument("--n-estimators", type=int, default=80)
    parser.add_argument("--max-depth", type=int, default=14)
    parser.add_argument("--predict-depth", type=int, default=8)
    parser.add_argument("--n-jobs", type=int, default=2)
    parser.add_argument("--run-light-retrain", action="store_true", help="reserved; default scoring does not retrain masked datasets")
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    if args.run_light_retrain:
        print("--run-light-retrain is reserved for a later controlled run; default scoring will not retrain masked datasets.", file=sys.stderr)

    raw_root = args.raw_root.resolve()
    if not raw_root.is_dir():
        print(f"raw CSV root does not exist: {raw_root}", file=sys.stderr)
        return 2

    config = load_group_config(args.config)
    groups = groups_by_name(config)
    encoded_zero_value = infer_encoded_zero_value(raw_root / "test.csv")
    retrain_drops = load_retrain_mask_drops()
    split_ids = [int(value.strip()) for value in args.splits.split(",") if value.strip()]

    split_rows: list[dict[str, object]] = []
    for split_id in split_ids:
        print(f"scoring split{split_id} with max_train={args.max_train}, max_test={args.max_test}")
        train, test = read_split(raw_root, split_id, args.max_train, args.max_test, args.seed)
        split_rows.extend(
            score_split(
                split_id,
                train,
                test,
                groups,
                encoded_zero_value,
                args.seed,
                args.n_estimators,
                args.max_depth,
                args.predict_depth,
                args.n_jobs,
            )
        )

    aggregated = aggregate_scores(split_rows, groups, retrain_drops)
    output_frame = pd.DataFrame(aggregated)
    args.output_csv.parent.mkdir(parents=True, exist_ok=True)
    output_frame.to_csv(args.output_csv, index=False)
    with args.output_json.open("w", encoding="utf-8") as file:
        json.dump(
            {
                "settings": {
                    "raw_root": str(raw_root),
                    "max_train": args.max_train,
                    "max_test": args.max_test,
                    "splits": split_ids,
                    "encoded_zero_value": encoded_zero_value,
                    "n_estimators": args.n_estimators,
                    "max_depth": args.max_depth,
                    "predict_depth": args.predict_depth,
                },
                "scores": aggregated,
                "split_rows": split_rows,
            },
            file,
            ensure_ascii=False,
            indent=2,
        )
    write_report(args.output_md, aggregated, split_rows, args)
    print(json.dumps({"csv": str(args.output_csv), "json": str(args.output_json), "report": str(args.output_md), "top_group": aggregated[0]["group_name"] if aggregated else None}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
