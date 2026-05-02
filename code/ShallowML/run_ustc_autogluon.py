#!/usr/bin/env python3
"""Run parameterized USTC-binary AutoGluon experiments."""

from __future__ import annotations

import argparse
import logging
import shutil
import sys
from pathlib import Path

from autogluon.tabular import TabularDataset, TabularPredictor


ALLOWED_EXPERIMENTS = {"mask_col4", "mask_top_shortcut"}
NUM_SPLITS = 3
LABEL = "class"
EXTRA_METRICS = [
    "f1_macro",
    "f1_micro",
    "precision_macro",
    "precision_micro",
    "recall_macro",
    "recall_micro",
]
HYPERPARAMETERS = {
    "GBM": [{}],
    "NN_TORCH": {},
    "XGB": {},
    "RF": [
        {
            "criterion": "gini",
            "ag_args": {
                "name_suffix": "Gini",
                "problem_types": ["binary", "multiclass"],
            },
        },
        {
            "criterion": "entropy",
            "ag_args": {
                "name_suffix": "Entr",
                "problem_types": ["binary", "multiclass"],
            },
        },
        {
            "criterion": "squared_error",
            "ag_args": {
                "name_suffix": "MSE",
                "problem_types": ["regression", "quantile"],
            },
        },
    ],
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run AutoGluon on a masked USTC-binary dataset."
    )
    parser.add_argument(
        "--name",
        required=True,
        choices=sorted(ALLOWED_EXPERIMENTS),
        help="Experiment name, for example mask_col4.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Delete existing result and model directories for this experiment before running.",
    )
    return parser.parse_args()


def configure_logging(script_dir: Path, name: str) -> logging.Logger:
    log_dir = script_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"AutoGluon_{name}.log"

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_path, mode="w"),
            logging.StreamHandler(),
        ],
        force=True,
    )
    logger = logging.getLogger(__name__)
    logger.info("Writing log to %s", log_path)
    return logger


def ensure_expected_path(path: Path, expected_parent: Path) -> None:
    resolved_path = path.resolve()
    resolved_parent = expected_parent.resolve()
    if resolved_path != resolved_parent and resolved_parent not in resolved_path.parents:
        raise ValueError(f"Refusing to operate outside {resolved_parent}: {resolved_path}")


def prepare_output_dirs(
    result_dir: Path,
    model_dir: Path,
    result_parent: Path,
    model_parent: Path,
    overwrite: bool,
) -> None:
    ensure_expected_path(result_dir, result_parent)
    ensure_expected_path(model_dir, model_parent)

    existing = [path for path in (result_dir, model_dir) if path.exists()]
    if existing and not overwrite:
        existing_text = ", ".join(str(path) for path in existing)
        raise FileExistsError(
            "Existing result/model directory found. Re-run with --overwrite to replace: "
            f"{existing_text}"
        )

    if overwrite:
        for path in existing:
            shutil.rmtree(path)

    result_dir.mkdir(parents=True, exist_ok=False)
    model_dir.mkdir(parents=True, exist_ok=False)


def validate_inputs(data_dir: Path) -> None:
    required = [data_dir / "test.csv"]
    for split_id in range(NUM_SPLITS):
        split_dir = data_dir / f"train_val_split_{split_id}"
        required.extend([split_dir / "train.csv", split_dir / "val.csv"])

    missing = [path for path in required if not path.is_file()]
    if missing:
        missing_text = "\n".join(f"- {path}" for path in missing)
        raise FileNotFoundError(f"Missing required input CSV files:\n{missing_text}")


def run_experiment(name: str, overwrite: bool) -> None:
    script_dir = Path(__file__).resolve().parent
    data_root = script_dir / "outputs" / "ustc-binary"
    result_root = script_dir / "results" / "ustc-binary"
    model_root = script_dir / "AutogluonModels" / "ustc-binary"

    data_dir = data_root / name
    result_dir = result_root / name
    model_dir = model_root / name

    logger = configure_logging(script_dir, name)
    logger.info("Starting experiment %s", name)
    logger.info("Input directory: %s", data_dir)
    logger.info("Result directory: %s", result_dir)
    logger.info("Model directory: %s", model_dir)

    validate_inputs(data_dir)
    prepare_output_dirs(result_dir, model_dir, result_root, model_root, overwrite)

    test_data = TabularDataset(str(data_dir / "test.csv"))

    for split_id in range(NUM_SPLITS):
        logger.info("Training split %s", split_id)
        train_data = TabularDataset(str(data_dir / f"train_val_split_{split_id}" / "train.csv"))
        tuning_data = TabularDataset(str(data_dir / f"train_val_split_{split_id}" / "val.csv"))
        split_model_dir = model_dir / f"split_{split_id}"

        predictor = TabularPredictor(label=LABEL, path=str(split_model_dir)).fit(
            train_data=train_data,
            tuning_data=tuning_data,
            num_gpus=0,
            hyperparameters=HYPERPARAMETERS,
        )

        leaderboard_path = result_dir / f"{name}_{split_id}.csv"
        predictor.leaderboard(test_data, extra_metrics=EXTRA_METRICS).to_csv(
            leaderboard_path,
            index=False,
        )
        logger.info("Saved leaderboard: %s", leaderboard_path)

    logger.info("Finished experiment %s", name)


def main() -> int:
    args = parse_args()
    try:
        run_experiment(args.name, args.overwrite)
    except Exception:
        logging.exception("Experiment failed")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
