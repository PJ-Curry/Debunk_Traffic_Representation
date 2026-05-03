#!/usr/bin/env bash
set -u

ROOT="/home/a/traffic_encryption/Debunk_Traffic_Representation"
ENV_ACTIVATE="/home/a/miniconda3/bin/activate"
CONDA_ENV="shallowml"
QA_CKPT="$ROOT/code/ShallowML/pcapencoder_medium_checkpoint/results/QA/QA/supervised/t5-base_standard-tokenizer/MediumQAqa_hard_medium_10k_from_denoiser_20260502/task-supervised_lr-0.0005_epochs-1_batch-1/seed_43/best_model"
PREP_SCRIPT="$ROOT/code/ShallowML/prepare_pcapencoder_ustc_masked_data.py"
CLASS_SCRIPT="$ROOT/code/PCAP_encoder/2.Training/classification/classification.py"
OVERNIGHT_LOG_ROOT="$ROOT/code/ShallowML/logs/pcapencoder_medium_overnight"
CURRENT_20K_PID="${1:-26505}"

source "$ENV_ACTIVATE" "$CONDA_ENV"
export PYTHONPATH="$ROOT/code/PCAP_encoder:${PYTHONPATH:-}"
mkdir -p "$OVERNIGHT_LOG_ROOT"
echo "$$" > "$OVERNIGHT_LOG_ROOT/pid.txt"

log() {
  echo "$(date '+%F %T') $*" | tee -a "$OVERNIGHT_LOG_ROOT/master.log"
}

has_test_result() {
  local eval_file="$1"
  python - "$eval_file" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.exists():
    raise SystemExit(1)
for line in path.read_text().splitlines():
    if not line.strip():
        continue
    try:
        row = json.loads(line)
    except json.JSONDecodeError:
        continue
    if row.get("epoch") == "test":
        raise SystemExit(0)
raise SystemExit(1)
PY
}

validate_dataset() {
  local data_dir="$1"
  local train_rows="$2"
  local val_rows="$3"
  local test_rows="$4"
  python - "$data_dir" "$train_rows" "$val_rows" "$test_rows" <<'PY'
import json
import sys
from pathlib import Path

import pandas as pd

data_dir = Path(sys.argv[1])
expected = {
    "train": int(sys.argv[2]),
    "val": int(sys.argv[3]),
    "test": int(sys.argv[4]),
}
summary = {}
for split, rows in expected.items():
    path = data_dir / f"{split}.parquet"
    if not path.exists():
        raise SystemExit(f"missing {path}")
    frame = pd.read_parquet(path, columns=["type_q", "class"])
    counts = frame["type_q"].value_counts().to_dict()
    if len(frame) != rows:
        raise SystemExit(f"{path} rows={len(frame)} expected={rows}")
    if counts.get("benign") != rows // 2 or counts.get("malware") != rows // 2:
        raise SystemExit(f"{path} unbalanced type_q counts={counts}")
    summary[split] = {"rows": len(frame), "type_q_distribution": counts}
print(json.dumps({"data_dir": str(data_dir), "summary": summary}, sort_keys=True))
PY
}

prepare_one() {
  local stage="$1"
  local split="$2"
  local mode="$3"
  local train_rows="$4"
  local val_rows="$5"
  local test_rows="$6"
  local data_root="$ROOT/code/ShallowML/pcapencoder_medium_classification_${stage}"
  local data_dir="$data_root/ustc_binary_${mode}_split${split}"
  local log_root="$ROOT/code/ShallowML/logs/pcapencoder_medium_classification_${stage}"
  mkdir -p "$log_root"

  if [ -d "$data_dir" ] && [ -n "$(find "$data_dir" -maxdepth 1 -type f -name '*.parquet' -print -quit 2>/dev/null)" ]; then
    log "${stage} data exists; validating split=${split} mode=${mode}"
  else
    log "${stage} preparing split=${split} mode=${mode}"
    python "$PREP_SCRIPT" \
      --mode "$mode" \
      --split-id "$split" \
      --max-train "$train_rows" \
      --max-val "$val_rows" \
      --max-test "$test_rows" \
      --output-root "$data_root" > "$log_root/prepare_split${split}_${mode}.log" 2>&1
    local status=$?
    if [ "$status" -ne 0 ]; then
      log "${stage} prepare failed split=${split} mode=${mode} status=${status}; see $log_root/prepare_split${split}_${mode}.log"
      return "$status"
    fi
  fi

  validate_dataset "$data_dir" "$train_rows" "$val_rows" "$test_rows" >> "$log_root/data_validation.log" 2>&1
  local status=$?
  if [ "$status" -ne 0 ]; then
    log "${stage} validation failed split=${split} mode=${mode}; see $log_root/data_validation.log"
    return "$status"
  fi
  log "${stage} data ready split=${split} mode=${mode}"
}

prepare_stage() {
  local stage="$1"
  local train_rows="$2"
  local val_rows="$3"
  local test_rows="$4"
  local split_list="$5"
  for split in $split_list; do
    prepare_one "$stage" "$split" raw "$train_rows" "$val_rows" "$test_rows" || return $?
    prepare_one "$stage" "$split" mask_top_shortcut "$train_rows" "$val_rows" "$test_rows" || return $?
  done
}

run_one() {
  local stage="$1"
  local split="$2"
  local mode="$3"
  local batch_size="$4"
  local data_root="$ROOT/code/ShallowML/pcapencoder_medium_classification_${stage}"
  local log_root="$ROOT/code/ShallowML/logs/pcapencoder_medium_classification_${stage}"
  local out_root="$data_root/results"
  local data_dir="$data_root/ustc_binary_${mode}_split${split}"
  local eval_file="$data_root/evaluation/MediumQAClassification${stage}ustc_binary_${mode}_split${split}_mediumQA_${stage}_20260503.json"
  local identifier="ustc_binary_${mode}_split${split}_mediumQA_${stage}_20260503"
  local log_file="$log_root/split${split}_${mode}_batch${batch_size}.log"

  mkdir -p "$out_root" "$data_root/evaluation" "$log_root"
  if has_test_result "$eval_file"; then
    log "${stage} result exists; skipping split=${split} mode=${mode}"
    return 0
  fi

  log "${stage} START split=${split} mode=${mode} batch=${batch_size}"
  (
    cd "$data_root" || exit 1
    accelerate launch "$CLASS_SCRIPT" \
      --identifier "$identifier" \
      --experiment "MediumQAClassification${stage}" \
      --task supervised \
      --tokenizer_name t5-base \
      --model_name t5-base \
      --log_level info \
      --output_path "$out_root" \
      --training_data "$data_dir/train.parquet" \
      --validation_data "$data_dir/val.parquet" \
      --testing_data "$data_dir/test.parquet" \
      --epochs 1 \
      --batch_size "$batch_size" \
      --lr 0.001 \
      --seed 43 \
      --bottleneck mean \
      --input_format every4 \
      --max_qst_length 512 \
      --max_ans_length 32 \
      --max_chunk_length 512 \
      --percentage 100 \
      --gpu 0, \
      --finetuned_path_model "$QA_CKPT" \
      --fix_encoder
  ) > "$log_file" 2>&1
  local status=$?

  if [ "$status" -eq 0 ]; then
    log "${stage} DONE split=${split} mode=${mode} batch=${batch_size}"
  else
    log "${stage} FAIL split=${split} mode=${mode} batch=${batch_size} status=${status}"
  fi
  return "$status"
}

run_with_oom_retry() {
  local stage="$1"
  local split="$2"
  local mode="$3"
  if run_one "$stage" "$split" "$mode" 2; then
    return 0
  fi
  local log_file="$ROOT/code/ShallowML/logs/pcapencoder_medium_classification_${stage}/split${split}_${mode}_batch2.log"
  if grep -qiE 'out of memory|OutOfMemoryError|CUDA error: out of memory' "$log_file"; then
    log "${stage} OOM detected; retrying split=${split} mode=${mode} with batch=1"
    run_one "$stage" "$split" "$mode" 1
    return "$?"
  fi
  return 1
}

run_stage() {
  local stage="$1"
  local split_list="$2"
  local log_root="$ROOT/code/ShallowML/logs/pcapencoder_medium_classification_${stage}"
  mkdir -p "$log_root"
  echo "$$" > "$log_root/pid.txt"
  : > "$log_root/master.log"

  for split in $split_list; do
    if ! run_with_oom_retry "$stage" "$split" raw; then
      log "${stage} STOP raw failed for split=${split}; corresponding mask will not run."
      return 1
    fi
    if ! run_with_oom_retry "$stage" "$split" mask_top_shortcut; then
      log "${stage} STOP mask failed for split=${split}."
      return 1
    fi
  done
  log "${stage} ALL DONE"
}

summarize_stage() {
  local stage="$1"
  local split_list="$2"
  local report_path="$3"
  local summary_path="$4"
  python - "$ROOT" "$stage" "$split_list" "$report_path" "$summary_path" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
stage = sys.argv[2]
splits = [int(x) for x in sys.argv[3].split()]
report_path = root / sys.argv[4]
summary_path = root / sys.argv[5]
data_root = root / "code" / "ShallowML" / f"pcapencoder_medium_classification_{stage}"

def read_test(eval_file: Path):
    if not eval_file.exists():
        return None
    for line in eval_file.read_text().splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("epoch") == "test":
            return row
    return None

rows = []
complete = True
for split in splits:
    split_row = {"split": split}
    for mode in ["raw", "mask_top_shortcut"]:
        eval_file = data_root / "evaluation" / f"MediumQAClassification{stage}ustc_binary_{mode}_split{split}_mediumQA_{stage}_20260503.json"
        result = read_test(eval_file)
        if result is None:
            complete = False
            split_row[mode] = {"success": False, "evaluation_file": str(eval_file.relative_to(root))}
        else:
            split_row[mode] = {
                "success": True,
                "accuracy": result["accuracy"],
                "macro_f1": result["f1_score_macro"],
                "micro_f1": result["f1_score_micro"],
                "loss": result["loss"],
                "evaluation_file": str(eval_file.relative_to(root)),
            }
    raw = split_row.get("raw", {})
    mask = split_row.get("mask_top_shortcut", {})
    if raw.get("success") and mask.get("success"):
        split_row["delta_raw_minus_mask"] = {
            "accuracy": raw["accuracy"] - mask["accuracy"],
            "accuracy_percentage_points": (raw["accuracy"] - mask["accuracy"]) * 100,
            "macro_f1": raw["macro_f1"] - mask["macro_f1"],
            "macro_f1_percentage_points": (raw["macro_f1"] - mask["macro_f1"]) * 100,
            "loss_mask_minus_raw": mask["loss"] - raw["loss"],
        }
    rows.append(split_row)

done_rows = [r for r in rows if r.get("delta_raw_minus_mask")]
averages = {}
if done_rows:
    averages = {
        "raw_macro_f1": sum(r["raw"]["macro_f1"] for r in done_rows) / len(done_rows),
        "mask_macro_f1": sum(r["mask_top_shortcut"]["macro_f1"] for r in done_rows) / len(done_rows),
        "macro_f1_drop_percentage_points": sum(r["delta_raw_minus_mask"]["macro_f1_percentage_points"] for r in done_rows) / len(done_rows),
        "accuracy_drop_percentage_points": sum(r["delta_raw_minus_mask"]["accuracy_percentage_points"] for r in done_rows) / len(done_rows),
    }

summary = {
    "stage": stage,
    "complete": complete,
    "data_root": str(data_root.relative_to(root)),
    "splits": rows,
    "averages": averages,
}
summary_path.parent.mkdir(parents=True, exist_ok=True)
summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")

title = f"Pcap-Encoder medium QA classification {stage} report"
lines = [
    f"# {title}",
    "",
    "日期：2026-05-03",
    "",
    f"状态：{'全部完成' if complete else '未全部完成或有失败'}。",
    "",
    "| split | raw accuracy | mask accuracy | accuracy drop | raw macro F1 | mask macro F1 | macro F1 drop | raw loss | mask loss |",
    "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
]
for row in rows:
    raw = row.get("raw", {})
    mask = row.get("mask_top_shortcut", {})
    delta = row.get("delta_raw_minus_mask")
    if not delta:
        lines.append(f"| split{row['split']} | - | - | - | - | - | - | - | - |")
        continue
    lines.append(
        f"| split{row['split']} | {raw['accuracy']:.4f} | {mask['accuracy']:.4f} | "
        f"{delta['accuracy_percentage_points']:.2f} pp | {raw['macro_f1']:.4f} | "
        f"{mask['macro_f1']:.4f} | {delta['macro_f1_percentage_points']:.2f} pp | "
        f"{raw['loss']:.4f} | {mask['loss']:.4f} |"
    )
if averages:
    lines.extend([
        "",
        "平均：",
        "",
        f"- raw macro F1 = {averages['raw_macro_f1']:.4f}",
        f"- mask macro F1 = {averages['mask_macro_f1']:.4f}",
        f"- macro F1 平均下降 = {averages['macro_f1_drop_percentage_points']:.2f} pp",
        f"- accuracy 平均下降 = {averages['accuracy_drop_percentage_points']:.2f} pp",
    ])
lines.extend([
    "",
    "说明：本阶段继续使用已训练好的 medium QA checkpoint，只做 downstream classification；没有重新训练 Denoiser 或 QA。",
])
report_path.parent.mkdir(parents=True, exist_ok=True)
report_path.write_text("\n".join(lines) + "\n")
PY
}

log "overnight monitor started; waiting for existing 20k PID=${CURRENT_20K_PID}"
while kill -0 "$CURRENT_20K_PID" 2>/dev/null; do
  sleep 60
done
log "existing 20k PID=${CURRENT_20K_PID} exited"

if ! grep -q 'ALL DONE' "$ROOT/code/ShallowML/logs/pcapencoder_medium_classification_20k/master.log" 2>/dev/null; then
  log "20k did not finish with ALL DONE; summarizing partial results and stopping overnight chain"
  summarize_stage "20k" "0 1 2" "code/ShallowML/notes_pcapencoder_medium_classification_20k_report.md" "code/ShallowML/pcapencoder_medium_classification_20k_summary.json"
  exit 1
fi

summarize_stage "20k" "0 1 2" "code/ShallowML/notes_pcapencoder_medium_classification_20k_report.md" "code/ShallowML/pcapencoder_medium_classification_20k_summary.json"
log "20k summarized"

log "starting 50k preparation"
if ! prepare_stage "50k" 50000 10000 50000 "0 1 2"; then
  log "50k data preparation failed; stopping"
  exit 1
fi
log "50k data preparation complete"

if ! run_stage "50k" "0 1 2"; then
  summarize_stage "50k" "0 1 2" "code/ShallowML/notes_pcapencoder_medium_classification_50k_report.md" "code/ShallowML/pcapencoder_medium_classification_50k_summary.json"
  log "50k failed; summarized partial results and stopping"
  exit 1
fi
summarize_stage "50k" "0 1 2" "code/ShallowML/notes_pcapencoder_medium_classification_50k_report.md" "code/ShallowML/pcapencoder_medium_classification_50k_summary.json"
log "50k summarized"

log "starting 100k split0 preparation"
if ! prepare_stage "100k" 100000 12000 100000 "0"; then
  log "100k data preparation failed; stopping"
  exit 1
fi
log "100k split0 data preparation complete"

if ! run_stage "100k" "0"; then
  summarize_stage "100k" "0" "code/ShallowML/notes_pcapencoder_medium_classification_100k_split0_report.md" "code/ShallowML/pcapencoder_medium_classification_100k_split0_summary.json"
  log "100k split0 failed; summarized partial results and stopping"
  exit 1
fi
summarize_stage "100k" "0" "code/ShallowML/notes_pcapencoder_medium_classification_100k_split0_report.md" "code/ShallowML/pcapencoder_medium_classification_100k_split0_summary.json"
log "100k split0 summarized; overnight chain complete"
