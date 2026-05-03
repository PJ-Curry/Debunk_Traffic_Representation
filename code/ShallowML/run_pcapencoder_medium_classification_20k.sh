#!/usr/bin/env bash
set -u

ROOT="/home/a/traffic_encryption/Debunk_Traffic_Representation"
ENV_ACTIVATE="/home/a/miniconda3/bin/activate"
CONDA_ENV="shallowml"
QA_CKPT="$ROOT/code/ShallowML/pcapencoder_medium_checkpoint/results/QA/QA/supervised/t5-base_standard-tokenizer/MediumQAqa_hard_medium_10k_from_denoiser_20260502/task-supervised_lr-0.0005_epochs-1_batch-1/seed_43/best_model"
DATA_ROOT="$ROOT/code/ShallowML/pcapencoder_medium_classification_20k"
OUT_ROOT="$DATA_ROOT/results"
LOG_ROOT="$ROOT/code/ShallowML/logs/pcapencoder_medium_classification_20k"
RUN_ROOT="$DATA_ROOT"
SCRIPT="$ROOT/code/PCAP_encoder/2.Training/classification/classification.py"

source "$ENV_ACTIVATE" "$CONDA_ENV"
export PYTHONPATH="$ROOT/code/PCAP_encoder:${PYTHONPATH:-}"
mkdir -p "$OUT_ROOT" "$LOG_ROOT" "$RUN_ROOT/evaluation"
cd "$RUN_ROOT" || exit 1

run_one() {
  local split="$1"
  local mode="$2"
  local batch_size="$3"
  local data_dir="$DATA_ROOT/ustc_binary_${mode}_split${split}"
  local identifier="ustc_binary_${mode}_split${split}_mediumQA_20k_20260503"
  local log_file="$LOG_ROOT/split${split}_${mode}_batch${batch_size}.log"

  echo "$(date '+%F %T') START split=${split} mode=${mode} batch=${batch_size}" | tee -a "$LOG_ROOT/master.log"
  accelerate launch "$SCRIPT" \
    --identifier "$identifier" \
    --experiment MediumQAClassification20k \
    --task supervised \
    --tokenizer_name t5-base \
    --model_name t5-base \
    --log_level info \
    --output_path "$OUT_ROOT" \
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
    --fix_encoder > "$log_file" 2>&1
  local status=$?
  if [ "$status" -eq 0 ]; then
    echo "$(date '+%F %T') DONE split=${split} mode=${mode} batch=${batch_size}" | tee -a "$LOG_ROOT/master.log"
  else
    echo "$(date '+%F %T') FAIL split=${split} mode=${mode} batch=${batch_size} status=${status}" | tee -a "$LOG_ROOT/master.log"
  fi
  return "$status"
}

run_with_oom_retry() {
  local split="$1"
  local mode="$2"
  if run_one "$split" "$mode" 2; then
    return 0
  fi

  local log_file="$LOG_ROOT/split${split}_${mode}_batch2.log"
  if grep -qiE 'out of memory|OutOfMemoryError|CUDA error: out of memory' "$log_file"; then
    echo "$(date '+%F %T') OOM detected; retrying split=${split} mode=${mode} with batch=1" | tee -a "$LOG_ROOT/master.log"
    run_one "$split" "$mode" 1
    return "$?"
  fi

  return 1
}

for split in 0 1 2; do
  if ! run_with_oom_retry "$split" raw; then
    echo "$(date '+%F %T') STOP raw failed for split=${split}; corresponding mask will not run." | tee -a "$LOG_ROOT/master.log"
    exit 1
  fi

  if ! run_with_oom_retry "$split" mask_top_shortcut; then
    echo "$(date '+%F %T') STOP mask failed for split=${split}." | tee -a "$LOG_ROOT/master.log"
    exit 1
  fi
done

echo "$(date '+%F %T') ALL DONE" | tee -a "$LOG_ROOT/master.log"
