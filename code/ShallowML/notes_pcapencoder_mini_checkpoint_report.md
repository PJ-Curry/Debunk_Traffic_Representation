# Pcap-Encoder mini checkpoint 实验报告

日期：2026-05-02

## 实验目的

本实验的目标不是复现论文正式 Pcap-Encoder 结果，而是在本机 RTX 4060 Laptop 8GB 上验证一个最小 checkpoint 链路是否可行：

1. 用小规模 Denoiser 数据训练 mini Denoiser checkpoint；
2. 用 mini Denoiser checkpoint 初始化 mini QA checkpoint；
3. 用 mini QA checkpoint 跑 USTC-binary split0 的 raw vs mask_top_shortcut classification smoke；
4. 检查 ShallowML 阶段发现的 header-level shortcut 现象是否在 Pcap-Encoder mini 链路中呈现同方向信号。

## mini Denoiser

数据来自 `Pretrained/Denoiser/Train_for_denoiser_450K.parquet` 的小规模抽样，没有使用 450K 全量数据。

| 文件 | 行数 | 字段 |
|---|---:|---|
| `code/ShallowML/pcapencoder_mini_checkpoint/data/denoiser_train_2k.parquet` | 2000 | `question`, `context` |
| `code/ShallowML/pcapencoder_mini_checkpoint/data/denoiser_test_500.parquet` | 500 | `question`, `context` |

训练参数核心设置：

- `model_name=t5-base`
- `tokenizer_name=t5-base`
- `epochs=1`
- `batch_size=1`
- `finetuned_path_model=Empty`
- `WANDB_MODE=disabled`

结果：mini Denoiser 跑通，并生成：

`code/ShallowML/pcapencoder_mini_checkpoint/results/denoiser/denoiser/supervised/t5-base_standard-tokenizer/MiniDenoiserdenoiser_mini_2k_20260502/task-supervised_lr-5e-06_epochs-1_batch-1/seed_43/best_model/weights.pth`

文件大小约 891.7 MB。

## mini QA

数据来自 `Pretrained/QA/Train_Hard.parquet` 和 `Pretrained/QA/Test_Hard.parquet` 的小规模抽样，没有使用 50K 全量 QA 数据。

| 文件 | 行数 | 字段 |
|---|---:|---|
| `code/ShallowML/pcapencoder_mini_checkpoint/data/qa_train_hard_2k.parquet` | 2000 | `question`, `context`, `answer`, `pkt_field` |
| `code/ShallowML/pcapencoder_mini_checkpoint/data/qa_test_hard_500.parquet` | 500 | `question`, `context`, `answer`, `pkt_field` |

QA train 的 `pkt_field` 分布：

| pkt_field | count |
|---|---:|
| `IPid` | 259 |
| `IPttl` | 256 |
| `checksum_check` | 239 |
| `chk3L` | 266 |
| `dstIP` | 255 |
| `last_header3L_byte` | 254 |
| `len_payload` | 226 |
| `srcIP` | 245 |

训练参数核心设置：

- `model_name=t5-base`
- `tokenizer_name=t5-base`
- `epochs=1`
- `batch_size=1`
- `lr=0.0005`
- `finetuned_path_model=<mini Denoiser best_model>`
- `WANDB_MODE=disabled`

结果：mini QA 训练和测试阶段跑完，并生成：

`code/ShallowML/pcapencoder_mini_checkpoint/results/QA/QA/supervised/t5-base_standard-tokenizer/MiniQAqa_hard_mini_2k_from_denoiser_20260502/task-supervised_lr-0.0005_epochs-1_batch-1/seed_43/best_model/weights.pth`

文件大小约 891.7 MB。

QA evaluation 记录：

| metric | value |
|---|---:|
| Total_accuracy | 17.5 |
| loss | 2.0423 |
| accIPid | 12.7 |
| accIPttl | 0.0 |
| accchecksum_check | 39.13 |
| accchk3L | 0.0 |
| accdstIP | 0.0 |
| acclast_header3L_byte | 43.18 |
| acclen_payload | 64.1 |
| accsrcIP | 0.0 |

## QA FileNotFoundError 与修复

QA 在 checkpoint 和 evaluation 已经生成之后，最后写实验报告时报错：

```text
FileNotFoundError: [Errno 2] No such file or directory: 'output_experiments/qa_hard_mini_2k_from_denoiser_20260502.txt'
```

原因是 `code/PCAP_encoder/Core/functions/utils.py` 中的 `generate_experiment_report()` 直接打开相对路径 `output_experiments/{exp_id}.txt`，但没有确保 `output_experiments/` 目录存在。

修复方式是最小兼容补丁：在写文件前执行：

```python
os.makedirs("output_experiments", exist_ok=True)
```

没有修改训练逻辑、模型逻辑、数据读取逻辑或评估逻辑。

## Classification: raw vs mask_top_shortcut

使用 mini QA checkpoint 作为 `--finetuned_path_model`，运行 USTC-binary split0 classification smoke。

共同参数：

- `epochs=1`
- `batch_size=2`
- `--fix_encoder`
- `lr=0.001`
- `loss=normal`
- `WANDB_MODE=disabled`

数据路径：

| 实验 | 数据目录 |
|---|---|
| raw | `code/ShallowML/pcapencoder_smoke/ustc_binary_raw_split0` |
| mask_top_shortcut | `code/ShallowML/pcapencoder_smoke/ustc_binary_mask_top_shortcut_split0` |

测试集结果：

| 实验 | accuracy | macro F1 | micro F1 | loss |
|---|---:|---:|---:|---:|
| raw | 0.8340 | 0.8319 | 0.8340 | 0.4731 |
| mask_top_shortcut | 0.7886 | 0.7875 | 0.7886 | 0.5243 |

mask_top_shortcut 相对 raw 的变化：

| metric | delta |
|---|---:|
| accuracy | -0.0454, 即下降 4.54 pp |
| macro F1 | -0.0445, 即下降 4.45 pp |
| loss | +0.0511 |

## 这次结果能说明什么

1. 本机 RTX 4060 Laptop 8GB 可以跑通 Pcap-Encoder 的 mini `Denoiser -> QA -> Classification` 链路。
2. Pcap-Encoder classification 能成功加载本地生成的 mini QA `best_model/weights.pth`。
3. 在这个 mini 链路上，mask_top_shortcut 后 raw vs mask 的性能差异方向与 ShallowML 阶段一致：mask 后 accuracy 和 macro F1 明显下降。
4. 这为后续扩大到更充分的 Pcap-Encoder checkpoint 训练提供了工程可行性依据。

## 这次结果不能说明什么

1. 这不是论文正式 Pcap-Encoder checkpoint，也不是论文复现结果。
2. Denoiser 和 QA 都只训练 1 epoch，样本量分别只有 2k/500，远小于原始 450K Denoiser 和 50K QA 规模。
3. 只有 split0、单次运行、单个 seed，没有多 split 或多 seed 置信区间。
4. mini QA 的 QA accuracy 很低，说明 checkpoint 还没有充分学习 QA 任务。
5. 因此 raw vs mask 的下降只能作为 mini smoke 方向性信号，不能作为正式 shortcut 迁移结论。

## 下一步建议

1. 先用修复后的 `output_experiments` 目录创建逻辑，做一个更小的 QA-only sanity run，确认报告写出不再报错。
2. 在 8GB 显存限制下逐步扩大 mini 数据规模，例如 Denoiser 10k/2k、QA 10k/2k，保持 `batch_size=1`，必要时开启梯度累积或混合精度。
3. 记录每个 checkpoint 的 QA accuracy，只有当 QA 任务明显收敛后，再解释 downstream classification 的 raw vs mask 差异。
4. 对 classification 至少跑 3 个 split，并和 ShallowML 的 mask_top_shortcut 下降幅度做方向一致性比较。
5. 如果要接近正式结论，应使用更强 GPU 训练完整或更接近完整规模的 Denoiser/QA checkpoint，并保留固定 seed、日志、evaluation JSONL 和 checkpoint 元数据。
