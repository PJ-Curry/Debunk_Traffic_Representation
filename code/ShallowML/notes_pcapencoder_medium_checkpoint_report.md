# Pcap-Encoder medium mini checkpoint 实验报告

日期：2026-05-02

## 实验目的

本次实验是在本机 RTX 4060 Laptop 8GB 上，把前一轮 Pcap-Encoder 2k/500 mini checkpoint 链路扩大到 10k/2k 规模，验证 `raw` 与 `mask_top_shortcut` 的下降趋势是否仍然存在。

这仍然不是 Pcap-Encoder 正式复现，也不是论文级结论；它的作用是验证：

- Denoiser -> QA -> downstream classification 的 checkpoint 链路可以在本机跑通。
- 使用更大的 mini checkpoint 后，ShallowML 阶段发现的 header-level shortcut masking 方向是否仍然出现。

## 数据规模

medium Denoiser：

- train: 10000 条
- test: 2000 条
- 源数据：`debunk_data/Debunk_Traffic_Representation/Pretrained/Denoiser/Train_for_denoiser_450K.parquet`
- 抽样输出：
  - `code/ShallowML/pcapencoder_medium_checkpoint/data/denoiser_train_10k.parquet`
  - `code/ShallowML/pcapencoder_medium_checkpoint/data/denoiser_test_2k.parquet`

medium QA：

- train: 10000 条
- test: 2000 条
- 源数据：
  - `debunk_data/Debunk_Traffic_Representation/Pretrained/QA/Train_Hard.parquet`
  - `debunk_data/Debunk_Traffic_Representation/Pretrained/QA/Test_Hard.parquet`
- 抽样输出：
  - `code/ShallowML/pcapencoder_medium_checkpoint/data/qa_train_hard_10k.parquet`
  - `code/ShallowML/pcapencoder_medium_checkpoint/data/qa_test_hard_2k.parquet`

downstream classification：

- raw split0: `code/ShallowML/pcapencoder_smoke/ustc_binary_raw_split0`
- mask split0: `code/ShallowML/pcapencoder_smoke/ustc_binary_mask_top_shortcut_split0`
- 这里沿用已有 USTC-binary Pcap-Encoder smoke parquet，不重新生成数据。

## 运行设置

公共设置：

- `WANDB_MODE=disabled`
- `model_name=t5-base`
- `tokenizer_name=t5-base`
- `epochs=1`
- `seed=43`

Denoiser：

- 初始尝试 `batch_size=2`
- `batch_size=2` 失败，错误为新版 transformers/T5 decoder causal mask 张量维度不兼容，不是 OOM
- 降到 `batch_size=1` 后成功完成
- `finetuned_path_model=Empty`

QA：

- 使用 medium Denoiser `best_model` 初始化
- 初始尝试 `batch_size=2`
- `batch_size=2` 同样因新版 transformers/T5 decoder causal mask 张量维度不兼容失败，不是 OOM
- 降到 `batch_size=1` 后成功完成

classification：

- 使用 medium QA `best_model` 初始化
- `batch_size=2`
- `epochs=1`
- `--fix_encoder`
- `lr=0.001`
- raw 和 mask 使用完全相同参数

## Checkpoint 结果

medium Denoiser 已成功生成：

`code/ShallowML/pcapencoder_medium_checkpoint/results/denoiser/denoiser/supervised/t5-base_standard-tokenizer/MediumDenoiserdenoiser_medium_10k_20260502/task-supervised_lr-5e-06_epochs-1_batch-1/seed_43/best_model/weights.pth`

- 大小：891733181 bytes，约 891.7 MB

medium QA 已成功生成：

`code/ShallowML/pcapencoder_medium_checkpoint/results/QA/QA/supervised/t5-base_standard-tokenizer/MediumQAqa_hard_medium_10k_from_denoiser_20260502/task-supervised_lr-0.0005_epochs-1_batch-1/seed_43/best_model/weights.pth`

- 大小：891733181 bytes，约 891.7 MB

classification 也分别为 raw 和 mask 生成了下游分类头 checkpoint：

- raw: `code/ShallowML/pcapencoder_medium_checkpoint/results/classification/supervised/t5-base_standard-tokenizer/MediumQAClassificationustc_binary_raw_split0_mediumQA_20260502/task-supervised_lr-0.001_epochs-1_batch-2/seed_43/best_model/weights.pth`
- mask: `code/ShallowML/pcapencoder_medium_checkpoint/results/classification/supervised/t5-base_standard-tokenizer/MediumQAClassificationustc_binary_mask_top_shortcut_split0_mediumQA_20260502/task-supervised_lr-0.001_epochs-1_batch-2/seed_43/best_model/weights.pth`

## QA 评估

medium QA evaluation:

- loss: 1.8562
- Total_accuracy: 19.4

该 QA checkpoint 只训练 1 epoch、10k mini 数据，因此仍然是链路验证级别，不应当当作正式 Pcap-Encoder QA checkpoint。

## Classification 结果

| 设置 | accuracy | macro F1 | micro F1 | test loss |
|---|---:|---:|---:|---:|
| raw split0 | 0.8394 | 0.8367 | 0.8394 | 0.5135 |
| mask_top_shortcut split0 | 0.7454 | 0.7452 | 0.7454 | 0.5508 |

相对 raw，`mask_top_shortcut` 后：

- accuracy 下降 0.0940，即 9.40 个百分点
- macro F1 下降 0.0915，即 9.15 个百分点
- test loss 上升 0.0373

## 与 2k mini checkpoint 对比

上一轮 2k/500 mini checkpoint：

| 设置 | accuracy | macro F1 | test loss |
|---|---:|---:|---:|
| raw split0 | 0.8340 | 0.8319 | 0.4731 |
| mask_top_shortcut split0 | 0.7886 | 0.7875 | 0.5243 |

上一轮 mask 后：

- accuracy 下降 4.54 个百分点
- macro F1 下降 4.45 个百分点

本轮 10k/2k medium checkpoint：

- accuracy 下降 9.40 个百分点
- macro F1 下降 9.15 个百分点

方向与 2k mini checkpoint 一致，而且下降幅度更大。这说明在当前小规模 checkpoint 链路里，mask_top_shortcut 对 Pcap-Encoder downstream classification 的影响没有消失。

## 显存与环境观察

- 本机 GPU：NVIDIA GeForce RTX 4060 Laptop GPU，约 8GB 显存。
- Denoiser/QA 的 `batch_size=2` 没有出现 OOM，而是触发新版 transformers 下 T5 decoder causal mask 的 batch 维度兼容问题。
- Denoiser/QA 降到 `batch_size=1` 后可以完成。
- classification 使用 `--fix_encoder` 和 `batch_size=2` 可以完成，显存压力较小。

## 能说明什么

本轮可以说明：

- 在本机 4060 8GB 上，Pcap-Encoder 的 Denoiser -> QA -> classification mini checkpoint 链路可以扩大到 10k/2k 并跑通。
- 使用 medium QA checkpoint 后，raw vs mask_top_shortcut 的方向与 ShallowML 和 2k mini Pcap-Encoder 观察一致。
- `mask_top_shortcut` 对 classification 的影响在更大的 mini checkpoint 下仍然存在，甚至更明显。

## 不能说明什么

本轮不能说明：

- 这不是正式 Pcap-Encoder 论文复现结果。
- medium Denoiser/QA 只训练 1 epoch，数据规模仍远小于论文级预训练或 QA 训练。
- 只做了 split0 smoke classification，没有多 split、多随机种子或全量评估。
- 不能仅凭这一次结果断言 shortcut 已经严格跨模型成立；它更适合作为下一步扩大验证的强信号。

## 下一步建议

建议下一步分两条路：

1. 如果继续用本机 RTX 4060 8GB，优先尝试 50k/10k 级别但仍保持 `batch_size=1`，并预留较长训练时间；classification 可以继续用 `--fix_encoder`。
2. 如果要接近正式结论，建议使用远程 GPU，至少 16GB 显存，更理想是 24GB+，用于更大 Denoiser/QA checkpoint、多 split、多 seed 的 raw vs mask_top_shortcut 对照。

同时需要保留当前约束：不要提交 `weights.pth`、checkpoint 目录、大 parquet 数据，只提交报告和小型 summary JSON。
