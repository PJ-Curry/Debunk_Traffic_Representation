# Pcap-Encoder raw vs mask_top_shortcut split0 smoke training 记录

## 实验目的

本次实验只验证 Pcap-Encoder classification 训练链路是否能在当前机器上跑通，并检查 ShallowML 阶段发现的 `mask_top_shortcut` 数据生成方式是否可以接入 Pcap-Encoder 的 packet-level parquet 输入。

重要限制：本次运行使用 `--finetuned_path_model Empty`，没有加载论文正式 Pcap-Encoder QA checkpoint。因此结果只能作为工程链路 smoke test，不能作为 Pcap-Encoder 论文复现结果，也不能作为正式的 shortcut 跨模型结论。

## 数据规模

两组 smoke 数据都使用 USTC-binary split 0 的小规模 parquet：

| split | 行数 | class 分布 |
|---|---:|---|
| train | 5,000 | `{0: 2500, 1: 2500}` |
| val | 1,000 | `{0: 500, 1: 500}` |
| test | 5,000 | `{0: 2500, 1: 2500}` |

## 数据路径

raw parquet：

- `code/ShallowML/pcapencoder_smoke/ustc_binary_raw_split0/train.parquet`
- `code/ShallowML/pcapencoder_smoke/ustc_binary_raw_split0/val.parquet`
- `code/ShallowML/pcapencoder_smoke/ustc_binary_raw_split0/test.parquet`

mask_top_shortcut parquet：

- `code/ShallowML/pcapencoder_smoke/ustc_binary_mask_top_shortcut_split0/train.parquet`
- `code/ShallowML/pcapencoder_smoke/ustc_binary_mask_top_shortcut_split0/val.parquet`
- `code/ShallowML/pcapencoder_smoke/ustc_binary_mask_top_shortcut_split0/test.parquet`

parquet 字段保持 Pcap-Encoder classification 输入格式：

- `question`
- `class`
- `type_q`
- `context`

## 运行入口与核心参数

训练入口：

- `code/PCAP_encoder/2.Training/classification/classification.py`

核心参数：

- `WANDB_MODE=disabled`
- `--task supervised`
- `--model_name t5-base`
- `--tokenizer_name t5-base`
- `--finetuned_path_model Empty`
- `--fix_encoder`
- `--epochs 1`
- `--batch_size 4`
- `--lr 0.001`
- `--input_format every4`
- `--bottleneck mean`
- `--seed 43`
- `--gpu 0,`

raw 运行标识：

- `--experiment ustc_binary_pcapencoder_smoke`
- `--identifier ustc_binary_raw_split0_smoke`

mask 运行标识：

- `--experiment ustc_binary_pcapencoder_smoke`
- `--identifier ustc_binary_mask_top_shortcut_split0_smoke`

## tokenizer 兼容补丁

当前环境的 `transformers` 版本为 4.57.6，`PreTrainedTokenizerFast._batch_encode_plus()` 不再接受 `pad_to_max_length=True`。Pcap-Encoder 原 tokenizer 代码同时传入了 `padding="max_length"` 和 `pad_to_max_length=True`，导致第一个 DataLoader batch 报错。

已做最小兼容补丁：

- 文件：`code/PCAP_encoder/Core/classes/tokenizer.py`
- 删除 T5/BART 的 `tokenize_question` 和 `tokenize_answer` 中的 `pad_to_max_length=True`
- 保留 `padding="max_length"`、`truncation=True`、`max_length`、`add_special_tokens=True`

备份文件：

- `backups/pcapencoder_tokenizer_fix_2026-05-02_tokenizer.py`

## 结果文件与输出目录

raw 日志：

- `code/ShallowML/logs/pcapencoder_raw_split0_smoke.log`

raw evaluation JSON：

- `code/ShallowML/pcapencoder_smoke/evaluation/ustc_binary_pcapencoder_smokeustc_binary_raw_split0_smoke.json`

raw 训练输出目录：

- `code/ShallowML/pcapencoder_smoke/results/supervised/t5-base_standard-tokenizer/ustc_binary_pcapencoder_smokeustc_binary_raw_split0_smoke/task-supervised_lr-0.001_epochs-1_batch-4/seed_43`

mask 日志：

- `code/ShallowML/logs/pcapencoder_mask_top_shortcut_split0_smoke.log`

mask evaluation JSON：

- `code/ShallowML/pcapencoder_smoke/evaluation/ustc_binary_pcapencoder_smokeustc_binary_mask_top_shortcut_split0_smoke.json`

mask 训练输出目录：

- `code/ShallowML/pcapencoder_smoke/results/supervised/t5-base_standard-tokenizer/ustc_binary_pcapencoder_smokeustc_binary_mask_top_shortcut_split0_smoke/task-supervised_lr-0.001_epochs-1_batch-4/seed_43`

注意：以上训练输出目录中包含本次 smoke 运行生成的 `best_model/weights.pth` 和 checkpoint 文件。它们来自 `--finetuned_path_model Empty` 的小规模 smoke 训练，不是论文正式 QA checkpoint。

## 测试集指标

| 实验 | accuracy | macro F1 | test loss |
|---|---:|---:|---:|
| raw split0 smoke | 0.9058 | 0.9053 | 0.4073 |
| mask_top_shortcut split0 smoke | 0.7858 | 0.7847 | 0.5270 |

相对 raw 的下降：

| 指标 | raw - mask_top_shortcut |
|---|---:|
| accuracy | 0.1200 |
| macro F1 | 0.1205 |

换算为百分点，mask_top_shortcut 在本次 smoke 设置下使 test accuracy 下降约 12.00 个百分点，macro F1 下降约 12.05 个百分点。

## 为什么这不是正式 Pcap-Encoder 结论

本次实验没有加载论文正式的 Pcap-Encoder QA checkpoint，而是使用 `--finetuned_path_model Empty` 从当前代码默认初始化路径进行小规模链路测试。训练数据也只使用 split 0 的 smoke 子集：train 5,000、val 1,000、test 5,000，且只训练 1 个 epoch。

因此，本次结果不能用于声称：

- 成功复现了 Pcap-Encoder 论文结果；
- Pcap-Encoder 正式模型已经验证了 shortcut 迁移；
- mask_top_shortcut 对深度模型的影响幅度就是约 12 个百分点。

它只能说明：当前数据格式、tokenizer、DataLoader、模型前向、训练、验证、测试和日志保存链路已经跑通。

## 对后续研究的意义

本次 smoke test 的价值在于，它确认了 ShallowML 阶段的 `mask_top_shortcut` 思路可以在 Pcap-Encoder preprocessing 阶段转化为 cleaned packet bytes 的 byte-offset masking，并且生成的 parquet 能被 Pcap-Encoder classification 入口正常消费。

raw 与 mask_top_shortcut 在 smoke 设置下出现明显差距，说明这条验证路线值得继续推进。但由于 checkpoint 和训练规模限制，该差距目前只能作为后续实验设计的信号，不能作为最终证据。

## 下一步

下一步应优先寻找或复现论文流程中的 Pcap-Encoder QA checkpoint，尤其是 classification 入口期望的 `best_model/weights.pth` 目录结构。拿到正式 checkpoint 后，再按相同 raw vs mask_top_shortcut split0 smoke 配置复跑，确认正式模型链路无误。

建议顺序：

1. 找到作者发布或项目流程生成的 QA / Pcap-Encoder checkpoint。
2. 用正式 checkpoint 复跑 raw vs mask_top_shortcut split0 smoke。
3. 确认指标、日志和输出目录正常后，扩大 smoke 数据规模。
4. 最后再考虑多 split 或全量训练对照。
