# Pcap-Encoder medium QA 3-split classification report

日期：2026-05-03

## 目标

继续使用已经训练好的 medium QA checkpoint，完成 USTC-binary split2 的 raw vs `mask_top_shortcut` Pcap-Encoder downstream classification 对照，并和 split0、split1 合并成 3 split 证据。

本轮没有重新训练 Denoiser，没有重新训练 QA，没有修改 `raw.ipynb` / `autogluon.ipynb`，也没有修改原始 pcap。

## 使用的 checkpoint

medium QA `best_model`：

`/home/a/traffic_encryption/Debunk_Traffic_Representation/code/ShallowML/pcapencoder_medium_checkpoint/results/QA/QA/supervised/t5-base_standard-tokenizer/MediumQAqa_hard_medium_10k_from_denoiser_20260502/task-supervised_lr-0.0005_epochs-1_batch-1/seed_43/best_model`

## split2 数据与运行配置

使用 `code/ShallowML/prepare_pcapencoder_ustc_masked_data.py` 生成：

| 数据 | 输出目录 | train | val | test |
|---|---|---:|---:|---:|
| raw split2 | `code/ShallowML/pcapencoder_smoke/ustc_binary_raw_split2` | 5000 | 1000 | 5000 |
| mask_top_shortcut split2 | `code/ShallowML/pcapencoder_smoke/ustc_binary_mask_top_shortcut_split2` | 5000 | 1000 | 5000 |

两个 split2 数据集均保持类别平衡：train/test 为 benign 2500、malware 2500；val 为 benign 500、malware 500。

classification 共同参数：

- `epochs=1`
- `batch_size=2`
- `--fix_encoder`
- `input_format=every4`
- `bottleneck=mean`
- `lr=0.001`
- `seed=43`
- `model_name=t5-base`
- `tokenizer_name=t5-base`
- `finetuned_path_model=<medium QA best_model>`

输出目录：

`code/ShallowML/pcapencoder_medium_checkpoint/results/classification_split2`

日志：

- raw: `code/ShallowML/logs/pcapencoder_medium_classification_split2_raw.log`
- mask: `code/ShallowML/logs/pcapencoder_medium_classification_split2_mask.log`

## split2 结果

split2 raw 和 mask 均成功完成。

| 设置 | accuracy | macro F1 | micro F1 | test loss |
|---|---:|---:|---:|---:|
| raw split2 | 0.8376 | 0.8341 | 0.8376 | 0.5142 |
| mask_top_shortcut split2 | 0.7698 | 0.7686 | 0.7698 | 0.5534 |

相对 raw，`mask_top_shortcut` 后：

- accuracy 下降 0.0678，即 6.78 个百分点
- macro F1 下降 0.0655，即 6.55 个百分点
- test loss 上升 0.0392

split2 方向与 split0、split1 一致：mask 后 accuracy 和 macro F1 均下降，loss 上升。

## 3 split 汇总

| split | raw macro F1 | mask macro F1 | macro F1 下降 |
|---|---:|---:|---:|
| split0 | 0.8367 | 0.7452 | 9.15 pp |
| split1 | 0.8312 | 0.7437 | 8.75 pp |
| split2 | 0.8341 | 0.7686 | 6.55 pp |

3 split 平均：

- raw macro F1 = 0.8340
- mask macro F1 = 0.7525
- macro F1 平均下降 = 8.15 个百分点
- accuracy 平均下降 = 8.39 个百分点

## 结论

这支持一个阶段性结论：在当前 Pcap-Encoder medium QA checkpoint smoke 设置下，`mask_top_shortcut` 对 downstream classification 有稳定影响。三个 split 都出现 raw 高于 mask 的同方向下降，macro F1 平均下降约 8.15 个百分点。

但仍然不能说明：

- 这不是正式全量 Pcap-Encoder 复现。
- 这不是多 seed 统计结论。
- checkpoint 只来自 10k/2k、1 epoch 的 medium 规模 Denoiser -> QA 链路。
- classification 也是 smoke 子集，非全量 USTC-binary 训练。
- 不能直接推出完整论文设置下的 shortcut 迁移幅度。

## 下一步建议

建议先把这个阶段收口，整理给老师看的阶段汇报。现在已经有 ShallowML 线索、Pcap-Encoder medium checkpoint、USTC-binary 3 split 一致性证据，足够形成一个清晰故事：header-level shortcut masking 在传统模型和 Pcap-Encoder downstream classification 中都表现出稳定影响。

扩大 checkpoint 规模可以作为下一阶段计划，但不建议在当前阶段继续盲目加实验。更合适的顺序是先整理结果、图表和限制，再根据反馈决定是否做更大 checkpoint、更多 seed 或全量设置。
