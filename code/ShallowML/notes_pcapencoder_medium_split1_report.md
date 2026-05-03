# Pcap-Encoder medium QA split1 classification report

日期：2026-05-03

## 目标

使用已经训练好的 medium QA checkpoint，把 Pcap-Encoder downstream classification 的 raw vs `mask_top_shortcut` 验证从 USTC-binary split0 扩展到 split1。

本次没有重新训练 Denoiser，没有重新训练 QA，没有修改 `raw.ipynb` / `autogluon.ipynb`，也没有修改原始 pcap。

## 使用的 checkpoint

medium QA `best_model`：

`code/ShallowML/pcapencoder_medium_checkpoint/results/QA/QA/supervised/t5-base_standard-tokenizer/MediumQAqa_hard_medium_10k_from_denoiser_20260502/task-supervised_lr-0.0005_epochs-1_batch-1/seed_43/best_model`

对应权重：

`code/ShallowML/pcapencoder_medium_checkpoint/results/QA/QA/supervised/t5-base_standard-tokenizer/MediumQAqa_hard_medium_10k_from_denoiser_20260502/task-supervised_lr-0.0005_epochs-1_batch-1/seed_43/best_model/weights.pth`

## split1 数据

使用 `code/ShallowML/prepare_pcapencoder_ustc_masked_data.py` 生成：

| 数据 | 输出目录 | train | val | test |
|---|---|---:|---:|---:|
| raw split1 | `code/ShallowML/pcapencoder_smoke/ustc_binary_raw_split1` | 5000 | 1000 | 5000 |
| mask_top_shortcut split1 | `code/ShallowML/pcapencoder_smoke/ustc_binary_mask_top_shortcut_split1` | 5000 | 1000 | 5000 |

两个数据集的 train/test 都是 benign 2500、malware 2500；val 是 benign 500、malware 500。

## classification 配置

共同参数：

- `model_name=t5-base`
- `tokenizer_name=t5-base`
- `finetuned_path_model=<medium QA best_model>`
- `epochs=1`
- `batch_size=2`
- `lr=0.001`
- `seed=43`
- `bottleneck=mean`
- `max_qst_length=512`
- `max_ans_length=32`
- `max_chunk_length=512`
- `percentage=100`
- `--fix_encoder`

输出目录：

`code/ShallowML/pcapencoder_medium_checkpoint/results/classification_split1`

evaluation 文件：

- raw: `code/ShallowML/pcapencoder_medium_checkpoint/evaluation/MediumQAClassificationustc_binary_raw_split1_mediumQA_20260503.json`
- mask: `code/ShallowML/pcapencoder_medium_checkpoint/evaluation/MediumQAClassificationustc_binary_mask_top_shortcut_split1_mediumQA_20260503.json`

备注：raw 日志里有一次启动失败记录，原因是第一次从 checkpoint 目录启动时没有设置 `PYTHONPATH`，分类脚本找不到 `Core` 包。随后补 `PYTHONPATH=code/PCAP_encoder` 后用相同训练参数重跑成功；失败启动没有产生结果指标。

## split1 结果

| 设置 | accuracy | macro F1 | micro F1 | test loss |
|---|---:|---:|---:|---:|
| raw split1 | 0.8336 | 0.8312 | 0.8336 | 0.4955 |
| mask_top_shortcut split1 | 0.7438 | 0.7437 | 0.7438 | 0.5638 |

相对 raw，`mask_top_shortcut` 后：

- accuracy 下降 0.0898，即 8.98 个百分点
- macro F1 下降 0.0875，即 8.75 个百分点
- test loss 上升 0.0683

## 与 split0 对比

split0 medium QA classification：

- raw macro F1 = 0.8367
- mask_top_shortcut macro F1 = 0.7452
- macro F1 下降 9.15 个百分点

split1 medium QA classification：

- raw macro F1 = 0.8312
- mask_top_shortcut macro F1 = 0.7437
- macro F1 下降 8.75 个百分点

趋势一致。split1 的 raw 和 mask 绝对值也都非常接近 split0，说明 `mask_top_shortcut` 造成的下降不是 split0 的孤立现象。

## 是否继续 split2

值得继续做 split2。split0 和 split1 已经给出同方向、相近幅度的下降；split2 的增量成本较低，而且可以把结论从“两份 split 观察一致”推进到“三份 split 观察一致”，更适合作为后续报告里的 multi-split 证据。
