# Stage Summary Tables

日期：2026-05-03

## Table 1. ShallowML stage 1 summary

四模型平均，单位为 macro F1。`drop` 为相对 raw 的百分点下降。

| experiment | avg macro F1 | avg drop |
|---|---:|---:|
| raw | 0.9998 | 0.00 pp |
| mask_col4 | 0.9997 | 0.01 pp |
| mask_top_shortcut | 0.9641 | 3.57 pp |
| mask_ip_basic | 0.9447 | 5.51 pp |
| mask_tcp_flags_window | 0.9998 | 0.00 pp |
| mask_tcp_options | 0.9999 | -0.01 pp |

备注：`mask_ip_basic` 的平均下降被 LightGBM split2 异常强烈拉大；当前最稳证据是 `mask_top_shortcut`。

## Table 2. ShallowML mask_top_shortcut by model

| model | raw macro F1 | mask_top_shortcut macro F1 | drop |
|---|---:|---:|---:|
| RandomForestGini | 0.999995 | 0.965931 | 3.41 pp |
| XGBoost | 0.999741 | 0.961749 | 3.80 pp |
| LightGBM | 0.999837 | 0.977336 | 2.25 pp |
| NeuralNetTorch | 0.999788 | 0.951511 | 4.83 pp |

## Table 3. Pcap-Encoder medium QA 5k smoke, 3 splits

使用 medium QA checkpoint，冻结 encoder，只训练 downstream classification head。每个 split 使用 5k train / 1k val / 5k test。

| split | raw accuracy | mask accuracy | accuracy drop | raw macro F1 | mask macro F1 | macro F1 drop |
|---|---:|---:|---:|---:|---:|---:|
| split0 | 0.8394 | 0.7454 | 9.40 pp | 0.8367 | 0.7452 | 9.15 pp |
| split1 | 0.8336 | 0.7438 | 8.98 pp | 0.8312 | 0.7437 | 8.75 pp |
| split2 | 0.8376 | 0.7698 | 6.78 pp | 0.8341 | 0.7686 | 6.55 pp |
| average | - | - | 8.39 pp | 0.8340 | 0.7525 | 8.15 pp |

## Table 4. Pcap-Encoder medium checkpoint details

| item | value |
|---|---|
| Denoiser train/test | 10k / 2k |
| QA train/test | 10k / 2k |
| base model | t5-base |
| QA epochs | 1 |
| classification epochs | 1 |
| classification batch size | 2 |
| classification encoder | frozen |
| classification bottleneck | mean |
| classification input format | every4 |
| seed | 43 |

## Table 5. Current 20k Pcap-Encoder classification expansion

状态：正在后台运行。

| split | setting | train | val | test | status |
|---|---|---:|---:|---:|---|
| split0 | raw | 20000 | 4000 | 20000 | running/queued |
| split0 | mask_top_shortcut | 20000 | 4000 | 20000 | queued |
| split1 | raw | 20000 | 4000 | 20000 | queued |
| split1 | mask_top_shortcut | 20000 | 4000 | 20000 | queued |
| split2 | raw | 20000 | 4000 | 20000 | queued |
| split2 | mask_top_shortcut | 20000 | 4000 | 20000 | queued |

后台队列会按表中顺序依次运行。结果目录：

`code/ShallowML/pcapencoder_medium_classification_20k/results`

evaluation 目录：

`code/ShallowML/pcapencoder_medium_classification_20k/evaluation`

日志目录：

`code/ShallowML/logs/pcapencoder_medium_classification_20k`

## Table 6. Claims and limitations

| category | statement |
|---|---|
| supported | ShallowML raw near-perfect performance depends partly on header shortcut group. |
| supported | `mask_top_shortcut` causes stable degradation across ShallowML models. |
| supported | Pcap-Encoder medium QA 5k smoke shows stable raw-to-mask macro F1 drop across 3 splits. |
| not claimed | Formal full-scale Pcap-Encoder reproduction. |
| not claimed | Multi-seed statistical conclusion. |
| not claimed | Complete paper checkpoint/result reproduction. |
| not claimed | True OOD generalization improvement. |

## Quick commands

查看后台主进程：

```bash
cat code/ShallowML/logs/pcapencoder_medium_classification_20k/pid.txt
ps -p "$(cat code/ShallowML/logs/pcapencoder_medium_classification_20k/pid.txt)" -o pid,ppid,stat,cmd
```

查看队列状态：

```bash
tail -f code/ShallowML/logs/pcapencoder_medium_classification_20k/master.log
```

查看当前 split0 raw 训练日志：

```bash
tail -f code/ShallowML/logs/pcapencoder_medium_classification_20k/split0_raw_batch2.log
```

查看已落盘的 20k evaluation：

```bash
ls -lh code/ShallowML/pcapencoder_medium_classification_20k/evaluation
```
