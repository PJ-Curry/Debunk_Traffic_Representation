# Shortcut Group Scoring Report

生成日期：2026-05-04

## 1. 设置

- raw CSV：`/home/a/traffic_encryption/Debunk_Traffic_Representation/code/ShallowML/outputs/ustc-binary/raw`
- train sample / split：`20000`
- test sample / split：`20000`
- model：RandomForest(n_estimators=80, max_depth=14) + group-only DecisionTree(max_depth=8)
- 未运行 AutoGluon、Pcap-Encoder、Denoiser、QA 或 accelerate。

## 2. ShortcutScore 公式

本轮使用可解释加权公式：

`ShortcutScore = 0.25 * normalized_predictability + 0.25 * normalized_importance + 0.25 * normalized_perturb_drop + 0.15 * stability_score + 0.10 * semantic_risk`

其中 `PerturbSensitivity` 来自 raw-trained lightweight RF 在 test-only zero/permute 后的 macro F1 drop；`stability_score` 越高表示跨 split 方差越低。

## 3. 排名

| rank | group | columns | score | predict F1 | importance | perturb drop | stability | retrain drop |
|---:|---|---|---:|---:|---:|---:|---:|---:|
| 1 | `current_mask_top_shortcut_columns` | `4,16,17,20,21,22,23,24,25` | 0.8721 | 0.9998 | 0.9211 | 0.6036 | 0.2144 | 3.571 pp |
| 2 | `tcp_options` | `20,21,22,23,24,25` | 0.7289 | 0.9935 | 0.6768 | 0.4923 | 0.0000 | -0.006 pp |
| 3 | `tcp_flags_window` | `16,17` | 0.4839 | 0.9930 | 0.0776 | 0.0012 | 0.9778 | 0.004 pp |
| 4 | `ip_basic` | `1,2,3,4,5` | 0.4451 | 1.0000 | 0.1969 | 0.0077 | 0.4587 | 5.512 pp |
| 5 | `ip_ttl_protocol` | `4` | 0.4268 | 1.0000 | 0.1666 | 0.0064 | 0.2287 | missing |
| 6 | `ip_len_id_checksum` | `1,2,5` | 0.3355 | 0.9056 | 0.0172 | 0.0001 | 0.4263 | missing |
| 7 | `random_same_size` | `1,3,5,10,12,15,18,29,31` | 0.3289 | 0.9638 | 0.0543 | 0.0054 | 0.4840 | missing |
| 8 | `tcp_seq_ack` | `12,13,14,15` | 0.2729 | 0.7644 | 0.0449 | 0.0014 | 0.4472 | missing |
| 9 | `udp_len_checksum` | `12,13` | 0.2052 | 0.5521 | 0.0024 | 0.0000 | 1.0000 | missing |
| 10 | `tcp_checksum_urgent` | `18,19` | 0.1801 | 0.5574 | 0.0018 | 0.0000 | 0.7810 | missing |

## 4. 解释

“遮掉下降”不等于 shortcut。一个字段被遮掉后下降，可能只是因为它包含合法任务信号，例如 packet length 或协议状态；也可能因为训练分布和测试分布都共享同一个 artifact。必须结合语义风险、只用该 group 的可预测性、模型 importance、跨 split 稳定性和 test-only perturbation 一起看。

test-only perturbation 更接近 shortcut 证据，因为训练模型先在 raw 表示上学习；随后只扰动 test 的某个 group。如果性能明显下降，说明 raw-trained model 在推理时确实依赖该 group。它比“重新训练 masked 数据后下降”更少受到 retraining optimization、容量补偿和替代特征学习的影响。

当前自动评分中，`current_mask_top_shortcut_columns` 排名：1。
当前最可疑 group：`current_mask_top_shortcut_columns`，score=0.8721。

是否需要更新 mask_top_shortcut：如果 top group 或前几名与 current_mask_top_shortcut 高度重合，可以继续把旧 mask 作为 manual baseline；如果自动 top group 稳定指向更小或更语义清晰的字段组，下一步应在远程 GPU 上加入 auto-selected mask 与 random mask 对照。

## 5. 限制

本脚本只做轻量 ShallowML scoring。UDP group 在当前 TCP-heavy/possibly TCP-only 样本中可能没有 pcap-aware gating；它的 CSV 默认 columns 只适合作为粗略 sanity signal。正式 field-level CSV 生成应使用 `make_ustc_field_masked_csv.py` 的 Scapy 动态定位。
