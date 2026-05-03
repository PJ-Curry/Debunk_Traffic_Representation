# 阶段性汇报草稿：USTC-binary shortcut masking 与 Pcap-Encoder 验证

日期：2026-05-03

## 一句话总结

我们目前已经形成一条初步证据链：USTC-binary 的 clean raw 表示在 ShallowML 上接近满分，但这种高分明显依赖一组冗余 header shortcut；进一步迁移到 Pcap-Encoder medium QA checkpoint 后，`mask_top_shortcut` 在 3 个 split 上都造成 downstream classification macro F1 稳定下降，平均下降约 8.15 个百分点。

当前正在把 Pcap-Encoder downstream classification 从 5k/1k/5k smoke 子集扩大到 20k/4k/20k，以检查这一现象在更大 classification 数据规模下是否仍然成立。

## 研究背景

加密流量分类里，模型很容易利用数据集采集过程、协议栈形态、header 结构或 trace construction 带来的 shortcut，而不是学习真正可迁移的 malicious behavior。USTC-binary 在 clean raw 表示下已经去掉 Ethernet、置零 IP 地址和 TCP/UDP 端口，并删除 payload；即便如此，ShallowML baseline 仍接近满分，这本身就提示存在 shortcut 风险。

当前关注的问题不是“能不能把 IID test 做高”，而是：

- raw high score 是否依赖 header-level artifact；
- 这种 shortcut 是否是单个字段，还是冗余 feature group；
- 这种现象是否能迁移到 representation learning / Pcap-Encoder downstream classification。

## ShallowML 阶段发现

ShallowML stage 1 使用同一 USTC-binary split，比较 raw 和多组 masking：

- `mask_col4`
- `mask_top_shortcut`
- `mask_ip_basic`
- `mask_tcp_flags_window`
- `mask_tcp_options`

核心发现：

- raw baseline 对 RandomForest、XGBoost、LightGBM、NeuralNetTorch 基本接近满分。
- 单独 mask column 4 几乎不降，说明虽然 column 4 是强单列候选，但模型有替代路径。
- 单独 mask TCP flags/window 或 TCP options/padding 也几乎不降。
- `mask_top_shortcut` 遮蔽一组由 feature importance 和单列诊断共同指向的 header shortcut columns，四类模型均稳定下降。
- 因此 shortcut 更像一个冗余 header feature group，而不是单字段决定分类。

ShallowML 阶段最稳的证据是 `mask_top_shortcut`：四个模型的平均 f1_macro 从约 0.9998 降到约 0.9641，平均下降约 3.57 个百分点。

## Pcap-Encoder medium checkpoint 阶段

我们没有使用论文正式 checkpoint，而是在本机完成了一个 medium mini 链路：

- Denoiser：10k train / 2k test，1 epoch
- QA：10k train / 2k test，1 epoch
- downstream classification：使用 medium QA `best_model`，冻结 encoder，只训练分类头

使用的 medium QA checkpoint：

`/home/a/traffic_encryption/Debunk_Traffic_Representation/code/ShallowML/pcapencoder_medium_checkpoint/results/QA/QA/supervised/t5-base_standard-tokenizer/MediumQAqa_hard_medium_10k_from_denoiser_20260502/task-supervised_lr-0.0005_epochs-1_batch-1/seed_43/best_model`

在 USTC-binary 5k/1k/5k smoke classification 上，split0/1/2 都显示 raw 高于 `mask_top_shortcut`：

| split | raw macro F1 | mask macro F1 | drop |
|---|---:|---:|---:|
| split0 | 0.8367 | 0.7452 | 9.15 pp |
| split1 | 0.8312 | 0.7437 | 8.75 pp |
| split2 | 0.8341 | 0.7686 | 6.55 pp |

3 split 平均：

- raw macro F1 = 0.8340
- mask macro F1 = 0.7525
- macro F1 平均下降 = 8.15 pp
- accuracy 平均下降 = 8.39 pp

这说明 `mask_top_shortcut` 的影响不是 ShallowML 特有，也不是 split0 的孤立现象；在当前 Pcap-Encoder medium QA checkpoint 的 downstream classification 中同样稳定存在。

## 当前正在进行的 20k classification 扩展

为了检查 classification 数据规模扩大后现象是否稳定，当前已经生成 20k/4k/20k parquet：

- split0 raw / mask_top_shortcut
- split1 raw / mask_top_shortcut
- split2 raw / mask_top_shortcut

每组数据：

- train = 20,000
- val = 4,000
- test = 20,000
- benign/malware 平衡

当前后台训练队列已经启动，按顺序运行：

1. split0 raw
2. split0 mask_top_shortcut
3. split1 raw
4. split1 mask_top_shortcut
5. split2 raw
6. split2 mask_top_shortcut

运行配置：

- medium QA `best_model`
- `epochs=1`
- `batch_size=2`
- `--fix_encoder`
- `input_format=every4`
- `bottleneck=mean`
- `lr=0.001`
- `seed=43`

如果 batch size 2 OOM，脚本会自动用 batch size 1 重试一次。如果某个 raw 失败，脚本会停止，不跑对应 mask。

## 当前结论

可以阶段性地说：

1. USTC-binary clean raw 的 near-perfect ShallowML performance 存在 shortcut 风险。
2. 该 shortcut 不是单个字段，而更像冗余 header feature group。
3. `mask_top_shortcut` 是当前最稳定、跨模型一致的 masking 证据。
4. 迁移到 Pcap-Encoder medium QA checkpoint 后，3 个 split 上都出现 raw 到 mask 的明显下降。
5. 当前证据支持：`mask_top_shortcut` 对 Pcap-Encoder medium checkpoint downstream classification 有稳定影响。

## 仍然不能说明什么

需要谨慎表述：

- 这不是正式全量 Pcap-Encoder 论文复现。
- medium checkpoint 只训练 10k/2k、1 epoch，不是论文正式规模。
- downstream classification 目前已完成的是 5k/1k/5k smoke；20k 扩展正在运行。
- 目前不是多 seed 统计结论。
- 不能直接推出完整论文设置或真实跨数据集场景下的 shortcut 影响幅度。
- 目前主要是 IID split 内的 masking sensitivity，不等价于真正 out-of-distribution generalization improvement。

## 下一步计划

建议当前阶段先整理成给老师看的阶段汇报，而不是继续无边界加实验。

优先级建议：

1. 完成 20k classification 运行并补充结果表。
2. 整理一页核心图表：ShallowML raw vs mask、Pcap-Encoder 3 split raw vs mask。
3. 明确限制：非正式全量复现、非多 seed、非完整论文 checkpoint。
4. 和老师确认下一阶段方向：
   - 扩大 checkpoint 规模；
   - 做更多 seed；
   - 做 full-data classification；
   - 或迁移到 ET-BERT / 其它 encoder 做同样 raw vs mask 对照。

我的建议是先阶段性收口，再根据反馈决定是否扩大 checkpoint。当前故事已经比较清楚：ShallowML 发现 header shortcut group，Pcap-Encoder medium checkpoint 验证其在 representation learning downstream classification 中仍然有效。
