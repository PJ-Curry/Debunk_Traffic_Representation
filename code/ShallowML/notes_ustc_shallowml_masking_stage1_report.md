# USTC-binary ShallowML Shortcut Masking Stage 1 Report

日期：2026-05-02

本文档整理 USTC-binary 在 ShallowML / AutoGluon 阶段的 shortcut masking 阶段性结果。报告只基于已有结果 CSV 和现有研究笔记整理，没有重跑实验，也没有新增 ShallowML 实验。

## 1. 实验背景

当前 USTC-binary binary task 的 clean raw baseline 在 ShallowML 模型上接近满分。原始输入经过 `raw.ipynb` 清洗后，已经去掉 Ethernet，置零 IP 地址和 TCP/UDP 端口，并删除 TCP/UDP payload。随后 packet bytes 被切成 34 个 16-bit token，即 CSV 中的 `0..33` 列，标签为 `class`。

虽然 payload、IP、port 已经被删除或置零，header token 中仍保留 IP length、IP ID、TTL/protocol、fragment flags、checksum、TCP flags/window、TCP options/padding 等结构信息。这些字段可能不是跨环境稳定的恶意语义，而是采集环境、OS/network stack、packet role、trace construction 或协议栈形态带来的 shortcut。

已有笔记 `notes_shortcut_generalization_research_direction.md` 中的前置诊断指出：

- RandomForestGini 和 LightGBM 的重要特征集中在 `4`, `16`, `17`, `20`, `21`, `23`, `24`, `25` 等 header/structure token。
- 单特征 majority-rule 中，feature `4` 单列 accuracy 接近 0.9995；`16`, `20`, `21`, `23`, `24`, `25` 也有很强单列预测能力。
- 因此本阶段目标不是追求更高分，而是通过结构化 masking 判断 near-perfect baseline 是否依赖 header shortcut。

## 2. 实验设置

所有 masking 都基于 `outputs/ustc-binary/raw` 复制生成，不改原始 raw baseline，不改 train/val/test split。训练逻辑与 `autogluon.ipynb` 保持一致：

- 读取 `train_val_split_0/1/2` 的 `train.csv` 和 `val.csv`。
- 读取同一份 `test.csv`。
- `label='class'`。
- 模型：`GBM`, `NN_TORCH`, `XGB`, `RandomForestGini`, `RandomForestEntr`。
- 汇总模型：`RandomForestGini`, `XGBoost`, `LightGBM`, `NeuralNetTorch`。
- 指标：`score_test`, `f1_macro`，均为 3 split 的 mean ± 95% CI。

mask 实验设置如下：

| experiment | masked columns | 目的 |
|---|---:|---|
| raw | none | clean raw baseline |
| mask_col4 | 4 | 单独遮蔽最强单列 shortcut 候选 |
| mask_top_shortcut | 4,16,17,20,21,22,23,24,25 | 遮蔽 feature importance 和单列诊断共同指向的 top shortcut union |
| mask_ip_basic | 1,2,3,4,5 | IP total length / ID / flags-fragment / TTL-protocol / checksum 近似区域 |
| mask_tcp_flags_window | 16,17,18,19 | TCP flags / window / checksum / urgent pointer 近似区域 |
| mask_tcp_options | 20,21,22,23,24,25,26,27,28,29 | TCP options / padding / header tail 近似区域 |

## 3. Raw Baseline

raw baseline 在四类模型上均接近满分：

| model | score_test mean ± 95% CI | f1_macro mean ± 95% CI |
|---|---:|---:|
| RandomForestGini | 0.999996 ± 0.000006 | 0.999995 ± 0.000006 |
| XGBoost | 0.999751 ± 0.000187 | 0.999741 ± 0.000195 |
| LightGBM | 0.999844 ± 0.000101 | 0.999837 ± 0.000105 |
| NeuralNetTorch | 0.999796 ± 0.000057 | 0.999788 ± 0.000059 |

这个结果说明当前数据表示在 IID test 上非常容易分类，但也让 shortcut 风险更强：如此高的 ShallowML 分数很可能不需要模型学习可迁移的恶意行为语义。

## 4. Masking Results

### 4.1 score_test / f1_macro mean ± 95% CI

| experiment | model | score_test | f1_macro |
|---|---|---:|---:|
| raw | RandomForestGini | 0.999996 ± 0.000006 | 0.999995 ± 0.000006 |
| raw | XGBoost | 0.999751 ± 0.000187 | 0.999741 ± 0.000195 |
| raw | LightGBM | 0.999844 ± 0.000101 | 0.999837 ± 0.000105 |
| raw | NeuralNetTorch | 0.999796 ± 0.000057 | 0.999788 ± 0.000059 |
| mask_col4 | RandomForestGini | 0.999915 ± 0.000015 | 0.999911 ± 0.000015 |
| mask_col4 | XGBoost | 0.999574 ± 0.000763 | 0.999557 ± 0.000794 |
| mask_col4 | LightGBM | 0.999807 ± 0.000231 | 0.999799 ± 0.000241 |
| mask_col4 | NeuralNetTorch | 0.999696 ± 0.000273 | 0.999684 ± 0.000284 |
| mask_top_shortcut | RandomForestGini | 0.967588 ± 0.001786 | 0.965931 ± 0.001929 |
| mask_top_shortcut | XGBoost | 0.963448 ± 0.006130 | 0.961749 ± 0.006411 |
| mask_top_shortcut | LightGBM | 0.978350 ± 0.000669 | 0.977336 ± 0.000695 |
| mask_top_shortcut | NeuralNetTorch | 0.953685 ± 0.001095 | 0.951511 ± 0.001321 |
| mask_ip_basic | RandomForestGini | 0.998051 ± 0.000461 | 0.997973 ± 0.000479 |
| mask_ip_basic | XGBoost | 0.997678 ± 0.001877 | 0.997585 ± 0.001955 |
| mask_ip_basic | LightGBM | 0.864898 ± 0.574105 | 0.790251 ± 0.894993 |
| mask_ip_basic | NeuralNetTorch | 0.993316 ± 0.000037 | 0.993067 ± 0.000038 |
| mask_tcp_flags_window | RandomForestGini | 0.999997 ± 0.000006 | 0.999997 ± 0.000006 |
| mask_tcp_flags_window | XGBoost | 0.999718 ± 0.000171 | 0.999706 ± 0.000178 |
| mask_tcp_flags_window | LightGBM | 0.999714 ± 0.000147 | 0.999703 ± 0.000153 |
| mask_tcp_flags_window | NeuralNetTorch | 0.999788 ± 0.000151 | 0.999779 ± 0.000157 |
| mask_tcp_options | RandomForestGini | 1.000000 ± 0.000000 | 1.000000 ± 0.000000 |
| mask_tcp_options | XGBoost | 0.999993 ± 0.000022 | 0.999993 ± 0.000022 |
| mask_tcp_options | LightGBM | 0.999996 ± 0.000019 | 0.999995 ± 0.000020 |
| mask_tcp_options | NeuralNetTorch | 0.999644 ± 0.000532 | 0.999630 ± 0.000553 |

### 4.2 相对 raw baseline 的下降幅度

单位为 percentage points。负值表示 masking 后均值略高于 raw，属于极小波动，不应解释为真实性能提升。

| experiment | model | score_test drop | f1_macro drop |
|---|---|---:|---:|
| mask_col4 | RandomForestGini | 0.0081 | 0.0084 |
| mask_col4 | XGBoost | 0.0176 | 0.0183 |
| mask_col4 | LightGBM | 0.0037 | 0.0038 |
| mask_col4 | NeuralNetTorch | 0.0100 | 0.0104 |
| mask_top_shortcut | RandomForestGini | 3.2408 | 3.4064 |
| mask_top_shortcut | XGBoost | 3.6303 | 3.7992 |
| mask_top_shortcut | LightGBM | 2.1493 | 2.2501 |
| mask_top_shortcut | NeuralNetTorch | 4.6111 | 4.8277 |
| mask_ip_basic | RandomForestGini | 0.1944 | 0.2022 |
| mask_ip_basic | XGBoost | 0.2072 | 0.2156 |
| mask_ip_basic | LightGBM | 13.4946 | 20.9586 |
| mask_ip_basic | NeuralNetTorch | 0.6480 | 0.6720 |
| mask_tcp_flags_window | RandomForestGini | -0.0002 | -0.0002 |
| mask_tcp_flags_window | XGBoost | 0.0033 | 0.0034 |
| mask_tcp_flags_window | LightGBM | 0.0129 | 0.0134 |
| mask_tcp_flags_window | NeuralNetTorch | 0.0008 | 0.0009 |
| mask_tcp_options | RandomForestGini | -0.0004 | -0.0005 |
| mask_tcp_options | XGBoost | -0.0243 | -0.0253 |
| mask_tcp_options | LightGBM | -0.0152 | -0.0158 |
| mask_tcp_options | NeuralNetTorch | 0.0152 | 0.0158 |

按四个模型做简单平均：

| experiment | avg score_test | avg f1_macro | avg score drop | avg f1 drop |
|---|---:|---:|---:|---:|
| raw | 0.999846 | 0.999840 | 0.0000 | 0.0000 |
| mask_col4 | 0.999748 | 0.999738 | 0.0098 | 0.0102 |
| mask_top_shortcut | 0.965768 | 0.964132 | 3.4079 | 3.5708 |
| mask_ip_basic | 0.963486 | 0.944719 | 3.6360 | 5.5121 |
| mask_tcp_flags_window | 0.999804 | 0.999796 | 0.0042 | 0.0044 |
| mask_tcp_options | 0.999908 | 0.999905 | -0.0062 | -0.0064 |

注意：`mask_ip_basic` 的平均下降被 LightGBM 单折异常强烈放大，不能直接按四模型平均解读为最强证据。详见第 8 节。

## 5. 为什么 mask_col4 不足以说明问题

feature `4` 在单特征 majority-rule 诊断中很强，且在常见 IPv4/TCP 无 IP options 的粗略解释下接近 TTL + protocol token。这让它成为高度可疑的 shortcut 候选。

但是 `mask_col4` 的实际结果几乎不下降：

- 四个模型的 score_test 下降只有 0.0037-0.0176 pp。
- f1_macro 下降只有 0.0038-0.0183 pp。
- 所有模型仍接近满分。

这说明单独遮蔽 column 4 不足以破坏模型的预测路径。模型很可能可以从其它 header token 中找到替代 shortcut，例如 TCP options/padding、TCP flags/window、IP length/ID/checksum 或其它协议栈结构模式。

因此，feature `4` 可以说明“存在强单列 shortcut 候选”，但不能单独证明 raw baseline 的高分主要依赖这一列。

## 6. 为什么 mask_top_shortcut 是当前最强证据

`mask_top_shortcut` 遮蔽 columns `4,16,17,20,21,22,23,24,25`，覆盖了单特征诊断和 feature importance 共同指向的一组 header shortcut 候选。

它是当前最强证据，原因有三点：

1. 下降幅度明显：四个模型 score_test 下降 2.1493-4.6111 pp，f1_macro 下降 2.2501-4.8277 pp。
2. 跨模型一致：RF、XGBoost、LightGBM、NeuralNetTorch 都下降，而不是某个模型的局部现象。
3. 跨 split 稳定：三个 split 中各模型表现都稳定处于 0.95-0.98 区间，不像 `mask_ip_basic` 的 LightGBM 那样由单折异常驱动。

这说明 raw baseline near-perfect performance 至少部分依赖一组 header shortcut features。遮蔽这组字段后，模型仍能分类，但性能从近满分稳定下降到更现实的水平。

## 7. 为什么 shortcut 更像冗余 header feature group，而不是单个字段

三组结构化消融给出的关键信息是：

- `mask_col4` 几乎不下降。
- `mask_tcp_flags_window` 几乎不下降。
- `mask_tcp_options` 几乎不下降。
- 但 `mask_top_shortcut` 稳定下降 2-5 pp。

这组现象更符合“冗余 header feature group”的解释，而不是“单个字段决定分类”的解释。

单独遮蔽一个字段或一个语义区域时，模型仍可利用其它相关 header token 作为替代路径。例如：

- column 4 可能携带 TTL/protocol 相关信息，但 IP length、ID、checksum、TCP options/padding 仍能替代。
- columns 16-19 单独遮蔽后，TCP options/padding 或 IP basic 区域仍保留。
- columns 20-29 单独遮蔽后，column 4、16、17 等仍保留。

只有当 `4 + 16/17 + 20-25` 这些候选一起遮蔽时，模型的冗余 shortcut 路径才被明显削弱。因此当前证据指向的是一个分散、冗余、可互相替代的 header shortcut group。

## 8. mask_ip_basic 中 LightGBM 异常 CI 的注意事项

`mask_ip_basic` 的整体平均看起来下降很大，但需要谨慎解释。原因是 LightGBM 的三折结果极不稳定：

| split | LightGBM score_test | LightGBM f1_macro | score_val |
|---|---:|---:|---:|
| split 0 | 0.998182 | 0.998108 | 0.998333 |
| split 1 | 0.998475 | 0.998414 | 0.998750 |
| split 2 | 0.598037 | 0.374232 | 0.998167 |

split 2 的 validation score 仍为 0.998167，但 test score 掉到 0.598037，导致 mean 和 CI 被极端拉宽：

- LightGBM score_test: 0.864898 ± 0.574105
- LightGBM f1_macro: 0.790251 ± 0.894993

这更像一个单模型单折的分布错配或模型路径异常，不应作为“IP basic 是主要 shortcut 来源”的核心证据。更稳妥的解读是：

- `mask_ip_basic` 对 RF/XGB/NN 有小到中等下降，约 0.2-0.7 pp。
- LightGBM split 2 暴露出某种不稳定性，值得在深度模型迁移时关注 IP basic 区域，但 ShallowML 阶段不再继续扩展实验。
- 当前最强、最稳定的 shortcut 证据仍是 `mask_top_shortcut`。

## 9. ShallowML 阶段性结论

USTC-binary ShallowML Stage 1 可以得出以下阶段性结论：

1. raw baseline 接近满分，但这不等价于学到了可迁移的 malicious semantics。
2. column 4 是强单列 shortcut 候选，但单独遮蔽几乎不降，说明模型存在替代路径。
3. TCP flags/window 单独遮蔽几乎不降，不像主要单独来源。
4. TCP options/padding 单独遮蔽也几乎不降，说明 options 区域不是单独决定因素。
5. `mask_top_shortcut` 稳定造成 2-5 pp 下降，是当前最强证据。
6. shortcut 更像由多个 header token 组成的冗余 feature group，而不是单个字段。
7. `mask_ip_basic` 提示 IP basic 区域也有一定影响，但 LightGBM 的大幅下降主要来自 split 2 异常，不能过度解读。

因此，ShallowML 阶段的核心结论是：当前 clean raw 表示中仍保留了足以支撑 near-perfect 分类的 header shortcut；这些 shortcut 具有冗余性，必须以 feature group 的方式评估，而不是只看单字段消融。

## 10. 下一步迁移到深度模型

ShallowML 阶段到此应停止扩展，不再新增更多 ShallowML masking 实验。下一步应将已有发现迁移到 ET-BERT、Pcap-Encoder 等深度模型，验证 shortcut 是否跨模型族存在。

建议的迁移路径：

1. 保持同一 train/val/test split。
   - raw、`mask_col4`、`mask_top_shortcut`、`mask_ip_basic`、`mask_tcp_flags_window`、`mask_tcp_options` 使用同一数据划分。
   - 避免把 split 差异误认为模型差异。

2. 将 column mask 映射回 byte/header offset。
   - 当前 `0..33` 是 16-bit token。
   - 深度模型输入通常是 byte/token 序列，需要把 column index 转换成对应 byte range。
   - 例如 column `k` 对应 packet byte stream 中近似第 `2k` 和 `2k+1` 个 byte。

3. 做 raw vs mask_top_shortcut 的最小深度对照。
   - 如果 ET-BERT / Pcap-Encoder 在 raw 近满分，在 `mask_top_shortcut` 后也稳定下降，说明 shortcut 不是 ShallowML 特有。
   - 如果深度模型不下降，需要检查它是否利用 payload、上下文序列或其它 byte-level pattern 补偿了 header shortcut。

4. 加入 frozen encoder 对照。
   - 冻结预训练 encoder，只训练分类头。
   - 如果只有 unfrozen fine-tuning 高分，而 frozen encoder 弱，说明模型可能主要在监督数据上重新学习 dataset-specific shortcut。

5. 加入 perturbation / normalization test。
   - 不只训练 masked 数据，也可对 test 做 header perturbation。
   - 例如 TTL normalization、TCP options zeroing、IP ID/checksum normalization、header offset masking。
   - 观察 raw-trained 深度模型对这些 perturbation 的敏感性。

6. 将 ShallowML 作为 shortcut 探针，而不是最终模型。
   - ShallowML 的价值在于低成本发现强离散 shortcut。
   - 深度模型阶段应验证这些 shortcut 是否仍被 representation learning 捕捉，以及 masking/augmentation 是否能提高跨环境稳定性。

最终目标不是证明某个字段“坏”，而是建立一条证据链：ShallowML 发现候选 shortcut group，深度模型复现实验验证其跨模型存在，最后通过 masking、augmentation 或 invariance objective 降低模型对 header artifact 的依赖。
