# 系统化规避 shortcut、提高泛化能力的研究切入点

本文档整理 `The Sweet Danger of Sugar: Debunking Representation Learning for Encrypted Traffic Classification` 与当前 USTC-binary ShallowML clean rerun 的连接点。论文部分聚焦其对 shortcut、benchmark 修正、输入消融和 shallow baseline 的分析；实验部分来自 `raw.ipynb`、`autogluon.ipynb`、`results/ustc-binary/raw` 以及已保存 AutoGluon 模型的 feature importance 分析。

## 1. 论文已有工作

论文的主线是：很多 encrypted traffic representation learning 工作看起来有很高准确率，但高分往往来自数据准备、split、fine-tuning 和 header/payload 处理中的 shortcut，而不是学到了可迁移的表示。

### 1.1 Benchmark / evaluation 设计

这些方法主要是为了让评估更接近真实部署，避免 train/test 泄漏或错误放大：

| 方法 | 作用 | 性质 |
|---|---|---|
| Per-flow split | 同一 flow 的所有 packets 只能落在 train/val/test 的一侧，避免 per-packet random split 把同一 flow 的隐式 ID 泄漏到测试集 | benchmark/evaluation 设计 |
| Frozen encoder | 下游分类时冻结预训练 encoder，只训练分类头，用来检测 encoder 是否真的学到了可复用 representation | benchmark/evaluation 设计 |
| Per-packet vs per-flow 对照 | 证明 per-packet split + unfrozen encoder 容易出现虚高分数 | benchmark/evaluation 设计 |
| 3-fold train/val on training partition | 用相同 splits 公平比较不同模型和配置 | benchmark/evaluation 设计 |
| 测试集不做 class support truncation | 避免人为改变真实测试分布 | benchmark/evaluation 设计 |
| Accuracy + macro F1 | 避免仅用 micro F1 或 accuracy 掩盖 minority class 的失败 | benchmark/evaluation 设计 |
| Shallow baseline 对比 | 用 RF/XGBoost/LightGBM/MLP 等简单模型验证复杂 representation learning 是否真的值得 | benchmark/evaluation 设计，也是 sanity check |

论文的重要判断是：如果 representation learning 真的学到了有意义、通用的 traffic representation，那么 frozen encoder 加简单分类头也应该有不错表现；但很多模型只有在 unfrozen fine-tuning 后才高分，说明它们更像在下游监督数据上重新学习任务相关 shortcut。

### 1.2 领域知识驱动的特征遮蔽 / ablation

这些方法是基于网络协议和流量采集机制的领域知识，直接改变输入信息，观察模型性能是否依赖特定字段或数据集 artifact：

| 方法 | 论文中的目的 | 性质 |
|---|---|---|
| Removing SeqNo/AckNo/TCP timestamp | 移除 per-packet split 中最典型的 implicit flow ID，验证模型是否靠同一 flow 的随机序列空间做捷径 | 领域知识驱动的 feature masking |
| w/o IP addr | 移除显式 flow/server identifier，测试模型是否记忆 IP range 或 server identity | 领域知识驱动的 feature masking |
| w/o header | 移除 TCP/IP header，检测模型是否主要依赖 header 而非 encrypted payload | 领域知识驱动的 feature masking |
| w/o payload | 移除 application payload，检测 encrypted payload 是否真正贡献分类能力 | 领域知识驱动的 feature masking |
| Shallow feature importance | 用 Random Forest importance 找模型依赖的 header fields，如 IP、TTL、TCP Win、SeqNo、AckNo、IP Len/Chk 等 | 人工诊断工具 |

论文中这些 benchmark 修正和 ablation 不是随意遮蔽，而是基于 networking expertise 设计：作者先识别 per-packet split、IP 地址、SeqNo/AckNo、TCP timestamp、header/payload 等可能引入 shortcut 的机制，再设计对应评估或消融实验。

此外，论文中 Pcap-Encoder 为了降低模型记忆固定模式的风险，在预训练阶段会 randomize IP addresses and TTL values。这说明作者已经意识到 IP/TTL 类字段可能影响泛化能力；不过这仍然是针对已知字段的领域知识驱动处理，还没有进一步抽象成一套可迁移到任意数据集、自动选择遮蔽特征组合的方法。

### 1.3 论文没有覆盖的空白

论文没有系统提出“自动化选择遮蔽特征组合”的方法。它做了强有力的 benchmark 修正和基于领域知识的人工 ablation，但没有回答以下问题：

- 给定一个新数据集，如何自动发现哪些字段是 shortcut 候选？
- 如何自动组合多个字段进行 masking，而不只是一组人类预先指定的字段？
- 如何在保持任务可学性的同时，最大化跨环境泛化能力？
- 如何把 feature importance、单特征可预测性、跨 split 稳定性、field semantics 统一成一个搜索或优化流程？

这正好可以成为我们研究的切入点：从“人工规避已知 shortcut”推进到“自动发现并系统遮蔽 shortcut feature groups”。

## 2. 当前 USTC-binary ShallowML 实验发现

### 2.1 raw 特征是什么

`raw.ipynb` 中 `clean_packet` 做了以下清洗：

- 去掉 Ethernet，只保留网络层及以上。
- IP/IPv6 源地址和目的地址置零。
- TCP/UDP 源端口和目的端口置零。
- 删除 TCP/UDP payload。

然后将清洗后的 packet 转成 bytes，再按每 2 bytes 一个 token 切分：

- `max_payload_length = 136` 个 hex chars，即 68 bytes。
- CSV 中 `0..33` 共 34 列，每列是一个 16-bit token 的 `byte_list.index(...)`。
- `class` 是 `benign.pcap` 或 `malware.pcap`。

所以这些列不是人工语义字段，而是 packet header byte stream 的 2-byte token 化结果。对于常见 IPv4/TCP 无 IP options 的包，可粗略映射为：

| 列 | 可能对应的 header 区域 |
|---:|---|
| 0 | IP version/IHL + DSCP/ECN |
| 1 | IP total length |
| 2 | IP identification |
| 3 | IP flags + fragment offset |
| 4 | 在常见 IPv4/TCP 无 IP options 情况下，大致对应 TTL + protocol |
| 5 | IP header checksum |
| 6-9 | src/dst IP，被置零后多为常量 |
| 10-11 | src/dst port，被置零后多为常量 |
| 12-13 | TCP seq 或 UDP length/checksum |
| 14-15 | TCP ack 或 padding |
| 16 | TCP data offset + TCP flags |
| 17 | TCP window |
| 18 | TCP checksum |
| 19 | TCP urgent pointer |
| 20-29 | TCP options / options padding / UDP 后续结构 / 清洗后结构残留 |
| 30-33 | padding 或较长 header 的尾部残留 |

重要点：虽然 payload、IP、port 被删除或置零，但 IP length、IP ID、TTL、protocol、flags、checksum、TCP flags、window、checksum、TCP options、padding pattern 等仍保留。这些字段足够形成强 shortcut。

### 2.2 AutoGluon clean rerun 结果

clean raw 重新跑完后，3 个 split 在 test 上几乎满分：

| model | split0 score / f1_macro | split1 score / f1_macro | split2 score / f1_macro |
|---|---:|---:|---:|
| RandomForestGini | 0.999995 / 0.999995 | 0.999998 / 0.999998 | 0.999993 / 0.999993 |
| XGBoost | 0.999729 / 0.999718 | 0.999688 / 0.999676 | 0.999834 / 0.999828 |
| LightGBM | 0.999888 / 0.999884 | 0.999833 / 0.999826 | 0.999810 / 0.999802 |
| NeuralNetTorch | 0.999774 / 0.999764 | 0.999795 / 0.999787 | 0.999819 / 0.999812 |

这说明当前 USTC-binary binary task 在这个 clean raw 表示下极易被 header token 区分。它可能是“数据集内可分性很强”，但从泛化角度看，更需要怀疑模型学到的是采集环境、OS/network stack、malware/benign trace construction、packet role 或协议栈形态，而不是真正可迁移的 malicious semantics。

### 2.3 Feature importance 证据

基于已保存 AutoGluon 模型，RandomForestGini 和 LightGBM 的平均 top features 为：

| 模型 | 平均 top features |
|---|---|
| RandomForestGini | 21, 4, 20, 24, 22, 23, 25, 19, 16, 17 |
| LightGBM | 21, 20, 24, 4, 23, 16, 26, 25 |

LightGBM 特别集中：

- split 0 中 feature `20` 贡献约 93% gain。
- split 1/2 中 feature `21` 贡献约 93% gain。

RandomForestGini 更分散，但也集中在 `4`, `20`, `21`, `24`, `23`, `25`, `16`, `17` 这些 header/structure token 上。

### 2.4 单特征 shortcut 证据

我们还做过单特征 majority-rule 检查：只用 train 中“某列取值多数属于哪个标签”的映射预测 test。平均结果：

| feature | 单列 accuracy | 单列 f1_macro | 解释 |
|---:|---:|---:|---|
| 4 | 0.999499 | 0.999479 | 在常见 IPv4/TCP 无 IP options 情况下，近似 TTL + protocol token，几乎直接区分类别 |
| 16 | 0.992713 | 0.992440 | TCP data offset + flags |
| 24 | 0.992566 | 0.992287 | TCP options / padding 区域 |
| 23 | 0.992287 | 0.991998 | TCP options / padding 区域 |
| 25 | 0.992059 | 0.991762 | TCP options / padding 区域 |
| 21 | 0.979198 | 0.978538 | TCP options / padding 区域 |
| 20 | 0.978565 | 0.977880 | TCP options / padding 区域，仅 3 个 test 取值 |

其中 feature `4` 在 test 中 125 个取值按标签完全纯：同一 token 取值没有 benign/malware 混杂。在常见 IPv4/TCP 无 IP options 的解释下，这个现象非常像 shortcut：模型只要学 “近似 TTL/protocol token 值 -> class”，几乎不用组合其它字段。

## 3. 为什么 feature 4、20、21、24 等可能是 shortcut

### 3.1 Feature 4：常见 IPv4/TCP 无 IP options 下的 TTL + protocol

feature `4` 不是语义字段名，而是第 8-9 个 byte 组成的 16-bit token。只有在常见 IPv4/TCP 且无 IP options 的包结构下，它才大致对应 IPv4 header 中的 TTL 和 protocol 两个字节；如果存在 IPv6、IP options、不同链路层处理或异常 header layout，这个 offset-level 解释就不能直接当作绝对语义。Protocol 多半是 TCP/UDP/ICMP，TTL 则与 OS default TTL、路由 hop count、采集位置、数据集生成方式有关。

如果 benign 和 malware traces 来自不同源环境、不同 OS、不同网络路径或不同 capture setup，TTL 分布会非常容易和标签绑定。当前 feature `4` 的单列 accuracy 接近 0.9995，说明这个 offset token 几乎成了标签代理变量。

这不是稳健的 malware/benign 语义：换一个网络路径、NAT、VPN、采集点、重放环境或操作系统，这类 TTL/协议栈相关分布可能立刻变化。

### 3.2 Feature 20/21/24：TCP options / padding pattern

feature `20`, `21`, `24` 大致落在 TCP options、options padding、清洗后 header 尾部结构附近。它们可能携带：

- TCP options 类型和顺序，如 MSS、SACK permitted、timestamp、window scale。
- OS/network stack fingerprint。
- Client/server packet role。
- TCP handshake 或 ACK-only packet 的结构模式。
- 被删除 payload 后留下的 header length / padding 形态。

这些字段很适合树模型做 split，因为取值离散、类别纯度高、跨当前 train/test split 稳定。LightGBM 对 `20/21` 的极高 gain 说明它们在 boosting tree 中是非常短路径、强分裂变量。

### 3.3 Feature 16/17：TCP flags/window

feature `16` 大致对应 TCP data offset + flags，feature `17` 对应 TCP window。它们可以反映：

- SYN/SYN-ACK/ACK/FIN/RST 的比例。
- ACK-only packets、control packets、data packets 的结构差异。
- TCP window size 的 OS 或应用实现差异。

这些可能和 “benign application traces vs malware sandbox traces” 强相关，但不一定代表可跨环境泛化的恶意性。

## 4. 潜在创新点

### 4.1 从人工 ablation 到自动化 shortcut discovery

论文已经证明很多高分来自 shortcut，并基于领域知识设计了 benchmark 修正和人工 ablation。我们可以推进一步：提出一个自动化流程，从数据和模型行为中发现 shortcut candidates，再系统搜索遮蔽组合。

可能框架：

1. Candidate scoring：
   - 单特征 majority-rule train->test accuracy。
   - 单特征 mutual information / conditional entropy。
   - test 内 value-label purity。
   - model feature importance / permutation importance。
   - 跨 split importance stability。
2. Semantic grouping：
   - 将 byte-token columns 映射回协议字段组：IP identity、IP length/checksum、TTL/protocol、TCP flags/window、TCP options、padding。
   - 对没有稳定语义的 raw token，先用 offset group 做近似分组。
3. Mask search：
   - Greedy masking：每轮遮蔽 shortcut score 最高的 group，看 IID/test 分数和 shortcut score 如何下降。
   - Beam search：保留多个候选遮蔽组合，避免贪心误删。
   - Pareto selection：在 accuracy 保留、shortcut reliance 降低、跨 split 稳定性之间找平衡。
4. Generalization stress test：
   - 不只看原 test，还构造 field perturbation test，例如 TTL randomization、TCP option normalization、checksum/length recompute 或 zeroing。
   - 如果 mask 后模型在 perturbation / cross-environment test 上更稳，即支持“提高泛化”。

### 4.2 从 field masking 到 invariance objective

更进一步，可以不只是删除字段，而是训练模型对 shortcut 字段不敏感：

- Data augmentation：随机化 TTL、IP ID、TCP timestamp、window、options padding。
- Group DRO / environment split：把不同 TTL/protocol/TCP option pattern 当作 environments，优化 worst-group performance。
- Adversarial removal：让主模型分类，同时让 adversary 无法从 representation 预测 shortcut group。
- Stability regularization：要求遮蔽前后预测一致，但不能依赖 shortcut-only features。

### 4.3 用 ShallowML 做低成本诊断前置

论文强调 shallow baseline 的价值。我们的创新可以把 shallow baseline 从“对比基线”变成“shortcut 探针”：

- RF/LightGBM 快速暴露强离散 shortcut。
- 单特征规则给出最小可解释证据。
- 再把发现的 shortcut groups 反馈给 deep representation learning pipeline 做遮蔽、增强或评估。

这比直接在大模型上盲目训练更省成本，也更容易解释给 reviewer。

## 5. 下一步最小实验计划

目标不是一次性重做全 pipeline，而是先用 USTC-binary raw 建立一个最小可发表的 shortcut-mitigation 证据链。

### Step 1：建立字段组映射

将 `0..33` 映射为粗粒度 groups：

| group | columns | 假设 |
|---|---|---|
| ip_basic | 0,1,2,3,4,5 | IP version/len/id/flags/TTL/protocol/checksum |
| ip_addr_zeroed | 6,7,8,9 | 已置零，应为常量或低信息 |
| port_zeroed | 10,11 | 已置零，应为常量或低信息 |
| tcp_seq_ack_udp | 12,13,14,15 | TCP seq/ack 或 UDP length/checksum |
| tcp_flags_window | 16,17,18,19 | TCP flags/window/checksum/urgent |
| tcp_options_padding | 20-29 | TCP options、padding、清洗后结构残留 |
| tail_padding | 30-33 | padding / 长 header 尾部 |

### Step 2：只做 masking，不改 split

在 clean raw CSV 的拷贝或新输出目录上做遮蔽，不改原始 `outputs/ustc-binary/raw`：

| 实验 | mask columns | 目的 |
|---|---|---|
| baseline | none | 当前 near-perfect 结果 |
| mask_f4 | 4 | 验证 TTL/protocol shortcut |
| mask_top_lgbm | 20,21 | 验证 boosting tree 最依赖字段 |
| mask_tcp_options | 20-29 | 去掉 TCP options/padding shortcut |
| mask_tcp_flags_window | 16-19 | 去掉 flags/window/checksum shortcut |
| mask_ip_basic_without_addr | 1,2,3,4,5 | 去掉 IP length/id/TTL/checksum |
| mask_header_shortcut_union | 4,16,17,20,21,23,24,25 | 遮蔽当前最强 shortcut set |
| payloadless_minimal | 仅保留极少稳定字段或全部 header token 归零 | 测试任务是否仍可学 |

### Step 3：每个 masking 只跑 shallow baseline

优先跑 RF / LightGBM / XGBoost，不必一开始跑所有 deep encoders。记录：

- score_test, f1_macro, f1_micro。
- feature importance 是否转移到新的字段。
- 单特征 majority-rule top accuracy 是否下降。
- 训练集分数和测试集分数是否出现明显 gap。

### Step 4：加入 perturbation test

不改变训练集，仅对 test 做字段扰动：

- TTL randomize / normalize。
- TCP options columns zeroing。
- TCP flags/window columns zeroing。
- top-k shortcut columns random permutation within test。

如果 baseline 模型一扰动就崩，而 masking-trained 模型更稳，这就是“规避 shortcut 提高泛化”的核心证据。

### Step 5：扩展到更难任务

USTC-binary 是论文中也相对简单的任务，接近满分并不意外。最小证据链跑通后，应迁移到：

- USTC-app：20 类，更容易暴露 header shortcut 和 class-specific artifact。
- TLS-120：论文中最能说明 representation learning 困境的任务。
- VPN-app：多类 app classification，也适合验证 IP/TTL/TCP options 依赖。

## 6. 可以和老师讨论的问题

1. 我们的创新是否应定位为“自动化 shortcut discovery + masking search”，而不是再提出一个新 classifier？
2. 论文已经做了人工 w/o IP/header/payload，我们能否把贡献明确为：自动发现 finer-grained header token shortcut，并给出系统遮蔽策略？
3. 对于 USTC-binary 这种 binary task，near-perfect 是否可以作为 shortcut diagnosis 的 case study，而不是最终泛化结论？
4. 是否需要引入跨环境测试集？如果没有，是否可以用 perturbation test 作为可控 proxy？
5. mask 后分数下降该如何解释：是去掉了 shortcut，还是去掉了 legitimate signal？需要哪些 evidence 区分？
6. 该以 byte offset columns 做实验，还是先把 raw packet decode 成 protocol fields，再以 field-level masking 作为主结果？
7. 自动搜索遮蔽组合的目标函数怎么定义：降低单特征 purity、降低 importance concentration、提升 perturbation robustness，还是保持 macro F1 的 Pareto frontier？
8. 是否把 shallow baseline 作为 shortcut detector，再把 detector 输出用于 Pcap-Encoder / ET-BERT / YaTC 的数据增强或遮蔽？
9. 最小论文故事是否可以是：现有 benchmark 修正了 split，但 header shortcut 在 per-flow split 下仍可能存在；我们提出 field-level systematic mitigation 来进一步提高泛化。

## 7. 一句话研究切入点

论文已经指出了 representation learning 在 encrypted traffic classification 中的 “sweet danger”：高分可能来自 shortcut。我们的切入点可以是：在正确 per-flow split 和 clean raw 之后，进一步自动发现并系统遮蔽 header-level shortcut，让模型从“利用数据集 artifact”转向“学习更可迁移的 traffic behavior”。
