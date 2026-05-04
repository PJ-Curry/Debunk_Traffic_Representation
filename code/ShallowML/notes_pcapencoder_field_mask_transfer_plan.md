# Pcap-Encoder Field-level Mask Transfer Plan

日期：2026-05-04

## 1. Column-offset mask vs field-level mask

当前 `mask_top_shortcut` 是 column-offset mask：先把 cleaned packet bytes 切成 16-bit token，然后遮 `4,16,17,20,21,22,23,24,25`。它的优点是简单、能和 ShallowML raw CSV 直接对齐；缺点是语义依赖固定 header layout。

field-level mask 则先解码 packet：去 Ethernet 后读取 IPv4 IHL、TCP data offset、UDP/TCP layer，再按字段范围 mask byte。最后再映射回 ShallowML 16-bit token 或 Pcap-Encoder byte context。这样 mask 的对象是 `IPv4.ttl`、`TCP.window`、`TCP.options`，不是“第 20 列”。

## 2. 为什么 Pcap-Encoder 更需要 field-level mask

Pcap-Encoder 输入保留 payload，而 ShallowML raw 删除 TCP/UDP payload。固定 columns `20-25` 在 ShallowML 中如果不属于 TCP options，通常会变成 padding；但在 Pcap-Encoder 中同样 offset 可能已经进入 payload。继续用固定 column mask 会把 header ablation 和 payload ablation 混在一起。

field-level mask 的优势：

- TCP options 通过 TCP `dataofs` 动态定位，短 TCP header 时跳过 options。
- 不误伤 payload，可以区分 w/o header、w/o payload、w/o IP、w/o TCP options。
- 可以把 ShallowML 发现的 group 用同一套协议字段语义迁移到 byte-level parquet。
- 后续报告能和论文中的 w/o IP / w/o header / w/o payload ablation 更清楚地对齐。

## 3. Parquet 生成方案

建议在远程 GPU 实验前先生成这些 Pcap-Encoder parquet 版本：

| dataset | mask 语义 | 用途 |
|---|---|---|
| raw | 只做既有 clean：去 Ether、IP/port 置零、payload 保留 | baseline |
| manual current_mask_top_shortcut | 复现旧 byte-offset mask：columns 4,16,17,20-25 对应 bytes 8-9,32-35,40-51 | 与已有 50k 结果对齐 |
| field-level ip_ttl_protocol | 动态 mask IPv4 TTL/protocol byte | 检查最强单列 shortcut 是否迁移 |
| field-level tcp_options | 动态 mask TCP options only | 避免短 header 误伤 payload |
| auto-selected top group | 使用 `shortcut_group_scores.csv` 排名最高或前几名组合 | 自动化策略验证 |
| random_same_size | 与 manual mask 同样数量 bytes/columns 的随机扰动 | sanity check |

生成时要保存 manifest：源 pcap、split、class、packet count、被 mask 字段命中率、跳过原因、payload 是否保留、checksum 是否重算。本阶段不运行 classification，不启动 `classification.py`、`train.py` 或 `accelerate`。

## 4. 后续远程 GPU 实验设计

建议的远程实验矩阵：

| checkpoint | downstream scale | comparison |
|---|---|---|
| medium QA checkpoint | 50k 三 split | raw vs manual mask vs field ip_ttl_protocol vs field tcp_options vs random |
| bigger QA checkpoint | 50k 三 split | 复查方向是否稳定 |
| bigger QA checkpoint | full 或更大 classification | raw vs manual mask vs auto-selected top group vs random |

每组至少记录 accuracy、macro F1、loss、per-class F1、split 均值和方差。优先固定 encoder 做第一轮，减少 classification head 训练波动；有余力再做 unfrozen 对照。

## 5. 暂不执行事项

本计划只定义数据生成和远程实验方案。当前本机阶段不训练 Pcap-Encoder，不跑 Denoiser/QA，不启动 `classification.py`、`train.py`、`accelerate`，也不修改原始 pcap 或已有 parquet/checkpoint。

