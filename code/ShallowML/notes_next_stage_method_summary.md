# 下一阶段方法总结

日期：2026-05-04

## 1. 为什么现在不能只说 mask_top_shortcut 就是 shortcut

`mask_top_shortcut = 4,16,17,20,21,22,23,24,25` 已经是很有价值的阶段性证据：ShallowML 平均 macro F1 下降约 3.57 pp，Pcap-Encoder medium QA 50k 三 split 平均下降约 4.75 pp。

但它还不能直接等同于“这些列就是 shortcut”。原因有三点：

- 它是人工/半人工 column 组合，来自 importance 和单列诊断的经验 union。
- 固定 column 解释依赖 IPv4/IHL=5/TCP data offset 足够长；短 TCP header 时 columns 20-25 在 Pcap-Encoder 可能进入 payload。
- 遮掉后下降只说明模型依赖这些信息，不自动说明这些信息全是非语义 shortcut；例如 total length 可能既是合法任务信号，也可能是数据集 artifact。

## 2. Field-level decoding mask 解决的严谨性问题

field-level decoding mask 把“遮第几列”升级成“遮哪个协议字段”。它先用 Scapy 解码 IPv4/TCP/UDP header，再按字段 byte range mask，最后映射回 ShallowML token 或 Pcap-Encoder byte input。

它解决的问题：

- TCP options 用 `dataofs` 动态定位，不把 payload 或 padding 误当作 options。
- UDP 包没有 TCP 字段时跳过并记录，而不是盲目遮固定 offset。
- ShallowML 删除 payload、Pcap-Encoder 保留 payload 的差异被显式记录。
- 后续 w/o IP、w/o header、w/o payload、w/o options 能形成同一套 field semantics。

## 3. ShortcutScore 解决的人工策略问题

ShortcutScore 的目标是把“拍脑袋选 mask group”改成可解释 scoring。当前公式综合：

- Predictability：只用该 group 是否能预测标签。
- Importance：raw lightweight RF 是否把 importance 集中在该 group。
- PerturbSensitivity：raw-trained 模型在 test-only perturb 后是否明显下降。
- CrossSplitStability：上述信号是否跨 split 稳定。
- SemanticRisk：字段语义是否容易代表 OS、路径、协议栈或采集环境 artifact。

这样可以把 `current_mask_top_shortcut_columns` 放在自动排名中，而不是让它永远作为唯一候选。

## 4. Test-only perturbation 解决的泛化证据问题

重新训练 masked 数据后的下降，不一定全是 shortcut 证据；模型可能因为训练分布改变、优化波动或可替代特征变化而升降。

test-only perturbation 更直接：先训练 raw lightweight model，再只扰动 test 的某个 group。如果 raw-trained model 的 macro F1 明显下降，说明模型推理时确实依赖该 group。它适合作为后续深度模型 stress test 的低成本预演。

## 5. 下一步远程 GPU 要验证什么

远程 GPU 阶段应验证三件事：

1. field-level mask 是否复现 manual `mask_top_shortcut` 的下降方向，并避免 payload 误伤。
2. ShortcutScore 自动选出的 top group 是否比 manual mask 更小、更稳定或更语义清晰。
3. 在 bigger QA checkpoint、50k/full classification、多 split 或多 seed 下，raw vs manual mask vs auto mask vs random mask 的相对关系是否稳定。

只有当自动 field-level group 在 ShallowML scoring、test-only perturbation 和 Pcap-Encoder downstream 中都稳定表现出高敏感性，才适合把它写成更强的 shortcut-discovery 方法贡献。

