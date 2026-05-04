# USTC-binary Field-Column Mapping

生成日期：2026-05-04

## 1. Scope

- 输入 pcap 根目录：`/home/a/traffic_encryption/debunk_data/Debunk_Traffic_Representation/packet-level-classification/per-flow-split/ustc-binary`
- clean mode：`shallowml`
- 每个 pcap 文件最多抽样：`1000` packets
- 实际保留 packet 数：`14000`
- 输出 CSV：`/home/a/traffic_encryption/Debunk_Traffic_Representation/code/ShallowML/field_column_mapping_ustc_sample.csv`

本脚本复用当前项目里的两套 clean 语义，并默认使用 ShallowML raw 语义做 field-column mapping：去 Ethernet，IP/IPv6 地址置零，TCP/UDP 端口置零，并删除 TCP/UDP payload。Pcap-Encoder 的 prepare 脚本同样去 Ethernet、置零 IP 和端口，但保留 payload；因此同一个 byte offset 在 Pcap-Encoder 中可能进入 payload，而在 ShallowML 中会变成 header 后的 padding。

column 与 byte offset 的关系是：`column k = cleaned_bytes[2k:2k+2]`。

## 2. Sample Summary

- protocol counts：TCP: 12601, UDP: 1399
- IPv4 IHL counts：5: 14000
- TCP data offset counts：8: 7465, 5: 3286, 7: 1453, 6: 200, 9: 195, 10: 2
- cleaned byte-length counts：52: 7465, 40: 3286, 48: 1453, 28: 1399, 44: 200, 56: 195, 60: 2

## 3. current mask_top_shortcut 对应字段

| column | byte offsets | stable/common interpretation | sampled dominant decoded fields |
|---:|---|---|---|
| 4 | 8-9 | IPv4 bytes 8-9: TTL + protocol | IPv4.ttl: 14000, IPv4.protocol: 14000 |
| 16 | 32-33 | TCP bytes 12-13 after IPv4/IHL=5: data offset/reserved/flags | TCP.data_offset_reserved_flags: 12601 |
| 17 | 34-35 | TCP bytes 14-15 after IPv4/IHL=5: window | TCP.window: 12601 |
| 20 | 40-41 | TCP option bytes 0-1 when TCP data offset >= 6 | TCP.tcp_options: 9315 |
| 21 | 42-43 | TCP option bytes 2-3 when TCP data offset >= 6 | TCP.tcp_options: 9315 |
| 22 | 44-45 | TCP option bytes 4-5 when TCP data offset >= 7 | TCP.tcp_options: 9115 |
| 23 | 46-47 | TCP option bytes 6-7 when TCP data offset >= 7 | TCP.tcp_options: 9115 |
| 24 | 48-49 | TCP option bytes 8-9 when TCP data offset >= 8 | TCP.tcp_options: 7662 |
| 25 | 50-51 | TCP option bytes 10-11 when TCP data offset >= 8 | TCP.tcp_options: 7662 |

在常见 IPv4/IHL=5/TCP 包中，当前 `mask_top_shortcut = 4,16,17,20,21,22,23,24,25` 大致覆盖：

- column `4`：IPv4 TTL + protocol。这个位置稳定属于 IPv4 header。
- column `16`：TCP data offset / reserved / flags。IPv4 IHL=5 时稳定属于 TCP header。
- column `17`：TCP window。IPv4 IHL=5 时稳定属于 TCP header。
- columns `20-25`：当 TCP data offset 至少为 8，也就是 TCP header 至少 32 bytes 时，这些列属于 TCP options；如果 TCP header 较短，则这些固定 columns 不再一定是 options。

## 4. Header 与 payload 边界

稳定 header 位置：IPv4 base header 的 columns `0-9`，以及 IPv4/IHL=5 下 TCP base header 的 columns `10-19`，前提是 packet 确实是 IPv4/TCP 且没有 IP options。

需要动态判断的位置：TCP options 必须通过 TCP `dataofs` 计算，范围是 `ip_header_len + 20` 到 `ip_header_len + tcp_dataofs * 4`。固定遮 `20-25` 只在 TCP header 足够长时等价于 options。

短 TCP header 风险：当 TCP data offset 为 5 时，TCP header 只有 20 bytes，columns `20-25` 在 Pcap-Encoder 输入中会落入 TCP payload；在 ShallowML raw 中 payload 已删除，这些列会落到 header 后的 zero padding。两种表示的语义不同，因此固定 column mask 不够严谨。

## 5. 为什么 field-level decoding mask 更严谨

field-level mask 先用 Scapy 解码实际协议层和 header 长度，再决定要 mask 哪些 byte range。这样可以：

- 对 TCP options 做动态定位，避免把 payload 当成 options。
- 在 UDP 包上跳过 TCP-only 字段，并记录 skip，而不是盲目遮固定 offset。
- 在存在 IP options、IPv6 或异常 header layout 时显式标记语义不适用。
- 让 ShallowML 的 16-bit token mask 与 Pcap-Encoder 的 byte-level mask 有同一套字段语义，便于后续做 w/o IP、w/o header、w/o payload 风格的 ablation 对齐。
