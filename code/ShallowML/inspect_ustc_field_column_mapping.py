#!/usr/bin/env python3
"""Inspect USTC-binary protocol fields and their ShallowML token columns."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

try:
    from scapy.all import Ether, IP, IPv6, TCP, UDP, PcapReader
except ImportError as exc:  # pragma: no cover - environment guard.
    raise SystemExit(
        "Missing dependency scapy. Run with the ShallowML environment, for example:\n"
        "  conda run -n shallowml python code/ShallowML/inspect_ustc_field_column_mapping.py"
    ) from exc

from ustc_field_mask_utils import CURRENT_MASK_TOP_SHORTCUT_COLUMNS, default_data_root, shallowml_dir


IPV4_FIELDS = [
    "version_ihl",
    "dscp_ecn",
    "total_length",
    "identification",
    "flags_fragment",
    "ttl",
    "protocol",
    "ip_checksum",
    "src_ip",
    "dst_ip",
]
TCP_FIELDS = [
    "sport",
    "dport",
    "seq",
    "ack",
    "data_offset_reserved_flags",
    "window",
    "tcp_checksum",
    "urgent_pointer",
    "tcp_options",
    "tcp_payload_range",
]
UDP_FIELDS = ["sport", "dport", "udp_length", "udp_checksum", "udp_payload_range"]


def column_span(byte_start: int | None, byte_end: int | None) -> str:
    if byte_start is None or byte_end is None or byte_end <= byte_start:
        return ""
    first = byte_start // 2
    last = (byte_end - 1) // 2
    return ",".join(str(index) for index in range(first, last + 1))


def clean_packet(packet, clean_mode: str):
    pkt = packet.copy()
    if pkt.haslayer(Ether):
        pkt = pkt[Ether].payload

    if pkt.haslayer(IP):
        pkt[IP].src = "0.0.0.0"
        pkt[IP].dst = "0.0.0.0"
    elif pkt.haslayer(IPv6):
        pkt[IPv6].src = "::"
        pkt[IPv6].dst = "::"
    else:
        return None

    if pkt.haslayer(UDP):
        pkt[UDP].sport = 0
        pkt[UDP].dport = 0
        if clean_mode == "shallowml":
            pkt[UDP].remove_payload()
    elif pkt.haslayer(TCP):
        pkt[TCP].sport = 0
        pkt[TCP].dport = 0
        if clean_mode == "shallowml":
            pkt[TCP].remove_payload()

    return pkt


def protocol_name(packet) -> str:
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(IP):
        return f"IP-proto-{packet[IP].proto}"
    if packet.haslayer(IPv6):
        return "IPv6"
    return "unknown"


def add_row(
    rows: list[dict[str, object]],
    packet_meta: dict[str, object],
    protocol: str,
    field_name: str,
    byte_start: int | None,
    byte_end: int | None,
    exists: bool,
    note: str = "",
) -> None:
    rows.append(
        {
            **packet_meta,
            "protocol": protocol,
            "field_name": field_name,
            "byte_start": "" if byte_start is None else byte_start,
            "byte_end": "" if byte_end is None else byte_end,
            "columns_touched": column_span(byte_start, byte_end) if exists else "",
            "exists": str(bool(exists)).lower(),
            "note": note,
        }
    )


def field_rows_for_packet(
    cleaned_packet,
    original_packet,
    packet_meta: dict[str, object],
    clean_mode: str,
) -> tuple[list[dict[str, object]], dict[str, object]]:
    rows: list[dict[str, object]] = []
    packet_bytes = bytes(cleaned_packet)
    original_network = original_packet[Ether].payload if original_packet.haslayer(Ether) else original_packet
    protocol = protocol_name(cleaned_packet)
    packet_stats: dict[str, object] = {
        "protocol": protocol,
        "cleaned_len": len(packet_bytes),
    }

    if cleaned_packet.haslayer(IP):
        ihl = int(cleaned_packet[IP].ihl or (packet_bytes[0] & 0x0F))
        ip_header_len = ihl * 4
        packet_stats["ip_ihl"] = ihl
        ipv4_ranges = {
            "version_ihl": (0, 1, "first byte: version + IHL"),
            "dscp_ecn": (1, 2, "second byte: DSCP + ECN"),
            "total_length": (2, 4, ""),
            "identification": (4, 6, ""),
            "flags_fragment": (6, 8, "flags + fragment offset"),
            "ttl": (8, 9, ""),
            "protocol": (9, 10, ""),
            "ip_checksum": (10, 12, "checksum value retained from original packet after address zeroing"),
            "src_ip": (12, 16, "zeroed by clean_packet"),
            "dst_ip": (16, 20, "zeroed by clean_packet"),
        }
        for field in IPV4_FIELDS:
            start, end, note = ipv4_ranges[field]
            add_row(rows, packet_meta, "IPv4", field, start, min(end, len(packet_bytes)), len(packet_bytes) >= end, note)

        if ip_header_len > 20:
            packet_stats["ip_options_len"] = ip_header_len - 20
    else:
        for field in IPV4_FIELDS:
            add_row(rows, packet_meta, "IPv4", field, None, None, False, "not an IPv4 packet")
        ip_header_len = 40 if cleaned_packet.haslayer(IPv6) else 0
        packet_stats["ip_ihl"] = None

    if cleaned_packet.haslayer(TCP) and cleaned_packet.haslayer(IP):
        tcp = cleaned_packet[TCP]
        tcp_start = ip_header_len
        tcp_dataofs = int(tcp.dataofs or (packet_bytes[tcp_start + 12] >> 4))
        tcp_header_len = tcp_dataofs * 4
        tcp_header_end = tcp_start + tcp_header_len
        packet_stats["tcp_dataofs"] = tcp_dataofs
        tcp_ranges = {
            "sport": (tcp_start, tcp_start + 2, "zeroed by clean_packet"),
            "dport": (tcp_start + 2, tcp_start + 4, "zeroed by clean_packet"),
            "seq": (tcp_start + 4, tcp_start + 8, ""),
            "ack": (tcp_start + 8, tcp_start + 12, ""),
            "data_offset_reserved_flags": (tcp_start + 12, tcp_start + 14, ""),
            "window": (tcp_start + 14, tcp_start + 16, ""),
            "tcp_checksum": (tcp_start + 16, tcp_start + 18, "checksum value retained from original packet after port zeroing"),
            "urgent_pointer": (tcp_start + 18, tcp_start + 20, ""),
        }
        for field in TCP_FIELDS:
            if field == "tcp_options":
                exists = tcp_header_len > 20 and len(packet_bytes) >= tcp_start + 20
                start = tcp_start + 20 if exists else None
                end = min(tcp_header_end, len(packet_bytes)) if exists else None
                note = "dynamic range from TCP data offset"
                add_row(rows, packet_meta, "TCP", field, start, end, bool(exists and end and end > start), note)
            elif field == "tcp_payload_range":
                payload_start = tcp_header_end
                payload_end = len(packet_bytes)
                exists = payload_end > payload_start
                if clean_mode == "shallowml":
                    original_payload_len = 0
                    if original_network.haslayer(TCP):
                        original_payload_len = len(bytes(original_network[TCP].payload))
                    note = f"payload removed by ShallowML clean mode; original TCP payload bytes={original_payload_len}"
                    add_row(rows, packet_meta, "TCP", field, None, None, False, note)
                else:
                    add_row(rows, packet_meta, "TCP", field, payload_start, payload_end, exists, "payload retained by Pcap-Encoder clean mode")
            else:
                start, end, note = tcp_ranges[field]
                add_row(rows, packet_meta, "TCP", field, start, min(end, len(packet_bytes)), len(packet_bytes) >= end, note)
    else:
        for field in TCP_FIELDS:
            add_row(rows, packet_meta, "TCP", field, None, None, False, "not a TCP/IPv4 packet")

    if cleaned_packet.haslayer(UDP) and cleaned_packet.haslayer(IP):
        udp_start = ip_header_len
        udp_ranges = {
            "sport": (udp_start, udp_start + 2, "zeroed by clean_packet"),
            "dport": (udp_start + 2, udp_start + 4, "zeroed by clean_packet"),
            "udp_length": (udp_start + 4, udp_start + 6, ""),
            "udp_checksum": (udp_start + 6, udp_start + 8, "checksum value retained from original packet after port zeroing"),
        }
        for field in UDP_FIELDS:
            if field == "udp_payload_range":
                payload_start = udp_start + 8
                payload_end = len(packet_bytes)
                exists = payload_end > payload_start
                if clean_mode == "shallowml":
                    original_payload_len = 0
                    if original_network.haslayer(UDP):
                        original_payload_len = len(bytes(original_network[UDP].payload))
                    note = f"payload removed by ShallowML clean mode; original UDP payload bytes={original_payload_len}"
                    add_row(rows, packet_meta, "UDP", field, None, None, False, note)
                else:
                    add_row(rows, packet_meta, "UDP", field, payload_start, payload_end, exists, "payload retained by Pcap-Encoder clean mode")
            else:
                start, end, note = udp_ranges[field]
                add_row(rows, packet_meta, "UDP", field, start, min(end, len(packet_bytes)), len(packet_bytes) >= end, note)
    else:
        for field in UDP_FIELDS:
            add_row(rows, packet_meta, "UDP", field, None, None, False, "not a UDP/IPv4 packet")

    return rows, packet_stats


def pcap_jobs(data_root: Path) -> list[tuple[str, str, str, Path]]:
    jobs: list[tuple[str, str, str, Path]] = []
    for split_dir in sorted(data_root.glob("train_val_split_*")):
        split = split_dir.name.replace("train_val_split_", "split")
        for subset in ("train", "val"):
            subset_dir = split_dir / subset
            for pcap_path in sorted(subset_dir.glob("*.pcap")):
                jobs.append((split, subset, pcap_path.name, pcap_path))
    test_dir = data_root / "test"
    for pcap_path in sorted(test_dir.glob("*.pcap")):
        jobs.append(("test", "test", pcap_path.name, pcap_path))
    return jobs


def inspect_pcaps(
    data_root: Path,
    max_packets_per_file: int,
    clean_mode: str,
) -> tuple[list[dict[str, object]], dict[str, object]]:
    rows: list[dict[str, object]] = []
    stats: dict[str, object] = {
        "packet_count": 0,
        "protocol_counts": Counter(),
        "ip_ihl_counts": Counter(),
        "tcp_dataofs_counts": Counter(),
        "cleaned_len_counts": Counter(),
        "field_column_counts": defaultdict(Counter),
        "jobs": [],
    }
    packet_id = 0

    for split, subset, class_name, pcap_path in pcap_jobs(data_root):
        kept = 0
        with PcapReader(str(pcap_path)) as reader:
            for source_index, packet in enumerate(reader):
                if kept >= max_packets_per_file:
                    break
                cleaned = clean_packet(packet, clean_mode=clean_mode)
                if cleaned is None:
                    continue
                meta = {
                    "packet_id": packet_id,
                    "split": split,
                    "subset": subset,
                    "class": class_name,
                }
                packet_rows, packet_stats = field_rows_for_packet(cleaned, packet, meta, clean_mode)
                rows.extend(packet_rows)
                packet_id += 1
                kept += 1
                stats["packet_count"] += 1
                stats["protocol_counts"][packet_stats["protocol"]] += 1
                stats["cleaned_len_counts"][str(packet_stats["cleaned_len"])] += 1
                if packet_stats.get("ip_ihl") is not None:
                    stats["ip_ihl_counts"][str(packet_stats["ip_ihl"])] += 1
                if packet_stats.get("tcp_dataofs") is not None:
                    stats["tcp_dataofs_counts"][str(packet_stats["tcp_dataofs"])] += 1
                for row in packet_rows:
                    if row["exists"] != "true":
                        continue
                    for col in str(row["columns_touched"]).split(","):
                        if col:
                            stats["field_column_counts"][col][f"{row['protocol']}.{row['field_name']}"] += 1
        stats["jobs"].append(
            {
                "split": split,
                "subset": subset,
                "class": class_name,
                "pcap": str(pcap_path),
                "packets": kept,
            }
        )
        print(f"{split}/{subset}/{class_name}: sampled {kept} packets")

    return rows, stats


def write_mapping_csv(rows: list[dict[str, object]], output_csv: Path) -> None:
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "packet_id",
        "split",
        "subset",
        "class",
        "protocol",
        "field_name",
        "byte_start",
        "byte_end",
        "columns_touched",
        "exists",
        "note",
    ]
    with output_csv.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _format_counter(counter: Counter) -> str:
    if not counter:
        return "none"
    return ", ".join(f"{key}: {value}" for key, value in counter.most_common())


def current_column_table(stats: dict[str, object]) -> list[str]:
    lines = [
        "| column | byte offsets | stable/common interpretation | sampled dominant decoded fields |",
        "|---:|---|---|---|",
    ]
    static_notes = {
        4: "IPv4 bytes 8-9: TTL + protocol",
        16: "TCP bytes 12-13 after IPv4/IHL=5: data offset/reserved/flags",
        17: "TCP bytes 14-15 after IPv4/IHL=5: window",
        20: "TCP option bytes 0-1 when TCP data offset >= 6",
        21: "TCP option bytes 2-3 when TCP data offset >= 6",
        22: "TCP option bytes 4-5 when TCP data offset >= 7",
        23: "TCP option bytes 6-7 when TCP data offset >= 7",
        24: "TCP option bytes 8-9 when TCP data offset >= 8",
        25: "TCP option bytes 10-11 when TCP data offset >= 8",
    }
    field_column_counts = stats["field_column_counts"]
    for col in CURRENT_MASK_TOP_SHORTCUT_COLUMNS:
        dominant = _format_counter(field_column_counts.get(str(col), Counter()))
        lines.append(f"| {col} | {2 * col}-{2 * col + 1} | {static_notes[col]} | {dominant} |")
    return lines


def write_report(output_md: Path, output_csv: Path, stats: dict[str, object], args: argparse.Namespace) -> None:
    output_md.parent.mkdir(parents=True, exist_ok=True)
    packet_count = stats["packet_count"]
    lines = [
        "# USTC-binary Field-Column Mapping",
        "",
        f"生成日期：2026-05-04",
        "",
        "## 1. Scope",
        "",
        f"- 输入 pcap 根目录：`{args.data_root}`",
        f"- clean mode：`{args.clean_mode}`",
        f"- 每个 pcap 文件最多抽样：`{args.max_packets_per_file}` packets",
        f"- 实际保留 packet 数：`{packet_count}`",
        f"- 输出 CSV：`{output_csv}`",
        "",
        "本脚本复用当前项目里的两套 clean 语义，并默认使用 ShallowML raw 语义做 field-column mapping：去 Ethernet，IP/IPv6 地址置零，TCP/UDP 端口置零，并删除 TCP/UDP payload。Pcap-Encoder 的 prepare 脚本同样去 Ethernet、置零 IP 和端口，但保留 payload；因此同一个 byte offset 在 Pcap-Encoder 中可能进入 payload，而在 ShallowML 中会变成 header 后的 padding。",
        "",
        "column 与 byte offset 的关系是：`column k = cleaned_bytes[2k:2k+2]`。",
        "",
        "## 2. Sample Summary",
        "",
        f"- protocol counts：{_format_counter(stats['protocol_counts'])}",
        f"- IPv4 IHL counts：{_format_counter(stats['ip_ihl_counts'])}",
        f"- TCP data offset counts：{_format_counter(stats['tcp_dataofs_counts'])}",
        f"- cleaned byte-length counts：{_format_counter(stats['cleaned_len_counts'])}",
        "",
        "## 3. current mask_top_shortcut 对应字段",
        "",
        *current_column_table(stats),
        "",
        "在常见 IPv4/IHL=5/TCP 包中，当前 `mask_top_shortcut = 4,16,17,20,21,22,23,24,25` 大致覆盖：",
        "",
        "- column `4`：IPv4 TTL + protocol。这个位置稳定属于 IPv4 header。",
        "- column `16`：TCP data offset / reserved / flags。IPv4 IHL=5 时稳定属于 TCP header。",
        "- column `17`：TCP window。IPv4 IHL=5 时稳定属于 TCP header。",
        "- columns `20-25`：当 TCP data offset 至少为 8，也就是 TCP header 至少 32 bytes 时，这些列属于 TCP options；如果 TCP header 较短，则这些固定 columns 不再一定是 options。",
        "",
        "## 4. Header 与 payload 边界",
        "",
        "稳定 header 位置：IPv4 base header 的 columns `0-9`，以及 IPv4/IHL=5 下 TCP base header 的 columns `10-19`，前提是 packet 确实是 IPv4/TCP 且没有 IP options。",
        "",
        "需要动态判断的位置：TCP options 必须通过 TCP `dataofs` 计算，范围是 `ip_header_len + 20` 到 `ip_header_len + tcp_dataofs * 4`。固定遮 `20-25` 只在 TCP header 足够长时等价于 options。",
        "",
        "短 TCP header 风险：当 TCP data offset 为 5 时，TCP header 只有 20 bytes，columns `20-25` 在 Pcap-Encoder 输入中会落入 TCP payload；在 ShallowML raw 中 payload 已删除，这些列会落到 header 后的 zero padding。两种表示的语义不同，因此固定 column mask 不够严谨。",
        "",
        "## 5. 为什么 field-level decoding mask 更严谨",
        "",
        "field-level mask 先用 Scapy 解码实际协议层和 header 长度，再决定要 mask 哪些 byte range。这样可以：",
        "",
        "- 对 TCP options 做动态定位，避免把 payload 当成 options。",
        "- 在 UDP 包上跳过 TCP-only 字段，并记录 skip，而不是盲目遮固定 offset。",
        "- 在存在 IP options、IPv6 或异常 header layout 时显式标记语义不适用。",
        "- 让 ShallowML 的 16-bit token mask 与 Pcap-Encoder 的 byte-level mask 有同一套字段语义，便于后续做 w/o IP、w/o header、w/o payload 风格的 ablation 对齐。",
    ]
    output_md.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=default_data_root())
    parser.add_argument("--max-packets-per-file", type=int, default=1000)
    parser.add_argument("--clean-mode", choices=["shallowml", "pcapencoder"], default="shallowml")
    parser.add_argument(
        "--output-csv",
        type=Path,
        default=shallowml_dir() / "field_column_mapping_ustc_sample.csv",
    )
    parser.add_argument(
        "--output-md",
        type=Path,
        default=shallowml_dir() / "notes_field_column_mapping.md",
    )
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    if args.max_packets_per_file <= 0:
        print("--max-packets-per-file must be positive", file=sys.stderr)
        return 2
    data_root = args.data_root.resolve()
    if not data_root.is_dir():
        print(f"data root does not exist: {data_root}", file=sys.stderr)
        return 2

    rows, stats = inspect_pcaps(data_root, args.max_packets_per_file, args.clean_mode)
    write_mapping_csv(rows, args.output_csv)
    write_report(args.output_md, args.output_csv, stats, args)
    print(json.dumps({"rows": len(rows), "packets": stats["packet_count"], "csv": str(args.output_csv), "report": str(args.output_md)}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

