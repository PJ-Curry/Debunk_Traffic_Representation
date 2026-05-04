#!/usr/bin/env python3
"""Create USTC-binary field-level masked CSV variants.

Default mode reuses the existing ShallowML raw CSV and aligns each row with the
corresponding pcap packet only to decode protocol fields. This preserves the
existing raw vocabulary ids and split layout.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

try:
    from scapy.all import Ether, IP, IPv6, TCP, UDP, PcapReader
except ImportError as exc:  # pragma: no cover - environment guard.
    raise SystemExit(
        "Missing dependency scapy. Run with the ShallowML environment, for example:\n"
        "  conda run -n shallowml python code/ShallowML/make_ustc_field_masked_csv.py --dry-run --group ip_ttl_protocol"
    ) from exc

from ustc_field_mask_utils import (
    CSV_FILES,
    CURRENT_MASK_TOP_SHORTCUT_COLUMNS,
    default_data_root,
    default_field_mask_root,
    default_group_config_path,
    default_raw_csv_root,
    feature_columns_from_header,
    groups_by_name,
    infer_encoded_zero_value,
    load_group_config,
    resolve_group_columns,
)


def validate_group_name(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        raise argparse.ArgumentTypeError("group name may only contain letters, digits, '.', '_' and '-'")
    return name


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


def padded_bytes(packet, num_columns: int) -> bytes:
    raw = bytes(packet)
    target_len = num_columns * 2
    if len(raw) < target_len:
        raw += b"\x00" * (target_len - len(raw))
    return raw[:target_len]


def bytes_to_columns(byte_start: int, byte_end: int) -> set[int]:
    if byte_end <= byte_start:
        return set()
    return set(range(byte_start // 2, ((byte_end - 1) // 2) + 1))


def field_range(packet, protocol: str, field_name: str) -> tuple[int | None, int | None, bool, str]:
    packet_bytes = bytes(packet)
    if not packet.haslayer(IP):
        return None, None, False, "not IPv4"
    ip_header_len = int(packet[IP].ihl or (packet_bytes[0] & 0x0F)) * 4

    if protocol == "IPv4":
        ranges = {
            "version_ihl": (0, 1),
            "dscp_ecn": (1, 2),
            "total_length": (2, 4),
            "identification": (4, 6),
            "flags_fragment": (6, 8),
            "ttl": (8, 9),
            "protocol": (9, 10),
            "ip_checksum": (10, 12),
            "src_ip": (12, 16),
            "dst_ip": (16, 20),
        }
        if field_name not in ranges:
            return None, None, False, f"unknown IPv4 field {field_name}"
        start, end = ranges[field_name]
        return start, end, len(packet_bytes) >= end, ""

    if protocol == "TCP":
        if not packet.haslayer(TCP):
            return None, None, False, "not TCP"
        tcp_start = ip_header_len
        if len(packet_bytes) < tcp_start + 20:
            return None, None, False, "short TCP header"
        tcp_dataofs = int(packet[TCP].dataofs or (packet_bytes[tcp_start + 12] >> 4))
        tcp_header_len = tcp_dataofs * 4
        tcp_header_end = min(tcp_start + tcp_header_len, len(packet_bytes))
        ranges = {
            "sport": (tcp_start, tcp_start + 2),
            "dport": (tcp_start + 2, tcp_start + 4),
            "seq": (tcp_start + 4, tcp_start + 8),
            "ack": (tcp_start + 8, tcp_start + 12),
            "data_offset_reserved_flags": (tcp_start + 12, tcp_start + 14),
            "window": (tcp_start + 14, tcp_start + 16),
            "tcp_checksum": (tcp_start + 16, tcp_start + 18),
            "urgent_pointer": (tcp_start + 18, tcp_start + 20),
        }
        if field_name == "tcp_options":
            if tcp_header_len <= 20:
                return None, None, False, "no TCP options according to data offset"
            start = tcp_start + 20
            end = tcp_header_end
            return start, end, end > start, "dynamic TCP data offset"
        if field_name not in ranges:
            return None, None, False, f"unknown TCP field {field_name}"
        start, end = ranges[field_name]
        return start, end, len(packet_bytes) >= end, ""

    if protocol == "UDP":
        if not packet.haslayer(UDP):
            return None, None, False, "not UDP"
        udp_start = ip_header_len
        ranges = {
            "sport": (udp_start, udp_start + 2),
            "dport": (udp_start + 2, udp_start + 4),
            "udp_length": (udp_start + 4, udp_start + 6),
            "udp_checksum": (udp_start + 6, udp_start + 8),
        }
        if field_name not in ranges:
            return None, None, False, f"unknown UDP field {field_name}"
        start, end = ranges[field_name]
        return start, end, len(packet_bytes) >= end, ""

    return None, None, False, f"unsupported protocol {protocol}"


def semantic_field_parts(field_def) -> tuple[str, str]:
    if isinstance(field_def, str):
        protocol, field_name = field_def.split(".", 1)
        return protocol, field_name
    protocol = field_def.get("protocol")
    field_name = field_def.get("field_name") or field_def.get("name")
    if not protocol or not field_name:
        raise ValueError(f"invalid semantic field entry: {field_def!r}")
    return str(protocol), str(field_name)


def mask_ranges_for_group(packet, group: dict[str, object]) -> tuple[list[tuple[int, int]], Counter[str]]:
    ranges: list[tuple[int, int]] = []
    skipped: Counter[str] = Counter()
    for field_def in group.get("semantic_fields", []):
        protocol, field_name = semantic_field_parts(field_def)
        start, end, exists, note = field_range(packet, protocol, field_name)
        key = f"{protocol}.{field_name}"
        if exists and start is not None and end is not None and end > start:
            ranges.append((start, end))
        else:
            skipped[f"{key}: {note}"] += 1
    return ranges, skipped


class PcapPacketStreams:
    def __init__(self, split_dir: Path, clean_mode: str):
        self.split_dir = split_dir
        self.clean_mode = clean_mode
        self.readers: dict[str, PcapReader] = {}

    def next_cleaned(self, class_label: str):
        if class_label not in self.readers:
            path = self.split_dir / class_label
            if not path.is_file():
                raise FileNotFoundError(f"pcap for class {class_label!r} not found under {self.split_dir}")
            self.readers[class_label] = PcapReader(str(path))
        reader = self.readers[class_label]
        for packet in reader:
            cleaned = clean_packet(packet, self.clean_mode)
            if cleaned is not None:
                return cleaned
        raise RuntimeError(f"pcap exhausted before CSV rows ended for class {class_label}")

    def close(self) -> None:
        for reader in self.readers.values():
            reader.close()


def split_dir_for_csv(data_root: Path, rel_path: Path) -> Path:
    if rel_path == Path("test.csv"):
        return data_root / "test"
    return data_root / rel_path.parent / rel_path.stem


def csv_num_columns(raw_csv: Path) -> int:
    with raw_csv.open("r", newline="") as file:
        header = next(csv.reader(file))
    return len(feature_columns_from_header(header))


def learn_token_vocab_map(
    raw_root: Path,
    data_root: Path,
    rel_paths: list[Path],
    clean_mode: str,
    max_rows_per_file: int | None,
) -> tuple[dict[str, str], Counter[str]]:
    token_to_value: dict[str, str] = {}
    conflicts: Counter[str] = Counter()
    for rel_path in rel_paths:
        raw_csv = raw_root / rel_path
        split_dir = split_dir_for_csv(data_root, rel_path)
        streams = PcapPacketStreams(split_dir, clean_mode)
        try:
            with raw_csv.open("r", newline="") as file:
                reader = csv.reader(file)
                header = next(reader)
                feature_cols = feature_columns_from_header(header)
                class_index = header.index("class")
                for row_index, row in enumerate(reader):
                    if max_rows_per_file is not None and row_index >= max_rows_per_file:
                        break
                    cleaned = streams.next_cleaned(row[class_index])
                    raw_bytes = padded_bytes(cleaned, len(feature_cols))
                    for col in feature_cols:
                        token = raw_bytes[2 * col : 2 * col + 2].hex()
                        value = row[header.index(str(col))]
                        old_value = token_to_value.setdefault(token, value)
                        if old_value != value:
                            conflicts[token] += 1
        finally:
            streams.close()
    return token_to_value, conflicts


def encode_masked_bytes(
    masked_bytes: bytes,
    feature_cols: list[int],
    token_to_value: dict[str, str],
    fallback_mask_value: str,
) -> list[str]:
    encoded: list[str] = []
    for col in feature_cols:
        token = masked_bytes[2 * col : 2 * col + 2].hex()
        encoded.append(token_to_value.get(token, fallback_mask_value))
    return encoded


@dataclass
class FileStats:
    rows: int = 0
    class_counts: Counter[str] = field(default_factory=Counter)
    changed_cells: int = 0
    changed_rows: int = 0
    non_mask_changed_cells: int = 0
    skipped_fields: Counter[str] = field(default_factory=Counter)
    touched_columns: Counter[str] = field(default_factory=Counter)


def apply_field_zero_mask_to_row(
    row: list[str],
    header: list[str],
    feature_cols: list[int],
    cleaned_packet,
    group: dict[str, object],
    token_to_value: dict[str, str],
    mask_value: str,
) -> tuple[list[str], set[int], Counter[str]]:
    ranges, skipped = mask_ranges_for_group(cleaned_packet, group)
    touched_cols: set[int] = set()
    raw_bytes = bytearray(padded_bytes(cleaned_packet, len(feature_cols)))
    for start, end in ranges:
        clipped_start = max(0, min(start, len(raw_bytes)))
        clipped_end = max(0, min(end, len(raw_bytes)))
        for index in range(clipped_start, clipped_end):
            raw_bytes[index] = 0
        touched_cols.update(bytes_to_columns(clipped_start, clipped_end))

    new_feature_values = encode_masked_bytes(bytes(raw_bytes), feature_cols, token_to_value, mask_value)
    new_row = list(row)
    for col, value in zip(feature_cols, new_feature_values):
        new_row[header.index(str(col))] = value
    return new_row, touched_cols, skipped


def apply_column_mask_to_rows(
    rows: list[list[str]],
    header: list[str],
    columns: list[int],
    mask_mode: str,
    mask_value: str,
    encoded_zero_value: str,
    rng: random.Random,
) -> tuple[list[list[str]], list[set[int]]]:
    mask_indexes = [header.index(str(col)) for col in columns]
    touched_by_row = [set(columns) for _ in rows]
    output = [list(row) for row in rows]

    if mask_mode in {"zero", "normalize"}:
        value = encoded_zero_value if mask_mode == "zero" else mask_value
        for row in output:
            for index in mask_indexes:
                row[index] = value
        return output, touched_by_row

    if mask_mode == "randomize":
        pools = {index: [row[index] for row in rows] for index in mask_indexes}
        for row in output:
            for index in mask_indexes:
                row[index] = rng.choice(pools[index])
        return output, touched_by_row

    if mask_mode == "permute":
        for index in mask_indexes:
            values = [row[index] for row in rows]
            rng.shuffle(values)
            for row, value in zip(output, values):
                row[index] = value
        return output, touched_by_row

    raise ValueError(f"unsupported mask mode for column mask: {mask_mode}")


def summarize_changes(
    original: list[str],
    masked: list[str],
    header: list[str],
    touched_cols: set[int],
    stats: FileStats,
) -> None:
    row_changed = False
    for col in feature_columns_from_header(header):
        index = header.index(str(col))
        if original[index] != masked[index]:
            stats.changed_cells += 1
            row_changed = True
            if col not in touched_cols:
                stats.non_mask_changed_cells += 1
    if row_changed:
        stats.changed_rows += 1
    for col in touched_cols:
        stats.touched_columns[str(col)] += 1


def read_rows(raw_csv: Path, max_rows: int | None) -> tuple[list[str], list[list[str]]]:
    with raw_csv.open("r", newline="") as file:
        reader = csv.reader(file)
        header = next(reader)
        rows = []
        for row_index, row in enumerate(reader):
            if max_rows is not None and row_index >= max_rows:
                break
            rows.append(row)
    return header, rows


def write_rows(path: Path, header: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(header)
        writer.writerows(rows)


def process_file(
    rel_path: Path,
    raw_root: Path,
    target_root: Path,
    data_root: Path,
    group: dict[str, object],
    mask_kind: str,
    mask_value: str,
    encoded_zero_value: str,
    token_to_value: dict[str, str],
    clean_mode: str,
    sample_rows_per_file: int | None,
    dry_run: bool,
    rng: random.Random,
) -> FileStats:
    raw_csv = raw_root / rel_path
    if not raw_csv.is_file():
        raise FileNotFoundError(f"missing raw CSV: {raw_csv}")
    header, rows = read_rows(raw_csv, sample_rows_per_file)
    class_index = header.index("class")
    feature_cols = feature_columns_from_header(header)
    stats = FileStats(rows=len(rows))
    for row in rows:
        stats.class_counts[row[class_index]] += 1

    if mask_kind == "column" or group.get("group_name") in {"current_mask_top_shortcut_columns", "random_same_size"}:
        columns = resolve_group_columns(group, feature_cols)
        missing = [col for col in columns if str(col) not in header]
        if missing:
            raise ValueError(f"{raw_csv} is missing columns {missing}")
        masked_rows, touched_sets = apply_column_mask_to_rows(
            rows,
            header,
            columns,
            str(group.get("mask_mode", "zero")),
            mask_value,
            encoded_zero_value,
            rng,
        )
        for original, masked, touched in zip(rows, masked_rows, touched_sets):
            summarize_changes(original, masked, header, touched, stats)
    else:
        split_dir = split_dir_for_csv(data_root, rel_path)
        streams = PcapPacketStreams(split_dir, clean_mode)
        masked_rows = []
        try:
            for row in rows:
                cleaned = streams.next_cleaned(row[class_index])
                masked, touched_cols, skipped = apply_field_zero_mask_to_row(
                    row,
                    header,
                    feature_cols,
                    cleaned,
                    group,
                    token_to_value,
                    mask_value,
                )
                masked_rows.append(masked)
                stats.skipped_fields.update(skipped)
                summarize_changes(row, masked, header, touched_cols, stats)
        finally:
            streams.close()

    if not dry_run:
        write_rows(target_root / rel_path, header, masked_rows)
    return stats


def merge_stats(stats_by_file: dict[str, FileStats]) -> dict[str, object]:
    total = FileStats()
    for stats in stats_by_file.values():
        total.rows += stats.rows
        total.class_counts.update(stats.class_counts)
        total.changed_cells += stats.changed_cells
        total.changed_rows += stats.changed_rows
        total.non_mask_changed_cells += stats.non_mask_changed_cells
        total.skipped_fields.update(stats.skipped_fields)
        total.touched_columns.update(stats.touched_columns)
    return {
        "rows": total.rows,
        "class_counts": dict(sorted(total.class_counts.items())),
        "changed_cells": total.changed_cells,
        "changed_rows": total.changed_rows,
        "non_mask_changed_cells": total.non_mask_changed_cells,
        "skipped_fields": dict(total.skipped_fields.most_common(20)),
        "touched_columns": dict(sorted(total.touched_columns.items(), key=lambda item: int(item[0]))),
    }


def selected_csv_files(split: str | None) -> list[Path]:
    if split is None or split == "all":
        return list(CSV_FILES)
    if split == "test":
        return [Path("test.csv")]
    if split in {"0", "1", "2"}:
        return [Path(f"train_val_split_{split}/train.csv"), Path(f"train_val_split_{split}/val.csv"), Path("test.csv")]
    raise ValueError("--split must be one of all, test, 0, 1, 2")


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--group", required=True, type=validate_group_name)
    parser.add_argument("--mask-kind", choices=["field", "column"], default="field")
    parser.add_argument("--config", type=Path, default=default_group_config_path())
    parser.add_argument("--raw-root", type=Path, default=default_raw_csv_root())
    parser.add_argument("--data-root", type=Path, default=default_data_root())
    parser.add_argument("--output-root", type=Path, default=default_field_mask_root())
    parser.add_argument("--clean-mode", choices=["shallowml", "pcapencoder"], default="shallowml")
    parser.add_argument("--mask-value", default="-1")
    parser.add_argument("--sample-rows-per-file", type=int, default=None)
    parser.add_argument("--sample", type=int, default=None, help="alias for --sample-rows-per-file")
    parser.add_argument("--split", default="all", help="all, test, 0, 1, or 2")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--seed", type=int, default=43)
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    sample_rows = args.sample_rows_per_file if args.sample_rows_per_file is not None else args.sample
    if sample_rows is not None and sample_rows <= 0:
        print("sample row count must be positive", file=sys.stderr)
        return 2

    config = load_group_config(args.config)
    groups = groups_by_name(config)
    if args.group not in groups:
        print(f"unknown group {args.group!r}; available={','.join(sorted(groups))}", file=sys.stderr)
        return 2
    group = groups[args.group]

    raw_root = args.raw_root.resolve()
    data_root = args.data_root.resolve()
    target_root = (args.output_root / args.group).resolve()
    rel_paths = selected_csv_files(args.split)

    if not raw_root.is_dir():
        print(f"raw CSV root does not exist: {raw_root}", file=sys.stderr)
        return 2
    if not data_root.is_dir():
        print(f"pcap data root does not exist: {data_root}", file=sys.stderr)
        return 2
    if target_root.exists() and any(target_root.iterdir()) and not args.dry_run and not args.overwrite:
        print(f"refusing to overwrite non-empty output directory: {target_root}", file=sys.stderr)
        return 2

    zero_source = raw_root / "test.csv"
    encoded_zero_value = infer_encoded_zero_value(zero_source)
    token_to_value: dict[str, str] = {}
    vocab_conflicts: Counter[str] = Counter()
    if args.mask_kind == "field" and group.get("group_name") not in {"current_mask_top_shortcut_columns", "random_same_size"}:
        token_to_value, vocab_conflicts = learn_token_vocab_map(
            raw_root,
            data_root,
            rel_paths,
            args.clean_mode,
            sample_rows,
        )
        if "0000" in token_to_value:
            encoded_zero_value = token_to_value["0000"]
        if vocab_conflicts:
            print(f"WARNING: token vocab conflicts detected: {dict(vocab_conflicts.most_common(5))}", file=sys.stderr)

    rng = random.Random(args.seed)
    stats_by_file: dict[str, FileStats] = {}
    for rel_path in rel_paths:
        stats = process_file(
            rel_path=rel_path,
            raw_root=raw_root,
            target_root=target_root,
            data_root=data_root,
            group=group,
            mask_kind=args.mask_kind,
            mask_value=args.mask_value,
            encoded_zero_value=encoded_zero_value,
            token_to_value=token_to_value,
            clean_mode=args.clean_mode,
            sample_rows_per_file=sample_rows,
            dry_run=args.dry_run,
            rng=rng,
        )
        stats_by_file[rel_path.as_posix()] = stats

    summary = {
        "group": args.group,
        "mask_kind": args.mask_kind,
        "mask_mode": group.get("mask_mode"),
        "dry_run": args.dry_run,
        "sample_rows_per_file": sample_rows,
        "clean_mode": args.clean_mode,
        "raw_root": str(raw_root),
        "output_dir": str(target_root),
        "encoded_zero_value": encoded_zero_value,
        "token_vocab_size_observed": len(token_to_value),
        "files": {
            path: {
                "rows": stats.rows,
                "class_counts": dict(sorted(stats.class_counts.items())),
                "changed_cells": stats.changed_cells,
                "changed_rows": stats.changed_rows,
                "non_mask_changed_cells": stats.non_mask_changed_cells,
                "skipped_fields_top": dict(stats.skipped_fields.most_common(10)),
                "touched_columns": dict(sorted(stats.touched_columns.items(), key=lambda item: int(item[0]))),
            }
            for path, stats in stats_by_file.items()
        },
        "total": merge_stats(stats_by_file),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))

    if not args.dry_run and summary["total"]["changed_cells"] == 0:
        print("WARNING: no cells changed; check whether this group applies to the selected protocol/files", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
