#!/usr/bin/env python3
"""Shared helpers for USTC-binary field-mask and shortcut-scoring scripts."""

from __future__ import annotations

import csv
import json
import random
from collections import Counter
from pathlib import Path
from typing import Any


CSV_FILES = (
    Path("test.csv"),
    Path("train_val_split_0/train.csv"),
    Path("train_val_split_0/val.csv"),
    Path("train_val_split_1/train.csv"),
    Path("train_val_split_1/val.csv"),
    Path("train_val_split_2/train.csv"),
    Path("train_val_split_2/val.csv"),
)

CURRENT_MASK_TOP_SHORTCUT_COLUMNS = [4, 16, 17, 20, 21, 22, 23, 24, 25]

# ShallowML raw CSV is a 16-bit token sequence after Ethernet removal, IP/port
# zeroing, and TCP/UDP payload removal. These defaults assume common IPv4 with
# IHL=5 and TCP without IP options; pcap-aware scripts refine this per packet.
FIELD_TO_DEFAULT_COLUMNS = {
    "IPv4.version_ihl": [0],
    "IPv4.dscp_ecn": [0],
    "IPv4.total_length": [1],
    "IPv4.identification": [2],
    "IPv4.flags_fragment": [3],
    "IPv4.ttl": [4],
    "IPv4.protocol": [4],
    "IPv4.ip_checksum": [5],
    "IPv4.src_ip": [6, 7],
    "IPv4.dst_ip": [8, 9],
    "TCP.sport": [10],
    "TCP.dport": [11],
    "TCP.seq": [12, 13],
    "TCP.ack": [14, 15],
    "TCP.data_offset_reserved_flags": [16],
    "TCP.window": [17],
    "TCP.tcp_checksum": [18],
    "TCP.urgent_pointer": [19],
    "TCP.tcp_options": [20, 21, 22, 23, 24, 25],
    "UDP.sport": [10],
    "UDP.dport": [11],
    "UDP.udp_length": [12],
    "UDP.udp_checksum": [13],
}


def shallowml_dir() -> Path:
    return Path(__file__).resolve().parent


def repo_root() -> Path:
    return shallowml_dir().parents[1]


def default_data_root() -> Path:
    return (
        repo_root().parent
        / "debunk_data"
        / "Debunk_Traffic_Representation"
        / "packet-level-classification"
        / "per-flow-split"
        / "ustc-binary"
    )


def default_raw_csv_root() -> Path:
    return shallowml_dir() / "outputs" / "ustc-binary" / "raw"


def default_field_mask_root() -> Path:
    return shallowml_dir() / "outputs" / "ustc-binary" / "field_masks"


def default_group_config_path() -> Path:
    return shallowml_dir() / "field_mask_groups.json"


def load_group_config(path: Path | None = None) -> dict[str, Any]:
    config_path = path or default_group_config_path()
    with config_path.open("r", encoding="utf-8") as file:
        return json.load(file)


def groups_by_name(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    groups = config.get("groups")
    if not isinstance(groups, list):
        raise ValueError("field mask config must contain a list named 'groups'")
    result = {}
    for group in groups:
        name = group.get("group_name")
        if not name:
            raise ValueError(f"group without group_name: {group}")
        if name in result:
            raise ValueError(f"duplicate group_name in config: {name}")
        result[name] = group
    return result


def _semantic_field_name(field: Any) -> str:
    if isinstance(field, str):
        return field
    if isinstance(field, dict):
        protocol = field.get("protocol")
        name = field.get("field_name") or field.get("name")
        if protocol and name:
            return f"{protocol}.{name}"
        if name:
            return str(name)
    raise ValueError(f"cannot resolve semantic field name from {field!r}")


def resolve_group_columns(
    group: dict[str, Any],
    available_columns: list[int] | None = None,
) -> list[int]:
    """Resolve a group to ShallowML token columns for lightweight CSV scoring.

    Pcap-aware scripts should use Scapy-decoded byte ranges instead. This helper
    intentionally returns the conservative default columns used by the old
    16-bit ShallowML representation.
    """

    if group.get("group_name") == "current_mask_top_shortcut_columns":
        return list(CURRENT_MASK_TOP_SHORTCUT_COLUMNS)

    if group.get("group_name") == "random_same_size":
        columns = available_columns or list(range(34))
        exclude = {int(col) for col in group.get("exclude_columns", [])}
        pool = [col for col in columns if col not in exclude]
        count = int(group.get("column_count", len(CURRENT_MASK_TOP_SHORTCUT_COLUMNS)))
        seed = int(group.get("random_seed", 43))
        rng = random.Random(seed)
        if len(pool) < count:
            pool = list(columns)
        return sorted(rng.sample(pool, count))

    if "columns" in group:
        return sorted({int(col) for col in group["columns"]})

    columns: set[int] = set()
    for field in group.get("semantic_fields", []):
        field_name = _semantic_field_name(field)
        columns.update(FIELD_TO_DEFAULT_COLUMNS.get(field_name, []))
    return sorted(columns)


def feature_columns_from_header(header: list[str]) -> list[int]:
    return sorted(int(col) for col in header if col.isdigit())


def infer_encoded_zero_value(raw_csv: Path) -> str:
    """Infer the ShallowML vocabulary id for the 16-bit token 0000.

    The raw notebook padded packets with zero bytes after payload removal, so the
    final feature column is normally all/m mostly the encoded zero token.
    """

    with raw_csv.open("r", newline="") as file:
        reader = csv.reader(file)
        header = next(reader)
        feature_cols = feature_columns_from_header(header)
        if not feature_cols:
            raise ValueError(f"no numeric feature columns in {raw_csv}")
        last_col = str(feature_cols[-1])
        last_index = header.index(last_col)
        counts: Counter[str] = Counter()
        for row_index, row in enumerate(reader):
            counts[row[last_index]] += 1
            if row_index >= 20000:
                break
    if not counts:
        raise ValueError(f"no data rows in {raw_csv}")
    return counts.most_common(1)[0][0]


def load_retrain_mask_drops(summary_path: Path | None = None) -> dict[str, float]:
    path = summary_path or (shallowml_dir() / "final_stage_combined_summary.json")
    if not path.is_file():
        return {}
    with path.open("r", encoding="utf-8") as file:
        summary = json.load(file)
    masking = summary.get("shallowml", {}).get("masking_averages", {})
    mapping = {
        "current_mask_top_shortcut_columns": "mask_top_shortcut",
        "ip_basic": "mask_ip_basic",
        "tcp_flags_window": "mask_tcp_flags_window",
        "tcp_options": "mask_tcp_options",
    }
    drops: dict[str, float] = {}
    for group_name, experiment_name in mapping.items():
        value = masking.get(experiment_name, {}).get("avg_macro_f1_drop_pp")
        if value is not None:
            drops[group_name] = float(value)
    return drops


def semantic_risk_score(group: dict[str, Any]) -> float:
    value = group.get("semantic_risk_score")
    if value is not None:
        return float(value)

    name = group.get("group_name", "")
    if name in {"ip_ttl_protocol", "tcp_options", "current_mask_top_shortcut_columns"}:
        return 0.9
    if name in {"ip_len_id_checksum", "tcp_flags_window", "tcp_seq_ack"}:
        return 0.7
    if name in {"ip_basic", "tcp_checksum_urgent"}:
        return 0.65
    if name == "udp_len_checksum":
        return 0.55
    return 0.4
