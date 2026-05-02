#!/usr/bin/env python3
"""Build small USTC-binary parquet datasets for Pcap-Encoder smoke checks."""

from __future__ import annotations

import argparse
import binascii
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable

import pandas as pd
from scapy.all import Ether, IP, IPv6, TCP, UDP, PcapReader


QUESTION = "What is the representation of this packet?"
OUTPUT_COLUMNS = ["question", "class", "type_q", "context"]
MASK_TOP_SHORTCUT_BYTE_OFFSETS = (
    [8, 9]
    + list(range(32, 36))
    + list(range(40, 52))
)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def default_data_root() -> Path:
    return (
        repo_root().parent
        / "debunk_data"
        / "Debunk_Traffic_Representation"
        / "packet-level-classification"
        / "per-flow-split"
        / "ustc-binary"
    )


def default_output_root() -> Path:
    return repo_root() / "code" / "ShallowML" / "pcapencoder_smoke"


def clean_packet(packet):
    """Mirror process_finetune_data/.../pcapencoder_process_pkt.ipynb."""
    pkt = packet.copy()
    if pkt.haslayer(Ether):
        pkt = pkt[Ether].payload

    if pkt.haslayer(IP):
        pkt[IP].src = "0.0.0.0"
        pkt[IP].dst = "0.0.0.0"
    elif pkt.haslayer(IPv6):
        pkt[IPv6].src = "::"
        pkt[IPv6].dst = "::"

    if pkt.haslayer(UDP):
        pkt[UDP].sport = 0
        pkt[UDP].dport = 0
    elif pkt.haslayer(TCP):
        pkt[TCP].sport = 0
        pkt[TCP].dport = 0

    return pkt


def bytes_to_context(packet_bytes: bytes) -> str:
    hex_string = binascii.hexlify(packet_bytes).decode()
    return " ".join(
        hex_string[index : index + 4] for index in range(0, len(hex_string), 4)
    )


def mask_top_shortcut(packet_bytes: bytes) -> bytes:
    masked = bytearray(packet_bytes)
    for offset in MASK_TOP_SHORTCUT_BYTE_OFFSETS:
        if offset < len(masked):
            masked[offset] = 0
    return bytes(masked)


def class_pcaps(split_dir: Path) -> list[Path]:
    pcaps = sorted(split_dir.glob("*.pcap"), key=lambda path: path.stem)
    if not pcaps:
        raise FileNotFoundError(f"No .pcap files found under {split_dir}")
    return pcaps


def class_mapping(data_root: Path, split_id: int) -> dict[str, int]:
    split_dirs = [
        data_root / f"train_val_split_{split_id}" / "train",
        data_root / f"train_val_split_{split_id}" / "val",
        data_root / "test",
    ]
    names: set[str] = set()
    for split_dir in split_dirs:
        if not split_dir.exists():
            raise FileNotFoundError(f"Missing split directory: {split_dir}")
        names.update(path.stem for path in class_pcaps(split_dir))
    return {name: index for index, name in enumerate(sorted(names))}


def quotas_for_files(pcaps: list[Path], max_rows: int) -> dict[Path, int]:
    if max_rows <= 0:
        raise ValueError("max row counts must be positive")
    base, remainder = divmod(max_rows, len(pcaps))
    return {
        path: base + (1 if index < remainder else 0)
        for index, path in enumerate(pcaps)
    }


def rows_from_pcap(
    pcap_path: Path,
    class_id: int,
    type_q: str,
    limit: int,
    mode: str,
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    with PcapReader(str(pcap_path)) as reader:
        for packet_index, packet in enumerate(reader):
            if len(rows) >= limit:
                break
            try:
                cleaned = clean_packet(packet)
                packet_bytes = bytes(cleaned)
                if mode == "mask_top_shortcut":
                    packet_bytes = mask_top_shortcut(packet_bytes)
                context = bytes_to_context(packet_bytes)
            except Exception as exc:  # pragma: no cover - keeps failures explicit.
                raise RuntimeError(
                    f"Failed to process {pcap_path} packet {packet_index}"
                ) from exc

            rows.append(
                {
                    "question": QUESTION,
                    "class": class_id,
                    "type_q": type_q,
                    "context": context,
                }
            )

    if len(rows) < limit:
        raise RuntimeError(
            f"{pcap_path} yielded {len(rows)} packets, fewer than requested {limit}"
        )
    return rows


def build_split(
    split_name: str,
    split_dir: Path,
    max_rows: int,
    labels: dict[str, int],
    mode: str,
) -> pd.DataFrame:
    pcaps = class_pcaps(split_dir)
    quotas = quotas_for_files(pcaps, max_rows)
    rows: list[dict[str, object]] = []
    for pcap_path in pcaps:
        type_q = pcap_path.stem
        if type_q not in labels:
            raise KeyError(f"Class {type_q!r} missing from label mapping")
        rows.extend(
            rows_from_pcap(
                pcap_path=pcap_path,
                class_id=labels[type_q],
                type_q=type_q,
                limit=quotas[pcap_path],
                mode=mode,
            )
        )

    frame = pd.DataFrame(rows, columns=OUTPUT_COLUMNS)
    if len(frame) != max_rows:
        raise RuntimeError(f"{split_name} has {len(frame)} rows, expected {max_rows}")
    return frame


def split_paths(data_root: Path, split_id: int) -> dict[str, Path]:
    return {
        "train": data_root / f"train_val_split_{split_id}" / "train",
        "val": data_root / f"train_val_split_{split_id}" / "val",
        "test": data_root / "test",
    }


def ensure_new_output_dir(output_dir: Path) -> None:
    if output_dir.exists() and any(output_dir.iterdir()):
        raise FileExistsError(
            f"Refusing to overwrite existing non-empty output directory: {output_dir}"
        )
    output_dir.mkdir(parents=True, exist_ok=True)


def write_splits(
    output_dir: Path,
    data_root: Path,
    split_id: int,
    mode: str,
    max_rows_by_split: dict[str, int],
) -> None:
    ensure_new_output_dir(output_dir)
    labels = class_mapping(data_root, split_id)
    print(f"mode={mode}")
    print(f"data_root={data_root}")
    print(f"output_dir={output_dir}")
    print(f"class_mapping={json.dumps(labels, sort_keys=True)}")

    for split_name, split_dir in split_paths(data_root, split_id).items():
        frame = build_split(
            split_name=split_name,
            split_dir=split_dir,
            max_rows=max_rows_by_split[split_name],
            labels=labels,
            mode=mode,
        )
        output_path = output_dir / f"{split_name}.parquet"
        frame.to_parquet(output_path, index=False)
        label_counts = Counter(frame["type_q"])
        class_counts = Counter(frame["class"])
        print(
            json.dumps(
                {
                    "split": split_name,
                    "path": str(output_path),
                    "rows": len(frame),
                    "columns": list(frame.columns),
                    "type_q_distribution": dict(sorted(label_counts.items())),
                    "class_distribution": {
                        str(key): value for key, value in sorted(class_counts.items())
                    },
                },
                sort_keys=True,
            )
        )


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Prepare Pcap-Encoder USTC-binary smoke parquet data."
    )
    parser.add_argument("--mode", choices=["raw", "mask_top_shortcut"], required=True)
    parser.add_argument("--split-id", type=int, default=0)
    parser.add_argument("--max-train", type=int, default=5000)
    parser.add_argument("--max-val", type=int, default=1000)
    parser.add_argument("--max-test", type=int, default=5000)
    parser.add_argument("--data-root", type=Path, default=default_data_root())
    parser.add_argument("--output-root", type=Path, default=default_output_root())
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    data_root = args.data_root.resolve()
    output_root = args.output_root.resolve()
    output_name = f"ustc_binary_{args.mode}_split{args.split_id}"
    output_dir = output_root / output_name

    max_rows_by_split = {
        "train": args.max_train,
        "val": args.max_val,
        "test": args.max_test,
    }

    try:
        write_splits(
            output_dir=output_dir,
            data_root=data_root,
            split_id=args.split_id,
            mode=args.mode,
            max_rows_by_split=max_rows_by_split,
        )
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
