#!/usr/bin/env python3
"""
RBS — Ransomware Behavior Simulator (clean / purple-team safe)

Replicates observable ransomware TTPs for EDR/SIEM tuning without irreversible
damage. All "encrypted" artifacts use reversible XOR with a lab-known key and
can be restored instantly via --restore.

MITRE mapping (simulated):
  T1083  File and Directory Discovery
  T1486  Data Encrypted for Impact (reversible XOR stub)
  T1490  Inhibit System Recovery (mock log only)
  T1071  Application Layer Protocol (optional local C2 stub)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import socket
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

# Lab-known XOR key — intentionally static for instant restore in sandbox.
SIM_KEY = b"RBS-LAB-KEY-2026"
SIM_SUFFIX = ".sim_enc"
NOTE_NAME = "README_SIM.txt"
MANIFEST_NAME = ".rbs_manifest.json"

# Hard deny-list: refuse operation outside an explicit lab target tree.
BLOCKED_PREFIXES = (
    Path("/"),
    Path("/etc"),
    Path("/usr"),
    Path("/bin"),
    Path("/sbin"),
    Path("/lib"),
    Path("/lib64"),
    Path("/boot"),
    Path("/root"),
    Path("/var"),
    Path("/proc"),
    Path("/sys"),
    Path("/dev"),
    Path("/run"),
    Path("C:/Windows"),
    Path("C:/Program Files"),
    Path("C:/Program Files (x86)"),
)

DEFAULT_EXTENSIONS = {
    ".txt", ".doc", ".docx", ".pdf", ".xls", ".xlsx",
    ".ppt", ".pptx", ".csv", ".json", ".xml", ".sql",
    ".jpg", ".jpeg", ".png", ".bmp", ".zip", ".tar", ".gz",
}


@dataclass
class Event:
    ts: str
    phase: str
    action: str
    detail: str = ""
    path: str = ""


@dataclass
class RunReport:
    mode: str
    target: str
    host: str
    pid: int
    started: str
    finished: str = ""
    events: list[Event] = field(default_factory=list)
    files_discovered: int = 0
    files_touched: int = 0
    bytes_processed: int = 0
    dry_run: bool = False

    def log(self, phase: str, action: str, detail: str = "", path: str = "") -> None:
        self.events.append(
            Event(
                ts=datetime.now(timezone.utc).isoformat(),
                phase=phase,
                action=action,
                detail=detail,
                path=path,
            )
        )


def xor_transform(data: bytes, key: bytes = SIM_KEY) -> bytes:
    """Single-byte XOR stream — reversible, fast, sufficient for behavior sim."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def resolve_target(raw: str, *, create: bool = False) -> Path:
    target = Path(raw).expanduser().resolve()
    if not target.exists():
        if create:
            target.mkdir(parents=True, exist_ok=True)
        else:
            raise SystemExit(f"[ERR] Target does not exist: {target}")
    if not target.is_dir():
        raise SystemExit(f"[ERR] Target must be a directory: {target}")
    return target


def assert_lab_safe(target: Path, force: bool) -> None:
    """Prevent accidental execution on system or home-wide paths."""
    target_s = str(target)
    for blocked in BLOCKED_PREFIXES:
        b = str(blocked.resolve()) if blocked.is_absolute() else str(blocked)
        if target == blocked or target_s.startswith(b + os.sep) or target_s == b:
            if not force:
                raise SystemExit(
                    f"[ERR] Refusing blocked path: {target}\n"
                    "      Use a dedicated lab subdirectory and --force if intentional."
                )

    home = Path.home().resolve()
    if target == home and not force:
        raise SystemExit(
            f"[ERR] Refusing entire home directory: {home}\n"
            "      Point --target to a lab folder (e.g. ~/rbs-sim/lab_data)."
        )


def discover_files(
    root: Path,
    extensions: set[str],
    max_files: int,
) -> Iterable[Path]:
    count = 0
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in extensions:
            if path.name in (NOTE_NAME, MANIFEST_NAME):
                continue
            if path.name.endswith(SIM_SUFFIX):
                continue
            yield path
            count += 1
            if count >= max_files:
                return


def write_manifest(root: Path, entries: list[dict], dry_run: bool) -> None:
    manifest = root / MANIFEST_NAME
    payload = {
        "tool": "rbs-sim",
        "version": "1.0.0",
        "key_hint": SIM_KEY.decode(),
        "entries": entries,
    }
    if dry_run:
        return
    manifest.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_ransom_note(root: Path, dry_run: bool) -> None:
    note = root / NOTE_NAME
    body = (
        "=== RBS SIMULATION — NOT REAL RANSOMWARE ===\n\n"
        "This file was dropped by rbs_sim.py for purple-team / EDR testing.\n"
        "All encrypted files use reversible XOR and can be restored with:\n\n"
        "    python3 rbs_sim.py --restore --target <this_directory>\n\n"
        "Simulation timestamp (UTC): "
        f"{datetime.now(timezone.utc).isoformat()}\n"
    )
    if dry_run:
        return
    note.write_text(body, encoding="utf-8")


def simulate_encryption(
    report: RunReport,
    target: Path,
    extensions: set[str],
    max_files: int,
    dry_run: bool,
) -> None:
    report.log("T1083", "discovery_start", f"extensions={sorted(extensions)}")
    entries: list[dict] = []

    for src in discover_files(target, extensions, max_files):
        report.files_discovered += 1
        dst = Path(str(src) + SIM_SUFFIX)

        report.log("T1486", "encrypt_file", f"size={src.stat().st_size}", str(src))

        if dry_run:
            report.files_touched += 1
            report.bytes_processed += src.stat().st_size
            entries.append({"src": str(src), "dst": str(dst), "simulated": True})
            continue

        data = src.read_bytes()
        dst.write_bytes(xor_transform(data))
        src.unlink()
        report.files_touched += 1
        report.bytes_processed += len(data)
        entries.append({"src": str(src), "dst": str(dst), "sha256_src": hashlib.sha256(data).hexdigest()})

        # Burst I/O pacing — mimics encryption throughput pattern.
        time.sleep(0.01)

    write_manifest(target, entries, dry_run)
    write_ransom_note(target, dry_run)
    report.log("T1486", "encryption_complete", f"files={report.files_touched}")


def mock_anti_recovery(report: RunReport) -> None:
    """Log-only simulation of T1490 — never executes destructive commands."""
    cmds = [
        "vssadmin delete shadows /all /quiet",
        "wmic shadowcopy delete",
        "bcdedit /set {default} recoveryenabled no",
        "rm -rf /var/backups/*",
    ]
    for cmd in cmds:
        report.log("T1490", "mock_anti_recovery", f"WOULD_EXECUTE: {cmd}")


def mock_c2(report: RunReport, host: str, port: int, timeout: float) -> None:
    """Optional local honeypot ping — fails gracefully if nothing listens."""
    report.log("T1071", "c2_attempt", f"{host}:{port}")
    try:
        with socket.create_connection((host, port), timeout=timeout):
            report.log("T1071", "c2_connected", f"{host}:{port}")
    except OSError as exc:
        report.log("T1071", "c2_failed", str(exc))


def restore_target(report: RunReport, target: Path, dry_run: bool) -> None:
    report.log("restore", "scan_start")
    restored = 0

    for enc in target.rglob(f"*{SIM_SUFFIX}"):
        if not enc.is_file():
            continue
        original = Path(str(enc)[: -len(SIM_SUFFIX)])
        report.log("restore", "decrypt_file", path=str(enc))

        if dry_run:
            restored += 1
            continue

        plain = xor_transform(enc.read_bytes())
        original.write_bytes(plain)
        enc.unlink()
        restored += 1

    for artifact in (target / NOTE_NAME, target / MANIFEST_NAME):
        if artifact.exists() and not dry_run:
            artifact.unlink()
            report.log("restore", "remove_artifact", path=str(artifact))

    report.files_touched = restored
    report.log("restore", "complete", f"files={restored}")


def emit_report(report: RunReport, json_out: Path | None) -> None:
    report.finished = datetime.now(timezone.utc).isoformat()
    payload = asdict(report)
    text = json.dumps(payload, indent=2)
    if json_out:
        json_out.write_text(text, encoding="utf-8")
        print(f"[OK] Report written: {json_out}")
    else:
        print(text)


def seed_lab_data(lab_dir: Path) -> None:
    lab_dir.mkdir(parents=True, exist_ok=True)
    samples = {
        "document1.txt": "Quarterly report draft — lab sample.",
        "budget.csv": "item,cost\nwidget,100\n",
        "notes.json": '{"project":"rbs-sim","classification":"test"}',
        "photo_stub.jpg": bytes([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10] + [0x00] * 32),
    }
    for name, content in samples.items():
        path = lab_dir / name
        if path.exists():
            continue
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
    print(f"[OK] Lab seed data ready: {lab_dir}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="RBS — reversible ransomware behavior simulator for purple-team labs.",
    )
    p.add_argument(
        "--target",
        default=str(Path(__file__).resolve().parent / "lab_data"),
        help="Lab directory to operate on (default: ./lab_data)",
    )
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--simulate", action="store_true", help="Run discovery + reversible encryption burst")
    mode.add_argument("--restore", action="store_true", help="Restore all .sim_enc files in target")
    mode.add_argument("--seed", action="store_true", help="Create sample files in target for testing")

    p.add_argument("--dry-run", action="store_true", help="Log actions without modifying files")
    p.add_argument("--force", action="store_true", help="Override path safety checks (lab only)")
    p.add_argument("--max-files", type=int, default=500, help="Cap processed files")
    p.add_argument(
        "--extensions",
        default=",".join(sorted(DEFAULT_EXTENSIONS)),
        help="Comma-separated target extensions",
    )
    p.add_argument("--mock-anti-recovery", action="store_true", help="Emit T1490 mock logs")
    p.add_argument("--c2-host", default="127.0.0.1", help="Local C2 honeypot host")
    p.add_argument("--c2-port", type=int, default=9999, help="Local C2 honeypot port")
    p.add_argument("--c2-timeout", type=float, default=1.0, help="C2 connect timeout (s)")
    p.add_argument("--report", type=Path, help="Write JSON telemetry report to path")
    return p


def main() -> None:
    args = build_parser().parse_args()
    target = resolve_target(args.target, create=args.seed)
    if not args.seed:
        assert_lab_safe(target, args.force)

    extensions = {e if e.startswith(".") else f".{e}" for e in args.extensions.split(",")}

    report = RunReport(
        mode="seed" if args.seed else ("restore" if args.restore else "simulate"),
        target=str(target),
        host=platform.node(),
        pid=os.getpid(),
        started=datetime.now(timezone.utc).isoformat(),
        dry_run=args.dry_run,
    )

    if args.seed:
        seed_lab_data(target)
        report.log("seed", "complete")
    elif args.restore:
        restore_target(report, target, args.dry_run)
    else:
        if args.mock_anti_recovery:
            mock_anti_recovery(report)
        simulate_encryption(report, target, extensions, args.max_files, args.dry_run)
        mock_c2(report, args.c2_host, args.c2_port, args.c2_timeout)

    emit_report(report, args.report)


if __name__ == "__main__":
    main()
