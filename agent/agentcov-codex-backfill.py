#!/usr/bin/env python3
"""Incrementally import this checkout's Codex reads when the session starts above it."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

from agentcov.codex_transcript import payloads_from_codex_record
from agentcov.hooks import events_from_payload
from agentcov.storage import append_events


def backfill_checkout(root: Path, sessions_root: Path, state_file: Path) -> tuple[int, int]:
    root = root.resolve()
    if not sessions_root.is_dir():
        return 0, 0
    try:
        state = json.loads(state_file.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        state = {}
    previous = state.get("sessions", {}) if state.get("repo_root") == str(root) else {}
    current = {}
    checked = imported = 0
    for session in sorted(sessions_root.glob("*/*/*/*.jsonl")):
        if session.is_symlink() or not session.is_file():
            continue
        with session.open("rb") as source:
            try:
                meta = json.loads(source.readline())
            except (ValueError, UnicodeDecodeError):
                continue
            cwd = meta.get("payload", {}).get("cwd")
            if not isinstance(cwd, str) or Path(cwd).resolve() not in (root, root.parent, root.parent.parent):
                continue
            key = str(session.resolve())
            size = session.stat().st_size
            offset = previous.get(key, 0)
            if not isinstance(offset, int) or offset < 0 or offset > size:
                offset = 0
            source.seek(offset)
            events = []
            while True:
                position = source.tell()
                line = source.readline()
                if not line:
                    break
                if not line.endswith(b"\n"):
                    source.seek(position)
                    break
                try:
                    record = json.loads(line)
                except (ValueError, UnicodeDecodeError):
                    continue
                for payload in payloads_from_codex_record(record):
                    _, parsed = events_from_payload(payload, source="transcript-backfill")
                    events.extend(event for event in parsed if event.repo_root and Path(event.repo_root).resolve() == root)
            current[key] = source.tell()
        if current[key] != offset:
            checked += 1
        if events:
            imported += append_events(events, root=root, dedupe=True)
    state_file.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=state_file.parent, delete=False) as output:
        temporary = Path(output.name)
        json.dump({"repo_root": str(root), "sessions": current}, output, separators=(",", ":"))
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, state_file)
    return checked, imported


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    sessions_root = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")) / "sessions"
    checked, imported = backfill_checkout(args.root, sessions_root, args.state)
    if checked or imported:
        print(f"Codex agentcov: {checked} changed sessions, {imported} new read events")


if __name__ == "__main__":
    main()
