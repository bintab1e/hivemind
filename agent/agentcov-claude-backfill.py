#!/usr/bin/env python3
"""Import only this checkout's Claude Code reads into local agentcov storage."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

from agentcov.backfill import backfill_claude_session
from agentcov.config import load_config
from agentcov.storage import append_events
from agentcov.transcripts import claude_session_paths_from_transcript


def within_root(cwd: object, root: Path) -> bool:
    if not isinstance(cwd, str) or not Path(cwd).is_absolute():
        return False
    try:
        Path(cwd).resolve().relative_to(root)
        return True
    except ValueError:
        return False


def belongs_to_checkout(session: Path, root: Path) -> bool:
    # Claude can write metadata before the first record carrying cwd.
    with session.open("r", encoding="utf-8") as source:
        for index, line in enumerate(source):
            if index >= 64:
                break
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict) and isinstance(record.get("cwd"), str) and record["cwd"]:
                return within_root(record["cwd"], root)
    return False


def save_state(state_file: Path, state: dict[str, object]) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=state_file.parent, delete=False) as output:
        temporary = Path(output.name)
        json.dump(state, output, separators=(",", ":"))
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, state_file)


def backfill_checkout(root: Path, sessions_root: Path, state_file: Path) -> tuple[int, int]:
    root = root.resolve()
    sessions_root = sessions_root.resolve()
    if not sessions_root.is_dir():
        return 0, 0
    try:
        state = json.loads(state_file.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        state = {}
    previous = state.get("sessions", {}) if state.get("repo_root") == str(root) else {}
    current: dict[str, list[list[int]]] = {}
    checked = imported = 0
    config = load_config(root)
    for session in sorted(sessions_root.glob("*/*.jsonl")):
        if session.is_symlink() or not session.is_file() or not belongs_to_checkout(session, root):
            continue
        paths = claude_session_paths_from_transcript(session)
        if any(path.is_symlink() or not path.resolve().is_relative_to(sessions_root) for path in paths):
            continue
        fingerprint = [[path.stat().st_mtime_ns, path.stat().st_size] for path in paths]
        key = str(session.resolve())
        current[key] = fingerprint
        if previous.get(key) == fingerprint:
            continue
        _, events = backfill_claude_session(transcript_path=session)
        scoped = [event for event in events if event.repo_root and Path(event.repo_root).resolve() == root]
        if scoped:
            imported += append_events(scoped, root=root, config=config, dedupe=True)
        checked += 1
    save_state(state_file, {"repo_root": str(root), "sessions": current})
    return checked, imported


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    claude_home = Path(os.environ.get("CLAUDE_CONFIG_DIR", Path.home() / ".claude"))
    checked, imported = backfill_checkout(args.root, claude_home / "projects", args.state)
    if checked or imported:
        print(f"Claude Code agentcov: {checked} changed sessions, {imported} new read events")


if __name__ == "__main__":
    main()
