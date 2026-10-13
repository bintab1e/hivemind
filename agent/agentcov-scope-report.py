#!/usr/bin/env python3
"""Generate agentcov LCOV and native JSON for an explicit Hivemind file scope.

agentcov 0.1.0 inventories an entire Git checkout before producing a report.
Linux is large enough that parsing the resulting JSON in the Node sync process
can exhaust its heap.  The package is pinned, so this adapter safely limits the
inventory and events before agentcov constructs its native report.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

import agentcov.aggregate as aggregate
from agentcov.config import load_config
from agentcov.report import write_lcov
from agentcov.storage import load_events


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--scope", type=Path, required=True)
    parser.add_argument("--lcov", type=Path, required=True)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--meta", type=Path, required=True)
    return parser.parse_args()


def write_json_atomic(value: object, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False
    ) as output:
        temporary = Path(output.name)
        try:
            json.dump(value, output, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            output.flush()
            os.fsync(output.fileno())
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    scope_data = json.loads(args.scope.read_text(encoding="utf-8"))
    scope = set(scope_data.get("files") or [])
    if not scope or any(not isinstance(name, str) or name.startswith("/") or ".." in Path(name).parts for name in scope):
        raise ValueError("scope must contain safe repository-relative paths")
    missing_includes = sorted(set(scope_data.get("missing_includes") or []))
    config = load_config(root)
    events = load_events(root=root, config=config)

    def in_scope(event: object) -> bool:
        file_name = getattr(event, "file", None)
        if not file_name:
            return False
        relative = aggregate._event_file_key(file_name, root=root, config=config)
        return relative in scope

    scoped_events = [event for event in events if in_scope(event)]
    original_inventory = aggregate.list_project_files
    aggregate.list_project_files = lambda _root, _config: sorted(scope)
    try:
        coverage = aggregate.build_coverage(root=root, events=scoped_events, config=config)
    finally:
        aggregate.list_project_files = original_inventory

    # LCOV is the server's source of truth and needs the native per-line map.
    # Write it before compacting the JSON-only representation below.
    args.lcov.parent.mkdir(parents=True, exist_ok=True)
    write_lcov(coverage, out=args.lcov, counts="binary")

    # The server derives its per-file and per-line coverage from the LCOV above.
    # Agentcov's files.*.read_ranges and search_seen_ranges repeat event details
    # hundreds of thousands of times and eventually exceed the telemetry limit.
    # Keep the native event log locally as the detailed source of truth and send
    # only the summary and scope metadata that are not represented by LCOV.
    transfer = {
        key: coverage[key]
        for key in ("schema_version", "tool", "summary")
        if key in coverage
    }
    transfer["git"] = {"head": coverage.get("git", {}).get("head")}
    transfer["hivemind_compaction"] = {
        "schema_version": 2,
        "omitted": ["files", "sessions", "unknown_events"],
        "coverage_source": "agentcov.info",
        "detail_source": ".agentcov/events.jsonl",
    }
    transfer["hivemind_scope"] = {
        "kind": "include_closure",
        "files": len(scope),
        "missing_includes": missing_includes,
    }
    write_json_atomic(transfer, args.json)
    write_json_atomic(
        {
            "files": coverage["summary"]["files"],
            "total_lines": coverage["summary"]["total_lines"],
            "read_lines": coverage["summary"]["read_lines"],
        },
        args.meta,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
