"""Translate simple PowerShell source reads before passing them to agentcov."""

import json
import re
import sys

from agentcov.hooks import run_post_tool_use


READ = re.compile(
    r"^\s*(?:Get-Content|gc|type)\s+(?:(?:-LiteralPath|-Path)\s+)?"
    r"(?:\"([^\"]+)\"|'([^']+)'|([^\s;|]+))(.*)$",
    re.IGNORECASE,
)


def normalize(payload):
    tool_input = payload.get("tool_input")
    command = (tool_input.get("cmd") or tool_input.get("command")) if isinstance(tool_input, dict) else None
    if not isinstance(command, str):
        return payload
    match = READ.fullmatch(command)
    if not match:
        return payload
    path = next(value for value in match.groups()[:3] if value is not None)
    tokens = match.group(4).split()
    total = skip = first = None
    in_select = False
    index = 0
    while index < len(tokens):
        token = tokens[index].lower()
        if token == "|" and not in_select and index + 1 < len(tokens) and tokens[index + 1].lower() == "select-object":
            in_select = True
            index += 2
            continue
        if token == "-raw" and not in_select:
            index += 1
            continue
        if token in ("-totalcount", "-skip", "-first") and index + 1 < len(tokens) and tokens[index + 1].isdigit():
            value = int(tokens[index + 1])
            if token == "-totalcount" and not in_select:
                total = value
            elif token == "-skip" and in_select:
                skip = value
            elif token == "-first" and in_select:
                first = value
            else:
                return payload
            index += 2
            continue
        return payload
    if (total is not None and total <= 0) or (first is not None and first <= 0):
        return payload
    start = (skip or 0) + 1
    end = total
    if first is not None:
        selected_end = (skip or 0) + first
        end = min(end, selected_end) if end is not None else selected_end
    if end is not None and end < start:
        return payload
    read_input = {"path": path, "start_line": start}
    if end is not None:
        read_input["end_line"] = end
    # ponytail: Other PowerShell shapes stay unknown; add only observed reads.
    return {**payload, "tool_name": "Read", "tool_input": read_input, "cwd": tool_input.get("workdir") or payload.get("cwd")}


if __name__ == "__main__":
    run_post_tool_use(normalize(json.load(sys.stdin)))
