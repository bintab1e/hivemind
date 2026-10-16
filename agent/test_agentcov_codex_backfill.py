import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


spec = importlib.util.spec_from_file_location("codex_backfill", Path(__file__).with_name("agentcov-codex-backfill.py"))
backfill = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backfill)


class CodexBackfillTest(unittest.TestCase):
    def test_parent_workspace_session_imports_only_checkout_reads_incrementally(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            root = base / "knfsd/build/linux"
            target = root / "fs/nfsd/main.c"
            target.parent.mkdir(parents=True)
            target.write_text("one\ntwo\nthree\n")
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            session = base / "sessions/2026/10/16/rollout.jsonl"
            session.parent.mkdir(parents=True)
            meta = {"type": "session_meta", "payload": {"cwd": str(root.parent.parent)}}
            def read(workdir, command):
                return {"tool_name": "exec_command", "tool_input": {"workdir": str(workdir), "cmd": command}}
            with session.open("w") as output:
                for record in (meta, read(root, "sed -n '1,2p' fs/nfsd/main.c"),
                               read(root.parent.parent, "cat AGENTS.md")):
                    output.write(json.dumps(record) + "\n")
            state = base / "state.json"
            self.assertEqual(backfill.backfill_checkout(root, base / "sessions", state), (1, 1))
            self.assertEqual(backfill.backfill_checkout(root, base / "sessions", state), (0, 0))
            with session.open("a") as output:
                output.write(json.dumps(read(root, "sed -n '2,3p' fs/nfsd/main.c")) + "\n")
            self.assertEqual(backfill.backfill_checkout(root, base / "sessions", state), (1, 1))
            events = [json.loads(line) for line in (root / ".agentcov/events.jsonl").read_text().splitlines()]
            self.assertEqual([event["file"] for event in events], ["fs/nfsd/main.c"] * 2)


if __name__ == "__main__":
    unittest.main()
