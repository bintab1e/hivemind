import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


spec = importlib.util.spec_from_file_location("claude_backfill", Path(__file__).with_name("agentcov-claude-backfill.py"))
backfill = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backfill)


class ClaudeBackfillTest(unittest.TestCase):
    def test_only_this_checkout_is_imported_and_unchanged_sessions_are_skipped(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            main, unrelated = base / "linux", base / "unrelated"
            for repo in (main, unrelated):
                (repo / "fs/nfsd").mkdir(parents=True)
                (repo / "fs/nfsd/main.c").write_text("one\ntwo\nthree\n")
                subprocess.run(["git", "init", "-q", str(repo)], check=True)
                subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
                subprocess.run(["git", "-C", str(repo), "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "sample"], check=True)
            sessions = base / "claude/projects"
            for name, cwd, target in (
                ("main", main, main),
                ("other-project", unrelated, unrelated),
                ("cross-repo-read", main, unrelated),
            ):
                directory = sessions / name
                directory.mkdir(parents=True)
                record = {
                    "type": "assistant", "cwd": str(cwd), "sessionId": name, "uuid": name,
                    "message": {"content": [{"type": "tool_use", "name": "Read", "id": f"{name}-read",
                                            "input": {"file_path": str(target / "fs/nfsd/main.c"), "offset": 1, "limit": 2}}]},
                }
                (directory / f"{name}.jsonl").write_text(json.dumps(record) + "\n")
            state = base / "runtime/state.json"
            self.assertEqual(backfill.backfill_checkout(main, sessions, state), (2, 1))
            self.assertEqual(backfill.backfill_checkout(main, sessions, state), (0, 0))
            events = [json.loads(line) for line in (main / ".agentcov/events.jsonl").read_text().splitlines()]
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["file"], "fs/nfsd/main.c")
            self.assertEqual(events[0]["agent"], "claude")
            self.assertFalse((unrelated / ".agentcov/events.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
