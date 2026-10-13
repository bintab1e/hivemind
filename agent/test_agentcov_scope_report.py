import importlib.util
import tempfile
import unittest
from pathlib import Path


spec = importlib.util.spec_from_file_location("scope_report", Path(__file__).with_name("agentcov-scope-report.py"))
scope_report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scope_report)


class SparseReportTest(unittest.TestCase):
    def test_sparse_lcov_keeps_only_read_lines_and_total_line_counts(self):
        coverage = {"files": {
            "fs/nfsd/main.c": {"line_count": 5, "lines": {
                "2": {"read_count": 2}, "4": {"read_count": 0}, "5": {"read_count": 1},
                "6": {"read_count": 1},
            }},
            "net/sunrpc/empty.c": {"line_count": 3, "lines": {}},
        }}
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "agentcov.info"
            scope_report.write_sparse_lcov(coverage, output)
            self.assertEqual(output.read_text(),
                "TN:hivemind-sparse-v1\nSF:fs/nfsd/main.c\nDA:2,1\nDA:5,1\nLH:2\nLF:5\nend_of_record\n"
                "TN:hivemind-sparse-v1\nSF:net/sunrpc/empty.c\nLH:0\nLF:3\nend_of_record\n")


if __name__ == "__main__":
    unittest.main()
