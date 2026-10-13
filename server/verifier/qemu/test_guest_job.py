import importlib.util
import io
from pathlib import Path
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("guest_job", Path(__file__).with_name("guest-job.py"))
guest_job = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest_job)


class GuestCommandTests(unittest.TestCase):
    def test_guest_waits_for_ack_after_arming_poc(self):
        with patch.object(guest_job, "emit") as emit:
            guest_job.wait_for_host_release(io.StringIO("HV_GO\nHV_POC_ACK\n"))
            emit.assert_called_once_with("HV_POC_BEGIN")
        with patch.object(guest_job, "emit") as emit:
            with self.assertRaisesRegex(ValueError, "release signal"):
                guest_job.wait_for_host_release(io.StringIO("HV_GO\n"))
            emit.assert_called_once_with("HV_POC_BEGIN")

    def test_poc_output_cannot_write_control_markers_to_serial(self):
        with patch.object(guest_job.subprocess, "run") as run:
            run.return_value.returncode = 0
            self.assertEqual(guest_job.command(["@BINARY@"], 90, {"poc": "poc.c"}), 0)
            options = run.call_args.kwargs
            self.assertEqual(options["stdout"], subprocess.DEVNULL)
            self.assertEqual(options["stderr"], subprocess.DEVNULL)
            self.assertIs(options["preexec_fn"], guest_job.drop_privileges)

    def test_child_drops_groups_gid_and_uid(self):
        account = SimpleNamespace(pw_gid=65534, pw_uid=65534)
        with patch.object(guest_job.pwd, "getpwnam", return_value=account) as lookup, \
             patch.object(guest_job.os, "setgroups") as groups, \
             patch.object(guest_job.os, "setgid") as gid, \
             patch.object(guest_job.os, "setuid") as uid:
            guest_job.drop_privileges()
        lookup.assert_called_once_with("nobody")
        groups.assert_called_once_with([])
        gid.assert_called_once_with(65534)
        uid.assert_called_once_with(65534)


if __name__ == "__main__":
    unittest.main()
