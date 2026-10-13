#!/usr/bin/env python3
"""Run a normalized verification manifest inside a disposable guest only."""

import json
import os
import pwd
import subprocess
import sys


JOB = "/mnt/job"
SERVER = "10.77.0.1"
MOUNT = "/mnt/nfs"
BINARY = "/tmp/hivemind-poc"


def emit(message):
    print(message, flush=True)


def drop_privileges():
    account = pwd.getpwnam("nobody")
    os.setgroups([])
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)


def command(argv, timeout, manifest, cwd="/tmp"):
    if not isinstance(argv, list) or not argv or not all(isinstance(item, str) for item in argv):
        raise ValueError("commands must be nonempty argv arrays")
    replacements = {
        "@POC@": JOB + "/" + manifest["poc"],
        "@BINARY@": BINARY,
        "@SERVER@": SERVER,
        "@MOUNT@": MOUNT,
    }
    args = [replacements.get(arg, arg) for arg in argv]
    return subprocess.run(args, cwd=cwd, timeout=timeout, check=False,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          preexec_fn=drop_privileges).returncode


def wait_for_host_release(serial):
    if serial.readline().strip() != "HV_GO":
        raise ValueError("missing host arm signal")
    emit("HV_POC_BEGIN")
    if serial.readline().strip() != "HV_POC_ACK":
        raise ValueError("missing host release signal")


def main():
    with open(JOB + "/manifest.json", encoding="utf-8") as handle:
        manifest = json.load(handle)
    if sys.argv[1] != "client":
        raise ValueError("unknown guest role")
    try:
        if manifest.get("mount", True):
            version = manifest.get("nfsVersion", "4.2")
            source = SERVER + (":/srv/export" if version == "3" else ":/")
            options = "vers=" + version + ",proto=tcp" + (",nolock" if version == "3" else "")
            result = subprocess.run(["mount", "-t", "nfs", "-o", options, source, MOUNT], timeout=30, check=False,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            emit("HV_MOUNT_EXIT:%d" % result.returncode)
            if result.returncode != 0:
                sys.exit(2)
        if manifest["poc"].endswith(".c"):
            compile_args = manifest.get("compile") or ["gcc", "-O0", "-g", "-o", "@BINARY@", "@POC@"]
            result = command(compile_args, 60, manifest)
            emit("HV_BUILD_EXIT:%d" % result)
            if result != 0:
                sys.exit(3)
            run_args = manifest.get("run") or ["@BINARY@", "@SERVER@", "@MOUNT@"]
        else:
            run_args = manifest.get("run") or ["python3", "@POC@", "@SERVER@", "@MOUNT@"]
        emit("HV_POC_READY")
        with open("/dev/ttyS0", encoding="ascii") as serial:
            wait_for_host_release(serial)
        emit("HV_POC_EXEC")
        result = command(run_args, 90, manifest)
        emit("HV_POC_EXIT:%d" % result)
    except subprocess.TimeoutExpired:
        emit("HV_GUEST_TIMEOUT")
        sys.exit(4)
    except Exception as error:
        emit("HV_GUEST_ERROR:%s" % type(error).__name__)
        sys.exit(5)


if __name__ == "__main__":
    main()
