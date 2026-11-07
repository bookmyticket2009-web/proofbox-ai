#!/usr/bin/env python3
"""
ProofBox AI - sandbox runner.

Deployed to /opt/proofbox/runner.py on the remote Vultr sandbox VM.
It is NOT imported by the backend API.

Protocol
  stdin : one JSON object  {"code": "<python source>", "timeout": <seconds>}
  stdout: one JSON object  (the result; the last line of stdout)

Safety controls
  * Refuses to run as root.
  * Code is written to a fresh temporary directory and removed afterwards.
  * Runs in its own process group; the whole group is killed on timeout or exit.
  * CPU time, address space, file size, core dumps and process count are limited.
  * User output goes to files (capped), never directly into the protocol stream.
  * Minimal environment. No inherited secrets.

Network isolation is NOT done here. It must be enforced at the VM level
(see deploy/setup_sandbox_vm.sh, which blocks outbound traffic for the sandbox UID).
"""

import datetime
import json
import os
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time

RUNNER_VERSION = "1.0"

MAX_REQUEST_BYTES = 64 * 1024          # JSON wrapper around the code; code limit is checked separately
MAX_CODE_BYTES = 20 * 1000
MAX_OUTPUT_BYTES = 64 * 1024
MAX_FILE_BYTES = 1024 * 1024            # RLIMIT_FSIZE: output files may not exceed this
MEMORY_BYTES = 256 * 1024 * 1024        # RLIMIT_AS: address space for the user code
MAX_PROCESSES = 32                      # RLIMIT_NPROC: stops fork bombs
DEFAULT_TIMEOUT = 10
MAX_TIMEOUT = 30


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def error_result(message):
    return {
        "runner_version": RUNNER_VERSION,
        "status": "error",
        "error": message,
        "exit_code": None,
        "timed_out": False,
        "output_limit_exceeded": False,
        "stdout": "",
        "stderr": "",
        "stdout_truncated": False,
        "stderr_truncated": False,
        "cleanup_confirmed": True,
    }


def read_request():
    raw = sys.stdin.read(MAX_REQUEST_BYTES + 1)
    if len(raw.encode("utf-8")) > MAX_REQUEST_BYTES:
        raise ValueError("request is too large")
    request = json.loads(raw)
    if not isinstance(request, dict):
        raise ValueError("request must be a JSON object")

    code = request.get("code")
    if not isinstance(code, str) or not code.strip():
        raise ValueError("code must be a non-empty string")
    if len(code.encode("utf-8")) > MAX_CODE_BYTES:
        raise ValueError(f"code exceeds the {MAX_CODE_BYTES}-byte limit")

    timeout = request.get("timeout", DEFAULT_TIMEOUT)
    if isinstance(timeout, bool) or not isinstance(timeout, int):
        raise ValueError("timeout must be an integer")
    timeout = max(1, min(timeout, MAX_TIMEOUT))
    return code, timeout


def apply_limits(timeout):
    def _set_limits():
        # Python ignores SIGXFSZ by default, which turns an oversized write into a
        # Python exception instead of a kill. Restore the default so the limit is enforced.
        signal.signal(signal.SIGXFSZ, signal.SIG_DFL)
        resource.setrlimit(resource.RLIMIT_CPU, (timeout + 2, timeout + 2))
        resource.setrlimit(resource.RLIMIT_AS, (MEMORY_BYTES, MEMORY_BYTES))
        resource.setrlimit(resource.RLIMIT_NPROC, (MAX_PROCESSES, MAX_PROCESSES))
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE_BYTES, MAX_FILE_BYTES))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    return _set_limits


def kill_group(pid):
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        pass


def read_capped(path):
    with open(path, "rb") as handle:
        data = handle.read(MAX_OUTPUT_BYTES + 1)
    truncated = len(data) > MAX_OUTPUT_BYTES
    return data[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace"), truncated


def execute(code, timeout):
    started_at = utc_now()
    started = time.monotonic()
    workdir = tempfile.mkdtemp(prefix="pbx-")
    result = None
    proc = None
    timed_out = False

    try:
        script_path = os.path.join(workdir, "main.py")
        stdout_path = os.path.join(workdir, "stdout.log")
        stderr_path = os.path.join(workdir, "stderr.log")

        with open(script_path, "w", encoding="utf-8") as handle:
            handle.write(code)

        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": workdir,
            "LANG": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONIOENCODING": "utf-8",
        }

        with open(stdout_path, "wb") as out_handle, open(stderr_path, "wb") as err_handle:
            proc = subprocess.Popen(
                [sys.executable, "-I", script_path],
                cwd=workdir,
                stdin=subprocess.DEVNULL,
                stdout=out_handle,
                stderr=err_handle,
                env=env,
                start_new_session=True,
                preexec_fn=apply_limits(timeout),
            )
            try:
                exit_code = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                kill_group(proc.pid)
                exit_code = proc.wait()

        # Kill anything the user code left running in its process group.
        kill_group(proc.pid)

        stdout, stdout_truncated = read_capped(stdout_path)
        stderr, stderr_truncated = read_capped(stderr_path)
        output_limit_exceeded = (
            exit_code == -signal.SIGXFSZ
            or os.path.getsize(stdout_path) >= MAX_FILE_BYTES
            or os.path.getsize(stderr_path) >= MAX_FILE_BYTES
        )

        if timed_out:
            status = "timed_out"
        elif output_limit_exceeded:
            status = "output_limit_exceeded"
        else:
            status = "completed"

        result = {
            "runner_version": RUNNER_VERSION,
            "status": status,
            "error": None,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "output_limit_exceeded": output_limit_exceeded,
            "stdout": stdout,
            "stderr": stderr,
            "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
        }
    finally:
        if proc is not None:
            kill_group(proc.pid)
        shutil.rmtree(workdir, ignore_errors=True)

    ended_at = utc_now()
    result.update({
        "started_at": started_at,
        "ended_at": ended_at,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "timeout_seconds": timeout,
        "cleanup_confirmed": not os.path.exists(workdir),
        "uid": os.getuid(),
        "python_version": sys.version.split()[0],
    })
    return result


def main():
    if os.geteuid() == 0:
        print(json.dumps(error_result("runner refuses to run as root")))
        return 1

    try:
        code, timeout = read_request()
    except (ValueError, json.JSONDecodeError) as err:
        print(json.dumps(error_result(str(err))))
        return 1

    print(json.dumps(execute(code, timeout)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
