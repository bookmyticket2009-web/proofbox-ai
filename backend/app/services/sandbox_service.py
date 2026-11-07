"""
ProofBox AI - remote sandbox client.

Sends Python source to the disposable sandbox VM over SSH and returns the
runner's result. The code travels on stdin as JSON and is never placed in a
shell command, so it cannot inject shell syntax on either side.

Environment variables
  SANDBOX_HOST        IP address or hostname of the sandbox VM (required)
  SANDBOX_USER        SSH user on the VM, default "sandbox"
  SANDBOX_KEY_PATH    path to the SSH private key file (required)
  SANDBOX_PORT        SSH port, default 22
  SANDBOX_SSH_BIN     ssh executable, default "ssh" (used by tests)
"""

import ipaddress
import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

MAX_CODE_BYTES = 20 * 1000
MAX_OUTPUT_CHARS = 64 * 1024
DEFAULT_TIMEOUT = 10
MAX_TIMEOUT = 30
REMOTE_RUNNER = "/opt/proofbox/runner.py"

_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,252}$")
_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


class SandboxConfigError(RuntimeError):
    """Raised when the sandbox is not configured correctly."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_valid_host(host: str) -> bool:
    """Accept IPv4, IPv6 (e.g. Vultr's IPv6-only instances) or a plain hostname."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_HOST_RE.match(host))


def load_config() -> Dict[str, str]:
    host = os.getenv("SANDBOX_HOST", "").strip()
    user = os.getenv("SANDBOX_USER", "sandbox").strip()
    key = os.getenv("SANDBOX_KEY_PATH", "").strip()
    port = os.getenv("SANDBOX_PORT", "22").strip()
    ssh_bin = os.getenv("SANDBOX_SSH_BIN", "ssh").strip() or "ssh"

    if not host:
        raise SandboxConfigError("SANDBOX_HOST is not set.")
    if not _is_valid_host(host):
        raise SandboxConfigError("SANDBOX_HOST is not a valid IP address or hostname.")
    if not _USER_RE.match(user):
        raise SandboxConfigError("SANDBOX_USER is not a valid username.")
    if not key or not os.path.isfile(key):
        raise SandboxConfigError("SANDBOX_KEY_PATH must point to an existing private key file.")
    if not port.isdigit() or not (1 <= int(port) <= 65535):
        raise SandboxConfigError("SANDBOX_PORT must be a number between 1 and 65535.")

    return {"host": host, "user": user, "key": key, "port": port, "ssh_bin": ssh_bin}


def _clamp_timeout(timeout: Optional[int]) -> int:
    if timeout is None:
        return DEFAULT_TIMEOUT
    if isinstance(timeout, bool) or not isinstance(timeout, int):
        raise ValueError("timeout must be an integer number of seconds.")
    return max(1, min(timeout, MAX_TIMEOUT))


def _error(message: str, meta: Dict[str, Any], **extra: Any) -> Dict[str, Any]:
    result = {
        "status": "error",
        "error": message,
        "exit_code": None,
        "timed_out": False,
        "output_limit_exceeded": False,
        "stdout": "",
        "stderr": "",
        "stdout_truncated": False,
        "stderr_truncated": False,
        "cleanup_confirmed": None,
    }
    result.update(meta)
    result.update(extra)
    return result


def _parse_runner_output(text: str) -> Optional[Dict[str, Any]]:
    """The runner prints one JSON object. SSH may print banners before it, so use the last JSON line."""
    for line in reversed(text.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict) and "status" in data:
                return data
    return None


def _trim(text: str) -> tuple:
    if len(text) > MAX_OUTPUT_CHARS:
        return text[:MAX_OUTPUT_CHARS], True
    return text, False


def run_python(code: str, timeout: Optional[int] = None) -> Dict[str, Any]:
    """Run Python source on the sandbox VM and return the result.

    Raises ValueError for invalid input and SandboxConfigError for a bad setup.
    Execution problems (timeouts, SSH failures, crashes) are returned as
    status "error" / "timed_out" so the caller can always record them.
    """
    if not isinstance(code, str) or not code.strip():
        raise ValueError("Code must be a non-empty string.")
    size = len(code.encode("utf-8"))
    if size > MAX_CODE_BYTES:
        raise ValueError(f"Code is {size} bytes; the limit is {MAX_CODE_BYTES}.")

    timeout = _clamp_timeout(timeout)
    cfg = load_config()  # raises SandboxConfigError if misconfigured

    meta = {
        "sandbox_host": cfg["host"],
        "sandbox_user": cfg["user"],
        "timeout_seconds": timeout,
        "requested_at": utc_now(),
    }

    command = [
        cfg["ssh_bin"],
        "-i", cfg["key"],
        "-p", cfg["port"],
        "-o", "BatchMode=yes",                 # never prompt for a password
        "-o", "StrictHostKeyChecking=yes",     # refuse unknown or changed host keys
        "-o", "ConnectTimeout=10",
        "-o", "ServerAliveInterval=5",
        f"{cfg['user']}@{cfg['host']}",
        f"python3 {REMOTE_RUNNER}",            # constant command; user code is not in it
    ]
    payload = json.dumps({"code": code, "timeout": timeout})

    try:
        proc = subprocess.run(
            command,
            input=payload,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout + 30,
        )
    except subprocess.TimeoutExpired:
        return _error("The sandbox did not respond in time.", meta, status="timed_out",
                      timed_out=True, cleanup_confirmed=None)
    except FileNotFoundError:
        raise SandboxConfigError(f"SSH client '{cfg['ssh_bin']}' was not found on this machine.")
    except OSError as err:
        return _error(f"Could not start SSH: {err}", meta)

    result = _parse_runner_output(proc.stdout)
    if result is None:
        detail = (proc.stderr or "").strip()[-500:] or "no output from the sandbox"
        return _error(f"Sandbox returned no valid result: {detail}", meta,
                      ssh_exit_code=proc.returncode)

    stdout, stdout_cut = _trim(str(result.get("stdout", "")))
    stderr, stderr_cut = _trim(str(result.get("stderr", "")))
    result["stdout"] = stdout
    result["stderr"] = stderr
    result["stdout_truncated"] = bool(result.get("stdout_truncated")) or stdout_cut
    result["stderr_truncated"] = bool(result.get("stderr_truncated")) or stderr_cut
    result["ssh_exit_code"] = proc.returncode
    result.update(meta)
    return result


# Runs inside the sandbox. It prints "blocked" when the sandbox user cannot reach the internet.
NETWORK_PROBE = (
    "import socket\n"
    "try:\n"
    "    socket.create_connection(('1.1.1.1', 53), 3)\n"
    "    print('reachable')\n"
    "except OSError:\n"
    "    print('blocked')\n"
)


CHECK_CACHE_SECONDS = 60
_check_cache: Dict[str, Any] = {"at": 0.0, "result": None}


def check_sandbox(force: bool = False) -> Dict[str, Any]:
    """Return the sandbox readiness check. A passing result is cached for 60 seconds,
    because the check makes real SSH connections. Failing results are never cached,
    so problems are rechecked immediately."""
    now = time.monotonic()
    if not force and _check_cache["result"] is not None and now - _check_cache["at"] < CHECK_CACHE_SECONDS:
        return {**_check_cache["result"], "cached": True}

    result = _run_sandbox_checks()
    if result.get("ok"):
        _check_cache.update(at=now, result=result)
    else:
        _check_cache.update(at=0.0, result=None)
    return {**result, "cached": False}


def _run_sandbox_checks() -> Dict[str, Any]:
    """Verify the sandbox before it is shown as ready.

    Checks, each made with a real run on the server:
      connection        - a trivial job runs and returns the expected output
      cleanup           - the runner confirmed its temporary folder was removed
      network_isolation - code running in the sandbox cannot open an internet connection
    """
    try:
        basic = run_python("print('proofbox-sandbox-ok')", timeout=5)
        probe = run_python(NETWORK_PROBE, timeout=10)
    except (ValueError, SandboxConfigError) as err:
        return {
            "ok": False,
            "state": "not_configured",
            "label": str(err),
            "checks": {"connection": False, "cleanup": False, "network_isolation": False},
        }

    connection = basic.get("status") == "completed" and basic.get("stdout", "").strip() == "proofbox-sandbox-ok"
    cleanup = basic.get("cleanup_confirmed") is True
    network_blocked = probe.get("status") == "completed" and probe.get("stdout", "").strip() == "blocked"

    checks = {"connection": connection, "cleanup": cleanup, "network_isolation": network_blocked}
    ready = all(checks.values())

    if ready:
        label = "Sandbox ready: connected, cleaned up, and internet access blocked"
    elif not connection:
        label = basic.get("error") or "Sandbox did not return the expected result"
    elif not network_blocked:
        label = "Sandbox can reach the internet. Network isolation is not in place."
    else:
        label = "Sandbox cleanup could not be confirmed"

    return {
        "ok": ready,
        "state": "ready" if ready else "not_ready",
        "label": label,
        "sandbox_host": basic.get("sandbox_host"),
        "checks": checks,
    }
