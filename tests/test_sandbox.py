"""
ProofBox AI - sandbox tests.

Two layers:
  1. Backend client (sandbox_service.py): input validation, config errors, result parsing.
  2. Runner (sandbox/runner.py): the safety controls, run as a non-root user.

The end-to-end tests use a fake "ssh" that runs the runner locally as a non-root
user, so the full protocol is exercised without a VM. They run on Linux only.
Run:  python tests/test_sandbox.py
"""

import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
RUNNER_SRC = BACKEND / "app" / "sandbox" / "runner.py"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services import sandbox_service as sbx  # noqa: E402

IS_LINUX = sys.platform.startswith("linux")
TEST_USER = os.getenv("PROOFBOX_TEST_USER", "pbxtest")
RUNNER_CHECKS = []


def _record(name, ok, info=""):
    RUNNER_CHECKS.append((name, ok))
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else f"  -> {info}"))


def _set_env(values):
    saved = {k: os.environ.get(k) for k in values}
    for k, v in values.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    return saved


def _restore(saved):
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def _temp_key():
    fd, path = tempfile.mkstemp(prefix="pbx-testkey-")
    os.write(fd, b"not-a-real-key")
    os.close(fd)
    return path


# ---------- 1. Backend client ----------

def test_missing_host_is_a_config_error():
    saved = _set_env({"SANDBOX_HOST": None, "SANDBOX_KEY_PATH": _temp_key()})
    try:
        try:
            sbx.load_config(); raise AssertionError("expected SandboxConfigError")
        except sbx.SandboxConfigError as err:
            assert "SANDBOX_HOST" in str(err)
    finally:
        _restore(saved)


def test_host_starting_with_dash_is_rejected():
    saved = _set_env({"SANDBOX_HOST": "-oProxyCommand=evil", "SANDBOX_KEY_PATH": _temp_key()})
    try:
        try:
            sbx.load_config(); raise AssertionError("expected rejection")
        except sbx.SandboxConfigError:
            pass
    finally:
        _restore(saved)


def test_ipv6_host_is_accepted():
    key = _temp_key()
    saved = _set_env({"SANDBOX_HOST": "2001:19f0:5401:2005:5400:07ff:fe04:e708", "SANDBOX_KEY_PATH": key})
    try:
        cfg = sbx.load_config()
        assert cfg["host"] == "2001:19f0:5401:2005:5400:07ff:fe04:e708"
    finally:
        _restore(saved)
        os.remove(key)


def test_bad_user_port_and_missing_key_are_rejected():
    key = _temp_key()
    cases = [
        {"SANDBOX_HOST": "203.0.113.10", "SANDBOX_KEY_PATH": key, "SANDBOX_USER": "root; rm -rf /"},
        {"SANDBOX_HOST": "203.0.113.10", "SANDBOX_KEY_PATH": key, "SANDBOX_PORT": "99999"},
        {"SANDBOX_HOST": "203.0.113.10", "SANDBOX_KEY_PATH": "/does/not/exist"},
    ]
    for env in cases:
        saved = _set_env({"SANDBOX_USER": None, "SANDBOX_PORT": None, **env})
        try:
            try:
                sbx.load_config(); raise AssertionError(f"accepted bad config: {env}")
            except sbx.SandboxConfigError:
                pass
        finally:
            _restore(saved)
    os.remove(key)


def test_empty_and_oversize_code_are_rejected_before_any_ssh_call():
    with patch.object(sbx.subprocess, "run") as run:
        for bad in ["", "   \n", "x" * (sbx.MAX_CODE_BYTES + 1)]:
            try:
                sbx.run_python(bad); raise AssertionError("expected ValueError")
            except ValueError:
                pass
        run.assert_not_called()


def test_timeout_is_clamped_and_validated():
    assert sbx._clamp_timeout(None) == sbx.DEFAULT_TIMEOUT
    assert sbx._clamp_timeout(0) == 1
    assert sbx._clamp_timeout(10_000) == sbx.MAX_TIMEOUT
    try:
        sbx._clamp_timeout("5"); raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_parser_skips_banners_and_rejects_garbage():
    text = "Warning: Permanently added host\n{\"status\": \"completed\", \"stdout\": \"ok\"}\n"
    assert sbx._parse_runner_output(text)["status"] == "completed"
    assert sbx._parse_runner_output("Permission denied (publickey).") is None
    assert sbx._parse_runner_output("{broken json") is None


def test_missing_ssh_binary_is_reported_as_config_error():
    key = _temp_key()
    saved = _set_env({"SANDBOX_HOST": "203.0.113.10", "SANDBOX_KEY_PATH": key,
                      "SANDBOX_SSH_BIN": "/definitely/not/ssh"})
    try:
        try:
            sbx.run_python("print(1)"); raise AssertionError("expected SandboxConfigError")
        except sbx.SandboxConfigError as err:
            assert "not found" in str(err)
    finally:
        _restore(saved)
        os.remove(key)


def test_ssh_command_never_contains_user_code():
    key = _temp_key()
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["input"] = kwargs.get("input")
        return subprocess.CompletedProcess(cmd, 0, stdout='{"status": "completed", "stdout": ""}', stderr="")

    saved = _set_env({"SANDBOX_HOST": "203.0.113.10", "SANDBOX_KEY_PATH": key,
                      "SANDBOX_SSH_BIN": "ssh", "SANDBOX_USER": None, "SANDBOX_PORT": None})
    try:
        with patch.object(sbx.subprocess, "run", side_effect=fake_run):
            sbx.run_python("print('$(touch /tmp/pwned)'); import os; os.system('id')")
        joined = " ".join(captured["cmd"])
        assert "touch" not in joined and "os.system" not in joined, "user code leaked into the ssh command"
        assert captured["cmd"][-1] == f"python3 {sbx.REMOTE_RUNNER}"
        assert "os.system" in json.loads(captured["input"])["code"]
        assert "BatchMode=yes" in captured["cmd"] and "StrictHostKeyChecking=yes" in captured["cmd"]
    finally:
        _restore(saved)
        os.remove(key)


# ---------- 2. End-to-end through a fake ssh (Linux, needs runuser + a non-root test user) ----------

def _e2e_available():
    if not IS_LINUX or shutil.which("runuser") is None:
        return False
    return subprocess.run(["id", TEST_USER], capture_output=True).returncode == 0


def _make_fake_ssh(tmpdir, mode="runner"):
    os.chmod(tmpdir, 0o755)  # the non-root runner must be able to read this directory
    script = Path(tmpdir) / "fake_ssh.sh"
    runner_copy = Path(tmpdir) / "runner.py"
    shutil.copy(RUNNER_SRC, runner_copy)
    os.chmod(runner_copy, 0o755)
    if mode == "runner":
        body = (f'echo "$@" > {tmpdir}/last_args.txt\n'
                f'exec runuser -u {TEST_USER} -- python3 {runner_copy}\n')
    else:  # simulates ssh printing an error instead of running the runner
        body = 'echo "Permission denied (publickey)." >&2\nexit 255\n'
    script.write_text("#!/bin/sh\n" + body)
    os.chmod(script, 0o755)
    return str(script)


def _run_e2e(code, timeout=5, mode="runner"):
    tmpdir = tempfile.mkdtemp(prefix="pbx-e2e-")
    key = _temp_key()
    fake = _make_fake_ssh(tmpdir, mode)
    saved = _set_env({"SANDBOX_HOST": "203.0.113.10", "SANDBOX_KEY_PATH": key,
                      "SANDBOX_SSH_BIN": fake, "SANDBOX_USER": "sandbox", "SANDBOX_PORT": None})
    try:
        return sbx.run_python(code, timeout=timeout), tmpdir
    finally:
        _restore(saved)
        os.remove(key)


def e2e_tests():
    if not _e2e_available():
        print("SKIP  end-to-end tests (need Linux, runuser, and user '%s')" % TEST_USER)
        return

    res, _ = _run_e2e("print('hello from the sandbox')")
    _record("e2e: completed run returns stdout", res["status"] == "completed" and res["stdout"] == "hello from the sandbox\n", res)
    _record("e2e: result records host and timing",
            res.get("sandbox_host") == "203.0.113.10" and (res.get("duration_ms") or 0) >= 0, res)

    res, _ = _run_e2e("import time\ntime.sleep(60)", timeout=2)
    _record("e2e: timeout reported", res["status"] == "timed_out" and res["timed_out"] is True, res.get("status"))

    res, _ = _run_e2e("raise ValueError('boom')")
    _record("e2e: runtime error keeps exit code and stderr", res["exit_code"] == 1 and "ValueError" in res["stderr"], res.get("exit_code"))

    res, tmpdir = _run_e2e("print('x')")
    args = Path(tmpdir, "last_args.txt").read_text()
    _record("e2e: ssh args carry no user code", "print" not in args and "python3 " in args, args)

    res, _ = _run_e2e("print(1)", mode="ssh-fails")
    _record("e2e: ssh failure returned as error, not a crash",
            res["status"] == "error" and "Permission denied" in res["error"], res.get("error"))


def test_check_sandbox_requires_all_three_checks():
    def fake_run(code, timeout=None):
        if "proofbox-sandbox-ok" in code:
            return {"status": "completed", "stdout": "proofbox-sandbox-ok\n", "cleanup_confirmed": True,
                    "sandbox_host": "203.0.113.10"}
        return {"status": "completed", "stdout": "blocked\n", "cleanup_confirmed": True}

    with patch.object(sbx, "run_python", side_effect=fake_run):
        ready = sbx.check_sandbox(force=True)
    assert ready["ok"] is True and ready["state"] == "ready", ready

    def leaky(code, timeout=None):
        if "proofbox-sandbox-ok" in code:
            return {"status": "completed", "stdout": "proofbox-sandbox-ok\n", "cleanup_confirmed": True}
        return {"status": "completed", "stdout": "reachable\n", "cleanup_confirmed": True}

    with patch.object(sbx, "run_python", side_effect=leaky):
        leak = sbx.check_sandbox(force=True)
    assert leak["ok"] is False and leak["checks"]["network_isolation"] is False, leak

    # A passing result is cached: a second call without force does not run the checks again
    with patch.object(sbx, "run_python", side_effect=fake_run):
        sbx.check_sandbox(force=True)
    with patch.object(sbx, "run_python", side_effect=AssertionError("should not run")):
        assert sbx.check_sandbox()["cached"] is True

    def no_cleanup(code, timeout=None):
        if "proofbox-sandbox-ok" in code:
            return {"status": "completed", "stdout": "proofbox-sandbox-ok\n", "cleanup_confirmed": False}
        return {"status": "completed", "stdout": "blocked\n", "cleanup_confirmed": True}

    with patch.object(sbx, "run_python", side_effect=no_cleanup):
        assert sbx.check_sandbox(force=True)["checks"]["cleanup"] is False


def test_check_sandbox_not_configured_is_not_ready():
    saved = _set_env({"SANDBOX_HOST": None})
    try:
        result = sbx.check_sandbox(force=True)
        assert result["ok"] is False and result["state"] == "not_configured"
    finally:
        _restore(saved)

# ---------- 3. Runner safety controls (run as the non-root user) ----------

def runner_tests():
    if not _e2e_available():
        print("SKIP  runner safety tests (need Linux, runuser, and user '%s')" % TEST_USER)
        return

    tmp = tempfile.mkdtemp(prefix="pbx-runner-")
    os.chmod(tmp, 0o755)
    runner = Path(tmp) / "runner.py"
    shutil.copy(RUNNER_SRC, runner)
    os.chmod(runner, 0o755)
    os.chmod(tmp, 0o755)

    def run(req, as_user=True, raw=None):
        body = raw if raw is not None else json.dumps(req)
        cmd = ["runuser", "-u", TEST_USER, "--", sys.executable, str(runner)] if as_user else [sys.executable, str(runner)]
        p = subprocess.run(cmd, input=body, capture_output=True, text=True, timeout=120)
        lines = [l for l in p.stdout.splitlines() if l.startswith("{")]
        return json.loads(lines[-1]) if lines else {"status": "no-output", "stderr": p.stderr[-300:]}

    before = len(glob.glob("/tmp/pbx-*"))

    r = run({"code": "print('hello')", "timeout": 5})
    _record("runner: normal run", r["status"] == "completed" and r["stdout"] == "hello\n" and r["exit_code"] == 0, r)
    _record("runner: runs as non-root", r.get("uid", 0) != 0, r.get("uid"))
    _record("runner: cleanup confirmed", r.get("cleanup_confirmed") is True)

    r = run({"code": "import time\ntime.sleep(60)", "timeout": 2})
    _record("runner: timeout enforced", r["status"] == "timed_out", r.get("status"))

    r = run({"code": "print('x' * 200000)", "timeout": 5})
    _record("runner: stdout capped at 64KB", len(r["stdout"]) <= 64 * 1024 and r["stdout_truncated"], len(r.get("stdout", "")))

    r = run({"code": "import sys\nwhile True:\n    sys.stdout.write('y' * 4096)", "timeout": 10})
    _record("runner: output flood stopped", r["status"] == "output_limit_exceeded", r.get("status"))

    r = run({"code": "x = bytearray(400 * 1024 * 1024)", "timeout": 5})
    _record("runner: memory limit enforced", r["exit_code"] != 0 and "MemoryError" in r["stderr"], r.get("stderr", "")[-120:])

    r = run({"code": "import subprocess\nsubprocess.Popen(['sleep', '300'])\nprint('done')", "timeout": 5})
    _record("runner: leftover child killed", r["status"] == "completed" and r["stdout"] == "done\n", r.get("status"))

    r = run({"code": "print(1)", "timeout": 5}, as_user=False)
    _record("runner: refuses root", r["status"] == "error" and "root" in r["error"], r)

    r = run(None, raw="{not json")
    _record("runner: invalid JSON rejected", r["status"] == "error", r)

    r = run({"code": "a" * 25000, "timeout": 5})
    _record("runner: oversize code rejected", r["status"] == "error" and "limit" in r["error"], r.get("error"))

    after = len(glob.glob("/tmp/pbx-*"))
    _record("runner: no temp directories left behind", after <= before, f"before={before} after={after}")

    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unit = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failures = 0
    for name, fn in unit:
        try:
            fn()
            print(f"PASS  {name}")
        except AssertionError as err:
            failures += 1
            print(f"FAIL  {name}: {err}")
        except Exception as err:  # noqa: BLE001
            failures += 1
            print(f"ERROR {name}: {type(err).__name__}: {err}")
    e2e_tests()
    runner_tests()
    failed = failures + sum(1 for _, ok in RUNNER_CHECKS if not ok)
    total = len(unit) + len(RUNNER_CHECKS)
    print(f"\n{total - failed}/{total} passed")
    sys.exit(1 if failed else 0)
