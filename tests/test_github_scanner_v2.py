"""
ProofBox AI - backend tests.

Run from the project root with:  pytest tests/
or without pytest:               python tests/test_github_scanner_v2.py

GitHub is never contacted: the network helpers are replaced with fixtures.
"""

import sys
from pathlib import Path
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.services import github_service  # noqa: E402
from app.services.export_service import build_sarif  # noqa: E402
from app.services.verification_service import VerificationService  # noqa: E402

COMMIT = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
# Realistic-looking key. Avoid placeholder words such as "example", which the scanner ignores on purpose.
AWS_KEY = "AKIAQ3XJ7PLMN2RTVWZ8"


def _fake_github(file_count: int, extra_entries=None):
    """Return a fake _github_json that serves a tree with `file_count` Python files."""
    tree = [
        {"path": f"module_{i}.py", "type": "blob", "size": 500} for i in range(file_count)
    ] + (extra_entries or [])

    def fake_json(url: str):
        if url.endswith("/commits/main"):
            return {"sha": COMMIT}
        if "/git/trees/" in url:
            return {"tree": tree, "truncated": False}
        if url.endswith("/mock-repo"):
            return {"default_branch": "main"}
        raise AssertionError(f"unexpected GitHub URL in test: {url}")

    return fake_json


def _run_stream(file_count=3, contents=None, cancel_check=None, max_files=100, extra_entries=None):
    contents = contents or {}

    def fake_fetch(owner, repo, sha, path):
        return contents.get(path, "x = 1\n")

    with patch.object(github_service, "_github_json", _fake_github(file_count, extra_entries)), \
         patch.object(github_service, "_fetch_text_file", fake_fetch):
        return list(github_service.scan_github_repository_stream(
            "https://github.com/mock-owner/mock-repo",
            max_files=max_files,
            cancel_check=cancel_check,
        ))


def _completed(events):
    return next(e["result"] for e in events if e["event"] == "completed")


# ---------- GitHub scanner ----------

def test_file_limit_and_partial_accounting():
    result = _completed(_run_stream(file_count=52, max_files=10))
    assert result["summary"]["files_discovered"] == 52
    assert result["summary"]["files_scanned"] == 10
    assert result["summary"]["files_skipped"] == 42
    assert result["partial_scan"] is True
    assert result["commit"] == COMMIT
    assert result["cancelled"] is False


def test_max_files_is_clamped_to_500():
    events = _run_stream(file_count=3, max_files=10_000)
    assert _completed(events)["limits"]["max_files"] == 500


def test_each_scanned_file_streams_its_findings_live():
    contents = {"module_0.py": f"key = '{AWS_KEY}'\n"}
    events = _run_stream(file_count=2, contents=contents)
    progress = [e for e in events if e["event"] == "file_progress" and e["status"] == "scanned"]
    assert len(progress) == 2

    first = progress[0]
    assert first["file"] == "module_0.py"
    assert first["new_findings"] == len(first["findings"]) >= 1
    assert first["findings"][0]["rule_name"] == "AWS Access Key"

    # Live findings must already be redacted
    assert AWS_KEY not in first["findings"][0]["line_snippet"]


def test_cancel_stops_early_and_returns_partial_results():
    calls = {"n": 0}

    def cancel_after_three():
        calls["n"] += 1
        return calls["n"] > 3  # allow files 1-3, cancel before file 4

    events = _run_stream(file_count=10, cancel_check=cancel_after_three)
    result = _completed(events)

    assert result["cancelled"] is True
    assert result["status"] == "cancelled"
    assert result["partial_scan"] is True
    assert result["summary"]["files_scanned"] == 3
    assert result["scanned_files"] == ["module_0.py", "module_1.py", "module_2.py"]


def test_cancel_before_start_scans_nothing():
    result = _completed(_run_stream(file_count=5, cancel_check=lambda: True))
    assert result["summary"]["files_scanned"] == 0
    assert result["cancelled"] is True


def test_secrets_are_redacted_in_final_findings():
    contents = {"module_0.py": f"key = '{AWS_KEY}'\n"}
    result = _completed(_run_stream(file_count=1, contents=contents))
    assert result["findings"], "expected at least one finding"
    for f in result["findings"]:
        assert AWS_KEY not in f["line_snippet"]


def test_string_literals_do_not_trigger_code_rules():
    # A regex utility calling .exec() should not be flagged as Python exec()
    contents = {"module_0.py": "import re\nm = re.compile('x').exec('y')\n"}
    result = _completed(_run_stream(file_count=1, contents=contents))
    assert all(f["rule_name"] != "Dynamic Code Execution (eval/exec)" for f in result["findings"])


# ---------- SARIF export ----------

def test_sarif_structure_and_levels():
    job = {
        "id": "job-123",
        "job_type": "github_scan",
        "target": "https://github.com/mock-owner/mock-repo",
        "commit_sha": COMMIT,
        "findings": [
            {"rule_name": "AWS Access Key", "severity": "critical", "file": "a.py",
             "line_number": 4, "line_snippet": "key = 'AKIA****'", "remediation": "Revoke key."},
            {"rule_name": "Unsafe YAML Loading", "severity": "medium", "file": "b.py",
             "line_number": 9, "line_snippet": "yaml.load(x)", "remediation": "Use safe_load."},
        ],
    }
    sarif = build_sarif(job)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "ProofBox AI"
    assert len(run["tool"]["driver"]["rules"]) == 2
    levels = [r["level"] for r in run["results"]]
    assert levels == ["error", "warning"]
    region = run["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 4
    assert "AKIA" in region["snippet"]["text"] and "IOSFODNN7EXAMPLE" not in region["snippet"]["text"]


def test_sarif_handles_empty_job():
    sarif = build_sarif({"id": "x", "findings": []})
    assert sarif["runs"][0]["results"] == []


# ---------- Verification service (static analysis of pasted code) ----------

def test_verification_detects_secrets_and_redacts():
    verifier = VerificationService()
    code_sample = f"""
    aws_key = "{AWS_KEY}"
    github_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    """
    findings = verifier.analyze_code(code_sample, "test_secrets.py")
    rule_ids = {f["rule_id"] for f in findings}
    assert "AWS_ACCESS_KEY" in rule_ids
    assert "GITHUB_PAT" in rule_ids
    for f in findings:
        assert "ghp_1234567890abcdefghijklmnopqrstuvwxyz" not in f["line_snippet"]
        assert AWS_KEY not in f["line_snippet"]
        assert "Static security heuristics assist" in f["description"]


def test_verification_detects_dangerous_patterns():
    verifier = VerificationService()
    vulnerable_code = """
import pickle, yaml, hashlib
def process(payload):
    eval(payload)
    data = pickle.loads(payload)
    doc = yaml.load(payload)
    sig = hashlib.md5(payload.encode()).hexdigest()
    return sig
"""
    rule_ids = {f["rule_id"] for f in verifier.analyze_code(vulnerable_code, "app.py")}
    assert "DANGEROUS_EXEC" in rule_ids
    assert "UNSAFE_DESERIALIZATION_PICKLE" in rule_ids
    assert "UNSAFE_YAML_LOAD" in rule_ids


# ---------- AI provider status ----------

def _status_with(env: dict, urlopen_side_effect=None):
    import os
    from app.services import ai_status
    ai_status._cache.update(at=0.0, result=None)
    keys = ["AI_PROVIDER", "OLLAMA_API_KEY", "OLLAMA_BASE_URL", "OLLAMA_MODEL"]
    saved = {k: os.environ.get(k) for k in keys}
    try:
        for k in keys:
            os.environ.pop(k, None)
        os.environ.update(env)
        if urlopen_side_effect is None:
            return ai_status.check_ai_provider(force=True)
        with patch.object(ai_status, "urlopen", side_effect=urlopen_side_effect):
            return ai_status.check_ai_provider(force=True)
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_ai_status_reports_missing_key_without_calling_provider():
    result = _status_with({"AI_PROVIDER": "ollama"})
    assert result["state"] == "no_key"
    assert result["ok"] is False


def test_ai_status_unsupported_provider():
    result = _status_with({"AI_PROVIDER": "azure", "OLLAMA_API_KEY": "k"})
    assert result["state"] == "unsupported"


def test_ai_status_rejected_key():
    from urllib.error import HTTPError
    err = HTTPError("https://ollama.com/api/tags", 401, "Unauthorized", None, None)
    result = _status_with({"AI_PROVIDER": "ollama", "OLLAMA_API_KEY": "bad"}, urlopen_side_effect=err)
    assert result["state"] == "invalid_key"


def test_ai_status_connected_and_never_leaks_key():
    class FakeResponse:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *a): return False

    secret = "super-secret-key-value"
    result = _status_with({"AI_PROVIDER": "ollama", "OLLAMA_API_KEY": secret},
                          urlopen_side_effect=lambda *a, **k: FakeResponse())
    assert result["state"] == "connected" and result["ok"] is True
    assert secret not in repr(result)


def test_ai_status_unreachable():
    from urllib.error import URLError
    result = _status_with({"AI_PROVIDER": "ollama", "OLLAMA_API_KEY": "k"},
                          urlopen_side_effect=URLError("no route"))
    assert result["state"] == "unreachable"


def test_missing_colon_is_a_syntax_error():
    from app.services.verification_service import check_python_syntax
    bad = 'def test_error_handling()\n    print("Missing a colon on the def line")\n'
    error = check_python_syntax(bad)
    assert error is not None and error["line_number"] == 1, error
    findings = VerificationService().analyze_code(bad, "t.py")
    assert any(f["rule_id"] == "PYTHON_SYNTAX_ERROR" and f["line_number"] == 1 for f in findings), findings


def test_valid_code_has_no_syntax_error():
    from app.services.verification_service import check_python_syntax
    assert check_python_syntax("def f(x):\n    return x + 1\n") is None



if __name__ == "__main__":
    tests = [(name, fn) for name, fn in sorted(globals().items()) if name.startswith("test_") and callable(fn)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS  {name}")
        except AssertionError as err:
            failed += 1
            print(f"FAIL  {name}: {err}")
        except Exception as err:  # noqa: BLE001
            failed += 1
            print(f"ERROR {name}: {type(err).__name__}: {err}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
