"""
ProofBox AI - AI provider tests (no network: the HTTP layer is replaced with fakes).
Run:  python tests/test_ai_service.py
"""

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services import ai_service, ai_status  # noqa: E402


class FakeResponse:
    def __init__(self, payload, status=200):
        self._body = json.dumps(payload).encode("utf-8")
        self.status = status

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _env(values):
    keys = ["AI_PROVIDER", "VULTR_INFERENCE_API_KEY", "VULTR_INFERENCE_MODEL",
            "VULTR_INFERENCE_BASE_URL", "OLLAMA_API_KEY"]
    saved = {k: os.environ.get(k) for k in keys}
    for k in keys:
        os.environ.pop(k, None)
    os.environ.update(values)
    return saved


def _restore(saved):
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def test_vultr_generate_code_uses_chat_format_and_model():
    saved = _env({"AI_PROVIDER": "vultr", "VULTR_INFERENCE_API_KEY": "k-test",
                  "VULTR_INFERENCE_MODEL": "test-model"})
    captured = {}

    def fake_urlopen(request, timeout=None):
        captured["url"] = request.full_url
        captured["auth"] = request.get_header("Authorization")
        captured["body"] = json.loads(request.data.decode("utf-8"))
        return FakeResponse({"choices": [{"message": {"content": "print(2 + 3)"}}]})

    try:
        with patch.object(ai_service.urllib.request, "urlopen", side_effect=fake_urlopen):
            code = ai_service.generate_code("add two numbers")
        assert code.strip() == "print(2 + 3)", code
        assert captured["url"] == "https://api.vultrinference.com/v1/chat/completions", captured["url"]
        assert captured["auth"] == "Bearer k-test"
        assert captured["body"]["model"] == "test-model"
        roles = [m["role"] for m in captured["body"]["messages"]]
        assert roles == ["system", "user"], roles
    finally:
        _restore(saved)


def test_missing_vultr_key_is_a_clear_error():
    saved = _env({"AI_PROVIDER": "vultr", "VULTR_INFERENCE_MODEL": "m"})
    try:
        try:
            ai_service.generate_code("x"); raise AssertionError("expected RuntimeError")
        except RuntimeError as err:
            assert "VULTR_INFERENCE_API_KEY" in str(err)
    finally:
        _restore(saved)


def test_vultr_status_connected_and_key_never_shown():
    saved = _env({"AI_PROVIDER": "vultr", "VULTR_INFERENCE_API_KEY": "secret-value-123",
                  "VULTR_INFERENCE_MODEL": "m"})
    ai_status._cache.update(at=0.0, result=None)
    try:
        with patch.object(ai_status, "urlopen", return_value=FakeResponse({"data": []})):
            result = ai_status.check_ai_provider(force=True)
        assert result["state"] == "connected" and result["ok"] is True, result
        assert "secret-value-123" not in repr(result)
    finally:
        _restore(saved)


def test_stray_tags_and_fences_are_removed():
    dirty = "<final>\ndef add(a, b):\n    return a + b\n</final>\n"
    cleaned = ai_service.clean_generated_code(dirty)
    assert "<final>" not in cleaned and "</final>" not in cleaned
    assert "def add(a, b):" in cleaned and "return a + b" in cleaned
    fenced = ai_service.clean_generated_code("```python\nprint(1)\n```")
    assert fenced.strip() == "print(1)", repr(fenced)


def test_generated_code_passes_syntax_check_after_cleaning():
    from app.services.verification_service import check_python_syntax
    cleaned = ai_service.clean_generated_code("def add(a, b):\n    return a + b\n</final>\n")
    assert check_python_syntax(cleaned) is None


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS  {name}")
        except Exception as err:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {name}: {type(err).__name__}: {err}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
