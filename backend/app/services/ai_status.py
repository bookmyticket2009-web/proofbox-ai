"""
ProofBox AI - AI provider status probe.

Checks whether the configured AI provider is reachable and the key is accepted.
Results are cached briefly so the sidebar polling does not hit the provider on
every request. The API key is never included in the returned data.
"""

import os
import socket
import time
from typing import Any, Dict, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from dotenv import load_dotenv

load_dotenv()

CACHE_SECONDS = 60
PROBE_TIMEOUT = 8
DEFAULT_OLLAMA_URL = "https://ollama.com"
DEFAULT_MODEL = "gpt-oss:120b"

_cache: Dict[str, Any] = {"at": 0.0, "result": None}


def _is_local(base_url: str) -> bool:
    host = (urlparse(base_url).hostname or "").lower()
    return host in ("localhost", "127.0.0.1", "::1")


def _probe_vultr() -> Dict[str, Any]:
    api_key = (os.getenv("VULTR_INFERENCE_API_KEY") or "").strip()
    model = (os.getenv("VULTR_INFERENCE_MODEL") or "").strip()
    base_url = (os.getenv("VULTR_INFERENCE_BASE_URL") or "https://api.vultrinference.com/v1").strip().rstrip("/")

    if not api_key:
        return {"provider": "vultr", "model": model, "state": "no_key", "ok": False,
                "label": "No Vultr Inference key configured"}
    if not model:
        return {"provider": "vultr", "model": model, "state": "error", "ok": False,
                "label": "No Vultr Inference model configured"}

    try:
        request = Request(f"{base_url}/models", headers={
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "ProofBox-AI",
        })
        with urlopen(request, timeout=PROBE_TIMEOUT) as resp:
            if 200 <= resp.status < 300:
                return {"provider": "vultr", "model": model, "state": "connected", "ok": True,
                        "label": "Connected to Vultr Serverless Inference"}
            return {"provider": "vultr", "model": model, "state": "error", "ok": False,
                    "label": f"Unexpected response (HTTP {resp.status})"}
    except HTTPError as err:
        if err.code in (401, 403):
            return {"provider": "vultr", "model": model, "state": "invalid_key", "ok": False,
                    "label": "Vultr Inference key rejected"}
        return {"provider": "vultr", "model": model, "state": "error", "ok": False,
                "label": f"Provider error (HTTP {err.code})"}
    except (URLError, socket.timeout, OSError):
        return {"provider": "vultr", "model": model, "state": "unreachable", "ok": False,
                "label": "Vultr Inference unreachable"}


def _probe() -> Dict[str, Any]:
    provider = (os.getenv("AI_PROVIDER") or "vultr").strip().lower()
    if provider == "vultr":
        return _probe_vultr()
    model = os.getenv("OLLAMA_MODEL") or DEFAULT_MODEL

    if provider != "ollama":
        return {
            "provider": provider,
            "model": model,
            "state": "unsupported",
            "ok": False,
            "label": f"Provider '{provider}' is not supported by the backend",
        }

    base_url = (os.getenv("OLLAMA_BASE_URL") or DEFAULT_OLLAMA_URL).strip().rstrip("/")
    api_key = (os.getenv("OLLAMA_API_KEY") or "").strip()

    if not api_key and not _is_local(base_url):
        return {
            "provider": "ollama",
            "model": model,
            "state": "no_key",
            "ok": False,
            "label": "No API key configured",
        }

    headers = {"User-Agent": "ProofBox-AI"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        with urlopen(Request(f"{base_url}/api/tags", headers=headers), timeout=PROBE_TIMEOUT) as resp:
            if 200 <= resp.status < 300:
                return {"provider": "ollama", "model": model, "state": "connected", "ok": True,
                        "label": "Connected"}
            return {"provider": "ollama", "model": model, "state": "error", "ok": False,
                    "label": f"Unexpected response (HTTP {resp.status})"}
    except HTTPError as err:
        if err.code in (401, 403):
            return {"provider": "ollama", "model": model, "state": "invalid_key", "ok": False,
                    "label": "API key rejected"}
        return {"provider": "ollama", "model": model, "state": "error", "ok": False,
                "label": f"Provider error (HTTP {err.code})"}
    except (URLError, socket.timeout, OSError):
        return {"provider": "ollama", "model": model, "state": "unreachable", "ok": False,
                "label": "Provider unreachable"}


def check_ai_provider(force: bool = False) -> Dict[str, Any]:
    now = time.monotonic()
    cached: Optional[Dict[str, Any]] = _cache["result"]
    if not force and cached is not None and now - _cache["at"] < CACHE_SECONDS:
        return {**cached, "cached": True}

    result = _probe()
    _cache["at"] = now
    _cache["result"] = result
    return {**result, "cached": False}
