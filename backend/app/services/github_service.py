"""
ProofBox AI - GitHub Scanner Service v2
Bounded static analysis of public repositories with line-by-line secret
detection, execution risk detection, SHA pinning, and live per-file streaming.
"""

import json
import os
import re
import socket
from typing import Any, Callable, Dict, Generator, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from dotenv import load_dotenv

load_dotenv()


def _get_env_int(key: str, default: int) -> int:
    val = os.getenv(key)
    if not val:
        return default
    try:
        parsed = int(val.strip())
        return parsed if parsed > 0 else default
    except ValueError:
        return default


# Production limits: 10 MB per file, 100 MB total repo payload (never cuts off normal repos)
MAX_FILE_BYTES = _get_env_int("GITHUB_MAX_FILE_BYTES", 10_000_000)
MAX_TOTAL_BYTES = _get_env_int("GITHUB_MAX_TOTAL_BYTES", 100_000_000)
MAX_RESPONSE_BYTES = _get_env_int("GITHUB_MAX_RESPONSE_BYTES", 20_000_000)
REQUEST_TIMEOUT = _get_env_int("GITHUB_REQUEST_TIMEOUT", 25)

GITHUB_API_BASE = "https://api.github.com"
GITHUB_RAW_BASE = "https://raw.githubusercontent.com"

SKIP_DIRECTORIES = {
    ".git", ".venv", "venv", "node_modules", "__pycache__",
    "dist", "build", "vendor", ".next", "coverage",
}

SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx",
    ".java", ".c", ".cpp", ".h", ".hpp",
    ".go", ".rs", ".php", ".rb",
    ".html", ".css", ".sh", ".ps1",
    ".yaml", ".yml", ".json", ".toml",
    ".ini", ".cfg", ".xml", ".sql",
    ".env", ".tf", ".mjs", ".cjs"
}

SPECIAL_FILENAMES = {
    "dockerfile", "makefile", "requirements.txt",
}

SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]

SECRET_PATTERNS = [
    ("AWS Access Key", "critical", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), "Revoke key in AWS IAM."),
    ("AWS Secret Key", "critical", re.compile(r"(?i)(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]"), "Rotate AWS secret key immediately."),
    ("GitHub Personal Access Token", "critical", re.compile(r"\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b"), "Revoke token via GitHub Developer Settings."),
    ("GitHub OAuth / App Token", "critical", re.compile(r"\b(gho_[0-9a-zA-Z]{36}|ghs_[0-9a-zA-Z]{36}|ghr_[0-9a-zA-Z]{36})\b"), "Invalidate OAuth application credentials."),
    ("Google API Key", "high", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"), "Restrict Google API key in GCP console."),
    ("Slack Token", "critical", re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32})\b"), "Revoke Slack token in App management console."),
    ("Stripe API Key", "critical", re.compile(r"\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,})\b"), "Rotate Stripe keys in developer dashboard."),
    ("Hardcoded Bearer Token", "high", re.compile(r"(?i)['\"]bearer\s+([a-zA-Z0-9_\-\.]{25,})['\"]"), "Inject authorization tokens at runtime via environment variables."),
]

# Excludes methods like regex.exec() from being flagged as Python eval/exec
CODE_PATTERNS = [
    ("Dynamic Code Execution (eval/exec)", "high", re.compile(r"(?<![\.\w$])(?:eval|exec)\s*\((?!\s*['\"][a-zA-Z0-9_]+['\"]\s*\))"), "Avoid dynamic eval/exec; use safe parsing like ast.literal_eval."),
    ("Subprocess Shell Injection Risk", "high", re.compile(r"\b(?:subprocess\.(?:Popen|call|run|check_call|check_output)|os\.system)\s*\(.*shell\s*=\s*True.*\)", re.DOTALL), "Pass commands as an argument array with shell=False."),
    ("Insecure Deserialization (pickle)", "high", re.compile(r"\b(?:pickle|_pickle)\.(?:loads|load)\s*\("), "Replace pickle with JSON, Protocol Buffers, or safe serialization."),
    ("Unsafe YAML Loading", "medium", re.compile(r"\byaml\.(?:load|unsafe_load)\s*\((?!.*Loader\s*=\s*(?:yaml\.)?SafeLoader)"), "Use yaml.safe_load(...) instead of unsafe loader."),
    ("Weak Cryptographic Hash (MD5/SHA1)", "low", re.compile(r"\bhashlib\.(?:md5|sha1)\s*\("), "Upgrade to SHA-256 (hashlib.sha256) for security checks."),
]


def _parse_repository_url(url: str) -> Tuple[str, str]:
    match = re.search(r"github\.com/([^/]+)/([^/]+?)(?:\.git)?(?:/.*)?$", url.strip())
    if not match:
        raise ValueError(f"Invalid GitHub repository URL: {url}")
    return match.group(1), match.group(2)


def _github_json(url: str) -> Any:
    headers = {"User-Agent": "ProofBox-AI-Scanner", "Accept": "application/vnd.github.v3+json"}
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = Request(url, headers=headers)
    try:
        with urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            data = resp.read(MAX_RESPONSE_BYTES)
            return json.loads(data.decode("utf-8"))
    except HTTPError as e:
        if e.code == 404:
            raise ValueError("Repository or resource not found on GitHub.")
        if e.code == 403:
            raise ValueError("GitHub API rate limit reached. Set GITHUB_TOKEN in your .env file.")
        raise ValueError(f"GitHub API error: {e.code}")
    except (URLError, socket.timeout) as e:
        raise ValueError(f"Network error while querying GitHub: {str(e)}")


def _is_supported_file(path: str) -> bool:
    parts = path.split("/")
    if any(part in SKIP_DIRECTORIES for part in parts[:-1]):
        return False
    filename = parts[-1].lower()
    if filename in SPECIAL_FILENAMES:
        return True
    _, ext = os.path.splitext(filename)
    return ext in SUPPORTED_EXTENSIONS


def _fetch_text_file(owner: str, repo: str, sha: str, path: str) -> Optional[str]:
    raw_url = f"{GITHUB_RAW_BASE}/{quote(owner, safe='')}/{quote(repo, safe='')}/{quote(sha, safe='')}/{quote(path, safe='/')}"
    req = Request(raw_url, headers={"User-Agent": "ProofBox-AI-Scanner"})
    try:
        with urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            raw_bytes = resp.read(MAX_FILE_BYTES + 4096)
            return raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        return None


def _mask_secret(val: str) -> str:
    if len(val) <= 8:
        return "****"
    return f"{val[:4]}{'*' * (len(val) - 8)}{val[-4:]}"


def _is_placeholder(val: str) -> bool:
    low = val.lower()
    return any(p in low for p in ["your_", "your-", "xxx", "dummy", "placeholder", "example", "sample", "todo"])


def _scan_file(path: str, content: str) -> List[Dict[str, Any]]:
    findings = []
    lines = content.splitlines()

    for line_idx, line in enumerate(lines, start=1):
        for name, severity, pattern, remed in SECRET_PATTERNS:
            for match in pattern.finditer(line):
                val = match.group(1) if match.groups() else match.group(0)
                if _is_placeholder(val):
                    continue
                findings.append({
                    "rule_name": name,
                    "severity": severity,
                    "file": path,
                    "line_number": line_idx,
                    "line_snippet": line.strip()[:160].replace(val, _mask_secret(val)),
                    "remediation": remed,
                })

    for name, severity, pattern, remed in CODE_PATTERNS:
        for match in pattern.finditer(content):
            start = match.start()
            line_no = content[:start].count("\n") + 1
            snippet = lines[line_no - 1].strip()[:160] if line_no - 1 < len(lines) else ""
            findings.append({
                "rule_name": name,
                "severity": severity,
                "file": path,
                "line_number": line_no,
                "line_snippet": snippet,
                "remediation": remed,
            })

    return findings


FINDINGS_PER_EVENT_LIMIT = 50


def scan_github_repository_stream(
    repository_url: str,
    max_files: int = 100,
    cancel_check: Optional[Callable[[], bool]] = None,
) -> Generator[Dict[str, Any], None, None]:
    """Yield progress events while scanning a repository.

    ``cancel_check`` is polled before each file. When it returns True the scan
    stops early and the final ``completed`` event carries ``cancelled: True``
    with whatever findings were collected so far.
    """
    effective_max_files = max(1, min(int(max_files or 100), 500))
    owner, repository = _parse_repository_url(repository_url)
    api_base = f"{GITHUB_API_BASE}/repos/{quote(owner, safe='')}/{quote(repository, safe='')}"

    yield {"event": "status", "message": "Resolving default branch..."}
    metadata = _github_json(api_base)
    default_branch = metadata.get("default_branch")
    if not isinstance(default_branch, str) or not default_branch:
        raise ValueError("Could not determine the repository's default branch.")

    yield {"event": "status", "message": f"Pinning commit on '{default_branch}'..."}
    commit_data = _github_json(f"{api_base}/commits/{quote(default_branch, safe='')}")
    commit_sha = commit_data.get("sha")
    if not isinstance(commit_sha, str) or not re.fullmatch(r"[0-9a-fA-F]{40,64}", commit_sha):
        raise ValueError("Could not resolve a valid repository commit SHA.")

    yield {"event": "status", "message": "Fetching repository file tree..."}
    tree_data = _github_json(f"{api_base}/git/trees/{commit_sha}?recursive=1")
    entries = tree_data.get("tree", [])

    candidates = [
        entry for entry in entries
        if isinstance(entry, dict) and entry.get("type") == "blob"
        and isinstance(entry.get("path"), str) and _is_supported_file(entry["path"])
    ]

    selected_files = candidates[:effective_max_files]
    skipped_files = [entry["path"] for entry in candidates[effective_max_files:]]
    findings: List[Dict[str, Any]] = []
    scanned_files: List[str] = []
    total_bytes = 0
    total_candidates = len(candidates)
    cancelled = False

    yield {
        "event": "tree_discovered",
        "discovered": total_candidates,
        "selected": len(selected_files),
        "commit": commit_sha,
        "default_branch": default_branch,
    }

    for idx, entry in enumerate(selected_files, start=1):
        if cancel_check and cancel_check():
            cancelled = True
            yield {"event": "status", "message": "Scan stopped by user. Returning partial results..."}
            break

        path = entry["path"]
        declared_size = entry.get("size")

        # Skip only if confirmed to exceed the per-file limit
        if isinstance(declared_size, int) and declared_size > MAX_FILE_BYTES:
            skipped_files.append(path)
            yield {
                "event": "file_progress",
                "status": "skipped",
                "reason": f"file size ({declared_size // 1024} KB > {MAX_FILE_BYTES // 1_000_000} MB limit)",
                "file": path,
                "current": idx,
                "total": total_candidates,
                "scanned_count": len(scanned_files),
                "skipped_count": len(skipped_files),
            }
            continue

        # Skip if the cumulative repo size cap is exceeded
        if isinstance(declared_size, int) and (total_bytes + declared_size > MAX_TOTAL_BYTES):
            skipped_files.append(path)
            yield {
                "event": "file_progress",
                "status": "skipped",
                "reason": "cumulative repo limit",
                "file": path,
                "current": idx,
                "total": total_candidates,
                "scanned_count": len(scanned_files),
                "skipped_count": len(skipped_files),
            }
            continue

        content = _fetch_text_file(owner, repository, commit_sha, path)
        if content is None:
            skipped_files.append(path)
            yield {
                "event": "file_progress",
                "status": "skipped",
                "reason": "could not fetch raw text",
                "file": path,
                "current": idx,
                "total": total_candidates,
                "scanned_count": len(scanned_files),
                "skipped_count": len(skipped_files),
            }
            continue

        file_findings = _scan_file(path, content)
        findings.extend(file_findings)
        total_bytes += len(content.encode("utf-8"))
        scanned_files.append(path)

        yield {
            "event": "file_progress",
            "status": "scanned",
            "file": path,
            "current": idx,
            "total": total_candidates,
            "scanned_count": len(scanned_files),
            "skipped_count": len(skipped_files),
            "new_findings": len(file_findings),
            "total_findings": len(findings),
            # Findings are already redacted by _scan_file, so they are safe to stream live.
            "findings": file_findings[:FINDINGS_PER_EVENT_LIMIT],
        }

    severity_counts = {level: 0 for level in SEVERITY_LEVELS}
    for f in findings:
        sev = f["severity"].lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    partial_scan = (
        cancelled
        or bool(tree_data.get("truncated", False))
        or len(candidates) > effective_max_files
        or bool(skipped_files)
    )

    final_result = {
        "status": "cancelled" if cancelled else "completed",
        "cancelled": cancelled,
        "repository": f"{owner}/{repository}",
        "repository_url": f"https://github.com/{owner}/{repository}",
        "commit": commit_sha,
        "default_branch": default_branch,
        "limits": {
            "max_files": effective_max_files,
            "max_file_bytes": MAX_FILE_BYTES,
            "max_total_bytes": MAX_TOTAL_BYTES,
            "request_timeout_seconds": REQUEST_TIMEOUT,
        },
        "summary": {
            "files_discovered": total_candidates,
            "files_scanned": len(scanned_files),
            "files_skipped": len(skipped_files),
            "total_findings": len(findings),
            "severity": severity_counts,
        },
        "findings": findings,
        "scanned_files": scanned_files,
        "skipped_files": skipped_files,
        "partial_scan": partial_scan,
    }

    yield {"event": "completed", "result": final_result}


def scan_github_repository(repository_url: str, max_files: int = 100) -> Dict[str, Any]:
    final_result = None
    for event in scan_github_repository_stream(repository_url, max_files=max_files):
        if event.get("event") == "completed":
            final_result = event.get("result")
    return final_result or {}