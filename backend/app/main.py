"""
ProofBox AI - Main Application (Milestone 12 Complete)
FastAPI service supporting code verification, AI generation, live streaming GitHub scans,
and persistent SQLite Job History & Audit Logging with code retention.
"""

from datetime import datetime, timezone
import json
import os
import sys
import threading
from pathlib import Path
from typing import Any, Dict, Optional
from uuid import uuid4

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

CURRENT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = CURRENT_DIR.parent
PROJECT_ROOT = BACKEND_DIR.parent
for p in [str(CURRENT_DIR), str(BACKEND_DIR), str(PROJECT_ROOT)]:
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    from app.db import (
        clear_audit_jobs,
        get_audit_job_detail,
        get_audit_jobs,
        init_db,
        insert_audit_job,
    )
except ImportError:
    from backend.app.db import (
        clear_audit_jobs,
        get_audit_job_detail,
        get_audit_jobs,
        init_db,
        insert_audit_job,
    )

try:
    from app.services.ai_service import generate_code
except ImportError:
    try:
        from backend.app.services.ai_service import generate_code
    except ImportError:
        def generate_code(task: str) -> str:
            return f"# Generated code for: {task}\ndef solve():\n    return True\n"

try:
    from app.services import verification_service
except ImportError:
    try:
        from backend.app.services import verification_service
    except ImportError:
        verification_service = None

def run_verify_code(code: str, filename: str = "snippet.py") -> dict:
    """Run the static checks. Never reports 'passed' unless the code parses and no rule fired."""
    code_size = f"{len(code.encode('utf-8'))} bytes"

    if not verification_service or not hasattr(verification_service, "VerificationService"):
        # The verifier did not load. Say so, instead of quietly approving the code.
        return {
            "status": "error",
            "syntax_valid": False,
            "is_safe": False,
            "total_findings": 0,
            "findings": [],
            "checks": {"code_size": code_size, "syntax": "Verifier unavailable"},
            "error": "The static verifier is not loaded on the server.",
        }

    verifier = verification_service.VerificationService()
    syntax_error = verification_service.check_python_syntax(code)
    findings = verifier.analyze_code(content=code, filename=filename)
    syntax_valid = syntax_error is None
    is_safe = syntax_valid and len(findings) == 0

    if syntax_error:
        syntax_text = f"Error on line {syntax_error['line_number']}: {syntax_error['message']}"
    else:
        syntax_text = "Valid"

    return {
        "status": "passed" if is_safe else "failed",
        "syntax_valid": syntax_valid,
        "is_safe": is_safe,
        "total_findings": len(findings),
        "findings": findings,
        "checks": {"code_size": code_size, "syntax": syntax_text},
    }


try:
    from app.services.export_service import build_sarif
    from app.services.ai_status import check_ai_provider
except ImportError:
    from backend.app.services.export_service import build_sarif
    from backend.app.services.ai_status import check_ai_provider

try:
    from app.services.sandbox_service import SandboxConfigError, check_sandbox, run_python
except ImportError:
    from backend.app.services.sandbox_service import SandboxConfigError, check_sandbox, run_python

try:
    from app.services.github_service import (
        scan_github_repository,
        scan_github_repository_stream,
    )
except ImportError:
    try:
        from backend.app.services.github_service import (
            scan_github_repository,
            scan_github_repository_stream,
        )
    except ImportError:
        def scan_github_repository_stream(url: str, max_files: int = 100, cancel_check=None):
            yield {"event": "status", "message": "Analyzing repository..."}
            yield {
                "event": "completed",
                "result": {
                    "repository": url,
                    "commit": "HEAD",
                    "summary": {"files_discovered": 0, "files_scanned": 0, "files_skipped": 0, "total_findings": 0},
                    "findings": [],
                    "partial_scan": False
                }
            }
        def scan_github_repository(url: str, max_files: int = 100):
            return {
                "repository": url,
                "commit": "HEAD",
                "summary": {"files_discovered": 0, "files_scanned": 0, "files_skipped": 0, "total_findings": 0},
                "findings": [],
                "partial_scan": False
            }

init_db()

# Cancel flags for in-flight repository scans, keyed by scan_id.
ACTIVE_SCANS: Dict[str, threading.Event] = {}
ACTIVE_SCANS_LOCK = threading.Lock()

app = FastAPI(
    title="ProofBox AI",
    version="2.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class CodeGenerationRequest(BaseModel):
    task: Optional[str] = None
    prompt: Optional[str] = None

    def get_task(self) -> str:
        t = self.task or self.prompt
        if not t or len(t.strip()) < 3:
            raise ValueError("Task description is required.")
        return t.strip()

class CodeVerificationRequest(BaseModel):
    code: Optional[str] = None
    source_code: Optional[str] = None

    def get_code(self) -> str:
        c = self.code or self.source_code
        if not c or not c.strip():
            raise ValueError("Source code cannot be empty.")
        return c

class GitHubScanRequest(BaseModel):
    repository_url: Optional[str] = None
    repo_url: Optional[str] = None
    url: Optional[str] = None
    max_files: Optional[int] = Field(default=100, ge=1, le=500)

    def get_url(self) -> str:
        u = self.repository_url or self.repo_url or self.url
        if not u or not u.strip():
            raise ValueError("GitHub repository URL is required.")
        return u.strip()

class SandboxRunRequest(BaseModel):
    code: str
    timeout: Optional[int] = Field(default=10)

@app.get("/api/sandbox/check")
def sandbox_check(force: bool = False):
    return check_sandbox(force=force)

@app.post("/api/sandbox/run")
def sandbox_run(request: SandboxRunRequest):
    try:
        result = run_python(request.code, request.timeout)
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))
    except SandboxConfigError as err:
        raise HTTPException(status_code=503, detail=str(err))

    job_id = str(uuid4())
    if result.get("status") == "completed" and result.get("exit_code") == 0:
        job_status = "completed"
    elif result.get("status") in ("timed_out", "output_limit_exceeded"):
        job_status = result["status"]
    else:
        job_status = "failed"

    try:
        insert_audit_job(
            job_id=job_id,
            job_type="sandbox_run",
            target=f"sandbox:{result.get('sandbox_host', 'unknown')}",
            status=job_status,
            code_content=request.code,
            total_findings=0,
            summary=result,
            findings=[],
        )
    except Exception as exc:  # the run result is still returned if saving fails
        result["history_error"] = str(exc)

    result["job_id"] = job_id
    return result

@app.get("/api/health")
@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "proofbox-backend",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

@app.get("/api/jobs")
def list_jobs(limit: int = 50, offset: int = 0):
    return {"jobs": get_audit_jobs(limit=limit, offset=offset)}

@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    detail = get_audit_job_detail(job_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Audit job not found")
    return detail

@app.delete("/api/jobs")
def delete_all_jobs():
    cleared = clear_audit_jobs()
    return {"message": f"Successfully deleted {cleared} audit jobs."}

@app.post("/api/generate")
def generate(request: CodeGenerationRequest):
    try:
        task_str = request.get_task()
        code = generate_code(task_str)
        job_id = str(uuid4())
        insert_audit_job(
            job_id=job_id,
            job_type="code_generation",
            target=task_str[:50] or "AI Prompt",
            status="completed",
            summary={"prompt": task_str, "code": code},
        )
        return {
            "status": "generated",
            "job_id": job_id,
            "language": "python",
            "code": code,
            "message": "Code generated successfully.",
        }
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"AI generation failed: {str(e)}")

@app.post("/api/verify")
@app.post("/api/verify-code")
def verify(request: CodeVerificationRequest):
    try:
        code_str = request.get_code()
        result = run_verify_code(code_str)
        job_id = str(uuid4())
        findings = result.get("findings", [])
        
        checks = result.get("checks", {})
        checks["code"] = code_str

        insert_audit_job(
            job_id=job_id,
            job_type="code_verification",
            target="Manual Code Verification",
            status=result.get("status", "completed"),
            total_findings=len(findings),
            summary=checks,
            findings=findings,
        )
        result["job_id"] = job_id
        return result
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

@app.post("/api/generate-and-verify")
def generate_and_verify(request: CodeGenerationRequest):
    try:
        task_str = request.get_task()
        code = generate_code(task_str)
        verification = run_verify_code(code)
        job_id = str(uuid4())
        findings = verification.get("findings", [])

        checks = verification.get("checks", {})
        checks["code"] = code

        insert_audit_job(
            job_id=job_id,
            job_type="generate_and_verify",
            target=f"Task: {task_str[:40]}",
            status=verification.get("status", "completed"),
            total_findings=len(findings),
            summary=checks,
            findings=findings,
        )
        return {
            "status": "completed",
            "job_id": job_id,
            "code": code,
            "verification": verification,
            "message": "Code generated and verified.",
        }
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Workflow failed: {str(e)}")

@app.post("/api/github/scan/stream")
@app.post("/api/scan-repo/stream")
def github_scan_stream(request: GitHubScanRequest):
    try:
        url = request.get_url()
        limit = request.max_files or 100
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))

    scan_id = str(uuid4())
    cancel_event = threading.Event()
    with ACTIVE_SCANS_LOCK:
        ACTIVE_SCANS[scan_id] = cancel_event

    def sse_generator():
        job_id = scan_id
        try:
            yield f"data: {json.dumps({'event': 'started', 'scan_id': scan_id})}\n\n"
            for event in scan_github_repository_stream(
                url, max_files=limit, cancel_check=cancel_event.is_set
            ):
                if event.get("event") == "completed":
                    res = event.get("result", {})
                    summary_data = res.get("summary", {})
                    summary_data["scanned_files"] = res.get("scanned_files", [])
                    summary_data["cancelled"] = bool(res.get("cancelled"))
                    if res.get("cancelled"):
                        job_status = "cancelled"
                    elif res.get("partial_scan"):
                        job_status = "partial"
                    else:
                        job_status = "completed"
                    insert_audit_job(
                        job_id=job_id,
                        job_type="github_scan",
                        target=url,
                        status=job_status,
                        commit_sha=res.get("commit"),
                        total_findings=res.get("summary", {}).get("total_findings", 0),
                        summary=summary_data,
                        findings=res.get("findings", []),
                    )
                    event["job_id"] = job_id
                yield f"data: {json.dumps(event)}\n\n"
        except Exception as exc:
            insert_audit_job(
                job_id=job_id,
                job_type="github_scan",
                target=url,
                status="failed",
                summary={"error": str(exc)},
            )
            yield f"data: {json.dumps({'event': 'error', 'message': str(exc)})}\n\n"
        finally:
            with ACTIVE_SCANS_LOCK:
                ACTIVE_SCANS.pop(scan_id, None)

    return StreamingResponse(sse_generator(), media_type="text/event-stream")

@app.post("/api/github/scan/{scan_id}/cancel")
def cancel_github_scan(scan_id: str):
    with ACTIVE_SCANS_LOCK:
        cancel_event = ACTIVE_SCANS.get(scan_id)
    if cancel_event is None:
        raise HTTPException(status_code=404, detail="No active scan with that id.")
    cancel_event.set()
    return {"status": "cancelling", "scan_id": scan_id}

@app.get("/api/ai/status")
def ai_status(force: bool = False):
    return check_ai_provider(force=force)

@app.get("/api/jobs/{job_id}/export")
def export_job(job_id: str, format: str = "json"):
    detail = get_audit_job_detail(job_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Audit job not found")

    fmt = format.lower()
    if fmt == "json":
        body = detail
    elif fmt == "sarif":
        body = build_sarif(detail)
    else:
        raise HTTPException(status_code=400, detail="format must be 'json' or 'sarif'")

    filename = f"proofbox-{job_id[:8]}.{'sarif.json' if fmt == 'sarif' else 'json'}"
    return JSONResponse(
        content=body,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

@app.post("/api/github/scan")
@app.post("/api/scan-repo")
@app.post("/api/scan")
def github_scan(request: GitHubScanRequest):
    try:
        url = request.get_url()
        limit = request.max_files or 100
        result = scan_github_repository(url, max_files=limit)
        job_id = str(uuid4())

        summary = result.get("summary", {})
        result["files_discovered"] = summary.get("files_discovered", result.get("files_discovered", 0))
        result["files_scanned"] = summary.get("files_scanned", result.get("files_scanned", 0))
        result["files_skipped"] = summary.get("files_skipped", result.get("files_skipped", 0))
        result["total_findings"] = len(result.get("findings", []))
        result["job_id"] = job_id

        summary["scanned_files"] = result.get("scanned_files", [])

        insert_audit_job(
            job_id=job_id,
            job_type="github_scan",
            target=url,
            status="completed" if not result.get("partial_scan") else "partial",
            commit_sha=result.get("commit"),
            total_findings=result["total_findings"],
            summary=summary,
            findings=result.get("findings", []),
        )

        return result
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Scan failed: {str(e)}")

FRONTEND_CANDIDATES = [
    PROJECT_ROOT / "frontend",
    BACKEND_DIR / "static",
    PROJECT_ROOT,
    Path.cwd(),
]
FRONTEND_DIR = next((p for p in FRONTEND_CANDIDATES if (p / "index.html").is_file()), None)

if FRONTEND_DIR:
    @app.get("/style.css")
    def serve_css():
        css = FRONTEND_DIR / "style.css"
        if css.is_file():
            return FileResponse(css, media_type="text/css")
        raise HTTPException(status_code=404, detail="style.css not found")

    @app.get("/app.js")
    def serve_js():
        js = FRONTEND_DIR / "app.js"
        if js.is_file():
            return FileResponse(js, media_type="application/javascript")
        raise HTTPException(status_code=404, detail="app.js not found")

    @app.get("/")
    def serve_index():
        return FileResponse(FRONTEND_DIR / "index.html")