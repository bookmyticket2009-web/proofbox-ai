"""
ProofBox AI - Local SQLite Database Engine
Provides lightweight persistent storage for jobs and audit trails with full source retention.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, Generator, List, Optional

DB_PATH = Path(__file__).resolve().parent.parent / "proofbox.db"


def init_db() -> None:
    """Initialize database tables and run schema migrations."""
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_jobs (
                id TEXT PRIMARY KEY,
                job_type TEXT NOT NULL,
                target TEXT NOT NULL,
                commit_sha TEXT,
                status TEXT NOT NULL,
                total_findings INTEGER DEFAULT 0,
                code_content TEXT,
                summary_json TEXT,
                findings_json TEXT,
                created_at TEXT NOT NULL
            )
        """)

        # Auto-migrate older DB versions if code_content column is missing
        cursor = conn.execute("PRAGMA table_info(audit_jobs)")
        columns = [row["name"] for row in cursor.fetchall()]
        if "code_content" not in columns:
            conn.execute("ALTER TABLE audit_jobs ADD COLUMN code_content TEXT")

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_jobs_created_at
            ON audit_jobs(created_at DESC)
        """)


@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(str(DB_PATH), timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def insert_audit_job(
    job_id: str,
    job_type: str,
    target: str,
    status: str,
    code_content: Optional[str] = None,
    commit_sha: Optional[str] = None,
    total_findings: int = 0,
    summary: Optional[Dict[str, Any]] = None,
    findings: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    now_iso = datetime.now(timezone.utc).isoformat()
    summary_str = json.dumps(summary or {})
    findings_str = json.dumps(findings or [])

    with get_db() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO audit_jobs
            (id, job_type, target, commit_sha, status, total_findings, code_content, summary_json, findings_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (job_id, job_type, target, commit_sha, status, total_findings, code_content, summary_str, findings_str, now_iso),
        )

    return {
        "id": job_id,
        "job_type": job_type,
        "target": target,
        "commit_sha": commit_sha,
        "status": status,
        "total_findings": total_findings,
        "code_content": code_content,
        "summary": summary or {},
        "created_at": now_iso,
    }


def get_audit_jobs(limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT id, job_type, target, commit_sha, status, total_findings, created_at
            FROM audit_jobs
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()

    jobs = []
    for r in rows:
        jobs.append({
            "id": r["id"],
            "job_type": r["job_type"],
            "target": r["target"],
            "commit_sha": r["commit_sha"],
            "status": r["status"],
            "total_findings": r["total_findings"],
            "created_at": r["created_at"],
        })
    return jobs


def get_audit_job_detail(job_id: str) -> Optional[Dict[str, Any]]:
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT id, job_type, target, commit_sha, status, total_findings, code_content, summary_json, findings_json, created_at
            FROM audit_jobs
            WHERE id = ?
            """,
            (job_id,),
        ).fetchone()

    if not row:
        return None

    return {
        "id": row["id"],
        "job_type": row["job_type"],
        "target": row["target"],
        "commit_sha": row["commit_sha"],
        "status": row["status"],
        "total_findings": row["total_findings"],
        "code_content": row["code_content"],
        "summary": json.loads(row["summary_json"] or "{}"),
        "findings": json.loads(row["findings_json"] or "[]"),
        "created_at": row["created_at"],
    }


def clear_audit_jobs() -> int:
    with get_db() as conn:
        cursor = conn.execute("DELETE FROM audit_jobs")
        return cursor.rowcount