"""
ProofBox AI - Report export.

Converts a stored audit job into SARIF 2.1.0 (for GitHub code scanning and
other SARIF consumers). Pure functions only, so it can be tested without a
running web server.
"""

import re
from typing import Any, Dict, List

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "ProofBox AI"
TOOL_VERSION = "2.0.0"

# SARIF levels: error | warning | note | none
SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _slug(text: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-").lower()
    return slug or "finding"


def build_sarif(job: Dict[str, Any]) -> Dict[str, Any]:
    """Build a SARIF 2.1.0 log from a job detail dict (as returned by get_audit_job_detail)."""
    findings: List[Dict[str, Any]] = job.get("findings") or []
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        rule_name = str(finding.get("rule_name") or finding.get("name") or finding.get("rule_id") or "Security Finding")
        rule_id = str(finding.get("rule_id") or _slug(rule_name))
        severity = str(finding.get("severity") or "medium").lower()
        level = SEVERITY_TO_LEVEL.get(severity, "warning")
        remediation = str(finding.get("remediation") or "Review this finding.")

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_name,
                "shortDescription": {"text": rule_name},
                "help": {"text": remediation},
                "defaultConfiguration": {"level": level},
            }

        region: Dict[str, Any] = {}
        line = finding.get("line_number")
        if isinstance(line, int) and line > 0:
            region["startLine"] = line
        snippet = finding.get("line_snippet")
        if snippet:
            region["snippet"] = {"text": str(snippet)}

        physical: Dict[str, Any] = {
            "artifactLocation": {"uri": str(finding.get("file") or job.get("target") or "unknown")},
        }
        if region:
            physical["region"] = region

        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f"{rule_name}: {remediation}"},
            "locations": [{"physicalLocation": physical}],
            "properties": {"severity": severity},
        })

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "invocations": [{"executionSuccessful": True}],
            "properties": {
                "jobId": job.get("id"),
                "target": job.get("target"),
                "commit": job.get("commit_sha"),
                "jobType": job.get("job_type"),
            },
        }],
    }
