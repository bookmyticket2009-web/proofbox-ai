"""
ProofBox AI - Verification Service (Detection Engine v2)
Includes advanced secret recognition, dangerous execution analysis,
unsafe deserialization, weak cryptographic hashing, and false-positive suppression.
"""

import ast
import re
from typing import Optional, Any, Dict, List

DISCLAIMER = "Static security heuristics assist in identifying exposure risks, but do not provide a mathematical guarantee of safety."

def check_python_syntax(content: str) -> Optional[Dict[str, Any]]:
    """Return None if the code parses as Python, otherwise details of the first syntax error."""
    try:
        ast.parse(content)
        return None
    except SyntaxError as err:
        line_no = err.lineno or 1
        lines = content.splitlines()
        snippet = lines[line_no - 1].strip()[:160] if 0 < line_no <= len(lines) else ""
        return {
            "line_number": line_no,
            "message": err.msg or "invalid syntax",
            "snippet": snippet,
        }
    except (ValueError, TypeError) as err:  # e.g. null bytes in the source
        return {"line_number": 1, "message": str(err), "snippet": ""}


class VerificationService:
    def __init__(self):
        # 1. High-fidelity secret patterns
        self.secret_rules = [
            {
                "id": "AWS_ACCESS_KEY",
                "name": "AWS Access Key ID",
                "severity": "CRITICAL",
                "pattern": re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
                "remediation": "Revoke the access key in AWS IAM and migrate credentials to IAM Roles or AWS Secrets Manager."
            },
            {
                "id": "AWS_SECRET_KEY",
                "name": "AWS Secret Access Key",
                "severity": "CRITICAL",
                "pattern": re.compile(r"(?i)(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]"),
                "remediation": "Rotate compromised AWS secrets immediately and remove hardcoded values from repository history."
            },
            {
                "id": "GITHUB_PAT",
                "name": "GitHub Personal Access Token",
                "severity": "CRITICAL",
                "pattern": re.compile(r"\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b"),
                "remediation": "Revoke the token in GitHub Developer Settings and use fine-grained GitHub Actions environment secrets."
            },
            {
                "id": "GITHUB_OAUTH",
                "name": "GitHub OAuth Token",
                "severity": "CRITICAL",
                "pattern": re.compile(r"\b(gho_[0-9a-zA-Z]{36}|ghs_[0-9a-zA-Z]{36}|ghr_[0-9a-zA-Z]{36})\b"),
                "remediation": "Invalidate the OAuth/installation secret and store tokens in encrypted vault backends."
            },
            {
                "id": "GOOGLE_API_KEY",
                "name": "Google / GCP API Key",
                "severity": "HIGH",
                "pattern": re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
                "remediation": "Apply API & HTTP referrer restrictions in Google Cloud Console and rotate the key."
            },
            {
                "id": "GOOGLE_OAUTH",
                "name": "Google OAuth Access Token",
                "severity": "HIGH",
                "pattern": re.compile(r"\b(ya29\.[0-9A-Za-z\-_]+)\b"),
                "remediation": "Do not hardcode transient user access tokens; obtain tokens dynamically at runtime."
            },
            {
                "id": "SLACK_TOKEN",
                "name": "Slack Bot/User Token",
                "severity": "CRITICAL",
                "pattern": re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32})\b"),
                "remediation": "Revoke token via Slack App configuration and configure environment-based injection."
            },
            {
                "id": "STRIPE_KEY",
                "name": "Stripe API Key",
                "severity": "CRITICAL",
                "pattern": re.compile(r"\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,})\b"),
                "remediation": "Roll Stripe API keys immediately in the Stripe Dashboard and restrict permissions."
            },
            {
                "id": "NPM_TOKEN",
                "name": "npm Access Token",
                "severity": "HIGH",
                "pattern": re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"),
                "remediation": "Revoke npm automation token using `npm token revoke` and use publishing trust tokens."
            },
            {
                "id": "HARDCODED_BEARER",
                "name": "Hardcoded Authorization Bearer Token",
                "severity": "HIGH",
                "pattern": re.compile(r"(?i)['\"]bearer\s+([a-zA-Z0-9_\-\.]{25,})['\"]"),
                "remediation": "Avoid static Authorization header strings; supply credentials via secure environment variables."
            },
            {
                "id": "GENERIC_SECRET",
                "name": "Hardcoded Secret or Password",
                "severity": "MEDIUM",
                "pattern": re.compile(r"(?i)\b(?:api_?key|auth_?token|client_?secret|db_?password|private_?key)\s*[:=]\s*['\"]([^'\"]{14,})['\"]"),
                "remediation": "Store confidential parameters outside version control using `.env` files or secret managers."
            }
        ]

        # 2. Execution, Deserialization & Cryptographic checks
        self.code_rules = [
            {
                "id": "DANGEROUS_EXEC",
                "name": "Dynamic Code Execution (eval/exec)",
                "severity": "HIGH",
                "pattern": re.compile(r"\b(?:eval|exec)\s*\((?!\s*['\"][a-zA-Z0-9_]+['\"]\s*\))"),
                "description": "Dynamic code evaluation can lead to arbitrary code execution if inputs are user-controlled.",
                "remediation": "Refactor logic using safe parsing such as `ast.literal_eval` or predefined lookups."
            },
            {
                "id": "UNSAFE_SHELL_EXEC",
                "name": "Subprocess Shell Execution",
                "severity": "HIGH",
                "pattern": re.compile(r"\b(?:subprocess\.(?:Popen|call|run|check_call|check_output)|os\.system)\s*\(.*shell\s*=\s*True.*\)", re.DOTALL),
                "description": "Executing system commands through a shell without rigorous sanitization invites shell injection.",
                "remediation": "Pass commands as an argument list (e.g., ['ls', '-la']) with `shell=False`."
            },
            {
                "id": "UNSAFE_DESERIALIZATION_PICKLE",
                "name": "Insecure Python Deserialization (pickle)",
                "severity": "HIGH",
                "pattern": re.compile(r"\b(?:pickle|_pickle)\.(?:loads|load)\s*\("),
                "description": "Pickle serialization can execute arbitrary bytecode upon unpacking unverified payloads.",
                "remediation": "Use safer serialization standards such as JSON, Protocol Buffers, or cryptographically signed formats."
            },
            {
                "id": "UNSAFE_YAML_LOAD",
                "name": "Unsafe YAML Parsing",
                "severity": "MEDIUM",
                "pattern": re.compile(r"\byaml\.(?:load|unsafe_load)\s*\((?!.*Loader\s*=\s*(?:yaml\.)?SafeLoader)"),
                "description": "Standard `yaml.load` without `SafeLoader` can instantiate arbitrary Python objects.",
                "remediation": "Use `yaml.safe_load(...)` or explicitly pass `Loader=yaml.SafeLoader`."
            },
            {
                "id": "WEAK_HASHING_MD5_SHA1",
                "name": "Weak Cryptographic Hash (MD5 / SHA-1)",
                "severity": "LOW",
                "pattern": re.compile(r"\bhashlib\.(?:md5|sha1)\s*\("),
                "description": "MD5 and SHA-1 suffer from known collision vulnerabilities and should not be used for security-critical integrity or password hashing.",
                "remediation": "Upgrade to SHA-256 (`hashlib.sha256`) or modern password hashes (argon2, bcrypt)."
            }
        ]

    def _is_placeholder(self, text: str) -> bool:
        """Filter out obvious false-positive placeholders and documentation templates."""
        low = text.lower()
        indicators = [
            "your-", "your_", "your.", "xxx", "dummy", "placeholder", "changeme",
            "example", "sample", "todo", "<key>", "{key}", "insert_", "secret_here"
        ]
        return any(ind in low for ind in indicators)

    @staticmethod
    def _mask_secret(secret: str) -> str:
        """Preserve prefix and suffix while obscuring the sensitive interior."""
        if len(secret) <= 8:
            return "****"
        return f"{secret[:4]}{'*' * (len(secret) - 8)}{secret[-4:]}"

    def _redact_text(self, text: str) -> str:
        """Mask any secret-looking values in a line before it is shown or stored."""
        for rule in self.secret_rules:
            for match in rule["pattern"].finditer(text):
                value = match.group(1) if match.groups() else match.group(0)
                if not self._is_placeholder(value):
                    text = text.replace(value, self._mask_secret(value))
        return text

    def analyze_code(self, content: str, filename: str = "") -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()

        # Syntax: code that does not parse can never be run, so it is reported as a failure.
        syntax_error = check_python_syntax(content)
        if syntax_error:
            findings.append({
                "rule_id": "PYTHON_SYNTAX_ERROR",
                "rule_name": "Python syntax error",
                "severity": "high",
                "line_number": syntax_error["line_number"],
                "line_snippet": self._redact_text(syntax_error["snippet"]),
                "description": f"The code does not parse as Python: {syntax_error['message']}. It cannot be run until this is fixed. {DISCLAIMER}",
                "remediation": "Fix the syntax error at the reported line, then verify again.",
            })

        # Check secret rules line-by-line
        for line_num, line in enumerate(lines, start=1):
            for rule in self.secret_rules:
                for match in rule["pattern"].finditer(line):
                    matched_val = match.group(1) if match.groups() else match.group(0)
                    if self._is_placeholder(matched_val):
                        continue

                    masked = self._mask_secret(matched_val)
                    findings.append({
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "severity": rule["severity"],
                        "line_number": line_num,
                        "line_snippet": line.strip()[:160].replace(matched_val, masked),
                        "description": f"Potential {rule['name']} detected. {DISCLAIMER}",
                        "remediation": rule["remediation"]
                    })

        # Check dangerous code patterns
        for rule in self.code_rules:
            for match in rule["pattern"].finditer(content):
                start_idx = match.start()
                line_no = content[:start_idx].count("\n") + 1
                matched_line = lines[line_no - 1] if line_no - 1 < len(lines) else ""
                findings.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "line_number": line_no,
                    "line_snippet": matched_line.strip()[:160],
                    "description": f"{rule['description']} {DISCLAIMER}",
                    "remediation": rule["remediation"]
                })

        return findings