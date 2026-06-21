"""Claude-powered static security scan over repository source files.

The scan is best-effort: if the API key is missing or Claude is unavailable,
``scan_source_files`` returns an empty list rather than crashing the pipeline.
"""
import os
from typing import Optional

from anthropic import AsyncAnthropic
from pydantic import BaseModel, Field

MODEL = "claude-opus-4-8"

SYSTEM_PROMPT = """You are a senior application security engineer performing a \
targeted code security audit. Analyze the provided source files and identify \
real, high-confidence security vulnerabilities.

Focus on:
- Injection (SQL, command, template, LDAP, XPath)
- Authentication / authorization bypasses
- Cryptographic weaknesses (weak algorithms, hardcoded secrets, improper key use)
- Insecure direct object references
- Path traversal / directory traversal
- XSS (reflected, stored, DOM-based)
- SSRF
- Insecure deserialization
- Sensitive data exposure (credentials, tokens hardcoded in source)
- Race conditions / TOCTOU

Rules:
- Only report HIGH-CONFIDENCE findings with clear evidence in the code.
- Be precise: include the exact file path and line numbers.
- Include the vulnerable code snippet in affected_code (keep it short).
- Assign a CVSS 3.1 base score that reflects real-world exploitability.
- Map each finding to its CWE ID(s).
- Keep remediation advice concise and actionable."""


class CodeVuln(BaseModel):
    title: str
    description: str
    severity: str           # critical | high | medium | low
    cvss: Optional[float] = None
    vuln_category: str      # injection | auth | crypto | xss | path_traversal | ssrf | ...
    cwe_ids: list[str] = Field(default_factory=list)
    file_path: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    affected_code: Optional[str] = None
    remediation: str


class CodeScanResult(BaseModel):
    vulnerabilities: list[CodeVuln] = Field(default_factory=list)


def _build_prompt(files: list[dict]) -> str:
    parts = [f"### {f['path']}\n```\n{f['content']}\n```" for f in files]
    return (
        "Analyze the following source files for security vulnerabilities:\n\n"
        + "\n\n".join(parts)
    )


async def scan_source_files(files: list[dict]) -> list[CodeVuln]:
    """Scan source files for code-level vulnerabilities using Claude."""
    if not files or not os.environ.get("ANTHROPIC_API_KEY"):
        return []

    client = AsyncAnthropic()
    try:
        response = await client.messages.parse(
            model=MODEL,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": _build_prompt(files)}],
            output_format=CodeScanResult,
        )
        return response.parsed_output.vulnerabilities
    except Exception:
        return []
