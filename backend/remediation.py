"""Generate detailed, actionable remediation plans for specific vulnerabilities.

Each plan is designed to be consumed by both a human developer and an AI coding
agent. It is saved to the DB on first generation and served from cache thereafter.
"""
import os
from anthropic import AsyncAnthropic

MODEL = "claude-opus-4-8"

SYSTEM_PROMPT = """You are a senior application security engineer writing a detailed remediation plan.

Your plans must be:
- **Immediately actionable**: exact shell commands, file paths, line numbers, and version pins
- **Contextual**: reference the actual project ecosystem, package manager, and codebase patterns
- **Agent-ready**: structured so an AI coding agent can parse and execute the fix autonomously
- **Complete**: root cause, blast radius, step-by-step fix, verification, and regression checklist

Rules:
- Never give generic security advice — every sentence must reference the specific vulnerability and project.
- Include exact upgrade commands for the detected package manager.
- If a code vulnerability: include the specific file, lines, and a corrected code snippet.
- The "Agent Context" section must be dense and self-contained — assume the agent has no other context."""


def _build_prompt(node: dict, connected: list[dict], edge_descriptions: list[str], repo_url: str) -> str:
    vuln_type = "Dependency CVE" if node["source"] == "dependency" else "Code Vulnerability"
    epss_pct = f"{node['epss'] * 100:.1f}%" if node.get("epss") is not None else "N/A"

    lines: list[str] = [
        f"Generate a detailed remediation plan for this {vuln_type} found in the project at: **{repo_url}**",
        "",
        "---",
        "## Vulnerability Details",
    ]

    if node["source"] == "dependency":
        lines += [
            f"- **CVE ID**: {node.get('cve_id') or 'N/A'}",
            f"- **Package**: `{node.get('package')}@{node.get('version')}` ({node.get('ecosystem')})",
            f"- **Fix version**: `{node.get('fixed_version') or 'No upstream fix available yet'}`",
        ]
    else:
        lines += [
            f"- **Finding**: {node.get('title')}",
            f"- **Category**: {node.get('vuln_category') or 'unknown'}",
            f"- **Location**: `{node.get('file_path')}:{node.get('line_start', '?')}`",
        ]
        if node.get("affected_code"):
            lines += ["- **Affected code**:", "```", node["affected_code"], "```"]

    lines += [
        f"- **Severity**: {(node.get('severity') or 'unknown').upper()} | CVSS {node.get('cvss') or 'N/A'}",
        f"- **EPSS**: {epss_pct} probability of exploitation in next 30 days",
        f"- **CISA KEV**: {'**YES — actively exploited in the wild**' if node.get('kev') else 'No'}",
        f"- **Attack vector**: {node.get('attack_vector') or 'Unknown'}",
        f"- **Privileges required**: {node.get('privileges_required') or 'Unknown'}",
        f"- **Scope change**: {node.get('scope') or 'Unknown'}",
    ]

    if node.get("cwe_ids"):
        lines.append(f"- **CWE**: {', '.join(node['cwe_ids'])}")

    if node.get("description"):
        lines += ["", f"**Description**: {node['description']}"]

    if node.get("remediation"):
        lines += ["", f"**Upstream remediation guidance**: {node['remediation']}"]

    if connected:
        lines += [
            "",
            "---",
            "## Exploit Chain Context",
            "These vulnerabilities are connected to the target in the project's exploit graph.",
            "Mention how fixing the target affects (or doesn't affect) each chain.",
        ]
        for i, (c, desc) in enumerate(zip(connected, edge_descriptions)):
            c_id = c.get("cve_id") or c.get("title", "Unknown")
            c_loc = (
                f"`{c.get('package')}@{c.get('version')}`"
                if c.get("package")
                else f"`{c.get('file_path', '')}`"
            )
            lines.append(f"{i + 1}. **{c_id}** ({c_loc}) — {desc}")

    lines += [
        "",
        "---",
        "## Required Plan Sections",
        "",
        "Write each section with a level-2 markdown heading (`##`). Do not skip any.",
        "",
        "### Section 1 — Executive Summary",
        "2–3 sentences a non-technical stakeholder can understand. State what is vulnerable, what the risk is, and what the fix is.",
        "",
        "### Section 2 — Technical Root Cause",
        "Explain exactly what the vulnerability is and why the affected code or dependency version is dangerous. Reference CVE details and CWE.",
        "",
        "### Section 3 — Impact Analysis",
        "What can an attacker concretely do if exploited? Be specific to the attack vector, scope, and privileges required.",
        "",
        "### Section 4 — Step-by-Step Remediation",
        "Numbered steps with exact commands. Include:",
        "- The correct package manager command to upgrade/patch",
        "- Any configuration changes required",
        "- Any code changes required (show before/after snippets)",
        "- Any environment variable or secret rotation required",
        "",
        "### Section 5 — Verification",
        "How to confirm the fix worked — specific commands the developer should run.",
        "",
        "### Section 6 — Regression Checklist",
        "A markdown checklist (`- [ ]`) of things to verify don't break after applying the fix.",
        "",
        "### Section 7 — Agent Context",
        "A dense, self-contained technical block (300–500 words) for an AI coding agent to use as its entire context window for fixing this issue.",
        "Include: exact repository URL, files to modify, exact versions to pin, commands to execute in order, and how to verify success.",
        "Write it as if the agent has never seen this conversation — it must be fully self-sufficient.",
    ]

    return "\n".join(lines)


async def generate_plan(
    node: dict,
    connected: list[dict],
    edge_descriptions: list[str],
    repo_url: str,
) -> str:
    """Call Claude Opus to generate a remediation plan and return it as markdown."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise RuntimeError("ANTHROPIC_API_KEY is not set.")

    client = AsyncAnthropic()
    prompt = _build_prompt(node, connected, edge_descriptions, repo_url)

    response = await client.messages.create(
        model=MODEL,
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text
