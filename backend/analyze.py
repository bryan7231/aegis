"""Claude Opus 4.8 vulnerability narrative.

The LLM never decides whether something is vulnerable — it only reasons over the
already-confirmed OSV CVE set to produce a human-readable report and chain summary.
Delete this layer and you still have a correct vulnerability list.
"""
import json
import os
from typing import Optional

from anthropic import AsyncAnthropic
from pydantic import BaseModel, Field

from models import AnalysisReport, Vulnerability

MODEL = "claude-opus-4-8"

SYSTEM_PROMPT = """You are a security analyst for ChainBreak. You are given a list \
of CONFIRMED vulnerabilities (CVEs) detected in a project's dependencies via the \
public OSV database. Every CVE in the list is real and already verified — do not \
question, add, or remove any.

Your job is to reason over this confirmed set and explain, in plain language a \
non-expert solo developer can understand:
- how these flaws combine into realistic multi-step attack paths (the chain), and
- which single path is the most dangerous.

Focus on the big picture: how unrelated "minor" flaws chain into a full compromise. \
Do not invent CVEs or capabilities not supported by the provided data."""


def _build_user_prompt(vulns: list[Vulnerability]) -> str:
    rows = [
        {
            "cve_id": v.cve_id,
            "package": v.package,
            "version": v.version,
            "cvss": v.cvss,
            "severity": v.severity,
            "epss": v.epss,
            "kev": v.kev,
            "fixed_version": v.fixed_version,
            "summary": v.summary,
        }
        for v in vulns
    ]
    return (
        "Here is the confirmed vulnerability set for this project:\n\n"
        f"{json.dumps(rows, indent=2)}\n\n"
        "Produce a report with three fields:\n"
        "- narrative: 2-4 sentences summarizing the overall risk in plain English.\n"
        "- chain_summary: how specific flaws chain together into an attack path "
        "(name the packages and what each step enables).\n"
        "- highest_risk_path: a short arrow-notation path from an entry point to a "
        'crown-jewel asset, e.g. "webhook -> express -> ejs -> RCE -> host".'
    )


EDGE_SYSTEM = """You are a security researcher specializing in exploit chain analysis.
Given a numbered list of vulnerabilities (dependency CVEs and code findings) from a \
single project, identify which pairs can be chained together in a realistic attack.

Edge types:
- dependency_chain   : vuln A is in a package that is a direct/transitive dependency of \
the component affected by vuln B, and both are on the same attack path
- data_flow          : a code vulnerability (e.g. SQLi, XSS) passes attacker-controlled \
data into a function covered by a dependency CVE, amplifying the impact
- privilege_escalation: exploiting A grants the access level (local user, network position) \
that B requires (check privileges_required field)
- cwe_chain          : A's weakness class is a documented precursor to B's \
(e.g. CWE-79 XSS → CWE-352 CSRF, CWE-89 SQLi → CWE-200 info disclosure)
- lateral_movement   : A enables access to a system or component where B can then be triggered

Rules:
- Only output edges with genuine chaining potential (confidence >= 0.5).
- A high EPSS or KEV flag on a node increases the realism of chains through it.
- Network attack_vector vulns make better entry points than Local ones.
- "Scope: Changed" means the vuln can jump component boundaries — important for chains.
- Be conservative: 3-10 high-quality edges beats 30 speculative ones."""


class EdgeSpec(BaseModel):
    source_index: int   # index into the nodes list passed to Claude
    target_index: int
    edge_type: str      # see edge types above
    confidence: float   # 0.0 – 1.0
    description: str    # plain-English explanation of the chain


class GraphEdgesResult(BaseModel):
    edges: list[EdgeSpec] = Field(default_factory=list)


def _node_summary(i: int, node: dict) -> str:
    if node["source"] == "dependency":
        parts = [
            f"[{i}] DEP {node.get('cve_id', '?')} — {node.get('package')}@{node.get('version')}",
            f"severity={node.get('severity','?')} cvss={node.get('cvss','?')}",
            f"AV={node.get('attack_vector','?')} PR={node.get('privileges_required','?')} scope={node.get('scope','?')}",
        ]
        if node.get("kev"):
            parts.append("KEV=yes")
        if node.get("cwe_ids"):
            parts.append(f"CWEs={','.join(node['cwe_ids'])}")
        desc = node.get("description") or node.get("summary", "")
        if desc:
            parts.append(f'"{desc[:120]}"')
    else:
        parts = [
            f"[{i}] CODE {node.get('title','?')} — {node.get('file_path','?')}:{node.get('line_start','?')}",
            f"category={node.get('vuln_category','?')} severity={node.get('severity','?')} cvss={node.get('cvss','?')}",
        ]
        if node.get("cwe_ids"):
            parts.append(f"CWEs={','.join(node['cwe_ids'])}")
        desc = node.get("description", "")
        if desc:
            parts.append(f'"{desc[:120]}"')
    return " | ".join(parts)


async def generate_edges(nodes: list[dict]) -> list[EdgeSpec]:
    """Ask Claude to find exploit-chain edges between vulnerability nodes."""
    if len(nodes) < 2 or not os.environ.get("ANTHROPIC_API_KEY"):
        return []

    summaries = "\n".join(_node_summary(i, n) for i, n in enumerate(nodes))
    prompt = (
        f"Project has {len(nodes)} vulnerabilities:\n\n{summaries}\n\n"
        "Identify realistic exploit chains between them. "
        "Return edges where source_index can be leveraged to reach or amplify target_index."
    )

    client = AsyncAnthropic()
    try:
        response = await client.messages.parse(
            model=MODEL,
            max_tokens=2048,
            system=EDGE_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
            output_format=GraphEdgesResult,
        )
        return response.parsed_output.edges
    except Exception:
        return []


async def generate_report(vulns: list[Vulnerability]) -> AnalysisReport:
    """Call Claude Opus 4.8 to synthesize the confirmed CVEs into a narrative."""
    if not vulns:
        return AnalysisReport(
            narrative="No known vulnerabilities were found in this project's dependencies.",
            chain_summary="No attack chains — the confirmed CVE set is empty.",
            highest_risk_path="",
        )

    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not set. Add it to backend/.env to enable the analyze report."
        )

    client = AsyncAnthropic()
    response = await client.messages.parse(
        model=MODEL,
        max_tokens=4096,
        thinking={"type": "adaptive"},
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": _build_user_prompt(vulns)}],
        output_format=AnalysisReport,
    )
    return response.parsed_output
