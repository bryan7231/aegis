"""Claude Opus 4.8 vulnerability narrative.

The LLM never decides whether something is vulnerable — it only reasons over the
already-confirmed OSV CVE set to produce a human-readable report and chain summary.
Delete this layer and you still have a correct vulnerability list.
"""
import json
import os

from anthropic import AsyncAnthropic

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
