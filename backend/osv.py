"""OSV ingest pipeline: lockfile -> confirmed CVEs, enriched with EPSS + CISA KEV.

Detection is a deterministic public-database lookup, never inference. OSV does the
semver range matching server-side when we pass the exact installed version, so the
list here is reproducible with `osv-scanner` on the same lockfile.
"""
import json
from typing import Optional

import httpx
from cvss import CVSS3

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Map lockfile filename -> OSV ecosystem key.
ECOSYSTEM_BY_FILENAME = {
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "requirements.txt": "PyPI",
    "pipfile.lock": "PyPI",
    "poetry.lock": "PyPI",
    "go.sum": "Go",
    "cargo.lock": "crates.io",
    "gemfile.lock": "RubyGems",
}


def detect_ecosystem(filename: str) -> Optional[str]:
    return ECOSYSTEM_BY_FILENAME.get(filename.strip().lower())


def parse_lockfile(filename: str, content: str) -> list[dict]:
    """Normalize a lockfile to a list of {name, version, ecosystem} tuples.

    Only npm `package-lock.json` (lockfileVersion 2/3) is fully implemented here;
    other ecosystems fall back to an empty list (the rest of the pipeline is shared
    and language-agnostic once parsing produces these tuples).
    """
    ecosystem = detect_ecosystem(filename)
    name = filename.strip().lower()
    if name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
        return _parse_package_lock(content)
    return []


def _parse_package_lock(content: str) -> list[dict]:
    data = json.loads(content)
    seen: set[tuple[str, str]] = set()
    packages: list[dict] = []

    # lockfileVersion 2/3: "packages" keyed by "node_modules/<name>".
    for path, info in data.get("packages", {}).items():
        if not path:  # root project entry
            continue
        pkg_name = path.split("node_modules/")[-1]
        version = info.get("version")
        if pkg_name and version and (pkg_name, version) not in seen:
            seen.add((pkg_name, version))
            packages.append({"name": pkg_name, "version": version, "ecosystem": "npm"})

    # lockfileVersion 1 fallback: nested "dependencies".
    if not packages:
        _walk_v1_deps(data.get("dependencies", {}), seen, packages)

    return packages


def _walk_v1_deps(deps: dict, seen: set, packages: list) -> None:
    for pkg_name, info in deps.items():
        version = info.get("version")
        if pkg_name and version and (pkg_name, version) not in seen:
            seen.add((pkg_name, version))
            packages.append({"name": pkg_name, "version": version, "ecosystem": "npm"})
        if isinstance(info.get("dependencies"), dict):
            _walk_v1_deps(info["dependencies"], seen, packages)


async def query_osv(packages: list[dict], client: httpx.AsyncClient) -> dict[int, list[str]]:
    """Batch-query OSV. Returns {package_index: [vuln_id, ...]} for matched packages."""
    if not packages:
        return {}
    queries = [
        {"package": {"name": p["name"], "ecosystem": p["ecosystem"]}, "version": p["version"]}
        for p in packages
    ]
    resp = await client.post(OSV_BATCH_URL, json={"queries": queries}, timeout=30.0)
    resp.raise_for_status()
    results = resp.json().get("results", [])

    matched: dict[int, list[str]] = {}
    for i, result in enumerate(results):
        vulns = result.get("vulns") or []
        ids = [v["id"] for v in vulns if v.get("id")]
        if ids:
            matched[i] = ids
    return matched


async def fetch_vuln_detail(vuln_id: str, client: httpx.AsyncClient) -> Optional[dict]:
    try:
        resp = await client.get(f"{OSV_VULN_URL}{vuln_id}", timeout=30.0)
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPError:
        return None


def _extract_cvss(vuln: dict) -> tuple[Optional[float], Optional[str]]:
    """Return (base_score, severity_tier) from an OSV vuln's CVSS_V3 vector."""
    for sev in vuln.get("severity", []) or []:
        if sev.get("type", "").startswith("CVSS_V3"):
            try:
                score = CVSS3(sev["score"]).base_score
                return float(score), _tier(float(score))
            except Exception:
                continue
    return None, None


def _tier(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _extract_fixed_version(vuln: dict, package: str, ecosystem: str) -> Optional[str]:
    for affected in vuln.get("affected", []) or []:
        pkg = affected.get("package", {})
        if pkg.get("name") != package or pkg.get("ecosystem") != ecosystem:
            continue
        for rng in affected.get("ranges", []) or []:
            for event in rng.get("events", []) or []:
                if "fixed" in event:
                    return event["fixed"]
    return None


def _preferred_cve_id(vuln: dict) -> str:
    """Prefer a CVE alias over a GHSA id for display."""
    for alias in vuln.get("aliases", []) or []:
        if alias.startswith("CVE-"):
            return alias
    return vuln.get("id", "")


async def enrich_epss(cve_ids: list[str], client: httpx.AsyncClient) -> dict[str, float]:
    cves = [c for c in cve_ids if c.startswith("CVE-")]
    if not cves:
        return {}
    try:
        resp = await client.get(EPSS_URL, params={"cve": ",".join(cves)}, timeout=30.0)
        resp.raise_for_status()
        return {row["cve"]: float(row["epss"]) for row in resp.json().get("data", [])}
    except (httpx.HTTPError, KeyError, ValueError):
        return {}


async def fetch_kev(client: httpx.AsyncClient) -> set[str]:
    try:
        resp = await client.get(KEV_URL, timeout=30.0)
        resp.raise_for_status()
        return {item["cveID"] for item in resp.json().get("vulnerabilities", [])}
    except (httpx.HTTPError, KeyError, ValueError):
        return set()


async def run_ingest(packages: list[dict]) -> list[dict]:
    """Full ingest: OSV match -> detail fetch -> EPSS/KEV enrichment.

    Returns a list of plain dicts ready to build Vulnerability models from.
    Degrades gracefully: if EPSS/KEV are slow or down, CVEs still return.
    """
    async with httpx.AsyncClient() as client:
        matched = await query_osv(packages, client)
        if not matched:
            return []

        vulns: list[dict] = []
        for pkg_index, vuln_ids in matched.items():
            pkg = packages[pkg_index]
            for vuln_id in vuln_ids:
                detail = await fetch_vuln_detail(vuln_id, client)
                if detail is None:
                    continue
                cvss, severity = _extract_cvss(detail)
                cve_id = _preferred_cve_id(detail)
                vulns.append({
                    "cve_id": cve_id,
                    "package": pkg["name"],
                    "version": pkg["version"],
                    "ecosystem": pkg["ecosystem"],
                    "cvss": cvss,
                    "severity": severity,
                    "fixed_version": _extract_fixed_version(detail, pkg["name"], pkg["ecosystem"]),
                    "summary": detail.get("summary") or detail.get("details", "")[:280],
                    "aliases": detail.get("aliases", []),
                    "osv_url": f"https://osv.dev/vulnerability/{detail.get('id')}",
                })

        cve_ids = [v["cve_id"] for v in vulns]
        epss_scores = await enrich_epss(cve_ids, client)
        kev_set = await fetch_kev(client)

        for v in vulns:
            v["epss"] = epss_scores.get(v["cve_id"])
            v["kev"] = v["cve_id"] in kev_set

    return vulns
