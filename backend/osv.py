"""OSV ingest pipeline: lockfile -> confirmed CVEs, enriched with EPSS + CISA KEV.

Detection is a deterministic public-database lookup, never inference. OSV does the
semver range matching server-side when we pass the exact installed version, so the
list here is reproducible with `osv-scanner` on the same lockfile.
"""
import json
import re
from typing import Optional

import httpx
from cvss import CVSS3

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


ECOSYSTEM_BY_FILENAME = {
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "package.json": "npm",
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
    """Normalise a dependency manifest to a list of {name, version, ecosystem} dicts."""
    name = filename.strip().lower()
    dispatch = {
        "package-lock.json": _parse_package_lock,
        "yarn.lock": _parse_yarn_lock,
        "pnpm-lock.yaml": _parse_pnpm_lock,
        "package.json": _parse_package_json,
        "requirements.txt": _parse_requirements_txt,
        "pipfile.lock": _parse_pipfile_lock,
        "poetry.lock": _parse_poetry_lock,
        "go.sum": _parse_go_sum,
        "cargo.lock": _parse_cargo_lock,
        "gemfile.lock": _parse_gemfile_lock,
    }
    parser = dispatch.get(name)
    if parser is None:
        return []
    try:
        return parser(content)
    except Exception:
        return []


# ── npm / Node parsers ────────────────────────────────────────────────────────

def _parse_package_lock(content: str) -> list[dict]:
    data = json.loads(content)
    seen: set[tuple[str, str]] = set()
    packages: list[dict] = []

    for path, info in data.get("packages", {}).items():
        if not path:
            continue
        pkg_name = path.split("node_modules/")[-1]
        version = info.get("version")
        if pkg_name and version and (pkg_name, version) not in seen:
            seen.add((pkg_name, version))
            packages.append({"name": pkg_name, "version": version, "ecosystem": "npm"})

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


def _npm_version(range_str: str) -> Optional[str]:
    """Extract a usable semver from a range string like ^1.2.3 or >=2.0.0 <3."""
    m = re.search(r"(\d+\.\d+(?:\.\d+)?(?:-[\w.]+)?)", range_str)
    return m.group(1) if m else None


def _parse_package_json(content: str) -> list[dict]:
    data = json.loads(content)
    seen: set[tuple[str, str]] = set()
    packages: list[dict] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for pkg_name, version_range in (data.get(section) or {}).items():
            if not isinstance(version_range, str):
                continue
            version = _npm_version(version_range)
            if version and (pkg_name, version) not in seen:
                seen.add((pkg_name, version))
                packages.append({"name": pkg_name, "version": version, "ecosystem": "npm"})
    return packages


def _parse_yarn_lock(content: str) -> list[dict]:
    """Parse yarn.lock v1 format."""
    seen: set[tuple[str, str]] = set()
    packages: list[dict] = []
    current_pkg: Optional[str] = None
    for line in content.splitlines():
        stripped = line.strip()
        # Header line: '"name@range, name@range":' or 'name@range:'
        if not line.startswith(" ") and stripped.endswith(":") and "@" in stripped:
            # Take the first entry and strip quotes
            first = stripped.rstrip(":").split(",")[0].strip().strip('"')
            at_idx = first.rfind("@")
            if at_idx > 0:
                current_pkg = first[:at_idx]
        elif current_pkg and stripped.startswith("version "):
            version = stripped.split(None, 1)[1].strip().strip('"')
            if version and (current_pkg, version) not in seen:
                seen.add((current_pkg, version))
                packages.append({"name": current_pkg, "version": version, "ecosystem": "npm"})
            current_pkg = None
    return packages


def _parse_pnpm_lock(content: str) -> list[dict]:
    """Parse pnpm-lock.yaml (v6 and v9 formats) with regex — no YAML dep needed."""
    seen: set[tuple[str, str]] = set()
    packages: list[dict] = []
    # v6: "/name/version:" or "/name@version:", v9: "name@version:"
    for m in re.finditer(
        r"^[ ]*/?([a-zA-Z0-9@][a-zA-Z0-9_.@/\-]*)[@/](\d[^\s:]*):$",
        content,
        re.MULTILINE,
    ):
        name, version = m.group(1).lstrip("/"), m.group(2)
        if name and version and (name, version) not in seen:
            seen.add((name, version))
            packages.append({"name": name, "version": version, "ecosystem": "npm"})
    return packages


# ── Python parsers ────────────────────────────────────────────────────────────

def _parse_requirements_txt(content: str) -> list[dict]:
    packages: list[dict] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "http", "git+")):
            continue
        # name==version (pinned) — most useful for OSV
        m = re.match(r"^([A-Za-z0-9_\-\.]+)==([^\s;#]+)", line)
        if m:
            packages.append({"name": m.group(1), "version": m.group(2), "ecosystem": "PyPI"})
    return packages


def _parse_pipfile_lock(content: str) -> list[dict]:
    data = json.loads(content)
    seen: set[tuple[str, str]] = set()
    packages: list[dict] = []
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            version = (info.get("version") or "").lstrip("=")
            if version and (name, version) not in seen:
                seen.add((name, version))
                packages.append({"name": name, "version": version, "ecosystem": "PyPI"})
    return packages


def _parse_poetry_lock(content: str) -> list[dict]:
    packages: list[dict] = []
    for block in re.split(r"\[\[package\]\]", content)[1:]:
        name_m = re.search(r'name\s*=\s*"([^"]+)"', block)
        ver_m = re.search(r'version\s*=\s*"([^"]+)"', block)
        if name_m and ver_m:
            packages.append({"name": name_m.group(1), "version": ver_m.group(1), "ecosystem": "PyPI"})
    return packages


# ── Go parser ─────────────────────────────────────────────────────────────────

def _parse_go_sum(content: str) -> list[dict]:
    """Parse go.sum: each line is 'module version/go.mod h1:...' or 'module version h1:...'"""
    seen: set[tuple[str, str]] = set()
    packages: list[dict] = []
    for line in content.splitlines():
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        module = parts[0]
        version_raw = parts[1].split("/")[0]  # strip /go.mod suffix
        version = version_raw.lstrip("v")
        if module and version and (module, version) not in seen:
            seen.add((module, version))
            packages.append({"name": module, "version": version, "ecosystem": "Go"})
    return packages


# ── Rust parser ───────────────────────────────────────────────────────────────

def _parse_cargo_lock(content: str) -> list[dict]:
    packages: list[dict] = []
    for block in re.split(r"\[\[package\]\]", content)[1:]:
        name_m = re.search(r'name\s*=\s*"([^"]+)"', block)
        ver_m = re.search(r'version\s*=\s*"([^"]+)"', block)
        if name_m and ver_m:
            packages.append({"name": name_m.group(1), "version": ver_m.group(1), "ecosystem": "crates.io"})
    return packages


# ── Ruby parser ───────────────────────────────────────────────────────────────

def _parse_gemfile_lock(content: str) -> list[dict]:
    seen: set[tuple[str, str]] = set()
    packages: list[dict] = []
    in_specs = False
    for line in content.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs:
            if line and not line[0].isspace():
                in_specs = False
                continue
            # "    gem_name (version)"
            m = re.match(r"    ([^\s(]+)\s+\(([^)]+)\)", line)
            if m:
                name, version = m.group(1), m.group(2)
                # Gemfile.lock can list "name (version-platform)" — strip platform
                version = version.split("-")[0]
                if (name, version) not in seen:
                    seen.add((name, version))
                    packages.append({"name": name, "version": version, "ecosystem": "RubyGems"})
    return packages


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


_AV_MAP = {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}
_AC_MAP = {"L": "Low", "H": "High"}
_PR_MAP = {"N": "None", "L": "Low", "H": "High"}
_UI_MAP = {"N": "None", "R": "Required"}
_SC_MAP = {"U": "Unchanged", "C": "Changed"}


def _extract_cvss_vector(vuln: dict) -> Optional[dict]:
    """Parse CVSS v3 vector string into component dict."""
    for sev in vuln.get("severity", []) or []:
        if sev.get("type", "").startswith("CVSS_V3"):
            parts: dict[str, str] = {}
            for segment in sev.get("score", "").split("/"):
                if ":" in segment:
                    k, v = segment.split(":", 1)
                    parts[k] = v
            return {
                "attack_vector": _AV_MAP.get(parts.get("AV", "")),
                "attack_complexity": _AC_MAP.get(parts.get("AC", "")),
                "privileges_required": _PR_MAP.get(parts.get("PR", "")),
                "user_interaction": _UI_MAP.get(parts.get("UI", "")),
                "scope": _SC_MAP.get(parts.get("S", "")),
            }
    return None


def _extract_cwe_ids(vuln: dict) -> list[str]:
    """Extract CWE IDs from OSV database_specific fields."""
    seen: set[str] = set()
    result: list[str] = []

    def _add(cwe: str) -> None:
        if cwe and cwe not in seen:
            seen.add(cwe)
            result.append(cwe)

    db = vuln.get("database_specific") or {}
    for cwe in db.get("cwe_ids", []) or []:
        _add(cwe)

    for affected in vuln.get("affected", []) or []:
        aff_db = affected.get("database_specific") or {}
        for entry in aff_db.get("cwes", []) or []:
            cwe_id = entry.get("cweId") if isinstance(entry, dict) else entry
            _add(str(cwe_id) if cwe_id else "")

    return result


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
                cvss_vector = _extract_cvss_vector(detail)
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
                    "cwe_ids": _extract_cwe_ids(detail),
                    "attack_vector": cvss_vector.get("attack_vector") if cvss_vector else None,
                    "attack_complexity": cvss_vector.get("attack_complexity") if cvss_vector else None,
                    "privileges_required": cvss_vector.get("privileges_required") if cvss_vector else None,
                    "user_interaction": cvss_vector.get("user_interaction") if cvss_vector else None,
                    "scope": cvss_vector.get("scope") if cvss_vector else None,
                })

        cve_ids = [v["cve_id"] for v in vulns]
        epss_scores = await enrich_epss(cve_ids, client)
        kev_set = await fetch_kev(client)

        for v in vulns:
            v["epss"] = epss_scores.get(v["cve_id"])
            v["kev"] = v["cve_id"] in kev_set

    return vulns
