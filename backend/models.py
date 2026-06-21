from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional
import uuid


class LockfileInput(BaseModel):
    filename: str
    content: str


class ProjectCreate(BaseModel):
    github_url: str
    name: Optional[str] = None
    description: Optional[str] = None
    files: Optional[list[LockfileInput]] = None


class ProjectShare(BaseModel):
    id: str
    project_id: str
    shared_with_email: str
    created_at: Optional[str] = None


class ShareRequest(BaseModel):
    email: str


class Project(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    repo_url: Optional[str] = None
    ecosystem: Optional[str] = None
    files: list[LockfileInput] = Field(default_factory=list)
    status: str = "pending"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    is_shared: bool = False
    shares: list[ProjectShare] = Field(default_factory=list)

    class Config:
        from_attributes = True


# ── Legacy flat vulnerability (kept for OSV ingest compatibility) ─────────────

class Vulnerability(BaseModel):
    """A single confirmed CVE from OSV, enriched with EPSS + KEV."""
    cve_id: str
    package: str
    version: str
    ecosystem: str
    cvss: Optional[float] = None
    severity: Optional[str] = None
    epss: Optional[float] = None
    kev: bool = False
    fixed_version: Optional[str] = None
    summary: str = ""
    aliases: list[str] = Field(default_factory=list)
    osv_url: Optional[str] = None
    # CVSS vector components
    cwe_ids: list[str] = Field(default_factory=list)
    attack_vector: Optional[str] = None        # Network | Adjacent | Local | Physical
    attack_complexity: Optional[str] = None    # Low | High
    privileges_required: Optional[str] = None  # None | Low | High
    user_interaction: Optional[str] = None     # None | Required
    scope: Optional[str] = None                # Unchanged | Changed


# ── Graph node / edge models ──────────────────────────────────────────────────

class VulnNode(BaseModel):
    """A vulnerability node in the exploit-chain graph.

    Covers both dependency CVEs and code-level findings so they can be
    connected in the same graph with meaningful edges.
    """
    id: str
    source: str                         # "dependency" | "code"
    title: str
    description: Optional[str] = None
    severity: Optional[str] = None
    cvss: Optional[float] = None
    cwe_ids: list[str] = Field(default_factory=list)
    remediation: Optional[str] = None

    # Dependency fields
    cve_id: Optional[str] = None
    package: Optional[str] = None
    version: Optional[str] = None
    ecosystem: Optional[str] = None
    epss: Optional[float] = None
    kev: bool = False
    fixed_version: Optional[str] = None
    osv_url: Optional[str] = None
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    scope: Optional[str] = None

    # Code-finding fields
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    vuln_category: Optional[str] = None    # injection | auth | crypto | xss | ...
    affected_code: Optional[str] = None

    # Graph metadata — set after edge computation
    centrality_score: float = 0.0


class VulnEdge(BaseModel):
    """A directed edge meaning "source can be leveraged to exploit target".

    Edge types:
    - dependency_chain   : A is a transitive dep of B; both are vulnerable
    - data_flow          : Code vuln passes attacker-controlled data into a dep vuln
    - privilege_escalation: A grants access/privilege that B requires (PR:L/H)
    - cwe_chain          : A's weakness class is a known precursor to B's (e.g. CWE-89→CWE-200)
    - lateral_movement   : A enables access to a component where B can be triggered
    """
    id: str
    source_id: str
    target_id: str
    edge_type: str
    confidence: float   # 0.0 – 1.0
    description: str    # Claude's plain-English explanation of the chain


class VulnGraph(BaseModel):
    nodes: list[VulnNode] = Field(default_factory=list)
    edges: list[VulnEdge] = Field(default_factory=list)


# ── Analysis report + response ────────────────────────────────────────────────

class AnalysisReport(BaseModel):
    """Claude Opus 4.8 narrative over the confirmed CVE set."""
    narrative: str
    chain_summary: str
    highest_risk_path: str


class AnalyzeResponse(BaseModel):
    project_id: str
    status: str = "complete"    # "analyzing" | "complete" | "error"
    ecosystem: Optional[str] = None
    report: Optional[AnalysisReport] = None
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    graph: Optional[VulnGraph] = None
    summary: dict = Field(default_factory=dict)
