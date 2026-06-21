from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional
import uuid


class LockfileInput(BaseModel):
    filename: str
    content: str


class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None
    files: Optional[list[LockfileInput]] = None


class Project(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    ecosystem: Optional[str] = None
    files: list[LockfileInput] = Field(default_factory=list)
    status: str = "pending"  # pending | analyzed
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        from_attributes = True


class Vulnerability(BaseModel):
    """A single confirmed CVE from OSV, enriched with EPSS + KEV."""
    cve_id: str
    package: str
    version: str
    ecosystem: str
    cvss: Optional[float] = None
    severity: Optional[str] = None  # critical | high | medium | low
    epss: Optional[float] = None
    kev: bool = False
    fixed_version: Optional[str] = None
    summary: str = ""
    aliases: list[str] = Field(default_factory=list)
    osv_url: Optional[str] = None


class AnalysisReport(BaseModel):
    """Claude Opus 4.8 narrative over the confirmed CVE set."""
    narrative: str
    chain_summary: str
    highest_risk_path: str


class AnalyzeResponse(BaseModel):
    project_id: str
    ecosystem: Optional[str] = None
    report: Optional[AnalysisReport] = None
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    summary: dict = Field(default_factory=dict)
