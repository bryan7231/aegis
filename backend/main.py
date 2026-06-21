from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from datetime import datetime

from models import (
    Project,
    ProjectCreate,
    Vulnerability,
    AnalyzeResponse,
)
import osv
import analyze

load_dotenv()

app = FastAPI(title="Aegis Backend", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

projects_db: dict[str, Project] = {}
analysis_db: dict[str, AnalyzeResponse] = {}


@app.get("/")
def read_root():
    return {"message": "Aegis Backend API"}


@app.post("/projects", response_model=Project)
def create_project(project_data: ProjectCreate):
    """Create a new project, optionally with lockfile(s) to analyze."""
    files = project_data.files or []
    ecosystem = None
    for f in files:
        ecosystem = osv.detect_ecosystem(f.filename)
        if ecosystem:
            break

    project = Project(
        name=project_data.name,
        description=project_data.description,
        files=files,
        ecosystem=ecosystem,
    )
    projects_db[project.id] = project
    return project


@app.get("/projects", response_model=list[Project])
def get_projects():
    """Get all previous projects."""
    return list(projects_db.values())


@app.get("/projects/{project_id}", response_model=Project)
def get_project(project_id: str):
    """Get a specific project by ID."""
    if project_id not in projects_db:
        raise HTTPException(status_code=404, detail="Project not found")
    return projects_db[project_id]


@app.put("/projects/{project_id}", response_model=Project)
def update_project(project_id: str, project_data: ProjectCreate):
    """Update a project."""
    if project_id not in projects_db:
        raise HTTPException(status_code=404, detail="Project not found")

    project = projects_db[project_id]
    project.name = project_data.name
    project.description = project_data.description
    if project_data.files is not None:
        project.files = project_data.files
    project.updated_at = datetime.utcnow()
    projects_db[project_id] = project
    return project


@app.delete("/projects/{project_id}")
def delete_project(project_id: str):
    """Delete a project."""
    if project_id not in projects_db:
        raise HTTPException(status_code=404, detail="Project not found")
    del projects_db[project_id]
    analysis_db.pop(project_id, None)
    return {"message": "Project deleted successfully"}


@app.post("/projects/{project_id}/analyze", response_model=AnalyzeResponse)
async def analyze_project(project_id: str):
    """The 'Analyze DB' button.

    1. Parse the stored lockfile(s) per ecosystem.
    2. Batch-query OSV for confirmed CVEs (+ EPSS / CISA KEV enrichment).
    3. Send the confirmed CVE set to Claude Opus 4.8 for a narrative report.

    Returns the vulnerability list + report (later parsed into the graph).
    """
    if project_id not in projects_db:
        raise HTTPException(status_code=404, detail="Project not found")

    project = projects_db[project_id]
    if not project.files:
        raise HTTPException(
            status_code=400,
            detail="Project has no lockfile to analyze. Add a lockfile first.",
        )

    # 1. Parse every stored lockfile into normalized package tuples.
    packages: list[dict] = []
    for f in project.files:
        packages.extend(osv.parse_lockfile(f.filename, f.content))

    # 2. OSV ingest + EPSS/KEV enrichment.
    raw_vulns = await osv.run_ingest(packages)
    vulnerabilities = [Vulnerability(**v) for v in raw_vulns]

    # 3. Claude Opus 4.8 narrative over the confirmed set.
    try:
        report = await analyze.generate_report(vulnerabilities)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))

    summary = {
        "total_packages": len(packages),
        "vulnerable_packages": len({v.package for v in vulnerabilities}),
        "total_cves": len(vulnerabilities),
        "kev_count": sum(1 for v in vulnerabilities if v.kev),
    }

    result = AnalyzeResponse(
        project_id=project_id,
        ecosystem=project.ecosystem,
        report=report,
        vulnerabilities=vulnerabilities,
        summary=summary,
    )

    project.status = "analyzed"
    project.updated_at = datetime.utcnow()
    analysis_db[project_id] = result
    return result


@app.get("/projects/{project_id}/analysis", response_model=AnalyzeResponse)
def get_analysis(project_id: str):
    """Return the cached analysis result for a project."""
    if project_id not in analysis_db:
        raise HTTPException(status_code=404, detail="No analysis found for this project")
    return analysis_db[project_id]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
