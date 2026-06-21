import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

import db
from auth import get_current_user_id
from models import (
    LockfileInput,
    Project,
    ProjectCreate,
    Vulnerability,
    AnalysisReport,
    AnalyzeResponse,
)
import github
import osv
import analyze

load_dotenv()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.get_pool()
    yield
    await db.close_pool()


app = FastAPI(title="Aegis Backend", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _row_to_project(row) -> Project:
    return Project(
        id=str(row["id"]),
        name=row["name"],
        description=row["description"],
        repo_url=row["repo_url"],
        ecosystem=row["ecosystem"],
        files=[LockfileInput(**f) for f in (row["files"] or [])],
        status=row["status"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _row_to_analysis(row) -> AnalyzeResponse:
    return AnalyzeResponse(
        project_id=str(row["project_id"]),
        ecosystem=row["ecosystem"],
        report=AnalysisReport(**row["report"]) if row["report"] else None,
        vulnerabilities=[Vulnerability(**v) for v in (row["vulnerabilities"] or [])],
        summary=row["summary"] or {},
    )


def _name_from_url(url: str) -> str:
    import re
    m = re.search(r"github\.com[/:][\w.-]+/([\w.-]+)", url)
    return m.group(1) if m else url


async def _resolve_files(project_data: ProjectCreate) -> list[LockfileInput]:
    files: list[LockfileInput] = list(project_data.files or [])

    if project_data.github_url:
        try:
            fetched = await github.fetch_lockfiles(project_data.github_url)
        except github.GitHubError as e:
            raise HTTPException(status_code=400, detail=str(e))
        files.extend(LockfileInput(**f) for f in fetched)
        if not files:
            raise HTTPException(
                status_code=400,
                detail="No supported lockfiles found in the repository.",
            )

    return files


def _detect_ecosystem(files: list[LockfileInput]) -> str | None:
    for f in files:
        ecosystem = osv.detect_ecosystem(f.filename)
        if ecosystem:
            return ecosystem
    return None


@app.get("/")
def read_root():
    return {"message": "Aegis Backend API"}


@app.post("/projects", response_model=Project)
async def create_project(
    project_data: ProjectCreate,
    user_id: str = Depends(get_current_user_id),
):
    files = await _resolve_files(project_data)
    ecosystem = _detect_ecosystem(files)
    project_id = uuid.uuid4()
    name = project_data.name or _name_from_url(project_data.github_url)

    pool = await db.get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO projects (id, user_id, name, description, repo_url, ecosystem, files)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            """,
            project_id,
            user_id,
            name,
            project_data.description,
            project_data.github_url,
            ecosystem,
            [f.model_dump() for f in files],
        )
    return _row_to_project(row)


@app.get("/projects", response_model=list[Project])
async def get_projects(user_id: str = Depends(get_current_user_id)):
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM projects WHERE user_id = $1 ORDER BY created_at DESC",
            user_id,
        )
    return [_row_to_project(row) for row in rows]


@app.get("/projects/{project_id}", response_model=Project)
async def get_project(
    project_id: str,
    user_id: str = Depends(get_current_user_id),
):
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM projects WHERE id = $1 AND user_id = $2",
            uuid.UUID(project_id),
            user_id,
        )
    if not row:
        raise HTTPException(status_code=404, detail="Project not found")
    return _row_to_project(row)


@app.put("/projects/{project_id}", response_model=Project)
async def update_project(
    project_id: str,
    project_data: ProjectCreate,
    user_id: str = Depends(get_current_user_id),
):
    pool = await db.get_pool()
    pid = uuid.UUID(project_id)

    async with pool.acquire() as conn:
        existing = await conn.fetchrow(
            "SELECT id FROM projects WHERE id = $1 AND user_id = $2", pid, user_id
        )
        if not existing:
            raise HTTPException(status_code=404, detail="Project not found")

        if project_data.github_url or project_data.files is not None:
            files = await _resolve_files(project_data)
            ecosystem = _detect_ecosystem(files)
            name = project_data.name or _name_from_url(project_data.github_url)
            row = await conn.fetchrow(
                """
                UPDATE projects
                SET name = $3, description = $4, repo_url = $5,
                    ecosystem = $6, files = $7, updated_at = now()
                WHERE id = $1 AND user_id = $2
                RETURNING *
                """,
                pid,
                user_id,
                name,
                project_data.description,
                project_data.github_url,
                ecosystem,
                [f.model_dump() for f in files],
            )
        else:
            name = project_data.name or ""
            row = await conn.fetchrow(
                """
                UPDATE projects
                SET name = $3, description = $4, updated_at = now()
                WHERE id = $1 AND user_id = $2
                RETURNING *
                """,
                pid,
                user_id,
                name,
                project_data.description,
            )

    return _row_to_project(row)


@app.delete("/projects/{project_id}")
async def delete_project(
    project_id: str,
    user_id: str = Depends(get_current_user_id),
):
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            "DELETE FROM projects WHERE id = $1 AND user_id = $2",
            uuid.UUID(project_id),
            user_id,
        )
    if result == "DELETE 0":
        raise HTTPException(status_code=404, detail="Project not found")
    return {"message": "Project deleted successfully"}


@app.post("/projects/{project_id}/analyze", response_model=AnalyzeResponse)
async def analyze_project(
    project_id: str,
    user_id: str = Depends(get_current_user_id),
):
    pool = await db.get_pool()
    pid = uuid.UUID(project_id)

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM projects WHERE id = $1 AND user_id = $2", pid, user_id
        )
    if not row:
        raise HTTPException(status_code=404, detail="Project not found")

    project = _row_to_project(row)
    if not project.files:
        raise HTTPException(
            status_code=400,
            detail="Project has no lockfile to analyze. Add a lockfile first.",
        )

    packages: list[dict] = []
    for f in project.files:
        packages.extend(osv.parse_lockfile(f.filename, f.content))

    raw_vulns = await osv.run_ingest(packages)
    vulnerabilities = [Vulnerability(**v) for v in raw_vulns]

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

    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO analyses (project_id, user_id, ecosystem, report, vulnerabilities, summary)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (project_id) DO UPDATE
            SET user_id = EXCLUDED.user_id,
                ecosystem = EXCLUDED.ecosystem,
                report = EXCLUDED.report,
                vulnerabilities = EXCLUDED.vulnerabilities,
                summary = EXCLUDED.summary
            """,
            pid,
            user_id,
            project.ecosystem,
            report.model_dump() if report else None,
            [v.model_dump() for v in vulnerabilities],
            summary,
        )
        await conn.execute(
            "UPDATE projects SET status = 'analyzed', updated_at = now() WHERE id = $1",
            pid,
        )

    return AnalyzeResponse(
        project_id=project_id,
        ecosystem=project.ecosystem,
        report=report,
        vulnerabilities=vulnerabilities,
        summary=summary,
    )


@app.get("/projects/{project_id}/analysis", response_model=AnalyzeResponse)
async def get_analysis(
    project_id: str,
    user_id: str = Depends(get_current_user_id),
):
    pool = await db.get_pool()
    pid = uuid.UUID(project_id)
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM analyses WHERE project_id = $1 AND user_id = $2",
            pid,
            user_id,
        )
    if not row:
        raise HTTPException(status_code=404, detail="No analysis found for this project")
    return _row_to_analysis(row)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
