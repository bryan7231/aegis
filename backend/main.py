import os
import uuid
from contextlib import asynccontextmanager

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

import db
from auth import get_current_user_id
from models import (
    LockfileInput,
    Project,
    ProjectCreate,
    ProjectShare,
    ShareRequest,
    Vulnerability,
    VulnNode,
    VulnEdge,
    VulnGraph,
    AnalysisReport,
    AnalyzeResponse,
)
import github
import osv
import analyze
import code_scan
import remediation

load_dotenv()

# Project IDs whose analysis is currently running in a background task.
# asyncio is single-threaded so no lock needed for set mutations.
_running: set[str] = set()


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


# ── helpers ──────────────────────────────────────────────────────────────────

def _row_to_project(row, shares=None) -> Project:
    try:
        is_shared = bool(row["is_shared"])
    except KeyError:
        is_shared = False
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
        is_shared=is_shared,
        shares=[ProjectShare(**s) for s in (shares or [])],
    )


async def _clerk_user_id_from_email(email: str) -> str | None:
    """Look up a Clerk user's ID by email address. Returns None on any failure."""
    secret = os.environ.get("CLERK_SECRET_KEY")
    if not secret:
        return None
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                "https://api.clerk.com/v1/users",
                params={"email_address": email},
                headers={"Authorization": f"Bearer {secret}"},
            )
            if resp.status_code == 200:
                users = resp.json()
                return users[0]["id"] if users else None
    except Exception:
        pass
    return None


async def _get_accessible_project(conn, pid: uuid.UUID, user_id: str):
    """Return project row if user owns it or was shared access. Raises 404 otherwise."""
    row = await conn.fetchrow(
        """
        SELECT p.*, (p.user_id != $2) AS is_shared
        FROM projects p
        WHERE p.id = $1
          AND (p.user_id = $2
               OR EXISTS (SELECT 1 FROM project_shares
                          WHERE project_id = $1 AND shared_with_user_id = $2))
        """,
        pid, user_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Project not found")
    return row


def _row_to_analysis(row, graph: VulnGraph | None = None) -> AnalyzeResponse:
    return AnalyzeResponse(
        project_id=str(row["project_id"]),
        ecosystem=row["ecosystem"],
        report=AnalysisReport(**row["report"]) if row["report"] else None,
        vulnerabilities=[Vulnerability(**v) for v in (row["vulnerabilities"] or [])],
        graph=graph,
        summary=row["summary"] or {},
    )


async def _load_graph(conn, pid: uuid.UUID) -> VulnGraph | None:
    """Load vuln_nodes + vuln_edges for a project from DB."""
    node_rows = await conn.fetch(
        "SELECT * FROM vuln_nodes WHERE project_id = $1 ORDER BY centrality_score DESC",
        pid,
    )
    if not node_rows:
        return None
    edge_rows = await conn.fetch(
        "SELECT * FROM vuln_edges WHERE project_id = $1",
        pid,
    )
    nodes = [
        VulnNode(
            id=str(r["id"]),
            source=r["source"],
            title=r["title"],
            description=r["description"],
            severity=r["severity"],
            cvss=r["cvss"],
            cwe_ids=list(r["cwe_ids"] or []),
            remediation=r["remediation"],
            cve_id=r["cve_id"],
            package=r["package"],
            version=r["version"],
            ecosystem=r["ecosystem"],
            epss=r["epss"],
            kev=r["kev"],
            fixed_version=r["fixed_version"],
            osv_url=r["osv_url"],
            attack_vector=r["attack_vector"],
            attack_complexity=r["attack_complexity"],
            privileges_required=r["privileges_required"],
            user_interaction=r["user_interaction"],
            scope=r["scope"],
            file_path=r["file_path"],
            line_start=r["line_start"],
            line_end=r["line_end"],
            vuln_category=r["vuln_category"],
            affected_code=r["affected_code"],
            centrality_score=r["centrality_score"],
        )
        for r in node_rows
    ]
    edges = [
        VulnEdge(
            id=str(r["id"]),
            source_id=str(r["source_id"]),
            target_id=str(r["target_id"]),
            edge_type=r["edge_type"],
            confidence=r["confidence"],
            description=r["description"] or "",
        )
        for r in edge_rows
    ]
    return VulnGraph(nodes=nodes, edges=edges)


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


async def _analyze_in_background(project: Project, user_id: str, pid: uuid.UUID) -> None:
    """Wrapper for background task: run analysis, update status, clean up _running."""
    str_pid = str(pid)
    try:
        await _run_analysis(project, user_id, pid)
    except Exception:
        pool = await db.get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE projects SET status = 'pending', updated_at = now() WHERE id = $1", pid
            )
    finally:
        _running.discard(str_pid)


async def _run_analysis(project: Project, user_id: str, pid: uuid.UUID) -> AnalyzeResponse:
    """Run full analysis pipeline: OSV + code scan + edge generation. Persist to DB."""
    import asyncio

    # ── 1. Dependency vulnerability ingest (OSV) ──────────────────────────────
    packages: list[dict] = []
    if project.files:
        for f in project.files:
            packages.extend(osv.parse_lockfile(f.filename, f.content))

    raw_vulns: list[dict] = []
    source_files: list[dict] = []

    repo_url = project.repo_url or ""

    # Run OSV ingest and source file fetch concurrently
    async def _fetch_source():
        if repo_url:
            try:
                return await github.fetch_source_files(repo_url)
            except Exception:
                return []
        return []

    async def _empty():
        return []

    raw_vulns, source_files = await asyncio.gather(
        osv.run_ingest(packages) if packages else _empty(),
        _fetch_source(),
    )

    # ── 2. Code scan (Claude) ─────────────────────────────────────────────────
    code_vulns = await code_scan.scan_source_files(source_files)

    # ── 3. Convert all vulns to VulnNode dicts ────────────────────────────────
    all_nodes: list[dict] = []

    for rv in raw_vulns:
        node_id = str(uuid.uuid4())
        all_nodes.append({
            "id": node_id,
            "source": "dependency",
            "title": rv.get("cve_id") or rv.get("package", "Unknown CVE"),
            "description": rv.get("summary", ""),
            "severity": rv.get("severity"),
            "cvss": rv.get("cvss"),
            "cwe_ids": rv.get("cwe_ids") or [],
            "remediation": (f"Upgrade to {rv['fixed_version']}" if rv.get("fixed_version") else None),
            "cve_id": rv.get("cve_id"),
            "package": rv.get("package"),
            "version": rv.get("version"),
            "ecosystem": rv.get("ecosystem"),
            "epss": rv.get("epss"),
            "kev": bool(rv.get("kev")),
            "fixed_version": rv.get("fixed_version"),
            "osv_url": rv.get("osv_url"),
            "attack_vector": rv.get("attack_vector"),
            "attack_complexity": rv.get("attack_complexity"),
            "privileges_required": rv.get("privileges_required"),
            "user_interaction": rv.get("user_interaction"),
            "scope": rv.get("scope"),
            "file_path": None,
            "line_start": None,
            "line_end": None,
            "vuln_category": None,
            "affected_code": None,
            "centrality_score": 0.0,
        })

    for cv in code_vulns:
        node_id = str(uuid.uuid4())
        all_nodes.append({
            "id": node_id,
            "source": "code",
            "title": cv.title,
            "description": cv.description,
            "severity": cv.severity,
            "cvss": cv.cvss,
            "cwe_ids": cv.cwe_ids or [],
            "remediation": cv.remediation,
            "cve_id": None,
            "package": None,
            "version": None,
            "ecosystem": None,
            "epss": None,
            "kev": False,
            "fixed_version": None,
            "osv_url": None,
            "attack_vector": None,
            "attack_complexity": None,
            "privileges_required": None,
            "user_interaction": None,
            "scope": None,
            "file_path": cv.file_path,
            "line_start": cv.line_start,
            "line_end": cv.line_end,
            "vuln_category": cv.vuln_category,
            "affected_code": cv.affected_code,
            "centrality_score": 0.0,
        })

    # ── 4. Generate exploit-chain edges ───────────────────────────────────────
    edge_specs = await analyze.generate_edges(all_nodes)

    # Build UUID-mapped edges
    edge_records: list[dict] = []
    for spec in edge_specs:
        if 0 <= spec.source_index < len(all_nodes) and 0 <= spec.target_index < len(all_nodes):
            edge_records.append({
                "id": str(uuid.uuid4()),
                "source_id": all_nodes[spec.source_index]["id"],
                "target_id": all_nodes[spec.target_index]["id"],
                "edge_type": spec.edge_type,
                "confidence": spec.confidence,
                "description": spec.description,
            })

    # ── 5. Compute degree centrality ──────────────────────────────────────────
    degree: dict[str, int] = {}
    for er in edge_records:
        degree[er["source_id"]] = degree.get(er["source_id"], 0) + 1
        degree[er["target_id"]] = degree.get(er["target_id"], 0) + 1

    max_degree = max(degree.values(), default=1)
    for node in all_nodes:
        node["centrality_score"] = degree.get(node["id"], 0) / max_degree

    # ── 6. Claude narrative report ────────────────────────────────────────────
    flat_vulns = [Vulnerability(**rv) for rv in raw_vulns]
    try:
        report = await analyze.generate_report(flat_vulns)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))

    summary = {
        "total_packages": len(packages),
        "vulnerable_packages": len({rv.get("package") for rv in raw_vulns if rv.get("package")}),
        "total_cves": len(raw_vulns),
        "code_vulns": len(code_vulns),
        "total_nodes": len(all_nodes),
        "total_edges": len(edge_records),
        "kev_count": sum(1 for rv in raw_vulns if rv.get("kev")),
    }

    # ── 7. Persist to DB ──────────────────────────────────────────────────────
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            # Upsert legacy analyses row (flat compat)
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
                pid, user_id, project.ecosystem,
                report.model_dump() if report else None,
                [v.model_dump() for v in flat_vulns],
                summary,
            )

            # Clear old graph data for this project before re-inserting
            await conn.execute("DELETE FROM vuln_edges WHERE project_id = $1", pid)
            await conn.execute("DELETE FROM vuln_nodes WHERE project_id = $1", pid)

            # Bulk-insert nodes
            if all_nodes:
                await conn.executemany(
                    """
                    INSERT INTO vuln_nodes (
                        id, project_id, user_id, source, title, description,
                        severity, cvss, cwe_ids, remediation,
                        cve_id, package, version, ecosystem, epss, kev,
                        fixed_version, osv_url,
                        attack_vector, attack_complexity, privileges_required,
                        user_interaction, scope,
                        file_path, line_start, line_end, vuln_category,
                        affected_code, centrality_score
                    ) VALUES (
                        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
                        $15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29
                    )
                    """,
                    [
                        (
                            uuid.UUID(n["id"]), pid, user_id, n["source"],
                            n["title"], n["description"],
                            n["severity"], n["cvss"], n["cwe_ids"], n["remediation"],
                            n["cve_id"], n["package"], n["version"], n["ecosystem"],
                            n["epss"], n["kev"],
                            n["fixed_version"], n["osv_url"],
                            n["attack_vector"], n["attack_complexity"],
                            n["privileges_required"], n["user_interaction"], n["scope"],
                            n["file_path"], n["line_start"], n["line_end"],
                            n["vuln_category"], n["affected_code"], n["centrality_score"],
                        )
                        for n in all_nodes
                    ],
                )

            # Bulk-insert edges
            if edge_records:
                await conn.executemany(
                    """
                    INSERT INTO vuln_edges (id, project_id, source_id, target_id, edge_type, confidence, description)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                    ON CONFLICT (source_id, target_id, edge_type) DO NOTHING
                    """,
                    [
                        (
                            uuid.UUID(er["id"]), pid,
                            uuid.UUID(er["source_id"]), uuid.UUID(er["target_id"]),
                            er["edge_type"], er["confidence"], er["description"],
                        )
                        for er in edge_records
                    ],
                )

            await conn.execute(
                "UPDATE projects SET status = 'analyzed', updated_at = now() WHERE id = $1",
                pid,
            )

    # ── 8. Build response ─────────────────────────────────────────────────────
    vuln_nodes = [VulnNode(**{k: v for k, v in n.items()}) for n in all_nodes]
    vuln_edges = [VulnEdge(**er) for er in edge_records]

    return AnalyzeResponse(
        project_id=str(pid),
        ecosystem=project.ecosystem,
        report=report,
        vulnerabilities=flat_vulns,
        graph=VulnGraph(nodes=vuln_nodes, edges=vuln_edges),
        summary=summary,
    )


# ── routes ────────────────────────────────────────────────────────────────────

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
        own_rows = await conn.fetch(
            "SELECT * FROM projects WHERE user_id = $1 ORDER BY created_at DESC",
            user_id,
        )
        own_ids = [r["id"] for r in own_rows]
        share_rows = (
            await conn.fetch(
                "SELECT * FROM project_shares WHERE project_id = ANY($1::uuid[]) ORDER BY created_at ASC",
                own_ids,
            )
            if own_ids else []
        )
        shared_rows = await conn.fetch(
            """
            SELECT p.*, true AS is_shared
            FROM projects p
            JOIN project_shares s ON s.project_id = p.id
            WHERE s.shared_with_user_id = $1
            ORDER BY p.created_at DESC
            """,
            user_id,
        )

    # Group shares by owned project id
    shares_map: dict[str, list] = {}
    for s in share_rows:
        key = str(s["project_id"])
        shares_map.setdefault(key, []).append({
            "id": str(s["id"]),
            "project_id": str(s["project_id"]),
            "shared_with_email": s["shared_with_email"],
            "created_at": s["created_at"].isoformat() if s["created_at"] else None,
        })

    result = [_row_to_project(r, shares=shares_map.get(str(r["id"]))) for r in own_rows]
    result += [_row_to_project(r) for r in shared_rows]
    return result


@app.get("/projects/{project_id}", response_model=Project)
async def get_project(
    project_id: str,
    user_id: str = Depends(get_current_user_id),
):
    pool = await db.get_pool()
    pid = uuid.UUID(project_id)
    async with pool.acquire() as conn:
        row = await _get_accessible_project(conn, pid, user_id)
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
                pid, user_id, name, project_data.description,
                project_data.github_url, ecosystem,
                [f.model_dump() for f in files],
            )
        else:
            row = await conn.fetchrow(
                """
                UPDATE projects
                SET name = $3, description = $4, updated_at = now()
                WHERE id = $1 AND user_id = $2
                RETURNING *
                """,
                pid, user_id,
                project_data.name or "",
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


@app.get("/projects/{project_id}/vulnerabilities", response_model=AnalyzeResponse)
async def get_vulnerabilities(
    project_id: str,
    background_tasks: BackgroundTasks,
    user_id: str = Depends(get_current_user_id),
):
    """Return cached vulnerability analysis, or kick off analysis and return 'analyzing'."""
    pool = await db.get_pool()
    pid = uuid.UUID(project_id)

    async with pool.acquire() as conn:
        project_row = await _get_accessible_project(conn, pid, user_id)
        cached = await conn.fetchrow("SELECT * FROM analyses WHERE project_id = $1", pid)
        if cached:
            graph = await _load_graph(conn, pid)
            return _row_to_analysis(cached, graph)

    # Not cached — kick off background analysis if not already running.
    str_pid = str(pid)
    if str_pid not in _running:
        _running.add(str_pid)
        # Mark project as "analyzing" so the frontend can distinguish states.
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE projects SET status = 'analyzing', updated_at = now() WHERE id = $1", pid
            )
        background_tasks.add_task(_analyze_in_background, _row_to_project(project_row), user_id, pid)

    return AnalyzeResponse(
        project_id=str_pid,
        status="analyzing",
        ecosystem=project_row["ecosystem"],
    )


@app.get("/projects/{project_id}/graph", response_model=VulnGraph)
async def get_graph(
    project_id: str,
    user_id: str = Depends(get_current_user_id),
):
    """Return the exploit-chain graph for a project (nodes + edges)."""
    pool = await db.get_pool()
    pid = uuid.UUID(project_id)

    async with pool.acquire() as conn:
        await _get_accessible_project(conn, pid, user_id)
        graph = await _load_graph(conn, pid)

    if graph is None:
        raise HTTPException(
            status_code=404,
            detail="No graph data yet. Run /analyze first.",
        )
    return graph


@app.post("/projects/{project_id}/analyze", response_model=AnalyzeResponse)
async def analyze_project(
    project_id: str,
    background_tasks: BackgroundTasks,
    user_id: str = Depends(get_current_user_id),
):
    """Force a fresh analysis, overwriting any cached result."""
    pool = await db.get_pool()
    pid = uuid.UUID(project_id)

    async with pool.acquire() as conn:
        row = await _get_accessible_project(conn, pid, user_id)

    str_pid = str(pid)
    if str_pid not in _running:
        _running.add(str_pid)
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE projects SET status = 'analyzing', updated_at = now() WHERE id = $1", pid
            )
        background_tasks.add_task(_analyze_in_background, _row_to_project(row), user_id, pid)

    return AnalyzeResponse(
        project_id=str_pid,
        status="analyzing",
        ecosystem=row["ecosystem"],
    )


@app.get("/projects/{project_id}/nodes/{node_id}/plan")
async def get_remediation_plan(
    project_id: str,
    node_id: str,
    user_id: str = Depends(get_current_user_id),
):
    """Return the cached remediation plan for a node, or generate and cache one."""
    pool = await db.get_pool()
    pid = uuid.UUID(project_id)
    nid = uuid.UUID(node_id)

    async with pool.acquire() as conn:
        await _get_accessible_project(conn, pid, user_id)

        cached = await conn.fetchrow(
            "SELECT plan, created_at FROM remediation_plans WHERE node_id = $1", nid
        )
        if cached:
            return {
                "node_id": str(nid),
                "plan": cached["plan"],
                "created_at": cached["created_at"].isoformat(),
                "cached": True,
            }

        node_row = await conn.fetchrow(
            "SELECT * FROM vuln_nodes WHERE id = $1 AND project_id = $2", nid, pid
        )
        if not node_row:
            raise HTTPException(status_code=404, detail="Vulnerability node not found")

        edge_rows = await conn.fetch(
            """
            SELECT e.description, e.edge_type,
                   n.title, n.cve_id, n.package, n.version,
                   n.file_path, n.severity, n.source
            FROM vuln_edges e
            JOIN vuln_nodes n ON (
                CASE WHEN e.source_id = $1 THEN e.target_id ELSE e.source_id END = n.id
            )
            WHERE (e.source_id = $1 OR e.target_id = $1)
              AND e.project_id = $2
            """,
            nid, pid,
        )

        proj_row = await conn.fetchrow("SELECT repo_url FROM projects WHERE id = $1", pid)

    node_dict = dict(node_row)
    connected = [
        {
            "cve_id": r["cve_id"],
            "title": r["title"],
            "package": r["package"],
            "version": r["version"],
            "file_path": r["file_path"],
            "severity": r["severity"],
            "source": r["source"],
        }
        for r in edge_rows
    ]
    edge_descriptions = [r["description"] or r["edge_type"] for r in edge_rows]

    try:
        plan = await remediation.generate_plan(
            node=node_dict,
            connected=connected,
            edge_descriptions=edge_descriptions,
            repo_url=proj_row["repo_url"] or "",
        )
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Plan generation failed: {e}")

    plan_id = uuid.uuid4()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO remediation_plans (id, node_id, project_id, user_id, plan)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (node_id) DO UPDATE SET plan = EXCLUDED.plan, created_at = now()
            """,
            plan_id, nid, pid, user_id, plan,
        )

    return {"node_id": str(nid), "plan": plan, "created_at": None, "cached": False}


@app.post("/projects/{project_id}/nodes/{node_id}/plan")
async def regenerate_remediation_plan(
    project_id: str,
    node_id: str,
    user_id: str = Depends(get_current_user_id),
):
    """Force-regenerate the remediation plan for a node, overwriting any cached version."""
    pool = await db.get_pool()
    pid = uuid.UUID(project_id)
    nid = uuid.UUID(node_id)

    async with pool.acquire() as conn:
        await _get_accessible_project(conn, pid, user_id)
        # Delete cached plan to force regen via the GET endpoint logic
        await conn.execute("DELETE FROM remediation_plans WHERE node_id = $1", nid)

    # Reuse the GET handler logic
    return await get_remediation_plan(project_id, node_id, user_id)


@app.get("/projects/{project_id}/analysis", response_model=AnalyzeResponse)
async def get_analysis(
    project_id: str,
    user_id: str = Depends(get_current_user_id),
):
    pool = await db.get_pool()
    pid = uuid.UUID(project_id)
    async with pool.acquire() as conn:
        await _get_accessible_project(conn, pid, user_id)
        row = await conn.fetchrow("SELECT * FROM analyses WHERE project_id = $1", pid)
    if not row:
        raise HTTPException(status_code=404, detail="No analysis found for this project")
    return _row_to_analysis(row)


# ── addressed vulns ───────────────────────────────────────────────────────────

@app.get("/projects/{project_id}/addressed")
async def get_addressed(
    project_id: str,
    user_id: str = Depends(get_current_user_id),
):
    pool = await db.get_pool()
    pid = uuid.UUID(project_id)
    async with pool.acquire() as conn:
        await _get_accessible_project(conn, pid, user_id)
        rows = await conn.fetch(
            "SELECT node_id FROM addressed_vulns WHERE project_id = $1 AND user_id = $2",
            pid, user_id,
        )
    return {"node_ids": [str(r["node_id"]) for r in rows]}


@app.post("/projects/{project_id}/addressed/{node_id}")
async def mark_addressed(
    project_id: str,
    node_id: str,
    user_id: str = Depends(get_current_user_id),
):
    pool = await db.get_pool()
    pid = uuid.UUID(project_id)
    nid = uuid.UUID(node_id)
    async with pool.acquire() as conn:
        await _get_accessible_project(conn, pid, user_id)
        await conn.execute(
            """
            INSERT INTO addressed_vulns (id, project_id, user_id, node_id)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (project_id, user_id, node_id) DO NOTHING
            """,
            uuid.uuid4(), pid, user_id, nid,
        )
    return {"addressed": True}


@app.delete("/projects/{project_id}/addressed/{node_id}")
async def unmark_addressed(
    project_id: str,
    node_id: str,
    user_id: str = Depends(get_current_user_id),
):
    pool = await db.get_pool()
    pid = uuid.UUID(project_id)
    nid = uuid.UUID(node_id)
    async with pool.acquire() as conn:
        await _get_accessible_project(conn, pid, user_id)
        await conn.execute(
            "DELETE FROM addressed_vulns WHERE project_id = $1 AND user_id = $2 AND node_id = $3",
            pid, user_id, nid,
        )
    return {"addressed": False}


# ── project sharing ───────────────────────────────────────────────────────────

@app.get("/projects/{project_id}/shares")
async def get_shares(
    project_id: str,
    user_id: str = Depends(get_current_user_id),
):
    pool = await db.get_pool()
    pid = uuid.UUID(project_id)
    async with pool.acquire() as conn:
        # Only the owner can see the shares list
        row = await conn.fetchrow(
            "SELECT id FROM projects WHERE id = $1 AND user_id = $2", pid, user_id
        )
        if not row:
            raise HTTPException(status_code=404, detail="Project not found")
        rows = await conn.fetch(
            "SELECT * FROM project_shares WHERE project_id = $1 ORDER BY created_at ASC", pid
        )
    return [
        {
            "id": str(r["id"]),
            "project_id": str(r["project_id"]),
            "shared_with_email": r["shared_with_email"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else None,
        }
        for r in rows
    ]


@app.post("/projects/{project_id}/shares")
async def share_project(
    project_id: str,
    body: ShareRequest,
    user_id: str = Depends(get_current_user_id),
):
    email = body.email.strip().lower()
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")

    pool = await db.get_pool()
    pid = uuid.UUID(project_id)

    async with pool.acquire() as conn:
        project = await conn.fetchrow(
            "SELECT id FROM projects WHERE id = $1 AND user_id = $2", pid, user_id
        )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if not os.environ.get("CLERK_SECRET_KEY"):
        raise HTTPException(
            status_code=503,
            detail="CLERK_SECRET_KEY is not configured — cannot look up users by email.",
        )

    shared_user_id = await _clerk_user_id_from_email(email)
    if shared_user_id is None:
        raise HTTPException(
            status_code=404,
            detail=f"No Aegis account found for {email}. They must sign up first.",
        )
    if shared_user_id == user_id:
        raise HTTPException(status_code=400, detail="Cannot share a project with yourself")

    share_id = uuid.uuid4()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO project_shares (id, project_id, owner_id, shared_with_email, shared_with_user_id)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (project_id, shared_with_email)
            DO UPDATE SET shared_with_user_id = EXCLUDED.shared_with_user_id
            RETURNING *
            """,
            share_id, pid, user_id, email, shared_user_id,
        )

    return {
        "id": str(row["id"]),
        "project_id": str(row["project_id"]),
        "shared_with_email": row["shared_with_email"],
        "created_at": row["created_at"].isoformat() if row["created_at"] else None,
    }


@app.delete("/projects/{project_id}/shares/{share_id}")
async def revoke_share(
    project_id: str,
    share_id: str,
    user_id: str = Depends(get_current_user_id),
):
    pool = await db.get_pool()
    pid = uuid.UUID(project_id)
    sid = uuid.UUID(share_id)
    async with pool.acquire() as conn:
        result = await conn.execute(
            """
            DELETE FROM project_shares
            WHERE id = $1 AND project_id = $2 AND owner_id = $3
            """,
            sid, pid, user_id,
        )
    if result == "DELETE 0":
        raise HTTPException(status_code=404, detail="Share not found")
    return {"message": "Share revoked"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
