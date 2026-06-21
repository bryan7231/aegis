import json
import os

import asyncpg

_pool: asyncpg.Pool | None = None


async def _init_connection(conn: asyncpg.Connection) -> None:
    await conn.set_type_codec(
        "jsonb",
        encoder=json.dumps,
        decoder=json.loads,
        schema="pg_catalog",
    )


async def get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        url = os.environ.get("DATABASE_URL")
        if not url:
            raise RuntimeError("DATABASE_URL env var is not set")
        _pool = await asyncpg.create_pool(
            url, min_size=2, max_size=10, init=_init_connection
        )
        await _create_schema(_pool)
    return _pool


async def close_pool() -> None:
    global _pool
    if _pool:
        await _pool.close()
        _pool = None


async def _create_schema(pool: asyncpg.Pool) -> None:
    async with pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS projects (
                id          UUID PRIMARY KEY,
                user_id     TEXT NOT NULL,
                name        TEXT NOT NULL,
                description TEXT,
                repo_url    TEXT,
                ecosystem   TEXT,
                files       JSONB NOT NULL DEFAULT '[]',
                status      TEXT NOT NULL DEFAULT 'pending',
                created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
                updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """)
        await conn.execute("""
            ALTER TABLE projects ADD COLUMN IF NOT EXISTS user_id TEXT NOT NULL DEFAULT ''
        """)

        # analyses — narrative report + flat vuln list for backward compat
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                project_id      UUID PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
                user_id         TEXT NOT NULL,
                ecosystem       TEXT,
                report          JSONB,
                vulnerabilities JSONB NOT NULL DEFAULT '[]',
                summary         JSONB NOT NULL DEFAULT '{}'
            )
        """)
        await conn.execute("""
            ALTER TABLE analyses ADD COLUMN IF NOT EXISTS user_id TEXT NOT NULL DEFAULT ''
        """)

        # vuln_nodes — one row per vulnerability (dep or code)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS vuln_nodes (
                id                  UUID PRIMARY KEY,
                project_id          UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                user_id             TEXT NOT NULL,
                source              TEXT NOT NULL,
                title               TEXT NOT NULL,
                description         TEXT,
                severity            TEXT,
                cvss                FLOAT,
                cwe_ids             TEXT[] NOT NULL DEFAULT '{}',
                remediation         TEXT,
                cve_id              TEXT,
                package             TEXT,
                version             TEXT,
                ecosystem           TEXT,
                epss                FLOAT,
                kev                 BOOLEAN NOT NULL DEFAULT FALSE,
                fixed_version       TEXT,
                osv_url             TEXT,
                attack_vector       TEXT,
                attack_complexity   TEXT,
                privileges_required TEXT,
                user_interaction    TEXT,
                scope               TEXT,
                file_path           TEXT,
                line_start          INT,
                line_end            INT,
                vuln_category       TEXT,
                affected_code       TEXT,
                centrality_score    FLOAT NOT NULL DEFAULT 0.0,
                created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """)

        # vuln_edges — directed exploit-chain edges between nodes
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS vuln_edges (
                id              UUID PRIMARY KEY,
                project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                source_id       UUID NOT NULL REFERENCES vuln_nodes(id) ON DELETE CASCADE,
                target_id       UUID NOT NULL REFERENCES vuln_nodes(id) ON DELETE CASCADE,
                edge_type       TEXT NOT NULL,
                confidence      FLOAT NOT NULL DEFAULT 0.5,
                description     TEXT,
                created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
                UNIQUE(source_id, target_id, edge_type)
            )
        """)

        # remediation_plans — one cached plan per vulnerability node
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS remediation_plans (
                id          UUID PRIMARY KEY,
                node_id     UUID NOT NULL REFERENCES vuln_nodes(id) ON DELETE CASCADE,
                project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                user_id     TEXT NOT NULL,
                plan        TEXT NOT NULL,
                created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
                UNIQUE (node_id)
            )
        """)

        for stmt in [
            "CREATE INDEX IF NOT EXISTS projects_user_id_idx ON projects (user_id)",
            "CREATE INDEX IF NOT EXISTS analyses_user_id_idx ON analyses (user_id)",
            "CREATE INDEX IF NOT EXISTS vuln_nodes_project_idx ON vuln_nodes (project_id)",
            "CREATE INDEX IF NOT EXISTS vuln_edges_project_idx ON vuln_edges (project_id)",
            "CREATE INDEX IF NOT EXISTS remediation_plans_project_idx ON remediation_plans (project_id)",
        ]:
            await conn.execute(stmt)
