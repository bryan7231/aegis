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
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS projects_user_id_idx ON projects (user_id)
        """)
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS analyses_user_id_idx ON analyses (user_id)
        """)
