"""Fetch dependency manifests and source files from a *public* GitHub repository.

Only public repos are supported. If the GitHub API reports a repo as private or
non-existent we raise ``GitHubError`` so the API layer can return a clear 4xx.

An optional ``GITHUB_TOKEN`` (read-only / public access) only raises the
unauthenticated rate limit; it is never required for public repos.
"""
import os
import re

import httpx

GITHUB_API = "https://api.github.com"
RAW_BASE = "https://raw.githubusercontent.com"

SOURCE_EXTENSIONS = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".java", ".php", ".cs", ".rs"}
SKIP_DIRS = {"node_modules", ".git", "dist", "build", "__pycache__", "vendor", ".venv", "venv", ".next", "out", "coverage", "target"}
PRIORITY_KEYWORDS = {"auth", "login", "session", "token", "password", "secret", "route", "api", "middleware", "db", "database", "model", "schema", "query", "config", "setting", "user", "admin"}
MAX_SOURCE_BYTES = 100_000  # 100 KB total

# Proper lock files — these are always fetched if found.
LOCKFILE_NAMES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "pipfile.lock",
    "poetry.lock",
    "go.sum",
    "cargo.lock",
    "gemfile.lock",
}

# Manifest fallbacks — used only when no proper lockfile for that ecosystem exists.
MANIFEST_NAMES = {
    "package.json",   # npm — has declared (possibly ranged) versions
}

# Ecosystems covered by a proper lockfile.
NPM_LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}

_REPO_URL_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/([^/\s]+)/([^/\s#?]+)",
    re.IGNORECASE,
)


class GitHubError(Exception):
    """Repo can't be used: invalid URL, not found, or not public."""


def parse_repo_url(url: str) -> tuple[str, str]:
    """Extract (owner, repo) from a GitHub URL. Raises GitHubError if not one."""
    match = _REPO_URL_RE.match((url or "").strip())
    if not match:
        raise GitHubError(
            f"{url!r} is not a valid GitHub repository URL "
            "(expected https://github.com/<owner>/<repo>)."
        )
    owner, repo = match.group(1), match.group(2)
    if repo.endswith(".git"):
        repo = repo[:-4]
    return owner, repo


def _headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def _validate_and_get_branch(client: httpx.AsyncClient, owner: str, repo: str) -> str:
    """Confirm repo is public and return its default branch. Raises GitHubError otherwise."""
    meta = await client.get(f"{GITHUB_API}/repos/{owner}/{repo}", timeout=30.0)
    if meta.status_code == 404:
        raise GitHubError(
            f"Repository '{owner}/{repo}' is private or does not exist. "
            "Only public GitHub repositories can be analyzed."
        )
    if meta.status_code == 403:
        raise GitHubError(
            "GitHub API rate limit reached. Set GITHUB_TOKEN in backend/.env and try again."
        )
    meta.raise_for_status()
    data = meta.json()
    if data.get("private", False):
        raise GitHubError(
            f"Repository '{owner}/{repo}' is private. "
            "Only public GitHub repositories can be analyzed."
        )
    return data.get("default_branch") or "main"


async def fetch_lockfiles(repo_url: str) -> list[dict]:
    """Validate a repo is public and return its dependency manifests.

    Returns ``{"filename", "content"}`` dicts for every recognised lockfile
    plus any manifest fallbacks (e.g. package.json when no npm lockfile exists).
    """
    owner, repo = parse_repo_url(repo_url)

    async with httpx.AsyncClient(headers=_headers()) as client:
        default_branch = await _validate_and_get_branch(client, owner, repo)

        tree = await client.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{default_branch}",
            params={"recursive": "1"},
            timeout=30.0,
        )
        tree.raise_for_status()
        entries = tree.json().get("tree", [])

        # Collect candidates — separate proper lock files from manifest fallbacks.
        lockfile_paths: list[dict] = []
        manifest_paths: list[dict] = []
        found_npm_lockfile = False

        for entry in entries:
            if entry.get("type") != "blob":
                continue
            path: str = entry.get("path", "")
            # Skip files inside ignored directories
            parts = path.split("/")
            if any(p.lower() in SKIP_DIRS for p in parts[:-1]):
                continue
            basename = parts[-1].lower()
            if basename in LOCKFILE_NAMES:
                lockfile_paths.append({"path": path, "basename": basename})
                if basename in NPM_LOCKFILES:
                    found_npm_lockfile = True
            elif basename in MANIFEST_NAMES:
                manifest_paths.append({"path": path, "basename": basename})

        # Include manifests only when the corresponding lockfile is absent.
        extra_paths: list[dict] = []
        for m in manifest_paths:
            if m["basename"] == "package.json" and not found_npm_lockfile:
                extra_paths.append(m)

        all_paths = lockfile_paths + extra_paths

        files: list[dict] = []
        for item in all_paths:
            raw = await client.get(
                f"{RAW_BASE}/{owner}/{repo}/{default_branch}/{item['path']}",
                timeout=30.0,
            )
            if raw.status_code == 200:
                files.append({"filename": item["basename"], "content": raw.text})

        return files


async def fetch_source_files(repo_url: str) -> list[dict]:
    """Fetch high-priority source files for static security analysis.

    Prioritises auth, routing, DB, and config files. Stops at MAX_SOURCE_BYTES
    total. Validates the repo is public before fetching.
    """
    owner, repo = parse_repo_url(repo_url)

    async with httpx.AsyncClient(headers=_headers()) as client:
        default_branch = await _validate_and_get_branch(client, owner, repo)

        tree = await client.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{default_branch}",
            params={"recursive": "1"},
            timeout=30.0,
        )
        tree.raise_for_status()
        entries = tree.json().get("tree", [])

        candidates: list[dict] = []
        for entry in entries:
            if entry.get("type") != "blob":
                continue
            path: str = entry.get("path", "")
            parts = path.split("/")
            if any(p in SKIP_DIRS for p in parts):
                continue
            ext = ("." + path.rsplit(".", 1)[-1].lower()) if "." in path else ""
            if ext not in SOURCE_EXTENSIONS:
                continue
            size: int = entry.get("size", 0)
            if size > 40_000:
                continue
            name_lower = path.lower()
            priority = sum(1 for kw in PRIORITY_KEYWORDS if kw in name_lower)
            depth_penalty = len(parts) - 1
            candidates.append({"path": path, "size": size, "score": priority * 10 - depth_penalty})

        candidates.sort(key=lambda x: (-x["score"], x["size"]))

        files: list[dict] = []
        total_bytes = 0
        for c in candidates:
            if total_bytes >= MAX_SOURCE_BYTES:
                break
            raw = await client.get(
                f"{RAW_BASE}/{owner}/{repo}/{default_branch}/{c['path']}",
                timeout=30.0,
            )
            if raw.status_code == 200:
                content = raw.text
                total_bytes += len(content.encode())
                files.append({"path": c["path"], "content": content})

        return files
