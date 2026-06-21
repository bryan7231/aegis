"""Fetch dependency lockfiles from a *public* GitHub repository.

The vulnerabilities pipeline takes a GitHub repo link as input. Only public
repos are supported: if the GitHub API reports the repo as private — or it does
not exist / is otherwise inaccessible — we raise ``GitHubError`` so the API layer
can return a clear 4xx instead of silently analyzing nothing.

An optional ``GITHUB_TOKEN`` (read-only / public access is enough) only raises the
unauthenticated rate limit; it is never required for public repos.
"""
import os
import re
from typing import Optional

import httpx

GITHUB_API = "https://api.github.com"
RAW_BASE = "https://raw.githubusercontent.com"

# Lockfile basenames we know how to map to an OSV ecosystem (see osv.py).
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

# Matches github.com/<owner>/<repo>[...] with or without scheme / trailing path.
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


async def fetch_lockfiles(repo_url: str) -> list[dict]:
    """Validate a repo is public and return its lockfiles.

    Returns a list of ``{"filename", "content"}`` dicts (basename + raw text)
    for every recognized lockfile found anywhere in the default branch.

    Raises ``GitHubError`` if the URL is malformed, the repo does not exist, or
    the repo is private — i.e. anything that is not a usable public repository.
    """
    owner, repo = parse_repo_url(repo_url)

    async with httpx.AsyncClient(headers=_headers()) as client:
        meta = await client.get(f"{GITHUB_API}/repos/{owner}/{repo}", timeout=30.0)

        # Unauthenticated requests to a private (or non-existent) repo get a 404
        # — GitHub deliberately hides whether a private repo exists.
        if meta.status_code == 404:
            raise GitHubError(
                f"Repository '{owner}/{repo}' is private or does not exist. "
                "Only public GitHub repositories can be analyzed."
            )
        if meta.status_code == 403:
            raise GitHubError(
                "GitHub API rate limit reached. Set GITHUB_TOKEN in backend/.env "
                "and try again."
            )
        meta.raise_for_status()

        data = meta.json()
        # Belt-and-suspenders: if a token granted access, still reject private.
        if data.get("private", False):
            raise GitHubError(
                f"Repository '{owner}/{repo}' is private. "
                "Only public GitHub repositories can be analyzed."
            )

        default_branch = data.get("default_branch") or "main"

        tree = await client.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{default_branch}",
            params={"recursive": "1"},
            timeout=30.0,
        )
        tree.raise_for_status()
        entries = tree.json().get("tree", [])

        files: list[dict] = []
        for entry in entries:
            if entry.get("type") != "blob":
                continue
            path = entry.get("path", "")
            basename = path.rsplit("/", 1)[-1].lower()
            if basename not in LOCKFILE_NAMES:
                continue
            raw = await client.get(
                f"{RAW_BASE}/{owner}/{repo}/{default_branch}/{path}", timeout=30.0
            )
            if raw.status_code == 200:
                files.append({"filename": basename, "content": raw.text})

        return files
