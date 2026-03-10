"""
GitHub repository collector: search, clone (or fetch via API), scan, with rate limiting and resume.
"""

import json
import os
import sqlite3
import subprocess
import time
from pathlib import Path
from typing import Any

import httpx
from loguru import logger

from scanner.output import build_aggregate_row, save_repo_json, write_aggregate_csv
from scanner.repo_scanner import scan_repository

# Default: scanner/state.db relative to this file
DEFAULT_STATE_DB = Path(__file__).resolve().parent / "state.db"
GITHUB_API = "https://api.github.com"


def _get_headers() -> dict[str, str]:
    token = os.getenv("GITHUB_TOKEN", "")
    if token:
        return {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"}
    return {"Accept": "application/vnd.github.v3+json"}


def _rate_limit_backoff(response: httpx.Response, attempt: int) -> None:
    """Exponential backoff on 403/429 or when X-RateLimit-Remaining is 0."""
    if response.status_code in (403, 429) or response.headers.get("X-RateLimit-Remaining") == "0":
        wait = (2 ** attempt) + 1
        logger.warning("Rate limit; waiting {}s", wait)
        time.sleep(wait)


def init_state_db(db_path: Path) -> None:
    """Create state DB and tables if not exist."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scanned_repos (
                repo_id TEXT PRIMARY KEY,
                scanned_at TEXT,
                metadata TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS aggregate_rows (
                repo_name TEXT PRIMARY KEY,
                row_json TEXT
            )
        """)


def is_already_scanned(repo_id: str, db_path: Path) -> bool:
    with sqlite3.connect(db_path) as conn:
        cur = conn.execute("SELECT 1 FROM scanned_repos WHERE repo_id = ?", (repo_id,))
        return cur.fetchone() is not None


def mark_scanned(repo_id: str, metadata: dict[str, Any], db_path: Path) -> None:
    from datetime import datetime, timezone
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO scanned_repos (repo_id, scanned_at, metadata) VALUES (?, ?, ?)",
            (repo_id, datetime.now(timezone.utc).isoformat(), __import__("json").dumps(metadata)),
        )


def search_repos(
    language: str,
    min_stars: int = 10,
    limit: int = 100,
    created_after: str | None = None,
    created_before: str | None = None,
) -> list[dict[str, Any]]:
    """
    Use GitHub Search API: search repositories by language and stars.
    Returns list of repo items (full_name, stargazers_count, etc.).
    """
    query_parts = [f"language:{language}", f"stars:>={min_stars}"]
    if created_after:
        query_parts.append(f"created:>={created_after}")
    if created_before:
        query_parts.append(f"created:<={created_before}")
    query = " ".join(query_parts)
    repos: list[dict[str, Any]] = []
    page = 1
    per_page = min(100, limit)
    max_pages = (limit + per_page - 1) // per_page

    with httpx.Client(timeout=30.0, headers=_get_headers()) as client:
        while len(repos) < limit:
            url = f"{GITHUB_API}/search/repositories"
            params = {"q": query, "sort": "stars", "order": "desc", "per_page": per_page, "page": page}
            for attempt in range(5):
                resp = client.get(url, params=params)
                _rate_limit_backoff(resp, attempt)
                if resp.status_code == 200:
                    break
                if resp.status_code in (403, 422):
                    logger.error("GitHub API error: {} {}", resp.status_code, resp.text[:200])
                    return repos
                time.sleep(2 ** attempt)
            else:
                return repos

            data = resp.json()
            items = data.get("items", [])
            if not items:
                break
            for item in items:
                repos.append({
                    "full_name": item["full_name"],
                    "name": item["name"],
                    "owner": item["owner"]["login"],
                    "language": item.get("language") or "",
                    "stargazers_count": item.get("stargazers_count", 0),
                    "forks_count": item.get("forks_count", 0),
                    "created_at": item.get("created_at", ""),
                    "size": item.get("size", 0),
                    "default_branch": item.get("default_branch", "main"),
                    "topics": item.get("topics", []),
                    "clone_url": item.get("clone_url", ""),
                })
                if len(repos) >= limit:
                    break
            page += 1
            if page > max_pages:
                break
            time.sleep(0.5)  # Be nice to API

    return repos


def clone_repo(clone_url: str, target_dir: Path, depth: int = 1) -> bool:
    """Shallow clone into target_dir. Returns True on success."""
    target_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["git", "clone", "--depth", str(depth), clone_url, str(target_dir)]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.warning("Clone failed: {}", e)
        return False


def clone_and_scan_repo(
    owner_repo: str,
    exclude_tests: bool = True,
    clone_root: Path | None = None,
) -> tuple[dict[str, Any] | None, Path | None]:
    """
    Clone owner/repo (shallow), scan it, return (result, repo_path).
    If clone_root is None, uses env PQC_CLONE_DIR or a temp dir (caller must clean up).
    """
    import tempfile
    clone_root = clone_root or Path(os.getenv("PQC_CLONE_DIR", tempfile.gettempdir()))
    # Fetch clone URL if not provided
    if "/" not in owner_repo:
        return None, None
    owner, name = owner_repo.split("/", 1)
    clone_url = f"https://github.com/{owner}/{name}.git"
    target = clone_root / f"pqc_scan_{owner}_{name}".replace(" ", "_")
    if target.exists():
        import shutil
        shutil.rmtree(target, ignore_errors=True)
    if not clone_repo(clone_url, target):
        return None, None
    result = scan_repository(target, exclude_tests=exclude_tests)
    return result, target


def collect_and_scan_repos(
    language: str,
    min_stars: int = 10,
    limit: int = 100,
    created_after: str | None = None,
    created_before: str | None = None,
    exclude_tests: bool = True,
    results_dir: Path | None = None,
    state_db_path: Path | None = None,
    clone_root: Path | None = None,
) -> None:
    """
    Search GitHub for repos, skip already-scanned (state DB), clone, scan, save JSON and update aggregate CSV.
    """
    results_dir = results_dir or Path("results")
    state_db_path = state_db_path or DEFAULT_STATE_DB
    clone_root = clone_root or Path(os.getenv("PQC_CLONE_DIR", os.path.join(os.getenv("TEMP", "/tmp"), "pqc_clones")))
    clone_root = Path(clone_root)
    clone_root.mkdir(parents=True, exist_ok=True)
    init_state_db(state_db_path)

    repos = search_repos(language=language, min_stars=min_stars, limit=limit * 2, created_after=created_after, created_before=created_before)
    to_scan = []
    for r in repos:
        rid = r["full_name"].replace("/", "_")
        if not is_already_scanned(rid, state_db_path) and len(to_scan) < limit:
            to_scan.append(r)

    aggregate_rows: list[dict[str, Any]] = []
    for i, repo in enumerate(to_scan):
        full_name = repo["full_name"]
        repo_id = full_name.replace("/", "_")
        logger.info("[{}/{}] {}", i + 1, len(to_scan), full_name)
        target = clone_root / f"pqc_scan_{repo_id}"
        if target.exists():
            import shutil
            shutil.rmtree(target, ignore_errors=True)
        if not clone_repo(repo.get("clone_url", f"https://github.com/{full_name}.git"), target):
            continue
        try:
            result = scan_repository(target, exclude_tests=exclude_tests)
        except Exception as e:
            logger.warning("Could not scan repository {}: {}", full_name, e)
            continue
        metadata = {
            "language": repo.get("language", ""),
            "stars": repo.get("stargazers_count", 0),
            "forks": repo.get("forks_count", 0),
            "created_at": repo.get("created_at", ""),
            "size": repo.get("size", 0),
            "default_branch": repo.get("default_branch", ""),
            "topics": repo.get("topics", []),
        }
        save_repo_json(result, repo_id, results_dir)
        print_repo_summary = __import__("scanner.output", fromlist=["print_repo_summary"]).print_repo_summary
        print_repo_summary(result)
        mark_scanned(repo_id, metadata, state_db_path)
        aggregate_rows.append(build_aggregate_row(full_name, result, metadata))

    # Rebuild full aggregate from all raw JSONs so CSV includes every scanned repo
    raw_dir = results_dir / "raw"
    if raw_dir.is_dir():
        by_name: dict[str, dict[str, Any]] = {}
        for jpath in raw_dir.glob("*.json"):
            try:
                data = json.loads(jpath.read_text(encoding="utf-8"))
            except Exception:
                continue
            repo_name = jpath.stem.replace("_", "/", 1) if "_" in jpath.stem else jpath.stem
            s = data.get("summary", {})
            by_name[repo_name] = {
                "repo_name": repo_name,
                "language": "",
                "stars": "",
                "forks": "",
                "created_at": "",
                "size": "",
                "total_findings": s.get("total_findings", 0),
                "vulnerable_count": s.get("vulnerable_count", 0),
                "safe_count": s.get("safe_count", 0),
                "pqc_ready_count": s.get("pqc_ready_count", 0),
                "has_vulnerable": s.get("has_vulnerable_primitives", False),
                "vulnerability_score": s.get("vulnerability_score", 0.0),
            }
        for row in aggregate_rows:
            by_name[row["repo_name"]] = row
        aggregate_rows = list(by_name.values())

    write_aggregate_csv(results_dir, aggregate_rows)
