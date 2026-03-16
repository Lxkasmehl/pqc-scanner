"""
GitHub repository collector: search, clone (or fetch via API), scan, with rate limiting and resume.
"""

import json
import os
import shutil
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
    # Support both GITHUB_TOKEN and GH_PAT (repo secret name) so .env can use either
    token = (os.getenv("GITHUB_TOKEN") or os.getenv("GH_PAT") or "").strip()
    if token:
        return {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"}
    return {"Accept": "application/vnd.github.v3+json"}


# Search API: ~30 req/min; secondary limits trigger easily. Min delay between search requests (seconds).
GITHUB_SEARCH_DELAY = float(os.getenv("GITHUB_SEARCH_DELAY", "2.5"))

# Extra delay (seconds) after each year-stratum to avoid secondary rate limit (403) on the next query.
# GitHub returns max 1000 results per query; after a full 1000 we add COOLDOWN_AFTER_FULL_STRATUM as well.
GITHUB_STRATUM_DELAY = float(os.getenv("GITHUB_STRATUM_DELAY", "15"))
COOLDOWN_AFTER_FULL_STRATUM = float(os.getenv("GITHUB_COOLDOWN_AFTER_FULL_STRATUM", "30"))

# When rate-limited, max time to keep retrying one request before giving up (seconds). Keeps total run under 6h.
RATE_LIMIT_MAX_WAIT_PER_REQUEST = int(os.getenv("GITHUB_RATE_LIMIT_MAX_WAIT", "900"))  # 15 min default


def _rate_limit_backoff(response: httpx.Response, attempt: int) -> int | None:
    """
    On 403/429 or X-RateLimit-Remaining=0: wait and return seconds waited (for optional retry).
    For 403 "secondary rate limit", respects Retry-After or waits 60–90s.
    Returns None if no rate limit hit.
    """
    if response.status_code not in (403, 429) and response.headers.get("X-RateLimit-Remaining") != "0":
        return None
    # Secondary rate limit often doesn't send Retry-After; need long backoff
    retry_after = response.headers.get("Retry-After")
    if retry_after and retry_after.isdigit():
        wait = min(int(retry_after), 300)
    else:
        wait = min(60 + (20 * attempt), 300)  # 60, 80, 100, 120, 140 s
    logger.warning("Rate limit ({}); waiting {}s before retry", response.status_code, wait)
    time.sleep(wait)
    return wait


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


def get_scanned_repos_metadata(db_path: Path) -> dict[str, dict[str, Any]]:
    """Load repo_id -> metadata for all scanned repos from state DB (for enriching CSV after rebuild)."""
    db_path = Path(db_path)
    if not db_path.is_file():
        return {}
    out: dict[str, dict[str, Any]] = {}
    with sqlite3.connect(db_path) as conn:
        for (repo_id, metadata_json) in conn.execute("SELECT repo_id, metadata FROM scanned_repos"):
            try:
                out[repo_id] = json.loads(metadata_json) if metadata_json else {}
            except Exception:
                continue
    return out


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
    star_max: int | None = None,
) -> list[dict[str, Any]]:
    """
    Use GitHub Search API: search repositories by language and stars.
    Returns list of repo items (full_name, stargazers_count, etc.).
    If star_max is set, uses stars:min_stars..star_max; otherwise stars:>=min_stars.
    """
    if star_max is not None:
        stars_qualifier = f"stars:{min_stars}..{star_max}"
    else:
        stars_qualifier = f"stars:>={min_stars}"
    query_parts = [f"language:{language}", stars_qualifier]
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
            resp = None
            attempt = 0
            waited_this_page = 0
            while True:
                resp = client.get(url, params=params)
                if resp.status_code == 200:
                    break
                if resp.status_code == 422:
                    logger.error("GitHub API error: {} {}", resp.status_code, resp.text[:200])
                    return repos
                if resp.status_code in (403, 429):
                    if waited_this_page >= RATE_LIMIT_MAX_WAIT_PER_REQUEST:
                        logger.error("Rate limit: gave up after {}s wait for this request", waited_this_page)
                        return repos
                    w = _rate_limit_backoff(resp, attempt)
                    if w is not None:
                        waited_this_page += w
                    attempt += 1
                    continue
                # Other errors: short backoff and retry
                time.sleep(min(2 ** attempt, 60))
                attempt += 1
                if attempt >= 8:
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
            time.sleep(GITHUB_SEARCH_DELAY)  # Search API: stay under ~30/min and avoid secondary limits

    return repos


# Star-range strata: each stratum is a separate API query (max 1000 per query), so we can get 5k+ per language.
# Order: high stars first, then lower. (low, None) = stars >= low.
_STAR_STRATA: list[tuple[int, int | None]] = [
    (10000, None),
    (5000, 9999),
    (1000, 4999),
    (500, 999),
    (100, 499),
    (10, 99),
]


def _collect_repos_for_language(
    language: str,
    min_stars: int,
    max_repos: int,
    created_year_start: int,
    created_year_end: int,
) -> list[dict[str, Any]]:
    """
    Run stratified search by star range for one language until we have max_repos or no more results.
    Each star stratum is a separate query (GitHub caps at 1000 per query), so we get up to 1000 per stratum.
    Uses stratum delay and cooldown after full 1000-result queries to avoid GitHub secondary rate limit (403).
    """
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for low, high in _STAR_STRATA:
        if len(result) >= max_repos:
            break
        if high is not None and high < min_stars:
            continue
        stratum_low = max(min_stars, low)
        stratum_high = high  # None => no upper bound
        limit = min(1000, max_repos - len(result))
        repos = search_repos(
            language=language,
            min_stars=stratum_low,
            limit=limit,
            created_after=None,
            created_before=None,
            star_max=stratum_high,
        )
        for r in repos:
            fn = r.get("full_name", "")
            if fn and fn not in seen:
                seen.add(fn)
                result.append(r)
                if len(result) >= max_repos:
                    break
        time.sleep(GITHUB_SEARCH_DELAY)
        time.sleep(GITHUB_STRATUM_DELAY)
        if len(repos) >= 1000:
            logger.debug("Stratum returned 1000 (API cap); cooldown {}s before next stratum", COOLDOWN_AFTER_FULL_STRATUM)
            time.sleep(COOLDOWN_AFTER_FULL_STRATUM)
    return result


def export_repos_multi_language(
    output_path: Path,
    languages: list[str] | None = None,
    total: int = 15000,
    min_stars: int = 10,
    created_year_start: int = 2015,
    created_year_end: int | None = None,
) -> int:
    """
    Build a single JSONL repo list with balanced proportions across languages (default: Python, Java, Go).
    Uses stratified search per language, then writes round-robin so the file has similar shares per language.
    Deduplicates by full_name (a repo may appear in multiple language searches).
    Returns total number of repos written.
    """
    import datetime
    if languages is None:
        languages = ["Python", "Java", "Go"]
    end = created_year_end or datetime.date.today().year
    per_lang = max(1, total // len(languages))
    logger.info("Target: {} repos total (up to {} per language: {})", total, per_lang, ", ".join(languages))

    lists: list[list[dict[str, Any]]] = []
    for lang in languages:
        logger.info("Collecting up to {} repos for language '{}'...", per_lang, lang)
        repos = _collect_repos_for_language(
            language=lang,
            min_stars=min_stars,
            max_repos=per_lang,
            created_year_start=created_year_start,
            created_year_end=end,
        )
        lists.append(repos)
        logger.info("  Got {} repos for {}", len(repos), lang)

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    written: set[str] = set()
    count = 0
    positions = [0] * len(lists)
    with open(output_path, "w", encoding="utf-8") as out:
        while True:
            any_advanced = False
            for i in range(len(lists)):
                while positions[i] < len(lists[i]):
                    r = lists[i][positions[i]]
                    positions[i] += 1
                    fn = r.get("full_name", "")
                    if fn and fn not in written:
                        written.add(fn)
                        out.write(json.dumps(r, ensure_ascii=False) + "\n")
                        count += 1
                    any_advanced = True
                    break  # one per language per round for balanced mix
            if not any_advanced:
                break
    logger.info("Wrote {} unique repos to {} (balanced: {})", count, output_path, ", ".join(languages))
    if count < total:
        logger.warning(
            "Only {} repos collected (target was {}). We use star-range strata (each query max 1000). "
            "If you hit secondary rate limit (403), stratum delays and GH_PAT help; re-run or increase GITHUB_STRATUM_DELAY.",
            count, total,
        )
    return count


def export_repos_stratified(
    output_path: Path,
    language: str = "python",
    min_stars: int = 10,
    created_year_start: int = 2015,
    created_year_end: int | None = None,
    max_repos_per_query: int = 1000,
) -> int:
    """
    Run multiple GitHub search queries by year (to stay under 1000 results per query),
    deduplicate by full_name, and write one JSON object per line (JSONL).
    Returns total number of repos written.
    """
    import datetime
    end = created_year_end or datetime.date.today().year
    seen: set[str] = set()
    total = 0
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as out:
        for year in range(created_year_start, end + 1):
            after = f"{year}-01-01"
            before = f"{year}-12-31"
            logger.info("Searching created {}..{}", after, before)
            repos = search_repos(
                language=language,
                min_stars=min_stars,
                limit=max_repos_per_query,
                created_after=after,
                created_before=before,
            )
            for r in repos:
                fn = r.get("full_name", "")
                if fn and fn not in seen:
                    seen.add(fn)
                    out.write(json.dumps(r, ensure_ascii=False) + "\n")
                    total += 1
            if len(repos) >= max_repos_per_query:
                logger.warning("Hit {} results for {}; consider splitting by month", len(repos), year)
            time.sleep(GITHUB_SEARCH_DELAY)
    logger.info("Exported {} unique repos to {}", total, output_path)
    return total


def clone_repo(clone_url: str, target_dir: Path, depth: int = 1) -> bool:
    """Shallow clone into target_dir. Returns True on success."""
    target_dir = Path(target_dir).resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["git", "clone", "--depth", str(depth), clone_url, str(target_dir)]
    # On Windows, long paths in repos can cause exit 128; enable long paths for the clone
    if os.name == "nt":
        cmd = ["git", "clone", "-c", "core.longpaths=true", "--depth", str(depth), clone_url, str(target_dir)]
    timeout_sec = int(os.getenv("PQC_CLONE_TIMEOUT", "300"))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
        if r.returncode == 0:
            return True
        err = (r.stderr or r.stdout or "").strip() or f"exit code {r.returncode}"
        logger.warning("Clone failed: {} -> {}", clone_url, err[:500])
        return False
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.warning("Clone failed: {}", e)
        return False


def clone_and_scan_repo(
    owner_repo: str,
    exclude_tests: bool = True,
    clone_root: Path | None = None,
    use_existing_clones: bool = False,
) -> tuple[dict[str, Any] | None, Path | None]:
    """
    Clone owner/repo (shallow), scan it, return (result, repo_path).
    If clone_root is None, uses env PQC_CLONE_DIR or a temp dir (caller must clean up).
    If use_existing_clones is True and target already exists, skip clone and just scan
    (so you can manually clone large repos and re-run evaluation).
    """
    import tempfile
    clone_root = clone_root or Path(os.getenv("PQC_CLONE_DIR", tempfile.gettempdir()))
    if "/" not in owner_repo:
        return None, None
    owner, name = owner_repo.split("/", 1)
    clone_url = f"https://github.com/{owner}/{name}.git"
    target = clone_root / f"pqc_scan_{owner}_{name}".replace(" ", "_")
    if target.exists() and use_existing_clones:
        # Use existing clone (e.g. manually cloned with longer timeout)
        result = scan_repository(target, exclude_tests=exclude_tests)
        return result, target
    if target.exists():
        import shutil
        shutil.rmtree(target, ignore_errors=True)
    if not clone_repo(clone_url, target):
        return None, None
    result = scan_repository(target, exclude_tests=exclude_tests)
    return result, target


def load_repo_list_from_file(repo_list_path: Path) -> list[dict[str, Any]]:
    """
    Load repo list from JSONL or plain text file.
    - JSONL: one JSON object per line with at least "full_name" (owner/repo); may include
      clone_url, language, stargazers_count, forks_count, created_at, size, topics.
    - Plain text: one line per repo, "owner/repo" or "https://github.com/owner/repo".
    """
    repos: list[dict[str, Any]] = []
    text = repo_list_path.read_text(encoding="utf-8", errors="replace")
    for line in text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                full_name = obj.get("full_name") or (f"{obj.get('owner', '')}/{obj.get('name', '')}".strip("/"))
                if not full_name:
                    continue
                if "full_name" not in obj:
                    obj["full_name"] = full_name
                if "clone_url" not in obj:
                    obj["clone_url"] = f"https://github.com/{full_name}.git"
                repos.append(obj)
            except json.JSONDecodeError:
                continue
        else:
            # "owner/repo" or URL
            if "github.com/" in line:
                part = line.split("github.com/")[-1].rstrip("/").replace(".git", "")
            else:
                part = line
            if "/" in part:
                repos.append({"full_name": part, "clone_url": f"https://github.com/{part}.git"})
    return repos


def collect_and_scan_repos(
    language: str = "python",
    min_stars: int = 10,
    limit: int = 100,
    created_after: str | None = None,
    created_before: str | None = None,
    exclude_tests: bool = True,
    results_dir: Path | None = None,
    state_db_path: Path | None = None,
    clone_root: Path | None = None,
    repo_list_path: Path | None = None,
) -> None:
    """
    Collect and scan repos: either from GitHub search (language, min_stars, etc.)
    or from a repo list file (repo_list_path). Skips already-scanned via state DB,
    clones, scans, saves JSON and updates aggregate CSV.
    Use repo_list_path for large runs (10k–50k): generate the list via stratified
    search or BigQuery, then run this (e.g. in Codespaces/cloud) with --from-file.
    """
    results_dir = results_dir or Path("results")
    state_db_path = state_db_path or DEFAULT_STATE_DB
    clone_root = clone_root or Path(os.getenv("PQC_CLONE_DIR", os.path.join(os.getenv("TEMP", "/tmp"), "pqc_clones")))
    clone_root = Path(clone_root)
    clone_root.mkdir(parents=True, exist_ok=True)
    init_state_db(state_db_path)

    if repo_list_path is not None:
        repo_list_path = Path(repo_list_path)
        if not repo_list_path.is_file():
            logger.error("Repo list file not found: {}", repo_list_path)
            return
        repos = load_repo_list_from_file(repo_list_path)
        to_scan = []
        for r in repos:
            full_name = r.get("full_name") or f"{r.get('owner','')}/{r.get('name','')}".strip("/")
            if not full_name:
                continue
            r["full_name"] = full_name
            rid = full_name.replace("/", "_")
            if not is_already_scanned(rid, state_db_path):
                to_scan.append(r)
        if limit > 0 and len(to_scan) > limit:
            to_scan = to_scan[:limit]
        logger.info("Loaded {} repos from file, {} to scan (after skipping already-scanned)", len(repos), len(to_scan))
    else:
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
            shutil.rmtree(target, ignore_errors=True)
        if not clone_repo(repo.get("clone_url", f"https://github.com/{full_name}.git"), target):
            if target.exists():
                shutil.rmtree(target, ignore_errors=True)
            continue
        try:
            result = scan_repository(target, exclude_tests=exclude_tests)
        except Exception as e:
            logger.warning("Could not scan repository {}: {}", full_name, e)
            continue
        finally:
            # Free disk: remove clone after scan so long runs don't fill the runner
            if target.exists():
                shutil.rmtree(target, ignore_errors=True)
        metadata = {
            "language": repo.get("language", ""),
            "stars": repo.get("stargazers_count", repo.get("stars", 0)),
            "forks": repo.get("forks_count", repo.get("forks", 0)),
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
    raw_dir = results_dir.resolve() / "raw"
    if raw_dir.is_dir():
        raw_files = list(raw_dir.glob("*.json"))
        by_name: dict[str, dict[str, Any]] = {}
        for jpath in raw_files:
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
                "topics": "",
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
        logger.info(
            "Rebuild aggregate: {} raw JSONs → {} CSV rows (this run: {})",
            len(raw_files), len(aggregate_rows), len(to_scan),
        )
    else:
        logger.warning("No raw dir at {}; CSV will have only current run ({} rows)", raw_dir, len(aggregate_rows))

    write_aggregate_csv(results_dir, aggregate_rows)
