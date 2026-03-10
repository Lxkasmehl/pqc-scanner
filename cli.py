"""
CLI for PQC-Readiness Scanner.
"""

import json
import os
import sys
from pathlib import Path

import typer
from dotenv import load_dotenv
from loguru import logger

# Load .env before other imports that might use config
load_dotenv()

# Add project root to path
_project_root = Path(__file__).resolve().parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from scanner.output import (
    build_aggregate_row,
    get_raw_dir,
    print_repo_summary,
    save_repo_json,
    write_aggregate_csv,
)
from scanner.repo_scanner import scan_repository

app = typer.Typer(help="PQC-Readiness Scanner: detect crypto primitives in source code")

RESULTS_DIR = Path(os.getenv("PQC_RESULTS_DIR", "results"))


def _setup_logging(verbose: bool = False) -> None:
    level = "DEBUG" if verbose else "INFO"
    logger.remove()
    logger.add(sys.stderr, level=level)


@app.command()
def scan(
    source: str = typer.Argument(..., help="'local' <path> or 'github' <owner/repo>"),
    path_or_repo: str = typer.Argument(..., help="Local path or owner/repo"),
    exclude_tests: bool = typer.Option(True, "--exclude-tests/--no-exclude-tests", help="Exclude test dirs from vulnerability summary"),
    verbose: bool = typer.Option(False, "-v", "--verbose"),
) -> None:
    """
    Scan a local directory or a single GitHub repo.
    Usage: scan local <path>   OR   scan github <owner/repo>
    """
    _setup_logging(verbose)
    if source.lower() == "local":
        repo_path = Path(path_or_repo).resolve()
        if not repo_path.is_dir():
            logger.error("Not a directory: {}", repo_path)
            raise typer.Exit(1)
        result = scan_repository(repo_path, exclude_tests=exclude_tests)
        print_repo_summary(result)
        print(json.dumps(result, indent=2))
        return

    if source.lower() == "github":
        _scan_github_repo(path_or_repo, exclude_tests=exclude_tests, verbose=verbose)
        return

    logger.error("First argument must be 'local' or 'github'")
    raise typer.Exit(1)


def _scan_github_repo(owner_repo: str, exclude_tests: bool, verbose: bool) -> None:
    """Clone (shallow) and scan a single GitHub repo."""
    from scanner.github_collector import clone_and_scan_repo
    repo_id = owner_repo.replace("/", "_")
    result, repo_path = clone_and_scan_repo(owner_repo, exclude_tests=exclude_tests)
    if result is None:
        logger.error("Failed to scan {}", owner_repo)
        raise typer.Exit(1)
    print_repo_summary(result)
    save_repo_json(result, repo_id, RESULTS_DIR)
    print(f"Repo path: {repo_path}")
    print(json.dumps(result, indent=2))


@app.command("collect")
def collect(
    language: str = typer.Option("python", "--language", "-l", help="Filter by language"),
    min_stars: int = typer.Option(10, "--min-stars"),
    limit: int = typer.Option(100, "--limit", help="Max repos to collect and scan"),
    created_after: str = typer.Option(None, "--created-after", help="ISO date YYYY-MM-DD"),
    created_before: str = typer.Option(None, "--created-before", help="ISO date YYYY-MM-DD"),
    exclude_tests: bool = typer.Option(True, "--exclude-tests/--no-exclude-tests"),
    verbose: bool = typer.Option(False, "-v", "--verbose"),
) -> None:
    """
    Collect and scan N repos from GitHub (search API), then update aggregate CSV.
    """
    _setup_logging(verbose)
    from scanner.github_collector import collect_and_scan_repos
    collect_and_scan_repos(
        language=language,
        min_stars=min_stars,
        limit=limit,
        created_after=created_after,
        created_before=created_before,
        exclude_tests=exclude_tests,
        results_dir=RESULTS_DIR,
    )


@app.command()
def report(
    results_dir: str = typer.Option(None, "--results-dir", help="Path to results/ (default: env PQC_RESULTS_DIR or 'results')"),
) -> None:
    """
    Generate summary statistics from all results in results/.
    """
    base = Path(results_dir or os.getenv("PQC_RESULTS_DIR", "results"))
    raw_dir = base / "raw"
    if not raw_dir.is_dir():
        logger.warning("No results/raw directory at {}", raw_dir)
        raise typer.Exit(0)

    total_repos = 0
    total_findings = 0
    total_vulnerable = 0
    repos_with_vulnerable = 0

    for p in raw_dir.glob("*.json"):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning("Skip {}: {}", p, e)
            continue
        total_repos += 1
        s = data.get("summary", {})
        total_findings += s.get("total_findings", 0)
        total_vulnerable += s.get("vulnerable_count", 0)
        if s.get("has_vulnerable_primitives"):
            repos_with_vulnerable += 1

    print("=== PQC-Readiness Scanner Report ===")
    print(f"Repos scanned: {total_repos}")
    print(f"Total findings: {total_findings}")
    print(f"Total vulnerable primitives: {total_vulnerable}")
    print(f"Repos with ≥1 vulnerable primitive: {repos_with_vulnerable}")
    if total_repos:
        print(f"Share of repos with vulnerable: {100 * repos_with_vulnerable / total_repos:.1f}%")
    agg = base / "aggregate.csv"
    if agg.exists():
        print(f"Aggregate CSV: {agg}")


if __name__ == "__main__":
    app()
