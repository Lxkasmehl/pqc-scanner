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
    enrich_aggregate_csv_from_state,
    get_raw_dir,
    print_repo_summary,
    rebuild_aggregate_csv_from_raw,
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
    language: str = typer.Option("python", "--language", "-l", help="Filter by language (used only without --from-file)"),
    min_stars: int = typer.Option(10, "--min-stars"),
    limit: int = typer.Option(100, "--limit", help="Max repos to scan (use 0 for no limit when using --from-file)"),
    created_after: str = typer.Option(None, "--created-after", help="ISO date YYYY-MM-DD"),
    created_before: str = typer.Option(None, "--created-before", help="ISO date YYYY-MM-DD"),
    from_file: Path | None = typer.Option(None, "--from-file", "-f", path_type=Path, help="JSONL or text file with repo list (one full_name or owner/repo per line) for large runs"),
    exclude_tests: bool = typer.Option(True, "--exclude-tests/--no-exclude-tests"),
    verbose: bool = typer.Option(False, "-v", "--verbose"),
) -> None:
    """
    Collect and scan repos: from GitHub search (default) or from a repo list file (--from-file).
    For 10k–50k repos, generate a list with 'collect export-repos' or BigQuery, then run
    with --from-file in a Codespace or cloud worker.
    """
    _setup_logging(verbose)
    from scanner.github_collector import collect_and_scan_repos
    collect_and_scan_repos(
        language=language,
        min_stars=min_stars,
        limit=limit,
        created_after=created_after or None,
        created_before=created_before or None,
        exclude_tests=exclude_tests,
        results_dir=RESULTS_DIR,
        repo_list_path=from_file,
    )


@app.command("build-repo-list")
def build_repo_list(
    output: Path = typer.Option(..., "--output", "-o", path_type=Path, help="Output JSONL file for collect --from-file"),
    languages: str = typer.Option("Python,Java,Go", "--languages", "-l", help="Comma-separated languages (balanced proportions)"),
    total: int = typer.Option(15000, "--total", "-n", help="Target total repos (split equally across languages)"),
    min_stars: int = typer.Option(10, "--min-stars"),
    years_start: int = typer.Option(2015, "--years-start"),
    years_end: int | None = typer.Option(None, "--years-end"),
    verbose: bool = typer.Option(False, "-v", "--verbose"),
) -> None:
    """
    Build one repo list with Python, Java, and Go in similar proportions (one command).
    Runs stratified search per language, writes round-robin to JSONL. Then run
    'collect --from-file <output> --limit 0' (e.g. in Codespaces).
    """
    _setup_logging(verbose)
    from scanner.github_collector import export_repos_multi_language
    lang_list = [s.strip() for s in languages.split(",") if s.strip()]
    export_repos_multi_language(
        output_path=output,
        languages=lang_list,
        total=total,
        min_stars=min_stars,
        created_year_start=years_start,
        created_year_end=years_end,
    )


@app.command("export-repos")
def export_repos(
    output: Path = typer.Option(..., "--output", "-o", path_type=Path, help="Output JSONL file (repo list for --from-file)"),
    language: str = typer.Option("python", "--language", "-l"),
    min_stars: int = typer.Option(10, "--min-stars"),
    years_start: int = typer.Option(2015, "--years-start"),
    years_end: int | None = typer.Option(None, "--years-end"),
    verbose: bool = typer.Option(False, "-v", "--verbose"),
) -> None:
    """
    Build a single-language repo list via stratified GitHub search (by year).
    For balanced Python/Java/Go use 'build-repo-list' instead.
    """
    _setup_logging(verbose)
    from scanner.github_collector import export_repos_stratified
    export_repos_stratified(
        output_path=output,
        language=language,
        min_stars=min_stars,
        created_year_start=years_start,
        created_year_end=years_end,
    )


@app.command("rebuild-aggregate")
def rebuild_aggregate(
    results_dir: str = typer.Option(None, "--results-dir", help="Path to results/ (default: env PQC_RESULTS_DIR or 'results')"),
) -> None:
    """
    Rebuild results/aggregate.csv from all results/raw/*.json.
    Use after downloading scanner-results from a resumed run so the CSV has one row per raw file.
    """
    base = Path(results_dir or os.getenv("PQC_RESULTS_DIR", "results"))
    path = rebuild_aggregate_csv_from_raw(base)
    logger.info("Aggregate CSV: {}", path)


@app.command("enrich-aggregate")
def enrich_aggregate(
    results_dir: str = typer.Option(None, "--results-dir", help="Path to results/ (default: env PQC_RESULTS_DIR or 'results')"),
    state_db: str = typer.Option(None, "--state-db", help="Path to scanner/state.db (default: scanner/state.db)"),
) -> None:
    """
    Fill language, stars, forks, created_at, size, topics in aggregate.csv from scanner state DB.
    Use after rebuild-aggregate when the CSV was built only from raw JSONs (no metadata).
    Requires the state.db from the same run (e.g. from the scanner-state artifact).
    """
    base = Path(results_dir or os.getenv("PQC_RESULTS_DIR", "results"))
    db_path = Path(state_db or str(_project_root / "scanner" / "state.db"))
    from scanner.github_collector import get_scanned_repos_metadata
    metadata = get_scanned_repos_metadata(db_path)
    if not metadata:
        logger.warning("No metadata in state DB at {} (or file missing). Copy scanner-state artifact to scanner/state.db.", db_path)
    path = enrich_aggregate_csv_from_state(base, db_path, metadata)
    logger.info("Aggregate CSV: {}", path)


@app.command()
def report(
    results_dir: str = typer.Option(None, "--results-dir", help="Path to results/ (default: env PQC_RESULTS_DIR or 'results')"),
    output: Path | None = typer.Option(None, "--output", "-o", path_type=Path, help="Write report to file (Markdown for paper/methods)"),
) -> None:
    """
    Generate summary statistics for the paper: PQC vulnerability rate, by language,
    primitive distribution, PQC adoption, and criticality (production vs test code).
    Use --output report.md to export a Markdown report for the paper.
    """
    base = Path(results_dir or os.getenv("PQC_RESULTS_DIR", "results"))
    raw_dir = base / "raw"
    if not raw_dir.is_dir():
        logger.warning("No results/raw directory at {}", raw_dir)
        raise typer.Exit(0)

    from scanner.output import compute_report, format_report_text, format_report_markdown
    aggregate_path = base / "aggregate.csv"
    stats = compute_report(raw_dir, aggregate_path if aggregate_path.exists() else None)
    if not stats:
        raise typer.Exit(0)

    text = format_report_text(stats)
    print(text)
    if aggregate_path.exists():
        print(f"Aggregate CSV: {aggregate_path}")

    if output:
        output = Path(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        md = format_report_markdown(stats)
        output.write_text(md, encoding="utf-8")
        logger.info("Wrote report to {}", output)


if __name__ == "__main__":
    app()
