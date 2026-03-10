"""
Output module: save per-repo JSON, aggregate CSV, and pretty-print summaries.
"""

import csv
import json
from pathlib import Path
from typing import Any

from loguru import logger


def get_raw_dir(results_root: Path) -> Path:
    """Ensure results/raw exists and return it."""
    raw = results_root / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    return raw


def save_repo_json(result: dict[str, Any], repo_identifier: str, results_root: Path) -> Path:
    """
    Save per-repo result as results/raw/{repo_identifier}.json.
    repo_identifier should be like 'owner_name' (underscore, no slash).
    """
    raw_dir = get_raw_dir(results_root)
    safe_name = repo_identifier.replace("/", "_").replace("\\", "_")
    out_path = raw_dir / f"{safe_name}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    logger.info("Saved {}", out_path)
    return out_path


def print_repo_summary(result: dict[str, Any]) -> None:
    """Pretty-print a one-repo summary to stdout."""
    s = result.get("summary", {})
    print(f"  Findings: {s.get('total_findings', 0)} total | "
          f"vulnerable: {s.get('vulnerable_count', 0)} | "
          f"safe: {s.get('safe_count', 0)} | "
          f"PQC-ready: {s.get('pqc_ready_count', 0)}")
    print(f"  Has vulnerable primitives: {s.get('has_vulnerable_primitives', False)} | "
          f"Vulnerability score: {s.get('vulnerability_score', 0.0):.4f}")


def write_aggregate_csv(results_root: Path, rows: list[dict[str, Any]]) -> Path:
    """
    Write results/aggregate.csv with one row per repo.
    Each row must have: repo_name, language, stars, forks, created_at, size,
    total_findings, vulnerable_count, safe_count, pqc_ready_count, has_vulnerable, vulnerability_score.
    """
    results_root.mkdir(parents=True, exist_ok=True)
    out_path = results_root / "aggregate.csv"
    if not rows:
        # Write header only
        fieldnames = [
            "repo_name", "language", "stars", "forks", "created_at", "size",
            "total_findings", "vulnerable_count", "safe_count", "pqc_ready_count",
            "has_vulnerable", "vulnerability_score",
        ]
        with open(out_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
        return out_path

    fieldnames = list(rows[0].keys())
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    logger.info("Wrote aggregate CSV: {}", out_path)
    return out_path


def build_aggregate_row(
    repo_name: str,
    result: dict[str, Any],
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Build one row for aggregate CSV from a scan result and optional repo metadata.
    metadata can contain: language, stars, forks, created_at, size, default_branch, topics.
    """
    s = result.get("summary", {})
    row: dict[str, Any] = {
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
    if metadata:
        row["language"] = metadata.get("language", "")
        row["stars"] = metadata.get("stars", "")
        row["forks"] = metadata.get("forks", "")
        row["created_at"] = metadata.get("created_at", "")
        row["size"] = metadata.get("size", "")
    return row
