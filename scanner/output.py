"""
Output module: save per-repo JSON, aggregate CSV, pretty-print summaries, and paper report.
"""

import csv
import json
from collections import Counter
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
            "repo_name", "language", "stars", "forks", "created_at", "size", "topics",
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
    topics are stored as pipe-separated for CSV (domain/correlation analysis).
    """
    s = result.get("summary", {})
    row: dict[str, Any] = {
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
    if metadata:
        row["language"] = metadata.get("language", "")
        row["stars"] = metadata.get("stars", "")
        row["forks"] = metadata.get("forks", "")
        row["created_at"] = metadata.get("created_at", "")
        row["size"] = metadata.get("size", "")
        topics = metadata.get("topics", [])
        row["topics"] = "|".join(topics) if isinstance(topics, list) else str(topics)
    return row


def compute_report(raw_dir: Path, aggregate_path: Path | None = None) -> dict[str, Any]:
    """
    Aggregate all raw JSONs (and optional aggregate CSV for language) into stats for the paper:
    - Overall: repos, PQC vulnerability rate, finding counts
    - By language: repos and % with vulnerable per language
    - Primitive distribution: counts per primitive (vulnerable / safe / PQC-ready)
    - PQC-ready adoption: repos and findings
    - Optional: vulnerable in test vs non-test (production path)
    """
    raw_dir = Path(raw_dir)
    if not raw_dir.is_dir():
        return {}

    # Per-repo language from aggregate CSV (repo_name -> language)
    repo_language: dict[str, str] = {}
    if aggregate_path and aggregate_path.is_file():
        with open(aggregate_path, encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                name = row.get("repo_name", "").strip()
                lang = (row.get("language") or "").strip()
                if name:
                    repo_language[name] = lang or "unknown"

    total_repos = 0
    total_findings = 0
    total_vulnerable = 0
    total_safe = 0
    total_pqc_ready = 0
    repos_with_vulnerable = 0
    repos_with_pqc_ready = 0
    primitive_counts: Counter[str] = Counter()
    primitive_by_class: dict[str, Counter] = {
        "post-quantum-vulnerable": Counter(),
        "quantum-safe": Counter(),
        "pqc-ready": Counter(),
        "unknown": Counter(),
    }
    vulnerable_in_test = 0
    vulnerable_in_production = 0
    by_language: dict[str, dict[str, Any]] = {}

    for jpath in raw_dir.glob("*.json"):
        try:
            data = json.loads(jpath.read_text(encoding="utf-8"))
        except Exception:
            continue
        total_repos += 1
        s = data.get("summary", {})
        total_findings += s.get("total_findings", 0)
        total_vulnerable += s.get("vulnerable_count", 0)
        total_safe += s.get("safe_count", 0)
        total_pqc_ready += s.get("pqc_ready_count", 0)
        if s.get("has_vulnerable_primitives"):
            repos_with_vulnerable += 1
        if s.get("pqc_ready_count", 0) > 0:
            repos_with_pqc_ready += 1

        repo_name = jpath.stem.replace("_", "/", 1) if "_" in jpath.stem else jpath.stem
        lang = repo_language.get(repo_name, "unknown")
        if lang not in by_language:
            by_language[lang] = {"repos": 0, "with_vulnerable": 0, "with_pqc": 0}
        by_language[lang]["repos"] += 1
        if s.get("has_vulnerable_primitives"):
            by_language[lang]["with_vulnerable"] += 1
        if s.get("pqc_ready_count", 0) > 0:
            by_language[lang]["with_pqc"] += 1

        for f in data.get("findings", []):
            prim = (f.get("primitive") or "").strip()
            if not prim:
                continue
            cl = f.get("classification", "unknown")
            primitive_counts[prim] += 1
            if cl in primitive_by_class:
                primitive_by_class[cl][prim] += 1
            if cl == "post-quantum-vulnerable":
                if f.get("is_test_file"):
                    vulnerable_in_test += 1
                else:
                    vulnerable_in_production += 1

    pqc_vulnerability_rate = (100.0 * repos_with_vulnerable / total_repos) if total_repos else 0.0
    pqc_adoption_rate = (100.0 * repos_with_pqc_ready / total_repos) if total_repos else 0.0

    return {
        "total_repos": total_repos,
        "total_findings": total_findings,
        "total_vulnerable": total_vulnerable,
        "total_safe": total_safe,
        "total_pqc_ready": total_pqc_ready,
        "repos_with_vulnerable": repos_with_vulnerable,
        "repos_with_pqc_ready": repos_with_pqc_ready,
        "pqc_vulnerability_rate_pct": round(pqc_vulnerability_rate, 2),
        "pqc_adoption_rate_pct": round(pqc_adoption_rate, 2),
        "by_language": by_language,
        "primitive_counts": dict(primitive_counts.most_common(50)),
        "primitive_by_class": {k: dict(v.most_common(30)) for k, v in primitive_by_class.items()},
        "vulnerable_in_test": vulnerable_in_test,
        "vulnerable_in_production": vulnerable_in_production,
        "aggregate_path": str(aggregate_path) if aggregate_path else None,
    }


def format_report_text(stats: dict[str, Any]) -> str:
    """Human-readable report for console."""
    if not stats:
        return "No data."
    lines = [
        "=== PQC-Readiness Scanner Report ===",
        "",
        "Sample",
        f"  Repositories scanned:     {stats['total_repos']}",
        "",
        "PQC vulnerability (paper metric)",
        f"  Repos with ≥1 vulnerable primitive:  {stats['repos_with_vulnerable']}  ({stats['pqc_vulnerability_rate_pct']}%)",
        f"  Total findings (vulnerable):          {stats['total_vulnerable']}",
        f"  Total findings (quantum-safe):       {stats['total_safe']}",
        f"  Total findings (PQC-ready):          {stats['total_pqc_ready']}",
        "",
        "PQC adoption",
        f"  Repos with ≥1 PQC-ready primitive:   {stats['repos_with_pqc_ready']}  ({stats['pqc_adoption_rate_pct']}%)",
        "",
        "Criticality (vulnerable primitives)",
        f"  In production code:  {stats['vulnerable_in_production']}",
        f"  In test/example code: {stats['vulnerable_in_test']}",
        "",
        "By language",
    ]
    for lang in sorted(stats["by_language"].keys(), key=lambda x: (x == "unknown", x.lower())):
        bl = stats["by_language"][lang]
        n = bl["repos"]
        v = bl["with_vulnerable"]
        pct = (100.0 * v / n) if n else 0
        lines.append(f"  {lang or 'unknown':12}  repos: {n:5}  with vulnerable: {v:4}  ({pct:.1f}%)")
    lines.extend([
        "",
        "Top primitives (vulnerable)",
    ])
    vuln = stats["primitive_by_class"].get("post-quantum-vulnerable", {})
    for prim, count in list(vuln.items())[:15]:
        lines.append(f"  {prim:30}  {count}")
    lines.extend([
        "",
        "Top primitives (PQC-ready)",
    ])
    pqc = stats["primitive_by_class"].get("pqc-ready", {})
    for prim, count in list(pqc.items())[:10]:
        lines.append(f"  {prim:30}  {count}")
    lines.append("")
    return "\n".join(lines)


def format_report_markdown(stats: dict[str, Any]) -> str:
    """Markdown report for paper / methods / appendix."""
    if not stats:
        return ""
    lines = [
        "# PQC-Readiness Scanner – Summary Report",
        "",
        "## Sample",
        f"- **Repositories scanned:** {stats['total_repos']}",
        "",
        "## PQC Vulnerability",
        f"- **Repositories with ≥1 post-quantum-vulnerable primitive:** {stats['repos_with_vulnerable']} ({stats['pqc_vulnerability_rate_pct']}%)",
        f"- Total vulnerable findings: {stats['total_vulnerable']}",
        f"- Total quantum-safe findings: {stats['total_safe']}",
        f"- Total PQC-ready findings: {stats['total_pqc_ready']}",
        "",
        "## PQC Adoption",
        f"- **Repositories with ≥1 PQC-ready primitive:** {stats['repos_with_pqc_ready']} ({stats['pqc_adoption_rate_pct']}%)",
        "",
        "## Criticality",
        f"- Vulnerable primitives in production code: {stats['vulnerable_in_production']}",
        f"- Vulnerable primitives in test/example code: {stats['vulnerable_in_test']}",
        "",
        "## By language",
        "",
        "| Language | Repos | With vulnerable | % | With PQC-ready |",
        "|----------|-------|-----------------|---|----------------|",
    ]
    for lang in sorted(stats["by_language"].keys(), key=lambda x: (x == "unknown", x.lower())):
        bl = stats["by_language"][lang]
        n = bl["repos"]
        v = bl["with_vulnerable"]
        pct = (100.0 * v / n) if n else 0
        pq = bl["with_pqc"]
        lines.append(f"| {lang or 'unknown'} | {n} | {v} | {pct:.1f}% | {pq} |")
    lines.extend([
        "",
        "## Top vulnerable primitives",
        "",
        "| Primitive | Count |",
        "|-----------|-------|",
    ])
    for prim, count in list(stats["primitive_by_class"].get("post-quantum-vulnerable", {}).items())[:20]:
        lines.append(f"| {prim} | {count} |")
    lines.extend([
        "",
        "## Top PQC-ready primitives",
        "",
        "| Primitive | Count |",
        "|-----------|-------|",
    ])
    for prim, count in list(stats["primitive_by_class"].get("pqc-ready", {}).items())[:10]:
        lines.append(f"| {prim} | {count} |")
    lines.append("")
    return "\n".join(lines)
