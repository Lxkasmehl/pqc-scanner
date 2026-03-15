#!/usr/bin/env python3
"""
Run scanner evaluation against a ground-truth CSV (repo-level).

Usage:
  From project root:
    python evaluation/run_evaluation.py --ground-truth evaluation/ground_truth.csv [--clone-dir /path] [--no-clone]

  Ground-truth CSV columns:
    repo_id         : owner/name for GitHub, or an id for local_path
    has_vulnerable  : 1 or 0 (expected)
    has_pqc_ready   : 1 or 0 (expected)
    local_path      : (optional) path to local repo dir; if set, we scan this instead of cloning repo_id
    notes           : (optional)

  If --no-clone is set, only rows with a non-empty local_path are run (no GitHub clone).
"""

from __future__ import annotations

import csv
import os
import subprocess
import sys
from pathlib import Path

# Project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner.github_collector import clone_and_scan_repo
from scanner.repo_scanner import scan_repository


def _default_branch(repo_path: Path) -> str:
    """Return default branch (e.g. main) for a git repo, else 'main'."""
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except Exception:
        pass
    return "main"


def _github_file_url(repo_id: str, rel_path: str, line: int, branch: str = "main") -> str:
    """Build GitHub link to file at line. rel_path is repo-relative (forward slashes ok)."""
    return f"https://github.com/{repo_id}/blob/{branch}/{rel_path}#L{line}"


def _write_verification_report(
    entries: list[tuple[str, Path, dict]],
    out_path: Path,
) -> None:
    """
    Write a Markdown report with direct GitHub links to each finding so you can
    verify without searching the repo. One section per repo; links go to file:line.
    """
    lines = [
        "# Verification report – where to look",
        "",
        "Use this file to **verify the scanner results on GitHub**. Each link opens the exact "
        "file and line the scanner flagged. You only need to check those locations (and the "
        "surrounding context) to decide: is this really vulnerable / PQC-ready / safe?",
        "",
        "After verifying, correct `ground_truth.csv` where the scanner was wrong, then run "
        "the evaluation again.",
        "",
        "---",
        "",
    ]
    for repo_id, repo_path, result in entries:
        branch = _default_branch(repo_path)
        findings = result.get("findings", [])
        summary = result.get("summary", {})
        n_v = summary.get("vulnerable_count", 0)
        n_pqc = summary.get("pqc_ready_count", 0)
        n_safe = summary.get("safe_count", 0)
        lines.append(f"## {repo_id}")
        lines.append("")
        lines.append(f"**Scanner summary:** vulnerable={n_v}, PQC-ready={n_pqc}, quantum-safe={n_safe}")
        lines.append("")
        if not findings:
            lines.append("*No findings – scanner saw no crypto primitives here. Check if the repo really has none.*")
            lines.append("")
            continue
        is_github_repo = "/" in repo_id and repo_id.count("/") == 1 and "\\" not in repo_id
        lines.append("| Type | Primitive | File:line | Link |")
        lines.append("|------|-----------|-----------|------|")
        for f in findings:
            cl = f.get("classification", "?")
            prim = (f.get("primitive") or "?").replace("|", " ")
            file_str = f.get("file", "")
            line_no = f.get("line", 0)
            try:
                rel = Path(file_str).relative_to(repo_path)
                rel_str = rel.as_posix()
            except (ValueError, TypeError):
                rel_str = file_str
            if is_github_repo:
                url = _github_file_url(repo_id, rel_str, line_no, branch)
                lines.append(f"| {cl} | {prim} | `{rel_str}:{line_no}` | [open on GitHub]({url}) |")
            else:
                lines.append(f"| {cl} | {prim} | `{rel_str}:{line_no}` | (local repo) |")
        lines.append("")
    out_path.write_text("\n".join(lines), encoding="utf-8")


def load_ground_truth(csv_path: Path) -> list[dict]:
    rows = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            repo_id = (row.get("repo_id") or "").strip()
            if not repo_id or repo_id.startswith("#"):
                continue
            try:
                has_vuln = int(row.get("has_vulnerable", 0))
            except ValueError:
                has_vuln = 0
            try:
                has_pqc = int(row.get("has_pqc_ready", 0))
            except ValueError:
                has_pqc = 0
            local_path = (row.get("local_path") or "").strip()
            rows.append({
                "repo_id": repo_id,
                "has_vulnerable": bool(has_vuln),
                "has_pqc_ready": bool(has_pqc),
                "local_path": local_path or None,
                "notes": (row.get("notes") or "").strip(),
            })
    return rows


def run_evaluation(
    ground_truth_path: Path,
    clone_dir: Path | None = None,
    exclude_tests: bool = True,
    no_clone: bool = False,
    verbose: bool = False,
    write_verification_report: bool = False,
    verification_report_path: Path | None = None,
) -> dict:
    gt = load_ground_truth(ground_truth_path)
    if not gt:
        return {"error": "No rows in ground truth", "results": [], "metrics": {}}

    results = []
    verification_entries: list[tuple[str, Path, dict]] = []
    for i, row in enumerate(gt):
        repo_id = row["repo_id"]
        local_path = row["local_path"]
        if no_clone and not local_path:
            if verbose:
                print(f"Skip {repo_id} (no local_path and --no-clone)")
            continue
        repo_path: Path | None = None
        if local_path:
            path = Path(local_path)
            if not path.is_absolute():
                path = (ground_truth_path.parent / path).resolve()
            if not path.is_dir():
                results.append({
                    "repo_id": repo_id,
                    "error": f"Local path not a directory: {path}",
                    "expected_vulnerable": row["has_vulnerable"],
                    "expected_pqc_ready": row["has_pqc_ready"],
                })
                continue
            try:
                result = scan_repository(path, exclude_tests=exclude_tests)
                repo_path = path
            except Exception as e:
                results.append({
                    "repo_id": repo_id,
                    "error": str(e),
                    "expected_vulnerable": row["has_vulnerable"],
                    "expected_pqc_ready": row["has_pqc_ready"],
                })
                continue
        else:
            # Default: clone into project eval_clones/ to avoid Windows Temp path issues (long path, 8.3 names)
            default_clone = PROJECT_ROOT / "eval_clones"
            clone_root = clone_dir or Path(os.getenv("PQC_CLONE_DIR", str(default_clone)))
            clone_root = Path(clone_root).resolve()
            result, _path = clone_and_scan_repo(repo_id, exclude_tests=exclude_tests, clone_root=clone_root)
            if result is None:
                results.append({
                    "repo_id": repo_id,
                    "error": "Clone or scan failed",
                    "expected_vulnerable": row["has_vulnerable"],
                    "expected_pqc_ready": row["has_pqc_ready"],
                })
                continue
            repo_path = _path or Path(result.get("repo_path", "."))

        summary = result.get("summary", {})
        pred_vuln = summary.get("has_vulnerable_primitives", False)
        pred_pqc = (summary.get("pqc_ready_count", 0) or 0) >= 1
        exp_vuln = row["has_vulnerable"]
        exp_pqc = row["has_pqc_ready"]

        if write_verification_report and repo_path is not None:
            verification_entries.append((repo_id, repo_path, result))

        results.append({
            "repo_id": repo_id,
            "expected_vulnerable": exp_vuln,
            "expected_pqc_ready": exp_pqc,
            "predicted_vulnerable": pred_vuln,
            "predicted_pqc_ready": pred_pqc,
            "vulnerable_ok": exp_vuln == pred_vuln,
            "pqc_ready_ok": exp_pqc == pred_pqc,
        })

    verification_report_written: Path | None = None
    if write_verification_report and verification_entries:
        report_path = verification_report_path or (ground_truth_path.parent / "verification_report.md")
        _write_verification_report(verification_entries, report_path)
        verification_report_written = report_path

    # Metrics: binary classification for "has_vulnerable" and "has_pqc_ready"
    def metrics(binary_results: list[tuple[bool, bool]]) -> dict:
        """binary_results: list of (expected, predicted)."""
        tp = sum(1 for e, p in binary_results if e and p)
        fp = sum(1 for e, p in binary_results if not e and p)
        fn = sum(1 for e, p in binary_results if e and not p)
        tn = sum(1 for e, p in binary_results if not e and not p)
        n = len(binary_results)
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        return {
            "n": n,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
        }

    valid = [r for r in results if "error" not in r]
    vuln_pairs = [(r["expected_vulnerable"], r["predicted_vulnerable"]) for r in valid]
    pqc_pairs = [(r["expected_pqc_ready"], r["predicted_pqc_ready"]) for r in valid]

    return {
        "results": results,
        "n_total": len(gt),
        "n_ok": len(valid),
        "n_error": len(results) - len(valid),
        "metrics": {
            "has_vulnerable": metrics(vuln_pairs) if vuln_pairs else {},
            "has_pqc_ready": metrics(pqc_pairs) if pqc_pairs else {},
        },
        "verification_report": verification_report_written,
    }


def main():
    import argparse
    p = argparse.ArgumentParser(description="Evaluate scanner against ground-truth CSV (repo-level)")
    p.add_argument("--ground-truth", "-g", type=Path, required=True, help="Path to ground-truth CSV")
    p.add_argument("--clone-dir", type=Path, default=None, help="Directory for cloning repos (default: env PQC_CLONE_DIR or temp)")
    p.add_argument("--no-clone", action="store_true", help="Only evaluate rows that have local_path set (no GitHub clone)")
    p.add_argument("--no-exclude-tests", action="store_true", help="Include test paths in vulnerability summary")
    p.add_argument("--write-verification-report", action="store_true", help="Write verification_report.md with direct GitHub links to each finding (so you can verify without searching the repo)")
    p.add_argument("--verification-report", type=Path, default=None, help="Path for verification report (default: next to ground-truth CSV)")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    gt_path = args.ground_truth
    if not gt_path.is_absolute():
        gt_path = (Path.cwd() / gt_path).resolve()
    if not gt_path.is_file():
        print(f"Error: ground truth file not found: {gt_path}", file=sys.stderr)
        sys.exit(1)

    out = run_evaluation(
        ground_truth_path=gt_path,
        clone_dir=args.clone_dir,
        exclude_tests=not args.no_exclude_tests,
        no_clone=args.no_clone,
        verbose=args.verbose,
        write_verification_report=args.write_verification_report,
        verification_report_path=args.verification_report,
    )

    if out.get("error"):
        print(out["error"], file=sys.stderr)
        sys.exit(1)

    results = out["results"]
    metrics = out["metrics"]

    if out.get("verification_report"):
        print(f"Verification report (direct links to each finding): {out['verification_report']}")
        print()

    print("Evaluation summary")
    print("-----------------")
    print(f"Ground truth: {out['n_total']} rows, evaluated: {out['n_ok']}, errors: {out['n_error']}")
    print()

    for task, m in metrics.items():
        if not m:
            continue
        print(f"Task: {task}")
        print(f"  n={m['n']}  TP={m['tp']}  FP={m['fp']}  TN={m['tn']}  FN={m['fn']}")
        print(f"  Precision: {m['precision']:.4f}  Recall: {m['recall']:.4f}  F1: {m['f1']:.4f}")
        print()

    mismatches = [r for r in results if "error" not in r and (not r["vulnerable_ok"] or not r["pqc_ready_ok"])]
    if mismatches:
        print("Mismatches (expected vs predicted)")
        print("-----------------------------------")
        for r in mismatches:
            v = "vulnerable" if r["expected_vulnerable"] else "no vulnerable"
            pv = "vulnerable" if r["predicted_vulnerable"] else "no vulnerable"
            q = "PQC-ready" if r["expected_pqc_ready"] else "no PQC"
            pq = "PQC-ready" if r["predicted_pqc_ready"] else "no PQC"
            print(f"  {r['repo_id']}: vulnerable exp={v} got={pv}; pqc exp={q} got={pq}")
    else:
        print("No mismatches.")

    errors = [r for r in results if "error" in r]
    if errors:
        print()
        print("Errors")
        print("------")
        for r in errors:
            print(f"  {r['repo_id']}: {r['error']}")


if __name__ == "__main__":
    main()
