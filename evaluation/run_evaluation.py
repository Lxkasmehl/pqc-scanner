#!/usr/bin/env python3
"""
Run scanner evaluation against a ground-truth CSV (repo-level).

Recommended workflow (from project root)
-----------------------------------------
  python evaluation/run_evaluation.py -g evaluation/ground_truth_curated.csv --write-verification-report

  This clones each GitHub repo (or uses local_path if set), scans it, compares to the CSV labels,
  and writes a short summary report (evaluation/verification_report.md by default).

Options
-------
  --use-existing-clones   If a repo is already cloned under clone-dir (e.g. manually), use it
                          and do not re-clone. Repos not yet cloned are still cloned. So you can
                          extend the CSV and mix: some repos already in eval_clones/, others new.
  --report-style summary  One short Markdown file (default).
  --report-style full     Index + one file per repo with detailed findings and GitHub links.
  --from-raw              Use results/raw/*.json only; no cloning. Only rows without local_path
                          are considered; repos missing in raw/ are skipped.
  --no-clone              Only evaluate rows that have local_path set (no GitHub clone at all).
  --clone-dir PATH        Where to clone (default: eval_clones). Env: PQC_CLONE_DIR.
  PQC_CLONE_TIMEOUT       Clone timeout in seconds (default 300). Increase for large repos.

Manual clone (if one repo times out)
------------------------------------
  Clone into <clone-dir>/pqc_scan_<owner>_<repo>. Example for bcgit/bc-java with default clone-dir:
    mkdir eval_clones
    git clone -c core.longpaths=true --depth 1 https://github.com/bcgit/bc-java.git eval_clones/pqc_scan_bcgit_bc-java
  Then run with --use-existing-clones so that repo is used; other repos in the CSV are still
  cloned if not present.

CSV columns: repo_id (owner/name or id), has_vulnerable (1/0), has_pqc_ready (1/0),
             local_path (optional), notes (optional).
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


def _github_file_url(repo_id: str, rel_path: str, line: int, branch: str = "HEAD") -> str:
    """Build GitHub link to file at line. Use HEAD when unknown – GitHub redirects to default branch."""
    return f"https://github.com/{repo_id}/blob/{branch}/{rel_path}#L{line}"


def _rel_path_from_raw(repo_path_str: str, file_str: str) -> str:
    """From raw JSON: get path relative to repo root (repo_path and file may be from another OS)."""
    if not repo_path_str or not file_str:
        return file_str or ""
    rp = repo_path_str.rstrip("/\\")
    if not rp:
        return file_str.replace("\\", "/").lstrip("/")
    if file_str.startswith(rp):
        rel = file_str[len(rp) :].lstrip("/\\")
    else:
        # try normalized (e.g. different path separators)
        rel = file_str.replace("\\", "/").replace(rp.replace("\\", "/"), "").lstrip("/")
    return rel.replace("\\", "/") if rel else file_str.replace("\\", "/")


def _one_repo_section(repo_id: str, repo_path: Path, result: dict) -> list[str]:
    """Build markdown lines for one repo (clone/local path)."""
    branch = _default_branch(repo_path)
    findings = result.get("findings", [])
    summary = result.get("summary", {})
    n_v = summary.get("vulnerable_count", 0)
    n_pqc = summary.get("pqc_ready_count", 0)
    n_safe = summary.get("safe_count", 0)
    lines = [
        f"# {repo_id}",
        "",
        f"**Scanner summary:** vulnerable={n_v}, PQC-ready={n_pqc}, quantum-safe={n_safe}",
        "",
    ]
    if not findings:
        lines.append("*No findings.*")
        lines.append("")
        return lines
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
    return lines


def _one_repo_section_raw(repo_id: str, result: dict, branch: str = "HEAD") -> list[str]:
    """Build markdown lines for one repo (from raw JSON)."""
    repo_path_str = result.get("repo_path", "")
    findings = result.get("findings", [])
    summary = result.get("summary", {})
    n_v = summary.get("vulnerable_count", 0)
    n_pqc = summary.get("pqc_ready_count", 0)
    n_safe = summary.get("safe_count", 0)
    lines = [
        f"# {repo_id}",
        "",
        f"**Scanner summary:** vulnerable={n_v}, PQC-ready={n_pqc}, quantum-safe={n_safe}",
        "",
    ]
    if not findings:
        lines.append("*No findings.*")
        lines.append("")
        return lines
    is_github_repo = "/" in repo_id and repo_id.count("/") == 1 and "\\" not in repo_id
    lines.append("| Type | Primitive | File:line | Link |")
    lines.append("|------|-----------|-----------|------|")
    for f in findings:
        cl = f.get("classification", "?")
        prim = (f.get("primitive") or "?").replace("|", " ")
        file_str = f.get("file", "")
        line_no = f.get("line", 0)
        rel_str = _rel_path_from_raw(repo_path_str, file_str)
        if is_github_repo and rel_str:
            url = _github_file_url(repo_id, rel_str, line_no, branch)
            lines.append(f"| {cl} | {prim} | `{rel_str}:{line_no}` | [open on GitHub]({url}) |")
        elif is_github_repo:
            lines.append(f"| {cl} | {prim} | `{rel_str}:{line_no}` | [repo](https://github.com/{repo_id}) |")
        else:
            lines.append(f"| {cl} | {prim} | `{rel_str}:{line_no}` | — |")
    lines.append("")
    return lines


def _write_summary_report(
    results: list[dict],
    metrics: dict,
    out_path: Path,
    n_total: int,
    n_ok: int,
    n_error: int,
) -> None:
    """Write a single concise Markdown report: metrics + per-repo one-liners (no per-repo files)."""
    out_path = Path(out_path).resolve()
    lines = [
        "# Evaluation summary",
        "",
        "Results of evaluating the scanner against a curated ground-truth set of repositories.",
        "",
        "## Counts",
        "",
        f"- Ground-truth rows: **{n_total}**",
        f"- Successfully evaluated: **{n_ok}**",
        f"- Errors (e.g. clone failed): **{n_error}**",
        "",
        "## Metrics (binary: has vulnerable / has PQC-ready)",
        "",
    ]
    for task, m in metrics.items():
        if not m:
            continue
        lines.append(f"### {task}")
        lines.append("")
        lines.append(f"| Metric    | Value |")
        lines.append("|-----------|-------|")
        lines.append(f"| n         | {m['n']} |")
        lines.append(f"| TP / FP   | {m['tp']} / {m['fp']} |")
        lines.append(f"| TN / FN   | {m['tn']} / {m['fn']} |")
        lines.append(f"| Precision | {m['precision']:.4f} |")
        lines.append(f"| Recall    | {m['recall']:.4f} |")
        lines.append(f"| F1        | {m['f1']:.4f} |")
        lines.append("")
    lines.append("## Per-repo results")
    lines.append("")
    lines.append("| Repo | Exp. vulnerable | Exp. PQC-ready | Pred. vulnerable | Pred. PQC-ready | OK |")
    lines.append("|------|-----------------|----------------|------------------|-----------------|-----|")
    for r in results:
        if "error" in r:
            err = r["error"]
            err_cell = f"**error**: {err[:50]}…" if len(err) > 50 else f"**error**: {err}"
            lines.append(f"| {r['repo_id']} | — | — | — | — | {err_cell} |")
            continue
        ev = "yes" if r["expected_vulnerable"] else "no"
        ep = "yes" if r["expected_pqc_ready"] else "no"
        pv = "yes" if r["predicted_vulnerable"] else "no"
        pp = "yes" if r["predicted_pqc_ready"] else "no"
        ok = "✓" if (r["vulnerable_ok"] and r["pqc_ready_ok"]) else "✗"
        lines.append(f"| {r['repo_id']} | {ev} | {ep} | {pv} | {pp} | {ok} |")
    lines.append("")
    errors = [r for r in results if "error" in r]
    if errors:
        lines.append("## Errors")
        lines.append("")
        for r in errors:
            lines.append(f"- **{r['repo_id']}**: {r['error']}")
        lines.append("")
    out_path.write_text("\n".join(lines), encoding="utf-8")


def _write_split_verification_reports(
    repo_contents: list[tuple[str, list[str]]],
    out_path: Path,
    intro: list[str],
) -> None:
    """Write one small file per repo + a short index file so the report is openable."""
    out_path = Path(out_path).resolve()
    report_dir = out_path.parent / "verification_reports"
    if report_dir.exists():
        for f in report_dir.iterdir():
            if f.is_file():
                f.unlink()
    report_dir.mkdir(parents=True, exist_ok=True)
    index_lines = list(intro)
    index_lines.append("")
    index_lines.append("## Repos (open one file at a time)")
    index_lines.append("")
    for repo_id, lines in repo_contents:
        safe = repo_id.replace("/", "_").replace("\\", "_")
        part_path = report_dir / f"{safe}.md"
        part_path.write_text("\n".join(lines), encoding="utf-8")
        rel = part_path.relative_to(out_path.parent)
        index_lines.append(f"- [{repo_id}]({rel.as_posix()})")
    index_lines.append("")
    out_path.write_text("\n".join(index_lines), encoding="utf-8")


def _write_verification_report(
    entries: list[tuple[str, Path, dict]],
    out_path: Path,
) -> None:
    """Write verification report: one small file per repo + short index (no single huge file)."""
    intro = [
        "# Verification report – index",
        "",
        "Open **one repo at a time** via the links below. Each linked file contains the findings for that repo with direct GitHub links.",
        "",
        "After verifying, correct `ground_truth.csv` where the scanner was wrong, then re-run the evaluation.",
    ]
    repo_contents = [(repo_id, _one_repo_section(repo_id, repo_path, result)) for repo_id, repo_path, result in entries]
    _write_split_verification_reports(repo_contents, out_path, intro)


def _write_verification_report_from_raw(
    entries: list[tuple[str, dict]],
    out_path: Path,
    branch: str = "HEAD",
) -> None:
    """Write verification report from raw JSON: one small file per repo + short index."""
    intro = [
        "# Verification report – index (from existing scan)",
        "",
        "Generated from **results/raw/*.json**. Open **one repo at a time** below. Each file has direct GitHub links to the findings.",
        "",
        "Verify those spots, correct `ground_truth.csv` if needed, then re-run with `--from-raw`.",
    ]
    repo_contents = [(repo_id, _one_repo_section_raw(repo_id, result, branch)) for repo_id, result in entries]
    _write_split_verification_reports(repo_contents, out_path, intro)


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


def _load_raw_result(repo_id: str, raw_dir: Path) -> dict | None:
    """Load results/raw/{owner_name}.json if present. Returns parsed JSON or None."""
    import json
    safe = repo_id.replace("/", "_").replace("\\", "_")
    path = raw_dir / f"{safe}.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def run_evaluation(
    ground_truth_path: Path,
    clone_dir: Path | None = None,
    exclude_tests: bool = True,
    no_clone: bool = False,
    from_raw: bool = False,
    raw_dir: Path | None = None,
    use_existing_clones: bool = False,
    verbose: bool = False,
    write_verification_report: bool = False,
    verification_report_path: Path | None = None,
    report_style: str = "full",
) -> dict:
    gt = load_ground_truth(ground_truth_path)
    if not gt:
        return {"error": "No rows in ground truth", "results": [], "metrics": {}}

    results = []
    verification_entries: list[tuple[str, Path, dict]] = []
    verification_entries_raw: list[tuple[str, dict]] = []

    if from_raw:
        raw_dir = Path(raw_dir or PROJECT_ROOT / "results" / "raw").resolve()
        if not raw_dir.is_dir():
            return {"error": f"Raw dir not found: {raw_dir} (run scanner first to populate results/raw/)", "results": [], "metrics": {}}
        n_gt = len([r for r in gt if not r["local_path"]])
        for idx, row in enumerate(gt):
            repo_id = row["repo_id"]
            if row["local_path"]:
                if verbose:
                    print(f"Skip {repo_id} (from-raw ignores local_path)")
                continue
            print(f"  [{idx + 1}/{n_gt}] {repo_id} ...", flush=True)
            result = _load_raw_result(repo_id, raw_dir)
            if result is None:
                results.append({
                    "repo_id": repo_id,
                    "error": "No raw JSON (repo was not in this scan)",
                    "expected_vulnerable": row["has_vulnerable"],
                    "expected_pqc_ready": row["has_pqc_ready"],
                })
                continue
            summary = result.get("summary", {})
            pred_vuln = summary.get("has_vulnerable_primitives", False)
            pred_pqc = (summary.get("pqc_ready_count", 0) or 0) >= 1
            results.append({
                "repo_id": repo_id,
                "expected_vulnerable": row["has_vulnerable"],
                "expected_pqc_ready": row["has_pqc_ready"],
                "predicted_vulnerable": pred_vuln,
                "predicted_pqc_ready": pred_pqc,
                "vulnerable_ok": row["has_vulnerable"] == pred_vuln,
                "pqc_ready_ok": row["has_pqc_ready"] == pred_pqc,
            })
            if write_verification_report:
                verification_entries_raw.append((repo_id, result))
    else:
        to_process = [r for r in gt if not (no_clone and not r["local_path"])]
        for i, row in enumerate(gt):
            repo_id = row["repo_id"]
            local_path = row["local_path"]
            if no_clone and not local_path:
                if verbose:
                    print(f"Skip {repo_id} (no local_path and --no-clone)")
                continue
            repo_path = None
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
                # Default: clone into project eval_clones/ to avoid Windows Temp path issues
                n_total = len(to_process)
                print(f"  [{len(results) + 1}/{n_total}] {repo_id} (clone + scan, can take minutes) ...", flush=True)
                default_clone = PROJECT_ROOT / "eval_clones"
                clone_root = clone_dir or Path(os.getenv("PQC_CLONE_DIR", str(default_clone)))
                clone_root = Path(clone_root).resolve()
                result, _path = clone_and_scan_repo(
                    repo_id,
                    exclude_tests=exclude_tests,
                    clone_root=clone_root,
                    use_existing_clones=use_existing_clones,
                )
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
    computed_metrics = {
        "has_vulnerable": metrics(vuln_pairs) if vuln_pairs else {},
        "has_pqc_ready": metrics(pqc_pairs) if pqc_pairs else {},
    }

    verification_report_written = None
    if write_verification_report:
        report_path = verification_report_path or (ground_truth_path.parent / "verification_report.md")
        if report_style == "summary":
            _write_summary_report(
                results, computed_metrics, report_path, len(gt), len(valid), len(results) - len(valid)
            )
            verification_report_written = report_path
        elif from_raw and verification_entries_raw:
            _write_verification_report_from_raw(verification_entries_raw, report_path)
            verification_report_written = report_path
        elif verification_entries:
            _write_verification_report(verification_entries, report_path)
            verification_report_written = report_path

    return {
        "results": results,
        "n_total": len(gt),
        "n_ok": len(valid),
        "n_error": len(results) - len(valid),
        "metrics": computed_metrics,
        "verification_report": verification_report_written,
    }


def main():
    import argparse
    p = argparse.ArgumentParser(description="Evaluate scanner against ground-truth CSV (repo-level)")
    p.add_argument("--ground-truth", "-g", type=Path, required=True, help="Path to ground-truth CSV")
    p.add_argument("--clone-dir", type=Path, default=None, help="Directory for cloning repos (default: env PQC_CLONE_DIR or temp)")
    p.add_argument("--no-clone", action="store_true", help="Only evaluate rows that have local_path set (no GitHub clone)")
    p.add_argument("--from-raw", action="store_true", help="Use existing results/raw/*.json only (from your scanner run) – no cloning.")
    p.add_argument("--raw-dir", type=Path, default=None, help="Directory with raw JSONs (default: results/raw)")
    p.add_argument("--no-exclude-tests", action="store_true", help="Include test paths in vulnerability summary")
    p.add_argument("--use-existing-clones", action="store_true", help="If a repo is already cloned under clone-dir (e.g. manually), skip clone and just scan")
    p.add_argument("--write-verification-report", action="store_true", help="Write verification report (Markdown)")
    p.add_argument("--report-style", choices=("summary", "full"), default="summary", help="summary = one short Markdown file; full = index + per-repo files (default: summary)")
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
        from_raw=args.from_raw,
        raw_dir=args.raw_dir,
        use_existing_clones=args.use_existing_clones,
        verbose=args.verbose,
        write_verification_report=args.write_verification_report,
        verification_report_path=args.verification_report,
        report_style=args.report_style,
    )

    if out.get("error"):
        print(out["error"], file=sys.stderr)
        sys.exit(1)

    results = out["results"]
    metrics = out["metrics"]

    if out.get("verification_report"):
        print(f"Report written: {out['verification_report']}")
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
