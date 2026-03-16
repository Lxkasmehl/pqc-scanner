# Scanner evaluation (repo-level)

Evaluate the PQC scanner against a **ground-truth CSV**: clone (or use local paths), scan, compare to labels, report precision/recall and optionally a verification report.

## Quick start

From the **project root**:

```bash
python evaluation/run_evaluation.py -g evaluation/ground_truth_curated.csv --write-verification-report
```

- Reads the CSV, clones each GitHub repo (or uses `local_path` if set), runs the scanner, compares repo-level “has vulnerable” / “has PQC-ready” to your labels.
- Writes **evaluation/verification_report.md** (one short summary by default).
- Prints counts, precision/recall/F1 for both tasks, and any mismatches/errors.

## Ground-truth CSV

| Column           | Required | Description |
|------------------|----------|-------------|
| `repo_id`        | yes      | GitHub `owner/name` (e.g. `pyca/cryptography`) or any id when using `local_path`. |
| `has_vulnerable` | yes      | `1` = repo expected to have ≥1 post-quantum-vulnerable primitive, `0` = not. |
| `has_pqc_ready`  | yes      | `1` = repo expected to have ≥1 PQC-ready primitive, `0` = not. |
| `local_path`     | no       | If set, scan this path instead of cloning `repo_id`. Relative to CSV file or absolute. |
| `notes`         | no       | Optional (e.g. "RSA only"). |

Example:

```csv
repo_id,has_vulnerable,has_pqc_ready,local_path,notes
pyca/cryptography,1,0,,RSA, ECDSA
open-quantum-safe/liboqs-python,0,1,,OQS bindings
fixtures,1,1,../tests/fixtures,Local fixtures
```

## Useful options

- **`--use-existing-clones`** — Use repos already cloned under clone-dir (e.g. you cloned some manually). Repos **not** yet cloned are still cloned. So you can extend the CSV and mix existing clones with new ones.
- **`--report-style full`** — Write index + one Markdown file per repo (findings with GitHub links). Default is `summary` (one short file).
- **`--from-raw`** — No cloning: use existing **results/raw/*.json** from a prior scanner run. Repos missing in raw/ are skipped.
- **`--no-clone`** — Only evaluate rows that have `local_path` set (no GitHub clone).
- **`--clone-dir PATH`** — Where to clone (default: **eval_clones**). Env: `PQC_CLONE_DIR`.
- **`PQC_CLONE_TIMEOUT`** — Clone timeout in seconds (default 300). Increase for large repos.

See the script docstring (`evaluation/run_evaluation.py`) for manual-clone path format and full options.

## Verification report

With `--write-verification-report`:

- **summary** (default): One Markdown file with counts, metrics table, and per-repo one-liner (expected vs predicted, OK/error).
- **full**: Index file plus one file per repo with each finding and a link to the line on GitHub (for spot-checking and correcting labels).

For the full evaluation workflow (finding repos, labelling, what to report in the paper), see **docs/EVALUATION.md**.
