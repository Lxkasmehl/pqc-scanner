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

## Re-running so all 20 ground-truth repos are evaluated

By default, clone timeout is 300 seconds. Large repos (**bcgit/bc-java**, **golang/go**) can fail with “Clone or scan failed” and are then excluded. The repo **stevelr/python-rsa** no longer exists on GitHub (404); the ground truth also includes **sybrenstuvel/python-rsa** (canonical PyPI `rsa`), so at most 19 of the 20 entries can be cloned. You can remove the `stevelr/python-rsa` row from the CSV to get a clean 19-repo evaluation.

**Option A: Increase clone timeout (recommended first try)**

From the project root, set a longer timeout and run as usual:

```bash
# Windows (PowerShell)
$env:PQC_CLONE_TIMEOUT = "900"
python evaluation/run_evaluation.py -g evaluation/ground_truth_curated.csv --write-verification-report

# Linux/macOS
export PQC_CLONE_TIMEOUT=900
python evaluation/run_evaluation.py -g evaluation/ground_truth_curated.csv --write-verification-report
```

Use 900 (15 min) or 1200 (20 min) if needed. Clone directory defaults to **eval_clones/** (or `PQC_CLONE_DIR`).

**Option B: Pre-clone the failing repos, then run with existing clones**

If some repos still time out, clone them once manually (e.g. with `--depth 1`), then re-run so the script reuses those clones:

1. Create clone dir (if needed):  
   `mkdir eval_clones` (or use your `PQC_CLONE_DIR`).

2. Clone the repos that time out (names must match what the script expects). **Note:** `stevelr/python-rsa` is no longer on GitHub (404); only clone the two below (or remove that row from the CSV).
   - `pqc_scan_bcgit_bc-java` → `git clone -c core.longpaths=true --depth 1 https://github.com/bcgit/bc-java.git eval_clones/pqc_scan_bcgit_bc-java`
   - `pqc_scan_golang_go` → `git clone --depth 1 https://github.com/golang/go.git eval_clones/pqc_scan_golang_go`

3. Run evaluation reusing existing clones (other repos are still cloned by the script if missing):
   ```bash
   python evaluation/run_evaluation.py -g evaluation/ground_truth_curated.csv --write-verification-report --use-existing-clones
   ```

The generated **verification_report.md** (and optional per-repo reports with `--report-style full`) will then reflect all repos that could be cloned and scanned (up to 19 if you drop the `stevelr/python-rsa` row, since that repo no longer exists).
