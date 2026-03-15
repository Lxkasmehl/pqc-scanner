# Scanner Evaluation (Repo-Level)

This folder contains tools to evaluate the PQC scanner against a **ground-truth** set of repositories, so you can report precision/recall in the paper (Section 4 – Evaluation).

## Quick start

1. **Create a ground-truth CSV** (see format below). You can copy `ground_truth_example.csv` and add your own repos. Alternatively, **seed from scan results**: pick repos from `results/aggregate.csv`, add them with the scanner’s prediction as initial labels, then manually verify on GitHub and correct the CSV (see **Backwards** in `docs/EVALUATION.md`).
2. **Run the evaluation** from the **project root**:
   ```bash
   python evaluation/run_evaluation.py --ground-truth evaluation/ground_truth.csv
   ```
   The script will clone each `repo_id` (GitHub `owner/name`), run the scanner, and compare the scanner’s “has vulnerable” / “has PQC-ready” to your labels.
3. **Verification report (recommended):** To verify labels without searching huge repos, run once with `--write-verification-report`. This writes **evaluation/verification_report.md** with **direct GitHub links to each finding** (file and line). Open the report, click the links, and only check those lines; then correct `ground_truth.csv` where the scanner was wrong.
   ```bash
   python evaluation/run_evaluation.py --ground-truth evaluation/ground_truth.csv --write-verification-report
   ```
5. **Optional: use local paths only** (no cloning), e.g. for fixtures or pre-cloned repos:
   ```bash
   python evaluation/run_evaluation.py --ground-truth evaluation/ground_truth.csv --no-clone
   ```
   Only rows with a non-empty `local_path` are evaluated.

## Ground-truth CSV format

| Column           | Required | Description |
|------------------|----------|-------------|
| `repo_id`        | yes      | GitHub `owner/name` (e.g. `pyca/cryptography`) or any id when using `local_path`. |
| `has_vulnerable` | yes      | `1` = repo is expected to have ≥1 post-quantum-vulnerable primitive, `0` = not. |
| `has_pqc_ready`  | yes      | `1` = repo is expected to have ≥1 PQC-ready primitive (Kyber, Dilithium, oqs), `0` = not. |
| `local_path`     | no       | If set, this path is scanned instead of cloning `repo_id`. Can be relative to the CSV file. |
| `notes`          | no       | Optional note (e.g. "RSA only"). |

Example:

```csv
repo_id,has_vulnerable,has_pqc_ready,local_path,notes
pyca/cryptography,1,0,,RSA, ECDSA
open-quantum-safe/liboqs,0,1,,liboqs
my/local/repo,1,0,/path/to/clone,local clone
```

## Verification report

If you pass `--write-verification-report`, the script writes a Markdown file (default: **evaluation/verification_report.md**) with one section per repo. Each section lists every finding with type (vulnerable / safe / PQC-ready), primitive name, file:line, and a **link that opens that exact line on GitHub**. Use it to verify the scanner’s results without searching the repo; then fix `ground_truth.csv` and re-run the evaluation.

## Output

The script prints:

- **Counts:** how many rows were evaluated and how many failed (clone/scan error).
- **Metrics** for the two binary tasks:
  - **has_vulnerable:** precision, recall, F1 (and TP/FP/TN/FN).
  - **has_pqc_ready:** precision, recall, F1.
- **Mismatches:** repos where the scanner’s prediction disagreed with the ground truth.
- **Errors:** repos that could not be cloned or scanned.

Use these numbers in the paper (Section 4) and mention sample size and threats to validity; see `docs/EVALUATION.md` for the full evaluation workflow and how to find repos to annotate.
