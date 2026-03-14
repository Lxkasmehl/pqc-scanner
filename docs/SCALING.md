# Running at scale (10,000–50,000 repositories)

The GitHub Search API returns **at most 1,000 results per query**. To build a dataset of 10k–50k repos for the paper, you need a different workflow: generate a repo list once (stratified search or BigQuery), then run the scanner in an environment that can run for hours/days (e.g. GitHub Codespaces, cloud VM, or batch job).

## Option A: Stratified search + repo list file (no BigQuery)

1. **Build the repo list in one command** (Python, Java, Go in similar proportions):

   ```bash
   python cli.py build-repo-list --output repo_list.jsonl --total 15000
   ```

   This runs stratified search per language (by year), then writes one JSONL with round-robin order so each language has roughly equal share. Default: 15,000 repos (5,000 per language). Options:

   - `--total 15000` — target size (default); split equally across languages
   - `--languages "Python,Java,Go"` — default; use e.g. `"Python,Go"` for two languages
   - `--min-stars 10`, `--years-start 2015`, `--years-end 2024`

   The Search API is throttled (about 2.5 s between requests) to avoid “secondary rate limit” 403s. Building 15k repos can take roughly 1–2 hours. If you still hit 403, set `GITHUB_STRATUM_DELAY=20`, `GITHUB_COOLDOWN_AFTER_FULL_STRATUM=45`, or `GITHUB_SEARCH_DELAY=3` in `.env`.

   **GitHub Actions (no local run):** You can build the list in the cloud without committing it. Go to **Actions → Build repo list → Run workflow**, choose total (e.g. 15000), then run. When the job finishes, download the `repo-list` artifact (the JSONL file). The file is in `.gitignore` and must not be committed. For higher rate limits, add a repo secret `GH_PAT` (GitHub Personal Access Token with no extra scopes).

   For a **single language** only, use `export-repos` instead:

   ```bash
   python cli.py export-repos --output repo_list_python.jsonl --language python --min-stars 10 --years-start 2015 --years-end 2024
   ```

2. **Run the scanner from the list** in an environment with enough disk and time (Codespaces, cloud VM):

   ```bash
   # Process entire list (use --limit 0)
   python cli.py collect --from-file repo_list.jsonl --limit 0

   # Or process in batches (e.g. first 5000)
   python cli.py collect --from-file repo_list.jsonl --limit 5000
   ```

   - State is stored in `scanner/state.db`; already-scanned repos are skipped on resume.
   - Persist `results/` and `scanner/state.db` (e.g. commit results, or copy out of the environment) so you can resume or merge runs.

   **Run the scanner in GitHub Actions:** You can also run the scanner in the cloud without Oracle or a VM. Use **Actions → Run scanner (from list)**. Each run has a 6-hour job limit; the scan step stops after 5 hours so that state and results are always uploaded (even on timeout). Use a batch size that finishes within that window (e.g. `limit` 500–4000 depending on speed). You must pass the **Run ID** of a completed "Build repo list" run so the workflow can download the repo list artifact. To process more repos, run the workflow again and set **Resume from run ID** to the previous "Run scanner" run; it will download `state.db` and `results/` and continue. **Important:** If a run hits the timeout, you still get `scanner-state` and `scanner-results` artifacts from that run, so you can resume from it. Download the artifacts from each run if you want to merge or keep them locally. `results/` and `scanner/state.db` are in `.gitignore` and must not be committed.

   **Artifact `scanner-results`:** The workflow rebuilds `aggregate.csv` from all `results/raw/*.json` before upload, so the CSV should have one row per raw file. If you have an older artifact where the CSV has fewer rows than the raw folder, extract the artifact into a `results/` directory (with `raw/` and optionally the old `aggregate.csv`), then run locally: `python cli.py rebuild-aggregate` to regenerate a full CSV from the raw folder. You can then use `report` and the CSV for your paper.

## Option B: GitHub Archive / BigQuery (largest scale)

If you have access to [BigQuery and the GitHub dataset](https://www.gharchive.org/), you can export a repo list that is not limited by the Search API:

1. Run a BigQuery query that selects `repo.name` (or `repo.name` + `actor.login` for owner) for repositories that match your criteria (language, stars, etc.). Export the result to GCS or CSV.
2. Convert the export to JSONL with one repo per line, e.g. `{"full_name": "owner/repo"}` or plain `owner/repo` per line.
3. Run the scanner with `--from-file` as in Option A.

Example BigQuery-style filter (adapt to the actual schema you use): repositories with recent activity, by language. The exact query depends on which GitHub/BigQuery tables you use (e.g. `github_repos` or event tables).

## Where to run (10k–50k is not realistic locally)

| Environment | Pros | Cons |
|-------------|------|------|
| **GitHub Codespaces** | Same setup as your dev run; persistent state if you save `state.db` and `results/` | Need to keep the machine on; storage limits; may need to re-run in chunks and merge |
| **Cloud VM (GCP, AWS, etc.)** | Full control, large disk, can run for days | You pay for compute; need to set up Git, Python, env |
| **Batch job (e.g. GCP Cloud Run Jobs, AWS Batch)** | Good for splitting work (e.g. 10 workers × 5k repos each) | More setup: split repo list into shards, run one job per shard, merge CSVs at the end |

### Practical recommendation

1. **One-time**: On your machine or a Codespace, run `build-repo-list --output repo_list.jsonl --total 15000` (or your target size). Set `GITHUB_TOKEN` in `.env` for higher rate limits during export.
2. **Long run**: Open a **GitHub Codespace** (or a cloud VM), clone the repo, install deps, set `GITHUB_TOKEN`, and run:
   ```bash
   python cli.py collect --from-file repo_list.jsonl --limit 0
   ```
   Let it run for hours/days. Persist `results/` and `scanner/state.db` (e.g. copy to Drive, or push results to a separate repo).
3. **Resume**: If the run is interrupted, run the same command again; already-scanned repos are skipped thanks to `state.db`.
4. **Optional parallelism**: To split work across multiple machines, split `repo_list.jsonl` into N files (e.g. 5 × 10k), run one `collect --from-file part1.jsonl --limit 0` per machine, then merge the `results/raw/*.json` and rebuild `aggregate.csv` from the combined raw folder (the report command and CSV rebuild in the collector already aggregate all JSONs in `results/raw/`).

## File format for `--from-file`

- **JSONL**: One JSON object per line. Each object should have at least `full_name` (e.g. `"owner/repo"`). Optional: `clone_url`, `language`, `stargazers_count`, `forks_count`, `created_at`, `size`, `topics` (for the aggregate CSV).
- **Plain text**: One line per repo: `owner/repo` or `https://github.com/owner/repo`. Metadata will be empty in the CSV.

Example JSONL line (from `export-repos`):

```json
{"full_name": "owner/repo", "name": "repo", "owner": "owner", "language": "Python", "stargazers_count": 100, "forks_count": 10, "created_at": "2020-01-15T...", "size": 5000, "topics": ["crypto", "security"], "clone_url": "https://github.com/owner/repo.git"}
```
