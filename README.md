# PQC-Readiness Scanner

A research prototype for an empirical study on **post-quantum cryptography (PQC) adoption** in open-source software. The scanner analyzes source code repositories and detects usage of cryptographic primitives, classifying them as **post-quantum-vulnerable**, **quantum-safe**, or **PQC-ready**.

## Research context

The goal is to run this tool on large sets of public GitHub repositories (e.g. 10,000–50,000) and produce a dataset for a research paper on where and how often classical public-key crypto (RSA, ECDSA, ECDH, etc.) is used versus quantum-safe alternatives (e.g. Kyber, Dilithium).

## Features

- **Multi-language (Phase 1):** Python, Java, Go
- **AST-based detection:** Python via `ast`, Java/Go via tree-sitter
- **Classification:** Each finding is labeled as vulnerable, safe, or PQC-ready
- **Confidence levels:** high (direct API call), medium (import only), low (string match)
- **GitHub integration:** Search API, shallow clone, rate limiting, resume via SQLite state
- **Output:** Per-repo JSON, aggregated CSV, CLI report

## Requirements

- Python 3.11+
- Git (for cloning repos when using `scan github` or `collect`)
- Optional: GitHub token for higher API rate limits

## Setup

```bash
cd pqc-scanner
python -m venv .venv
.venv\Scripts\activate   # Windows
# source .venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
cp .env.example .env
# Edit .env and set GITHUB_TOKEN if you use collect/scan github
```

## Usage

### Scan a local repository

```bash
python cli.py scan local /path/to/repo
```

Prints a short summary and the full JSON result. Use `--no-exclude-tests` to include test directories in the vulnerability summary.

### Scan a single GitHub repo

Clones the repo (shallow) and scans it:

```bash
python cli.py scan github owner/repo
```

### Collect and scan many repos from GitHub

Searches GitHub by language and star count, skips already-scanned repos (state in `scanner/state.db`), clones and scans each, writes `results/raw/*.json` and `results/aggregate.csv`:

```bash
python cli.py collect --language python --min-stars 10 --limit 100
```

Options: `--created-after`, `--created-before` (YYYY-MM-DD), `--exclude-tests`, `-v`.

For **10,000–50,000 repos** (e.g. for the paper’s empirical study), the Search API’s 1,000-result limit requires a two-step workflow: build a repo list, then run the scanner from that list (e.g. in a Codespace or cloud VM). See **[docs/SCALING.md](docs/SCALING.md)**.

- **Build repo list** (one command, Python/Java/Go in similar proportions):
  ```bash
  python cli.py build-repo-list --output repo_list.jsonl --total 15000
  ```
- **Scan from list** (use `--limit 0` to process the whole file):
  ```bash
  python cli.py collect --from-file repo_list.jsonl --limit 0
  ```

Single-language list: `export-repos --output ... --language python` (see docs).

### Report

Print paper-ready statistics: PQC vulnerability rate, breakdown by language, primitive distribution, PQC adoption, and criticality (vulnerable in production vs test code). Export a Markdown report for the paper with `--output`:

```bash
python cli.py report
python cli.py report --output results/report.md
```

The report includes: sample size, % repos with vulnerable primitives, % with PQC-ready primitives, counts **by GitHub primary language** (Python / Java / Go), top vulnerable/PQC-ready primitives, and vulnerable findings in production vs test code. Primitive names are aggregated by a canonical key (e.g. RSA, ECDSA, `crypto/rsa`, `rsa.GenerateKey` merged) so the top-primitives tables are not split by spelling or language.

**Language column in `results/aggregate.csv`:** Rows rebuilt from raw JSON only (e.g. `rebuild-aggregate`) start with an empty `language` field. The **same** GitHub metadata that `collect` stored in `scanner/state.db` is merged when you run `report` (default: `scanner/state.db`) and when you run **`enrich-aggregate`** or **`rebuild-aggregate`** (auto-enriches from `state.db` if present). That way the CSV and the Markdown report stay aligned with the paper’s per-language table without manual scripts.

## Configuration (.env)

| Variable              | Description                                                       |
|-----------------------|-------------------------------------------------------------------|
| `GITHUB_TOKEN`        | GitHub personal access token (recommended; higher search limits)   |
| `PQC_RESULTS_DIR`     | Output directory (default: `results`)                             |
| `PQC_CLONE_DIR`       | Where to clone repos (default: temp dir)                          |
| `GITHUB_SEARCH_DELAY` | Seconds between Search API requests (default: 2.5). Increase to 3–4 if you hit secondary rate limits. |

Scanner state (already-scanned repos) is stored in `scanner/state.db`.  
`build-repo-list` is throttled so 15k repos can take roughly 1–2 hours; on 403 it backs off and retries.

## Project structure

```
pqc-scanner/
├── scanner/
│   ├── classifier.py      # Primitive → vulnerable/safe/pqc-ready
│   ├── repo_scanner.py    # Walk repo, run detectors, aggregate
│   ├── github_collector.py # Search, clone, rate limit, state DB
│   ├── output.py         # JSON, CSV, summary print
│   ├── state.db          # Created on first collect (resume)
│   └── detectors/
│       ├── base.py       # BaseDetector, Finding, Confidence
│       ├── python_detector.py  # ast-based
│       ├── java_detector.py    # tree-sitter
│       └── go_detector.py     # tree-sitter
├── tests/
│   ├── fixtures/         # Small .py/.java/.go snippets
│   ├── test_classifier.py
│   ├── test_*_detector.py
├── results/
│   ├── raw/              # Per-repo JSON
│   └── aggregate.csv     # One row per repo
├── docs/
│   ├── SCALING.md       # Running at 10k–50k repos (Codespaces, BigQuery)
│   └── METHODOLOGY.md   # Paper: normalisation, Go TLS, test/vendor, PQC adoption
├── cli.py
├── .env.example
├── requirements.txt
└── README.md
```

## Running tests

From the project root (`pqc-scanner/`):

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

Java/Go detector tests are skipped if `tree-sitter-java` or `tree-sitter-go` are not installed.

## Classification categories

- **post-quantum-vulnerable:** RSA, ECDSA, ECDH, DH, DSA, ElGamal, classic curves (P-256, etc.)
- **quantum-safe:** AES, SHA-2, SHA-3, ChaCha20, HMAC (symmetric/hash only)
- **pqc-ready:** Kyber/ML-KEM, Dilithium/ML-DSA, SPHINCS+, NTRU, liboqs
- **unknown:** Unmapped primitives

Extend `scanner/classifier.py` → `PRIMITIVE_CLASSIFICATION` to add more mappings.

## Design notes

- **Low false positives:** Classification uses exact normalized matches; detectors focus on clear API/import signals.
- **Performance:** File I/O and parsing only; no full-repo load into memory. Tree-sitter is incremental.
- **Exclude tests:** By default, test paths (`test/`, `tests/`, `vendor/`, etc.) are still scanned and tagged with `is_test_file`, but the repo-level vulnerability score uses all findings (vulnerable/total). Use `--exclude-tests` to change behavior if you add summary logic that excludes test findings from the score.

## License

MIT License. See [LICENSE](LICENSE) for details. Use for research and prototyping as needed.
