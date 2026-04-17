# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**The Consensus Engine** tracks CVSS scoring divergence between NVD (National Vulnerability Database) and the GitHub Advisory Database. It measures the "Data Integrity Gap" — where two authoritative sources score the same CVE differently.

**Core constraint: No backend, no database.** The repository _is_ the database (flat JSON files). All processing runs in GitHub Actions; the UI is 100% client-side on GitHub Pages.

## Commands

```bash
# Install Python dependencies
pip install -r scripts/requirements.txt

# Run ingestion pipeline (requires NVD_API_KEY and GH_TOKEN env vars)
python scripts/ingest_nvd.py
python scripts/ingest_github.py
python scripts/compute_drift.py
python scripts/build_cna_map.py
python scripts/build_indexes.py

# Serve locally
python -m http.server 8080 --directory docs
```

There is no build step, no linter, no test suite, and no package.json. The frontend is static HTML served from `docs/`.

## Architecture

```
scripts/              Python data pipeline (runs in GitHub Actions daily at 02:00 UTC)
  ingest_nvd.py       Fetch NVD API 2.0 (120-day windows, tenacity retry)
  ingest_github.py    Fetch GitHub Advisory DB (GHSA → CVE mapping)
  compute_drift.py    Calculate drift scores, classify conflict/gap/rejected
  build_cna_map.py    Resolve NVD CNA UUIDs → human-readable names
  build_indexes.py    Generate all pre-computed JSON indexes and CSV exports

docs/                 GitHub Pages root (everything here is deployed)
  index.html          Drift Leaderboard (top 500 conflicts)
  conflict-map.html   NVD vs GitHub scatter plot + year-over-year chart
  vector-breakdown.html  Per-CVSS-metric disagreement analysis
  cna.html            CNA-level conflict statistics
  coverage-gap.html   CVEs scored by GitHub but missing from NVD
  cve.html            Individual CVE detail page (?id=CVE-XXXX-XXXXX)
  data/{year}/        Individual CVE JSON files (137k+ files)
  data/indexes/       Pre-computed aggregates (leaderboard, stats, etc.)
  data/conflicts.csv  CSV export of all conflicts
```

### Data Flow

1. **Ingest**: Python scripts fetch NVD API 2.0 and GitHub Advisory DB (incremental: last 25-48 hours after initial backfill)
2. **Store**: Raw data merged into `docs/data/{year}/CVE-{ID}.json`
3. **Compute**: Drift scores calculated — `|GitHub CVSS − NVD CVSS|` within same CVSS version only
4. **Index**: Pre-computed JSON indexes generated for all frontend views
5. **Deploy**: GitHub Actions commits changes and deploys to GitHub Pages

### Critical Rules

- **Never compare CVSS scores across versions** (v3.1 vs v4.0 is invalid → classified as `gap`)
- **Never compute rankings client-side** — there are 240k+ CVEs; all aggregates must be pre-computed by CI into `docs/data/indexes/`
- **Never introduce a database** — flat JSON files in the repo are the storage layer
- `drift_type` is one of: `"conflict"` (both scored, values differ), `"gap"` (missing score or version mismatch), `"rejected"` (NVD rejected but GitHub scores it)

### Frontend Stack

- **Tailwind CSS** via CDN (dark theme, no config file)
- **Alpine.js** via CDN (component state in `x-data`, no build step)
- **Chart.js** via CDN (scatter plots, bar charts)
- All data loaded at runtime via `fetch('data/indexes/*.json')`

### NVD API Rate Limits

- Without API key: 5 requests / 30 seconds
- With API key: 50 requests / 30 seconds
- Scripts use tenacity retry with exponential backoff; 0.7s between requests with key
