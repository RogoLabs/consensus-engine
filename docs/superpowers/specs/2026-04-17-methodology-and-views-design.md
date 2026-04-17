# Design: Methodology Hardening & New Frontend Views

**Date:** 2026-04-17
**Status:** Approved
**Author:** Jerry Gamblin + Claude

## Motivation

The Consensus Engine is gaining press. This design addresses two priorities equally:

1. **Methodology hardening** — ensure the data science holds up under peer review
2. **New views** — add charts and pages that vuln managers, researchers, and policy audiences want to see

A deep audit of all four pipeline scripts and seven HTML pages identified issues ranging from a constant masquerading as a variable to a stale hardcoded callout. This spec captures the approved fixes and additions.

---

## Section 1: Critical Methodology Fixes

### 1A. Remove metadata_conflict from drift_score

**Problem:** `metadata_conflict` adds +0.2 to 100% of conflict CVEs (1,552/1,567). GitHub _always_ has `affected` data and NVD _never_ has CPE data for these records. The field is a structural constant, not a per-CVE signal. Every drift score is inflated by the same 0.2, and the formula doesn't match what the site claims (`|GitHub - NVD|`).

**Fix:**

- In `compute_drift.py`, change `compute_drift_score()` so that conflict/gap drift_score = `cvss_variance` only (no metadata_conflict addition)
- Keep the `compute_metadata_conflict()` function and the `metadata_conflict` field in CVE JSON as an annotation — it's still valid data, just doesn't feed the headline number
- The drift_score formula becomes exactly `|GitHub CVSS - NVD CVSS|` as documented

**Impact:** Top leaderboard entries drop from 7.1 to 6.9. All stats recalculate. The formula becomes reproducible by anyone who downloads the CSV.

### 1B. Fix rejected CVE scoring

**Problem:** Rejected CVE drift_score = GitHub CVSS score (e.g., 9.8). This conflates "how severe GitHub thinks it is" with "how much sources disagree." CVE-2022-50807 gets drift_score 9.8 with cvss_variance 0.0.

**Fix:**

- Change `compute_drift_score()` to return `0.0` for `drift_type == "rejected"` regardless of inputs
- The leaderboard already filters to conflict-only (line 382 of build_indexes.py), so no leaderboard change needed
- The `drift_type: "rejected"` flag and `rejected-with-ghsa.csv` remain the way to surface these
- Stats page `rejected_scored_count` continues to report the count (25)

**Rationale:** Rejected CVEs are an "existence dispute," not a "score dispute." They're a different phenomenon that doesn't belong on the same scale.

### 1C. Fix vector-breakdown AC callout

**Problem:** Static hardcoded callout claims Attack Complexity is the primary source of disagreement. Actual ranking: Availability (31.4%) > Confidentiality (29.2%) > Scope (28.3%) > Integrity (27.9%) > AC (26.8%). The callout was likely accurate at an earlier data snapshot but is now wrong.

**Fix:** Make the callout data-driven. On page load:

1. Find the metric with the highest directional skew: `|nvd_higher - gh_higher| / (nvd_higher + gh_higher)`
2. Generate callout text dynamically from that metric's data

AC's actual story is _more interesting_ than raw disagreement rate — it has 92% directional bias (NVD says Low, GitHub says High). The new callout should focus on this:

> "When NVD and GitHub disagree on **Attack Complexity**, NVD rates it as Low (easier to exploit) **92%** of the time. This is the strongest directional bias of any CVSS metric — not random noise, but a systematic difference in how these authorities assess exploitability."

The callout auto-updates as data changes.

---

## Section 2: Important Credibility Additions

### 2A. Variance range filter and noise disclosure

**Problem:** 15.3% of conflicts are Δ < 0.5 (122 are Δ0.1, which could be calculator rounding). Users can't distinguish noise from signal.

**Fix (frontend only, no classification change):**

- Add a variance range filter to the leaderboard toolbar: `All | Δ >= 0.5 | Δ >= 1.0 | Δ >= 2.0` (toggle buttons, same style as existing sort buttons). Default: `All`
- Update the conflict count stat card subtitle to show both raw and filtered: "1,567 total · 1,048 at Δ >= 1.0"

**Rationale:** Changing the conflict classification threshold would be opinionated. Showing the distribution lets users draw their own line.

### 2B. NVD Status disclosure

**Problem:** 110 conflict CVEs (7%) have NVD status "Deferred" — the NVD score is CNA-provided, not independently analyzed. This isn't visible to most users.

**Fix:**

- Change NVD Status column visibility from `lg:table-cell` to `md:table-cell` on the leaderboard
- Add one sentence to the explainer callout: "Some NVD scores are CNA-provided (status: Deferred) rather than independently analyzed by NVD staff."

### 2C. Methodology page

**New file:** `methodology.html` — static page, no data fetches. Linked from nav bar and footer.

**Sections:**

1. **What the Drift Score measures** — `|GitHub CVSS - NVD CVSS|`, same-version only
2. **What counts as a conflict** — both scored, same CVSS version, variance > 0
3. **What counts as a gap** — missing score, cross-version mismatch, or CVSS 0.0
4. **Data sources** — NVD API 2.0 (with note about CNA pass-through for Deferred status) and GitHub Advisory Database
5. **Known limitations:**
   - Ecosystem bias: GitHub Advisory covers software packages (npm, Maven, pip, Go, NuGet, etc.) but not hardware, firmware, or network appliances. The conflict rate is representative of these ecosystems, not all CVEs.
   - Deferred CVEs: ~7% of conflicts use CNA-provided scores via NVD, not NVD's independent analysis.
   - Temporal alignment: NVD and GitHub data are fetched in the same CI run but not simultaneously; scores for very new CVEs could shift between fetches.
   - Rounding: CVSS calculators can produce Δ0.1 differences from identical vector assessments. ~8% of conflicts are Δ0.1.
6. **Update frequency** — daily at 02:00 UTC, incremental
7. **How to cite** — suggested citation format for researchers

**Style:** Same dark theme, header, and footer as existing pages. Prose-heavy, no charts.

---

## Section 3: New Frontend Views

### 3A. Drift Distribution Histogram

**What:** Bar chart showing conflict count per 0.5-point variance bucket (0–0.5, 0.5–1.0, ... 6.5–7.0).

**Where:** New section on `conflict-map.html`, below "Conflicts by Year" chart.

**Data changes:**

- `build_indexes.py`: compute `variance_distribution` array of `{bucket, count}` objects
- Add to `stats.json`

**Frontend:** Chart.js vertical bar chart. Color-coded: green (Δ < 1.0), yellow (1.0–3.0), orange/red (3.0+).

### 3B. Severity Flip Matrix

**What:** 4x4 heatmap grid (Critical/High/Medium/Low on each axis, NVD severity vs GitHub severity) showing conflict counts per cell. Color intensity = count.

**Where:** New section on `conflict-map.html`, below the histogram.

**Data changes:**

- `build_indexes.py`: compute `severity_flip_matrix` as a dict of `"NVD_band→GH_band": count` pairs
- Add to `stats.json`

**Frontend:** HTML table or CSS grid with background color intensity. No Chart.js needed — a styled 4x4 grid is cleaner and more readable for this data shape.

### 3C. Directional Bias Over Time

**What:** Line chart showing NVD-higher count vs GH-higher count by year.

**Where:** New section on `conflict-map.html`, below existing "Conflicts by Year" bar chart. The bar chart shows volume; this shows direction. Natural pairing.

**Data changes:**

- `build_indexes.py`: extend conflict-by-year computation to split by direction
- Add `conflict_direction_by_year` to `stats.json`:
  ```json
  {"2024": {"nvd_higher": 310, "gh_higher": 245}, ...}
  ```

**Frontend:** Chart.js line chart, two lines (orange for NVD-higher, blue for GH-higher).

### 3D. Drift by CWE Category

**What:** Horizontal bar chart showing average variance and conflict count grouped by top 15-20 CWE IDs. Table below with full details.

**Where:** New page: `cwe.html`. Added to nav bar alongside CNAs.

**Data changes:**

- `build_indexes.py`: new `build_cwe_stats()` function computing per-CWE conflict count, avg variance, direction split
- New index file: `cwe-stats.json`
- CWE ID-to-name lookup: hardcoded static map for top ~50 CWEs (they rarely change)

**Frontend:** Same page structure as `cna.html` — stat cards at top, horizontal bar chart, sortable table with columns: CWE ID, Name, Conflict Count, Avg Variance, NVD Higher %, GH Higher %.

---

## Backlog removal

The NVD backlog analysis (analysis lag stats, backlog.json, days_to_analysis in stats.json) is out of scope for this project — it measures NVD operational capacity, not scoring disagreement. This design does NOT include removing it (that's a separate cleanup decision), but none of the new views depend on it.

---

## Implementation Order

1. **Critical fixes (1A, 1B, 1C)** — do first, re-run pipeline, verify stats change as expected
2. **Credibility additions (2A, 2B, 2C)** — methodology page, filters, disclosure text
3. **New views (3A, 3B, 3C, 3D)** — histogram, flip matrix, directional trend, CWE page

Each section can be implemented and verified independently.

---

## Out of Scope

- Removing backlog computation (separate decision)
- Adding new data sources (EPSS, CISA KEV are already in CVE detail page)
- Changing conflict classification threshold
- API/download endpoint for full JSON (nice-to-have, not in this design)
- Mobile-specific layout overhaul
