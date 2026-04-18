# The Consensus Engine — Site Redesign

> **Goal:** Transform the site from a data dashboard into an editorial data journalism piece that tells the story "CVSS scoring disagreement is systematic, not random" — while still serving practitioners who need to drill into the data.

## Design Decisions

- **Audience:** Press/execs (10-second headline), researchers (context and evidence), practitioners (drill-down tables). Inverted pyramid: headline first, depth on demand.
- **Core message:** "Scoring disagreement between authorities is systematic and predictable, and relying on a single source leaves you exposed."
- **Tone:** Editorial / data journalism (think The Pudding, NYT Upshot). Narrative-first, stats as punctuation, charts earn their place by supporting the thesis.
- **Theme:** Light default with dark mode toggle. Light matches the RogoLabs portfolio (rogolabs.net, cve.icu, cnascorecard.org). Dark mode for practitioners who prefer it. Persisted to localStorage.
- **Branding:** "The Consensus Engine" in small uppercase letterspaced type. No lightning bolt emoji. Clean typography carries the brand.
- **Chart philosophy:** Ruthless curation. 5 charts total across the entire site (down from ~10). Each chart must directly support the "systematic, not random" narrative. No scatter plot, no drift histogram, no severity flip matrix.

## Information Architecture

| Page              | File               | Purpose                                               | Visualizations                                              |
| ----------------- | ------------------ | ----------------------------------------------------- | ----------------------------------------------------------- |
| Homepage          | `index.html`       | Editorial thesis + key stats                          | Conflicts by Year stacked bar (1)                           |
| How They Disagree | `patterns.html`    | Patterns in disagreement — metrics, direction, trends | Directional Bias line chart (1) + 8 metric cards            |
| Who Disagrees     | `sources.html`     | CNA + CWE analysis combined                           | CNA bar chart (1) + CWE bar chart (1) + 2 searchable tables |
| The Data          | `data.html`        | Conflict explorer + coverage gaps                     | Tables with search/filter, no charts                        |
| CVE Detail        | `cve.html`         | Individual CVE deep-dive                              | Restyled to match new design system                         |
| Methodology       | `methodology.html` | Data sources, limitations, citation                   | Restyled, text updated for new schedule                     |

**Navigation:** Horizontal nav bar — `The Consensus Engine` (left, site name) | `How They Disagree` | `Who Disagrees` | `The Data` | `Methodology` (center/right) | dark mode toggle + GitHub link (far right). Current page indicated by font weight. On mobile, a hamburger menu for hidden items.

### What Gets Cut

- **Scatter plot** (`conflict-map.html` main chart) — visually busy, doesn't support "systematic" thesis
- **Drift score histogram** — methodology detail, not narrative
- **Severity flip matrix** (4×4 table) — becomes a callout stat: "X CVEs cross severity band boundaries"
- **Lightning bolt emoji** — replaced by clean typography
- **`conflict-map.html`** — page eliminated; its Conflicts by Year chart moves to homepage, Directional Bias chart moves to patterns.html
- **`vector-breakdown.html`** — page eliminated; metric cards and directional bias callout move to patterns.html
- **`coverage-gap.html`** — page eliminated; table folds into data.html as a section
- **`cna.html`** — page eliminated; content moves to sources.html CNA section
- **`cwe.html`** — page eliminated; content moves to sources.html CWE section

### What Gets Kept

- **Conflicts by Year** stacked bar — hero chart on homepage, shows the problem is growing
- **Directional Bias Over Time** line chart — proves "systematic" thesis with trend data
- **Vector breakdown metric cards** (8 cards) — compact, informative, show per-metric disagreement rates with directional bars
- **CNA horizontal bar chart** — names names, compelling for accountability
- **CWE horizontal bar chart** — shows which vuln types have worst disagreement
- **Strongest Directional Bias callout** — auto-detected, data-driven insight
- **All searchable/sortable tables** — practitioners need these for drill-down
- **CVE nutrition label** — good concept, just needs visual alignment
- **Coverage gap data** — important for the "single source leaves you exposed" message

## Visual Design System

### Theme Tokens (CSS Custom Properties)

**Light mode (default):**

- `--bg-primary: #f8fafc`
- `--bg-card: #ffffff`
- `--border: #e2e8f0`
- `--text-primary: #0f172a`
- `--text-secondary: #64748b`
- `--text-muted: #94a3b8`

**Dark mode:**

- `--bg-primary: #0f1117`
- `--bg-card: #1a1d2e`
- `--border: #2d3748`
- `--text-primary: #f3f4f6`
- `--text-secondary: #9ca3af`
- `--text-muted: #6b7280`

**Shared (both modes):**

- `--brand: #2563eb` (light) / `#3b82f6` (dark)
- `--danger: #dc2626` (light) / `#ef4444` (dark)
- `--warning: #d97706` (light) / `#f59e0b` (dark)
- `--nvd-higher: #fb923c` (orange, both modes)
- `--gh-higher: #60a5fa` (blue, both modes)

### Typography

- **Font:** Inter via Google Fonts (weights 300, 400, 500, 600, 700)
- **Site name:** 11px, uppercase, letter-spacing 3px, `--text-muted`
- **Page headlines:** 28-32px, weight 700, line-height 1.2
- **Headline accent (key stat):** `--warning` color (amber/orange)
- **Body prose:** 14-15px, weight 400, line-height 1.7, `--text-secondary`
- **Stat numbers:** 32-36px, weight 300 (light weight = editorial feel)
- **Labels:** 11px, uppercase, letter-spacing 1-2px, `--text-muted`
- **Monospace:** system monospace for CVE IDs, scores, code references

### Cards & Containers

- Card background: `--bg-card` with `1px solid var(--border)` and subtle shadow in light mode
- 8px border-radius consistently
- No gradient accent bars, no hover lift effects — clean and flat
- Section dividers: `1px solid var(--border)` horizontal rules (newspaper style)

### Spacing

- Max content width: `max-w-5xl` (64rem / 1024px) for editorial pages (homepage, patterns, methodology)
- Max content width: `max-w-7xl` (80rem / 1280px) for data-heavy pages (sources, data explorer)
- Section gaps: generous, separated by borders not just whitespace
- Stat rows: column dividers between items (newspaper style)

## Page Layouts

### Homepage (`index.html`)

1. **Header:** Horizontal nav with site name, page links, dark mode toggle, GitHub link
2. **Hero block:**
   - Site name (small, uppercase, letterspaced)
   - Headline: "Two authorities score the same vulnerability. _They disagree X% of the time._" (X pulled from stats.json, amber accent on the stat)
   - Two sentences of context prose explaining what the Consensus Engine tracks
3. **Stat row** with column dividers:
   - Conflict rate (%)
   - Severity flips (count)
   - Average score gap (Δ)
4. **Hero chart:** Conflicts by Year stacked bar
   - One-line editorial intro above: "The problem is growing."
   - NVD-higher in orange, GH-higher in blue
5. **Navigation cards** (3-column grid):
   - "How They Disagree →" — "Patterns in directional bias, metrics, and severity"
   - "Who Disagrees →" — "Which CNAs and CWE types drive the most conflict"
   - "The Data →" — "Explore all conflicts, search by CVE, filter by drift"
6. **Footer:** attribution (Jerry Gamblin at RogoLabs), GitHub link, data sources, last updated timestamp

### How They Disagree (`patterns.html`)

1. **Header** (same nav across all pages)
2. **Page title:** "How They Disagree"
3. **Context prose:** 2 sentences explaining the systematic nature of disagreement
4. **Strongest Directional Bias callout:** amber-tinted box, auto-detected from data — e.g., "When NVD and GitHub disagree on Scope, NVD assigns the more severe value 78% of the time."
5. **Metric cards:** 4×2 grid of 8 CVSS metrics. Each card shows:
   - Metric key (AV, AC, PR, UI, S, C, I, A)
   - Metric name
   - Disagreement rate % (color-coded: red ≥25%, yellow ≥12%, green otherwise)
   - Small horizontal directional bar (orange = NVD higher, blue = GH higher)
6. **Directional Bias Over Time:** line chart showing NVD-higher % vs GH-higher % by year
   - One-line editorial intro: "NVD has scored higher than GitHub in every year since 2019."
7. **Severity flip callout:** "X CVEs cross severity band boundaries — a High in one source is a Medium or Critical in the other." (stat pulled from stats.json, not a matrix visualization)
8. **Footer**

### Who Disagrees (`sources.html`)

1. **Header**
2. **Page title:** "Who Disagrees"
3. **Context prose:** "Conflict isn't uniformly distributed. Certain CVE Numbering Authorities and vulnerability types account for disproportionate disagreement."
4. **CNA section:**
   - Section label: "By CNA (Scoring Organization)"
   - Horizontal bar chart: top 15 CNAs by conflict rate
   - Searchable/sortable table below: CNA name, conflict rate (with progress bar), conflict count, total CVEs, avg drift, NVD higher %, GH higher %
5. **CWE section** (separated by border):
   - Section label: "By CWE (Vulnerability Type)"
   - Horizontal bar chart: top 15 CWEs by avg drift
   - Searchable/sortable table below: CWE ID, name, conflict count, avg drift, NVD higher %, GH higher %
6. **Footer**

### The Data (`data.html`)

1. **Header**
2. **Page title:** "The Data"
3. **Subtitle:** "Search, filter, and explore all scoring conflicts. Updated every six hours."
4. **Filter bar:**
   - Search input (by CVE ID)
   - Drift threshold buttons: All | ≥Δ0.5 | ≥Δ1.0 | ≥Δ2.0
   - Toggle: "Severity flips only"
   - Toggle: "Hide CNA pass-through"
5. **Conflict table:** CVE ID (linked to detail), NVD score, GitHub score, Drift score, CNA, NVD Status, Published date
   - Sorted by drift score descending by default
   - Showing count: "X total · Y shown"
6. **Coverage Gaps section** (separated by border):
   - Section label: "Coverage Gaps"
   - Context: "CVEs scored by GitHub but missing from NVD — invisible to NVD-only tools."
   - Table: CVE ID, GitHub score, severity, NVD status, published date, GHSA ID
7. **Footer**

### CVE Detail (`cve.html`)

- Restyle to match new design system: light default background, proper header/nav (not just a back link), Inter font (not monospace body), same card styling
- Keep nutrition label concept and source scores section
- Add dark mode support via same CSS custom properties

### Methodology (`methodology.html`)

- Same content structure, restyled with new typography and theme tokens
- Update text: "Data is updated every six hours and on every push" (replaces "daily at 02:00 UTC")
- Narrow reading column (`max-w-3xl`) is correct, keep it
- Add dark mode support

## GitHub Actions Changes

**Current trigger:**

```yaml
schedule:
  - cron: "0 2 * * *"
```

**New trigger:**

```yaml
on:
  push:
    branches: [main]
  schedule:
    - cron: "0 */6 * * *"
```

This runs the ingestion pipeline on every push to main and every 6 hours (00:00, 06:00, 12:00, 18:00 UTC). The methodology page text updates to reflect this.

## Footer (Consistent Across All Pages)

All pages use the same footer:

- "Built by Jerry Gamblin at RogoLabs · GitHub · Data: NVD API 2.0 · GitHub Advisory Database"
- Last updated timestamp (from stats.json `generated_at`)

## Constraints

- **No backend, no database.** Flat JSON files, static HTML, CDN dependencies only.
- **No build step.** All HTML is hand-authored, served from `docs/`.
- **Tailwind CSS via CDN** with inline config for custom properties.
- **Alpine.js via CDN** for component state.
- **Chart.js via CDN** for charts.
- **Dark mode toggle** persists to localStorage, applies a class on `<html>` that flips CSS custom properties.
- **All aggregates pre-computed** by the Python pipeline into `docs/data/indexes/`. No client-side computation of rankings or statistics.
