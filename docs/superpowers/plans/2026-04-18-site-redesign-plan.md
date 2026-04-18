# Site Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform The Consensus Engine from a data dashboard into an editorial data journalism site with light/dark theme, consolidated pages (8 → 6), and ruthlessly curated charts (10 → 5).

**Architecture:** Each HTML page is self-contained static HTML using Tailwind CSS, Alpine.js, and Chart.js via CDN. Dark mode is toggled via a `dark` class on `<html>`, which flips CSS custom properties. All data comes from pre-computed JSON indexes in `docs/data/indexes/`. No build step, no backend.

**Tech Stack:** HTML, Tailwind CSS (CDN), Alpine.js 3.x (CDN), Chart.js 4.x (CDN), GitHub Actions

**Spec:** `docs/superpowers/specs/2026-04-18-site-redesign-design.md`

---

## File Structure

**Create (new files):**

- `docs/patterns.html` — "How They Disagree" page (merges conflict-map + vector-breakdown)
- `docs/sources.html` — "Who Disagrees" page (merges cna + cwe)
- `docs/data.html` — "The Data" page (merges leaderboard + coverage-gap)

**Rewrite (existing files, full replacement):**

- `docs/index.html` — New editorial homepage
- `docs/cve.html` — Restyled to match new design system
- `docs/methodology.html` — Restyled with dark mode + updated text

**Modify:**

- `.github/workflows/ingest.yml` — Add `on: push` trigger, change cron to every 6 hours

**Delete (after all new pages are verified):**

- `docs/conflict-map.html`
- `docs/vector-breakdown.html`
- `docs/cna.html`
- `docs/cwe.html`
- `docs/coverage-gap.html`

---

### Task 1: Update GitHub Actions Workflow

**Files:**

- Modify: `.github/workflows/ingest.yml:3-6`

This is the smallest, most isolated change — get it done first.

- [ ] **Step 1: Update the workflow triggers**

In `.github/workflows/ingest.yml`, replace lines 3-6:

```yaml
on:
  schedule:
    - cron: "0 2 * * *" # Daily at 02:00 UTC
  workflow_dispatch: # Allow manual runs
```

with:

```yaml
on:
  push:
    branches: [main]
  schedule:
    - cron: "0 */6 * * *" # Every 6 hours
  workflow_dispatch: # Allow manual runs
```

- [ ] **Step 2: Update the commit message template**

In the same file, replace line 67:

```yaml
git commit -m "chore: daily ingest $(date -u '+%Y-%m-%d')"
```

with:

```yaml
git commit -m "chore: ingest $(date -u '+%Y-%m-%dT%H:%M')"
```

- [ ] **Step 3: Verify the YAML is valid**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ingest.yml')); print('Valid YAML')"`
Expected: `Valid YAML`

If `yaml` module not available: `python3 -c "import json; print('skip yaml check — visual inspection only')"`

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ingest.yml
git commit -m "ci: run pipeline on push and every 6 hours"
```

---

### Task 2: Create the Homepage (`index.html`)

**Files:**

- Rewrite: `docs/index.html`

This is the editorial landing page. It fetches `stats.json` and `conflict-map.json` (for the Conflicts by Year chart). It does NOT show the leaderboard table — that moves to `data.html`.

- [ ] **Step 1: Write the complete homepage**

Write `docs/index.html` with the following structure. The complete HTML is below.

Key implementation details:

- Alpine.js component: `homePage()`
- Fetches: `data/indexes/stats.json`, `data/indexes/conflict-map.json`
- One Chart.js chart: `yearChart` (stacked bar, Conflicts by Year)
- Dark mode toggle: reads/writes `localStorage.getItem('theme')`, toggles `dark` class on `<html>`
- CSS custom properties defined in `<style>` block for both `:root` (light) and `.dark` (dark) selectors
- Tailwind config extended with CSS variable references

```html
<!doctype html>
<html lang="en" class="h-full">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>The Consensus Engine</title>
    <meta
      name="description"
      content="CVSS scoring disagreement between NVD and GitHub Advisory is systematic, not random. Tracking divergence across 130,000+ CVEs."
    />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link
      href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap"
      rel="stylesheet"
    />
    <script>
      if (
        localStorage.getItem("theme") === "dark" ||
        (!localStorage.getItem("theme") &&
          window.matchMedia("(prefers-color-scheme: dark)").matches)
      ) {
        document.documentElement.classList.add("dark");
      }
    </script>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
      tailwind.config = {
        darkMode: "class",
        theme: {
          extend: {
            fontFamily: { sans: ["Inter", "ui-sans-serif", "system-ui"] },
            colors: {
              surface: {
                DEFAULT: "var(--bg-primary)",
                card: "var(--bg-card)",
                border: "var(--border)",
              },
              brand: {
                DEFAULT: "var(--brand)",
                light: "var(--brand-light)",
              },
            },
          },
        },
      };
    </script>
    <script
      defer
      src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"
    ></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
    <style>
      :root {
        --bg-primary: #f8fafc;
        --bg-card: #ffffff;
        --border: #e2e8f0;
        --text-primary: #0f172a;
        --text-secondary: #64748b;
        --text-muted: #94a3b8;
        --brand: #2563eb;
        --brand-light: #3b82f6;
        --danger: #dc2626;
        --warning: #d97706;
        --nvd-higher: #fb923c;
        --gh-higher: #60a5fa;
        --chart-grid: rgba(148, 163, 184, 0.2);
        --chart-text: #64748b;
      }
      .dark {
        --bg-primary: #0f1117;
        --bg-card: #1a1d2e;
        --border: #2d3748;
        --text-primary: #f3f4f6;
        --text-secondary: #9ca3af;
        --text-muted: #6b7280;
        --brand: #3b82f6;
        --brand-light: #60a5fa;
        --danger: #ef4444;
        --warning: #f59e0b;
        --nvd-higher: #fb923c;
        --gh-higher: #60a5fa;
        --chart-grid: rgba(45, 55, 72, 0.8);
        --chart-text: #6b7280;
      }
      body {
        font-family: "Inter", ui-sans-serif, system-ui;
        background: var(--bg-primary);
        color: var(--text-primary);
      }
    </style>
  </head>
  <body class="min-h-full">
    <!-- Header -->
    <header
      class="border-b sticky top-0 z-40"
      style="
        border-color: var(--border);
        background: var(--bg-primary);
      "
    >
      <div
        class="max-w-5xl mx-auto px-4 sm:px-6 py-3 flex items-center justify-between gap-4"
      >
        <div class="flex items-center gap-6">
          <a
            href="index.html"
            class="font-semibold text-sm tracking-wide uppercase"
            style="color: var(--text-muted); letter-spacing: 0.1em"
            >The Consensus Engine</a
          >
          <nav
            class="hidden sm:flex items-center gap-4 text-sm"
            style="color: var(--text-secondary)"
          >
            <a href="patterns.html" class="hover:opacity-80 transition-opacity"
              >How They Disagree</a
            >
            <a href="sources.html" class="hover:opacity-80 transition-opacity"
              >Who Disagrees</a
            >
            <a href="data.html" class="hover:opacity-80 transition-opacity"
              >The Data</a
            >
            <a
              href="methodology.html"
              class="hover:opacity-80 transition-opacity"
              >Methodology</a
            >
          </nav>
        </div>
        <div class="flex items-center gap-3">
          <button
            onclick="document.documentElement.classList.toggle('dark'); localStorage.setItem('theme', document.documentElement.classList.contains('dark') ? 'dark' : 'light')"
            class="p-1.5 rounded-md hover:opacity-80 transition-opacity"
            style="color: var(--text-muted)"
            aria-label="Toggle dark mode"
          >
            <svg
              class="w-4 h-4 dark:hidden"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                stroke-width="2"
                d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"
              />
            </svg>
            <svg
              class="w-4 h-4 hidden dark:block"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                stroke-width="2"
                d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"
              />
            </svg>
          </button>
          <!-- Mobile menu button -->
          <button
            class="sm:hidden p-1.5 rounded-md hover:opacity-80"
            style="color: var(--text-muted)"
            onclick="document.getElementById('mobile-nav').classList.toggle('hidden')"
            aria-label="Menu"
          >
            <svg
              class="w-5 h-5"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                stroke-width="2"
                d="M4 6h16M4 12h16M4 18h16"
              />
            </svg>
          </button>
          <a
            href="https://github.com/RogoLabs/consensus-engine"
            target="_blank"
            rel="noopener"
            class="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-opacity hover:opacity-80"
            style="
              border: 1px solid var(--border);
              color: var(--text-secondary);
            "
          >
            <svg class="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 24 24">
              <path
                d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"
              />
            </svg>
            GitHub
          </a>
        </div>
      </div>
      <!-- Mobile nav dropdown -->
      <div
        id="mobile-nav"
        class="hidden sm:hidden border-t px-4 py-3 space-y-2 text-sm"
        style="border-color: var(--border); color: var(--text-secondary)"
      >
        <a href="patterns.html" class="block py-1">How They Disagree</a>
        <a href="sources.html" class="block py-1">Who Disagrees</a>
        <a href="data.html" class="block py-1">The Data</a>
        <a href="methodology.html" class="block py-1">Methodology</a>
        <a
          href="https://github.com/RogoLabs/consensus-engine"
          target="_blank"
          rel="noopener"
          class="block py-1"
          >GitHub</a
        >
      </div>
    </header>

    <main
      x-data="homePage()"
      x-init="init()"
      class="max-w-5xl mx-auto px-4 sm:px-6"
    >
      <!-- Hero -->
      <div class="py-12 sm:py-16">
        <div
          class="text-xs font-semibold uppercase tracking-[0.2em] mb-4"
          style="color: var(--text-muted)"
        >
          The Consensus Engine
        </div>
        <h1
          class="text-3xl sm:text-4xl font-bold leading-tight mb-4"
          style="color: var(--text-primary)"
        >
          Two authorities score the same vulnerability.
          <br />
          <span style="color: var(--warning)"
            >They disagree
            <span x-text="stats ? stats.conflict_rate + '%' : '...'"></span> of
            the time.</span
          >
        </h1>
        <p
          class="text-base leading-relaxed max-w-2xl"
          style="color: var(--text-secondary)"
        >
          When NVD and GitHub Advisory both assign a CVSS score to the same CVE,
          their scores differ more often than they agree — and the disagreement
          isn't random. It follows predictable patterns across vulnerability
          types, scoring organizations, and individual CVSS metrics.
        </p>
      </div>

      <!-- Stat row -->
      <div
        class="flex flex-col sm:flex-row border-y"
        style="border-color: var(--border)"
      >
        <div
          class="flex-1 py-5 sm:py-6 px-1 sm:border-r"
          style="border-color: var(--border)"
        >
          <div
            class="text-3xl sm:text-4xl font-light"
            style="color: var(--text-primary)"
          >
            <span x-text="stats ? stats.conflict_rate + '%' : '...'"></span>
          </div>
          <div class="text-xs mt-1" style="color: var(--text-muted)">
            of dual-scored CVEs conflict
          </div>
        </div>
        <div
          class="flex-1 py-5 sm:py-6 sm:px-6 sm:border-r"
          style="border-color: var(--border)"
        >
          <div
            class="text-3xl sm:text-4xl font-light"
            style="color: var(--danger)"
          >
            <span
              x-text="stats ? stats.severity_flip_count.toLocaleString() : '...'"
            ></span>
          </div>
          <div class="text-xs mt-1" style="color: var(--text-muted)">
            cross severity band boundaries
          </div>
        </div>
        <div class="flex-1 py-5 sm:py-6 sm:px-6">
          <div
            class="text-3xl sm:text-4xl font-light"
            style="color: var(--warning)"
          >
            <span x-text="stats ? 'Δ ' + stats.avg_variance : '...'"></span>
          </div>
          <div class="text-xs mt-1" style="color: var(--text-muted)">
            average score gap
          </div>
        </div>
      </div>

      <!-- Hero chart: Conflicts by Year -->
      <div class="py-10">
        <p class="text-sm mb-4" style="color: var(--text-secondary)">
          The problem is growing.
        </p>
        <div
          class="rounded-lg p-4 sm:p-6"
          style="
            background: var(--bg-card);
            border: 1px solid var(--border);
          "
        >
          <div class="relative" style="height: 280px">
            <canvas id="yearChart"></canvas>
          </div>
        </div>
      </div>

      <!-- Navigation cards -->
      <div class="grid grid-cols-1 sm:grid-cols-3 gap-4 pb-12">
        <a
          href="patterns.html"
          class="block rounded-lg p-5 transition-opacity hover:opacity-80"
          style="
            background: var(--bg-card);
            border: 1px solid var(--border);
          "
        >
          <div
            class="font-semibold text-sm mb-1"
            style="color: var(--text-primary)"
          >
            How They Disagree →
          </div>
          <div class="text-xs" style="color: var(--text-muted)">
            Patterns in directional bias, metrics, and severity
          </div>
        </a>
        <a
          href="sources.html"
          class="block rounded-lg p-5 transition-opacity hover:opacity-80"
          style="
            background: var(--bg-card);
            border: 1px solid var(--border);
          "
        >
          <div
            class="font-semibold text-sm mb-1"
            style="color: var(--text-primary)"
          >
            Who Disagrees →
          </div>
          <div class="text-xs" style="color: var(--text-muted)">
            Which CNAs and CWE types drive the most conflict
          </div>
        </a>
        <a
          href="data.html"
          class="block rounded-lg p-5 transition-opacity hover:opacity-80"
          style="
            background: var(--bg-card);
            border: 1px solid var(--border);
          "
        >
          <div
            class="font-semibold text-sm mb-1"
            style="color: var(--text-primary)"
          >
            The Data →
          </div>
          <div class="text-xs" style="color: var(--text-muted)">
            Explore all conflicts, search by CVE, filter by drift
          </div>
        </a>
      </div>
    </main>

    <!-- Footer -->
    <footer class="border-t py-6" style="border-color: var(--border)">
      <div
        class="max-w-5xl mx-auto px-4 sm:px-6 flex flex-col sm:flex-row items-center justify-between gap-2 text-xs"
        style="color: var(--text-muted)"
      >
        <div class="flex items-center gap-3 flex-wrap justify-center">
          <span>
            Built by
            <a
              href="https://rogolabs.net"
              class="hover:underline"
              style="color: var(--brand)"
              >Jerry Gamblin at RogoLabs</a
            >
          </span>
          <span>·</span>
          <a
            href="https://github.com/RogoLabs/consensus-engine"
            class="hover:underline"
            style="color: var(--brand)"
            >GitHub</a
          >
          <span>·</span>
          <span>Data: NVD API 2.0 · GitHub Advisory Database</span>
        </div>
        <div
          x-show="stats"
          x-text="stats ? `Updated ${new Date(stats.generated_at).toLocaleDateString('en-US', {month:'short',day:'numeric',year:'numeric'})}` : ''"
        ></div>
      </div>
    </footer>

    <script>
      function homePage() {
        return {
          stats: null,
          entries: [],

          async init() {
            try {
              const [statsRes, mapRes] = await Promise.all([
                fetch("data/indexes/stats.json"),
                fetch("data/indexes/conflict-map.json"),
              ]);
              if (statsRes.ok) this.stats = await statsRes.json();
              if (mapRes.ok) this.entries = await mapRes.json();
            } catch (e) {
              console.error("Failed to load data:", e);
            }
            if (this.stats) this.$nextTick(() => this.buildYearChart());
          },

          buildYearChart() {
            const byYear = {};
            for (const e of this.entries) {
              const year = e.published_date
                ? e.published_date.slice(0, 4)
                : "Unknown";
              if (!byYear[year]) byYear[year] = { nvdHigher: 0, ghHigher: 0 };
              if ((e.nvd_score ?? 0) > (e.github_score ?? 0))
                byYear[year].nvdHigher++;
              else byYear[year].ghHigher++;
            }
            const years = Object.keys(byYear)
              .filter(
                (y) =>
                  y !== "Unknown" &&
                  byYear[y].nvdHigher + byYear[y].ghHigher >= 5,
              )
              .sort();
            const nvdData = years.map((y) => byYear[y].nvdHigher);
            const ghData = years.map((y) => byYear[y].ghHigher);

            const ctx = document.getElementById("yearChart");
            if (!ctx) return;
            new Chart(ctx, {
              type: "bar",
              data: {
                labels: years,
                datasets: [
                  {
                    label: "NVD scores higher",
                    data: nvdData,
                    backgroundColor: "var(--nvd-higher)",
                  },
                  {
                    label: "GitHub scores higher",
                    data: ghData,
                    backgroundColor: "var(--gh-higher)",
                  },
                ],
              },
              options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                plugins: {
                  legend: {
                    display: true,
                    labels: {
                      color: getComputedStyle(document.documentElement)
                        .getPropertyValue("--chart-text")
                        .trim(),
                      font: { family: "Inter", size: 11 },
                    },
                  },
                },
                scales: {
                  x: {
                    stacked: true,
                    ticks: {
                      color: getComputedStyle(document.documentElement)
                        .getPropertyValue("--chart-text")
                        .trim(),
                    },
                    grid: {
                      color: getComputedStyle(document.documentElement)
                        .getPropertyValue("--chart-grid")
                        .trim(),
                    },
                  },
                  y: {
                    stacked: true,
                    title: {
                      display: true,
                      text: "Conflicts",
                      color: getComputedStyle(document.documentElement)
                        .getPropertyValue("--chart-text")
                        .trim(),
                      font: { family: "Inter", size: 12 },
                    },
                    ticks: {
                      color: getComputedStyle(document.documentElement)
                        .getPropertyValue("--chart-text")
                        .trim(),
                    },
                    grid: {
                      color: getComputedStyle(document.documentElement)
                        .getPropertyValue("--chart-grid")
                        .trim(),
                    },
                  },
                },
              },
            });
          },
        };
      }
    </script>
  </body>
</html>
```

- [ ] **Step 2: Serve locally and verify**

Run: `python -m http.server 8080 --directory docs`

Open `http://localhost:8080/` and verify:

- Light theme loads by default
- Dark mode toggle works (moon/sun icon)
- Stats load from JSON (conflict rate, severity flips, avg variance)
- Conflicts by Year chart renders with stacked orange/blue bars
- Three navigation cards link to correct pages
- Mobile hamburger menu shows/hides nav items
- Footer shows "Updated" date

- [ ] **Step 3: Commit**

```bash
git add docs/index.html
git commit -m "feat: redesign homepage with editorial layout and dark mode"
```

---

### Task 3: Create "How They Disagree" (`patterns.html`)

**Files:**

- Create: `docs/patterns.html`

Merges content from the old `conflict-map.html` (directional bias chart) and `vector-breakdown.html` (metric cards + strongest bias callout). Fetches `stats.json` and `vector-analysis.json`.

- [ ] **Step 1: Write the complete patterns page**

Write `docs/patterns.html`. This page reuses the same `<head>` boilerplate (CSS variables, Tailwind config, Inter font, dark mode script) from Task 2's `index.html`. Copy that entire `<head>` block, changing only the `<title>` to `How They Disagree — The Consensus Engine`.

The header and footer are identical to `index.html` except: in the nav, `How They Disagree` uses `font-weight: 600` (bold) instead of being a link.

Alpine.js component: `patternsPage()`

Properties:

- `loading: true`
- `error: null`
- `stats: null` — from `data/indexes/stats.json`
- `vectorData: null` — from `data/indexes/vector-analysis.json`

Computed properties:

- `topSkew` — finds the metric with the strongest directional bias (same logic as old `vector-breakdown.html` lines 403-424): iterate `vectorData.metrics`, compute `|nvd_higher_count - gh_higher_count| / (nvd_higher_count + gh_higher_count)` for each metric with 10+ total disagreements, return the metric with the highest skew ratio plus a `skewPct` field (the dominant side's percentage)

Methods:

- `init()` — fetches both JSON files, then calls `buildDirectionChart()`
- `rateColor(rate)` — returns a CSS class: red text for rate ≥25, yellow for ≥12, green otherwise. Use inline styles with `var(--danger)` / `var(--warning)` / green.
- `directionPct(m, which)` — returns the percentage width for the directional bar. Same logic as old vector-breakdown: `nvd_higher_count / (nvd_higher_count + gh_higher_count) * 100`
- `buildDirectionChart()` — renders the Directional Bias Over Time line chart using `stats.conflict_direction_by_year`. Chart ID: `directionChart`. Two datasets: NVD-higher % (orange line with fill) and GH-higher % (blue line with fill).

Page body structure:

1. Header (same as homepage, with `How They Disagree` bolded in nav)
2. `<main class="max-w-5xl mx-auto px-4 sm:px-6 py-10">`
3. Page title: `<h1>` "How They Disagree" + 2-sentence context paragraph
4. Strongest Directional Bias callout — amber-tinted box: `background: color-mix(in srgb, var(--warning) 8%, transparent); border: 1px solid color-mix(in srgb, var(--warning) 20%, transparent);`
5. Section label "Per-metric disagreement rate" (11px uppercase)
6. 8 metric cards in a `grid grid-cols-2 sm:grid-cols-4 gap-3` — each card shows: metric key (monospace, bold, brand color), metric name, disagreement rate % (large, color-coded), small horizontal directional bar (orange/blue `div`s with percentage widths), counts below bar ("NVD higher: X" / "GH higher: X")
7. Directional Bias Over Time chart in a card container
8. Severity flip callout: "X CVEs cross severity band boundaries — a High in one source is a Medium or Critical in the other." where X = `stats.severity_flip_count`
9. Footer

The `<script>` block contains the `patternsPage()` function with all the above logic.

- [ ] **Step 2: Serve locally and verify**

Run: `python -m http.server 8080 --directory docs`

Open `http://localhost:8080/patterns.html` and verify:

- Strongest bias callout renders with correct metric name and percentage
- 8 metric cards show with disagreement rates and directional bars
- Directional Bias Over Time line chart renders
- Severity flip callout shows correct count
- Dark mode toggle works
- Navigation links work

- [ ] **Step 3: Commit**

```bash
git add docs/patterns.html
git commit -m "feat: add How They Disagree page (patterns)"
```

---

### Task 4: Create "Who Disagrees" (`sources.html`)

**Files:**

- Create: `docs/sources.html`

Merges CNA analysis and CWE analysis onto one page. Fetches `cna-stats.json` and `cwe-stats.json`. Two sections, each with a horizontal bar chart and a searchable/sortable table.

- [ ] **Step 1: Write the complete sources page**

Write `docs/sources.html`. Same `<head>` boilerplate as previous pages. Title: `Who Disagrees — The Consensus Engine`.

Alpine.js component: `sourcesPage()`

Properties:

- `loading: true`
- `error: null`
- `cnas: []` — from `cna-stats.json`
- `cwes: []` — from `cwe-stats.json`
- `cnaSort: "conflict_rate"` — default CNA sort
- `cweSort: "conflict_count"` — default CWE sort
- `cnaSearch: ""`
- `cweSearch: ""`
- `generatedAt: null`

Computed properties:

- `filteredCnas` — sorts by `cnaSort` descending, filters by `cnaSearch` matching `name`
- `filteredCwes` — sorts by `cweSort` descending, filters by `cweSearch` matching `cwe_id` or `name`

Methods:

- `init()` — fetches both JSON files, stores arrays and `generated_at`, then calls `buildCnaChart()` and `buildCweChart()`
- `buildCnaChart()` — horizontal bar chart (Chart.js, `indexAxis: 'y'`), top 15 CNAs by conflict rate. Chart ID: `cnaChart`. Color-coded: red ≥30, yellow ≥15, green otherwise.
- `buildCweChart()` — horizontal bar chart, top 15 CWEs by avg drift. Chart ID: `cweChart`. Color-coded: red ≥3.0, yellow ≥1.5, green otherwise.

This page uses `max-w-7xl` (wider container for tables).

Page body structure:

1. Header (same, `Who Disagrees` bolded)
2. `<main class="max-w-7xl mx-auto px-4 sm:px-6 py-10">`
3. Page title + context prose
4. **CNA section:**
   - Section label: "By CNA (Scoring Organization)" — 11px uppercase
   - Bar chart in card
   - Table toolbar: count + search input
   - Table: #, CNA name, Conflict Rate (with inline progress bar on sm+), Conflicts, Total CVEs (md+), Avg Drift (md+), NVD Higher % (md+), GH Higher % (md+)
   - Sortable column headers for Conflict Rate, Conflicts, Avg Drift
5. Border divider
6. **CWE section:**
   - Section label: "By CWE (Vulnerability Type)"
   - Bar chart in card
   - Table toolbar: count + search input
   - Table: #, CWE ID, Name (sm+), Conflicts, Avg Drift, NVD Higher % (md+), GH Higher % (md+)
   - Sortable column headers for Conflicts, Avg Drift
7. Footer

CNA table conflict rate progress bar: a small `div` inside the table cell with `width` set to `conflict_rate + '%'`, `height: 4px`, `background: var(--brand)`, `border-radius: 2px`. Only shown on `sm:` breakpoint and up.

- [ ] **Step 2: Serve locally and verify**

Open `http://localhost:8080/sources.html` and verify:

- Both charts render
- Both tables are searchable and sortable
- CNA progress bars show on desktop
- Dark mode works
- Footer shows updated date

- [ ] **Step 3: Commit**

```bash
git add docs/sources.html
git commit -m "feat: add Who Disagrees page (CNA + CWE sources)"
```

---

### Task 5: Create "The Data" (`data.html`)

**Files:**

- Create: `docs/data.html`

The practitioner drill-down page. Merges the leaderboard table from old `index.html` and coverage gaps from old `coverage-gap.html`. Fetches `leaderboard.json`, `stats.json`, and `coverage-gap.json`.

- [ ] **Step 1: Write the complete data page**

Write `docs/data.html`. Same `<head>` boilerplate. Title: `The Data — The Consensus Engine`. No Chart.js needed (no charts on this page) — omit the Chart.js `<script>` tag.

Alpine.js component: `dataPage()`

Properties:

- `loading: true`
- `error: null`
- `entries: []` — from `leaderboard.json`
- `stats: null` — from `stats.json`
- `gaps: null` — from `coverage-gap.json` (the full object including `entries` array and `total`)
- `sort: "drift_score"`
- `search: ""`
- `minVariance: 0`
- `flipOnly: false`
- `hideDeferred: false`

Computed properties:

- `sorted` — returns `entries` sorted by current `sort` field descending
- `filtered` — applies all filters on `sorted`:
  - If `search`: filter where `cve_id` or `assigning_cna` includes search (case-insensitive)
  - If `flipOnly`: filter where `severity_flip === true`
  - If `minVariance > 0`: filter where `drift_score >= minVariance`
  - If `hideDeferred`: filter where `nvd_status !== "Deferred"`

Methods:

- `init()` — fetches all three JSON files
- `sortBy(field)` — sets `sort`
- `scoreColor(score)` — returns inline style color: red for ≥9.0, orange for ≥7.0, yellow for ≥4.0, green otherwise
- `statusColor(status)` — returns color for NVD status badges

This page uses `max-w-7xl` (wider container).

Page body structure:

1. Header (same, `The Data` bolded)
2. `<main class="max-w-7xl mx-auto px-4 sm:px-6 py-10">`
3. Page title: "The Data" + subtitle: "Search, filter, and explore all scoring conflicts. Updated every six hours."
4. Filter bar: search input + Min Δ buttons (All/≥0.5/≥1.0/≥2.0) + toggles (Severity flips only, Hide CNA pass-through) — all in a single flex row that wraps on mobile
5. Count indicator: "X total · Y shown"
6. Conflict table in card: #, CVE ID (linked to `cve.html?id=`), NVD Score, GitHub Score, Drift Score (color-coded), CNA (sm+), NVD Status (md+), Published (md+)
   - Sortable headers for Drift Score, GitHub Score, NVD Score, Published
   - Severity flip badge on CVE ID row when applicable
7. Border divider + "Coverage Gaps" section
   - Section label: "Coverage Gaps"
   - Context text: "CVEs scored by GitHub but missing from NVD — invisible to NVD-only tools."
   - Count: "X GitHub-only CVEs"
   - Table in card: #, CVE ID (linked), GitHub Score, Severity badge (sm+), NVD Status (sm+), Published (md+), GHSA ID (md+, linked to `https://github.com/advisories/`)
8. Footer

- [ ] **Step 2: Serve locally and verify**

Open `http://localhost:8080/data.html` and verify:

- Leaderboard table loads with 500 entries
- All filters work (search, min variance, severity flips, hide deferred)
- Count updates ("X total · Y shown")
- Coverage gap table loads below
- CVE links go to `cve.html?id=CVE-...`
- GHSA links open GitHub advisory
- Dark mode works
- Sorting works on all sortable columns

- [ ] **Step 3: Commit**

```bash
git add docs/data.html
git commit -m "feat: add The Data page (conflict explorer + coverage gaps)"
```

---

### Task 6: Restyle CVE Detail (`cve.html`)

**Files:**

- Rewrite: `docs/cve.html`

The existing page works well functionally but uses different styling (gray-950 background, monospace body, no header nav). Restyle to match the new design system while keeping all existing logic.

- [ ] **Step 1: Rewrite cve.html with new design system**

Write `docs/cve.html`. Same `<head>` boilerplate (CSS variables, dark mode, Tailwind config). Title: dynamic — `CVE Detail — The Consensus Engine`.

Alpine.js component: `cvePage()` — same properties and methods as the current `cve.html`:

- `loading`, `error`, `cve`, `nutrition`
- `init()` — reads `?id=` param, fetches `data/{year}/{id}.json`, calls `computeNutrition()`
- `computeNutrition(cve)` — identical logic to current implementation (6 traffic-light metrics: Coverage, Agreement, Timeliness, Exploitation Signal, Remediation Clarity, CWE Quality)
- `trafficLight(color)` — maps "green"/"yellow"/"red" to CSS: green uses `color: #16a34a` / dark `#4ade80`, yellow uses `color: #ca8a04` / dark `#facc15`, red uses `var(--danger)`
- `driftTypeBadge(type)`, `scoreColor(score)`, `statusColor(status)` — same logic

Changes from current design:

- Uses standard header with nav (same as all pages, no page bolded in nav)
- Uses `var(--bg-primary)` background instead of `bg-gray-950`
- Uses `var(--bg-card)` for cards instead of `bg-gray-900`
- Uses Inter font for body (not monospace)
- Uses `max-w-5xl` container
- Nutrition label and source scores sections use same card styling as other pages

Page body structure:

1. Standard header with nav (no page bolded — this is a detail page reached via link)
2. `<main class="max-w-5xl mx-auto px-4 sm:px-6 py-10">`
3. Back link: `← Back to The Data` linking to `data.html`
4. CVE ID heading with drift type badge
5. Metadata row: CNA, Drift Score, CVSS Variance, Source Count
6. CVE Nutrition Label section: 6 items in a 2×3 or 3×2 grid, each with traffic light indicator (colored dot), label, and detail text
7. Source Scores section: NVD details, GitHub details, CISA KEV, EPSS — each in a card
8. Footer

- [ ] **Step 2: Serve locally and verify**

Open `http://localhost:8080/cve.html?id=CVE-2025-47735` (or any CVE from the leaderboard) and verify:

- Data loads correctly
- Nutrition label shows 6 traffic lights with correct colors
- Source scores render for all available sources
- Navigation works (header, back link)
- Dark mode works
- Styling matches the rest of the site

- [ ] **Step 3: Commit**

```bash
git add docs/cve.html
git commit -m "feat: restyle CVE detail page to match new design system"
```

---

### Task 7: Restyle Methodology (`methodology.html`)

**Files:**

- Rewrite: `docs/methodology.html`

Same content, new visual treatment. No Alpine.js data component needed (static content), but needs the dark mode toggle.

- [ ] **Step 1: Rewrite methodology.html**

Write `docs/methodology.html`. Same `<head>` boilerplate minus Alpine.js and Chart.js (not needed). Title: `Methodology — The Consensus Engine`.

Dark mode toggle still needs a tiny Alpine-like handler, but since there's no data, use plain JS: the toggle button in the header calls the same `classList.toggle('dark')` + `localStorage.setItem` pattern.

Changes from current:

- Add standard header with nav (`Methodology` bolded)
- Add dark mode CSS variables and toggle
- Update text in "Update frequency" section: replace "Data is updated daily at 02:00 UTC" with "Data is updated every six hours (00:00, 06:00, 12:00, 18:00 UTC) and on every push to the main branch."
- Update text in "Data sources" section: replace "Both sources are fetched daily at 02:00 UTC via GitHub Actions" with "Both sources are fetched every six hours via GitHub Actions."
- Use `max-w-3xl` container for the reading column (already correct)
- Use `var(--bg-primary)` and `var(--text-primary)` etc. for all colors
- Same footer as other pages

Content sections (unchanged except for the two text updates above):

1. What the Drift Score measures
2. Classification
3. Data sources
4. Known limitations (8 items)
5. Update frequency
6. How to cite

- [ ] **Step 2: Serve locally and verify**

Open `http://localhost:8080/methodology.html` and verify:

- All sections render with correct content
- Updated text says "every six hours" not "daily"
- Dark mode toggle works
- Navigation works
- Typography is clean and readable

- [ ] **Step 3: Commit**

```bash
git add docs/methodology.html
git commit -m "feat: restyle methodology page with dark mode and updated schedule"
```

---

### Task 8: Delete Old Pages

**Files:**

- Delete: `docs/conflict-map.html`
- Delete: `docs/vector-breakdown.html`
- Delete: `docs/cna.html`
- Delete: `docs/cwe.html`
- Delete: `docs/coverage-gap.html`

- [ ] **Step 1: Verify all new pages work**

Run: `python -m http.server 8080 --directory docs`

Verify each new page loads correctly:

- `http://localhost:8080/` — homepage
- `http://localhost:8080/patterns.html` — How They Disagree
- `http://localhost:8080/sources.html` — Who Disagrees
- `http://localhost:8080/data.html` — The Data
- `http://localhost:8080/cve.html?id=CVE-2025-47735` — CVE Detail
- `http://localhost:8080/methodology.html` — Methodology

Verify no page links to the old pages (search for `conflict-map.html`, `vector-breakdown.html`, `cna.html`, `cwe.html`, `coverage-gap.html` in all new HTML files).

- [ ] **Step 2: Delete old pages**

```bash
rm docs/conflict-map.html docs/vector-breakdown.html docs/cna.html docs/cwe.html docs/coverage-gap.html
```

- [ ] **Step 3: Commit**

```bash
git add -A docs/
git commit -m "chore: remove old pages replaced by redesign"
```

---

## Implementation Notes

**Shared boilerplate:** Every page repeats the same `<head>` block (CSS variables, Tailwind config, dark mode init script, Inter font), header, and footer. This is intentional — the project has no build step and no template system, so each HTML file must be self-contained. When implementing, copy the `<head>`, header, and footer from the homepage (`index.html`) for each subsequent page, changing only the `<title>` and which nav item is bolded.

**Chart.js and CSS variables:** Chart.js does not natively read CSS custom properties for colors. Use `getComputedStyle(document.documentElement).getPropertyValue('--variable-name').trim()` at chart-build time. This means charts won't live-update when toggling dark mode — they render with the colors active at build time. This is acceptable; a page reload applies the new theme to charts. If you want live theme switching for charts, you'd need to rebuild them on toggle, but that's scope creep for this redesign.

**No test suite:** This project has no automated tests. Verification is manual — serve locally and check each page in a browser. The plan includes verification steps after each task.

**Data dependencies:** All pages fetch from `docs/data/indexes/*.json`. These files already exist and are regenerated by the CI pipeline. No changes to `build_indexes.py` or `compute_drift.py` are needed — the existing indexes contain all the data the new pages require.
