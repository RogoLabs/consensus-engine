# Methodology Hardening & New Views Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix three methodology issues in the data pipeline, add credibility features (filters, disclosures, methodology page), and build four new frontend views (histogram, severity flip matrix, directional trend, CWE analysis page).

**Architecture:** Python pipeline scripts (`scripts/`) compute data and write JSON indexes to `docs/data/indexes/`. Static HTML pages (`docs/`) fetch those indexes client-side with Alpine.js and render with Chart.js. No build step, no backend. All new views follow this same pattern.

**Tech Stack:** Python 3.12+ (pipeline), HTML + Tailwind CSS CDN + Alpine.js CDN + Chart.js CDN (frontend)

**Spec:** `docs/superpowers/specs/2026-04-17-methodology-and-views-design.md`

---

## File Map

**Modified files:**

- `scripts/compute_drift.py` — Tasks 1, 2 (drift_score formula, rejected scoring)
- `scripts/build_indexes.py` — Tasks 5, 6, 7, 8 (new index data: variance distribution, severity matrix, direction-by-year, CWE stats)
- `docs/index.html` — Task 4 (filters, disclosures on leaderboard)
- `docs/vector-breakdown.html` — Task 3 (data-driven callout)
- `docs/conflict-map.html` — Tasks 9, 10, 11 (histogram, severity matrix, directional trend)
- All nav-bearing HTML files — Task 13 (add CWE + Methodology links to nav)

**New files:**

- `docs/cwe.html` — Task 12 (CWE analysis page)
- `docs/methodology.html` — Task 14 (static methodology/limitations page)

---

### Task 1: Remove metadata_conflict from drift_score formula

**Files:**

- Modify: `scripts/compute_drift.py:143-157`

- [ ] **Step 1: Edit `compute_drift_score()` to remove metadata_conflict from the formula**

In `scripts/compute_drift.py`, replace the `compute_drift_score` function (lines 143-157):

```python
def compute_drift_score(
    drift_type: str,
    cvss_variance: float,
    metadata_conflict: float = 0.0,
    max_other_score: float | None = None,
):
    """
    Drift score = |GH − NVD| + metadata_conflict (capped at 10.0) for conflict/gap CVEs.
    metadata_conflict (0.0–1.0) adds up to 1 additional point for CWE/version-range gaps.
    For rejected CVEs: the GitHub score itself (NVD has no score to compare).
    Tombstones (rejected, no other source): 0.0.
    """
    if drift_type == "rejected":
        return round(max_other_score, 2) if max_other_score is not None else 0.0
    return round(min(cvss_variance + metadata_conflict, 10.0), 2)
```

With:

```python
def compute_drift_score(
    drift_type: str,
    cvss_variance: float,
    metadata_conflict: float = 0.0,
    max_other_score: float | None = None,
):
    """
    Drift score = |GH − NVD| (capped at 10.0) for conflict/gap CVEs.
    metadata_conflict is computed and stored but does not affect drift_score.
    For rejected CVEs: 0.0 (existence dispute, not score dispute).
    Tombstones (rejected, no other source): 0.0.
    """
    if drift_type == "rejected":
        return 0.0
    return round(min(cvss_variance, 10.0), 2)
```

- [ ] **Step 2: Verify the change locally**

Run on a sample file to check output:

```bash
cd /Users/gamblin/Documents/Github/consensus-engine
python3 -c "
from scripts.compute_drift import compute_drift_score
# Conflict: was 6.9 + 0.2 = 7.1, now should be 6.9
print(compute_drift_score('conflict', 6.9, 0.2))
# Rejected: was 9.8, now should be 0.0
print(compute_drift_score('rejected', 0.0, 0.0, 9.8))
# Gap: was 0.0 + 0.3 = 0.3, now should be 0.0
print(compute_drift_score('gap', 0.0, 0.3))
"
```

Expected output:

```
6.9
0.0
0.0
```

- [ ] **Step 3: Commit**

```bash
git add scripts/compute_drift.py
git commit -m "fix: remove metadata_conflict from drift_score, zero-score rejected CVEs

drift_score is now pure |GitHub CVSS - NVD CVSS|. metadata_conflict
remains as an annotation in CVE JSON but no longer inflates the
headline number. Rejected CVEs get drift_score 0.0 since they
represent existence disputes, not score disputes."
```

---

### Task 2: Re-run drift computation on all CVE files

**Files:**

- Modify: all `docs/data/{year}/CVE-*.json` files (via script execution)

- [ ] **Step 1: Run compute_drift.py to rewrite all CVE files with the new formula**

```bash
cd /Users/gamblin/Documents/Github/consensus-engine
python3 scripts/compute_drift.py
```

Expected: prints `Computing drift scores for ~137803 CVEs...` and completes. Conflict/gap/rejected counts should remain the same — only the drift_score values change.

- [ ] **Step 2: Verify a known CVE's drift_score changed**

```bash
python3 -c "
import json
# CVE-2025-47735: was drift_score 7.1 (6.9 + 0.2), should now be 6.9
r = json.load(open('docs/data/2025/CVE-2025-47735.json'))
print(f'drift_score: {r[\"drift_score\"]}')
print(f'cvss_variance: {r[\"cvss_variance\"]}')
print(f'metadata_conflict: {r[\"metadata_conflict\"]}')
"
```

Expected:

```
drift_score: 6.9
cvss_variance: 6.9
metadata_conflict: 0.2
```

- [ ] **Step 3: Verify a rejected CVE is now 0.0**

```bash
python3 -c "
import json
r = json.load(open('docs/data/2022/CVE-2022-50807.json'))
print(f'drift_score: {r[\"drift_score\"]}')
print(f'drift_type: {r[\"drift_type\"]}')
"
```

Expected:

```
drift_score: 0.0
drift_type: rejected
```

- [ ] **Step 4: Re-run build_indexes.py to regenerate all indexes with new scores**

```bash
python3 scripts/build_indexes.py
```

- [ ] **Step 5: Verify stats.json reflects the changes**

```bash
python3 -c "
import json
s = json.load(open('docs/data/indexes/stats.json'))
print(f'max_drift_score: {s[\"max_drift_score\"]}')
print(f'max_drift_cve: {s[\"max_drift_cve\"]}')
print(f'max_variance: {s[\"max_variance\"]}')
print(f'avg_variance: {s[\"avg_variance\"]}')
"
```

Expected: `max_drift_score` should now equal `max_variance` (6.9), since rejected CVEs are 0.0 and metadata_conflict no longer inflates. The `max_drift_cve` should be the same as `max_variance_cve`.

- [ ] **Step 6: Commit all recomputed data**

```bash
git add docs/data/
git commit -m "chore: recompute all drift scores with corrected formula"
```

---

### Task 3: Make vector-breakdown AC callout data-driven

**Files:**

- Modify: `docs/vector-breakdown.html:91-106` (callout HTML) and `:236-248` (JS computed property)

- [ ] **Step 1: Replace the static callout HTML with a data-driven template**

In `docs/vector-breakdown.html`, replace lines 92-106 (the static `<div class="bg-yellow-900/20...` callout block) with:

```html
<div
  x-show="topSkew"
  class="bg-yellow-900/20 border border-yellow-700/40 rounded-xl p-4 sm:p-5 mb-8"
>
  <div class="flex items-start gap-3">
    <span class="text-yellow-400 text-xl mt-0.5">!</span>
    <div>
      <p class="text-yellow-300 font-semibold text-sm mb-1">
        Strongest Directional Bias
      </p>
      <p class="text-gray-300 text-sm leading-relaxed">
        When NVD and GitHub disagree on
        <span class="text-white font-medium" x-text="topSkew.name"></span>,
        <span x-show="topSkew.nvd_higher_count > topSkew.gh_higher_count">
          NVD assigns the more severe value
        </span>
        <span x-show="topSkew.gh_higher_count > topSkew.nvd_higher_count">
          GitHub assigns the more severe value
        </span>
        <span
          class="text-white font-semibold"
          x-text="`${topSkew.skewPct}%`"
        ></span>
        of the time. This is the strongest directional bias of any CVSS metric —
        not random noise, but a systematic difference in how these authorities
        score
        <span
          class="text-white font-medium"
          x-text="topSkew.name.toLowerCase()"
        ></span
        >.
      </p>
    </div>
  </div>
</div>
```

- [ ] **Step 2: Add the `topSkew` computed property to the Alpine component**

In the `vectorBreakdown()` function in the `<script>` tag, add this computed property after the existing `acRatio` getter:

```javascript
        get topSkew() {
          if (!this.data) return null;
          let best = null;
          let bestSkew = 0;
          for (const m of this.data.metrics) {
            const total = m.nvd_higher_count + m.gh_higher_count;
            if (total < 10) continue;
            const skew = Math.abs(m.nvd_higher_count - m.gh_higher_count) / total;
            if (skew > bestSkew) {
              bestSkew = skew;
              best = m;
            }
          }
          if (!best) return null;
          const total = best.nvd_higher_count + best.gh_higher_count;
          const dominant = Math.max(best.nvd_higher_count, best.gh_higher_count);
          return { ...best, skewPct: Math.round(dominant / total * 100) };
        },
```

- [ ] **Step 3: Remove the now-unused `acRatio` getter**

Delete the `get acRatio()` computed property from the Alpine component (it was only used by the old static callout).

- [ ] **Step 4: Verify by serving locally**

```bash
python3 -m http.server 8080 --directory docs
```

Open `http://localhost:8080/vector-breakdown.html` — the callout should now show whichever metric has the strongest directional skew (currently AC at ~92% NVD-higher) and update dynamically.

- [ ] **Step 5: Commit**

```bash
git add docs/vector-breakdown.html
git commit -m "fix: make vector-breakdown callout data-driven instead of hardcoded

Callout now finds the metric with the strongest directional skew
and generates text dynamically. Prevents stale claims as data
changes over time."
```

---

### Task 4: Add variance filter, Deferred filter, and disclosures to leaderboard

**Files:**

- Modify: `docs/index.html`

- [ ] **Step 1: Add `minVariance` and `hideDeferred` state to the Alpine component**

In the `dashboard()` function in `docs/index.html`, add to the initial state (after `flipOnly: false,`):

```javascript
        minVariance: 0,
        hideDeferred: false,
```

- [ ] **Step 2: Add the variance filter buttons and Deferred checkbox to the toolbar**

In `docs/index.html`, find the filter row that contains the "Severity flips only" checkbox (around line 181-185). After the closing `</label>` of the flipOnly checkbox, add:

```html
<label
  class="flex items-center gap-1.5 text-xs text-gray-400 cursor-pointer select-none"
>
  <input type="checkbox" x-model="hideDeferred" class="accent-brand" />
  <span>Hide CNA pass-through</span>
</label>
```

Then find the sort buttons row (around line 186-194). After the closing `</div>` of that row, add a new row:

```html
<div
  class="flex items-center gap-2 text-xs text-gray-500 overflow-x-auto pb-0.5"
>
  <span class="shrink-0">Min Δ:</span>
  <template x-for="v in [0, 0.5, 1.0, 2.0]" :key="v">
    <button
      @click="minVariance = v"
      :class="minVariance === v ? 'bg-brand text-white' : 'bg-surface-border text-gray-300 hover:text-white'"
      class="px-2.5 py-1 rounded transition-colors font-medium shrink-0"
      x-text="v === 0 ? 'All' : `≥ ${v}`"
    ></button>
  </template>
</div>
```

- [ ] **Step 3: Update the `filtered` computed property to apply both new filters**

In the `dashboard()` Alpine component, replace the `get filtered()` getter:

```javascript
        get filtered() {
          let result = this.sorted;
          if (this.flipOnly) result = result.filter(e => e.severity_flip);
          if (this.minVariance > 0) result = result.filter(e => (e.cvss_variance ?? 0) >= this.minVariance);
          if (this.hideDeferred) result = result.filter(e => e.nvd_status !== 'Deferred');
          const q = this.search.trim().toLowerCase();
          if (q) {
            result = result.filter(e =>
              e.cve_id.toLowerCase().includes(q) ||
              (e.assigning_cna ?? '').toLowerCase().includes(q)
            );
          }
          return result;
        },
```

- [ ] **Step 4: Update the conflict count stat card subtitle**

Find the "Conflict Rate" stat card subtitle (around line 119). Replace:

```html
<div
  class="text-xs text-gray-600 mt-1"
  x-text="stats ? `${stats.conflict_count.toLocaleString()} CVEs disagree` : ''"
></div>
```

With:

```html
<div
  class="text-xs text-gray-600 mt-1"
  x-text="stats ? `${stats.conflict_count.toLocaleString()} total · ${filtered.length.toLocaleString()} shown` : ''"
></div>
```

- [ ] **Step 5: Change NVD Status column visibility from lg to md**

Find the `<th>` and `<td>` for NVD Status (around lines 207 and 243). Change both occurrences of `hidden lg:table-cell` to `hidden md:table-cell`.

- [ ] **Step 6: Add Deferred disclosure to the explainer callout**

Find the explainer callout `<div>` (around lines 146-153). After the existing text about `↑NVD / ↑GH`, add:

```html
<span class="block mt-1.5 text-gray-500"
  >Some NVD scores are CNA-provided (status: Deferred) rather than independently
  analyzed by NVD staff.</span
>
```

- [ ] **Step 7: Verify by serving locally**

```bash
python3 -m http.server 8080 --directory docs
```

Open `http://localhost:8080/index.html`. Verify:

- Min Δ buttons filter the table (clicking "≥ 1.0" should reduce the count)
- "Hide CNA pass-through" checkbox filters out Deferred rows
- Stat card subtitle shows "X total · Y shown"
- NVD Status column visible on medium screens
- Deferred disclosure text appears in the explainer callout

- [ ] **Step 8: Commit**

```bash
git add docs/index.html
git commit -m "feat: add variance filter, Deferred filter, and disclosures to leaderboard

Adds Min Δ filter (All/0.5/1.0/2.0), Deferred checkbox to hide CNA
pass-through scores, updated stat card subtitle, wider NVD Status
column visibility, and Deferred disclosure in explainer callout."
```

---

### Task 5: Add variance_distribution to build_indexes.py

**Files:**

- Modify: `scripts/build_indexes.py`

- [ ] **Step 1: Add the variance distribution computation**

In `scripts/build_indexes.py`, in the `main()` function, find the block that computes `variances` (around line 450). After the `median_variance` computation (around line 455), add:

```python
    # Variance distribution: 0.5-point buckets for histogram
    variance_distribution = []
    bucket_width = 0.5
    max_bucket = 10.0
    b = 0.0
    while b < max_bucket:
        count = sum(1 for v in variances if b <= v < b + bucket_width)
        if count > 0:
            variance_distribution.append({
                "bucket": f"{b:.1f}-{b + bucket_width:.1f}",
                "min": b,
                "count": count,
            })
        b = round(b + bucket_width, 1)
```

- [ ] **Step 2: Add variance_distribution to the stats dict**

In the same function, find where the `stats` dict is constructed (around line 497). Add this key after `"median_variance": median_variance,`:

```python
        "variance_distribution": variance_distribution,
```

- [ ] **Step 3: Commit**

```bash
git add scripts/build_indexes.py
git commit -m "feat: add variance_distribution to stats.json for histogram view"
```

---

### Task 6: Add severity_flip_matrix to build_indexes.py

**Files:**

- Modify: `scripts/build_indexes.py`

- [ ] **Step 1: Import get_severity_band from compute_drift**

At the top of `scripts/build_indexes.py`, after the existing imports (around line 9), add:

```python
from scripts.compute_drift import get_severity_band
```

Note: If running from the repo root, this import path works. If it doesn't resolve, use a relative import or inline the function. The function is simple:

```python
_SEVERITY_BANDS = [(9.0, "Critical"), (7.0, "High"), (4.0, "Medium"), (0.1, "Low")]

def _get_severity_band(score):
    if score is None or score <= 0:
        return None
    for threshold, label in _SEVERITY_BANDS:
        if score >= threshold:
            return label
    return None
```

If the import doesn't work cleanly, add `_get_severity_band` as a local function in `build_indexes.py` instead.

- [ ] **Step 2: Compute the severity flip matrix in main()**

In `main()`, after the `severity_flip_count` computation (around line 473), add:

```python
    # Severity flip matrix: NVD band vs GitHub band for all conflict CVEs
    bands = ["Critical", "High", "Medium", "Low"]
    severity_matrix = {f"{nvd_b}→{gh_b}": 0 for nvd_b in bands for gh_b in bands}
    severity_matrix_totals = {"nvd": {b: 0 for b in bands}, "gh": {b: 0 for b in bands}}
    for r in conflict_records:
        nvd_s = r.get("sources", {}).get("nvd", {}).get("cvss_score")
        gh_s = r.get("sources", {}).get("github", {}).get("cvss_score")
        nvd_b = _get_severity_band(nvd_s)
        gh_b = _get_severity_band(gh_s)
        if nvd_b and gh_b:
            severity_matrix[f"{nvd_b}→{gh_b}"] += 1
            severity_matrix_totals["nvd"][nvd_b] += 1
            severity_matrix_totals["gh"][gh_b] += 1
```

- [ ] **Step 3: Add severity_flip_matrix to the stats dict**

In the `stats` dict construction, add after `"severity_flip_count": severity_flip_count,`:

```python
        "severity_flip_matrix": severity_matrix,
        "severity_matrix_totals": severity_matrix_totals,
```

- [ ] **Step 4: Commit**

```bash
git add scripts/build_indexes.py
git commit -m "feat: add severity_flip_matrix to stats.json for heatmap view"
```

---

### Task 7: Add conflict_direction_by_year to build_indexes.py

**Files:**

- Modify: `scripts/build_indexes.py`

- [ ] **Step 1: Compute direction-by-year with comparable counts**

In `main()`, find the `conflict_by_year` computation (around lines 466-470). Replace it with an expanded version that also tracks direction and comparable count per year:

```python
    # Conflict by year with direction split and comparable count
    conflict_by_year: dict[str, int] = defaultdict(int)
    conflict_direction_by_year: dict[str, dict] = defaultdict(lambda: {"nvd_higher": 0, "gh_higher": 0, "comparable": 0})
    comparable_by_year: dict[str, int] = defaultdict(int)

    for r in comparable_records:
        pub = r.get("sources", {}).get("nvd", {}).get("published", "")
        if pub:
            comparable_by_year[pub[:4]] += 1

    for r in conflict_records:
        pub = r.get("sources", {}).get("nvd", {}).get("published", "")
        if pub:
            year = pub[:4]
            conflict_by_year[year] += 1
            nvd_s = r.get("sources", {}).get("nvd", {}).get("cvss_score") or 0
            gh_s = r.get("sources", {}).get("github", {}).get("cvss_score") or 0
            if nvd_s > gh_s:
                conflict_direction_by_year[year]["nvd_higher"] += 1
            else:
                conflict_direction_by_year[year]["gh_higher"] += 1

    for year in conflict_direction_by_year:
        conflict_direction_by_year[year]["comparable"] = comparable_by_year.get(year, 0)
```

- [ ] **Step 2: Add to stats dict**

In the stats dict, the existing `"conflict_by_year"` key stays. Add after it:

```python
        "conflict_direction_by_year": {k: dict(v) for k, v in sorted(conflict_direction_by_year.items()) if v["comparable"] >= 20},
```

- [ ] **Step 3: Commit**

```bash
git add scripts/build_indexes.py
git commit -m "feat: add conflict_direction_by_year to stats.json for trend view"
```

---

### Task 8: Add CWE stats computation to build_indexes.py

**Files:**

- Modify: `scripts/build_indexes.py`

- [ ] **Step 1: Add CWE name lookup map**

At the top of `scripts/build_indexes.py`, after the `CVSS_METRICS` dict (around line 61), add:

```python
CWE_NAMES = {
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-94": "Code Injection",
    "CWE-119": "Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-200": "Information Exposure",
    "CWE-269": "Improper Privilege Management",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-287": "Improper Authentication",
    "CWE-306": "Missing Authentication",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-362": "Race Condition",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-401": "Memory Leak",
    "CWE-416": "Use After Free",
    "CWE-434": "Unrestricted File Upload",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-532": "Log Injection / Information Exposure Through Log",
    "CWE-601": "Open Redirect",
    "CWE-611": "XXE",
    "CWE-613": "Insufficient Session Expiration",
    "CWE-617": "Reachable Assertion",
    "CWE-639": "Authorization Bypass Through User-Controlled Key",
    "CWE-668": "Exposure of Resource to Wrong Sphere",
    "CWE-732": "Incorrect Permission Assignment",
    "CWE-754": "Improper Check for Unusual Conditions",
    "CWE-770": "Allocation of Resources Without Limits",
    "CWE-776": "XML Entity Expansion",
    "CWE-787": "Out-of-bounds Write",
    "CWE-798": "Hard-coded Credentials",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-1321": "Prototype Pollution",
    "CWE-1333": "Inefficient Regular Expression",
}
```

- [ ] **Step 2: Add `build_cwe_stats()` function**

Add this function before `main()`:

```python
CWE_STATS_FILE = INDEXES_DIR / "cwe-stats.json"

WEAK_CWES_SET = {"NVD-CWE-noinfo", "NVD-CWE-Other", "CWE-noinfo", "CWE-Other"}

def build_cwe_stats(conflict_records: list) -> list:
    """Build per-CWE conflict statistics for cwe-stats.json."""
    cwe_data: dict[str, dict] = defaultdict(lambda: {
        "conflicts": 0, "variances": [], "nvd_higher": 0, "gh_higher": 0,
    })

    for r in conflict_records:
        cwes = r.get("sources", {}).get("nvd", {}).get("cwe", [])
        nvd_s = r.get("sources", {}).get("nvd", {}).get("cvss_score") or 0
        gh_s = r.get("sources", {}).get("github", {}).get("cvss_score") or 0
        variance = r.get("cvss_variance", 0)

        for cwe in cwes:
            if cwe in WEAK_CWES_SET:
                continue
            d = cwe_data[cwe]
            d["conflicts"] += 1
            d["variances"].append(variance)
            if nvd_s > gh_s:
                d["nvd_higher"] += 1
            else:
                d["gh_higher"] += 1

    result = []
    for cwe_id, d in cwe_data.items():
        if d["conflicts"] < 5:
            continue
        variances = d["variances"]
        avg_v = round(sum(variances) / len(variances), 2)
        result.append({
            "cwe_id": cwe_id,
            "name": CWE_NAMES.get(cwe_id, cwe_id),
            "conflict_count": d["conflicts"],
            "avg_variance": avg_v,
            "nvd_higher_count": d["nvd_higher"],
            "gh_higher_count": d["gh_higher"],
        })

    result.sort(key=lambda x: -x["conflict_count"])
    return result
```

- [ ] **Step 3: Call build_cwe_stats() in main() and write the file**

In `main()`, after the Coverage Gap block (around line 540), add:

```python
    # CWE Stats
    cwe_stats = build_cwe_stats(conflict_records)
    CWE_STATS_FILE.write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "cwes": cwe_stats,
    }, indent=2))
    print(f"CWE Stats written: {CWE_STATS_FILE} ({len(cwe_stats)} CWEs)")
```

- [ ] **Step 4: Run build_indexes.py and verify new output files**

```bash
python3 scripts/build_indexes.py
python3 -c "
import json
s = json.load(open('docs/data/indexes/stats.json'))
print('variance_distribution buckets:', len(s.get('variance_distribution', [])))
print('severity_flip_matrix keys:', len(s.get('severity_flip_matrix', {})))
print('direction_by_year years:', len(s.get('conflict_direction_by_year', {})))
c = json.load(open('docs/data/indexes/cwe-stats.json'))
print('CWE stats count:', len(c.get('cwes', [])))
print('Top CWE:', c['cwes'][0] if c.get('cwes') else 'none')
"
```

Expected: All four new data structures should be populated.

- [ ] **Step 5: Commit**

```bash
git add scripts/build_indexes.py docs/data/indexes/
git commit -m "feat: add CWE stats, variance distribution, severity matrix, direction-by-year indexes"
```

---

### Task 9: Add drift distribution histogram to conflict-map.html

**Files:**

- Modify: `docs/conflict-map.html`

- [ ] **Step 1: Add stats data fetch to the Alpine component's init()**

In `docs/conflict-map.html`, in the `conflictMap()` Alpine component, add `stats: null,` to the initial state (after `tooltip: {...}`). Then in the `init()` method, after the existing `fetch('data/indexes/conflict-map.json')` block, add a stats fetch:

```javascript
const statsRes = await fetch("data/indexes/stats.json");
if (statsRes.ok) this.stats = await statsRes.json();
```

- [ ] **Step 2: Add the histogram HTML section**

In `docs/conflict-map.html`, after the closing `</div>` of the "Conflicts by Year chart" section (around line 157), add:

```html
<!-- Drift Distribution Histogram -->
<div x-show="!loading && !error && stats?.variance_distribution" class="mt-10">
  <h2 class="text-xl font-bold text-white mb-1">Drift Score Distribution</h2>
  <p class="text-gray-400 text-sm mb-4">
    How many conflicts fall in each score-gap bucket. A third of conflicts are
    below Δ1.0 — possible noise from CVSS calculator rounding.
  </p>
  <div
    class="bg-surface-card border border-surface-border rounded-lg p-4 sm:p-6"
  >
    <div class="relative" style="height: 280px;">
      <canvas id="histogramChart"></canvas>
    </div>
  </div>
</div>
```

- [ ] **Step 3: Add the histogram chart builder**

In the `conflictMap()` Alpine component, after the `buildYearChart()` method, add:

```javascript
        buildHistogram() {
          if (!this.stats?.variance_distribution) return;
          const dist = this.stats.variance_distribution;
          const labels = dist.map(d => d.bucket);
          const counts = dist.map(d => d.count);
          const colors = dist.map(d =>
            d.min < 1.0 ? 'rgba(74,222,128,0.7)' :
            d.min < 3.0 ? 'rgba(250,204,21,0.7)' :
            'rgba(248,113,113,0.7)'
          );

          const ctx = document.getElementById('histogramChart');
          if (!ctx) return;
          new Chart(ctx, {
            type: 'bar',
            data: {
              labels,
              datasets: [{
                label: 'Conflicts',
                data: counts,
                backgroundColor: colors,
                borderRadius: 4,
                borderSkipped: false,
              }]
            },
            options: {
              responsive: true,
              maintainAspectRatio: false,
              animation: false,
              plugins: {
                legend: { display: false },
                tooltip: {
                  callbacks: {
                    title: ([item]) => `Δ ${item.label}`,
                    label: (item) => `${item.raw} conflicts`,
                  }
                }
              },
              scales: {
                x: {
                  title: { display: true, text: 'CVSS Variance (Δ)', color: '#9ca3af', font: { family: 'Inter', size: 12 } },
                  ticks: { color: '#6b7280' },
                  grid: { color: 'rgba(45,55,72,0.5)' },
                },
                y: {
                  title: { display: true, text: 'Conflicts', color: '#9ca3af', font: { family: 'Inter', size: 12 } },
                  ticks: { color: '#6b7280' },
                  grid: { color: 'rgba(45,55,72,0.5)' },
                },
              }
            }
          });
        },
```

- [ ] **Step 4: Call buildHistogram() after buildYearChart()**

In the `buildChart()` method, the last line calls `this.buildYearChart()`. After that, add:

```javascript
this.buildHistogram();
```

- [ ] **Step 5: Verify locally**

```bash
python3 -m http.server 8080 --directory docs
```

Open `http://localhost:8080/conflict-map.html` — the histogram should appear below "Conflicts by Year" with green/yellow/red bars.

- [ ] **Step 6: Commit**

```bash
git add docs/conflict-map.html
git commit -m "feat: add drift distribution histogram to conflict map page"
```

---

### Task 10: Add severity flip matrix to conflict-map.html

**Files:**

- Modify: `docs/conflict-map.html`

- [ ] **Step 1: Add the severity flip matrix HTML section**

In `docs/conflict-map.html`, after the histogram section added in Task 9, add:

```html
<!-- Severity Flip Matrix -->
<div x-show="!loading && !error && stats?.severity_flip_matrix" class="mt-10">
  <h2 class="text-xl font-bold text-white mb-1">Severity Flip Matrix</h2>
  <p class="text-gray-400 text-sm mb-4">
    How many conflicts cross each severity band boundary. Rows = NVD severity,
    columns = GitHub severity. Diagonal = same band (not a flip).
  </p>
  <div
    class="bg-surface-card border border-surface-border rounded-lg p-4 sm:p-6 overflow-x-auto"
  >
    <table class="text-sm mx-auto">
      <thead>
        <tr>
          <th class="px-3 py-2 text-gray-500 text-xs"></th>
          <template
            x-for="band in ['Critical','High','Medium','Low']"
            :key="'gh-' + band"
          >
            <th
              class="px-3 py-2 text-xs text-gray-400 font-medium text-center"
              x-text="'GH: ' + band"
            ></th>
          </template>
          <th class="px-3 py-2 text-xs text-gray-600 font-medium text-center">
            Total
          </th>
        </tr>
      </thead>
      <tbody>
        <template
          x-for="nvdBand in ['Critical','High','Medium','Low']"
          :key="'nvd-' + nvdBand"
        >
          <tr>
            <td
              class="px-3 py-2 text-xs text-gray-400 font-medium"
              x-text="'NVD: ' + nvdBand"
            ></td>
            <template
              x-for="ghBand in ['Critical','High','Medium','Low']"
              :key="nvdBand + '-' + ghBand"
            >
              <td
                class="px-3 py-2 text-center rounded"
                :style="`background-color: rgba(${nvdBand === ghBand ? '74,222,128' : '248,113,113'}, ${matrixOpacity(nvdBand, ghBand)})`"
              >
                <span
                  class="font-bold text-sm"
                  :class="matrixCell(nvdBand, ghBand) > 0 ? 'text-white' : 'text-gray-700'"
                  x-text="matrixCell(nvdBand, ghBand)"
                ></span>
              </td>
            </template>
            <td
              class="px-3 py-2 text-center text-xs text-gray-500"
              x-text="stats?.severity_matrix_totals?.nvd?.[nvdBand] ?? 0"
            ></td>
          </tr>
        </template>
        <tr class="border-t border-surface-border">
          <td class="px-3 py-2 text-xs text-gray-600 font-medium">Total</td>
          <template
            x-for="ghBand in ['Critical','High','Medium','Low']"
            :key="'total-' + ghBand"
          >
            <td
              class="px-3 py-2 text-center text-xs text-gray-500"
              x-text="stats?.severity_matrix_totals?.gh?.[ghBand] ?? 0"
            ></td>
          </template>
          <td></td>
        </tr>
      </tbody>
    </table>
  </div>
</div>
```

- [ ] **Step 2: Add helper methods to the Alpine component**

In the `conflictMap()` Alpine component, add these methods:

```javascript
        matrixCell(nvdBand, ghBand) {
          if (!this.stats?.severity_flip_matrix) return 0;
          return this.stats.severity_flip_matrix[`${nvdBand}→${ghBand}`] ?? 0;
        },

        matrixOpacity(nvdBand, ghBand) {
          const val = this.matrixCell(nvdBand, ghBand);
          if (val === 0) return '0';
          const max = Math.max(...Object.values(this.stats.severity_flip_matrix));
          return (0.15 + 0.7 * (val / max)).toFixed(2);
        },
```

- [ ] **Step 3: Verify locally**

Open `http://localhost:8080/conflict-map.html` — the 4x4 matrix should appear with color intensity and marginal totals.

- [ ] **Step 4: Commit**

```bash
git add docs/conflict-map.html
git commit -m "feat: add severity flip matrix heatmap to conflict map page"
```

---

### Task 11: Add directional bias trend to conflict-map.html

**Files:**

- Modify: `docs/conflict-map.html`

- [ ] **Step 1: Add the directional bias trend HTML section**

In `docs/conflict-map.html`, after the "Conflicts by Year" chart section but before the histogram (so it's a natural pair with the year chart), add:

```html
<!-- Directional Bias Over Time -->
<div
  x-show="!loading && !error && stats?.conflict_direction_by_year"
  class="mt-10"
>
  <h2 class="text-xl font-bold text-white mb-1">Directional Bias Over Time</h2>
  <p class="text-gray-400 text-sm mb-4">
    When scores conflict, which source rates higher? Shown as a percentage of
    comparable CVEs per year (years with &lt;20 comparable CVEs excluded).
  </p>
  <div
    class="bg-surface-card border border-surface-border rounded-lg p-4 sm:p-6"
  >
    <div class="relative" style="height: 280px;">
      <canvas id="directionChart"></canvas>
    </div>
  </div>
</div>
```

- [ ] **Step 2: Add the direction chart builder**

In the `conflictMap()` Alpine component, add this method:

```javascript
        buildDirectionChart() {
          if (!this.stats?.conflict_direction_by_year) return;
          const raw = this.stats.conflict_direction_by_year;
          const years = Object.keys(raw).sort();
          const nvdPct = years.map(y => {
            const d = raw[y];
            return d.comparable > 0 ? Math.round(d.nvd_higher / d.comparable * 1000) / 10 : 0;
          });
          const ghPct = years.map(y => {
            const d = raw[y];
            return d.comparable > 0 ? Math.round(d.gh_higher / d.comparable * 1000) / 10 : 0;
          });

          const ctx = document.getElementById('directionChart');
          if (!ctx) return;
          new Chart(ctx, {
            type: 'line',
            data: {
              labels: years,
              datasets: [
                {
                  label: 'NVD scores higher (%)',
                  data: nvdPct,
                  borderColor: 'rgba(251,146,60,1)',
                  backgroundColor: 'rgba(251,146,60,0.1)',
                  fill: true,
                  tension: 0.3,
                  pointRadius: 4,
                },
                {
                  label: 'GitHub scores higher (%)',
                  data: ghPct,
                  borderColor: 'rgba(96,165,250,1)',
                  backgroundColor: 'rgba(96,165,250,0.1)',
                  fill: true,
                  tension: 0.3,
                  pointRadius: 4,
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
                  labels: { color: '#9ca3af', font: { family: 'Inter', size: 11 } },
                },
                tooltip: {
                  callbacks: {
                    label: (ctx) => `${ctx.dataset.label}: ${ctx.raw}%`,
                  }
                }
              },
              scales: {
                x: {
                  ticks: { color: '#6b7280' },
                  grid: { color: 'rgba(45,55,72,0.5)' },
                },
                y: {
                  title: { display: true, text: '% of comparable CVEs', color: '#9ca3af', font: { family: 'Inter', size: 12 } },
                  ticks: { color: '#6b7280', callback: v => `${v}%` },
                  grid: { color: 'rgba(45,55,72,0.5)' },
                },
              }
            }
          });
        },
```

- [ ] **Step 3: Call buildDirectionChart() in the chart build chain**

In the `buildChart()` method, after `this.buildYearChart();`, add:

```javascript
this.buildDirectionChart();
```

(The histogram call from Task 9 should come after this one.)

- [ ] **Step 4: Verify locally**

Open `http://localhost:8080/conflict-map.html` — two-line chart should appear below "Conflicts by Year" showing percentage trends.

- [ ] **Step 5: Commit**

```bash
git add docs/conflict-map.html
git commit -m "feat: add directional bias trend chart to conflict map page"
```

---

### Task 12: Create CWE analysis page

**Files:**

- Create: `docs/cwe.html`

- [ ] **Step 1: Create `docs/cwe.html`**

Create `docs/cwe.html` with the full page content. Follow the same structure as `docs/cna.html` — header, stat cards, bar chart, sortable table. The page fetches `data/indexes/cwe-stats.json`.

```html
<!DOCTYPE html>
<html lang="en" class="h-full">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>CWE Conflict Analysis — The Consensus Engine</title>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link
      href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap"
      rel="stylesheet"
    />
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
      tailwind.config = {
        theme: {
          extend: {
            colors: {
              surface: "#0f1117",
              "surface-card": "#1a1d2e",
              "surface-border": "#2d3748",
              brand: "#3b82f6",
              "brand-light": "#60a5fa",
            },
            fontFamily: { sans: ["Inter", "sans-serif"] },
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
      body {
        font-family: "Inter", sans-serif;
      }
    </style>
  </head>
  <body
    class="min-h-full bg-surface text-gray-100"
    x-data="cwePage()"
    x-init="init()"
  >
    <!-- Header -->
    <header class="border-b border-surface-border bg-surface sticky top-0 z-40">
      <div
        class="max-w-7xl mx-auto px-4 sm:px-6 py-3 flex items-center justify-between gap-4"
      >
        <div class="flex items-center gap-6">
          <a
            href="index.html"
            class="flex items-center gap-2 font-bold text-lg text-white hover:text-brand-light transition-colors"
          >
            <span class="text-brand">⚡</span>
            <span class="hidden sm:inline">The Consensus Engine</span>
            <span class="sm:hidden">CE</span>
          </a>
          <nav class="flex items-center gap-4 text-sm whitespace-nowrap">
            <a
              href="index.html"
              class="text-gray-400 hover:text-white transition-colors"
              >Score Conflicts</a
            >
            <a
              href="conflict-map.html"
              class="text-gray-400 hover:text-white transition-colors"
              >Conflict Map</a
            >
            <a
              href="vector-breakdown.html"
              class="text-gray-400 hover:text-white transition-colors hidden sm:inline"
              >Vector Breakdown</a
            >
            <a
              href="cna.html"
              class="text-gray-400 hover:text-white transition-colors hidden sm:inline"
              >CNAs</a
            >
            <span class="text-white font-medium hidden sm:inline">CWEs</span>
            <a
              href="coverage-gap.html"
              class="text-gray-400 hover:text-white transition-colors hidden sm:inline"
              >Coverage Gap</a
            >
          </nav>
        </div>
        <a
          href="https://github.com/RogoLabs/consensus-engine"
          target="_blank"
          rel="noopener"
          class="flex items-center gap-1.5 bg-surface-border hover:bg-gray-700 text-gray-300 hover:text-white px-3 py-1.5 rounded-lg text-xs font-medium transition-colors"
        >
          <svg class="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 24 24">
            <path
              d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"
            />
          </svg>
          GitHub
        </a>
      </div>
    </header>

    <main class="max-w-7xl mx-auto px-4 py-8">
      <div class="mb-8">
        <h1 class="text-2xl font-bold text-white mb-2">
          CWE Conflict Analysis
        </h1>
        <p class="text-gray-400 max-w-2xl text-sm leading-relaxed">
          Which vulnerability types have the most CVSS scoring disagreement
          between NVD and GitHub? Only CWEs with 5+ conflict CVEs are shown.
          Weak/generic CWEs (NVD-CWE-noinfo, etc.) are excluded.
        </p>
      </div>

      <div x-show="loading" class="text-center py-24 text-gray-500 text-sm">
        Loading CWE data...
      </div>
      <div
        x-show="error && !loading"
        class="bg-red-950 border border-red-800 text-red-300 px-4 py-3 rounded-lg text-sm mb-6"
        x-text="error"
      ></div>

      <div x-show="!loading && !error">
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          <div
            class="bg-surface-card border border-surface-border rounded-xl p-4"
          >
            <div
              class="text-2xl font-bold text-brand"
              x-text="cwes.length"
            ></div>
            <div class="text-gray-400 text-xs mt-1">CWEs with conflicts</div>
          </div>
          <div
            class="bg-surface-card border border-surface-border rounded-xl p-4"
          >
            <div
              class="text-2xl font-bold text-red-400"
              x-text="cwes[0]?.cwe_id ?? '—'"
            ></div>
            <div class="text-gray-400 text-xs mt-1">Most conflicts</div>
          </div>
          <div
            class="bg-surface-card border border-surface-border rounded-xl p-4"
          >
            <div
              class="text-2xl font-bold text-orange-400"
              x-text="highestAvg ? `Δ${highestAvg.avg_variance.toFixed(2)}` : '—'"
            ></div>
            <div
              class="text-gray-400 text-xs mt-1"
              x-text="highestAvg ? highestAvg.cwe_id : ''"
            >
              Highest avg drift
            </div>
          </div>
          <div
            class="bg-surface-card border border-surface-border rounded-xl p-4"
          >
            <div
              class="text-2xl font-bold text-yellow-400"
              x-text="generatedAt ? generatedAt.slice(0, 10) : '—'"
            ></div>
            <div class="text-gray-400 text-xs mt-1">Data as of</div>
          </div>
        </div>

        <!-- Bar chart -->
        <div
          class="bg-surface-card border border-surface-border rounded-xl p-5 sm:p-6 mb-8"
        >
          <h2 class="text-lg font-semibold text-white mb-1">
            Avg Drift by CWE (top 15)
          </h2>
          <p class="text-gray-500 text-xs mb-4">
            Average CVSS variance among conflict CVEs, grouped by NVD CWE
            assignment
          </p>
          <div class="relative" style="height: 320px;">
            <canvas id="cweChart"></canvas>
          </div>
        </div>

        <!-- Table -->
        <div
          class="bg-surface-card border border-surface-border rounded-xl overflow-hidden"
        >
          <div
            class="px-4 py-3 border-b border-surface-border flex items-center gap-3"
          >
            <span
              class="text-sm font-medium text-gray-300"
              x-text="`${filtered.length} CWEs`"
            ></span>
            <input
              x-model="search"
              type="search"
              placeholder="Filter by CWE ID or name..."
              class="ml-auto bg-surface border border-surface-border text-gray-200 placeholder-gray-600 rounded px-2.5 py-1 text-xs focus:outline-none focus:border-brand w-52"
            />
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-sm">
              <thead>
                <tr
                  class="border-b border-surface-border text-gray-500 text-xs uppercase tracking-wider"
                >
                  <th class="px-4 py-3 text-left">#</th>
                  <th class="px-4 py-3 text-left">CWE</th>
                  <th class="px-4 py-3 text-left hidden sm:table-cell">Name</th>
                  <th
                    class="px-4 py-3 text-right cursor-pointer hover:text-white"
                    @click="sortBy('conflict_count')"
                  >
                    Conflicts
                    <span x-show="sort === 'conflict_count'">&#8595;</span>
                  </th>
                  <th
                    class="px-4 py-3 text-right cursor-pointer hover:text-white"
                    @click="sortBy('avg_variance')"
                  >
                    Avg Drift
                    <span x-show="sort === 'avg_variance'">&#8595;</span>
                  </th>
                  <th class="px-4 py-3 text-right hidden md:table-cell">
                    NVD Higher %
                  </th>
                  <th class="px-4 py-3 text-right hidden md:table-cell">
                    GH Higher %
                  </th>
                </tr>
              </thead>
              <tbody class="divide-y divide-surface-border">
                <template x-for="(row, i) in filtered" :key="row.cwe_id">
                  <tr class="transition-colors hover:bg-surface">
                    <td
                      class="px-4 py-3 text-gray-600 text-xs"
                      x-text="i + 1"
                    ></td>
                    <td
                      class="px-4 py-3 font-mono font-medium text-brand"
                      x-text="row.cwe_id"
                    ></td>
                    <td
                      class="px-4 py-3 text-gray-400 text-xs hidden sm:table-cell"
                      x-text="row.name"
                    ></td>
                    <td
                      class="px-4 py-3 text-right text-gray-300"
                      x-text="row.conflict_count"
                    ></td>
                    <td
                      class="px-4 py-3 text-right font-mono"
                      :class="row.avg_variance >= 3 ? 'text-red-400' : row.avg_variance >= 1.5 ? 'text-orange-400' : 'text-gray-300'"
                      x-text="row.avg_variance.toFixed(2)"
                    ></td>
                    <td
                      class="px-4 py-3 text-right text-orange-400 hidden md:table-cell"
                      x-text="row.conflict_count ? `${(row.nvd_higher_count / row.conflict_count * 100).toFixed(0)}%` : '—'"
                    ></td>
                    <td
                      class="px-4 py-3 text-right text-blue-400 hidden md:table-cell"
                      x-text="row.conflict_count ? `${(row.gh_higher_count / row.conflict_count * 100).toFixed(0)}%` : '—'"
                    ></td>
                  </tr>
                </template>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </main>

    <footer
      class="border-t border-surface-border mt-12 py-6 text-center text-gray-600 text-xs"
    >
      Built by
      <a href="https://rogolabs.net" class="text-brand hover:underline"
        >Jerry Gamblin at RogoLabs</a
      >
      ·
      <a
        href="https://github.com/RogoLabs/consensus-engine"
        class="text-brand hover:underline"
        >GitHub</a
      >
    </footer>

    <script>
      function cwePage() {
        return {
          loading: true,
          error: null,
          cwes: [],
          generatedAt: null,
          sort: "conflict_count",
          search: "",

          async init() {
            try {
              const res = await fetch("data/indexes/cwe-stats.json");
              if (!res.ok) throw new Error(`HTTP ${res.status}`);
              const json = await res.json();
              this.cwes = json.cwes ?? [];
              this.generatedAt = json.generated_at ?? null;
            } catch (e) {
              this.error = `Failed to load CWE data: ${e.message}`;
            } finally {
              this.loading = false;
            }
            if (!this.error) this.$nextTick(() => this.buildChart());
          },

          sortBy(field) {
            this.sort = field;
          },

          get filtered() {
            let result = [...this.cwes].sort(
              (a, b) => (b[this.sort] ?? 0) - (a[this.sort] ?? 0),
            );
            const q = this.search.trim().toLowerCase();
            if (q)
              result = result.filter(
                (r) =>
                  r.cwe_id.toLowerCase().includes(q) ||
                  r.name.toLowerCase().includes(q),
              );
            return result;
          },

          get highestAvg() {
            if (!this.cwes.length) return null;
            return this.cwes.reduce((a, b) =>
              a.avg_variance > b.avg_variance ? a : b,
            );
          },

          buildChart() {
            const top = [...this.cwes]
              .sort((a, b) => b.avg_variance - a.avg_variance)
              .slice(0, 15);
            const labels = top.map((c) => `${c.cwe_id} — ${c.name}`);
            const data = top.map((c) => c.avg_variance);
            const colors = data.map((v) =>
              v >= 3 ? "#f87171" : v >= 1.5 ? "#facc15" : "#4ade80",
            );

            const ctx = document.getElementById("cweChart");
            if (!ctx) return;
            new Chart(ctx, {
              type: "bar",
              data: {
                labels,
                datasets: [
                  {
                    label: "Avg Drift (Δ)",
                    data,
                    backgroundColor: colors,
                    borderRadius: 4,
                    borderSkipped: false,
                  },
                ],
              },
              options: {
                indexAxis: "y",
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                  legend: { display: false },
                  tooltip: {
                    callbacks: {
                      label: (ctx) => ` Avg Δ${ctx.raw.toFixed(2)}`,
                    },
                  },
                },
                scales: {
                  x: {
                    min: 0,
                    ticks: { color: "#9ca3af", callback: (v) => `Δ${v}` },
                    grid: { color: "#2d3748" },
                  },
                  y: {
                    ticks: { color: "#d1d5db", font: { size: 10 } },
                    grid: { display: false },
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

- [ ] **Step 2: Verify locally**

```bash
python3 -m http.server 8080 --directory docs
```

Open `http://localhost:8080/cwe.html` — should show stat cards, horizontal bar chart of top 15 CWEs by avg drift, and a sortable/searchable table.

- [ ] **Step 3: Commit**

```bash
git add docs/cwe.html
git commit -m "feat: add CWE conflict analysis page"
```

---

### Task 13: Add CWE and Methodology links to nav on all pages

**Files:**

- Modify: `docs/index.html`, `docs/conflict-map.html`, `docs/vector-breakdown.html`, `docs/cna.html`, `docs/coverage-gap.html`, `docs/cwe.html`

The nav in every page currently has: Score Conflicts | Conflict Map | Vector Breakdown | CNAs | Coverage Gap. We need to add CWEs (after CNAs) and Methodology (at the end, after Coverage Gap).

- [ ] **Step 1: Update nav in `docs/index.html`**

Find the nav block (lines 56-62). After the Coverage Gap link, add:

```html
<a
  href="methodology.html"
  class="text-gray-400 hover:text-white transition-colors hidden sm:inline"
  >Methodology</a
>
```

And after the CNAs link, add:

```html
<a
  href="cwe.html"
  class="text-gray-400 hover:text-white transition-colors hidden sm:inline"
  >CWEs</a
>
```

- [ ] **Step 2: Update nav in `docs/conflict-map.html`**

Same pattern. After CNAs link add CWEs link, after Coverage Gap link add Methodology link.

- [ ] **Step 3: Update nav in `docs/vector-breakdown.html`**

Same pattern.

- [ ] **Step 4: Update nav in `docs/cna.html`**

Same pattern. CWEs link goes after the CNAs `<span>`.

- [ ] **Step 5: Update nav in `docs/coverage-gap.html`**

Same pattern.

- [ ] **Step 6: Update nav in `docs/cwe.html`**

Already has CWEs as active `<span>`. Add Methodology link after Coverage Gap.

- [ ] **Step 7: Verify nav consistency across all pages**

Open each page locally and verify the nav shows: Score Conflicts | Conflict Map | Vector Breakdown | CNAs | CWEs | Coverage Gap | Methodology — with the correct one highlighted on each page.

- [ ] **Step 8: Commit**

```bash
git add docs/index.html docs/conflict-map.html docs/vector-breakdown.html docs/cna.html docs/coverage-gap.html docs/cwe.html
git commit -m "feat: add CWEs and Methodology links to nav across all pages"
```

---

### Task 14: Create methodology page

**Files:**

- Create: `docs/methodology.html`

- [ ] **Step 1: Create `docs/methodology.html`**

Static page, same theme as other pages. No data fetches, no Alpine.js data component needed (just static HTML). Uses the same header/footer pattern.

```html
<!DOCTYPE html>
<html lang="en" class="h-full">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Methodology — The Consensus Engine</title>
    <meta
      name="description"
      content="How the Drift Score is computed, what data sources are used, and known limitations of The Consensus Engine."
    />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link
      href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap"
      rel="stylesheet"
    />
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
      tailwind.config = {
        theme: {
          extend: {
            colors: {
              surface: "#0f1117",
              "surface-card": "#1a1d2e",
              "surface-border": "#2d3748",
              brand: "#3b82f6",
              "brand-light": "#60a5fa",
            },
            fontFamily: { sans: ["Inter", "sans-serif"] },
          },
        },
      };
    </script>
    <style>
      body {
        font-family: "Inter", sans-serif;
      }
    </style>
  </head>
  <body class="min-h-full bg-surface text-gray-100">
    <!-- Header -->
    <header class="border-b border-surface-border bg-surface sticky top-0 z-40">
      <div
        class="max-w-7xl mx-auto px-4 sm:px-6 py-3 flex items-center justify-between gap-4"
      >
        <div class="flex items-center gap-6">
          <a
            href="index.html"
            class="flex items-center gap-2 font-bold text-lg text-white hover:text-brand-light transition-colors"
          >
            <span class="text-brand">⚡</span>
            <span class="hidden sm:inline">The Consensus Engine</span>
            <span class="sm:hidden">CE</span>
          </a>
          <nav class="flex items-center gap-4 text-sm whitespace-nowrap">
            <a
              href="index.html"
              class="text-gray-400 hover:text-white transition-colors"
              >Score Conflicts</a
            >
            <a
              href="conflict-map.html"
              class="text-gray-400 hover:text-white transition-colors"
              >Conflict Map</a
            >
            <a
              href="vector-breakdown.html"
              class="text-gray-400 hover:text-white transition-colors hidden sm:inline"
              >Vector Breakdown</a
            >
            <a
              href="cna.html"
              class="text-gray-400 hover:text-white transition-colors hidden sm:inline"
              >CNAs</a
            >
            <a
              href="cwe.html"
              class="text-gray-400 hover:text-white transition-colors hidden sm:inline"
              >CWEs</a
            >
            <a
              href="coverage-gap.html"
              class="text-gray-400 hover:text-white transition-colors hidden sm:inline"
              >Coverage Gap</a
            >
            <span class="text-white font-medium hidden sm:inline"
              >Methodology</span
            >
          </nav>
        </div>
        <a
          href="https://github.com/RogoLabs/consensus-engine"
          target="_blank"
          rel="noopener"
          class="flex items-center gap-1.5 bg-surface-border hover:bg-gray-700 text-gray-300 hover:text-white px-3 py-1.5 rounded-lg text-xs font-medium transition-colors"
        >
          <svg class="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 24 24">
            <path
              d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"
            />
          </svg>
          GitHub
        </a>
      </div>
    </header>

    <main class="max-w-3xl mx-auto px-4 py-10">
      <h1 class="text-3xl font-bold text-white mb-6">Methodology</h1>

      <div
        class="prose prose-invert max-w-none space-y-8 text-gray-300 text-sm leading-relaxed"
      >
        <section>
          <h2 class="text-xl font-semibold text-white mb-3">
            What the Drift Score measures
          </h2>
          <p>
            The Drift Score is
            <span class="text-white font-medium font-mono"
              >|GitHub CVSS - NVD CVSS|</span
            >
            — the absolute difference between the CVSS base scores assigned by
            NVD and the GitHub Advisory Database for the same CVE. Scores are
            only compared when both sources use the
            <strong>same CVSS version</strong> (e.g., both v3.1). Cross-version
            comparisons (v3.1 vs. v4.0) are classified as data gaps, not
            conflicts.
          </p>
          <p class="text-gray-500 mt-2">
            Note: The <span class="font-mono">drift_score</span> and
            <span class="font-mono">cvss_variance</span> fields in the data are
            currently equivalent. Both represent the raw score delta. The
            project retains both fields in case the formula evolves in the
            future.
          </p>
        </section>

        <section>
          <h2 class="text-xl font-semibold text-white mb-3">Classification</h2>
          <p>
            Every CVE in the dataset is assigned a
            <span class="font-mono text-white">drift_type</span>:
          </p>
          <ul class="list-disc list-inside space-y-1 mt-2">
            <li>
              <strong class="text-yellow-400">conflict</strong> — Both NVD and
              GitHub have assigned a CVSS score using the same version, and the
              scores differ.
            </li>
            <li>
              <strong class="text-gray-400">gap</strong> — One or both sources
              have not assigned a score, or the scores use different CVSS
              versions (cross-version mismatch).
            </li>
            <li>
              <strong class="text-red-400">rejected</strong> — NVD has marked
              the CVE as Rejected, but GitHub still maintains an advisory for
              it. This is an existence dispute, not a score dispute, so the
              Drift Score is 0.0.
            </li>
          </ul>
        </section>

        <section>
          <h2 class="text-xl font-semibold text-white mb-3">Data sources</h2>
          <ul class="list-disc list-inside space-y-2 mt-2">
            <li>
              <strong class="text-white">NVD API 2.0</strong> — CVSS scores, CWE
              assignments, CPE strings, publication dates, and analysis status.
              For CVEs with status "Analyzed" or "Modified," the score reflects
              NVD's independent assessment. For CVEs with status
              <strong>"Deferred,"</strong> NVD did not independently analyze the
              CVE — the score is the CNA-provided score passed through the NVD
              API. Approximately 7% of conflicts in this dataset fall into this
              category.
            </li>
            <li>
              <strong class="text-white">GitHub Advisory Database</strong> —
              CVSS scores (primarily v3.1), affected package versions, and GHSA
              identifiers. GitHub's scores are not always independent
              assessments — many come from maintainer-submitted advisories or
              CNA-provided vectors.
            </li>
          </ul>
          <p class="mt-2">
            Both sources are fetched daily at 02:00 UTC via GitHub Actions.
            After the initial backfill, only incremental updates are fetched
            (last 25 hours for NVD, last 48 hours for GitHub).
          </p>
        </section>

        <section>
          <h2 class="text-xl font-semibold text-white mb-3">
            Known limitations
          </h2>
          <ul class="list-disc list-inside space-y-3 mt-2">
            <li>
              <strong class="text-white">Ecosystem bias.</strong>
              GitHub Advisory Database covers software package ecosystems (npm,
              Maven, pip, Go, NuGet, Composer, RubyGems, Rust). CVEs for
              hardware, firmware, network appliances, and non-packaged software
              are largely absent. The conflict rate reported here is
              representative of these ecosystems, not all CVEs.
            </li>
            <li>
              <strong class="text-white">Survivorship bias.</strong>
              Only ~4.5% of CVEs in the dataset have scores from both NVD and
              GitHub Advisory. The conflict rate applies to this small,
              non-random subset of dual-scored CVEs. It should not be
              generalized to "X% of all CVEs have conflicting scores."
            </li>
            <li>
              <strong class="text-white">CNA pass-through.</strong>
              ~7% of conflict CVEs have NVD status "Deferred." For these, the
              "NVD score" is actually the CNA-provided score — not an
              independent NVD assessment. The leaderboard provides a filter to
              exclude these.
            </li>
            <li>
              <strong class="text-white">GitHub upstream sources.</strong>
              GitHub Advisory scores are not always independent assessments.
              When GitHub and the assigning CNA agree on a score but NVD
              independently re-scores differently, the measured "disagreement"
              is NVD-vs-CNA rather than NVD-vs-GitHub.
            </li>
            <li>
              <strong class="text-white">Temporal alignment.</strong>
              NVD and GitHub data are fetched in the same CI run but not
              simultaneously. For very new CVEs, one source may have been
              updated between fetch times.
            </li>
            <li>
              <strong class="text-white">CVSS calculator rounding.</strong>
              Different implementations of the CVSS specification can produce
              slightly different scores from identical vector strings. ~8% of
              conflicts have a variance of exactly 0.1, and deltas of 0.2-0.3
              may also be implementation artifacts rather than genuine
              analytical disagreements.
            </li>
            <li>
              <strong class="text-white">Terminology.</strong>
              The field <span class="font-mono">cvss_variance</span> in the data
              is the <em>range</em> (max - min), not the statistical variance
              (mean of squared deviations). It is equivalent to
              <span class="font-mono">|GitHub CVSS - NVD CVSS|</span>.
            </li>
            <li>
              <strong class="text-white">CNA minimum threshold.</strong>
              The CNA analysis page only includes CNAs with 5 or more
              dual-scored CVEs to avoid misleading statistics from small
              samples. The CWE analysis page applies the same threshold.
            </li>
          </ul>
        </section>

        <section>
          <h2 class="text-xl font-semibold text-white mb-3">
            Update frequency
          </h2>
          <p>
            Data is updated daily at 02:00 UTC via a GitHub Actions pipeline.
            After the initial historical backfill, only CVEs modified in the
            last 25 hours (NVD) or 48 hours (GitHub) are re-fetched. All
            aggregate indexes are recomputed from scratch on every run.
          </p>
        </section>

        <section>
          <h2 class="text-xl font-semibold text-white mb-3">How to cite</h2>
          <div
            class="bg-surface-card border border-surface-border rounded-lg p-4 font-mono text-xs text-gray-400 leading-relaxed"
          >
            Gamblin, J. (2026). The Consensus Engine: Tracking CVSS Scoring
            Divergence Between NVD and GitHub Advisory Database. RogoLabs.
            https://github.com/RogoLabs/consensus-engine
          </div>
        </section>
      </div>
    </main>

    <footer
      class="border-t border-surface-border mt-12 py-6 text-center text-gray-600 text-xs"
    >
      Built by
      <a href="https://rogolabs.net" class="text-brand hover:underline"
        >Jerry Gamblin at RogoLabs</a
      >
      ·
      <a
        href="https://github.com/RogoLabs/consensus-engine"
        class="text-brand hover:underline"
        >GitHub</a
      >
    </footer>
  </body>
</html>
```

- [ ] **Step 2: Verify locally**

```bash
python3 -m http.server 8080 --directory docs
```

Open `http://localhost:8080/methodology.html` — should show all sections with correct styling, nav highlighting "Methodology."

- [ ] **Step 3: Commit**

```bash
git add docs/methodology.html
git commit -m "feat: add methodology and limitations page"
```

---

### Task 15: Final verification and cleanup commit

- [ ] **Step 1: Run the full pipeline**

```bash
cd /Users/gamblin/Documents/Github/consensus-engine
python3 scripts/compute_drift.py
python3 scripts/build_indexes.py
```

- [ ] **Step 2: Serve and verify all pages**

```bash
python3 -m http.server 8080 --directory docs
```

Open each page and verify:

- `index.html` — variance filter buttons work, Deferred checkbox works, stat card subtitle updates, NVD Status visible on medium screens, Deferred disclosure in callout
- `conflict-map.html` — scatter plot, year chart, directional bias trend (line chart with percentages), histogram (color-coded bars), severity flip matrix (4x4 with marginal totals)
- `vector-breakdown.html` — data-driven callout shows correct metric with strongest directional skew
- `cna.html` — unchanged, nav updated
- `cwe.html` — stat cards, bar chart, sortable table with CWE data
- `coverage-gap.html` — unchanged, nav updated
- `methodology.html` — all sections render, static content, no data fetch errors

- [ ] **Step 3: Commit any recomputed data**

```bash
git add docs/data/indexes/
git commit -m "chore: regenerate all indexes with new stats fields"
```
