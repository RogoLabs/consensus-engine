# LinkedIn Post & Image Generation — Design Spec

## Context

The Consensus Engine has been running for several weeks, tracking CVSS scoring divergence between NVD and GitHub Advisory Database. The site was recently redesigned (2026-04-18) and is actively ingesting data every 6 hours. Jerry wants to showcase the project on LinkedIn with a compelling post and a composite screenshot image. The goal is builder/hacker energy — showing off what he built and the surprising findings.

## LinkedIn Post Copy (Final)

```
25.6% of CVEs scored by both NVD and GitHub Advisory have meaningful scoring conflicts.

I built something to track this at scale.

The Consensus Engine checks every CVE scored by both NVD and GitHub Advisory Database. When both sources score the same vulnerability differently, I flag it — and the results are wild:

→ 1,585 active scoring conflicts
→ 849 CVEs that cross severity band boundaries (Critical → Medium, etc.)
→ Maximum observed drift: 6.9 points on the same CVE
→ NVD and GitHub disagree on MongoDB's CVEs 88.9% of the time

The stack: No backend. No database. The repo IS the database — flat JSON files, GitHub Actions pipeline running every 6 hours, and a static frontend on GitHub Pages. All open source.

If your patching SLA says "Critical = 7 days" but one source says Critical and the other says Medium... which clock are you on?

🔗 https://rogolabs.github.io/consensus-engine/

#cybersecurity #vulnerabilitymanagement #cvss #opensource #infosec
```

## Image Specification

**Format:** 1200×627px PNG (LinkedIn recommended dimensions)

**Composition:** Two-panel composite from real site screenshots

### Left Panel (40% width)

- Source: `docs/index.html` stat row area
- Content captured:
  - 25.6% conflict rate
  - 849 severity flips
  - Directional bias: NVD higher 57% / GitHub higher 43%
- If the stat row doesn't show this exact layout on the live site, capture the hero section and crop to the stats area

### Right Panel (60% width)

- Source: `docs/patterns.html` scatter chart
- Content: The NVD vs GitHub CVSS scatter plot showing red dots for severity boundary crossings
- Wait for Chart.js to fully render before capture

### Stitching

- Side-by-side with a thin dark divider or seamless join
- Background: match site dark theme (#0f0f23 or similar)
- Final output: single 1200×627 PNG

## Implementation Approach

### Tool: Playwright (Python)

1. **Serve the site locally** — `python -m http.server 8080 --directory docs`
2. **Screenshot the stat section** — Navigate to `http://localhost:8080/`, wait for Alpine.js hydration and data fetch, clip the stat row region
3. **Screenshot the scatter plot** — Navigate to `http://localhost:8080/patterns.html`, wait for Chart.js render, clip the scatter chart canvas area
4. **Composite the images** — Use Pillow (PIL) to stitch the two captures into a 1200×627 final image
5. **Output** — Save to `docs/linkedin-share.png` (or a location of Jerry's choice)

### Dependencies

- `playwright` (Python) + chromium browser install
- `Pillow` for image compositing
- Local HTTP server for the static site

### Script Location

- `scripts/generate_linkedin_image.py`

## Verification

1. Serve site locally and confirm both pages render correctly
2. Run the Playwright script
3. Open the output PNG and verify:
   - Stats are legible at LinkedIn's display size
   - Scatter plot dots and colors are visible
   - No clipping or layout issues
   - Dark theme background is consistent across both panels
4. Preview in LinkedIn's post composer to confirm aspect ratio
