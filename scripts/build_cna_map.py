"""Build a UUID → short name map for CNA source identifiers.

NVD transitioned from email-style sourceIdentifiers (secure@microsoft.com)
to UUID-style identifiers (f86ef6dc-4d3a-42ad-8f28-e6d5547a5007). This
script resolves those UUIDs to human-readable short names by cross-referencing
the CVEProject/cvelistV5 repository, which stores assignerOrgId +
assignerShortName in every CVE's cveMetadata.

Strategy:
  1. Scan all local CVE JSON files to find unique UUID-style assigning_cna values.
  2. For each UUID, find a CVE in our local data that has it, then fetch that
     CVE from cvelistV5 raw content to read assignerShortName.
  3. Write docs/data/indexes/cna-uuid-map.json.

The output file is merged with any existing map so previously resolved entries
survive even if we no longer have local CVEs from that CNA.
"""

import json
import re
import time
import pathlib
import urllib.request
import urllib.error
import sys

DATA_DIR = pathlib.Path("docs/data")
INDEXES_DIR = DATA_DIR / "indexes"
MAP_PATH = INDEXES_DIR / "cna-uuid-map.json"

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)

CVELISTV5_RAW = (
    "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
    "/{year}/{bucket}/{cve_id}.json"
)


def _cve_bucket(cve_id: str) -> str:
    """Return the cvelistV5 directory bucket for a CVE ID.

    CVE-2024-12345 → '12xxx', CVE-2024-1234 → '1xxx', CVE-2024-123 → '0xxx'
    """
    num = cve_id.split("-")[2]  # e.g. "12345"
    if len(num) <= 3:
        return "0xxx"
    return num[:-3] + "xxx"


def _fetch_shortname(cve_id: str) -> str | None:
    """Fetch assignerShortName from cvelistV5 for a given CVE ID."""
    parts = cve_id.split("-")
    year = parts[1]
    bucket = _cve_bucket(cve_id)
    url = CVELISTV5_RAW.format(year=year, bucket=bucket, cve_id=cve_id)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "consensus-engine/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        return data.get("cveMetadata", {}).get("assignerShortName")
    except Exception:
        return None


def collect_uuid_cve_samples() -> dict[str, str]:
    """Return {uuid: cve_id} — one sample CVE per UUID from local data."""
    samples: dict[str, str] = {}
    for f in DATA_DIR.rglob("CVE-*.json"):
        try:
            d = json.loads(f.read_text())
        except Exception:
            continue
        cna = d.get("assigning_cna", "")
        cve_id = d.get("cve_id", "")
        if cna and cve_id and UUID_RE.match(cna) and cna not in samples:
            samples[cna] = cve_id
    return samples


def main() -> None:
    INDEXES_DIR.mkdir(parents=True, exist_ok=True)

    # Load existing map so we don't re-fetch already-resolved UUIDs
    existing: dict[str, str] = {}
    if MAP_PATH.exists():
        try:
            existing = json.loads(MAP_PATH.read_text())
        except Exception:
            pass

    samples = collect_uuid_cve_samples()
    print(f"Found {len(samples)} unique UUID-style CNAs in local data")

    unresolved = {uuid: cve for uuid, cve in samples.items() if uuid not in existing}
    print(f"Need to resolve {len(unresolved)} new UUIDs (have {len(existing)} cached)")

    resolved = dict(existing)
    failed = []

    for i, (uuid, cve_id) in enumerate(unresolved.items(), 1):
        shortname = _fetch_shortname(cve_id)
        if shortname:
            resolved[uuid] = shortname
            print(f"  [{i}/{len(unresolved)}] {uuid} → {shortname} (via {cve_id})")
        else:
            failed.append(uuid)
            print(f"  [{i}/{len(unresolved)}] {uuid} — FAILED (via {cve_id})", file=sys.stderr)
        # Be polite to GitHub raw CDN
        if i % 10 == 0:
            time.sleep(1)

    MAP_PATH.write_text(json.dumps(resolved, indent=2, sort_keys=True))
    print(f"\nCNA UUID map written: {MAP_PATH} ({len(resolved)} entries)")
    if failed:
        print(f"Could not resolve {len(failed)} UUIDs: {failed[:10]}", file=sys.stderr)


if __name__ == "__main__":
    main()
