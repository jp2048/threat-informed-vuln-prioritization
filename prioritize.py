#!/usr/bin/env python3
"""
Threat-Informed Vulnerability Prioritization
=============================================

Takes scanner findings (Qualys / Nessus style CSV export) and re-prioritizes
them using real-world threat intelligence instead of CVSS alone:

  1. CISA Known Exploited Vulnerabilities (KEV) catalog -- CVEs confirmed
     exploited in the wild. Downloaded from CISA and cached locally.
  2. EPSS (Exploit Prediction Scoring System) scores from the FIRST API --
     the modeled probability a CVE will be exploited in the next 30 days.
  3. CVSS base score as a severity floor for findings with no CVE mapping
     or no threat-intel coverage.

Priority model (evaluated top-down, first match wins):

  P1 Critical : KEV-listed (actively exploited) OR EPSS >= 0.50
  P2 High     : CVSS >= 9.0 OR EPSS >= 0.20
  P3 Medium   : CVSS >= 7.0 OR EPSS >= 0.05
  P4 Low      : everything else

Usage:
    python3 prioritize.py                       # uses sample_findings.csv
    python3 prioritize.py -i findings.csv -o prioritized.csv
    python3 prioritize.py --refresh-kev         # force fresh KEV download

Dependencies: requests (see requirements.txt). Everything else is stdlib.
No API keys required -- both data sources are public.
"""

import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime, timezone

import requests

# ---------------------------------------------------------------------------
# Data sources & local caches
# ---------------------------------------------------------------------------

KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
)
EPSS_API_URL = "https://api.first.org/data/v1/epss"

KEV_CACHE_FILE = "kev_catalog.csv"
KEV_MAX_AGE_HOURS = 24          # re-download the catalog if older than this
EPSS_CACHE_FILE = "epss_cache.json"
EPSS_BATCH_SIZE = 100           # FIRST API accepts comma-separated CVE lists
REQUEST_TIMEOUT = 30

# ---------------------------------------------------------------------------
# Priority model thresholds
# ---------------------------------------------------------------------------

EPSS_P1 = 0.50
EPSS_P2 = 0.20
EPSS_P3 = 0.05
CVSS_P2 = 9.0
CVSS_P3 = 7.0

TIERS = ("P1", "P2", "P3", "P4")
TIER_LABELS = {
    "P1": "P1 Critical",
    "P2": "P2 High",
    "P3": "P3 Medium",
    "P4": "P4 Low",
}
# Remediation SLA targets (calendar days) -- adjust to your org's policy.
SLA_DAYS = {"P1": 7, "P2": 15, "P3": 30, "P4": 90}

INPUT_COLUMNS = [
    "plugin_id",
    "cve",
    "host",
    "severity",
    "cvss_score",
    "plugin_name",
    "solution",
]
OUTPUT_COLUMNS = INPUT_COLUMNS + [
    "kev_exploited",
    "kev_vuln_name",
    "epss_score",
    "epss_percentile",
    "priority_tier",
    "sla_days",
    "rationale",
]


# ---------------------------------------------------------------------------
# CISA KEV catalog
# ---------------------------------------------------------------------------

def _cache_is_fresh(path, max_age_hours):
    """True if the cache file exists and is younger than max_age_hours."""
    if not os.path.exists(path):
        return False
    age_hours = (time.time() - os.path.getmtime(path)) / 3600
    return age_hours < max_age_hours


def load_kev_catalog(force_refresh=False):
    """
    Return {cve_id: {vuln_name, date_added, due_date}} from the CISA KEV
    catalog. Downloads a fresh copy when the cache is missing/stale; falls
    back to the stale cache (or an empty catalog with a warning) if the
    download fails so a run never hard-fails on network issues.
    """
    path = KEV_CACHE_FILE
    if force_refresh or not _cache_is_fresh(path, KEV_MAX_AGE_HOURS):
        try:
            print(f"[*] Downloading CISA KEV catalog...", flush=True)
            resp = requests.get(KEV_CATALOG_URL, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(resp.text)
            print(f"[*] KEV catalog cached to {path}", flush=True)
        except requests.RequestException as exc:
            print(f"[!] KEV download failed: {exc}", flush=True)
            if not os.path.exists(path):
                print("[!] No cached KEV catalog available; "
                      "KEV enrichment will be skipped.", flush=True)
                return {}

    catalog = {}
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                cve = (row.get("cveID") or "").strip().upper()
                if cve:
                    catalog[cve] = {
                        "vuln_name": row.get("vulnerabilityName", "").strip(),
                        "date_added": row.get("dateAdded", "").strip(),
                        "due_date": row.get("dueDate", "").strip(),
                    }
    except (OSError, csv.Error) as exc:
        print(f"[!] Could not parse KEV cache ({exc}); "
              "KEV enrichment will be skipped.", flush=True)
        return {}
    print(f"[*] Loaded {len(catalog)} KEV entries", flush=True)
    return catalog


# ---------------------------------------------------------------------------
# EPSS scores (FIRST API) with local cache
# ---------------------------------------------------------------------------

def _load_epss_cache(path):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
            return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _save_epss_cache(path, cache):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(cache, fh, indent=2, sort_keys=True)


def fetch_epss_scores(cve_ids):
    """
    Return {cve_id: {"epss": float, "percentile": float, "date": str}}.

    CVEs already in the local cache are reused; only missing CVEs hit the
    FIRST API (batched). If the API call fails, cached values are used and
    missing CVEs are left without a score (handled downstream) -- the run
    never fails just because EPSS is unreachable.
    """
    cache = _load_epss_cache(EPSS_CACHE_FILE)
    wanted = sorted({c.strip().upper() for c in cve_ids if c and c.strip()})
    missing = [c for c in wanted if c not in cache]

    if missing:
        print(f"[*] Querying EPSS API for {len(missing)} CVE(s)...", flush=True)
        today = datetime.now(timezone.utc).date().isoformat()
        try:
            for i in range(0, len(missing), EPSS_BATCH_SIZE):
                batch = missing[i:i + EPSS_BATCH_SIZE]
                resp = requests.get(
                    EPSS_API_URL,
                    params={"cve": ",".join(batch)},
                    timeout=REQUEST_TIMEOUT,
                )
                resp.raise_for_status()
                payload = resp.json()
                for item in payload.get("data", []):
                    cve = (item.get("cve") or "").strip().upper()
                    try:
                        cache[cve] = {
                            "epss": float(item.get("epss", 0.0)),
                            "percentile": float(item.get("percentile", 0.0)),
                            "date": item.get("date", today),
                        }
                    except (TypeError, ValueError):
                        continue
            _save_epss_cache(EPSS_CACHE_FILE, cache)
            print(f"[*] EPSS cache updated ({EPSS_CACHE_FILE})", flush=True)
        except (requests.RequestException, ValueError) as exc:
            print(f"[!] EPSS API query failed: {exc}", flush=True)
            print("[!] Continuing with cached EPSS values only; "
                  "unscored CVEs fall back to CVSS.", flush=True)
    else:
        print("[*] All CVEs already in EPSS cache; no API calls needed.",
              flush=True)

    return {cve: cache[cve] for cve in wanted if cve in cache}


# ---------------------------------------------------------------------------
# Priority model
# ---------------------------------------------------------------------------

def prioritize(cve, cvss, kev_entry, epss_entry):
    """
    Apply the threat-informed priority model.

    Returns (tier, sla_days, rationale). Rationale names the exact rule that
    fired so the tier is auditable -- important when remediation owners ask
    "why is this P1?".
    """
    cve = (cve or "").strip().upper()

    # P1: confirmed exploitation in the wild beats every other signal.
    if kev_entry:
        return (
            "P1",
            SLA_DAYS["P1"],
            f"CISA KEV: actively exploited in the wild "
            f"({kev_entry['vuln_name'] or 'listed'})",
        )

    epss = epss_entry.get("epss") if epss_entry else None

    # P1: very high predicted exploitation likelihood.
    if epss is not None and epss >= EPSS_P1:
        return (
            "P1",
            SLA_DAYS["P1"],
            f"EPSS {epss:.3f} >= {EPSS_P1}: high predicted exploitation likelihood",
        )

    # P2: severe CVSS or elevated exploitation likelihood.
    if cvss >= CVSS_P2:
        return "P2", SLA_DAYS["P2"], f"CVSS {cvss:.1f} >= {CVSS_P2}"
    if epss is not None and epss >= EPSS_P2:
        return (
            "P2",
            SLA_DAYS["P2"],
            f"EPSS {epss:.3f} >= {EPSS_P2}: elevated exploitation likelihood",
        )

    # P3: high-ish CVSS or non-trivial exploitation likelihood.
    if cvss >= CVSS_P3:
        return "P3", SLA_DAYS["P3"], f"CVSS {cvss:.1f} >= {CVSS_P3}"
    if epss is not None and epss >= EPSS_P3:
        return (
            "P3",
            SLA_DAYS["P3"],
            f"EPSS {epss:.3f} >= {EPSS_P3}: non-trivial exploitation likelihood",
        )

    # P4: nothing above fired.
    if not cve:
        return (
            "P4",
            SLA_DAYS["P4"],
            "No CVE mapping; low CVSS -- track in standard patch cycle",
        )
    if epss is None:
        return (
            "P4",
            SLA_DAYS["P4"],
            "Low CVSS; EPSS unavailable -- track in standard patch cycle",
        )
    return (
        "P4",
        SLA_DAYS["P4"],
        f"Low CVSS and low predicted exploitation (EPSS {epss:.3f})",
    )


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def read_findings(path):
    """Read scanner findings CSV; tolerate missing/extra columns gracefully."""
    findings = []
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        missing = [c for c in INPUT_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            raise ValueError(
                f"Input CSV is missing required columns: {', '.join(missing)}"
            )
        for row in reader:
            findings.append({c: (row.get(c) or "").strip() for c in INPUT_COLUMNS})
    return findings


def parse_cvss(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def enrich_findings(findings, kev_catalog, epss_scores):
    enriched = []
    for f in findings:
        cve = f["cve"].strip().upper()
        cvss = parse_cvss(f["cvss_score"])
        kev_entry = kev_catalog.get(cve) if cve else None
        epss_entry = epss_scores.get(cve) if cve else None

        tier, sla, rationale = prioritize(cve, cvss, kev_entry, epss_entry)

        enriched.append({
            **f,
            "kev_exploited": "Yes" if kev_entry else "No",
            "kev_vuln_name": kev_entry["vuln_name"] if kev_entry else "",
            "epss_score": f"{epss_entry['epss']:.5f}" if epss_entry else "",
            "epss_percentile": f"{epss_entry['percentile']:.5f}" if epss_entry else "",
            "priority_tier": tier,
            "sla_days": str(sla),
            "rationale": rationale,
            # sort helpers (not written to CSV)
            "_epss_sort": epss_entry["epss"] if epss_entry else -1.0,
            "_cvss_sort": cvss,
        })
    return enriched


def write_output(enriched, path):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
        for row in enriched:
            writer.writerow({c: row[c] for c in OUTPUT_COLUMNS})


def print_summary(enriched):
    tier_order = {t: i for i, t in enumerate(TIERS)}
    counts = {t: 0 for t in TIERS}
    for row in enriched:
        counts[row["priority_tier"]] += 1

    print()
    print("=" * 64)
    print("THREAT-INFORMED PRIORITIZATION SUMMARY")
    print("=" * 64)
    print(f"{'Tier':<14}{'Findings':>10}   {'SLA (days)':>10}")
    print("-" * 64)
    for tier in TIERS:
        print(f"{TIER_LABELS[tier]:<14}{counts[tier]:>10}   {SLA_DAYS[tier]:>10}")
    print("-" * 64)
    print(f"{'Total':<14}{len(enriched):>10}")
    print()

    kev_hits = sum(1 for r in enriched if r["kev_exploited"] == "Yes")
    print(f"Findings matching CISA KEV (exploited in the wild): {kev_hits}")
    print()
    print("Top 10 by priority:")
    print("-" * 64)
    ranked = sorted(
        enriched,
        key=lambda r: (tier_order[r["priority_tier"]],
                       -r["_epss_sort"], -r["_cvss_sort"]),
    )
    for i, row in enumerate(ranked[:10], 1):
        cve = row["cve"] or "(no CVE)"
        epss = row["epss_score"] or "n/a"
        print(f"{i:>2}. [{row['priority_tier']}] {cve:<18} "
              f"CVSS {row['cvss_score']:<5} EPSS {epss:<9} {row['host']}")
    print()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Prioritize scanner findings using CISA KEV + EPSS + CVSS."
    )
    parser.add_argument("-i", "--input", default="sample_findings.csv",
                        help="Scanner findings CSV (default: sample_findings.csv)")
    parser.add_argument("-o", "--output", default="prioritized_findings.csv",
                        help="Output CSV path (default: prioritized_findings.csv)")
    parser.add_argument("--refresh-kev", action="store_true",
                        help="Force a fresh download of the CISA KEV catalog")
    args = parser.parse_args(argv)

    if not os.path.exists(args.input):
        print(f"[!] Input file not found: {args.input}", file=sys.stderr)
        return 1

    findings = read_findings(args.input)
    print(f"[*] Read {len(findings)} findings from {args.input}", flush=True)

    kev_catalog = load_kev_catalog(force_refresh=args.refresh_kev)
    cves = [f["cve"] for f in findings if f["cve"].strip()]
    epss_scores = fetch_epss_scores(cves)

    enriched = enrich_findings(findings, kev_catalog, epss_scores)
    write_output(enriched, args.output)
    print(f"[*] Wrote {len(enriched)} prioritized findings to {args.output}",
          flush=True)

    print_summary(enriched)
    return 0


if __name__ == "__main__":
    sys.exit(main())
