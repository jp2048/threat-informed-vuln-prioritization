# Threat-Informed Vulnerability Prioritization

Re-prioritize scanner findings using real-world threat intelligence — not CVSS alone.

Most vulnerability management programs still sort by CVSS score and work top-down.
The problem: CVSS measures *theoretical severity*, not *likelihood of exploitation*.
A CVSS 9.8 that nobody exploits jumps the queue ahead of a CVSS 7.8 that is being
exploited in the wild right now. This project fixes that by layering two public
threat-intel signals on top of CVSS:

1. **CISA Known Exploited Vulnerabilities (KEV) catalog** — CVEs CISA confirms are
   actively exploited in the wild. (Under BOD 22-01, US federal agencies must
   remediate these by CISA's due dates.)
2. **EPSS (Exploit Prediction Scoring System)** — from FIRST.org, the modeled
   probability a CVE will be exploited in the next 30 days, updated daily.

## Methodology

Each finding is evaluated top-down; the first matching rule assigns the tier.
Every tier ships with a human-readable `rationale` so the decision is auditable —
when a system owner asks "why is this P1?", the answer is in the CSV.

| Tier | Label | Rule (first match wins) | Remediation SLA |
|------|-------|-------------------------|-----------------|
| P1 | Critical | KEV-listed (exploited in the wild) **or** EPSS ≥ 0.50 | 7 days |
| P2 | High | CVSS ≥ 9.0 **or** EPSS ≥ 0.20 | 15 days |
| P3 | Medium | CVSS ≥ 7.0 **or** EPSS ≥ 0.05 | 30 days |
| P4 | Low | Everything else | 90 days |

### Why this beats CVSS-only prioritization

Same data, different decisions. From the included sample run:

| CVE | CVSS | KEV? | EPSS | CVSS-only priority | Threat-informed tier |
|-----|------|------|------|--------------------|----------------------|
| CVE-2024-6387 (OpenSSH regreSSHion) | 8.1 High | No | **0.995** | "High — patch soon" | **P1** — exploitation is highly likely; treat it like a critical |
| CVE-2023-21709 (Exchange EoP) | 9.8 Critical | No | 0.020 | "Critical — drop everything" | **P2** — severe bug, but negligible predicted exploitation; patch in normal cycle |
| CVE-2023-36036 (Win Cloud Files EoP) | 7.8 High | **Yes** | 0.167 | "High — routine queue" | **P1** — confirmed in-the-wild exploitation outranks the CVSS label |
| CVE-2021-44228 (Log4Shell) | 10.0 Critical | **Yes** | 1.000 | Critical | **P1** — all signals agree |

CVSS-only sorting would have put the Exchange 9.8 (EPSS 0.02) ahead of the
KEV-listed 7.8 that attackers are actually using. Threat-informed ordering
spends remediation effort where the risk is.

## Architecture / data flow

```
sample_findings.csv  (or your scanner export)
        │
        ▼
┌─────────────────┐     ┌──────────────────────────┐
│ prioritize.py   │────▶│ CISA KEV catalog (CSV)     │  cached → kev_catalog.csv
│                 │     │  refreshed if > 24h old    │
│  match on CVE ──┼────▶│ FIRST EPSS API (batched)   │  cached → epss_cache.json
│                 │     │  failures fall back to cache│
└─────────────────┘     └──────────────────────────┘
        │
        ▼
prioritized_findings.csv  (original columns + kev_exploited, kev_vuln_name,
                           epss_score, epss_percentile, priority_tier,
                           sla_days, rationale)
        │
        ▼
console summary: tier counts, KEV hit count, top-10 ranked findings
```

Design notes:

- **No API keys.** Both sources are public and unauthenticated.
- **Resilient by default.** If the KEV download or EPSS API fails, the script
  uses cached data and keeps going — a prioritization run should never fail
  just because a threat feed is unreachable. Unscored CVEs fall back to CVSS.
- **Findings without a CVE** (common in scanner exports, e.g. config findings)
  are prioritized on CVSS only and flagged in the rationale.
- **EPSS requests are batched** (100 CVEs per call) and cached locally, so
  repeat runs make zero API calls.

## Setup

Requirements: Python 3.8+.

```bash
git clone <this-repo>
cd threat-informed-vuln-prioritization
pip install -r requirements.txt
```

No configuration needed. `.env.example` documents that no secrets are required
(and where scanner credentials would go if you extend the script to pull
directly from a Qualys/Tenable API).

## Usage

Run against the included 25-finding sample (covers KEV hits, high-EPSS
non-KEV CVEs, CVSS-9.8-but-quiet CVEs, mediums, and no-CVE findings):

```bash
python3 prioritize.py
```

Run against your own scanner export (columns: `plugin_id, cve, host, severity,
cvss_score, plugin_name, solution`):

```bash
python3 prioritize.py -i findings.csv -o prioritized.csv
```

Force a fresh KEV catalog download:

```bash
python3 prioritize.py --refresh-kev
```

## Sample output

```
[*] Read 25 findings from sample_findings.csv
[*] Downloading CISA KEV catalog...
[*] KEV catalog cached to kev_catalog.csv
[*] Loaded 1734 KEV entries
[*] Querying EPSS API for 23 CVE(s)...
[*] EPSS cache updated (epss_cache.json)
[*] Wrote 25 prioritized findings to prioritized_findings.csv

================================================================
THREAT-INFORMED PRIORITIZATION SUMMARY
================================================================
Tier            Findings   SLA (days)
----------------------------------------------------------------
P1 Critical           11            7
P2 High                6           15
P3 Medium              5           30
P4 Low                 3           90
----------------------------------------------------------------
Total                 25

Findings matching CISA KEV (exploited in the wild): 9

Top 10 by priority:
----------------------------------------------------------------
 1. [P1] CVE-2021-44228     CVSS 10.0  EPSS 0.99999   web-prod-01.corp.example.com
 2. [P1] CVE-2024-3400      CVSS 10.0  EPSS 0.99999   vpn-gateway.corp.example.com
 3. [P1] CVE-2024-21887     CVSS 9.1   EPSS 0.99999   vpn-gateway.corp.example.com
 4. [P1] CVE-2023-4863      CVSS 8.8   EPSS 0.99979   web-prod-01.corp.example.com
 5. [P1] CVE-2023-34362     CVSS 9.8   EPSS 0.99934   filedrop.corp.example.com
 6. [P1] CVE-2021-34527     CVSS 8.8   EPSS 0.99792   dc-01.corp.example.com
 7. [P1] CVE-2022-22965     CVSS 9.8   EPSS 0.99638   app-srv-04.corp.example.com
 8. [P1] CVE-2023-20198     CVSS 10.0  EPSS 0.99571   edge-router-02.corp.example.com
 9. [P1] CVE-2024-6387      CVSS 8.1   EPSS 0.99506   bastion-01.corp.example.com
10. [P1] CVE-2023-21716     CVSS 9.8   EPSS 0.84800   ws-fin-112.corp.example.com
```

And a slice of `prioritized_findings.csv` showing the new columns:

```csv
cve,host,cvss_score,kev_exploited,epss_score,priority_tier,sla_days,rationale
CVE-2023-36036,ws-fin-115.corp.example.com,7.8,Yes,0.16670,P1,7,"CISA KEV: actively exploited in the wild (Microsoft Windows Cloud Files Mini Filter Driver Privilege Escalation Vulnerability)"
CVE-2023-21709,mail-01.corp.example.com,9.8,No,0.01983,P2,15,"CVSS 9.8 >= 9.0"
CVE-2023-24932,ws-fin-118.corp.example.com,6.7,No,0.10561,P3,30,"EPSS 0.106 >= 0.05: non-trivial exploitation likelihood"
```

## Limitations

- **EPSS is a prediction, not a verdict.** A low EPSS does not mean "safe" —
  targeted attacks won't show up in global telemetry. Use it to order work,
  not to dismiss findings.
- **No asset context.** The model doesn't know whether a host is
  internet-facing or an isolated lab box. A production program should weight
  exposure and asset criticality alongside these signals.
- **KEV catalog latency.** CISA adds CVEs after confirming exploitation; there
  is a gap between first exploit and KEV listing. EPSS partially covers this.
- **Scanner severity mapping varies.** The `severity` column is passed through
  from the scanner; only the CVSS numeric score drives the model.
- **Cache staleness.** EPSS scores refresh daily upstream; the local cache is
  only refreshed for CVEs not already cached. Delete `epss_cache.json` to
  force a full refresh.

## Roadmap

- [ ] Asset exposure weighting (internet-facing vs. internal) as a tier modifier
- [ ] CISA KEV `dueDate` surfaced per finding for BOD 22-01 tracking
- [ ] EPSS percentile bands as an alternative to raw-score thresholds
- [ ] Trend output: tier movement between runs (new P1s, resolved P1s)
- [ ] Export formats for ticketing (ServiceNow/Jira CSV shapes)
- [ ] Optional Qualys/Tenable API ingestion (credentials via `.env`, never committed)

## Why this matters to employers

This is how mature vulnerability management programs actually operate: CISA's
KEV catalog is mandatory reading under BOD 22-01, and EPSS is the industry's
standard answer to "CVSS doesn't predict exploitation." Building the
prioritization logic — with caching, failure handling, and auditable
rationales — demonstrates program-level thinking, not just scanner operation.
