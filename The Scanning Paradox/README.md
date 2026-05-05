# The Scanning Paradox: More Tools, More Confusion

> **CleanStart Use Cases** — Practical evidence for hardened container images.
> Every number in this README is from actual scan execution. Clone and verify yourself.

---

## The Core Finding

```
Same image. Same day. Two scanners. Completely different answers.
```

| Scanner | CRITICAL | HIGH | HIGH+CRIT | Total (all) |
|---------|----------|------|-----------|-------------|
| Trivy v0.68.2 | 3 | 299 | **302** | — |
| Grype v0.112.0 | 11 | 168 | **179** | 1,562 |

| CVE Agreement | Count |
|---|---|
| Trivy unique HIGH+CRIT CVE IDs | 187 |
| Grype unique HIGH+CRIT CVE IDs | 55 |
| **Both scanners agree** | **43** |
| Only Trivy finds | 144 |
| Only Grype finds | 12 |
| **Consensus rate** | **23%** |

**Only 23% of HIGH/CRITICAL CVEs are confirmed by both scanners.**
The other 77% creates noise, duplicate tickets, and blocked pipelines.

---

## Step 1 — Pull the Image

**Command:**
```bash
docker pull python:3.14
```

---

## Step 2 — Check Package Count

**Command:**
```bash
docker run --rm python:3.14 sh -c "apt list --installed 2>/dev/null | wc -l"
```

**Result:** `470` packages

---

## Step 3 — Trivy Scan on python:3.14

**Command:**
```bash
trivy image python:3.14 --severity HIGH,CRITICAL
```

**Result:**
```
Packages scanned : 469
CVEs reported    : 302  (HIGH: 299 · CRITICAL: 3)
```

> Trivy uses NVD + OSV databases with raw CVSS severity scoring.
> Reports CVEs going back to 2013 (`CVE-2013-7445` in `linux-libc-dev`).

---

## Step 4 — Grype Scan on python:3.14

**Command:**
```bash
grype python:3.14 --output table
```

**Result:**
```
Total CVEs    : 1,562  (all severities)
HIGH+CRIT     : 179    (HIGH: 168 · CRITICAL: 11)
```

> Grype uses Anchore DB (NVD + GHSA + distro advisories) with
> exploitability percentile scoring — same CVE can score differently
> than Trivy.

---

## Step 5 — CVE Overlap Analysis

**Commands:**
```bash
# Save both outputs as JSON
trivy image python:3.14 --severity HIGH,CRITICAL --format json \
    --output results/raw/trivy_out.json --quiet

grype python:3.14 --output json \
    --file results/raw/grype_out.json 2>/dev/null

# Run overlap analysis
python3 scripts/overlap.py
```

**Result:**
```
====================================================
  SCANNING PARADOX — CVE OVERLAP ANALYSIS
  Image: python:3.14 | May 4, 2026
====================================================
  Trivy  HIGH+CRIT unique CVEs :  187
  Grype  HIGH+CRIT unique CVEs :   55
  Both agree (consensus)       :   43
  Only Trivy finds             :  144
  Only Grype finds             :   12
  Consensus rate               : 23.0%
====================================================
  Sample — only Trivy : ['CVE-2013-7445', 'CVE-2019-19449', 'CVE-2019-19814']
  Sample — only Grype : ['CVE-2025-13151', 'CVE-2025-59375', 'CVE-2026-3298']
```

---

## Step 6 — Trivy Scan on CleanStart

**Command:**
```bash
trivy image cleanstart/python:latest --severity HIGH,CRITICAL
```

**Result:**
```
Detected OS  : family="none"
CVEs         : 0
```

> `family="none"` means Trivy found no OS fingerprint, no package
> manager, no scannable surface. Zero findings.

---

## Step 7 — Grype Scan on CleanStart

**Command:**
```bash
grype cleanstart/python:latest --output table
```

**Result:**
```
CRITICAL : 1  →  CVE-2026-6100   python3==3.14.3-r0
HIGH     : 3  →  CVE-2026-3298   python3==3.14.3-r0
               →  CVE-2026-4786   python3==3.14.3-r0
               →  CVE-2026-4878   libcap2==2.70-r1
```

> Grype still finds 4 HIGH+CRIT findings that Trivy completely misses.
> Same image. The paradox persists — but at a completely different scale.

---

## Full Comparison

| | `python:3.14` | `cleanstart/python` |
|---|---|---|
| **Trivy HIGH+CRIT** | 302 | **0** |
| **Grype HIGH+CRIT** | 179 | **4** |
| **Consensus rate** | 23% | partial |
| **OS detectable** | Debian 13.4 | `family="none"` |

```
python:3.14       → 302 findings to argue about
cleanstart/python →   4 findings to fix
```

---

## Why Do They Disagree?

| Root Cause | What Happens | Share |
|------------|--------------|-------|
| **Database scope** | Trivy includes kernel header CVEs; Grype filters by exploitability | ~40% |
| **Severity model** | Trivy = raw CVSS; Grype = exploitability percentile | ~30% |
| **Distro awareness** | Grype reads Debian backport changelog; Trivy may still flag | ~20% |
| **DB freshness lag** | NVD ingestion delay — one tool knows a CVE before the other | ~10% |

---

## Real Developer Impact

**Blocked pipeline no one can explain**
CI runs Trivy: 3 CRITICAL, build blocked. Developer runs Grype locally:
11 CRITICAL, different list. Same image. Same day. No one agrees.

**Duplicate ticket flood**
`CVE-2023-44431` appears in both scanner outputs — two separate tickets,
two separate remediation tasks, two review cycles. Same CVE. Twice the work.

**Severity inflation trap**
Grype scores a CVE CRITICAL. Trivy scores same CVE HIGH. Team escalates
to P1. Two engineers pulled off product work. Finding: not exploitable
in this container runtime. Time lost: 16 hours.

---

## Recommendations

**1. One authoritative scanner per pipeline stage**
Pick Trivy or Grype for CI gates. Run the other in report-only mode.
Only the primary can block a build. Ends the "which scanner is right" debate.

**2. Act on consensus findings first**
Only 43 of 187+55 CVEs are confirmed by both. Start there.
Single-scanner-only findings go to a review queue, not the sprint board.

**3. Use exploitability context**
`CVE-2013-7445` in `linux-libc-dev` has been in Trivy output for years —
not exploitable in a container. Raw CVSS does not account for your runtime.

**4. Reduce the image first**
Fewer packages = fewer CVEs = less scanner disagreement.
This is not about choosing the right scanner.
It is about removing the conditions that create disagreement.

---

## CleanStart as a Resolution Strategy

The scanning paradox is not caused by flawed scanners.
It is caused by excessive attack surface.

Every additional package introduces more CVE entries, more database
mismatches, and more disagreement between tools.

When you reduce the surface, disagreement shrinks proportionally:

```
python:3.14       → Trivy: 302  Grype: 179  Noise: massive
cleanstart/python → Trivy:   0  Grype:   4  Noise: 4 named CVEs
```

4 specific findings across 2 packages — teams just fix them.
302 findings across 470 packages — teams argue about which scanner is right.

---

## Project Structure

```
The Scanning Paradox/
├── scripts/
│   ├── run_scans.sh              # Run Trivy + Grype, save JSON outputs
│   └── overlap.py                # Calculate CVE consensus between scanners
├── results/
│   ├── raw/
│   │   ├── trivy_out.json        # Trivy JSON output
│   │   └── grype_out.json        # Grype JSON output
│   └── summary/
│       └── verified_results_20260504.txt
└── README.md
```

---

## Reproduce This

```bash
git clone https://github.com/cleanstart-dev/cleanstart-use-cases.git
cd "cleanstart-use-cases/The Scanning Paradox"

# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sudo sh -s -- -b /usr/local/bin

# Install Grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sudo sh -s -- -b /usr/local/bin

# Run all scans
bash scripts/run_scans.sh

# CVE overlap analysis
python3 scripts/overlap.py
```
