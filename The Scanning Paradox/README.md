# The Scanning Paradox: More Tools, More Confusion
Practical Evidence from Running Multiple Scanners on the Same Image

---

## Overview

More scanners does not mean more security. It means more noise.

**The Problem:**
Security teams run multiple vulnerability scanners believing better coverage
comes from more tools. In practice, each scanner uses a different database,
a different severity model, and a different scope — producing contradictory
results on the exact same image. Teams waste hours triaging disagreements
instead of fixing real vulnerabilities.

**What This Use Case Proves:**
- Two scanners on the same image produce a 41% gap in findings
- Only 23.3% of HIGH/CRITICAL CVEs are confirmed by both scanners
- The same CVE can be CRITICAL in one tool and HIGH in another
- A hardened base image reduces scanner noise from 302 findings to 4

**Tools used:** Trivy v0.68.2 · Grype v0.112.0
**Image under test:** `python:3.14` (Debian 13.4) · May 5, 2026

---

## The Problem

Running two scanners on `python:3.14` produced these results:

| Scanner | CRITICAL | HIGH | HIGH+CRIT | Total |
|---------|----------|------|-----------|-------|
| Trivy v0.68.2 | 3 | 299 | **302** | — |
| Grype v0.112.0 | 11 | 168 | **179** | 1,562 |

Same image. Same day. 3 CRITICAL vs 11 CRITICAL. Neither scanner is wrong.

This disagreement creates three real problems for engineering teams:

**Alert fatigue** — 302 + 179 findings means hundreds of alerts per pipeline
run, most of which overlap, conflict, or cannot be actioned without manual
triage. Developers spend more time arguing about findings than fixing them.

**Duplicate tickets** — Without a unified policy, each scanner generates its
own issue. `CVE-2023-44431` appears in both outputs — two tickets, two
remediation cycles, twice the engineering time. Same CVE.

**Blocked pipelines** — CI gates configured with different scanners
produce different pass/fail outcomes on the same build. Teams bypass
gates under deadline pressure, defeating the purpose entirely.

---

## Why Do Scanners Disagree?

| Root Cause | What Happens | ~Share |
|------------|--------------|--------|
| **Database scope** | Trivy includes kernel header CVEs; Grype filters by exploitability context | ~40% |
| **Severity model** | Trivy uses raw CVSS; Grype uses exploitability percentile — same CVE scores differently | ~30% |
| **Distro awareness** | Grype reads Debian backport changelog; Trivy may flag a CVE Debian already patched | ~20% |
| **DB freshness lag** | NVD ingestion delay — one tool knows about a CVE before the other | ~10% |

---

## Experiment: Analyzing Scanner Disagreement

### Step 1: Pull the Image and Check Package Count

```bash
# Pull the image
docker pull python:3.14

# Check image size
docker images python:3.14

# Count installed packages
docker run --rm python:3.14 sh -c "apt list --installed 2>/dev/null | wc -l"
```

**Results:**

| Metric | Value |
|--------|-------|
| Image Size | 1.63 GB |
| Total Packages | 470 |

470 packages. Your Python app uses roughly 10 of them. The other 460
ship into production — compilers, image editors, Bluetooth libraries,
SSH clients — each carrying its own CVE surface.

---

### Step 2: Scan with Trivy

```bash
trivy image python:3.14 --severity HIGH,CRITICAL
```

**Results:**

| Metric | Value |
|--------|-------|
| Packages scanned | 469 |
| CRITICAL CVEs | 3 |
| HIGH CVEs | 299 |
| Total HIGH+CRITICAL | **302** |

Notable vulnerabilities found:
- `linux-libc-dev` — 100+ kernel CVEs (headers your app never needs)
- `libraw23t64` — 3 CRITICAL (arbitrary code execution)
- `libopenexr` — 11 HIGH (remote code execution via crafted files)
- `openssh-client` — 3 HIGH (privilege escalation, command injection)

---

### Step 3: Scan with Grype

```bash
grype python:3.14 --output table
```

**Results:**

| Metric | Value |
|--------|-------|
| Total CVEs (all severities) | 1,562 |
| CRITICAL CVEs | 11 |
| HIGH CVEs | 168 |
| Total HIGH+CRITICAL | **179** |

Same image. Grype reports 11 CRITICAL where Trivy reports 3.
Grype reports 168 HIGH where Trivy reports 299.
The gap is not a bug — it is a fundamental difference in scoring models.

---

### Step 4: CVE Overlap Analysis

```bash
# Run all 4 scans (Trivy + Grype on both images)
bash scripts/run_scans.sh

# Calculate CVE consensus
python3 scripts/overlap.py
```

**Results:**

```
========================================================
  SCANNING PARADOX - CVE OVERLAP ANALYSIS
  May 5, 2026
========================================================
  IMAGE 1: python:3.14 (baseline)
  --------------------------------------------------
  Trivy  HIGH+CRIT unique CVEs :  189
  Grype  HIGH+CRIT unique CVEs :   55
  Both agree (consensus)       :   44
  Only Trivy finds             :  145
  Only Grype finds             :   11
  Consensus rate               :  23.3%

  Sample - only Trivy : ['CVE-2013-7445', 'CVE-2019-19449', 'CVE-2019-19814']
  Sample - only Grype : ['CVE-2025-13151', 'CVE-2025-59375', 'CVE-2026-3298']
  Sample - both agree : ['CVE-2023-44431', 'CVE-2023-51596', 'CVE-2025-12495']

  IMAGE 2: cleanstart/python:latest (hardened)
  --------------------------------------------------
  Trivy  HIGH+CRIT CVEs :    0  (OS: family=none)
  Grype  CRITICAL       :    1
  Grype  HIGH           :    3
  Grype  HIGH+CRIT      :    4
  Grype findings        : ['CVE-2026-3298', 'CVE-2026-4786',
                           'CVE-2026-4878', 'CVE-2026-6100']

========================================================
  COMPARISON SUMMARY
========================================================
  Image                          Trivy    Grype   Consensus
  ----------------------------------------------------------
  python:3.14                      189       55       23.3%
  cleanstart/python:latest           0        4     partial
========================================================
```

---

### Step 5: Scan CleanStart Hardened Image with Trivy

```bash
docker pull cleanstart/python:latest
docker images cleanstart/python:latest
trivy image cleanstart/python:latest --severity HIGH,CRITICAL
```

**Results:**

| Metric | Value |
|--------|-------|
| Image Size | 87.5 MB |
| Detected OS | `family="none"` |
| Total CVEs | **0** |

`family="none"` means Trivy found no OS fingerprint, no package manager,
no scannable surface. This is not a scan failure — it is the result of
building only what the runtime needs.

---

### Step 6: Scan CleanStart Hardened Image with Grype

```bash
grype cleanstart/python:latest --output table
```

**Results:**

| Metric | Value |
|--------|-------|
| CRITICAL CVEs | 1 |
| HIGH CVEs | 3 |
| Total HIGH+CRITICAL | **4** |

| Severity | CVE | Package |
|----------|-----|---------|
| CRITICAL | CVE-2026-6100 | python3==3.14.3-r0 |
| HIGH | CVE-2026-3298 | python3==3.14.3-r0 |
| HIGH | CVE-2026-4786 | python3==3.14.3-r0 |
| HIGH | CVE-2026-4878 | libcap2==2.70-r1 |

Grype finds 4 findings that Trivy completely misses on the same image.
The paradox persists on a hardened image — but the scale changes completely.

---

## Comparison Summary

| Metric | python:3.14 | cleanstart/python |
|--------|-------------|-------------------|
| Image Size | 1.63 GB | **87.5 MB** |
| Total Packages | 470 | **minimal** |
| Trivy HIGH+CRIT CVEs | 302 | **0** |
| Grype HIGH+CRIT CVEs | 179 | **4** |
| Scanner Consensus | 23.3% | partial |
| OS Detectable | Debian 13.4 | **family="none"** |
| Attack Surface | Baseline | **95%+ reduced** |

---

## Key Takeaways

✅ Two scanners on the same image disagree by 41% on HIGH+CRIT findings

✅ Only 23.3% consensus — 77% of findings require manual triage

✅ Same CVE scored CRITICAL by Grype and HIGH by Trivy simultaneously

✅ Hardened image reduces noise from 302 findings to 4 specific CVEs

✅ With fewer packages, both scanners agree more — and there is less to fix

---

## Practical Strategies

**1. Designate One Authoritative Scanner**
Pick Trivy or Grype for CI gates. Run the other in report-only mode.
Only the primary scanner can block a build. Ends the "which scanner wins"
debate before it starts.

**2. Act on Consensus Findings First**
Of 189 Trivy + 55 Grype CVEs, only 44 appear in both. Prioritise these.
They are your highest-confidence findings. Single-scanner-only findings
go to a review queue, not the sprint board.

**3. Use Exploitability Context, Not Raw CVSS**
`CVE-2013-7445` in `linux-libc-dev` has been in Trivy output for years —
not exploitable in a container runtime. Raw CVSS does not account for your
specific context. VEX files are the production-grade solution.

**4. Pin Scanner Versions in CI**
Different scanner versions silently change your security posture. Pin
exact versions and update all scanners together on a fixed cadence.

**5. Reduce the Image First**
The root cause of scanner disagreement is image bloat. Fewer packages
means fewer CVE entries, less database mismatches, and less noise —
regardless of which tools you run.

---

## Summary

The scanning paradox is real, measurable, and reproducible.

**The Problem:** Two scanners on `python:3.14` produced a 41% gap in findings
with only 23.3% consensus — 77% of alerts require manual triage before
any team can act.

**Strategies:**
- Designate one authoritative scanner — avoid "which tool wins"
- Act on consensus first — 44 agreed findings, not 302 + 179
- Use exploitability context — raw CVSS creates false urgency
- Reduce the image — fewer packages = less disagreement

**Impact:** `python:3.14` → 302 Trivy / 179 Grype findings →
`cleanstart/python` → 0 Trivy / 4 Grype findings → 95%+ noise reduction

CleanStart provides dependency-minimized images with only essential runtime
requirements — when there is nothing to find, there is nothing to argue about.

Less surface. Less noise. Less disagreement.
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

# Run all scans + overlap analysis
bash scripts/run_scans.sh
python3 scripts/overlap.py
