# Image Update Fatigue: Managing the Patch Treadmill with CleanStart

> A runnable demo of the difference between **"patching as a recurring engineering task"** and **"patching as a property of the platform"** — built around real Trivy scans of public images and their CleanStart counterparts, using syft for SBOM generation and trivy for CVE analysis.

---

## The problem and the vision

Most teams treat container image patching as cleanup work. Pull a base image, scanner fires 150 alerts, engineer triages which ones matter, rebuilds the image, waits for CI, re-deploys, scanner fires again next week. The treadmill never stops — new CVEs land faster than teams can patch them, and the effort is entirely manual.

A different approach is to make security a property of the image itself.

→ The base image ships with near-zero CVEs before it ever runs.

→ Teams pull an updated tag and re-deploy. No Dockerfile changes, no CI changes, no triage.

Nothing in that workflow requires an engineer to read a scanner report.

This repo demonstrates the gap with real scan data: six public Docker Hub images versus their CleanStart counterparts, scanned with syft and trivy, compared side by side.

---

## What "architectural" means here, concretely

| Layer | Treadmill approach | CleanStart approach |
|---|---|---|
| Base image content | Full OS base layer — hundreds of packages most apps never use | Only runtime-required packages — structural reduction before any CVE lookup |
| CVE count | 11–151 CVEs per image, continuously growing | 0–5 CVEs per image at time of scan |
| Patch cycle | Update Dockerfile → trigger CI → fix regressions → re-deploy | Pull updated tag — no build changes required |
| Patch lag | 7–14 day industry average from disclosure to published fix | Same day for CRITICAL, hours for HIGH |
| SBOM + provenance | Manual if documented at all | Automatic — signed CycloneDX SBOM + SLSA provenance on every image |
| Engineer time | ~4h per actionable CVE × ongoing disclosures | Near zero — patching is the platform's job, not the team's |

---

## Real scan results

| Public image | CVEs | CleanStart image | CVEs | Reduction |
|---|---|---|---|---|
| `python:3.14.5` | 151 (C:3 H:8 M:37 L:97) | `cleanstart/python:latest` | 0 | **100%** |
| `node:26.3.0` | 150 (C:3 H:8 M:37 L:96) | `cleanstart/node:latest` | 2 | **99%** |
| `nginx:1.31.1` | 43 (C:0 H:4 M:15 L:23) | `cleanstart/nginx:latest` | 0 | **100%** |
| `prom/prometheus:v3.11.3` | 22 (C:0 H:15 M:7 L:0) | `cleanstart/prometheus:latest` | 5 | **77%** |
| `postgres:18.4` | 68 (C:3 H:19 M:24 L:18) | `cleanstart/postgres:latest` | 0 | **100%** |
| `redis:8.6.4` | 11 (C:0 H:0 M:3 L:8) | `cleanstart/redis:latest` | 0 | **100%** |
| **Total** | **445** | | **7** | **98%** |

**33 actionable CVEs** (HIGH or CRITICAL with a fix available) in public images.
**0 actionable CVEs** in CleanStart images at the same threshold.

At ~4 engineer-hours per CVE (triage + rebuild + test + deploy), that is **~132 engineer-hours per scan cycle** eliminated.

---

## Project structure

```
patch-treadmill/
├── images.txt          ← 6 image pairs: public | cleanstart
├── scan.sh             ← Step 1: syft SBOM → trivy CVE scan for every pair
├── analyze.py          ← Step 2: filter, score, generate HTML report
├── sboms/              ← created by scan.sh — one .sbom.json per image
├── scan_results/       ← created by scan.sh — one .trivy.json per image
└── docs/
    └── index.html      ← created by analyze.py — comparison dashboard
```

---

## Prerequisites

**syft** — generates the SBOM

```bash
# macOS
brew install syft

# Linux
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
  | sh -s -- -b /usr/local/bin

syft version
```

**trivy** — scans the SBOM for CVEs

```bash
# macOS
brew install trivy

# Linux
curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sh -s -- -b /usr/local/bin

trivy --version
```

Python 3.8+ is also required. No extra packages needed.

---

## Run it

### Step 1 — Scan all image pairs

```bash
bash scan.sh
```

For each pair in `images.txt` this runs:

```bash
syft <image> --output cyclonedx-json=sboms/<slug>.sbom.json
trivy sbom sboms/<slug>.sbom.json --format json --output scan_results/<slug>.trivy.json
```

First run takes 10–15 minutes — trivy downloads its vulnerability database (~200 MB) and each image is pulled. Subsequent runs are faster.

To scan a single pair:

```bash
bash scan.sh python
bash scan.sh redis
```

### Step 2 — Generate the report

```bash
python3 analyze.py
```

Filters to actionable CVEs (HIGH+ with a fix available by default), scores them by severity and patch age, and writes `docs/index.html`.

Options:

```bash
python3 analyze.py --min-severity MEDIUM   # include MEDIUM CVEs
python3 analyze.py --no-require-fix        # include CVEs with no fix yet
```

### Step 3 — Open the report

```bash
# macOS
open docs/index.html

# Linux / WSL
cd docs && python3 -m http.server 8181
# then open http://localhost:8181
```

---

## How CleanStart patches without manual effort

When a CVE is disclosed, the two paths diverge immediately.

**Public image path:**
1. Scanner fires — engineer opens ticket
2. Engineer reads advisory, checks each SBOM manually (~2h per image)
3. Engineer updates Dockerfile or base tag
4. CI pipeline triggered — engineer waits, fixes regressions
5. Image rebuilt, re-deployed
6. Scanner re-run to confirm fix
7. Repeat for next CVE — typically 7–14 days after disclosure

**CleanStart path:**
1. Agentic system detects affected images from CVE feed — no human involved
2. Automated impact check — is the package present? Is it runtime-reachable? If not present (most OS utilities aren't in CleanStart minimal images) the CVE doesn't apply
3. Patch applied via locked source dependencies, hermetic build
4. Automated compatibility tests run — no engineer involvement
5. Patched image published to CleanStart registry — same day for CRITICAL
6. Teams pull the updated tag and re-deploy — no Dockerfile change, no CI change

The second path removes the engineer from steps 1 through 5 entirely.

---

## Run individual commands manually

```bash
# Generate SBOM for one image
syft python:3.14.5 --output cyclonedx-json=sboms/python-3-14-5.sbom.json

# Inspect the SBOM — see every package syft found
cat sboms/python-3-14-5.sbom.json | python3 -m json.tool | grep '"name"' | head -30

# Scan the SBOM with trivy
trivy sbom sboms/python-3-14-5.sbom.json \
  --format json \
  --output scan_results/python-3-14-5.trivy.json

# Quick table in the terminal
trivy sbom sboms/python-3-14-5.sbom.json

# Only HIGH and CRITICAL
trivy sbom sboms/python-3-14-5.sbom.json --severity HIGH,CRITICAL
```

---

## Priority score formula

CVEs in the report are ranked so the most urgent appear first:

```
score = (severity_weight × 25) + patch_lag_bonus + fix_bonus

  CRITICAL = 4  →  base 100
  HIGH     = 3  →  base  75
  MEDIUM   = 2  →  base  50

patch_lag_bonus = (days since CVE published − 14) × 0.1   [only if older than 14 days]
fix_bonus       = +5 if a fix version is available
```

A CRITICAL CVE published 180 days ago with a fix scores 121.6.
A HIGH CVE from last week with no fix scores 75.
The oldest, highest-severity, fixable CVEs always surface first.

---

## What's still your responsibility

CleanStart handles the base image layer. The rest of the stack is yours:

1. **Application dependencies** — `pip install` / `npm install` bring their own CVE surface; pin and scan in CI
2. **Your application code** — SAST on every PR
3. **Container runtime config** — non-root user, read-only rootfs, dropped capabilities in your pod spec
4. **Network policy** — ingress/egress restrictions
5. **Secrets management** — never bake secrets into images or environment variables in plain text
6. **Runtime detection** — Falco or Sysdig for anomaly detection post-deploy

---

The CleanStart base removes the OS layer from your vulnerability backlog.
What remains is work only your team can do.