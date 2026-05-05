# Why "Shift Left" failed - Demo

>A reproducible proof-of-concept showing where shift left security breaks down in container workflows — and what a layered approach looks like instead.

## 1. The Problem

"Shift left" means moving security checks earlier in the development lifecycle — scanning code and dependencies at commit or build time rather than after deployment. The instinct is right. The implementation usually isn't.

### Where it breaks down

**It's treated as sufficient, not as a starting point.**
Most teams run a scanner at build time, see a passing report, and ship. The scan is a checkbox — not a gate. Findings are logged, not blocked on.

**It only sees a snapshot.**
Scanners run once, at build time. New CVEs are disclosed every day. An image that was clean on Monday may have three critical findings by Friday. Nobody rescans the running container.

**It's blind to runtime.**
Packages added after the build — via entrypoint scripts, plugin loaders, or runtime installs — never appear in build-time scans. The scanner left before they arrived.

**It creates false confidence.**
A passing scan report with `--exit-code 0` looks identical to a genuinely clean image. Teams ship both the same way.

### The result

```
Day 0 — build  →  scan runs  →  passes  →  image ships
Day 3          →  new CVE disclosed for a dep in the image
Day 3–∞        →  nothing checks the running container
                   vulnerability is live until next manual build
```

Shift left caught nothing it couldn't have caught at build time. Everything after that point is invisible.

## 2. Recreation Steps

### Prerequisites

```bash
# Trivy — vulnerability scanner
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Verify Docker is available
docker --version

# Make scripts executable
chmod +x pipeline-broken.sh pipeline-fixed.sh
```

### Project structure

```
shift-left-failed-demo/
├── Dockerfile
├── app.py
├── requirements.txt          # pinned to vulnerable versions — intentional
├── requirements.fixed.txt    # patched versions
├── pipeline-broken.sh        # shift-left-only pipeline (the failure)
├── pipeline-fixed.sh         # layered pipeline (the fix)
└── README.md
```

---

### Step 1 — Run the broken pipeline

```bash
./pipeline-broken.sh
```

This simulates a typical shift-left-only CI pipeline:
- Builds the image
- Runs Trivy with `--exit-code 0` (non-blocking)
- Logs findings but deploys regardless
- Never rescans after deploy

```bash
════════════════════════════════════════
  CI PIPELINE — Shift Left Only
════════════════════════════════════════

▶ [1/3] Building image...
[+] Building 56.8s (15/15) FINISHED                                                                                docker:default
 .
 .
 .
 => [internal] load build context                                                              0.1s
 => => transferring context: 677B                                                              0.1s
 => [2/9] WORKDIR /app                                                                         0.2s
 => [3/9] RUN apk update && apk search pip                                                     1.2s
 => [4/9] RUN adduser --disabled-password --gecos '' appuser &&     chown -R appuser:appuser /app                                                                                           0.4s
 => [5/9] RUN python -m venv /venv &&     chown -R appuser:appuser /venv                       5.3s
 => [6/9] COPY requirements.txt .                                                              0.1s
 => [7/9] RUN pip install --no-cache-dir -r requirements.txt                                  32.8s
 => [8/9] COPY app.py .                                                                        0.0s
 => [9/9] RUN mkdir -p /app/data &&     chown -R appuser:appuser /app/data                     0.4s
 => exporting to image                                                                         0.3s
 => => exporting layers                                                                        0.3s
 => => writing image sha256:ac9e64c0fa1896b463ac83f73e3cecc50ed247cfc96138ee648ddaf1e4b70f34   0.0s
 => => naming to docker.io/library/shift-left-demo:latest                                      0.0s
✔ Build complete

▶ [2/3] Running vulnerability scan (build-time)...
2026-05-05T07:30:45Z    INFO    [vulndb] Need to update DB
2026-05-05T07:30:45Z    INFO    [vulndb] Downloading vulnerability DB...
2026-05-05T07:30:45Z    INFO    [vulndb] Downloading artifact...        repo="mirror.gcr.io/aquasec/trivy-db:2"
91.14 MiB / 91.14 MiB [-------------------------------------------------------------------------------------------------------------------------] 100.00% 2.89 MiB p/s 32s
2026-05-05T07:31:15Z    INFO    [vulndb] Artifact successfully downloaded       repo="mirror.gcr.io/aquasec/trivy-db:2"
2026-05-05T07:31:15Z    INFO    [vuln] Vulnerability scanning is enabled
2026-05-05T07:31:15Z    INFO    [secret] Secret scanning is enabled
2026-05-05T07:31:15Z    INFO    [secret] If your scanning is slow, please try '--scanners vuln' to disable secret scanning
2026-05-05T07:31:15Z    INFO    [secret] Please see https://trivy.dev/docs/v0.68/guide/scanner/secret#recommendation for faster secret detection
2026-05-05T07:31:24Z    INFO    [python] Licenses acquired from one or more METADATA files may be subject to additional terms. Use `--debug` flag to see all affected packages.
2026-05-05T07:31:24Z    INFO    Detected OS     family="none" version=""
2026-05-05T07:31:24Z    WARN    Unsupported os  family="none"
2026-05-05T07:31:24Z    INFO    Number of language-specific files       num=1
2026-05-05T07:31:24Z    INFO    [python-pkg] Detecting vulnerabilities...

📣 Notices:
  - Version 0.70.0 of Trivy is now available, current version is 0.68.2

To suppress version checks, run Trivy scans with the --skip-version-check flag


  Scan results at build time:
  ├─ CRITICAL: 0
  └─ HIGH:     8

  ⚠️  Pipeline configured with --exit-code 0 (non-blocking)
  ⚠️  Findings logged but deployment proceeds regardless

✔ Scan stage passed (non-blocking)

▶ [3/3] Deploying image to production...

  🚀 Image: shift-left-demo:latest
  🚀 Status: DEPLOYED

════════════════════════════════════════
  ✔ Pipeline complete. Image is live.
════════════════════════════════════════

  What this pipeline missed:
  ✗ Scan was non-blocking — CVEs logged, not gated
  ✗ No rescan scheduled — image is never checked again
  ✗ No runtime monitoring — new CVEs disclosed after
    deploy are invisible until the next manual build

  Run pipeline-fixed.sh to see the difference.
```

---

### Step 2 — Inspect the scan report

```bash
# See what the broken pipeline actually found but ignored
cat trivy-report-build-time.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for result in data.get('Results', []):
    vulns = result.get('Vulnerabilities') or []
    critical = [v for v in vulns if v.get('Severity') == 'CRITICAL']
    high = [v for v in vulns if v.get('Severity') == 'HIGH']
    if critical or high:
        print(f\"Target: {result.get('Target')}\")
        for v in critical + high:
            print(f\"  [{v['Severity']}] {v['VulnerabilityID']} — {v.get('PkgName')} {v.get('InstalledVersion')}\")
            print(f\"          Fixed in: {v.get('FixedVersion', 'no fix available')}\")
"
```

```bash
Target: Python
  [HIGH] CVE-2023-30861 — Flask 2.2.0
          Fixed in: 2.3.2, 2.2.5
  [HIGH] CVE-2023-0286 — cryptography 38.0.0
          Fixed in: 39.0.1
  [HIGH] CVE-2023-50782 — cryptography 38.0.0
          Fixed in: 42.0.0
  [HIGH] CVE-2024-26130 — cryptography 38.0.0
          Fixed in: 42.0.4
  [HIGH] CVE-2026-26007 — cryptography 38.0.0
          Fixed in: 46.0.5
  [HIGH] CVE-2025-66418 — urllib3 1.26.20
          Fixed in: 2.6.0
  [HIGH] CVE-2025-66471 — urllib3 1.26.20
          Fixed in: 2.6.0
  [HIGH] CVE-2026-21441 — urllib3 1.26.20
          Fixed in: 2.6.3
```

---

### Step 3 — The post-deploy gap

A new CVE can be disclosed days after the image is already deployed. The broken pipeline has no mechanism to catch this.

---

### Step 4 — Run the fixed pipeline

```bash
./pipeline-fixed.sh
```

This simulates a layered security pipeline:
- Builds with patched dependencies
- Runs Trivy as a **blocking gate** with defined thresholds
- Deploys only if thresholds are met
- Simulates a scheduled rescan post-deploy
- Alerts on new findings discovered after deployment

```
════════════════════════════════════════
  CI PIPELINE — Layered Security
════════════════════════════════════════

▶ [1/4] Building image with patched dependencies...
[+] Building 34.1s (14/14) FINISHED                                                                                            docker:default
.
.
.
✔ Build complete

▶ [2/4] Running vulnerability scan (BLOCKING)...
2026-05-05T07:32:49Z    INFO    [vuln] Vulnerability scanning is enabled
2026-05-05T07:32:49Z    INFO    [secret] Secret scanning is enabled
2026-05-05T07:32:49Z    INFO    [secret] If your scanning is slow, please try '--scanners vuln' to disable secret scanning
2026-05-05T07:32:49Z    INFO    [secret] Please see https://trivy.dev/docs/v0.68/guide/scanner/secret#recommendation for faster secret detection
2026-05-05T07:32:53Z    INFO    [python] Licenses acquired from one or more METADATA files may be subject to additional terms. Use `--debug` flag to see all affected packages.
2026-05-05T07:32:53Z    INFO    Detected OS     family="none" version=""
2026-05-05T07:32:53Z    WARN    Unsupported os  family="none"
2026-05-05T07:32:53Z    INFO    Number of language-specific files       num=1
2026-05-05T07:32:53Z    INFO    [python-pkg] Detecting vulnerabilities...

📣 Notices:
  - Version 0.70.0 of Trivy is now available, current version is 0.68.2

To suppress version checks, run Trivy scans with the --skip-version-check flag


  Scan results at build time:
  ├─ CRITICAL: 0 (threshold: 0)
  └─ HIGH:     4 (threshold: 5)

✔ Build-time scan passed (blocking gate cleared)

▶ [3/4] Deploying image...

  🚀 Image: shift-left-demo-fixed:latest
  🚀 Status: DEPLOYED

✔ Deploy complete

▶ [4/4] Simulating scheduled rescan (post-deploy)...
  (In production: runs daily via cron / CI scheduled trigger)

2026-05-05T07:32:53Z    INFO    [vuln] Vulnerability scanning is enabled
2026-05-05T07:32:53Z    INFO    [secret] Secret scanning is enabled
2026-05-05T07:32:53Z    INFO    [secret] If your scanning is slow, please try '--scanners vuln' to disable secret scanning
2026-05-05T07:32:53Z    INFO    [secret] Please see https://trivy.dev/docs/v0.68/guide/scanner/secret#recommendation for faster secret detection
2026-05-05T07:32:53Z    INFO    Detected OS     family="none" version=""
2026-05-05T07:32:53Z    WARN    Unsupported os  family="none"
2026-05-05T07:32:53Z    INFO    Number of language-specific files       num=1
2026-05-05T07:32:53Z    INFO    [python-pkg] Detecting vulnerabilities...
  Rescan results (post-deploy):
  ├─ CRITICAL: 0
  └─ HIGH:     4

✔ Rescan passed — no new critical findings post-deploy

════════════════════════════════════════
  ✔ Pipeline complete.
════════════════════════════════════════

  What this pipeline does differently:
  ✓ Blocking scan — deployment stops on CRITICAL findings
  ✓ Defined thresholds — not just logging, actually gating
  ✓ Scheduled rescan — catches CVEs disclosed after deploy
  ✓ Post-deploy alerting — runtime drift is visible
```

---

### Step 5 — Compare scan reports

```bash
# Broken pipeline — what it found and ignored
echo "=== Broken pipeline scan (build-time, non-blocking) ==="
cat trivy-report-build-time.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
results = data.get('Results', [])
critical = sum(len([v for v in r.get('Vulnerabilities', []) or [] if v.get('Severity') == 'CRITICAL']) for r in results)
high = sum(len([v for v in r.get('Vulnerabilities', []) or [] if v.get('Severity') == 'HIGH']) for r in results)
print(f'  CRITICAL: {critical}')
print(f'  HIGH:     {high}')
print(f'  Action taken: none (--exit-code 0)')
"

echo ""

# Fixed pipeline — build-time scan with blocking
echo "=== Fixed pipeline scan (build-time, blocking) ==="
cat trivy-report-fixed-build.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
results = data.get('Results', [])
critical = sum(len([v for v in r.get('Vulnerabilities', []) or [] if v.get('Severity') == 'CRITICAL']) for r in results)
high = sum(len([v for v in r.get('Vulnerabilities', []) or [] if v.get('Severity') == 'HIGH']) for r in results)
print(f'  CRITICAL: {critical}')
print(f'  HIGH:     {high}')
print(f'  Action taken: deploy blocked if thresholds exceeded')
"
```

```bash
=== Broken pipeline scan (build-time, non-blocking) ===
  CRITICAL: 0
  HIGH:     8
  Action taken: none (--exit-code 0)

=== Fixed pipeline scan (build-time, blocking) ===
  CRITICAL: 0
  HIGH:     4
  Action taken: deploy blocked if thresholds exceeded
```

## 3. Solution

Shift left is not wrong — it is incomplete on its own. The fix is treating it as one layer in a stack, not the whole stack. And the most effective place to start is before your pipeline even runs: the base image.
 
### Start with a secure base — cleanstart
 
Most shift left failures begin before the first line of application code. A developer pulls `python:latest` or `node:slim`, writes their app, scans it at build time, and inherits hundreds of OS-level vulnerabilities they never introduced and can't easily fix. The scanner fires on the base image. The developer can't patch upstream packages. The gate gets disabled.
 
This is where [cleanstart](https://hub.docker.com/u/cleanstart) changes the equation.
 
cleanstart images are purpose-built, minimal base images designed to ship with as few vulnerabilities as possible from day one. Instead of starting from a general-purpose distro and stripping it down, cleanstart starts from a hardened, minimal foundation — non-root by default, no unnecessary packages, no build tools in the runtime image.
 
```dockerfile
# Instead of this — inherits full distro vulnerability surface
FROM python:3.11-slim
 
# Use this — hardened, minimal, non-root out of the box
FROM cleanstart/python:latest-dev
```
 
The practical effect on shift left:
 
- **Fewer base image findings** — developers spend less time triaging CVEs they didn't introduce and can't fix
- **Cleaner scan baselines** — thresholds are easier to set and maintain when the noise floor is lower
- **No post-build hardening required** — non-root user, no shell, no package manager in the runtime image are defaults, not things the developer has to configure in the entrypoint or Dockerfile
- **Smaller attack surface from the start** — less code in the image means less to scan, less to patch, less to monitor at runtime
Shift left works best when the thing you're shifting left onto is already secure. cleanstart makes that the default, not the exception.
 
### The layered approach
 
```
Base image    →  Start from a hardened, minimal image (cleanstart)
Commit time   →  SAST, secret scanning, dependency audit
Build time    →  Container scan (BLOCKING, with thresholds)
Post-build    →  SBOM generation + attestation
Post-deploy   →  Scheduled rescan (daily/weekly)
Runtime       →  Anomaly detection, policy enforcement (Falco, OPA)
```
 
Each layer catches what the previous one cannot. cleanstart reduces the burden on every layer above it.
 
### The three pipeline fixes that actually matter
 
**1. Make the build-time scan blocking**
 
```bash
# Non-blocking — findings logged, nothing stops
trivy image --exit-code 0 --severity CRITICAL myimage:latest
 
# Blocking — pipeline fails on CRITICAL findings
trivy image --exit-code 1 --severity CRITICAL myimage:latest
```
 
Non-blocking scans are not security controls. They are telemetry. If the pipeline does not stop on findings, the scan is not doing security work.
 
**2. Rescan on a schedule, not just on commit**
 
New CVEs are disclosed continuously. An image built three weeks ago and never rescanned is not a clean image — it is an unchecked image. Add a scheduled job that rescans every deployed image tag against the latest vulnerability database.
 
```bash
# Run this daily via cron or a scheduled CI trigger
trivy image --exit-code 1 --severity CRITICAL \
    --ignore-unfixed \
    myregistry/myimage:$(cat .deployed-tag)
```
 
**3. Define and enforce thresholds**
 
```bash
trivy image \
    --exit-code 1 \
    --severity CRITICAL \
    --ignore-unfixed \
    myimage:latest
```
 
"No CRITICAL findings with available fixes" is a reasonable gate. "No findings of any severity" will never pass and teams will disable it. Thresholds that are never enforced train teams to ignore security gates entirely.
 
### Rules to enforce going forward
 
| Rule | Why it matters |
|---|---|
| Start from a hardened base image (cleanstart) | Reduces inherited CVEs before the pipeline runs |
| Build-time scan must be blocking (`--exit-code 1`) | Non-blocking scans are logging, not security |
| Define severity thresholds explicitly | Vague gates get disabled or ignored |
| Schedule rescans against deployed images | CVEs don't wait for your next commit |
| Generate and attest SBOMs at build time | Gives rescans an accurate component list to match against |
| Pin base image digests, not tags | `latest` can silently pull a newly vulnerable layer |
 