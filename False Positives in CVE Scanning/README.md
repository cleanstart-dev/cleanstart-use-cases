# False Positives in CVE Scanning

> A comparative analysis of vulnerability scan results for the same Grafana Loki binary across a standard and a minimal hardened container image — demonstrating how OS-level package bloat inflates CVE counts and obscures real risk.

---

## The Problem and The Argument

Most teams treat container CVE reports as ground truth. A scanner flags 31 vulnerabilities — the team works through 31 vulnerabilities. The trouble is that a significant proportion of those findings originate in OS packages the application never calls, never loads, and cannot reach at runtime.

Loki is a Go binary. That means:

- Most of its dependencies are compiled directly into the binary at build time.
- The container runtime does not use most OS packages present in the image.
- Scanners like Trivy inspect everything installed in the image — not just what runs.

The result is a report full of CVEs for BusyBox, OpenSSL, apk tools, and system utilities that Loki never touches. These findings consume triage time, generate alert fatigue, and erode trust in the scanner — without representing genuine risk to the application.

> The problem is not just vulnerabilities — it is **signal versus noise**. Full OS images inflate CVE counts. Minimal images reduce noise. Real vulnerabilities remain visible.

---

## What This Project Demonstrates

This project compares vulnerability scan results for the identical Loki binary across two container images:

| Image | CVEs Flagged | Packages | Notes |
|---|---|---|---|
| `grafana/loki:3.7.1` | 31 | 1,314 | Official image — full Alpine OS |
| `cleanstart/loki:latest` | 4 | 854 | Minimal hardened image — OS packages removed |

> **Note:** These numbers reflect a snapshot in time. CVE counts change as new vulnerabilities are discovered and patched. The point is not the specific numbers — it is the ratio. Run the compare script yourself to see the current state.

**What changed:**

- 35% fewer packages in the minimal image
- 27 CVEs eliminated (87% reduction)

**What stayed the same:**

- CVEs in the Loki binary itself
- CVEs in compiled Go dependencies

### Key Finding

From analysis of the scan differential:

- **~42%** of CVEs in `grafana/loki:3.7.1` are not reachable by the application
- **27 of 31** CVEs disappear when OS packages are removed from the image
- **18 CVEs** flagged as likely true positives originate in `stdlib` — the Go runtime compiled into the binary itself

> This is not fixing vulnerabilities. It is removing irrelevant attack surface — making the remaining findings meaningful and actionable.

---

## True vs. False Positives

The following classification distinguishes findings that represent genuine risk to the running application from those that originate in unused OS components.

### Likely True Positives

These CVEs affect the actual Loki binary or its compiled Go dependencies. They are present in both images and must be addressed through patching or upgrading.

| Package / Component | Classification | Rationale |
|---|---|---|
| `stdlib` (Go runtime) | TRUE POSITIVE | Core runtime — compiled into binary; 18 CVEs flagged |
| `github.com/grafana/loki/v3` | TRUE POSITIVE | Application code itself |
| `go.opentelemetry.io/*` | TRUE POSITIVE | Instrumentation — loaded at runtime |
| `github.com/prometheus/prometheus` | TRUE POSITIVE | Metrics exporter — active at runtime |
| `github.com/aws/aws-sdk-go-v2` | TRUE POSITIVE | Storage backend — reachable code path |
| `github.com/go-jose/*` | TRUE POSITIVE | Auth library — reachable code path |

### Likely False Positives

These CVEs originate in Go dependencies that are either not reachable from Loki's active code paths or are indirect transitive dependencies. They are present only in the full OS image's scan and disappear in the minimal image.

| Package / Component | Classification | Rationale |
|---|---|---|
| `github.com/apache/thrift` | FALSE POSITIVE | Transitive dep — no active Loki code path |
| `github.com/prometheus/prometheus` | FALSE POSITIVE | Metrics lib — CVEs in unused sub-packages |
| `go.opentelemetry.io/otel/exporters/*` | FALSE POSITIVE | Exporter sub-packages — not all are active |
| `go.opentelemetry.io/otel/sdk` | FALSE POSITIVE | SDK CVE in unused code path |

---

## Project Structure

```
False Positives in CVE Scanning/
├── compare.py          # Diff and classify scan results
├── README.md           # This document
├── sboms/              # CycloneDX SBOMs for both images
└── scans/              # Trivy JSON scan outputs
```

---

## Quick Start

The following four steps reproduce the full analysis from scratch.

### Step 1 — Pull Images

```bash
docker pull grafana/loki:3.7.1
docker pull cleanstart/loki:latest
```

### Step 2 — Generate SBOMs with Syft

```bash
syft grafana/loki:3.7.1     -o cyclonedx-json=sboms/grafana_loki.cdx.json
syft cleanstart/loki:latest -o cyclonedx-json=sboms/cleanstart_loki.cdx.json
```

### Step 3 — Scan with Trivy

```bash
trivy sbom --format json --output scans/grafana_loki.json \
    sboms/grafana_loki.cdx.json

trivy sbom --format json --output scans/cleanstart_loki.json \
    sboms/cleanstart_loki.cdx.json
```

### Step 4 — Compare

```bash
python3 compare.py \
  scans/grafana_loki.json \
  scans/cleanstart_loki.json \
  --label-standard   "grafana/loki:3.7.1" \
  --label-cleanstart "cleanstart/loki:latest" \
  --sbom-standard    sboms/grafana_loki.cdx.json \
  --sbom-cleanstart  sboms/cleanstart_loki.cdx.json
```

---

## Why This Matters

Security teams working from unfiltered CVE reports commonly encounter a compounding problem: the sheer volume of findings — many of which are irrelevant — degrades the quality of remediation decisions.

| Consequence | Root Cause |
|---|---|
| Alert fatigue | High finding volume including unreachable packages |
| Wasted triage time | No distinction between reachable and unreachable CVEs |
| Distrust in scanners | Repeated false positives with no explanation |
| Delayed remediation | Real risks buried under noise |

Minimal images address the root cause structurally. By removing OS packages that the application never uses, the attack surface shrinks and the scan report reflects only what is actually reachable.

---

## Summary

> Same binary. Same real risks. Far fewer distractions.
>
> Minimal images do not fix vulnerabilities — they remove irrelevant ones from view, so the findings that remain are the ones that matter.