# The Golden Image Problem — Attack Surface Demo

> A real-world demonstration of how bloated base images silently accumulate vulnerabilities — and how `cleanstart/node` eliminates them.

---

## The Problem

In large organizations, a single Platform team owns and maintains **golden images** — hardened base images that every product team builds on. The intention is good: consistent security, compliance, standardization.

But the model breaks at scale.

### What goes wrong

| Week | Event | Impact |
|------|-------|--------|
| 0 | Team needs Node.js 20 LTS | Platform backlog ticket #47. ETA: 1 week |
| 3 | CVE published (e.g. OpenSSL) | 600 services affected. 2 engineers to patch |
| 4 | Team builds their own base image | Shadow IT. Audit failure. Incident opened |
| 6 | Drift scan runs | 30% of instances on images 90+ days old |
| 8 | Post-mortem | The architecture is the problem, not the people |

The root cause isn't negligence — it's that **centralized image ownership doesn't scale**. Every package bundled into a base image that teams don't actually need is:

- A CVE they'll eventually have to patch
- A dependency that can drift out of date
- Attack surface that exists for no reason

---

## The Solution: Minimal Images

`cleanstart/node` is a minimal Node.js base image — it ships only what Node.js actually needs to run. Nothing more.

The result is a dramatically smaller attack surface compared to standard base images like `node:20-bullseye` or `node:20`, which bundle hundreds of OS packages your application never touches.

---

## Demo: check_drift.sh

This repo contains a single script that proves the point by checking two things on any Docker image:

1. **Image age** — is the base image stale?
2. **CVE surface** — how many known vulnerabilities does it carry?

### Prerequisites

```bash
# Required
docker

# Optional (for CVE scanning)
# Linux
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# macOS
brew install aquasecurity/trivy/trivy
```

### Usage

```bash
docker pull cleanstart/node:latest
docker pull node:20-bullseye
docker pull node:20
```


```bash
chmod +x check_drift.sh

./check_drift.sh <image> [max-age-days]

# Examples
./check_drift.sh cleanstart/node:latest 30
./check_drift.sh node:20-bullseye 30
./check_drift.sh node:20 30
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | All checks passed — image is compliant |
| `1` | Image is too old — exceeds age threshold |
| `2` | CRITICAL CVEs detected — not safe to promote |

---

## Results

Run against three images pulled on the same day:

```
./check_drift.sh node:20-bullseye 30

  Image : node:20-bullseye
  ────────────────────────────────
  AGE   PASS  14 days old — within 30-day threshold
  CVE   FAIL  21 CRITICAL, 22 HIGH — run: trivy image node:20-bullseye
  ────────────────────────────────
  RESULT  FAIL (exit 2)
```

```
./check_drift.sh node:20 30

  Image : node:20
  ────────────────────────────────
  AGE   PASS  14 days old — within 30-day threshold
  CVE   FAIL  18 CRITICAL, 19 HIGH — run: trivy image node:20
  ────────────────────────────────
  RESULT  FAIL (exit 2)
```

```
./check_drift.sh cleanstart/node:latest 30

  Image : cleanstart/node:latest
  ────────────────────────────────
  AGE   PASS  1 days old — within 30-day threshold
  CVE   PASS  0 CRITICAL, 0 HIGH — minimal attack surface
  ────────────────────────────────
  RESULT  PASS
```

### Summary

| Image | Age | CRITICAL | HIGH | Result |
|-------|-----|----------|------|--------|
| `node:20-bullseye` | 14 days | 21 | 22 | FAIL |
| `node:20` | 14 days | 18 | 19 | FAIL |
| `cleanstart/node:latest` | 1 day | 0 | 0 | **PASS** |

Same Node.js runtime. Completely different risk profile. The difference is everything that `cleanstart/node` chose **not** to include.

---

## Why This Matters

Every package that ships in your base image but isn't used by your application is:

- **Invisible risk** — teams don't patch what they don't know they're carrying
- **Audit debt** — CVE scanners flag packages in the base layer as the app team's problem
- **Compliance exposure** — PCI-DSS, SOC 2, and ISO 27001 all require known vulnerabilities to be addressed within defined SLAs

A minimal image isn't a nicety — it's a security posture decision. You can't be exploited through a package that isn't there.

---