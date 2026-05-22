# STIG Hardening by Design vs. Retrofit: Which Approach Wins?

> **Part of the CleanStart Use Cases series** — practical, reproducible evidence for hardened container images.
> Don't just read about hardened images — see the results yourself.

---

## TL;DR

Same STIG, two paths.

- **Retrofit:** Take stock `ubuntu:22.04`, write a ~350-line remediation script against PAM, auditd, sshd, sysctl, modprobe, AIDE. Build a hardened image yourself.
- **By design:** Start from a hardened-by-design base where STIG-aligned controls are architectural properties, not bolted-on layers.

Independent public reporting (Dark Reading, Nov 2025) finds hardened-by-design images "have reduced the vulnerability count by **more than 97%**, resulting in near-zero known vulnerabilities" [1]. CleanStart's own published metric is **60–80% smaller images, near-zero CVEs, FIPS-aligned out of the box** [2][3]. The DISA Container Hardening Process Guide itself tells assessors: *"If an OpenSCAP scan returns noncompliant result(s), always evaluate the validity of those findings"* — meaning raw scan numbers without filtering are misleading [4].

The structural argument is simple: a base that ships without `wget`, `dpkg`, `bash`, and ~20 setuid binaries passes the corresponding STIG rules by construction. A retrofit can never remove those without breaking itself.

This repo gives you the Dockerfiles, the ~350-line remediation script, and the scan harness so you can verify any claim end-to-end.

---

## The Question

When a security team says "make this container STIG-compliant," there are two paths:

1. **Retrofit** — start with a general-purpose base image (Ubuntu, Alpine, RHEL UBI), then apply STIG remediation: remove packages, rewrite configs, patch permissions, add audit rules.
2. **By design** — start from a base built to satisfy STIG-aligned requirements as architectural properties: minimal package surface, non-root by default, no shell, locked-down configs, signed provenance.

Both produce a "compliant" artifact on paper. The interesting question is what each costs in build time, image size, remaining findings, drift risk, and engineering hours.

---

## What the public record actually says

These are not numbers we invented. Every figure below is sourced.

### On retrofit complexity

- The Canonical Ubuntu 22.04 STIG (current release **V2R6**, January 2026) contains **over 300 individual rules** [5][6]. Canonical itself states that implementing it by hand is "prohibitively time-consuming" — which is why they ship the Ubuntu Security Guide (USG) as an automation tool, available only with the paid Ubuntu Pro subscription [5].
- BigFix's published V2R6 site contains **182 fixlets** (remediation actions) just for the OS-level checks [7]. That's the maintenance surface a retrofit team owns.

### On the size/CVE reduction from hardened-by-design images

- **Dark Reading (Nov 14, 2025):** *"Typically, the hardened images have reduced the vulnerability count by more than 97%, resulting in near-zero known vulnerabilities."* [1]
- **CleanStart official metrics:** Each image is *"hardened to near zero CVEs, 60–80% smaller than original versions ... All meet NIST FIPS standards"* [2][3].
- **CleanStart blog (Jan 2026) citing a hardened-image study:** *"Debloated images (same base family, fewer packages) reduced total CVEs by about 64%. Hardened images (minimal, security-focused) achieved about 99% fewer CVEs on average, often shipping with zero known CVEs at build time compared to hundreds in the baseline."* [8]
- **Concrete size data from Chainguard's published benchmarks:**
  - Debian base: ~140 MB → Chainguard static: ~2–3 MB [9]
  - Go application: 892 MB (Debian-based) → 775 MB (Chainguard one-line FROM swap), with CVE count falling **to 0** on both Docker Scout and Grype [10]
  - `nginx:latest`: 225 MB → `nginx:alpine`: 79.8 MB → `cgr.dev/chainguard/nginx`: **0 vulnerabilities** vs. 6 CVEs on `nginxinc/nginx-unprivileged:alpine-slim` [11]
- **Chainguard Academy:** Chainguard containers have *"90%+ fewer CVEs than Docker Official Images"* [12].

### On the DISA position itself

- **DISA has not published a STIG specifically for containers.** Container guidance lives in the *DISA Container Hardening Process Guide* (V1.2 / V1R1.10), which derives from the General Purpose Operating System SRG [4][13].
- The Process Guide is explicit: *"With a properly locked down hosting environment, containers inherit most of the security controls and benefits from infrastructure to host OS-level remediation requirements."* [4]
- And: *"False positives are common within major host OS-based containers, as the security profiles normally account for all host-level controls potentially not applicable to a container build (e.g., GUI, CAC authentication, etc.). In addition to false positives, many of the base OS STIG requirements are not applicable in the containers either."* [4]

This is the most important context: a high "fail" count on a raw OpenSCAP container scan does not mean the container is non-compliant. It almost always includes host-inherited rules that don't apply.

---

## The retrofit path (what it actually costs)

`configs/Dockerfile.retrofit` is what most teams write when handed a STIG mandate on top of an existing Ubuntu base. The relevant parts:

```dockerfile
FROM ubuntu:22.04

# 1. Remove packages flagged by STIG (telnet, ftp, rsh, talk, finger, etc.)
RUN apt-get remove --purge -y telnet ftp rsh-client talk finger nis ...

# 2. Install audit + crypto policy enforcement
RUN apt-get install -y auditd libpam-pwquality aide

# 3. Apply the bulk remediation script (~350 lines of sed/echo/chmod
#    against PAM, sshd, auditd, sysctl, modprobe, AIDE, banners, cron)
COPY scripts/retrofit-remediation.sh /tmp/
RUN bash /tmp/retrofit-remediation.sh

# 4. Drop a non-root user (Ubuntu base ships as root)
RUN groupadd -g 65532 app && useradd -u 65532 -g 65532 -s /sbin/nologin app
USER 65532
```

`scripts/retrofit-remediation.sh` in this repo is **354 lines** of real bash. We include it verbatim so the maintenance surface is visible. This script must be maintained against:

- Every STIG benchmark release (V1R1 → V2R1 → ... → V2R6 → V2R7, released roughly quarterly per BigFix's publication cadence [7][14])
- Every new CVE in any included package
- Every breaking change in PAM, sshd, auditd, or sysctl tooling

### Structural failures retrofit cannot resolve

Independent of which scan run you do, the following SSG rule families will not pass on a stock-Ubuntu retrofit:

| Rule family | Why retrofit cannot fix |
|---|---|
| `package_wget_removed`, `package_curl_removed`, `package_tar_removed` | Required for image build / runtime operations |
| `package_apt_removed`, `package_dpkg_removed` | Removing breaks the OS package management the image depends on |
| `no_shells_in_passwd` | Ubuntu's `/bin/sh` is wired into core utilities |
| `setuid_files_minimized` | Stock Ubuntu ships ~20 setuid binaries (`mount`, `su`, `sudo`, `ping`, etc.) — pruning breaks the image |
| `package_perl_removed`, `package_python3_removed` | Pulled in transitively by apt and admin tooling |

A hardened-by-design image ships without these to begin with — which is why Chainguard's static base is ~2–3 MB vs. Debian's ~140 MB [9].

---

## The by-design path

We use **`cleanstart/glibc:latest`** for this comparison — it's CleanStart's foundational base OS image, the apples-to-apples target against `ubuntu:22.04`. CleanStart's published description: *"security-hardened and optimized for enterprise deployments, featuring minimal attack surface and FIPS-compliant cryptographic functions"* [16].

For Java/Node/Python/Go/etc workloads, swap to `cleanstart/jdk`, `cleanstart/nodejs`, `cleanstart/python`, etc. — 62 hardened images are available at https://hub.docker.com/u/cleanstart.

```dockerfile
FROM cleanstart/glibc:latest

COPY --chown=1000:1000 app /app
USER 1000
ENTRYPOINT ["/app/server"]
```

CleanStart's documented hardened-deployment runtime flags:

```bash
docker run -d --name app \
  --read-only \
  --security-opt=no-new-privileges \
  --user 1000:1000 \
  cleanstart/glibc:latest [args]
```

No remediation script. The base ships with:

- Minimal package surface — CleanStart reports 60–80% smaller than the original equivalent [2][3]
- Non-root default user
- No interactive shell, no package manager
- Pre-applied STIG-aligned PAM/sysctl/audit configuration
- FIPS 140-3 alignment [2]
- Signed SBOM + provenance attestation (SLSA-aligned) [15]

The maintenance surface is owned by the base image vendor, not by every consuming team.

---

## Side-by-side: public-benchmark figures

These are real numbers from public sources, not from this repo's harness. Use them as the credible-source baseline. When you run the harness in your environment, update the table with your own observations.

| Metric | Retrofit (Ubuntu + remediation) | By design (hardened base) | Source |
|---|---|---|---|
| STIG rules to manage | 300+ individual rules | Same 300+ rules, but most pass by construction | Canonical [5] |
| Public V2R6 fixlet count | 182 fixlets to maintain | 0 (vendor-maintained) | BigFix [7] |
| Image size (Debian base reference) | ~140 MB | ~2–3 MB (Chainguard static) | Chainguard [9] |
| Image size (Go app reference) | 892 MB | 775 MB on one-line FROM swap | Chainguard [10] |
| Image size (nginx reference) | 225 MB (`nginx:latest`) | Significantly smaller | Mathieu Benoit / Medium [11] |
| CVE count (Go app, scanned with Grype) | 42 low + critical/high | 0 | Chainguard [10] |
| CVE count (nginx) | 6 CVEs (Alpine variant) | 0 | Mathieu Benoit [11] |
| CVE reduction (hardened study, average) | baseline | ~99% fewer CVEs | Hardened-image study via CleanStart [8] |
| CVE reduction (industry analyst) | baseline | 97%+ reduction | Dark Reading [1] |
| CVE reduction (Chainguard vs DOI) | baseline | 90%+ fewer | Chainguard Academy [12] |
| Maintenance owner | Every consuming team | Base image vendor | DISA Process Guide Section 5 [4] |

---

## The lifecycle cost (the part scans don't show)

A single point-in-time scan flatters the retrofit path. The real cost shows up over the next 12 months:

| Lifecycle event | Retrofit cost | By-design cost |
|---|---|---|
| New CVE in `wget` (still present) | Rebuild, re-test, re-scan, re-deploy | Not present in image — no action |
| STIG benchmark version bump (V2R6 → V2R7) | Reread the diff, re-implement, re-test | Vendor base updates; consumer rebuilds |
| Engineer who owned the remediation script leaves | Tribal knowledge loss | Vendor maintains baseline |
| Auditor asks for signed SBOM + provenance | Generate from scratch | Ships with the base [15] |
| New service team needs STIG image | Fork the remediation script | Pull the base, ship the app |

The retrofit cost is paid by every team, every quarter. The by-design cost is paid once, by the base image vendor.

---

## When retrofit is the right answer

This is not "by-design always wins":

- **Legacy stack** that genuinely needs packages a minimal base doesn't ship
- **Air-gapped environments** with no path to consume an external hardened base
- **Single-tenant deployments** needing exact parity with a host OS image

In those cases, the retrofit script in this repo is a reasonable starting point. Fork it, harden further, own the maintenance.

---

## What's in this repo

```
.
├── README.md                       ← you are here
├── SOURCES.md                      every citation traceable to a primary source
├── scripts/
│   ├── 01-build-retrofit.sh        build the retrofitted Ubuntu image
│   ├── 02-build-by-design.sh       build the CleanStart-based image
│   ├── 03-scan-both.sh             run OpenSCAP STIG profile against both
│   ├── 04-compare-results.sh       generate the side-by-side comparison
│   └── retrofit-remediation.sh     the 354-line remediation script
├── configs/
│   ├── Dockerfile.retrofit         Ubuntu 22.04 + remediation layers
│   └── Dockerfile.by-design        CleanStart hardened base (cleanstart/glibc:latest)
└── results/
    ├── retrofit-scan.txt           your scan output goes here
    ├── by-design-scan.txt          your scan output goes here
    └── timings.csv                 build + scan timings
```

---

## Reproduce it yourself

```bash
git clone https://github.com/cleanstart-dev/cleanstart-use-cases.git
cd cleanstart-use-cases/stig-by-design-vs-retrofit

# The Dockerfiles are ready to build. No placeholders to fill.
bash scripts/01-build-retrofit.sh    # ~6 min (Ubuntu + 354-line remediation)
bash scripts/02-build-by-design.sh   # seconds (cleanstart/glibc:latest + COPY layer)
bash scripts/03-scan-both.sh         # OpenSCAP STIG profile against both
bash scripts/04-compare-results.sh   # writes results/comparison.md
```

Got different numbers in your environment? Open an issue or PR. That's the point.

---

## Sources

[1] Dark Reading, *"Hardened Images Aim to Squash Container Vulnerabilities"*, Nov 14, 2025. https://www.darkreading.com/application-security/hardened-containers-eliminate-common-source-vulnerabilities

[2] CleanStart / PR Newswire, *"CleanStart Achieves 350+ Hardened, Vulnerability-Free Container Images"*, Aug 20, 2025. https://www.prnewswire.com/news-releases/cleanstart-achieves-350-hardened-vulnerability-free-container-images-accelerating-us-expansion-302534311.html

[3] The AI Journal coverage of CleanStart announcement, Aug 20, 2025. https://aijourn.com/cleanstart-achieves-350-hardened-vulnerability-free-container-images-accelerating-u-s-expansion/

[4] Chainguard, *"STIG Hardening: Applying DISA Guidelines to Container Images"*, June 7, 2024 — quoting Sections 5 and 6 of the DISA Container Hardening Process Guide V1.2. https://www.chainguard.dev/unchained/stig-hardening-container-images

[5] Canonical, *"Meet DISA-STIG compliance requirements for Ubuntu 22.04 LTS with USG"*, June 24, 2024. https://ubuntu.com/blog/disa-stig-ubuntu-22-04-usg

[6] NIST National Checklist Program, Canonical Ubuntu 22.04 LTS STIG V2R6, checklist ID 1235. https://ncp.nist.gov/checklist/revision/6653

[7] BigFix Compliance, *"Updated DISA STIG Checklist for Ubuntu 22.04 LTS Server"*, Jan 28, 2026 (V2R6, 182 fixlets). https://forum.bigfix.com/t/bigfix-compliance-updated-disa-stig-checklist-for-ubuntu-22-04-lts-server-published-2026-01-28/53638

[8] CleanStart blog, *"CVE fatigue occurs when container and platform teams..."*, Jan 9, 2026. https://www.cleanstart.com/blogs/cve-fatigue-occurs-when-container-and-platform-teams

[9] Chainguard Academy, *"Using the Chainguard Static Base Container Image"* — Debian ~140 MB, Chainguard static ~2–3 MB. https://edu.chainguard.dev/chainguard/chainguard-images/how-to-use/static-base-image/

[10] Chainguard, *"Building minimal and low CVE images for compiled languages"*, Feb 27, 2024. https://www.chainguard.dev/unchained/building-minimal-and-low-cve-images-for-compiled-languages

[11] Mathieu Benoit, *"Distroless & Nginx container image, towards more security, by default and by design"*, Medium, Dec 18, 2025. https://medium.com/@mabenoit/chainguards-nginx-container-image-1ec38245fcd0

[12] Chainguard Academy, *"Vulnerability Comparisons"* — 90%+ fewer CVEs than Docker Official Images. https://edu.chainguard.dev/chainguard/chainguard-images/vuln-comparison/

[13] DoD CIO, *DoD Enterprise DevSecOps Reference Design — CNCF Kubernetes*, Oct 2021, citing DISA Container Hardening Process Guide V1R1.10. https://dodcio.defense.gov/Portals/0/Documents/Library/DoD%20Enterprise%20DevSecOps%20Reference%20Design%20-%20CNCF%20Kubernetes%20w-DD1910_cleared_20211022.pdf

[14] BigFix Compliance, *"Updated DISA STIG Checklist for Ubuntu 22.04 LTS Server"*, June 24, 2025 (V2R4, prior release showing quarterly cadence). https://forum.bigfix.com/t/bigfix-compliance-updated-disa-stig-checklist-for-ubuntu-22-04-lts-server-published-2025-06-24/52083

[15] CleanStart blog, *"Minimal vs Hardened vs Secure Container Images"*, Jan 31, 2026 — on SLSA-aligned signed provenance. https://www.cleanstart.com/blogs/minimal-vs-hardened-vs-secure-container-images-whats-the-difference-and-why-it-matters

[16] CleanStart `glibc` image on Docker Hub. https://hub.docker.com/r/cleanstart/glibc

---
