# The Truth About Zero-Day Vulnerabilities in Containers

> A runnable demo of why CVE scanning can't defend against zero-days, and what actually does — built around real syft SBOM data for six public Docker Hub images versus their CleanStart counterparts, cross-referenced against 12 real historical zero-day disclosures.

---

## The problem and the vision

Most container security programs are built around one loop: scan the image, find CVEs, patch, rescan. But it structurally cannot catch a zero-day.

A zero-day has no CVE entry, no signature, and no fix at the moment it's used. Trivy, Docker Scout, and every other scanner match installed packages against a database of *known* vulnerabilities. Before disclosure, there is nothing in that database to match against. Heartbleed existed in OpenSSL for two years before anyone found it. The XZ Utils backdoor sat in release tarballs for weeks before an engineer noticed SSH logins were 500ms slower than usual and started digging. No scanner flagged either one, because there was nothing to flag yet.

So what actually reduces risk from an unknown, undisclosed flaw?

→ **Fewer packages** — a smaller attack surface means fewer places the next zero-day can land at all.

→ **Less privilege by default** — if the package that gets hit *is* present, what does the attacker get: root, a shell, both?

→ **Faster response once it is disclosed** — the race after disclosure is still real, and a small, known package list makes "are we affected?" answerable in minutes.

This repo measures the first two with real data, and uses 12 real historical zero-days as illustrative probes for exposure surface — not as a live vulnerability scan.

---

## What this is *not*

This is **not** a CVE scanner and **not** a zero-day detector. The 12 incidents in `zero_days.json` are all real, all patched years ago. Matching them against today's images can't tell you if you're vulnerable to something new — nothing can, that's the point. What it *can* tell you: of the packages responsible for the worst zero-day-class incidents of the last decade, how many are sitting in your image right now, today, for no reason other than "the base image included them." That's a legitimate, evidence-based proxy for how exposed an image's *architecture* is to the next incident in the same category.

---

## Real results from this scan

Six image pairs, real `syft` SBOM data (reused from the Image Update Fatigue use case's scan output — same images, same day):

| Metric | Public images (6) | CleanStart images (6) |
|---|---|---|
| Total packages (attack surface) | 64,331 | 15,121 |
| Historical zero-day package hits (of 12 tracked) | 38 | 19 |
| Images shipping a shell (busybox/bash/etc.) | 6 / 6 | 6 / 6 |

**76% attack surface reduction** by package count. **Zero-day package overlap roughly halved**, not eliminated — CleanStart images are minimal, not empty, and every one of the six still ships busybox, which provides a shell. That's worth being honest about: attack surface reduction is a spectrum, not a boolean, and this data shows exactly where CleanStart's current images sit on it.

---

## Project structure

```
zero-day-exposure/
├── images.txt              ← 6 image pairs: public | cleanstart
├── zero_days.json          ← 12 real historical zero-day disclosures + affected package aliases
├── scan.sh                 ← Step 1: syft SBOM + crane image config for every pair
├── exposure_audit.py       ← Step 2: cross-reference SBOMs, generate HTML report
├── sboms/                  ← real syft CycloneDX SBOMs
├── configs/                ← crane image-config JSON — empty until scan.sh runs with crane access
└── docs/
    └── index.html          ← created by exposure_audit.py — the report
```

---

## Prerequisites

**syft** — generates the SBOM (only needed if you want to re-scan; SBOMs are already included)

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
```

**crane** — reads the OCI image config for the blast-radius section (optional — that section SKIPs cleanly without it)

```bash
go install github.com/google/go-containerregistry/cmd/crane@latest
# or: brew install crane
```

Python 3.8+. No extra packages needed for `exposure_audit.py`.

---

## Run it

### Step 1 (optional) — re-scan the images

The `sboms/` directory already has real syft output for all 12 images. Only run this if you want fresh data or different images:

```bash
bash scan.sh              # all pairs
bash scan.sh redis        # just the redis pair
```

### Step 2 — run the audit

```bash
python3 exposure_audit.py
```

Cross-references every SBOM against `zero_days.json`, checks for shell-providing packages, and writes `docs/index.html`. If `configs/` is empty, the blast-radius section reports an explicit SKIP instead of guessing.

### Step 3 — open the report

```bash
cd docs && python3 -m http.server 8181
# then open http://localhost:8181
```

---

## The zero-day dataset

`zero_days.json` holds 12 disclosures spanning 2014–2024, each tagged with the packages that carried it and which layer it lives at:

| Layer | Meaning | Example |
|---|---|---|
| `os-package` | Ships in the base image's OS package layer — this is what an SBOM comparison actually measures | Heartbleed (openssl), XZ backdoor (liblzma) |
| `app-dependency` | Lives in the *application's* own dependency tree (Maven, npm, pip) — invisible to a base-image SBOM | Log4Shell, Spring4Shell |
| `host-kernel` | Lives in the host kernel, not any image at all — no base image choice changes exposure | Dirty COW |

Including the `app-dependency` and `host-kernel` entries is deliberate. A zero-day exposure story that only ever shows wins isn't a credible one — some of the worst incidents in the dataset are entirely outside what a minimal base image can do anything about, and the report says so.

---

## Extending this

- **Add newer incidents** as they're disclosed — append to `zero_days.json` with `package_aliases`, `layer`, and a plain-language `summary`.
- **Wire in crane** (`bash scan.sh`) to populate the blast-radius section with real default-user data instead of the SKIP.
- **Add more image pairs** to `images.txt` — anything with a syft-generatable SBOM works.

---

The base image can't stop an unknown flaw from being unknown. It can make sure fewer of your images are the ones that end up in the next incident's blast radius.
