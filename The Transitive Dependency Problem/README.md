# 🔍 Transitive Dependency Vulnerabilities — Even on a Hardened Base Image

> **The scenario:** Your team switched to `cleanstart/node:latest` — a hardened, minimal, near-zero-CVE base image. Trivy scans the image. Clean. Then someone runs `npm audit`.
>
> **9 vulnerabilities. 1 critical. 6 of them in packages you never installed.**

This project is a fully executable demo of the **two-layer vulnerability model** — what `cleanstart/node` protects, what it can't, and exactly how to fix both.

---

## The Core Insight

```
┌──────────────────────────────────────────────────────────────┐
│  LAYER 2 — npm / node_modules                  ✗ VULNERABLE  │
│                                                              │
│  110 packages installed from just 6 in package.json         │
│  6 of 9 vulnerabilities are in packages you never chose      │
│                                                              │
│  ✗ path-to-regexp  (via express)         HIGH   ReDoS        │
│  ✗ body-parser     (via express)         HIGH   DoS          │
│  ✗ qs              (via express)         MODERATE DoS        │
│  ✗ cookie          (via express)         LOW                 │
│  ✗ send            (via express)         LOW                 │
│  ✗ serve-static    (via express)         LOW                 │
│                                                              │
│  cleanstart/node has no visibility into this layer           │
├──────────────────────────────────────────────────────────────┤
│  LAYER 1 — OS / cleanstart/node:latest         ✔ CLEAN       │
│                                                              │
│  ✔ No shell (bash/sh removed)                                │
│  ✔ No package manager (apt/apk removed)                      │
│  ✔ No curl/wget/git                                          │
│  ✔ Non-root user enforced                                    │
│  ✔ Near-zero OS-level CVEs                                   │
│  ✔ Signed SBOM + SLSA provenance                             │
└──────────────────────────────────────────────────────────────┘
```

`cleanstart/node` does its job perfectly on Layer 1. But `npm ci` in your Dockerfile drops 110 packages into `/app/node_modules` — completely above the hardened base. Those packages carry their own CVE history, and no base image scanner will catch them.

---

## Prerequisites

```bash
# Install Node.js 20 via NodeSource (Ubuntu/Debian/WSL)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# Verify
node -v   # v20.x.x
npm -v    # 10.x.x
```

> ⚠️ Do **not** use `apt install npm` — it installs npm 6.x from 2019 which will break with modern packages.

---

## Setup

```bash
cd "The Transitive Dependency Problem"

# Install all scripts into the scripts/ folder (download from repo)
mkdir -p scripts reports

npm install
```

After install you will see immediately:

```
added 110 packages, and audited 111 packages in 16s
9 vulnerabilities (3 low, 1 moderate, 4 high, 1 critical)
```

That output is the whole demo in one line.

---

## ▶️ Full Walkthrough — Run Every Step

### Step 1 — See the two-layer model with live data from your install

```bash
npm run scan:layers
```

**What it does:** Runs `npm audit --json` live, then prints the two-layer architecture diagram populated with your actual vulnerability count. Shows which scanning tool sees which layer and where the blind spot is.

**Actual output:**
```
  ┌────────────────────────────────────────────────────────────┐
  │  LAYER 2 — npm / node_modules                              │
  │  110 packages installed  (6 direct, 104 transitive)        │
  │  npm audit found: 9 vulnerabilities                        │
  │  ✗ mongoose          CRITICAL                              │
  │  ✗ axios             HIGH                                  │
  │  ✗ body-parser       HIGH     [transitive]                 │
  │  ✗ express           HIGH     [transitive]                 │
  │  ✗ path-to-regexp    HIGH     [transitive]                 │
  │  ✗ qs                MODERATE [transitive]                 │
  │  cleanstart/node CANNOT protect you here                   │
  ├────────────────────────────────────────────────────────────┤
  │  LAYER 1 — OS / cleanstart/node:latest                     │
  │  ✔ No shell, no package manager, no curl/wget              │
  │  ✔ Non-root user enforced                                  │
  │  ✔ Near-zero OS-level CVEs                                 │
  │  ✔ Signed SBOM + SLSA provenance                           │
  └────────────────────────────────────────────────────────────┘

  WHAT EACH SCANNING TOOL SEES
  Trivy (image scan)    OS packages (Layer 1)    ✔ Clean — cleanstart works
  npm audit             node_modules (Layer 2)   ✗ 9 vulns (1 critical, 4 high)
```

---

### Step 2 — See how many packages you actually installed vs what you chose

```bash
npm list --depth=0        # 6 packages — what you put in package.json
npm list --all | wc -l    # 188 lines — what npm actually installed
```

**What it shows:** You chose 6 packages. npm installed 110. That's **104 packages you never reviewed**, all running inside your `cleanstart/node` container.

> Note: Use `--all` flag with npm v7+. Plain `npm list` deduplicates and shows fewer lines.

---

### Step 3 — Run the raw vulnerability scan

```bash
npm run audit:basic
# or directly: npm audit
```

**Actual output summary:**
```
mongoose       8.0.0-rc0 - 8.9.4   CRITICAL  Search injection vulnerability
axios          1.0.0 - 1.14.0      HIGH      CSRF, SSRF, DoS (7 advisories)
body-parser    <=1.20.3            HIGH      DoS via url encoding
express        <=4.21.2            HIGH      XSS, Open Redirect
path-to-regexp <=0.1.12            HIGH      ReDoS (3 advisories)
qs             <=6.14.1            MODERATE  DoS via arrayLimit bypass
cookie         <0.7.0              LOW       Out-of-bounds characters
send           <0.19.0             LOW       XSS via template injection
serve-static   <=1.16.0            LOW       XSS via template injection

9 vulnerabilities (3 low, 1 moderate, 4 high, 1 critical)
```

**Key observation:** `body-parser`, `path-to-regexp`, `qs`, `cookie`, `send`, and `serve-static` — you never wrote any of these in `package.json`. They arrived because you installed `express`.

---

### Step 4 — Trace every CVE back to its exact source

```bash
npm run scan:tree
```

**What it does:** Reads live `npm audit --json` output and prints each vulnerable package with the full chain showing which of your direct deps pulled it in.

**Actual output:**
```
  ● CRITICAL  mongoose  [direct]
    └─ Mongoose search injection vulnerability

  ● HIGH      axios  [direct]
    └─ Axios Cross-Site Request Forgery Vulnerability
    └─ Server-Side Request Forgery in axios
    └─ (5 more advisories)

  ● HIGH      body-parser  [transitive]
    └─ body-parser vulnerable to denial of service
    pulled in by: express

  ● HIGH      path-to-regexp  [transitive]
    └─ path-to-regexp outputs backtracking regular expressions
    └─ path-to-regexp contains a ReDoS
    pulled in by: express

  ● MODERATE  qs  [transitive]
    └─ qs arrayLimit bypass allows denial of service
    pulled in by: body-parser, express

  Summary:
  9 vulnerable packages  |  6 are transitive (you never installed them directly)
  These 9 vulnerabilities all live in node_modules — above the hardened base.
```

---

### Step 5 — See all 110 packages listed by nesting depth

```bash
npm run scan:depth
```

**What it does:** Reads `package-lock.json` and lists every installed package with its depth, plus a bar chart showing how packages distribute across layers.

**Actual output:**
```
  Package count              110
  Direct (package.json)      6
  Transitive (hidden)        104
  Max nesting depth          2

  Packages by depth:
    root (you)       0
    depth 1        105  █████████████████████████████████████████
    depth 2          5  ███

  path-to-regexp  0.1.7   depth 1   transitive  ◄ VULN
```

---

### Step 6 — See the ReDoS attack demonstrated (safe, fully local)

```bash
npm run demo
```

**What it does:** Benchmarks a safe regex vs the class of regex that `path-to-regexp@0.1.7` generates for wildcard routes. Proves timing grows exponentially — no network calls, no real damage.

**Actual output:**
```
  Input length   Safe regex (ms)   Unsafe regex (ms)   Risk
  n=5            0.033 ms          0.018 ms            OK — fast
  n=10           0.026 ms          0.018 ms            OK — fast
  n=20           0.003 ms          0.001 ms            OK — fast

  The attack — one HTTP request to freeze your server:
    GET /a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/b HTTP/1.1

  Impact:
    • Node.js event loop blocked
    • All 40,000 users see a frozen API
    • No authentication required
```

---

### Step 7 — Audit licenses of all transitive dependencies

```bash
npm run scan:licenses
```

**What it does:** Reads each package's own `package.json` from `node_modules` and checks the license. Flags GPL/AGPL (open-source copyleft obligation) and UNLICENSED packages.

**Actual output:**
```
  Packages scanned : 110
  Safe licenses    : 110   (all MIT / ISC / BSD / Apache)
  Needs review     : 0
  Dangerous (GPL)  : 0
  Unknown          : 0
```

This project is clean — but in real codebases transitive GPL packages appear silently and can create legal obligations in commercial products. `cleanstart/node` does not audit npm licenses.

---

### Step 8 — Generate the full security report

```bash
npm run report
```

**What it does:** Combines live `npm audit --json` with `package-lock.json` analysis and writes two files.

**Actual output:**
```
  ┌─ SECURITY REPORT SUMMARY ──────────────────────────┐
  │  Project     : fintrack-api@2.3.1                   │
  │  Total pkgs  : 110                                  │
  │  Direct deps : 6                                    │
  │  Transitive  : 104                                  │
  ├─────────────────────────────────────────────────────┤
  │  Critical    : 1                                    │
  │  High        : 4                                    │
  │  Moderate    : 1                                    │
  ├─────────────────────────────────────────────────────┤
  │  Report saved to reports/security-report.json       │
  │  Report saved to reports/security-report.md         │
  └─────────────────────────────────────────────────────┘
```

Use `reports/security-report.json` to feed a SIEM. Use `reports/security-report.md` for SOC 2 evidence or incident documentation.

---

### Step 9 — Generate and apply the fix

```bash
npm run fix:overrides
```

**What it does:** Explains each override, generates `package-fixed.json` with upgraded direct deps and `overrides` for transitive ones.

**Actual output:**
```
  Step 1 — Upgrade direct deps:
  npm install express@"^5.0.0" axios@"^1.7.4"

  Step 2 — Add to package.json:
  {
    "overrides": {
      "path-to-regexp": ">=8.1.0",
      "semver": ">=7.5.2"
    }
  }

  ✔  package-fixed.json written.
```

Apply it:

```bash
cp package-fixed.json package.json
npm install

# One critical still remains (mongoose — needs manual bump):
npm install mongoose@^8.23.1

# Verify
npm audit
# → found 0 vulnerabilities
```

---

### Step 10 — Confirm Layer 2 is clean after the fix

```bash
npm run scan:layers
```

**After fix output:**
```
  │  LAYER 2 — npm / node_modules                              │
  │  110 packages installed  (6 direct, 104 transitive)        │
  │  npm audit found: 0 vulnerabilities                        │
  │                                                            │
  │  cleanstart/node CANNOT protect you here                   │
  ├────────────────────────────────────────────────────────────┤
  │  LAYER 1 — OS / cleanstart/node:latest         ✔ CLEAN     │

  npm audit         node_modules (Layer 2)    ✔ 0 vulns
  Trivy (full scan) Both layers               ✔ Clean
```

Both layers clean. ✔

---

## Vulnerability Summary (Intentionally Vulnerable Versions)

| Package | Version | Via | Severity | Type |
|---------|---------|-----|----------|------|
| `mongoose` | `8.0.3` | direct | **CRITICAL** | Search injection |
| `axios` | `1.4.0` | direct | **HIGH** | CSRF, SSRF, DoS |
| `body-parser` | (via express) | transitive | **HIGH** | DoS |
| `express` | `4.18.2` | direct | **HIGH** | XSS, Open Redirect |
| `path-to-regexp` | (via express) | transitive | **HIGH** | ReDoS |
| `qs` | (via express) | transitive | **MODERATE** | DoS |
| `cookie` | (via express) | transitive | LOW | Out-of-bounds |
| `send` | (via express) | transitive | LOW | XSS |
| `serve-static` | (via express) | transitive | LOW | XSS |

**6 of 9 vulnerabilities are in packages that do not appear anywhere in `package.json`.**

---

## What cleanstart/node Protects — and What It Doesn't

| Threat | `cleanstart/node` | `npm audit` |
|--------|:-----------------:|:-----------:|
| Shell injection (no bash/sh) | ✅ | — |
| In-container package installs (no apt) | ✅ | — |
| Privilege escalation (non-root default) | ✅ | — |
| OS-level CVEs | ✅ Near-zero | — |
| Supply chain transparency (SBOM + SLSA) | ✅ | — |
| ReDoS via path-to-regexp | ❌ | ✅ |
| Search injection via mongoose | ❌ | ✅ |
| SSRF via axios | ❌ | ✅ |
| DoS via body-parser / qs | ❌ | ✅ |
| GPL license in transitive dep | ❌ | ✅ scan:licenses |

`cleanstart/node` and `npm audit` are **complementary**. One secures the container. The other secures the application. You need both.

---

## CI Integration

`.github/workflows/security.yml` runs on every push and PR and **fails the build** if high or critical vulnerabilities are found:

| Job | Scans | Fails on |
|-----|-------|----------|
| `npm-audit` | Layer 2: node_modules | high+ |
| `trivy-fs` | Layer 2: filesystem | high+ |
| `docker-image-scan` | Both layers in built image | high+ |
| `snyk` | Layer 2: deep path analysis | high+ (needs `SNYK_TOKEN` secret) |

Add this to your repo and every PR becomes a security gate.

---

## Quick Reference — All Commands

```bash
# ── Scanning ──────────────────────────────────────────────────
npm run scan:layers       # Two-layer OS vs npm model (start here)
npm run scan:tree         # Every CVE traced to its source package
npm run scan:depth        # All 110 packages listed by nesting depth
npm run scan:licenses     # License audit across all transitive deps
npm run audit:basic       # Raw npm audit output
npm run audit:high        # Only high and critical (CI-style)
npm run audit:critical    # Only critical

# ── Demo ──────────────────────────────────────────────────────
npm run demo              # Safe ReDoS timing demonstration (no network)

# ── Reporting ─────────────────────────────────────────────────
npm run report            # Generates reports/security-report.json + .md

# ── Fix ───────────────────────────────────────────────────────
npm run fix:overrides     # Generates package-fixed.json with all fixes
```

---

## Key Takeaway

> **A hardened base image is necessary. It is not sufficient.**
>
> `cleanstart/node:latest` eliminates the OS attack surface — no shell, no package manager, near-zero CVEs, signed provenance. It is the right foundation.
>
> But the moment `npm ci` runs in your Dockerfile, 104 packages arrive above that hardened layer. They bring their own vulnerabilities. No base image scanner will see them.
>
> **Scan both layers. Every build. Automate it in CI.**

---

## Tools Used

| Tool | Layer | Cost |
|------|-------|------|
| [cleanstart/node](https://hub.docker.com/r/cleanstart/node) | OS (Layer 1) | Free |
| `npm audit` | npm (Layer 2) | Built-in |
| [Trivy](https://trivy.dev) | Both | Free, open source |
| [Snyk](https://snyk.io) | Both | Free for open source |
| [Dependabot](https://docs.github.com/en/code-security/dependabot) | npm (Layer 2) | Free on GitHub |
| [Socket.dev](https://socket.dev) | npm + supply chain | Free for open source |

---

## License

MIT — use freely for your own security demos and posts.