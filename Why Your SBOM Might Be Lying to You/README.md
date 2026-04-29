# Why Your SBOM Might Be Lying to You - Demo

>A reproducible proof-of-concept showing how SBOMs can be incomplete and misleading.

## 1. The Problem

Software Bill of Materials (SBOM) tools like Syft perform **static filesystem analysis** — they scan what exists in the container image at build time. They read package metadata from `site-packages/`, OS package databases (`dpkg`, `rpm`, `apk`), and lock files.

**They do not execute the image. They do not observe what happens at runtime.**

This creates a silent gap: any dependency installed after the image is built — via a startup script, entrypoint, plugin loader, or runtime `pip install` — is completely invisible to the SBOM scanner. The SBOM looks clean. CVE scans against it report zero issues. But a vulnerable package is running live in production.

### What the gap looks like

| Check | Result |
|---|---|
| Packages declared in SBOM | `flask`, `requests` |
| Packages running at runtime | `flask`, `requests`, **`cryptography`** |
| CVE scan against SBOM file | `0 issues` ✅ (misleading) |
| CVE scan against live image | `vulnerabilities found` ⚠️ |

### Why this happens

SBOM generators scan the container filesystem **once, at build time**. They never execute the image, so anything installed by the application itself on startup is outside the scanner's visibility window.

```
Build time  ──────────────────────────►  Runtime
     │                                      │
   Syft                                  app.py
   scans                               installs
   here                               cryptography
     │                                      │
  [flask]                             [flask]
  [requests]                          [requests]
                                      [cryptography]  ← invisible to SBOM
```

### Common patterns that trigger this gap

| Pattern | Why it's missed |
|---|---|
| Runtime `pip install` in entrypoints or init scripts | Happens after image build; scanner never sees it |
| JVM fat JARs with nested dependencies | Inner JAR versions differ from declared POM |
| Multi-stage builds with artifact leakage | Build tools appear in SBOM but not the final image |
| Distroless / minimal images | OS package DB is stripped; scanners undercount |
| Dynamic plugin loaders | Plugins fetched from a remote registry at startup |
| Language wrappers over native libs | Python `cryptography` wraps `openssl`; version mismatch is common |

> A signed SBOM that is incomplete is more dangerous than no SBOM — it creates false confidence.

---

## 2. Recreation Steps

### Prerequisites

```bash
# Syft — SBOM generator
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Grype — vulnerability scanner
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Verify Docker is available
docker --version
```

### Project structure

```
sbom-gap-demo/
├── Dockerfile              # uses cleanstart/python:latest-dev base
├── app.py                  # deliberately installs a dep at runtime
├── requirements.txt        # missing cryptography intentionally
├── sbom-output.json        # generated — not committed
├── sbom-spdx.json          # generated — not committed
└── README.md
```

---

### Step 1 — Build the image

```bash
docker build -t sbom-demo:latest .
```

---

### Step 2 — Generate the SBOM

```bash
# CycloneDX format
syft sbom-demo:latest -o cyclonedx-json > sbom-output.json
```

```
 ✔ Loaded image                                                                                                                                                                              sbom-demo:latest
 ✔ Parsed image                                                                                                                       sha256:8680fb7e10fcf72b63e623e9b2c2fa0fb9a2640154dedd2120aeb2f09f16d6d4
 ✔ Cataloged contents                                                                                                                        61d3b11314cd6aacb1a1d59c0a4cbed3fd219f70a604e350340ab98bd9d3bef2
   ├── ✔ Packages                        [167 packages]
   ├── ✔ Executables                     [907 executables]
   ├── ✔ File metadata                   [4,301 locations]
   └── ✔ File digests                    [4,301 files]
A newer version of syft is available for download: 1.43.0 (installed version is 1.39.0)
```

---

### Step 3 — Search the SBOM for the hidden package

```bash
# Grep for the runtime-installed package — expect no results
cat sbom-output.json | python3 -m json.tool | grep -i "cryptography"

# List only Python packages declared in the SBOM
cat sbom-output.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
components = data.get('components', [])
python_pkgs = [c for c in components if c.get('purl', '').startswith('pkg:pypi')]
print(f'Python packages in SBOM: {len(python_pkgs)}')
for c in python_pkgs:
    print(f\"  - {c['name']}=={c.get('version','?')}\")
"
```

**Expected output:** `cryptography` is not found. The SBOM lists only `flask`, `requests`, and their transitive dependencies.

> Note: The total SBOM component count will be large (thousands) because Syft also catalogues OS-level packages from the base image. Filtering by `pkg:pypi` purl isolates just the Python packages, which is what matters for this demonstration.

```
Python packages in SBOM: 13
  - blinker==1.9.0
  - certifi==2026.4.22
  - charset-normalizer==3.4.7
  - click==8.3.3
  - flask==3.0.0
  - idna==3.13
  - itsdangerous==2.2.0
  - jinja2==3.1.6
  - markupsafe==3.0.3
  - pip==26.0
  - requests==2.31.0
  - urllib3==2.6.3
  - werkzeug==3.1.8
```

---

### Step 4 — Prove the package exists at runtime

Since the `ENTRYPOINT` is set to `python`, running commands directly via `docker run` would be interpreted as Python arguments. Start the container in the background instead and exec into it.

```bash
# Start the container — app.py installs cryptography on startup
docker run -d --name sbom-test sbom-demo:latest

# Wait for the startup install to complete
sleep 8

# Check logs to confirm the install succeeded
docker logs sbom-test

# List packages inside the running container
docker exec sbom-test pip list

# Grep specifically for cryptography
docker exec sbom-test pip list | grep -i cryptography
```

**Expected output:** `cryptography 41.0.0` appears in the running container despite not being in the SBOM.

```bash
# Clean up
docker stop sbom-test && docker rm sbom-test
```

```
Package            Version
------------------ ---------
blinker            1.9.0
certifi            2026.4.22
cffi               2.0.0
charset-normalizer 3.4.7
click              8.3.3
cryptography       41.0.0    <---
Flask              3.0.0
idna               3.13
itsdangerous       2.2.0
Jinja2             3.1.6
MarkupSafe         3.0.3
pip                26.0
pycparser          3.0
requests           2.31.0
urllib3            2.6.3
Werkzeug           3.1.8
```

---

### Step 5 — CVE scan: SBOM file vs. live image

```bash
# Start the container again for the live scan
docker run -d --name sbom-test sbom-demo:latest
sleep 8

# Scan the SBOM file — what compliance tools see
grype sbom:sbom-output.json

# Scan the live running image — ground truth
grype sbom-demo:latest

# Clean up
docker stop sbom-test && docker rm sbom-test
```

**Expected result:** The SBOM-based scan shows fewer or zero vulnerabilities for `cryptography`. The live image scan surfaces CVEs that the SBOM scan missed entirely.

>scan without cryptography
```
 ✔ Vulnerability DB                [updated]
 ✔ Scanned for vulnerabilities     [45 vulnerability matches]
   ├── by severity: 2 critical, 3 high, 21 medium, 18 low, 1 negligible
   └── by status:   4 fixed, 41 not-fixed, 0 ignored
```

>scan with cryptography
```
 ✔ Loaded image                                                                                                                                                                              sbom-demo:latest
 ✔ Parsed image                                                                                                                       sha256:e039c0702e101ac8aee46521d7c998e28a5fb16d7d727fff49bc19fc2eb99faa
 ✔ Cataloged contents                                                                                                                        839782e84b303141e59360db87e9648da77203c4894c25f436692c46a332b5b5
   ├── ✔ Packages                        [167 packages]
   ├── ✔ Executables                     [907 executables]
   ├── ✔ File metadata                   [4,301 locations]
   └── ✔ File digests                    [4,301 files]
 ✔ Scanned for vulnerabilities     [46 vulnerability matches]
   ├── by severity: 2 critical, 3 high, 22 medium, 18 low, 1 negligible
   └── by status:   16 fixed, 30 not-fixed, 0 ignored
```

## 3. Solution

The root cause is installing dependencies outside the image build process. The fix is to declare all dependencies in `requirements.txt` and install them during `docker build` so Syft can see everything in the filesystem before the image ships.


### Rules to enforce going forward

| Rule | Why it matters |
|---|---|
| All dependencies go in `requirements.txt` / `package-lock.json` / `go.sum` | Makes them visible to SBOM scanners and reproducible across builds |
| No `pip install`, `npm install`, or `apt-get` in entrypoints or init scripts | Runtime installs bypass the build layer and the scanner entirely |
| Pin exact versions | Floating versions mean the SBOM version and runtime version can silently diverge |
| Regenerate and re-sign the SBOM on every image rebuild | A stale SBOM reflects a stale snapshot, not the current image |
| Diff SBOM output against `pip list` in CI | Catches drift before it reaches production |

### Additional hardening

- Sign SBOMs with Cosign and include scan scope metadata so consumers know what was scanned and when
- Use `--no-cache-dir` in pip installs to prevent stale cached packages from affecting reproducibility
- Generate separate SBOMs per architecture in multi-arch builds — dependency trees can differ between AMD64 and ARM64
- Attest with in-toto for full supply chain provenance linking each build step to its output