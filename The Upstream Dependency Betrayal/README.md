# The Upstream Dependency Betrayal: When Trusted Sources Become Compromised

> **Use Case:** Illustrating risks when upstream base images and package dependencies are silently compromised — and how to detect and mitigate supply chain attacks before they reach production.

---

## The Problem

Modern containerized workloads are built on trust. Engineers pull base images from Docker Hub, install packages from PyPI, npm, or apt mirrors, and assume the upstream maintainer — or the registry — hasn't been compromised.

That assumption is the attack surface.

**Upstream dependency betrayal** occurs when a source that a team legitimately trusts — a base image, a language package, a system library — is silently replaced, tampered with, or taken over. The malicious artifact flows downstream through CI/CD pipelines, gets baked into container images, and lands in production without raising an alarm, because every step in the chain trusted the previous one.

### Why This Is Dangerous for Container Workloads

- Base images are pulled by tag (`python:3.12-slim`), not by digest. Tags are mutable — the same tag can point to a different layer set tomorrow.
- Most pipelines do not verify image signatures or SBOMs at pull time.
- A compromised `apt` or `pip` package installs silently alongside legitimate dependencies — no build failure, no warning.
- Container images are rebuilt frequently. Each rebuild is a fresh opportunity to ingest a poisoned upstream artifact.
- The attacker's code runs inside your runtime environment, often with access to secrets, service tokens, and internal network paths.

### Real-World Precedents

| Incident | Vector | Impact |
|---|---|---|
| **SolarWinds (2020)** | Trojanized build artifact injected into signed update | ~18,000 organizations compromised |
| **ua-parser-js (2021)** | npm package account hijacked; malicious version published | Cryptominer + credential stealer shipped to millions |
| **CodeCov (2021)** | CI bash uploader script tampered via compromised GCP credentials | CI secrets exfiltrated from thousands of pipelines |
| **PyTorch nightly (2022)** | Dependency confusion attack via PyPI; malicious `torchtriton` package | Researcher credentials exposed |
| **xz utils (2024)** | Multi-year social engineering → backdoor in `liblzma` upstream | Targeted SSH authentication bypass in Linux distros |
| **tj-actions/changed-files (2025)** | GitHub Actions workflow compromised; secrets dumped in logs | Broad CI/CD secret exposure across public repos |

The pattern is consistent: trusted artifact → silent substitution or injection → downstream consumers inherit the compromise.

---

## Replication Steps

> **⚠ This section is for educational and controlled lab use only. Do not run against production systems or real registries.**

The following walkthrough simulates an upstream tag mutation attack — the most common vector for base image poisoning in a CI/CD pipeline. All five steps run from a **single script** that generates every required file (Dockerfiles, app code) inline and executes the full attack chain end-to-end.

### Prerequisites

- Docker with BuildKit enabled
- A local registry (`registry:2`) running on `localhost:5000`
  ```bash
  docker run -d -p 5000:5000 --name local-registry registry:2
  ```
- [`syft`](https://github.com/anchore/syft) — SBOM generation
- [`grype`](https://github.com/anchore/grype) — vulnerability scanning
- `jq`

### Run the Lab

```bash
chmod +x replicate.sh
./replicate.sh
```

All artefacts are written to `./lab-workspace/`. The script walks through five numbered sections with clear output at each stage.

### What each step does

**Step 1 — Establish a Trusted Baseline**
Pulls `python:3.12-slim` by immutable digest (not tag), pushes it to the local registry as the trusted upstream, and generates a CycloneDX baseline SBOM capturing the exact component inventory.

**Step 2 — Simulate the Upstream Compromise**
Builds a poisoned image (`Dockerfile.poisoned`) that injects a hidden backdoor file and silently adds the `requests` package — then overwrites the same tag in the local registry. The tag now resolves to a different image with a different digest. No notification is sent downstream.

**Step 3 — Downstream Victim Build**
Runs a standard CI/CD application build (`Dockerfile`) that pulls by tag. Because the tag now resolves to the poisoned image, the application image silently inherits the attacker's layers. The build completes with no error and no warning.

**Step 4 — Detection Gap Demonstration**
Runs a CVE scan with `grype` — it passes, because `requests` carries no known CVE. Then diffs the current SBOM against the baseline — the unexpected `requests` addition is immediately visible. A digest mismatch check confirms the tag resolved to a different image than was originally trusted.

**Step 5 — Verify the Attack Path**
Runs the built application container and confirms the backdoor file is present inside it. Simulates the attacker's access to environment variables (secrets, tokens, keys) that the injected layer would have had access to at runtime.

### Cleanup

```bash
docker rmi myapp:latest localhost:5000/python:3.12-slim 2>/dev/null || true
docker stop local-registry && docker rm local-registry 2>/dev/null || true
rm -rf ./lab-workspace
```

---

## The CleanStart Solution

CleanStart container images are designed to eliminate the trust gaps that make upstream dependency betrayal possible. The protection operates at three layers: **provenance**, **composition**, and **verification**.

### 1. Immutable, Digest-Pinned Base Images

All CleanStart images are referenced and distributed by SHA-256 digest, not mutable tags. Every image is published with a stable digest that does not change once released.

A tag pointing to a different digest than expected is a detectable, alertable event — not a silent failure.

---

### 2. Cosign Signature Verification at Pull Time

Every CleanStart image is signed using [Sigstore Cosign](https://github.com/sigstore/cosign). Before any image is used in a build pipeline, its signature can be verified against CleanStart's public key.

A tampered or unsigned image fails verification and never enters the build pipeline.

---

### 3. CycloneDX SBOMs Published Per Image

Every CleanStart image ships with a signed CycloneDX SBOM that enumerates all OS packages, language runtimes, and installed libraries — down to version and file hash.

Any unexpected component addition, removal, or version change between image releases is immediately visible — no manual layer inspection required.

---

### 4. Minimal Attack Surface by Design

CleanStart images are distroless-oriented and hardened: no package managers, no shells, no unnecessary tooling in production images. This directly limits the blast radius of a compromised upstream:

- No `pip`, `apt`, or `curl` at runtime means a compromised layer cannot silently install additional payloads post-deployment.
- Minimal OS footprint reduces the set of patchable system libraries an attacker can target.
- Images are rebuilt and re-signed on every upstream CVE fix, not on a monthly schedule.

---

## Other Applicable Solutions

These measures complement or extend the CleanStart approach and apply broadly across any container supply chain.

### Dependency and Image Pinning

| Practice | Tool / Mechanism |
|---|---|
| Pin base images by digest in Dockerfiles | `FROM python:3.12-slim@sha256:<digest>` |
| Pin Python packages to exact versions + hashes | `pip install --require-hashes -r requirements.txt` |
| Pin npm packages with lockfiles | `npm ci` (uses `package-lock.json`) |
| Pin Go modules | `go.sum` verification |
| Pin GitHub Actions by commit SHA | `uses: actions/checkout@<full-sha>` |

Pinning by digest or hash ensures that what you specified is exactly what gets used — regardless of what a tag now resolves to.

---

### Software Supply Chain Frameworks

**SLSA (Supply Chain Levels for Software Artifacts)**

SLSA defines a graduated framework of hardening levels (1–4) covering build provenance, hermetic builds, and two-person review. At SLSA Level 2+, every artifact is accompanied by a signed provenance attestation describing how it was built, by what system, and from which source.

```bash
# Verify SLSA provenance using slsa-verifier
slsa-verifier verify-image \
  public.ecr.aws/cleanstart/python:3.12-slim \
  --source-uri github.com/cleanstart/images \
  --source-tag v1.2.3
```

**In-toto**

In-toto defines a supply chain layout: a signed policy document that specifies who is authorized to perform each step (clone, build, test, package, sign) and links signed attestations from each step. Any deviation — a step skipped, a step run by an unauthorized party — fails verification.

---

### Dependency Confusion and Typosquatting Defenses

| Threat | Mitigation |
|---|---|
| Dependency confusion (private package names resolved from public registries) | Use `--index-url` scoping; configure trusted internal registry as the sole resolver |
| Typosquatting (`requets`, `flask-restfull`) | Enforce allowlist of approved packages in CI; use `pip-audit` or `socket.dev` |
| Malicious transitive dependencies | Generate and diff SBOMs on every build; use `pip-licenses` or `cyclonedx-py` |

---

### CI/CD Pipeline Hardening

```yaml
# GitHub Actions — pull by digest, verify signature before build
- name: Verify base image signature
  run: |
    cosign verify \
      --key ${{ secrets.COSIGN_PUBLIC_KEY }} \
      public.ecr.aws/cleanstart/python:3.12-slim@sha256:${{ env.BASE_DIGEST }}

- name: Build application image
  run: |
    docker build \
      --build-arg BASE=public.ecr.aws/cleanstart/python:3.12-slim@sha256:${{ env.BASE_DIGEST }} \
      -t myapp:${{ github.sha }} .
```

Key pipeline controls:

- **Fail-fast on signature mismatch** — treat unsigned images as untrusted inputs.
- **SBOM generation on every build** — attach CycloneDX SBOM as a build artifact.
- **SBOM diff gating** — fail the build if unexpected components appear versus the previous release SBOM.
- **Ephemeral build environments** — use isolated, short-lived runners; never reuse build state across pipelines.
- **Least-privilege registry credentials** — CI tokens should have pull-only access; push credentials should be scoped to specific repositories and short-lived.

---

### Runtime Detection

Even with strong supply chain controls at build time, runtime monitoring provides a defense-in-depth layer:

| Tool | What It Detects |
|---|---|
| **Falco** | Unexpected process spawns, outbound connections, file writes in read-only containers |
| **Tetragon** | eBPF-based syscall monitoring; detects exfiltration patterns at the kernel level |
| **Grype / Trivy (continuous)** | New CVEs published against already-deployed images (via scheduled rescans) |
| **Admission webhooks** | Block pods referencing images that fail current signature or SBOM policy checks |

A backdoor that made it through the build pipeline can still be caught at runtime if it exhibits unusual behavior — spawning shells, making unexpected network calls, or writing to unexpected paths.

---

## Summary

| Layer | Without CleanStart | With CleanStart |
|---|---|---|
| Base image integrity | Mutable tags, no verification | Immutable digests + Cosign signatures |
| Dependency visibility | No SBOM, manual inspection | Signed CycloneDX SBOM per image |
| Build-time trust | Pull by tag, silent mutation possible | Digest pinning + signature gate in CI |
| Runtime enforcement | No admission control | Kyverno / OPA policy enforces signed images |
| Attack surface | Full OS toolchain in image | Minimal / distroless; no runtime package managers |

Upstream dependency betrayal works because trust is implicit and verification is optional. The mitigation strategy is to make trust explicit — every artifact must carry a verifiable proof of who built it, from what inputs, and when — and to make verification mandatory at every stage of the pipeline.

---

*Use case authored for CleanStart Technologies · Container Security & DevSecOps*