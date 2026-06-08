# Container Image Signing & Verification
## Community Use Case · Category 7: Supply Chain & Trust Issues

> **Tagline:** Don't just read about hardened images — see the results yourself.

---

## What this use case demonstrates

1. Pulling an unsigned public image produces **no warning** — the failure is invisible by default.
2. `cosign verify` immediately reveals missing signatures on unmanaged images.
3. A well-hardened image should carry **two layers of cryptographic trust**: a Cosign signature and a SLSA provenance attestation.
4. A Kyverno `ClusterPolicy` can enforce signature verification at admission time — unsigned images are rejected before they ever run.

---

## Prerequisites

| Tool | Version | Install |
|---|---|---|
| `cosign` | v2.x+ | https://docs.sigstore.dev/cosign/system_config/installation |
| `docker` | 24+ | https://docs.docker.com/get-docker |
| `kubectl` | 1.28+ | Optional — for Kyverno enforcement demo |
| `jq` | any | `apt install jq` / `brew install jq` |

Kyverno must be installed in the cluster for the admission policy step:

```bash
helm repo add kyverno https://kyverno.github.io/kyverno/
helm install kyverno kyverno/kyverno -n kyverno --create-namespace
```

---

## Files

| File | Purpose |
|---|---|
| `run-use-case.sh` | Main demo script — runs all steps in sequence |
| `verify-signed.sh` | Verifies Cosign signature + SLSA provenance attestation on a CleanStart image |
| `kyverno-policy.yaml` | ClusterPolicy enforcing image signatures and SLSA provenance at admission time |
| `README.md` | This file |

---

## Running the demo

```bash
git clone https://github.com/cleanstart-dev/cleanstart-use-cases
cd cleanstart-use-cases/image-signing

chmod +x run-use-case.sh verify-signed.sh
./run-use-case.sh
```

---

## Expected output summary

### Step 1 — Pull unsigned nginx
```
Status: Downloaded newer image for nginx:1.25
# No warning. No signature check. Runs fine.
```

### Step 2 — cosign verify unsigned image
```
Error: no signatures found
error during command execution: no signatures found
```

### Step 3 — cosign verify CleanStart image
```json
{
  "digest": "sha256:d28197fc6e61f2ca2c862466cf09666991be19c44e5d97d83d6589a8fb89823e",
  "ref":    "clnstrt-images.cleanstart.com/cleanstartos/python",
  "type":   "cosign container image signature"
}
Transparency log entry confirmed via Rekor.

{
  "builderId":  "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.3",
  "buildType":  "https://cloudbuild.googleapis.com/CloudBuildYaml@v0.1",
  "entryPoint": "cloudbuild.yaml"
}
SLSA provenance verified.
```

> Note: the digest will differ as the image updates — the signature and provenance structure remain the same.

### Step 4 — Kyverno blocks unsigned image
```
Error from server: admission webhook denied the request:
image signature verification failed for nginx:1.25
```

---

## Why this matters

The core problem is that signing failure is **silent** — an unsigned image still deploys, still runs, and produces no alert. This means there is no operational urgency to adopt signing, even though the risk is real.

The attack surface is the gap between:
- What a publisher built and signed at build time
- What the runtime actually pulled from the registry

Image signing closes that gap. Without it, a compromised registry, a MITM on a pull-through cache, or a tag-overwrite attack is completely invisible to the cluster.

---

## Tooling landscape (2025)

| Tool | Approach | Key management | Registry support |
|---|---|---|---|
| Cosign / Sigstore | Keyless via OIDC + Rekor | None required | OCI-compliant registries |
| Notation / Notary v2 | Key-based | Customer-managed | OCI + Azure ACR, AWS ECR |
| Docker Content Trust | Notary v1 | Customer-managed | Docker Hub (limited) |

As a reference implementation, CleanStart uses **Cosign keyless** via Google Cloud Workload Identity — no key rotation overhead, all signatures publicly auditable via the Sigstore Rekor transparency log.

---

## Adoption reality check

| Metric | Estimate (2025) |
|---|---|
| Public images with any signature | ~4% |
| Teams enforcing verification in CI/CD | ~8% |
| K8s clusters with admission policy | ~11% |
| CNCF projects shipping signed releases | ~38% |
| **CleanStart images — signed** | **100%** |

---

## Contributing

Found a bug? Ran this in a different environment and got different results? Open a PR:

- Add your execution output to `results/your-environment.txt`
- Note your OS, registry, Cosign version, and cluster setup
- Reference this topic number in the PR title

---

*Published as part of the CleanStart community use case initiative.*
*GitHub: https://github.com/cleanstart-dev/cleanstart-use-cases*