# Rootless Containers: Security Theater or Real Protection?

> **CleanStart Use Case** — A 5-minute experiment comparing rootless containers against a hardened base image using SBOM-based vulnerability scanning. All numbers below are reproducible via `./run.sh`.

---

## The Short Answer

**Both — and that is the trap.**

Rootless containers provide **real protection** against one specific class of attacks: privilege escalation and container-to-host escape.

Rootless containers provide **zero protection** against the much larger class of attacks that breach production systems: CVEs in the base image, vulnerable libraries your app loads, and living-off-the-land attacks using shell utilities that ship in your image whether you run as root or not.

This repo proves both halves with **SBOM-based** scans using `syft` + `grype`.

---

## The Result, in One Table

> Verified scan · same Python application · syft + grype, May 2026

| Severity | Rootless (`python:3.14`) | CleanStart | Reduction |
|---|---|---|---|
| **Critical** | 19 | **1** | **94.7%** |
| **High** | 182 | **3** | **98.4%** |
| **Medium** | 397 | 16 | **96.0%** |
| **Low** | 73 | 17 | 76.7% |
| **Negligible** | 844 | 1 | 99.9% |
| **TOTAL CVEs** | **1,579** | **38** | **97.6%** |
| Packages | 473 | **47** | **90.1%** |

Same Python application. Same scanner. Same SBOM format. Different base image.

---

## What Rootless DOES Protect Against (real wins)

1. **Container escape via privileged kernel operations.** A UID 0 process can attempt `mount`, `modprobe`, write to `/proc/sysrq-trigger`, or exploit kernel CVEs requiring capabilities. A non-root UID cannot.
2. **Reduced damage from capability leaks.** Misconfigured runtimes (`--privileged`, dangerous bind mounts) are far more dangerous when the in-container process is root.
3. **Filesystem protection inside the container.** Non-root cannot modify `/etc`, `/usr/bin`, or runtime libraries.

If your threat model is "attacker pwns my app and tries to escalate to host root," rootless is doing real work. **Not theater.**

---

## What Rootless Does NOT Protect Against

1. **CVEs in the base image.** Grype does not care who runs the binary — it cares whether the package is installed. The rootless image ships **19 Critical and 182 High CVEs** that are all accessible to UID 10001 just as they would be to root.
2. **Application-level vulnerabilities.** SQL injection, RCE in a dependency, deserialization bugs — these run at your app's UID. Root not required.
3. **Living-off-the-land attacks.** `bash`, `sh`, `apt`, `gcc`, `curl`, `wget` — all PRESENT in the rootless image. An attacker has a full Unix toolchain. None of it needs root.
4. **Supply-chain compromise.** A malicious dependency does whatever it wants at the application UID.

---

## The Real Story — CleanStart Eliminates Vulnerable Libraries You Don't Need

The 19 Critical CVEs in the rootless image come from libraries the application never uses:

| Library | Critical CVEs | Why is it even there? |
|---|---|---|
| `libraw23t64` | 6 | RAW image processing — not needed for a Python API |
| `libgnutls30t64` | 1 | Alternative TLS library — Python uses OpenSSL |
| `libopenexr` | 2 | HDR image format — not needed |
| `libc6` (4 packages) | 4 | C library — needed, but Debian ships unpatched version |

CleanStart's 1 Critical (`CVE-2026-6100` in Python itself) is the same one present in rootless — it is a real upstream Python CVE. **CleanStart is not hiding it.** The difference is that 18 other Critical CVEs in libraries the app never touches have been removed by not shipping those libraries.

This is **security through elimination**, not security through patching.

---

## Requirements

Before running the experiment, install these tools:

- **Docker** — for building images
- **Syft** — for generating SBOMs
```bash
  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin
```
- **Grype** — for scanning SBOMs
```bash
  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin
```

---
## The Experiment

Two Dockerfiles, same demo app:

```
Dockerfile.rootless    — python:3.14 + USER appuser (UID 10001)
Dockerfile.cleanstart  — cleanstart/python + USER clnstrt
```

Run the comparison:

```bash
git clone https://github.com/cleanstart-dev/cleanstart-use-cases.git
cd cleanstart-use-cases/rootless-containers

chmod +x run.sh
./run.sh
```

What it does:

1. Builds both images
2. Prints UID inside each container (both non-root — rootless works)
3. Generates SBOMs with `syft`
4. Checks dangerous binaries (bash, gcc, curl, etc.) inside each image
5. Scans SBOMs with `grype` and prints CVE counts by severity

---

## Why CleanStart Wins

What an attacker who breaches each container can actually do:

| Attacker capability | rootless | **cleanstart** |
|---|---|---|
| Run as root | no | no |
| Spawn `bash` shell | yes | **no** |
| Compile exploits (`gcc`) | yes | **no** |
| Install packages (`apt`) | yes | **no** |
| Exfiltrate via `curl`/`wget` | yes | **no** |
| Exploit Critical CVEs | 19 available | **1 available** |
| Exploit High CVEs | 182 available | **3 available** |
| Total CVE pool | 1,579 | **38** |

Rootless is one control: it makes privilege escalation harder. CleanStart **plus** rootless reduces the attack surface itself.

---

## The Correct Mental Model

> **Rootless alone** = "if attacker gets in, they cannot become root"
>
> **CleanStart + rootless** = "if attacker gets in, there is nothing to run, 97.6% fewer CVEs to exploit, and they are not root anyway"

Rootless is a single layer of defense. CleanStart provides image-layer defenses (no shell toolchain, 90% fewer packages, 97.6% fewer CVEs) **plus** the rootless layer — in one base image.

---

## What Good Looks Like in Practice

```dockerfile
FROM cleanstart/python:latest
WORKDIR /app
COPY app.py .
USER clnstrt
CMD ["app.py"]
```

```yaml
# Kubernetes pod spec — runtime controls that compose with the image
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
  seccompProfile:
    type: RuntimeDefault
```

---

## Project Structure

```
rootless-containers/
├── README.md              # This file
├── Dockerfile.rootless    # python:3.14 + USER appuser
├── Dockerfile.cleanstart  # cleanstart/python + USER clnstrt
├── app.py                 # Demo app that prints UID/GID
└── run.sh                 # Build + SBOM generation + 4 tests
```

---

## Key Takeaways

1. **Rootless is real protection — for a specific threat model.** It blocks privileged escape. Not theater.
2. **Rootless does not reduce CVEs.** The rootless image still ships 19 Critical and 182 High CVEs that root would have had. UID 10001 can exploit them all.
3. **Rootless does not remove your attack toolchain.** Same `bash`, `gcc`, `curl`, `wget` as a root container.
4. **CleanStart eliminates 90% of packages and 97.6% of CVEs.** SBOM-verified, reproducible, scanner-agnostic.
5. **CleanStart is honest about what remains.** 1 Critical (the upstream Python CVE) is shared with rootless — but 18 Criticals from unused libraries are gone.
6. **If you can only do one thing, switch base image.** CleanStart gives you both layers in one move.

---
