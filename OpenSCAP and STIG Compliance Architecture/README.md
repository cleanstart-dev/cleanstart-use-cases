# STIG Compliance Demo: `cleanstart/python:latest`

A hands-on demo showing how the hardened `cleanstart/python:latest` image qualifies as a STIG-compliant base for Python workloads in both **Docker** and **Kubernetes** environments.

---

## Overview

| Dimension | `python:latest` | `cleanstart/python:latest` |
|---|---|---|
| Image size | 1.63 GB | 125 MB |
| Default user | `root` (UID 0) | non-root (UID 1000) |
| Shell present | `bash`, `sh`, `dash` | none |
| Package manager | `apt`, `pip` | none in runtime |
| HIGH/CRITICAL CVEs | 1693 | 0 |
| Signed provenance (SLSA) | ❌ | ✅ |
| CIS Benchmark applied | ❌ | ✅ |
| Continuous rebuild | weeks/months | daily |

---

## STIG Compliance Parameters

A container image qualifies as STIG-compliant when it meets these requirements:

| # | Parameter | Reference |
|---|---|---|
| 1 | Runs as a **non-root user** | STIG V-257791, CIS 4.1 |
| 2 | **No shells** (`bash`, `sh`, `ash`, `dash`) | STIG V-257777, CIS 4.3 |
| 3 | **No package managers** (`apt`, `apk`, `yum`, `dnf`) | STIG "least functionality" |
| 4 | **Zero HIGH/CRITICAL CVEs** | STIG V-257780 |
| 5 | Supports **read-only root filesystem** | STIG V-257792, CIS 5.12 |
| 6 | **No setuid/setgid binaries** | STIG V-204451, CIS 4.8 |
| 7 | Compatible with `--cap-drop=ALL` | STIG V-257789, CIS 5.3 |
| 8 | **SBOM** included | NIST 800-218, EO 14028 |
| 9 | **Cryptographically signed** | STIG V-257795, SLSA L3 |
| 10 | **Continuously rebuilt** for new CVEs | STIG V-257780 |

`cleanstart/python:latest` meets all ten. The stock `python:latest` meets none.

---

## Why `cleanstart/python:latest` Qualifies

| Image Property | Control Satisfied | Why It Matters |
|---|---|---|
| Distroless (no shell, no package manager) | STIG V-257777, CIS Docker 4.3 | Attacker who lands in the container has no shell to pivot from |
| Runs as non-root by default | STIG V-257791, NIST AC-6 | Container escape attempts hit a non-root user |
| Read-only root filesystem compatible | STIG V-257792, CIS Docker 5.12 | Prevents tampering with binaries at runtime |
| No `setuid` / `setgid` binaries | STIG V-204451, CIS Docker 4.8 | Removes a classic privilege-escalation vector |
| Signed images (Cosign / Sigstore) | NIST 800-218 PS.2, SLSA L3 | Cryptographic proof the image wasn't tampered with |
| SBOM included (SPDX/CycloneDX) | EO 14028, CMMC SI.L2-3.14.5 | Auditor gets a signed parts list, not a guess |
| Continuous CVE rebuilds | STIG V-257780, NIST SI-2 | Patches arrive in hours, not sprints |
| CIS Benchmark hardening applied | CIS Docker Benchmark v1.6 | Hardened defaults out of the box |
| Hermetic, reproducible builds | SLSA L3, NIST 800-218 PS.3 | Same inputs → same output, every time |
| Minimal attack surface (~80 vs ~610 packages) | STIG "least functionality" family | Fewer packages, fewer CVEs to track |

**The bottom line:** If an auditor asks *"what's your hardening baseline for Python containers?"*, the answer **"we start from `cleanstart/python:latest`, verify the signature, ingest the SBOM, and run with a read-only rootfs as a non-root user"** is complete and defensible. You're not promising to harden — you've adopted an image that ships hardened.

---

## Prerequisites

- **Docker** required for both paths
- **Trivy** for CVE scanning 
- **kind** + **kubectl** for the Kubernetes path 

---

## Test 1: Container (Docker)

### Step 1 — Pull both images

```bash
docker pull python:latest
docker pull cleanstart/python:latest
```

### Step 2 — Compare image sizes

```bash
docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" \
  | grep -E "python\s+latest|cleanstart/python"
```

Expected: stock 1.63 GB, cleanstart 125 MB (>90% smaller).

### Step 3 — Verify the default user (STIG V-257791)

```bash
# Stock image — runs as root (FAIL)
docker run --rm --entrypoint="" python:latest id

# Hardened image — runs as non-root (PASS)
docker run --rm cleanstart/python:latest -c "import os; print(f'uid={os.getuid()} gid={os.getgid()}')"
```

### Step 4 — Check for shells (STIG V-257777)

```bash
# Stock image — lists /bin/sh, /bin/bash, /bin/dash (FAIL)
docker run --rm --entrypoint="" python:latest sh -c "ls /bin/sh /bin/bash /bin/dash 2>/dev/null"

# Hardened image — empty list (PASS)
docker run --rm --entrypoint="" cleanstart/python:latest -c \
  "import shutil; print([s for s in ['sh','bash','ash','dash'] if shutil.which(s)])"
```

### Step 5 — Check for package managers

```bash
# Stock image — finds apt (FAIL)
docker run --rm --entrypoint="" python:latest sh -c "which apt apk yum dnf 2>/dev/null"

# Hardened image — empty list (PASS)
docker run --rm --entrypoint="" cleanstart/python:latest -c \
  "import shutil; print([p for p in ['apt','apk','yum','dnf'] if shutil.which(p)])"
```

### Step 6 — Scan for vulnerabilities

```bash
trivy image --quiet --format json --scanners vuln python:latest \
| jq '[.Results[]? | .Vulnerabilities[]?] | length'

trivy image --quiet --format json --scanners vuln cleanstart/python:latest \
| jq '[.Results[]? | .Vulnerabilities[]?] | length'```

Expected: stock has 1693 CVEs, cleanstart has 0.
```

### Step 7 — Generate an SBOM

```bash
trivy image --format cyclonedx --output sbom.json python:latest
trivy image --format cyclonedx --output sbom.json cleanstart/python:latest
```

### Step 8 — Run with all STIG-compliant runtime flags

```bash
docker run --rm \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --user 1000:102 \
  cleanstart/python:latest \
  -c "print('Running in hardened mode')"
```

| Flag | Satisfies |
|---|---|
| `--read-only` | STIG V-257792, CIS 5.12 |
| `--cap-drop=ALL` | STIG V-257789, CIS 5.3 |
| `--no-new-privileges` | CIS 5.25 |
| `--user 1000:102` | STIG V-257791, CIS 4.1 |

---

## Test 2: Kubernetes

### Cluster setup (kind)

```bash
Install kind

Install kubectl

# Create the cluster
kind create cluster --name stig-demo
kubectl cluster-info
```

### Deploy the hardened pod

```bash
kubectl apply -f k8s/hardened-deployment.yaml

# Wait for the pod to be ready
kubectl get pods -n stig-hardened -w
# Press Ctrl+C once you see Running
```

### Verify compliance

```bash
# Non-root user
kubectl exec -n stig-hardened deploy/hardened-python -- \
  python -c "import os; print(f'uid={os.getuid()} gid={os.getgid()}')"
# Expected: uid=1000 gid=102

# Read-only root filesystem
kubectl exec -n stig-hardened deploy/hardened-python -- \
  python -c "open('/test', 'w').write('x')"
# Expected: OSError: [Errno 30] Read-only file system

# No shell
kubectl exec -n stig-hardened deploy/hardened-python -- sh -c "echo hi"
# Expected: error — sh doesn't exist

# Inspect the effective security context
kubectl get pod -n stig-hardened -l app=hardened-python -o yaml \
  | grep -A 20 "securityContext:"
```

### Negative test — try to deploy an insecure pod

```bash
kubectl apply -f k8s/insecure-deployment.yaml
```

Expected output:

```
Warning: would violate PodSecurity "restricted:latest":
  allowPrivilegeEscalation != false,
  unrestricted capabilities,
  runAsNonRoot != true,
  seccompProfile not set to RuntimeDefault or Localhost
```

The deployment is created but its pods fail to schedule. **Kubernetes itself enforces STIG-style controls** — non-compliant workloads cannot run.

Clean it up:

```bash
kubectl delete -f k8s/insecure-deployment.yaml
```

### Optional — network policy

```bash
kubectl apply -f k8s/network-policy.yaml
```

Default-deny ingress and egress for the namespace. Maps to **NIST 800-53 SC-7** (boundary protection).

⚠️ kind's default CNI doesn't enforce NetworkPolicy. For real enforcement, install Calico or Cilium.

### Clean up

```bash
kind delete cluster --name stig-demo
```

### Kubernetes control mapping

| K8s Setting | STIG / CIS Reference |
|---|---|
| `runAsNonRoot: true` | STIG V-257791, CIS K8s 5.2.6 |
| `runAsUser` (non-zero) | STIG V-257791, CIS K8s 5.2.6 |
| `readOnlyRootFilesystem: true` | STIG V-257792, CIS K8s 5.2.5 |
| `allowPrivilegeEscalation: false` | CIS K8s 5.2.5 |
| `capabilities.drop: [ALL]` | STIG V-257789, CIS K8s 5.2.7 |
| `seccompProfile: RuntimeDefault` | CIS K8s 5.7.2 |
| `automountServiceAccountToken: false` | CIS K8s 5.1.6 |
| Pod Security Admission `restricted` | CIS K8s 5.2 family |
| NetworkPolicy default-deny | NIST 800-53 SC-7 |
| Resource limits set | STIG container DoS protection |

---

## Sample App on the Hardened Base

The `app/` folder has a tiny Flask app using `cleanstart/python:latest` as the base image.

### Build

```bash
docker build -t my-secure-app:latest -f app/Dockerfile app/
```

### Run with STIG-compliant flags

```bash
docker run --rm -d \
  --name my-secure-app \
  -p 8080:8080 \
  --read-only \
  --tmpfs /tmp \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --user 1000:102 \
  my-secure-app:latest
```

### Test

```bash
curl http://localhost:8080/health
curl http://localhost:8080/whoami   # proves the container runs as non-root
```

### Clean up

```bash
docker stop my-secure-app
```

---

## OpenSCAP

OpenSCAP is the DISA-endorsed scanner for STIG compliance, but it scans **host operating systems** — not distroless container images. The cleanstart image has no shell, no package database, and no `/etc` configs for OpenSCAP to introspect (that's the point — minimal attack surface).

In a real architecture, OpenSCAP covers the layers Trivy can't:

```
┌─────────────────────────────────────────────────┐
│  Pod (hardened-python)        ← securityContext │
│  Container image              ← Trivy           │
├─────────────────────────────────────────────────┤
│  Container runtime / Kubelet  ← OpenSCAP        │
│  Worker Node / Docker Host    ← OpenSCAP        │
└─────────────────────────────────────────────────┘
```

| Layer | Scanner |
|---|---|
| Container image content | Trivy |
| Container host / K8s nodes | OpenSCAP |
| Runtime behavior | Falco / Sysdig |

### Quick host scan on Ubuntu (incl. WSL)

```bash
sudo apt-get update
sudo apt-get install -y openscap-scanner ssg-debderived

sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_stig \
  --results scan-results.xml \
  --report scan-report.html \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml

# Open scan-report.html in a browser
```

### On RHEL / Fedora

```bash
sudo dnf install -y openscap-scanner scap-security-guide

sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_stig \
  --results scan-results.xml \
  --report scan-report.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

The report shows pass/fail for every STIG rule on your host — kernel hardening, sshd config, audit rules, file permissions, password policy, and more.

---

## Detailed STIG Control Mapping

### Container Platform STIG Controls

| STIG ID | Control | How `cleanstart/python:latest` Satisfies It |
|---|---|---|
| V-257777 | Unnecessary software must not be installed | Distroless; ~80 packages vs. ~610 |
| V-257780 | Security patches must be applied in a timely manner | Continuous daily rebuild |
| V-257789 | Containers must not be granted unnecessary capabilities | Runs cleanly with `--cap-drop=ALL` |
| V-257791 | Containers must not run as the root user | Default UID is 1000 (non-root) |
| V-257792 | Container root filesystem must be read-only where possible | Compatible with `--read-only` |
| V-257795 | Container images must be signed | Cosign/Sigstore signatures published |

### CIS Docker Benchmark

| CIS ID | Control | Status |
|---|---|---|
| 4.1 | Image should run as a non-root user | ✅ |
| 4.3 | Only install necessary packages | ✅ |
| 4.6 | HEALTHCHECK instructions | ⚠️ Add in your Dockerfile |
| 4.8 | setuid/setgid permissions removed | ✅ |
| 5.3 | Linux capabilities restricted | ✅ With `--cap-drop=ALL` |
| 5.12 | Root filesystem mounted read-only | ✅ With `--read-only` |
| 5.25 | No privilege acquisition | ✅ With `--security-opt=no-new-privileges` |
| 5.31 | Docker socket not mounted | ⚠️ Enforce at orchestration layer |

### NIST SP 800-53 / 800-171

| Family | Controls | Mapping |
|---|---|---|
| Access Control (AC) | AC-6 (least privilege) | Non-root by default |
| Configuration Management (CM) | CM-7 (least functionality) | Distroless; minimal packages |
| System & Information Integrity (SI) | SI-2, SI-7 | Continuous rebuilds; signed provenance |
| System & Communications Protection (SC) | SC-39 | Read-only rootfs, capability drop |
| Supply Chain Risk Management (SR) | SR-3, SR-4, SR-11 | SBOM; SLSA-aligned reproducible builds |

---

## What's Still Your Responsibility

The hardened base is a *starting point*, not the end of compliance. You're still responsible for:

1. **Your application code** — SAST/SCA scanning, secure coding practices
2. **Your dependencies** — `pip install` brings its own CVE surface; pin and scan
3. **Network policy** — ingress/egress restrictions, mTLS
4. **Secrets management** — never bake secrets into images
5. **Logging and audit** — tamper-resistant log storage
6. **Runtime detection** — Falco / Sysdig for anomaly detection
7. **Registry access control** — only pull signed images, only push from trusted CI

---
