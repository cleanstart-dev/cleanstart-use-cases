# OpenSCAP and STIG Compliance Architecture with `cleanstart/python:latest`

> A small, runnable demo of the difference between **"STIG compliance as a remediation task"** and **"STIG compliance as a property of the platform"** — built around `cleanstart/python:latest`, Kubernetes Pod Security Standards, and an OpenSCAP host scan that covers what the image alone can't.

---

## The problem and The vision

Most teams treat container compliance as cleanup work. Pull a base image, scan it, file the findings, patch what's broken, write up the report, repeat next quarter. The trouble is the work never ends — the same image carries new CVEs by next week, someone drops the `USER` directive in a refactor, a sidecar quietly runs as root, and the next audit catches the same things again.

A different approach is to make compliance a property of the stack itself. 

&rarr; The base image ships hardened before it ever runs. 

&rarr; The Kubernetes API server refuses to admit a pod that isn't compliant. 

&rarr; The host gets scanned on a schedule with a tool auditors actually accept. 

Nothing in the pipeline gives you a way to express the insecure state — so staying compliant becomes easier than drifting out of it.

This repo demonstrates that mindset across three layers: the image, the workload, and the host.

## What "architectural" means here, concretely

| Layer | Checklist approach | Architectural approach |
|---|---|---|
| Base image | "remember to harden Python" | `FROM cleanstart/python:latest` — distroless, non-root, signed, zero HIGH/CRITICAL CVEs |
| Shell access | "audit for unused shells" | No shell in the image — nothing to pivot from |
| Root user | "remember the USER directive" | UID 1000 by default; root isn't an option |
| Pod admission | "review YAML manually" | Pod Security Standard `restricted` rejects insecure pods at the API server |
| Runtime writes | "monitor for tampering" | `readOnlyRootFilesystem: true` makes them impossible |
| Capabilities | "remember to drop caps" | `capabilities.drop: [ALL]`, `allowPrivilegeEscalation: false` |
| CVE scanning | "scan everytime" | Trivy on every build; image rebuilt daily upstream |
| Host hardening | "manually configured" | OpenSCAP XCCDF scan against the official STIG profile |
| Evidence for auditors | "spreadsheet of findings" | Signed SBOM + cosign attestation + OpenSCAP report |

## Prerequisites

- **Docker** required for both paths
- **Trivy** for CVE scanning
- **kind** + **kubectl** for the Kubernetes path
- **OpenSCAP** (`oscap`) for the host scan

---

## Run it locally

### 1. Compare the two images

Same Python. Two starting points.

```bash
docker pull python:latest
docker pull cleanstart/python:latest

docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" \
  | grep -E "python\s+latest|cleanstart/python"
```

Expected: stock is 1.63 GB, cleanstart is 125 MB.

### 2. Check user, shell, package manager

```bash
# Stock — runs as root, has shells, has apt (FAIL on three controls)
docker run --rm --entrypoint="" python:latest id
docker run --rm --entrypoint="" python:latest sh -c "ls /bin/sh /bin/bash /bin/dash 2>/dev/null"
docker run --rm --entrypoint="" python:latest sh -c "which apt apk yum dnf 2>/dev/null"

# Hardened — UID 1000, no shells, no package managers
docker run --rm cleanstart/python:latest -c "import os; print(f'uid={os.getuid()} gid={os.getgid()}')"
docker run --rm cleanstart/python:latest -c \
  "import shutil; print([s for s in ['sh','bash','ash','dash'] if shutil.which(s)])"
docker run --rm cleanstart/python:latest -c \
  "import shutil; print([p for p in ['apt','apk','yum','dnf'] if shutil.which(p)])"
```

You can't pivot through a shell that doesn't exist. You can't escalate through an `apt` that isn't there.

### 3. Scan for CVEs

```bash
trivy image --quiet --format json --scanners vuln python:latest \
  | jq '[.Results[]? | .Vulnerabilities[]?] | length'

trivy image --quiet --format json --scanners vuln cleanstart/python:latest \
  | jq '[.Results[]? | .Vulnerabilities[]?] | length'
```

Stock returns 1,693 CVEs. Cleanstart returns 0. You can't be vulnerable to a CVE in a library that isn't installed.

### 4. Run with all STIG-compliant flags

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

### 5. The Kubernetes gate

```bash
kind create cluster --name stig-demo
kubectl apply -f k8s/hardened-deployment.yaml   # admitted, runs cleanly
kubectl apply -f k8s/insecure-deployment.yaml   # rejected by the API server
```

The insecure deploy is created but its pods can't schedule:

```
Warning: would violate PodSecurity "restricted:latest":
  allowPrivilegeEscalation != false,
  unrestricted capabilities,
  runAsNonRoot != true,
  seccompProfile not set to RuntimeDefault or Localhost
```

This isn't a linter telling you to fix things. It's the platform refusing to run them.

Verify the hardened pod:

```bash
kubectl exec -n stig-hardened deploy/hardened-python -- \
  python -c "import os; print(f'uid={os.getuid()} gid={os.getgid()}')"
# uid=1000 gid=102

kubectl exec -n stig-hardened deploy/hardened-python -- \
  python -c "open('/test','w').write('x')"
# OSError: [Errno 30] Read-only file system

kubectl exec -n stig-hardened deploy/hardened-python -- sh -c "echo hi"
# error: sh doesn't exist
```

Clean up:

```bash
kind delete cluster --name stig-demo
```

### 6. Scan the host with OpenSCAP

The image and Pod Security cover the container layer. OpenSCAP covers the layer underneath — the worker node, the kernel config, sshd, audit rules, file permissions.

```bash
# Ubuntu / WSL
sudo apt-get install -y openscap-scanner ssg-debderived
sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_stig \
  --results scan-results.xml \
  --report scan-report.html \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml

# RHEL / Fedora
sudo dnf install -y openscap-scanner scap-security-guide
sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_stig \
  --results scan-results.xml \
  --report scan-report.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

`scan-report.html` is the evidence format auditors actually accept — rule-level pass/fail, severity, and auto-generated remediation, in the XCCDF schema DISA publishes STIGs in.

---

## How the layers cover each other

```
┌─────────────────────────────────────────────────┐
│  Pod                          ← Pod Security    │
│  Container image              ← Trivy + Cleanstart base │
├─────────────────────────────────────────────────┤
│  Container runtime / Kubelet  ← OpenSCAP        │
│  Worker node / Host OS        ← OpenSCAP        │
└─────────────────────────────────────────────────┘
```

| Layer | Tool | What it enforces |
|---|---|---|
| Container image | Cleanstart base + Trivy | Hardened content, zero HIGH/CRITICAL CVEs, signed provenance |
| Workload | Pod Security `restricted` | Non-root, read-only rootfs, dropped caps, seccomp profile |
| Host / node | OpenSCAP | Kernel hardening, sshd, audit rules, file permissions, password policy |
| Runtime behavior | Falco / Sysdig | Anomaly detection |

---

## Mapping to STIG / CIS / NIST

### Container Platform STIG

| STIG ID | Control | How this stack satisfies it |
|---|---|---|
| V-257777 | Unnecessary software must not be installed | Distroless base; ~80 packages vs. ~610 |
| V-257780 | Security patches applied in a timely manner | Continuous daily rebuild |
| V-257789 | Containers must not be granted unnecessary capabilities | `cap-drop: ALL` enforced by Pod Security |
| V-257791 | Containers must not run as root | Default UID 1000 in image; `runAsNonRoot: true` in pod |
| V-257792 | Container root filesystem must be read-only | `readOnlyRootFilesystem: true` |
| V-257795 | Container images must be signed | Cosign / Sigstore signatures published |

### CIS Docker Benchmark

| CIS ID | Control | Status |
|---|---|---|
| 4.1 | Image runs as a non-root user | ✅ |
| 4.3 | Only necessary packages installed | ✅ |
| 4.8 | setuid/setgid permissions removed | ✅ |
| 5.3 | Linux capabilities restricted | ✅ |
| 5.12 | Root filesystem mounted read-only | ✅ |
| 5.25 | No privilege acquisition | ✅ |

### NIST SP 800-53 / 800-171

| Family | Controls | How it maps |
|---|---|---|
| Access Control (AC) | AC-6 | Non-root by default |
| Configuration Management (CM) | CM-7 | Distroless, least functionality |
| System & Information Integrity (SI) | SI-2, SI-7 | Daily rebuilds, signed provenance |
| System & Communications Protection (SC) | SC-39 | Read-only rootfs, capability drop |
| Supply Chain Risk Management (SR) | SR-3, SR-4, SR-11 | SBOM, SLSA-aligned reproducible builds |

---

## What's still your responsibility

The architecture covers image, workload, and host. The remaining layers are still yours:

1. **Application code** — SAST/SCA on every PR
2. **Python dependencies** — `pip install` brings its own CVE surface; pin and scan
3. **Network policy** — ingress/egress restrictions, mTLS
4. **Secrets management** — never bake secrets into images
5. **Runtime detection** — Falco / Sysdig for anomalies
6. **Registry access** — only pull signed images, only push from trusted CI

---

The Cleanstart base is the foundation. Pod Security Standards are the workload gate. OpenSCAP is the host scan. 
This platform enforces the rules, not a checklist someone has to remember.