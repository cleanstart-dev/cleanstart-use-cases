# Migrating from Alpine, Ubuntu, and BusyBox to `cleanstart/python:latest`

> A small, runnable demo of the difference between **"securing a public base image"** and **"starting from a base that is already secure"** — built around the same Python app running in four different containers.

---

## The problem and the vision

Most teams pick a base image for convenience and then spend time hardening it. Pull `python:alpine`, strip the shell, add a `USER` directive, scan for CVEs, patch what's broken, repeat next quarter. The trouble is the work never ends — Alpine ships a new CVE by next week, someone removes the `USER` directive in a refactor, and the next audit catches the same things again.

A different approach is to start from a base where there is nothing to harden.

&rarr; The image ships with no shell — there is nothing to exec into.

&rarr; The image ships with no package manager — there is nothing to install post-breach.

&rarr; The image runs as a non-root user by default — escalation requires escaping the runtime itself.

&rarr; The image is signed and ships with an SBOM — the supply chain is verifiable, not assumed.

This repo makes that difference concrete. Same app. Same port. Four base images. One comparison script.

---

## What changes, and why it matters

| | Ubuntu 26.04 | python:3.14.5-alpine | BusyBox:1.38.0 | `cleanstart/python:latest` |
|---|:---:|:---:|:---:|:---:|
| No shell | ✗ | ✗ | ✗ | ✓ |
| No package manager | ✗ | ✗ | — | ✓ |
| Non-root by default | ✗ | ✗ | ✗ | ✓ |
| Signed + SBOM | ✗ | ✗ | ✗ | ✓ |
| ~0 CVEs | ✗ | ✗ | ✗ | ✓ |

BusyBox has no package manager, but it ships a shell with 300+ Unix utilities baked into a single binary. Removing `apt` is not the same as removing the attack surface.

---

## What's inside

```
cleanstart-demo/
├── app.py                  # Same Python app — runs identically in every image
├── Dockerfile.ubuntu       # Before: ubuntu:26.04
├── Dockerfile.alpine       # Before: python:3.14.5-alpine
├── Dockerfile.busybox      # Before: busybox:1.38.0
├── Dockerfile.cleanstart   # After:  cleanstart/python:latest
├── compare.sh              # Build all four and compare them across five dimensions
└── README.md
```

The application code never changes. Only the base image does. That is the point.

---

## Run it

```bash
bash compare.sh
```

Requires Docker only. The script builds all four images and runs five checks on each.

---

## The five checks

### 1. Image size

A larger image means more packages bundled into the filesystem. More packages means more CVE surface — libraries your app never calls, binaries that exist only to be exploited.

| Image | Typical Size |
|---|---|
| Ubuntu 26.04 | ~55 MB |
| python:3.14.5-alpine | ~20 MB |
| BusyBox:1.38.0 | ~40 MB |
| **cleanstart/python** | **~30 MB** |

CleanStart is comparable in size to Alpine. The difference is what's inside — only the Python runtime, nothing else.

---

### 2. Shell access

A shell is the first thing an attacker reaches for after exploiting a vulnerability in your application. With a shell, they can read environment variables, traverse the filesystem, exfiltrate credentials, and pivot to other services.

```bash
# What an attacker runs the moment they have code execution in your container:
docker exec -it <container> sh
```

| Image | Shell present? |
|---|---|
| Ubuntu 26.04 | ✗ bash + sh at `/usr/bin/sh` |
| python:3.14.5-alpine | ✗ sh at `/bin/sh` |
| BusyBox:1.38.0 | ✗ sh via busybox binary |
| **cleanstart/python** | **✓ `/bin/sh` does not exist** |

You cannot exec into a shell that isn't there.

---

### 3. Package manager

If `apt` or `apk` is reachable inside a running container, an attacker with shell access can install a full toolkit — network scanners, reverse shells, exfiltration tools — without ever touching the host.

```bash
# From inside a breached Alpine container:
apk add nmap curl netcat-openbsd
# → the container is now a lateral movement platform
```

| Image | Package manager |
|---|---|
| Ubuntu 26.04 | ✗ apt-get at `/usr/bin/apt-get` |
| python:3.14.5-alpine | ✗ apk at `/sbin/apk` |
| BusyBox:1.38.0 | — none, but shell is still present |
| **cleanstart/python** | **✓ none** |

---

### 4. Running user

A process running as `root` inside a container means a code execution vulnerability in your app is one kernel exploit away from root on the host. Non-root containers break that escalation path at the workload level.

```bash
# Verify the running user for each image:
docker run --rm --entrypoint="" demo-ubuntu    sh -c "id"
docker run --rm --entrypoint="" demo-alpine    sh -c "id"
docker run --rm --entrypoint="" demo-busybox   sh -c "id"

# CleanStart — no shell; verify via Python directly:
docker run --rm demo-cleanstart -c "import os; print(f'uid={os.getuid()}')"
```

| Image | Default user |
|---|---|
| Ubuntu 26.04 | ✗ root (uid=0) |
| python:3.14.5-alpine | ✗ root (uid=0) |
| BusyBox:1.38.0 | ✗ root (uid=0) |
| **cleanstart/python** | **✓ nonroot (uid=65532)** |

---

### 5. Image layers

Each layer in an image represents a set of filesystem changes — packages installed, files added, binaries pulled in. Fewer layers from a minimal base means less bundled software and a proportionally smaller CVE surface.

```bash
# Inspect layer count for any image:
docker image inspect demo-ubuntu --format='{{len .RootFS.Layers}}'
docker image inspect demo-cleanstart --format='{{len .RootFS.Layers}}'
```

| Image | Typical layers |
|---|---|
| Ubuntu 26.04 | 5–7 |
| python:3.14.5-alpine | 6–9 |
| BusyBox:1.38.0 | 5–8 |
| **cleanstart/python** | **3–6** |

For a full CVE breakdown, run Trivy separately against any image:

```bash
trivy image --severity HIGH,CRITICAL demo-ubuntu
trivy image --severity HIGH,CRITICAL demo-alpine
trivy image --severity HIGH,CRITICAL demo-cleanstart
```

| Image | Typical CVEs (HIGH + CRITICAL) |
|---|---|
| Ubuntu 26.04 | 50–100 |
| python:3.14.5-alpine | 20–40 |
| BusyBox:1.38.0 | 10–20 |
| **cleanstart/python** | **~0** |

---

## How to migrate

Replace one line. Everything else in your Dockerfile stays exactly the same.

### Before

```dockerfile
FROM python:3.14.5-alpine

WORKDIR /app
COPY app.py .

EXPOSE 3000
CMD ["python", "app.py"]
```

### After

```dockerfile
FROM cleanstart/python:latest   # ← only this line changes

WORKDIR /app
COPY app.py .

EXPOSE 3000
CMD ["python", "app.py"]
```

### Migration checklist

| Step | What to do | Why |
|---|---|---|
| **1** | Replace `FROM <public-image>` with `FROM cleanstart/python:latest` | Swaps the base — everything else stays the same |
| **2** | Ensure `CMD` uses array form: `["python", "app.py"]` | No shell to parse string form — but you're likely already doing this |
| **3** | Remove any `RUN` commands that call `sh` or `bash` directly | No shell available — use Python scripts instead |
| **4** | Remove health checks that rely on `curl` or shell scripts | Rewrite as a Python HTTP check or use Docker's exec health check |

---

## What CleanStart gives you out of the box

| Feature | Alpine | Ubuntu | CleanStart |
|---|:---:|:---:|:---:|
| No shell | ✗ | ✗ | ✓ |
| No package manager | ✗ | ✗ | ✓ |
| Non-root by default | ✗ | ✗ | ✓ |
| Read-only filesystem compatible | ✗ | ✗ | ✓ |
| Signed image (Sigstore/cosign) | ✗ | ✗ | ✓ |
| SBOM included | ✗ | ✗ | ✓ |
| CIS Docker Benchmark compliant | ✗ | ✗ | ✓ |
| ~0 CVEs | ✗ | ✗ | ✓ |

These are not hardening steps you apply after pulling the image. They are properties of the image itself.

---

## What's still your responsibility

CleanStart removes the OS bloat and the attack surface that comes with it. The remaining layers are still yours:

1. **Application code** — SAST/SCA on every PR
2. **Python dependencies** — `pip install` brings its own CVE surface; pin versions and scan
3. **Secrets** — never bake credentials into images; use a secrets manager
4. **Network policy** — restrict ingress and egress at the cluster level
5. **Runtime detection** — Falco or equivalent for anomaly detection post-deployment

---

## CVE scanning with Trivy (optional)

`compare.sh` requires only Docker. For a full CVE breakdown, install Trivy and run it separately:

```bash
# macOS
brew install trivy

# Linux
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sh -s -- -b /usr/local/bin
```

```bash
trivy image --severity HIGH,CRITICAL demo-ubuntu
trivy image --severity HIGH,CRITICAL demo-alpine
trivy image --severity HIGH,CRITICAL demo-cleanstart
```

---

## Further reading

- [CleanStart Python Image](https://hub.docker.com/r/cleanstart/python)
- [Trivy vulnerability scanner](https://aquasecurity.github.io/trivy/)
- [Docker security best practices](https://docs.docker.com/develop/security-best-practices/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [SLSA supply chain framework](https://slsa.dev/)

---

The CleanStart base is the foundation. Hardening is not a step you perform on top of it — it is already done.
