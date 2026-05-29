# Debugging Hardened Images Without Shell Access

Hardened container images strip out shells, package managers, and debug tools to reduce attack surface. Great for security — painful when something breaks at 2 AM. This use case shows **3 practical techniques** to debug them, with real command outputs you can verify yourself.

---

## The Problem

Modern container security pushes teams toward hardened, distroless, or minimal base images. The trade-off shows up the first time something breaks in production:

```bash
$ kubectl exec -it my-pod -- sh
error: Internal error occurred: error executing command in container:
failed to exec in container: starting container process caused:
exec: "sh": executable file not found in $PATH
```

Or with Docker directly:

```bash
$ docker run --rm --entrypoint sh <hardened-image>
docker: Error response from daemon: failed to create task for container:
failed to create shim task: OCI runtime create failed: runc create failed:
unable to start container process: error during container init:
exec: "sh": executable file not found in $PATH: unknown
```

No shell. No `ps`, `curl`, `netstat`, or `cat`. The image is working exactly as designed — now you need to debug without breaking that guarantee.

---

## What "Hardened" Actually Means Inside a Container

Most teams don't realize how minimal a hardened image is until they're staring at a broken production pod with no shell. Here's a like-for-like comparison between a stock Ubuntu base and a hardened base image — verified locally with Docker (commands in the "Verify It Yourself" section below):

| Metric | Stock Ubuntu 22.04 | Hardened base (example: `cleanstart/glibc:latest`) |
|---|---|---|
| Executables in `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin` | 366 | **13** (glibc runtime only) |
| Shell (`sh`, `bash`) present | ✅ `bash` | ❌ none |
| Package manager (`apt`, `dpkg`) | ✅ present | ❌ none |
| Debugging tools (`ps`, `netstat`, `curl`, `cat`) | ✅ present | ❌ none |
| Default user | `root` (uid 0) | non-root (uid 1000) |
| Login shell for default user | `/bin/bash` | `/sbin/nologin` |
| Image size on disk | 78.1 MB | **44.9 MB** |

The 13 binaries that remain in this example are **glibc runtime utilities** (`ldd`, `iconv`, `locale`, `getent`, `localedef`, `tzselect`, etc.) — essential library functions, not interactive tools. Zero shells, zero package managers, zero debug utilities. The default user can't even log in interactively (`/sbin/nologin`).

That's the design — and why you need a different debugging strategy.

---

## Prerequisites

- **Docker 20.10+** — for Techniques 1 and 2
- **Kubernetes 1.25+** — for Technique 3 (`kubectl debug` requires 1.25+)
- A running hardened container or pod (see `scripts/00-demo-pod.yaml` to spin one up)

---

## Three Techniques

### 1. `kubectl debug` — Ephemeral Debug Container

Attach a debug sidecar that shares the target's process namespace. The hardened container stays untouched — you bring tools to it, temporarily.

> **Requires a running Kubernetes cluster.** Deploy `scripts/00-demo-pod.yaml` first.

```bash
# First — confirm the shell exec fails (expected output)
$ kubectl exec -it hardened-app -c app -- sh
error: Internal error occurred: exec: "sh": executable file not found in $PATH

# Solution — attach an ephemeral busybox alongside it
$ kubectl debug -it hardened-app --image=busybox --target=app
Defaulting debug container name to debugger-xk9p2.
If you don't see a command prompt, try pressing enter.
/ #
```

Inside the debug container (expected output):

```bash
/ # ps -ef
PID   USER     TIME  COMMAND
    1 1000      0:00 /app/server          # hardened app (non-root, uid 1000)
   12 root      0:00 sh                   # debug container's shell

/ # ls /proc/1/root/app/
config.yaml  server

/ # netstat -tulpn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address  Foreign Address  State   PID/Program
tcp        0      0 0.0.0.0:8080   0.0.0.0:*        LISTEN  1/server
```

The debug container is ephemeral — it disappears when you exit. The hardened app never changes.

See [`scripts/01-kubectl-debug.sh`](scripts/01-kubectl-debug.sh).

---

### 2. `docker cp` — Pull Files Out Without Going In

No shell needed to read a file. `docker cp` works directly against the container's filesystem from the host.

```bash
# This fails — no shell, no cat inside the container
$ docker exec hardened-app cat /app/config.yaml
OCI runtime exec failed: exec failed: unable to start container process:
exec: "cat": executable file not found in $PATH

# This works — copy the file out, inspect on host
$ docker cp hardened-app:/app/config.yaml ./config.yaml
$ cat ./config.yaml
port: 8080
log_level: info

# Same for logs — common 2 AM use case
$ docker cp hardened-app:/var/log/app.log ./app.log
$ tail ./app.log
2026-05-28 02:14:33 ERROR connection refused: db:5432
```

**Verified against a hardened image** — `docker cp` works even when the container has zero interactive tools inside:

```bash
# Hardened images often have no default CMD/ENTRYPOINT — pass a dummy command so docker create works
$ docker create --name temp cleanstart/glibc:latest /nonexistent
399cbfb731ca120d049dbff2b0125db3e542a7adb92889170cda3430bf2a0f74

# Extract a real glibc binary from the running container
$ docker cp temp:/usr/bin/ldd ./ldd-extracted
$ ls -la ./ldd-extracted
-rwxr-xr-x  1 user user  5412  May 27 09:54 ./ldd-extracted

$ docker rm temp
```

You just pulled a binary out of a running hardened container without ever opening a shell inside it.

See [`scripts/02-docker-cp.sh`](scripts/02-docker-cp.sh).

---

### 3. Sidecar Pattern — Bake Debug Access Into the Deployment

> **Requires a running Kubernetes cluster.**
> **⚠️ Production note:** `shareProcessNamespace: true` weakens container isolation — the debug sidecar can read the app's memory, files via `/proc/1/root/`, and send signals. Use freely in staging; in production, gate it behind a feature flag or apply only when actively debugging.

For repeatable debugging needs, add a dormant debug sidecar to your Pod spec. It shares the app's process namespace and is always ready — no `kubectl debug` needed at 2 AM.

```yaml
# scripts/03-sidecar.yaml
spec:
  shareProcessNamespace: true
  containers:
    - name: app
      image: <your-hardened-image>
    - name: debug
      image: busybox:1.36
      command: ["sleep", "infinity"]
```

Then debug any time:

```bash
$ kubectl exec -it hardened-app -c debug -- sh
/ # ps -ef
PID   USER     TIME  COMMAND
    1 1000      0:00 /app/server          # hardened app
    8 root      0:00 sleep infinity       # debug sidecar idle
   12 root      0:00 sh                   # your shell in debug sidecar

/ # ls /proc/1/root/app/
config.yaml  server
```

See [`scripts/03-sidecar.yaml`](scripts/03-sidecar.yaml).

---

## Quick Comparison

| Technique | When to use | Requires cluster? | Persists? |
|---|---|---|---|
| `kubectl debug` | Live incident, one-off investigation | Yes (k8s 1.25+) | No — ephemeral |
| `docker cp` | Pull logs, configs, binaries | No — Docker only | No |
| Sidecar | Recurring debugging, staging envs | Yes | Yes — in spec |

---

## Reproduce It Yourself

**Step 1 — Start a demo hardened pod:**

```bash
kubectl apply -f scripts/00-demo-pod.yaml
kubectl wait --for=condition=Ready pod/hardened-app --timeout=60s
```

**Step 2 — Run the techniques:**

```bash
bash scripts/01-kubectl-debug.sh           # kubectl debug demo
bash scripts/02-docker-cp.sh               # docker cp demo
kubectl apply -f scripts/03-sidecar.yaml   # sidecar pattern
```

---

## What's in This Repo

```
├── scripts/
│   ├── 00-demo-pod.yaml      deploy a hardened pod to test against
│   ├── 01-kubectl-debug.sh   Technique 1 — ephemeral debug container
│   ├── 02-docker-cp.sh       Technique 2 — extract files without a shell
│   └── 03-sidecar.yaml       Technique 3 — dormant debug sidecar
```

---

## Verify the Hardening Yourself

Don't trust the comparison table — reproduce every number with these commands. We used `cleanstart/glibc:latest` as the hardened-image example here; the same commands work against any hardened or distroless base.

```bash
# Pull a hardened base image
docker pull cleanstart/glibc:latest

# 1. Confirm image size (claim: 44.9 MB)
docker images cleanstart/glibc:latest
# REPOSITORY         TAG      IMAGE ID       SIZE
# cleanstart/glibc   latest   64b634b4f8dd   44.9MB

# 2. Confirm default user is non-root (claim: uid 1000)
docker inspect cleanstart/glibc:latest --format='{{.Config.User}}'
# clnstrt
docker run --rm --user clnstrt cleanstart/glibc:latest /usr/bin/getent passwd clnstrt
# clnstrt:x:1000:102:Linux User,,,:/home/clnstrt:/sbin/nologin
# Note: /sbin/nologin = no interactive login, even if a shell existed

# 3. Count executables (claim: 13)
docker create --name inspect cleanstart/glibc:latest /nonexistent
docker export inspect | tar -tv | grep -E "^-rwx" | grep -E "(usr/bin/|usr/sbin/)" | wc -l
# 13

# 4. List what those 13 binaries actually are
docker export inspect | tar -tv | grep -E "^-rwx" | grep -E "(usr/bin/|usr/sbin/)"
# c_rehash, getconf, getent, iconv, ldd, ldd.glibc, locale, localedef,
# scanelf, ssl_client, tzselect, nscd, update-ca-certificates
# All glibc runtime utilities — no shell, no apt, no debug tools.
docker rm inspect

# 5. Confirm sh doesn't exist (claim: shell exec fails)
docker run --rm --entrypoint sh cleanstart/glibc:latest
# docker: Error response from daemon: ... exec: "sh": executable file not found in $PATH

# 6. Compare with stock Ubuntu 22.04 (claim: 366 binaries, 78.1 MB)
docker pull ubuntu:22.04
docker images ubuntu:22.04
# ubuntu  22.04  86f1a8d7b38e  78.1MB
docker create --name inspect-ubu ubuntu:22.04
docker export inspect-ubu | tar -tv | grep -E "^-rwx" | grep -E "(usr/bin/|usr/sbin/|^bin/|^sbin/)" | wc -l
# 366
docker rm inspect-ubu
```

Every number in the comparison table above was produced by these exact commands. Run them against any hardened image of your choice and the techniques in this repo will apply the same way.

---

## Common Pitfalls

**`kubectl debug` not working?**
Check your Kubernetes version — ephemeral containers require 1.25+.

```bash
kubectl version --short
```

**`shareProcessNamespace: true` blocked by policy?**
Some clusters restrict this via PodSecurityPolicy or OPA. Check with your platform team before adding it to production specs. In staging it's generally safe.

**`docker cp` returns "no such file"?**
The file path may not exist in the hardened image. Use `docker export` to browse the full filesystem:

```bash
docker export my-container | tar -tv | grep config
```

**`docker create` fails with "no command specified"?**
Some hardened images have no default `CMD` or `ENTRYPOINT`. Pass any dummy command — `docker create --name temp <image> /nonexistent` works fine; you're not going to run it, just create the container to copy files from.

---

## Key Insight

**Hardened images don't make debugging impossible — they make it deliberate.**

The instinct when you see `sh: not found` is to add bash back. "Just for now." That instinct is exactly what attackers rely on.

Instead of every container shipping with `sh` "just in case," you bring tools when you need them.

In the example above: **366 interactive binaries reduced to 13 glibc runtime utilities.** Zero shells, debug tools, or package managers. The default user can't even log in. Same debuggability via the techniques above. Drastically smaller attack surface.

This is the trade-off worth making — once you have the debugging playbook for it.

---

*Part of a series on hardened container images. Example image used here: [`cleanstart/glibc`](https://hub.docker.com/u/cleanstart). The techniques apply to any hardened or distroless base.*