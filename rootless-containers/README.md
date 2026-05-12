# Rootless Containers: Security Theater or Real Protection?

> **CleanStart Use Case** — A 5-minute experiment proving what rootless containers protect against, what they don't, and why CleanStart closes both gaps.

---

## The Short Answer

**Both — and that is the trap.**

Rootless containers provide **real protection** against one specific class of attacks: privilege escalation and container-to-host escape.

Rootless containers provide **zero protection** against the much larger class of attacks that breach production systems today: CVEs in the base image, vulnerable libraries your app loads, and "living off the land" attacks using `bash`, `gcc`, `curl` — tools that ship in your image whether you run as root or not.

This repo proves both halves with verified Trivy scan output.

---

## The Result, in One Table

> Verified Trivy scan · same Python application · May 2026

| Image | UID | Critical CVEs | Attack tools | Trivy detection |
|---|---|---|---|---|
| `python:3.14` + `USER appuser` | 10001 | CVE-2026-6100, CVE-2026-1299, CVE-2025-8194, CVE-2025-13836, CVE-2025-15366, CVE-2025-15367, and more | bash, sh, apt, gcc, curl, wget all PRESENT | Full Debian fingerprint detected |
| **`cleanstart/python:latest`** | 65532 | **None scannable** | **All ABSENT** | **No target, no type, no surface** |

The rootless image gives you a non-root UID. Nothing else. Same CVEs as the root version, same attack toolchain.

The CleanStart image gives you non-root **plus** no scannable surface — Trivy literally could not identify a target, type, or package database to scan.

---

## What Rootless DOES Protect Against (real wins)

1. **Container escape via privileged kernel operations.** A UID 0 process can attempt `mount`, `modprobe`, write to `/proc/sysrq-trigger`, or exploit kernel CVEs requiring capabilities. A non-root UID cannot.
2. **Reduced damage from capability leaks.** Misconfigured runtimes (`--privileged`, bind mounts) are far more dangerous when the in-container process is root.
3. **Filesystem protection inside the container.** Non-root cannot modify `/etc`, `/usr/bin`, or runtime libraries.

If your threat model is "attacker pwns my app and tries to escalate to host root," rootless is doing real work. **Not theater.**

---

## What Rootless Does NOT Protect Against

1. **CVEs in the base image.** Trivy does not care who runs the binary — it cares whether the binary is present. The rootless image in our test exposed CVE-2026-6100 (arbitrary code execution in Python), CVE-2026-1299 (email header injection), CVE-2025-8194 (Python infinite loop), and more — all available to UID 10001 just as to root.
2. **Application-level vulnerabilities.** SQL injection, RCE in a dependency, deserialization bugs — these run at *your app's* UID. Root not required.
3. **Data exfiltration.** Your rootless container still has `curl`, `wget`, `python -c "urllib..."`. Outbound HTTPS works fine as UID 10001.
4. **Living-off-the-land attacks.** `bash`, `gcc`, `apt` — all still in the rootless image. An attacker has a full Unix toolchain. None of it needs root.
5. **Supply-chain compromise.** A malicious version of `requests` does whatever it wants at the application UID.
6. **User-namespace CVEs themselves.** Multiple 2025–2026 CVEs exploited user namespaces to gain admin capabilities. The "rootless" mechanism itself is now an attack surface.

---

## The Experiment

Two Dockerfiles, same demo app:

```
Dockerfile.rootless    — python:3.14 + USER appuser (UID 10001)
Dockerfile.cleanstart  — cleanstart/python + USER 65532
```

Run all three tests:

```bash
git clone https://github.com/cleanstart-dev/cleanstart-use-cases.git
cd cleanstart-use-cases/rootless-containers

chmod +x run.sh
./run.sh
```

You will see:

- **Test 1:** UID inside each container (10001 vs 65532) — both non-root
- **Test 2:** Dangerous binaries — rootless = all PRESENT, CleanStart = all ABSENT
- **Test 3:** CVE scan — rootless exposes critical Python CVEs, CleanStart returns no scannable surface

---

## The Trivy Output That Tells the Story

**Rootless image scan (excerpt):**

```
python3.13-minimal | CVE-2025-8194    | Cpython infinite loop when parsing a tarfile
                   | CVE-2025-13836   | Excessive read buffering DoS in http.client
                   | CVE-2025-15366   | IMAP command injection
                   | CVE-2025-15367   | POP3 command injection
                   | CVE-2026-1299    | email header injection due to unquoted newlines
                   | CVE-2026-6100    | Arbitrary code execution via use-after-free in decompression
```

**CleanStart image scan:**

```
┌────────┬──────┬─────────────────┬─────────┐
│ Target │ Type │ Vulnerabilities │ Secrets │
├────────┼──────┼─────────────────┼─────────┤
│   -    │  -   │        -        │    -    │
└────────┴──────┴─────────────────┴─────────┘
```

Trivy could not identify a target, a type, vulnerabilities, or secrets. Every field returned `-`. This is what "no scannable surface" looks like.

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
| Exploit known base CVEs | CVE-2026-6100 and more | **no scannable CVEs** |
| Fingerprint OS for recon | Debian fully detected | **Trivy returns `-`** |

The `-` result is unique. Trivy itself cannot identify an OS, package database, or libraries to scan. An attacker landing in this container has:

- No shell to execute commands in
- No compiler to build exploits with
- No package manager to pull tools from
- No CVE-bearing libraries that scanners (or attackers) can find
- No OS fingerprint to plan an attack against
- And — through `USER 65532` — no root privileges either

This is what defense in depth **at the image layer** actually looks like. Rootless is one control. CleanStart provides the others *in the same image*.

---

## The Correct Mental Model

> **Rootless alone** = "if attacker gets in, they cannot become root"
>
> **CleanStart** = "if attacker gets in, there is nothing to run, nothing to exploit, no surface to scan, and they are not root anyway"

Rootless is a single layer of defense. CleanStart provides image-layer defenses (no toolchain, no scannable surface) *plus* the rootless layer — in one base image.

---

## What Good Looks Like in Practice

```dockerfile
FROM cleanstart/python:latest
WORKDIR /app
COPY app.py .
USER 65532
CMD ["app.py"]
```

```yaml
# Kubernetes pod spec — runtime controls that compose with the image
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
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
├── Dockerfile.cleanstart  # cleanstart/python + USER 65532
├── app.py                 # Demo app that prints UID/GID
└── run.sh                 # Build + 3 comparison tests
```

---

## Key Takeaways

1. **Rootless is real protection — for a specific threat model.** It blocks privileged escape. Not theater.
2. **Rootless does not reduce CVEs.** `python:3.14` ships with CVE-2026-6100, CVE-2025-8194, and more. Adding `USER appuser` removes none of them.
3. **Rootless does not remove your attack toolchain.** Same `bash`, `gcc`, `curl` as a root container.
4. **CleanStart removes the entire scannable surface.** Trivy returned `-` for target, type, vulnerabilities, and secrets.
5. **If you can only do one thing, switch base image.** CleanStart gives you both layers in one move.

---

> **Don't just read about container security — see the results yourself.**
>
> `git clone https://github.com/cleanstart-dev/cleanstart-use-cases.git`
