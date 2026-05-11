# CIS Hardening Beyond Checklists

> A small, runnable demo of the difference between **"hardening as a checklist"** and **"hardening as an architectural property"** — built around a hardened Nginx image (`cleanstart/nginx`), policy-as-code, and a CI gate that makes insecure Dockerfiles impossible to merge.

---

## The idea

Most teams treat CIS Benchmarks like a quarterly to-do list: scan the environment, fix findings, file the report, repeat. The trouble is the fixes silently rot — someone tweaks a config, drops a `:latest` tag, opens a port, and the next audit catches the same things again.

A different approach is to make the *architecture itself* enforce the rules. A non-compliant configuration shouldn't reach production because the pipeline won't let it, and the runtime environment shouldn't be capable of expressing the insecure state in the first place. This repo demonstrates that mindset on the smallest possible surface — one web server.


## What "architectural" means here, concretely

| Layer | Checklist approach | Architectural approach (this repo) |
|---|---|---|
| Base image | "remember to use a hardened image" | `FROM cleanstart/nginx` — pinned, hardened, minimal |
| User | "remember to add USER directive" | OPA policy fails the build if missing |
| Privileged ports | "remember not to expose 80" | OPA policy rejects any `EXPOSE < 1024` |
| Vulnerabilities | "scan quarterly" | Trivy gate on every PR, build fails on HIGH/CRITICAL |
| Runtime writes | "audit detects drift" | `read_only: true` makes them physically impossible |
| Capabilities | "remember to drop caps" | `cap_drop: ALL`, `no-new-privileges`, audited tmpfs paths |
| Visibility | "ask the team what's running" | SBOM generated on every build |

## Prerequisites

- Docker + Docker Compose
- [Conftest](https://www.conftest.dev/install/) (for policy checks)
- [Trivy](https://trivy.dev/) (for CVE scanning)

## Run it locally

### 1. Run the policy check

This is the architectural gate — same policy, two Dockerfiles, mechanical pass/fail.

```bash
conftest test --policy policies/ Dockerfile.baseline  # Results: 8 tests, 4 passed, 1 warning, 3 failures, 0 exceptions
conftest test --policy policies/ Dockerfile.hardened  # Results: 8 tests, 8 passed, 0 warnings, 0 failures, 0 exceptions
```

Expected:

- **Baseline:** 3 failures + 1 warning (uses `:latest`, no `USER`, exposes port 80, no `HEALTHCHECK`)
- **Hardened:** all 8 checks pass

### 2. Build and run

```bash
make build       # builds both images
make run         # starts the hardened container on :8080
curl -I http://localhost:8080     # show the html status along with security content
```

You should see security headers in the response: `Strict-Transport-Security`, `X-Frame-Options: DENY`, `Content-Security-Policy`, `Permissions-Policy`. The `Server` header carries no version disclosure.

### 4. Compare the attack surfaces

Try to get a shell in each container:

```bash
docker exec -it nginx-hardened sh    # No shell in cleanstart/nginx , ouput : executable file not found in $PATH

# baseline not present in make file, please run below commands manually to get into shell in baseline
docker compose up -d baseline  # starts the basline
docker exec -it nginx-baseline sh  # able to get into shell of the basline image

whoami
id
ls /bin | wc -l
which apt curl wget bash
exit
```

This isn't a bug. The hardened image ships without a shell, package manager, or debug tools — there's nothing for an attacker to pivot with.

### 5. Compare CVEs

```bash
trivy image --severity HIGH,CRITICAL --scanners vuln demo/nginx-baseline:local  # 20 critical/high vulnerabilities
trivy image --severity HIGH,CRITICAL --scanners vuln demo/nginx-hardened:local  # 0 critical/high vulnerabilities
```

The baseline reports a list of HIGH and CRITICAL CVEs in libraries nginx doesn't even use to serve HTTP — `libheif`, `libde265`, `libgnutls`, etc. — bloat dragged in by Debian's package system. The hardened image returns nothing. You can't be vulnerable to a CVE in a library that isn't installed.

### 6. Stop

```bash
make stop # stop docker compose 
```

## Mapping to CIS Docker Benchmark

The Rego policy in `policies/docker_policy.rego` enforces below checks:

- **CIS 4.1** — non-root user (deny)
- **CIS 4.6** — `HEALTHCHECK` declared (warn)
- **CIS 4.7** — no `:latest`, tag pinned or digest-pinned (deny)
- **CIS 4.9** — prefer `COPY` over `ADD` (warn)
- **CIS 4.10** — no secrets in `ENV` (deny)
- **CIS 5.8** — no privileged ports (`<1024`) exposed (deny)


Wired into a CI pipeline, a non-compliant change cannot reach the main branch.
The same pattern works in GitLab CI, Jenkins, CircleCI, or any other pipeline runner. 

The hardened image is the foundation. An OPA Rego policy is the gate. The policy mechanically enforces CIS Docker Benchmark rules — pinned digests, non-root user, no privileged ports, no secrets in ENV. Same policy, two Dockerfiles, automatic pass/fail.