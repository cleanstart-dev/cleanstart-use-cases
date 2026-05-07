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
conftest test --policy policies/ Dockerfile.baseline
conftest test --policy policies/ Dockerfile.hardened
```

Expected:

- **Baseline:** 3 failures + 1 warning (uses `:latest`, no `USER`, exposes port 80, no `HEALTHCHECK`)
- **Hardened:** all 8 checks pass

### 2. Build and run

```bash
make build       # builds both images
make run         # starts the hardened container on :8080
curl -I http://localhost:8080
```

You should see security headers in the response: `Strict-Transport-Security`, `X-Frame-Options: DENY`, `Content-Security-Policy`, `Permissions-Policy`. The `Server` header carries no version disclosure.

### 4. Compare the attack surfaces

Try to get a shell in each container:

```bash
docker exec -it nginx-hardened sh    # present in make file

# baseline not present in make file, please run below commands manually to get into shell in baseline
docker compose up -d baseline
docker exec -it nginx-baseline sh

whoami
id
ls /bin | wc -l
which apt curl wget bash
exit
```

This isn't a bug. The hardened image ships without a shell, package manager, or debug tools — there's nothing for an attacker to pivot with.

### 5. Compare CVEs

```bash
trivy image --severity HIGH,CRITICAL --scanners vuln demo/nginx-baseline:local
trivy image --severity HIGH,CRITICAL --scanners vuln demo/nginx-hardened:local
```

The baseline reports a list of HIGH and CRITICAL CVEs in libraries nginx doesn't even use to serve HTTP — `libheif`, `libde265`, `libgnutls`, etc. — bloat dragged in by Debian's package system. The hardened image returns *"Detected OS: family=none. Unsupported os."* — there's no OS metadata, no package database, nothing for the scanner to match against. You can't be vulnerable to a CVE in a library that isn't installed.

### 6. Stop

```bash
make stop
```

## Mapping to CIS Docker Benchmark

The Rego policy in `policies/docker_policy.rego` enforces:

- **CIS 4.1** — non-root user (deny)
- **CIS 4.6** — `HEALTHCHECK` declared (warn)
- **CIS 4.7** — no `:latest`, tag pinned or digest-pinned (deny)
- **CIS 4.9** — prefer `COPY` over `ADD` (warn)
- **CIS 4.10** — no secrets in `ENV` (deny)
- **CIS 5.8** — no privileged ports (`<1024`) exposed (deny)

## The takeaway

Asking *"did we check rule 4.1?"* is a checklist mindset.

Asking *"is it possible for rule 4.1 to be wrong in our pipeline?"* is an architectural one. If the answer is no — because the build fails, or the runtime can't express the insecure state — you've moved security from *process* to *property*.

These are enforced *at build time* by the CI workflow, not audited *after deployment*.

## Wiring this into a CI/CD pipeline

Running `conftest test` locally proves the policy works. Wiring it into your pipeline is what makes it architectural — the rule then applies to *everyone*, *every time*, with no human in the loop. A reference workflow for GitHub Actions might look like:

```yaml
name: security-gate
on:
  pull_request:
    branches: [main]

jobs:
  policy-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Conftest
        run: |
          wget -q https://github.com/open-policy-agent/conftest/releases/download/v0.56.0/conftest_0.56.0_Linux_x86_64.tar.gz
          tar xzf conftest_0.56.0_Linux_x86_64.tar.gz
          sudo mv conftest /usr/local/bin
      - name: Verify hardened Dockerfile passes CIS policy
        run: conftest test --policy policies/ Dockerfile.hardened
      - name: Confirm baseline Dockerfile fails CIS policy (sanity check)
        run: |
          if conftest test --policy policies/ Dockerfile.baseline; then
            echo "Baseline should have failed but passed. Policy is broken." && exit 1
          fi

  vuln-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build hardened image
        run: docker build -t nginx-hardened:ci -f Dockerfile.hardened .
      - name: Trivy scan
        uses: aquasecurity/trivy-action@0.28.0
        with:
          image-ref: nginx-hardened:ci
          severity: HIGH,CRITICAL
          scanners: vuln
          exit-code: '1'
          ignore-unfixed: true
          timeout: 15m
```

The same pattern works in GitLab CI, Jenkins, CircleCI, or any other pipeline runner. The point is that the policy file is portable — once `policies/docker_policy.rego` exists, *any* CI system can be the gate.

Combine the gate with branch protection (GitHub: Settings → Branches → "Require status checks to pass before merging") and a non-compliant change becomes structurally unable to reach `main`. That combination — automated policy + organizational rule that no one can bypass — is the full picture of "security as a property."
