# Breaking the Migration Barrier — Legacy to Hardened Images

> **Build & Development Workflow Issues**
> Part of the [CleanStart Use Cases](https://github.com/cleanstart-dev/cleanstart-use-cases) series.

## 🎯 Scenario

A fintech processing 4M payment receipts/day. Their `receipt-api` runs on `node:25.9.0-bullseye` across 120+ pods. A PCI-DSS audit flags the image with **5000+ CVEs** (1000+ High, 150+ Critical). The CISO mandates a move to hardened images within one quarter.

Five days in, the team escalates: *"Hardened images don't work for our use case."* Builds fail because `apt-get` doesn't exist. The container won't start because the app expects to run as root. The entrypoint uses `bash`, which isn't there.

**They're wrong.** Every blocker is a documented migration barrier with a known fix. This walks through below common ones.

---

## 📁 Repo Structure

```
.
├── README.md
├── Dockerfile.legacy          # Bloated baseline (node:25.9.0-bullseye)
├── Dockerfile.hardened        # Multi-stage, both stages on CleanStart
├── app/
│   ├── package.json
│   ├── server.js
│   └── healthcheck.js
└── k8s/
    ├── deployment-legacy.yaml
    └── deployment-hardened.yaml
```

---

## ✅ Prerequisites

| Tool | Install |
|---|---|
| Docker 24+ | curl -fsSL https://get.docker.com | sh |
| Trivy 0.50+ | curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh && mv ./bin/trivy /usr/local/bin/ |
| Syft 1.0+ | curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin |
| jq | apt install jq |

```bash
docker pull cleanstart/node:latest-dev   # builder (npm, build tools)
docker pull cleanstart/node:latest       # runtime (hardened, near-zero CVEs)
```

---

## Step 1 — Build & inspect the legacy image

```bash
docker build -f Dockerfile.legacy -t receipt-api:legacy .
docker images receipt-api:legacy --format "{{.Size}}"
docker run --rm --entrypoint id receipt-api:legacy
```

## Step 2 — Scan legacy

```bash
trivy image receipt-api:legacy --severity HIGH,CRITICAL
trivy image receipt-api:legacy --format json --output legacy-scan.json
syft receipt-api:legacy -o spdx-json > legacy-sbom.json

jq '[.Results[]?.Vulnerabilities[]?] | length' legacy-scan.json
jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' legacy-scan.json
jq -r '[.Results[].Vulnerabilities[]?.Severity] | group_by(.) | map({sev: .[0], count: length})' legacy-scan.json
jq '.packages | length' legacy-sbom.json
```

Expect ~3300+ CVEs, 12 CRITICAL, 472 HIGH, 629 packages, 1.52 GB image.

## Step 3 — Build & inspect hardened

```bash
docker build -f Dockerfile.hardened -t receipt-api:hardened .
docker images receipt-api:hardened --format "{{.Size}}"
docker image inspect receipt-api:hardened --format '{{.Config.User}}'
```

## Step 4 — Scan hardened

```bash
trivy image receipt-api:hardened --severity HIGH,CRITICAL
trivy image receipt-api:hardened --format json --output hardened-scan.json
syft receipt-api:hardened -o spdx-json > hardened-sbom.json

jq '[.Results[]?.Vulnerabilities[]?] | length' hardened-scan.json
jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' hardened-scan.json
jq -r '[.Results[].Vulnerabilities[]?.Severity] | group_by(.) | map({sev: .[0], count: length})' hardened-scan.json
jq '.packages | length' hardened-sbom.json
```

## Step 5 — Behavioral parity test

```bash
docker run --rm -d -p 3001:3000 --name legacy-test receipt-api:legacy
docker run --rm -d -p 3002:3000 --name hardened-test receipt-api:hardened
sleep 3

curl -s http://localhost:3001/healthz && echo
curl -s -X POST http://localhost:3001/receipt -H "Content-Type: application/json" \
  -d '{"amount": 1500, "currency": "INR"}' && echo

curl -s http://localhost:3002/healthz && echo
curl -s -X POST http://localhost:3002/receipt -H "Content-Type: application/json" \
  -d '{"amount": 1500, "currency": "INR"}' && echo

docker stop legacy-test hardened-test
```

Both must respond identically. If they do, the migration works.

---

## 🚧 The Migration Barriers

**1. `apt-get` not found** → Move installs to a builder stage; copy artifacts only. Use `cleanstart/node:latest-dev` for the builder, `cleanstart/node:latest` for runtime.

**2. No shell to debug** (on truly distroless images — `cleanstart/node:latest` does ship a minimal `sh`) → Use `kubectl debug -it <pod> --image=busybox --target=<container> --share-processes` instead of relying on a shell in the production image without shell.

**3. Permission denied as non-root** → Pre-create writable dirs in the builder, `chown -R 65532:65532 /app`, set `USER 65532:65532` in runtime. Bind to ports >1024.

**4. Entrypoint script breaks** → Drop `bash` wrappers. Use exec-form: `ENTRYPOINT ["server.js"]`. If you need pre-start logic, use a Kubernetes init container.

**5. Healthcheck fails (`curl` missing)** → Use `httpGet` probes in Kubernetes, not `exec` probes. Or ship a static healthcheck (we ship `healthcheck.js`).

---

## 📈 Expected Results

| Metric | Legacy (`node:25.9.0-bullseye`) | Hardened (`cleanstart/node:latest`) |
|---|---:|---:|
| Image size           | 1.52 GB | ~223 MB |
| Total CVEs           | ~3300+      | 0     |
| HIGH + CRITICAL CVEs | 484       | 0       |
| Packages in SBOM     | 629      | 254     |
| Runs as root         | ✅ Yes    | ❌ No (uid 65532) |
| Entrypoint           | docker-entrypoint.sh | /usr/bin/node |  

Numbers will vary by machine and image version — run the steps above and capture your own.

---

## 🧹 Cleanup

```bash
docker rmi receipt-api:legacy receipt-api:hardened
rm -f legacy-scan.json hardened-scan.json legacy-sbom.json hardened-sbom.json
```

---

## 💡 Takeaways

1. The migration barrier is mostly cultural, not technical. Every blocker has a documented fix.
2. Multi-stage builds are non-negotiable. Anything needing `apt`, `gcc`, or `make` belongs in a builder stage.
3. Treat the first migration as a template. Once one service is hardened, the next ten are mechanical.
4. Measure to convince skeptics. A 150+ CVE → 0 CVE delta ends arguments faster than any whitepaper.

> The question isn't whether you can migrate to hardened images. It's whether you can afford another quarter of audit findings while you debate it.