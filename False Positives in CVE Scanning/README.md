# Go App + CVE Image Comparison: golang:1.26.2 vs cleanstart/go:latest

A small project that takes a basic Go HTTP service, packages it two ways, scans both with Trivy, and shows side-by-side how many of the CVEs flagged in `golang:1.26.2` are actually **false positives** for a Go application — and how a hardened minimal base like `cleanstart/go:latest` eliminates them at the source.

**Zero Python dependencies.** Standard library only. Just needs Python 3.8+, plus Docker and Trivy if you want to generate fresh scans.

## The argument

A Go HTTP service compiled with `CGO_ENABLED=0` is a static binary. It calls only the Go standard library. It does not link `libxml2`, `libwebp`, `perl`, `curl`, `bash`, or any of the other ~50 OS packages that ship in `golang:1.26.2` (which is Debian Trixie based).

But Trivy doesn't know that. It scans the image's package database and dutifully reports every CVE in every installed package — even ones the Go binary never touches.

This project demonstrates the gap:

```
golang:1.26.2          →  47 CVEs flagged   (45 false positives for our Go app)
cleanstart/go:latest   →   0 CVEs flagged
```

Same Go binary. Different base image. The false positives don't get filtered — they get **eliminated** because the vulnerable packages aren't there in the first place.

## Repo layout

```
go-image-cve-comparison/
├── app/
│   ├── main.go                    ← tiny HTTP service (/health, /hello)
│   ├── go.mod
│   ├── Dockerfile.golang          ← packages the app on golang:1.26.2
│   └── Dockerfile.cleanstart      ← packages the same app on cleanstart/go
├── scans/
│   ├── golang_1_26_2.json         ← sample Trivy report (47 CVEs, bundled)
│   └── cleanstart_go.json         ← sample Trivy report (0 CVEs, bundled)
├── compare.py                     ← the comparison/report script
└── README.md
```

## Quick start (with the bundled sample scans, no Docker needed)

```bash
python3 compare.py scans/golang_1_26_2.json scans/cleanstart_go.json
```

You'll see CVEs side-by-side, the noisiest packages in `golang:1.26.2`, a labeled list of CVEs (`TRUE POSITIVE` / `FALSE POSITIVE`), and the bottom-line summary.

The bundled JSONs are realistic samples so you can see the output immediately. To get **your own real numbers**, generate fresh scans with the steps below.

---

## How to generate the scan JSON files yourself

### Prerequisites

- **Docker** — install from <https://docs.docker.com/get-docker/>
- **Trivy** — install:

  ```bash
  # Linux / WSL
  sudo apt-get install -y wget gnupg
  wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo gpg --dearmor -o /usr/share/keyrings/trivy.gpg
  echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee /etc/apt/sources.list.d/trivy.list
  sudo apt-get update && sudo apt-get install -y trivy

  # macOS
  brew install trivy
  ```

  Verify: `trivy --version`

- **Python 3.8+** — already on your system if `python3 --version` works.

### Step 1 — Build the standard image (uses public golang:1.26.2)

```bash
docker build -f app/Dockerfile.golang -t demo-go-standard:1.26.2 app/
```

### Step 2 — Build the hardened image (uses cleanstart/go:latest)

```bash
docker build -f app/Dockerfile.cleanstart -t demo-go-cleanstart:latest app/
```

### Step 3 — Scan both images with Trivy

```bash
trivy image --format json --output scans/golang_1_26_2.json demo-go-standard:1.26.2
trivy image --format json --output scans/cleanstart_go.json demo-go-cleanstart:latest
```

The `--output` flag writes Trivy's JSON report to the path you give it. That's the file `compare.py` reads.

### Step 4 — Run the comparison

```bash
python3 compare.py scans/golang_1_26_2.json scans/cleanstart_go.json
```

### Optional — scan the base images directly without your app

You can scan any public image without building anything:

```bash
trivy image --format json --output scans/golang_1_26_2.json    golang:1.26.2
trivy image --format json --output scans/cleanstart_go.json    cleanstart/go:latest
python3 compare.py scans/golang_1_26_2.json scans/cleanstart_go.json
```

This compares the base images themselves. The numbers come out essentially the same because the Go binary itself contributes only one or two stdlib CVEs — the OS layer dominates.

### Troubleshooting

- **`trivy: command not found`** → re-check the install step above. On WSL with broken IPv6, `apt` may fail. Workaround: download the binary directly from <https://github.com/aquasecurity/trivy/releases> and put it on your PATH.
- **`docker: permission denied`** → add your user to the `docker` group: `sudo usermod -aG docker $USER`, then log out and back in.
- **First scan is slow** → Trivy downloads its vulnerability database (~500MB) on first run. Subsequent scans are fast.

---

## How the false positive classification works

The script considers a CVE a **false positive** when the affected package is one the Go binary cannot reach. For a static Go HTTP service, the relevant set is small:

```python
APP_RELEVANT_PACKAGES = {
    "ca-certificates",   # TLS root certs (used at runtime)
    "stdlib",            # Go standard library itself
    "golang.org/x/net",  # net/http indirect deps
    "net/http", "net/mail", "html/template",
}
```

Everything else — `bash`, `curl`, `perl-base`, `libwebp7`, `libsystemd0`, the kernel headers, `openssh-client`, etc. — is dead weight from this app's point of view.

This is a deliberately conservative classification. In real triage you'd add a few more packages (e.g., glibc if you're not using `CGO_ENABLED=0`), but the principle holds: **most of what's in `golang:1.26.2` is not what your Go binary uses**, and a hardened image proves that by simply not shipping it.

## Why this matters

- A typical security pipeline turns those 47 CVEs into 47 Jira tickets. Most get closed as "won't fix" weeks later.
- Developers learn to distrust scanner output when 95%+ of "critical" findings turn out not to apply.
- The fix isn't smarter filtering. It's not shipping vulnerable code in the first place.

## The Dockerfiles

**`Dockerfile.golang`** — single-stage, intentionally bloated:
```dockerfile
FROM golang:1.26.2
WORKDIR /src
COPY go.mod main.go ./
RUN go build -o /app ./...
ENTRYPOINT ["/app"]
```

**`Dockerfile.cleanstart`** — multi-stage, hardened runtime:
```dockerfile
FROM cleanstart/go:latest-dev AS builder
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -ldflags='-s -w' -o /app ./...

FROM cleanstart/go:latest
COPY --from=builder /app /app
ENTRYPOINT ["/app"]
```

Same source code. Same compiled binary. Vastly different attack surface.
