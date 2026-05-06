# 📦 False Positives in CVE Scanning

A small project that compares vulnerability scan results for the same Grafana Loki binary across two container images:

* `grafana/loki:3.7.1` (official image)
* `cleanstart/loki:latest` (minimal hardened image)

The goal is to show:

> How many reported CVEs come from **unused packages**, not the application itself.

---

## 🧠 The argument

Loki is a Go binary.

That means:

* Most dependencies are compiled into the binary
* The runtime does **not use most OS packages** in the container

Yet scanners like Trivy:

* Scan **everything installed in the image**
* Report CVEs for:

  * BusyBox
  * OpenSSL
  * apk tools
  * system utilities

Even if Loki never calls them.

---

## 🔬 What this project demonstrates

```
grafana/loki:3.7.1   → 19 CVEs flagged
cleanstart/loki      →  4 CVEs flagged
```

Same Loki binary.

### What changed?

* OS packages removed
* Scanner noise reduced

### What stayed the same?

* CVEs in Loki itself
* CVEs in Go dependencies

---

## 📊 Key insight

From analysis:

* ~63% of CVEs in `grafana/loki:3.7.1` are **not reachable**
* These disappear in the minimal image

👉 This is not “fixing vulnerabilities”
👉 It’s **removing irrelevant attack surface**

---

## ⚖️ True vs False Positives

### ✅ Likely TRUE positives

These affect the actual Loki binary:

* `stdlib` (Go runtime)
* `github.com/grafana/loki/v3`
* `golang.org/x/*`
* `prometheus` libraries

👉 Present in both images
👉 Must be fixed via patching/upgrading

---

### ❌ Likely FALSE positives

These come from OS packages Loki does not use:

* `busybox`, `busybox-binsh`
* `ssl_client`
* `apk-tools`
* shell utilities

👉 Present only in full OS image
👉 Removed in minimal image

---

## 📁 Project structure

```
False Positives in CVE Scanning/
├── compare.py
├── README.md
├── sboms/
└── scans/
```

---

## ⚡ Quick start

### 1. Pull images

```bash
docker pull grafana/loki:3.7.1
docker pull cleanstart/loki:latest
```

---

### 2. Generate SBOMs (with Syft)

```bash
syft grafana/loki:3.7.1     -o cyclonedx-json=sboms/grafana_loki.cdx.json
syft cleanstart/loki:latest -o cyclonedx-json=sboms/cleanstart_loki.cdx.json
```

---

### 3. Scan with Trivy

```bash
trivy sbom --format json --output scans/grafana_loki.json \
    sboms/grafana_loki.cdx.json

trivy sbom --format json --output scans/cleanstart_loki.json \
    sboms/cleanstart_loki.cdx.json
```

---

### 4. Compare

```bash
python3 compare.py scans/grafana_loki.json scans/cleanstart_loki.json \
  --label-standard "grafana/loki:3.7.1" \
  --label-cleanstart "cleanstart/loki:latest" \
  --packages-standard < packages-standard > --packages-cleanstart < packages-cleanstart > \
  --execs-standard < execs-standard > --execs-cleanstart < execs-cleanstart > \
  --sizes "grafana/loki:3.7.1=< grafana/loki - size >" "cleanstart/loki:latest=< cleanstart/loki:latest - size >"
```

---

## 💡 Why this matters

Security teams often see:

* 100s of CVEs
* Most are irrelevant to the running app

This leads to:

* Alert fatigue
* Wasted triage time
* Distrust in scanners

---

## 🧾 Final takeaway

> The problem isn’t just vulnerabilities — it’s **signal vs noise**

* Full OS images inflate CVE counts
* Minimal images reduce noise
* Real vulnerabilities remain visible

---

## 🧠 One-line summary

> Same binary. Same real risks. Far fewer distractions.
