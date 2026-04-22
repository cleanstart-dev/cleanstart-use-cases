# cleanstart-use-cases

> Don't just read about hardened images — see the results yourself.

A comprehensive collection of practical use cases demonstrating the real-world impact of hardened container images. Every claim is backed by actual execution results and verifiable data.

---

## 📋 Overview

We're building a library of hands-on use cases for hardened container images — complete with commands, configurations, real metrics, and reproducible results. This transforms LinkedIn content from claims into verifiable, practical evidence.

Each use case includes:

- ✅ Complete commands for reproduction
- ✅ Actual execution results from real environments
- ✅ Comparative metrics (official images vs. hardened images)
- ✅ Scripts and configurations for automation
- ✅ Detailed analysis of security improvements

---

## 🚀 How It Works

| Step | Description |
|------|-------------|
| **Hands-on execution** | Each use case includes commands, configurations, and step-by-step instructions |
| **Actual results** | Real metrics from command outputs, scans, and comparisons |
| **GitHub repository** | All use cases, scripts, and results published at `cleanstart-use-cases` |
| **LinkedIn posts** | Each use case shared as a post with GitHub URL for full details |
| **Reproducible** | Anyone can clone the repo and verify results themselves |

---

## 🎯 Applications

| Use Case | Description |
|----------|-------------|
| **Workshops** | Ready-to-use material for hands-on training sessions |
| **Demos** | Live demonstrations with pre-validated results |
| **Quick fact checks** | Reference data for evaluating hardened images |
| **Community education** | Practical learning resources |

---

## 🔧 How to Use This Repository

1. **Browse use cases** — Each directory contains a complete scenario
2. **Review results** — See actual command outputs and metrics
3. **Reproduce locally** — Run the same commands in your environment
4. **Compare findings** — Validate results against your infrastructure
5. **Learn and apply** — Adapt patterns to your security requirements

---

## 📚 Use Case Categories

### Category 1: Foundation — Understanding the Problem Space

| S.No. | Topic | GitHub | LinkedIn |
|-------|-------|--------|----------|
| 1 | What Are Hardened Container Images? A Practical Definition | — | [Post](https://www.linkedin.com/feed/update/urn:li:activity:7429750774563323905?utm_source=share&utm_medium=member_desktop&rcm=ACoAADsC9HYBNTIuYxSvYr689odHBSpvD4U4k-s) |
| 2 | Zero-CVE Images Explained: Is Perfect Security Possible? | — | [Post](https://www.linkedin.com/feed/update/urn:li:activity:7432779690152689664?utm_source=share&utm_medium=member_desktop&rcm=ACoAADsC9HYBNTIuYxSvYr689odHBSpvD4U4k-s) |
| 3 | No Images vs. Images: Why "Just Use VMs" Isn't the Answer | — | — |
| 4 | The Hidden Cost of Public Container Images: Supply Chain Risk Analysis | — | [Post](https://www.linkedin.com/feed/update/urn:li:activity:7435226162454253568?utm_source=share&utm_medium=member_desktop&rcm=ACoAADsC9HYBNTIuYxSvYr689odHBSpvD4U4k-s) |

### Category 2: Base Image Selection Challenges

| S.No. | Topic | GitHub | LinkedIn |
|-------|-------|--------|----------|
| 5 | Distroless vs Alpine: Size Isn't Everything | — | [Post](https://www.linkedin.com/feed/update/urn:li:activity:7432391086637010944?utm_source=share&utm_medium=member_desktop&rcm=ACoAADsC9HYBNTIuYxSvYr689odHBSpvD4U4k-s) |
| 6 | Base Image Hell: When Updates Break Everything | — | [Post](https://www.linkedin.com/feed/update/urn:li:activity:7439566327054450688?utm_source=share&utm_medium=member_desktop&rcm=ACoAADsC9HYBNTIuYxSvYr689odHBSpvD4U4k-s) |
| 7 | The Scratch Image Trap: When Minimal Goes Too Far | — | [Post](hhttps://www.linkedin.com/feed/update/urn:li:activity:7440706076561506305?utm_source=share&utm_medium=member_desktop&rcm=ACoAADsC9HYBNTIuYxSvYr689odHBSpvD4U4k-s) |

### Category 3: Dependency & Attack Surface Problems

| S.No. | Topic | GitHub | LinkedIn |
|-------|-------|--------|----------|
| 8 | Attack Surface Reduction Through Dependency Management: Practical Strategies | [View](https://github.com/cleanstart-dev/cleanstart-use-cases/tree/main/Attack%20Surface%20Reduction) | [Post](https://www.linkedin.com/feed/update/urn:li:activity:7448002233507504128?utm_source=share&utm_medium=member_desktop&rcm=ACoAADsC9HYBNTIuYxSvYr689odHBSpvD4U4k-s) |
| 9 | Multi-Stage Builds: Your Secret Weapon Against Bloat | [View](https://github.com/cleanstart-dev/cleanstart-use-cases/tree/main/multi-stage%20builds) | — |
| 10 | The Transitive Dependency Problem: Vulnerabilities You Didn't Know You Had | — | — |

### Category 4: Scanning & Vulnerability Management Challenges

| S.No. | Topic | GitHub | LinkedIn |
|-------|-------|--------|----------|
| 11 | The Scanning Paradox: More Tools, More Vulnerabilities | — | — |
| 12 | False Positives in CVE Scanning: The 80/20 Problem | — | — |
| 13 | Why Your SBOM Might Be Lying to You | — | — |
| 14 | VEX Standards Explained: Moving from Vulnerability Lists to Exploitability Context | — | — |
| 15 | OSV.dev: The Universal Vulnerability Database for Open Source | — | [Post](https://www.linkedin.com/feed/update/urn:li:activity:7434575245669347328?utm_source=share&utm_medium=member_desktop&rcm=ACoAADsC9HYBNTIuYxSvYr689odHBSpvD4U4k-s) |

### Category 5: Build & Development Workflow Issues

| S.No. | Topic | GitHub | LinkedIn |
|-------|-------|--------|----------|
| 16 | Security-Velocity Trade-off: Why Zero-CVE Doesn't Mean Slow Builds | — | — |
| 17 | Why "Shift Left" Failed (And What Actually Works) | — | — |
| 18 | The Golden Image Problem: When Centralized Control Becomes a Bottleneck | — | — |
| 19 | Breaking the Migration Barrier: Moving from Legacy to Hardened Images | — | — |

### Category 6: Runtime Security Challenges

| S.No. | Topic | GitHub | LinkedIn |
|-------|-------|--------|----------|
| 20 | Rootless Containers: Security Theater or Real Protection? | — | — |
| 21 | The Truth About Zero-Day Vulnerabilities in Containers | — | — |
| 22 | Immutable Infrastructure vs. Runtime Patching: Choosing Your Security Model | — | — |

### Category 7: Supply Chain & Trust Issues

| S.No. | Topic | GitHub | LinkedIn |
|-------|-------|--------|----------|
| 23 | SLSA Levels Demystified: Understanding Supply Chain Trust States | — | — |
| 24 | Container Image Signing and Verification: Nobody's Actually Doing It (Yet) | — | — |
| 25 | Private Registry Security: Are Your Internal Images Actually Safer? | — | — |
| 26 | The Upstream Dependency Betrayal: When Trusted Sources Become Compromised | — | — |
| 27 | The Trivy Supply Chain Attack: When Security Scanners Become the Weapon | — | [Post](https://www.linkedin.com/feed/update/urn:li:activity:7442906600337584128?utm_source=share&utm_medium=member_desktop&rcm=ACoAADsC9HYBNTIuYxSvYr689odHBSpvD4U4k-s) |

### Category 8: Compliance & Regulatory Requirements

| S.No. | Topic | GitHub | LinkedIn |
|-------|-------|--------|----------|
| 28 | CIS Hardening Beyond Checklists: Making Security an Architectural Property | — | — |
| 29 | STIG Hardening by Design vs. Retrofit: Which Approach Wins? | — | — |
| 30 | FIPS 140-2/140-3 in Containers: Embedding Compliance at the Foundation | — | — |
| 31 | OpenSCAP and STIG Compliance Architecture: Implementation Patterns | — | — |

### Category 9: Operational & Debugging Challenges

| S.No. | Topic | GitHub | LinkedIn |
|-------|-------|--------|----------|
| 32 | The Debugging Dilemma: Troubleshooting Hardened Images Without Shell Access | — | — |
| 33 | Image Update Fatigue: Managing the Patch Treadmill | — | — |

---

## 📊 Progress Tracker

| Metric | Count |
|--------|-------|
| ✅ Published | 10 topics |
| 📝 Pending | 23 topics |
| 📊 Completion | 30% |

---

## 🛡️ About CleanStart

CleanStart provides zero-CVE, hardened container images built from source with security-first architecture.

**Key Capabilities:**

- **Zero-CVE images** — No known vulnerabilities at build time
- **Source recompilation** — Open-source packages rebuilt with security patches
- **Compliance-ready** — STIG, CIS, FIPS hardening by design
- **Verified provenance** — Cryptographic attestation and signed images
- **CVE data provider** — Recognized contributor to OSV.dev

🌐 **Website:** [cleanstart.com](https://cleanstart.com)  
📚 **Resource Center:** [cleanstart.com/resource-center](https://cleanstart.com/resource-center)

---

## 🐳 Container Images

Access CleanStart's hardened container images:

- **Docker Hub:** [hub.docker.com/u/cleanstart](https://hub.docker.com/u/cleanstart)
- **GitHub Container Registry:** [github.com/cleanstart-containers](https://github.com/cleanstart-containers)
- **AWS ECR Public Gallery:** [gallery.ecr.aws/cleanstart](https://gallery.ecr.aws/cleanstart)

---

## 🌐 Open Source Contributions

CleanStart is a recognized CVE data provider to **OSV.dev** — Google's Open Source Vulnerability database — contributing vulnerability intelligence from recompiled open-source packages.

- **GitHub Repository:** [cleanstart-dev/cleanstart-security-advisories](https://github.com/cleanstart-dev/cleanstart-security-advisories)
- **OSV Data:** [osv.dev/list?ecosystem=CleanStart](https://osv.dev/list?ecosystem=CleanStart)

---

## 👥 Join the Community

### 🔗 [Hardened Container Images LinkedIn Group](https://linkedin.com/groups/18324021)

A community for DevOps/DevSecOps engineers, security professionals, and developers focused on:

- Container hardening techniques and base image security
- CVE scanning, remediation, and prevention strategies
- Balancing security with performance and build speed
- Secure supply chain practices for container images
- Security-first architecture and design patterns
- Tools, workflows, and automation for zero-CVE deployments

**Follow CleanStart:**

| Platform | Link |
|----------|------|
| 📺 YouTube | [@CleanStart-official](https://youtube.com/@CleanStartOfficial) |
| 💼 LinkedIn | [@cleanstart-official](https://linkedin.com/company/cleanstart-official) |

---

## 🤝 Future: Open Contribution

Currently maintained by CleanStart. If community members show interest, we may open contributions where they can:

- Pick an existing use case and add their execution results
- Create new use cases with their specific scenarios
- Submit PRs with additional test cases or configurations
- Share findings from different environments
