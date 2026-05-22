# Sources

Every numerical claim in the README is traceable to a public source. This file lists them for fact-checking.

## Numerical claims and their sources

### "300+ individual rules in Ubuntu 22.04 STIG"
**Source:** Canonical official blog, *"Meet DISA-STIG compliance requirements for Ubuntu 22.04 LTS with USG"*, June 24, 2024.
**Direct quote:** *"There are over 300 individual rules within the Ubuntu STIG, and this makes it prohibitively time-consuming for anyone to implement it from scratch."*
**URL:** https://ubuntu.com/blog/disa-stig-ubuntu-22-04-usg

### "Current release: V2R6, January 2026"
**Source 1:** NIST National Checklist Program, checklist ID 1235.
**URL:** https://ncp.nist.gov/checklist/revision/6653
**Source 2:** BigFix Forum publication notice.
**URL:** https://forum.bigfix.com/t/bigfix-compliance-updated-disa-stig-checklist-for-ubuntu-22-04-lts-server-published-2026-01-28/53638

### "182 fixlets in BigFix V2R6 site"
**Source:** BigFix Forum, Jan 28, 2026.
**Direct text:** *"Total Fixlets in Site: 182"*
**URL:** https://forum.bigfix.com/t/bigfix-compliance-updated-disa-stig-checklist-for-ubuntu-22-04-lts-server-published-2026-01-28/53638

### "Hardened images reduced vulnerability count by more than 97%"
**Source:** Dark Reading, Robert Lemos, *"Hardened Images Aim to Squash Container Vulnerabilities"*, Nov 14, 2025.
**Direct quote:** *"Typically, the hardened images have reduced the vulnerability count by more than 97%, resulting in near-zero known vulnerabilities or publicly disclosed Common Vulnerabilities and Exposures (CVEs)."*
**URL:** https://www.darkreading.com/application-security/hardened-containers-eliminate-common-source-vulnerabilities

### "60–80% smaller, near-zero CVEs, FIPS standards"
**Source:** CleanStart PR Newswire release, Aug 20, 2025.
**Direct quote:** *"Each of CleanStart's images are hardened to near zero CVEs, 60–80% smaller than original versions, and stored in a private repository. All meet NIST FIPS standards."*
**URL:** https://www.prnewswire.com/news-releases/cleanstart-achieves-350-hardened-vulnerability-free-container-images-accelerating-us-expansion-302534311.html

### "Debian ~140 MB vs Chainguard static ~2–3 MB"
**Source:** Chainguard Academy, *"Using the Chainguard Static Base Container Image"*.
**Direct quote (transcript):** *"the Debian image ... that's around 140 megabytes in size ... the Chainguard static images are roughly the same around two or three megabytes."*
**URL:** https://edu.chainguard.dev/chainguard/chainguard-images/how-to-use/static-base-image/

### "Go app: 892 MB → 775 MB on Chainguard, 42 CVEs → 0"
**Source:** Chainguard blog, *"Building minimal and low CVE images for compiled languages"*, Feb 27, 2024.
**Direct quote:** *"At the time of writing, this results in an 892 MB image ... 42 low vulnerabilities ... If we just change the FROM line at the top to use the free Chainguard Images for Go ... The size reduces from 892 to 775MB ... The CVE count goes to 0. For both Docker Scout and Grype scans."*
**URL:** https://www.chainguard.dev/unchained/building-minimal-and-low-cve-images-for-compiled-languages

### "nginx:latest 225 MB → alpine 79.8 MB → Chainguard 0 vulnerabilities"
**Source:** Mathieu Benoit, *"Distroless & Nginx container image, towards more security, by default and by design"*, Medium, Dec 18, 2025.
**Direct quote:** *"nginx:alpine (79.8MB) is already appealing in comparison to the default nginx:latest (225MB) ... grype cgr.dev/chainguard/nginx — (0 vulnerabilities)"*
**URL:** https://medium.com/@mabenoit/chainguards-nginx-container-image-1ec38245fcd0

### "90%+ fewer CVEs than Docker Official Images"
**Source:** Chainguard Academy, *"Vulnerability Comparisons"*.
**Direct quote (meta description):** *"See why Chainguard containers have 90%+ fewer CVEs than Docker Official Images"*
**URL:** https://edu.chainguard.dev/chainguard/chainguard-images/vuln-comparison/

### "Debloated 64%, hardened 99% fewer CVEs"
**Source:** CleanStart blog, *"CVE fatigue occurs when container and platform teams..."*, Jan 9, 2026.
**Direct quote:** *"Debloated images (same base family, fewer packages) reduced total CVEs by about 64%. Hardened images (minimal, security-focused) achieved about 99% fewer CVEs on average, often shipping with zero known CVEs at build time compared to hundreds in the baseline."*
**URL:** https://www.cleanstart.com/blogs/cve-fatigue-occurs-when-container-and-platform-teams

### "DISA has not published a STIG specifically for containers"
**Source 1:** Docker Hardened Images STIG documentation.
**Direct quote:** *"Because DISA has not published a STIG specifically for containers, these profiles help apply STIG-like guidance to container environments..."*
**URL:** https://docs.docker.com/dhi/core-concepts/stig/

**Source 2:** Chainguard analysis of DISA Container Hardening Process Guide.
**URL:** https://www.chainguard.dev/unchained/stig-hardening-container-images

### DISA Container Hardening Process Guide quotes
**Source:** Chainguard's published analysis quoting Sections 5 and 6 of the Process Guide V1.2.
**Section 5 quote:** *"With a properly locked down hosting environment, containers inherit most of the security controls and benefits from infrastructure to host OS-level remediation requirements."*
**Section 6 quote:** *"If an OpenSCAP scan returns noncompliant result(s), always evaluate the validity of those findings. False positives are common within major host OS-based containers."*
**URL:** https://www.chainguard.dev/unchained/stig-hardening-container-images
**Primary source PDF (DoD):** https://dl.dod.cyber.mil/wp-content/uploads/devsecops/pdf/Final_DevSecOps_Enterprise_Container_Hardening_Guide_1.2.pdf

### CleanStart Docker Hub
**URL:** https://hub.docker.com/u/cleanstart
**Confirmed via:** Footer of cleanstart.com, "Docker verified" badge.

### CleanStart GitHub
**URL:** https://github.com/cleanstart-dev
**Confirmed via:** Footer of cleanstart.com.

### STIG quarterly release cadence
**Source:** BigFix release notices showing V2R3 (June 2025), V2R4 (Nov 2024), V2R5 (Dec 2025), V2R6 (Jan 2026).
**URL:** https://forum.bigfix.com/t/bigfix-compliance-updated-disa-stig-checklist-for-ubuntu-22-04-lts-server-published-2025-06-24/52083

## What this repo does NOT claim

- A specific OpenSCAP pass-rate percentage from this repo's harness (must be run)
- A specific build time number (must be measured on your hardware)
- A specific image size for a CleanStart image (must be pulled and inspected)

These are intentionally left for the team or contributor running the harness to fill in. The README's side-by-side table uses real cited numbers from Chainguard's public benchmarks and CleanStart's own publications as the structural baseline.
