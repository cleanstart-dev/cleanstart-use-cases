# Contributing to cleanstart-use-cases

This repository exists to provide verifiable, execution-backed evidence for claims made about hardened container images. Every use case here is expected to meet a production-grade bar: reproducible commands, real output, and conclusions that follow directly from the data — not from the framing.

If you're contributing, you're effectively co-authoring evidence that the community and CleanStart will stand behind publicly. Treat it with that level of rigor.

---

## Purpose and Editorial Standard

Each use case should answer a single, well-scoped question — "does X actually reduce Y, and by how much" — and answer it with data, not assertion. We optimize for:

- **Reproducibility** — anyone should be able to clone the repo and arrive at the same result
- **Honesty** — if results are mixed, partial, or don't favor a hardened approach in every dimension, say so
- **Precision** — exact versions, exact commands, exact output; no rounded or approximated claims presented as fact

A use case that proves a narrower point convincingly is more valuable than one that overclaims.

---

## Eagle View of Steps
A step-by-step guide to building a use case and sharing it with the Hardened Container Images LinkedIn community.

**Steps**
1. Identify a topic from the README tracker → https://github.com/cleanstart-dev/cleanstart-use-cases
2. Brainstorm and scope with Claude → https://claude.ai
3. Request repo access from Siddharth / Raghavendra and fork
4. Build scripts, Dockerfiles, and supporting files
5. Execute all commands and capture actual results
6. Write the use case README → Refer to guidelines at https://github.com/cleanstart-dev/cleanstart-use-cases/blob/main/CONTRIBUTING.md
7. Submit a Pull Request
8. Address review comments and merge
9. Draft the LinkedIn post and format via Typegrow → https://typegrow.com/tools/linkedin-text-formatter
10. Post to the LinkedIn community group → https://www.linkedin.com/groups/18324021/
11. Share with Ishan for final review before going live

**Notes**
- If you have your own topic, follow the same process
- If there are no scripts or commands to execute, skip the relevant steps

## Repository Conventions

Each use case occupies its own top-level directory, named to match the topic (e.g. `Attack Surface Reduction`, `The Transitive Dependency Problem`). Within that directory, contributors are expected to include:

- **README.md** — problem statement, methodology, commands, results, and a short conclusion
- **Scripts** — Shell, Python, or JavaScript, consistent with the languages already used in this repository
- **Dockerfiles** — where the use case involves a build comparison (baseline vs. hardened)
- **Raw output** — scan reports, SBOMs, logs, or comparison tables, committed alongside the README rather than summarized away

Where applicable, follow the existing pattern of comparing a baseline (official/legacy image) against the CleanStart hardened equivalent, with identical application logic so the base image is the only variable.

---

## Contribution Workflow

1. Check the topic tracker in the main README to confirm the use case isn't already covered or in progress.
2. Open an issue describing the problem you intend to demonstrate, your proposed methodology, and the tools involved. This avoids duplicated effort and lets maintainers flag methodology concerns early.
3. Fork and branch: `use-case/<topic-name>`.
4. Build the use case following the structure above. Run everything yourself before submitting — do not submit projected or estimated results.
5. Open a pull request that includes:
   - A summary of the question the use case answers
   - The topic from the tracker it corresponds to, if applicable
   - Confirmation that all commands were executed and results are unedited

Maintainer review will assess methodology validity, reproducibility, and whether the conclusion is supported by the data presented — not just whether the code runs.

---

## Tooling Conventions

This repository's existing use cases are built primarily in Shell, Python, and JavaScript, with Dockerfiles for image comparisons and Open Policy Agent for policy-as-code examples. Stay within this toolset unless there's a clear technical reason not to — note that reasoning in your PR description.

---

## What We Will Not Merge

- Use cases that compare a deliberately misconfigured baseline against a properly configured CleanStart image
- Conclusions that extrapolate beyond what the data shows
- Marketing language in place of methodology
- Results that cannot be reproduced from the committed scripts and Dockerfiles alone

---

## Current Contribution Model

This repository is presently maintained by the CleanStart team. We welcome early community involvement — proposing a use case, extending an existing one with results from a different environment, or flagging a methodology gap. Open an issue to start that conversation.

---

## Recognition

Merged use cases are credited to their contributors in the use case's README, and may be referenced in the corresponding LinkedIn post shared with the Hardened Container Images community.

---

## LinkedIn Use Case Posting Guidelines

This is the internal playbook for converting a completed GitHub use case into a community LinkedIn post. The goal is consistent: every post should read like a security engineer presenting findings, not a vendor presenting a pitch.

### Voice and Persona

Write as a senior DevSecOps/developer advocate sharing a finding from their own lab work. Characteristics:

- Confident, declarative sentences — let the data carry the weight, not adjectives
- No exclamation points, no "amazing," "huge," or "game-changing"
- CleanStart appears as a comparison subject and a footer link, never as the hero of the sentence
- Numbers are exact, not rounded for effect, and caveated where they're a snapshot in time

### Post Anatomy

Every long-form use case post follows this structure:

**1. The Hook** (1–2 lines, bolded with Unicode bold-sans formatting)
A sharp, specific statement of the failure mode or tension — not a question, not a generic intro. It should make a practitioner stop scrolling because it names something they've actually experienced.

Example pattern: *"Your pipeline trusted the upstream. The upstream was already compromised."*

**2. The Problem**
Describe the scenario in plain operational terms — what the user did, what they expected, what actually happened. Use short declarative lines, often with ✗ or ✓ markers, rather than full paragraphs.

**3. The Setup / Proof of Concept**
State exactly what was compared: same app, same Dockerfile structure, only one variable changed. Name the tools used (Trivy, Syft, grype, Cosign, etc.) and the exact versions/tags involved.

**4. The Data**
Present the comparison as a tight, scannable block — image names, CVE counts, package counts, sizes. Let the contrast do the persuading. Avoid narrative explanation of numbers that are already self-evident.

**5. The Classification / Why**
This is the section that separates a credible post from a marketing one — explain why the numbers differ. Which CVEs are real and unfixable without an upstream rebuild, which are noise, which attack surface was structurally removed versus patched. Intellectual honesty here is what earns trust with a technical audience.

**6. What Actually Works**
A short, prescriptive close — not "use CleanStart," but the underlying practice (pin by digest, verify signatures, reduce reachable surface, diff your SBOM). The product should be implied by the practice, not stated as the conclusion.

**7. CTA + Link**
One line pointing to the full repository for the script, Dockerfiles, and methodology. No additional pitch after the link.

**8. Hashtags**
6–8 tags, technical and specific. Core rotation: `#DevSecOps #ContainerSecurity #SupplyChainSecurity #AppSec #CloudNative #ZeroTrust #SBOM #cleanstart` — adjust 2–3 per post to match the specific tool or theme (`#Trivy`, `#Docker`, `#Python`, `#ShiftLeft`).

### Formatting Conventions

- Section headers use bold Unicode sans-serif text (𝗟𝗶𝗸𝗲 𝗧𝗵𝗶𝘀), not markdown bold — LinkedIn doesn't render markdown
- Use `──────────────────────────` as a visual divider between major sections on longer posts
- ✗ and ✓ for quick capability/status comparisons; avoid decorative emojis elsewhere
- Bullet points only for short, parallel facts (CVE counts, image sizes) — narrative reasoning stays in prose

### Length Guidance — Two Formats

**Short-form** (concept/explainer topics, ~500 characters): Used for foundational or conceptual topics without an attached lab result. Single idea, quick read, no data table required.

**Long-form** (use-case-backed topics, ~1,500–2,500 characters): Used whenever a GitHub use case with actual execution results backs the post. Follows the full anatomy above.

Match the format to whether you have a reproducible result behind it — don't pad a short-form topic into long-form, and don't compress a use case with real data into a 500-character post that strips out the proof.

### Pre-Publish Checklist

- [ ] Does the hook name a real, specific failure — not a generic security platitude?
- [ ] Is every number in the post traceable to a committed script/output in the repo?
- [ ] Does the "why" section explain the result rather than just restating it?
- [ ] Is the CleanStart mention proportionate — a comparison subject and a link, not the subject of the post?
- [ ] Does the close prescribe a practice, not just a product?
- [ ] Is the GitHub link the only link in the post?

### Template Skeleton

```
[𝗕𝗼𝗹𝗱 𝗵𝗼𝗼𝗸 𝗹𝗶𝗻𝗲 𝗻𝗮𝗺𝗶𝗻𝗴 𝘁𝗵𝗲 𝗳𝗮𝗶𝗹𝘂𝗿𝗲 𝗺𝗼𝗱𝗲]
Here's what actually happens 👇
──────────────────────────
🚨 𝗧𝗵𝗲 𝗽𝗿𝗼𝗯𝗹𝗲𝗺
[3–5 short lines, plain scenario]

──────────────────────────
🔬 𝗧𝗵𝗲 𝘀𝗲𝘁𝘂𝗽 / 𝗽𝗿𝗼𝗼𝗳 𝗼𝗳 𝗰𝗼𝗻𝗰𝗲𝗽𝘁
[exact tools, versions, what was held constant]

[data block — counts, sizes, comparison table]

──────────────────────────
𝗧𝗵𝗲 𝗰𝗹𝗮𝘀𝘀𝗶𝗳𝗶𝗰𝗮𝘁𝗶𝗼𝗻 / 𝘄𝗵𝘆
[honest breakdown of what the numbers mean]

──────────────────────────
✅ 𝗪𝗵𝗮𝘁 𝗮𝗰𝘁𝘂𝗮𝗹𝗹𝘆 𝘄𝗼𝗿𝗸𝘀
[prescriptive practice, 2–3 lines]

Full use case, scripts, and results on GitHub 👇
[link]

#DevSecOps #ContainerSecurity #SupplyChainSecurity #AppSec #CloudNative #cleanstart [+2-3 topic-specific tags]
```
