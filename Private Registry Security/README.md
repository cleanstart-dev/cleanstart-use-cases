# Private Registry Security: Are Your Internal Images Actually Safer? — with CleanStart

> Three small, independently runnable tools that separate **"who can reach this image"** from **"is this image actually patched"** — a real registry staleness audit, a reused CVE comparison, and an enforceable promotion policy.

---

## The problem and the vision

Most security reviews treat "it's in our private registry" as a control by itself. An image gets pulled from Docker Hub once, copied into Artifactory / Nexus / Harbor / ECR, approved in a change ticket, and from that point on it's "internal" — which quietly gets read as "safe."

That reasoning conflates two properties that have nothing to do with each other:

| | What it actually governs |
|---|---|
| **Reachability** | Registry auth, network policy, IP allowlists, mTLS between CI and the registry — *who can pull the image* |
| **Currency** | Whether the image has been rebuilt since the last disclosed CVE in its base OS — *what's actually inside it* |

A private registry controls the first. It says nothing about the second. In practice, private mirrors are frequently *worse* on currency than the public image they were copied from — because once something is "approved" and sitting in the internal repo, nobody re-pulls it, nobody re-scans it, and nobody notices when new CVEs land against packages it still contains.


| Tool | Answers | Grounded in |
|---|---|---|
| [`staleness-audit/`](staleness-audit/) | *How old is what's actually in my registry, right now?* | Live registry queries via `crane` — no estimates, no synthetic data |
| [`cve-comparison/`](cve-comparison/) | *What does that staleness typically cost in CVEs?* | syft → trivy pipeline |
| [`promotion-policy/`](promotion-policy/) | *Is this specific image fit to promote?* | A tested OPA/Rego policy that denies stale or unsigned images, with unit tests you can run |

Run them in that order: audit what you have → see what it costs you → codify the threshold so "how stale is too stale" stops being a judgement call.

---

## What this actually measures

| Layer | Private mirror (typical) | Public tag (current) | CleanStart |
|---|---|---|---|
| Who can reach it | Internal only — registry auth + network policy | Anyone with registry access | Internal only, same access model as your mirror |
| CVEs baked in | Same as the day it was mirrored — often years stale | Whatever's in today's tag | 0–5 at any time of scan |
| Re-scan cadence | Ad hoc — "if someone remembers" | Continuous, since public exposure invites scrutiny | "immediate on every CVE disclosure" |
| Provenance / signing | Rarely enforced beyond registry login | Varies by publisher | Signed SBOM + SLSA provenance on every image |
| Who owns the patch | Whoever mirrored it — often nobody, months later | Upstream maintainer | CleanStart's automated pipeline |
| False sense of security | High — "it's private" gets read as "it's safe" | Low — visibility keeps pressure on | N/A — currency isn't tied to visibility |

---

## Project structure

```
private-registry-security/
├── staleness-audit/           ← Tool 1: how old is what's in your registry?
│   ├── targets.txt              images to audit — point this at your own registry
│   ├── audit.sh                 crane digest + config → real age, real signature check
│   ├── analyze_staleness.py     renders docs/staleness.html
│   ├── results/                 created by audit.sh — one .json per image + summary.json
│   └── docs/staleness.html      created by analyze_staleness.py
│
├── cve-comparison/             ← Tool 2: what does that staleness cost in CVEs?
│   ├── images.txt                public | cleanstart pairs (reused from Image Update Fatigue)
│   ├── scan.sh                   syft SBOM → trivy CVE scan
│   ├── analyze.py                renders docs/index.html
│   ├── sboms/, scan_results/     created by scan.sh
│   └── docs/index.html           created by analyze.py
│
└── promotion-policy/           ← Tool 3: stop it from happening again
    ├── registry-freshness.rego     OPA policy: deny stale or unsigned images
    ├── registry-freshness_test.rego  unit tests — run with `opa test`
    ├── thresholds.json              max_age_days / require_signature, overridable per environment
    └── examples/                    sample inputs (one that fails, one that passes)
```

Each tool has its own inline documentation (read the header comment at the top of each script). What follows is how they fit together.

---

## Tool 1 — `staleness-audit/`: how old is what's in your registry?

This is the one genuinely new measurement in this use case: not a CVE count, but **when was this image actually last rebuilt, and is it signed?**

```bash
cd staleness-audit

# syft/trivy aren't needed here — just crane, and optionally cosign

# crane
curl -sL "https://github.com/google/go-containerregistry/releases/latest/download/go-containerregistry_Linux_x86_64.tar.gz" | tar xz crane
sudo mv crane /usr/local/bin/

# cosign (optional — enables real signature verification)
curl -O -L https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
sudo chmod +x cosign-linux-amd64
sudo mv cosign-linux-amd64 /usr/local/bin/cosign

bash audit.sh                        # audits every image in targets.txt
python3 analyze_staleness.py         # writes docs/staleness.html

cd docs && python3 -m http.server 8181
# then open http://localhost:8181/staleness.html
```

**Edit `targets.txt` to point at your own registry** — e.g. `your-registry.internal/team/api:2.3.1` — before running this for real. The six entries shipped in the file are real Docker Hub tags, included so the tool runs out of the box; every age and digest `audit.sh` reports comes directly from the registry at run time via `crane digest` and `crane config`. Nothing is estimated.

Without `cosign` installed, the report will show "not checked" for signatures instead of "unsigned" — it won't guess.

---

## Tool 2 — `cve-comparison/`: what does that staleness cost you?

This reuses the scan.sh / analyze.py pipeline from CleanStart's **Image Update Fatigue** use case, unmodified in substance — it's already a solid, real, syft+trivy-grounded comparison, so there was no reason to rebuild it.

```bash
cd cve-comparison
bash scan.sh              # syft SBOM → trivy CVE scan for each pair in images.txt
python3 analyze.py        # writes docs/index.html
```

**To model your actual exposure** rather than today's public tag: once `staleness-audit` tells you which image in your registry hasn't been touched in a while, replace the left-hand column in `images.txt` with that exact stale tag. If the audit flagged `postgres:14.8` as 38 months old, scan `postgres:14.8` here — not `postgres:18.4` — to see what that specific, real staleness is actually carrying.

---

## Tool 3 — `promotion-policy/`: stop it from happening again

An audit tells you what's wrong today. It doesn't tell you what to do about it. This is a small OPA/Rego policy that turns the staleness threshold from a number in a report into a decision you can actually evaluate — tested against a real OPA binary, current v1 Rego syntax.

```bash
cd promotion-policy

curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
chmod +x opa && sudo mv opa /usr/local/bin/

# Run the policy's own unit tests
opa test . -v --ignore examples

# Evaluate a stale, unsigned image against the policy
opa eval -d registry-freshness.rego -d thresholds.json \
  -i examples/stale-and-unsigned.json 'data.registry.freshness' --format pretty
# → deny: too old AND unsigned

# Evaluate a fresh, signed image
opa eval -d registry-freshness.rego -d thresholds.json \
  -i examples/fresh-and-signed.json 'data.registry.freshness' --format pretty
# → allow: true
```

The input shape the policy expects is the same shape `staleness-audit/audit.sh` already writes per image (`image`, `age_days`, `signed`) — so you can feed a real audit result straight into it:

```bash
opa eval -d registry-freshness.rego -d thresholds.json \
  -i ../staleness-audit/results/postgres-14-8.json \
  'data.registry.freshness.deny' --format pretty
```

`thresholds.json` holds `max_age_days` and `require_signature` — override it per environment (looser for a dev registry, strict for prod) without touching the policy itself.

An image with no build timestamp at all is denied by default — the policy doesn't assume "unknown" means "fine."

---

## Why the mirror stays stale without anyone deciding that

**Private mirror path:**
1. Image approved once, copied into the internal registry
2. No automated trigger to re-pull or re-scan it — the registry doesn't know or care that upstream published a fix
3. New CVEs accumulate silently against packages nobody's watching
4. Someone eventually notices during an audit, incident, or pen test — often weeks/months later
5. Emergency triage, rebuild, re-approval — under time pressure this time

**CleanStart path:**
1. Automated system detects affected images from the CVE feed — no human involved, regardless of which registry the image ends up mirrored into
2. Automated impact check — is the package present and runtime-reachable? If not, the CVE doesn't apply
3. Patch applied via locked source dependencies, hermetic build
4. Patched image published to the CleanStart registry
5. Your private mirror pulls the updated tag on your normal sync cadence — currency travels with the image, not with who's watching it

The second path doesn't depend on your registry, your mirroring schedule, or anyone remembering to check. The three tools above are what let you find out which path you're actually on, and put a floor under it.

---

## What's still your responsibility

None of the three tools above replace registry hygiene — they help you enforce it:

1. **Access control** — RBAC on the registry itself, network policy, mTLS between CI and the registry
2. **Re-scan cadence policy** — decide how often mirrored images get re-pulled and re-scanned; `staleness-audit` tells you the current state, it doesn't schedule the next run
3. **Enforcement** — `promotion-policy` gives you the decision; actually enforcing it on every dev → staging → prod promotion, rather than evaluating it manually once, is on you
4. **Signature / provenance verification** — verify signatures on every pull; being in your registry is not the same as being verified
5. **Retention and deprecation** — remove stale tags instead of leaving them pullable indefinitely
6. **Application dependencies and code** — `pip install` / `npm install` bring their own CVE surface; pin and scan in CI regardless of base image

---

A private registry is an access-control boundary, not a patch cycle. CleanStart makes currency a property of the image itself, so it travels with the image no matter which registry it sits behind.