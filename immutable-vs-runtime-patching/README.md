# Immutable Infrastructure vs. Runtime Patching: Choosing Your Security Model

> A runnable demo contrasting two ways to answer "we just got a critical CVE — now what": **patching a running container from a public base image** versus **rebuilding and redeploying a CleanStart image**. Same CVE, same deadline, two companies, two artifacts at the end.

---

## The problem and the vision

Most incident response for container vulnerabilities assumes patching means *changing a running thing*: exec into the container, run the package manager, hope the fix applies cleanly, hope every other host gets the same fix the same way. That model works, right up until someone asks "prove every host is patched" and the honest answer requires re-scanning the whole fleet, because the patched state was never captured anywhere except inside each container's own filesystem.

A different approach is to make the running container immutable and treat every patch as a new build.

→ Nothing is ever patched in place — there's no shell or package manager in the image to do it with.

→ A patch is a rebuilt image, a new signed digest, and a redeploy. Every host that pulls it gets the exact same bytes.

Nothing in that workflow depends on remembering which hosts were patched by hand and which weren't.

This repo demonstrates the gap with two runnable scripts: **Company A** patches a public base image's running container in place; **Company B** hits the same scenario against a CleanStart image, which has no in-place patch path at all.

---

## What "architectural" means here, concretely

| Layer | Company A — public image, runtime patching | Company B — CleanStart image, immutable rebuild |
|---|---|---|
| Base image | `python:3.14.7` (or any public Docker Hub image) — full OS layer, shell, package manager | `cleanstart/python:latest` — minimal, no shell, no package manager |
| How a CVE gets fixed | `docker exec` into the running container, run `apt-get upgrade`, hope it applies cleanly | Pull the new tag; the fixed digest is the only thing that ships |
| What proves the fix was applied | Re-scanning the container's live filesystem, host by host | Comparing the running digest against the CVE feed's fixed-version SBOM |
| Rollback | Reconstruct whatever the pre-patch state was — often undocumented | Redeploy the previous digest, byte-for-byte identical to what was already running |
| Fleet consistency | Depends on every host being patched the same way, in order | Guaranteed — every replica pulls the same digest |
| Artifact left behind | None — the patch lives only in that container's filesystem until it's destroyed | A new signed image with SBOM + provenance attached |

---

## Real numbers behind "no shell to patch"

Scanned six public/CleanStart image pairs with syft + trivy. The counts are the reason Company B has nothing to patch in the first place:

| Public image | CVEs | CleanStart image | CVEs |
|---|---|---|---|
| `python:3.14.7` | 151 | `cleanstart/python:latest` | 0 |
| `node:26.7.0` | 150 | `cleanstart/node:latest` | 2 |
| `nginx:1.31.1` | 43 | `cleanstart/nginx:latest` | 0 |
| `postgres:18.4` | 68 | `cleanstart/postgres:latest` | 0 |

---

## Project structure

```
immutable-vs-runtime-patching/
├── images.txt                       ← public | cleanstart image pairs
├── company-a-runtime-patch.sh       ← patches a running public-image container in place
├── company-b-immutable-rebuild.sh   ← shows the CleanStart image has no in-place patch path
├── compare-drift.py                 ← summarizes what each script captured
└── results/                         ← created by the scripts
```

---

## Prerequisites

**Docker**, running locally, with pull access to Docker Hub and the CleanStart registry.

```bash
docker --version
```

Python 3.8+ for `compare-drift.py`. No extra packages needed.

---

## Run it

### Step 1 — Company A: patch a public image in place

```bash
bash company-a-runtime-patch.sh python:3.14.7
```

This starts a container from the public image, snapshots its installed packages, runs `apt-get upgrade` inside the running container, and snapshots again. Results land in `results/company-a-*.txt`.

### Step 2 — Company B: try the same thing against a CleanStart image

```bash
bash company-b-immutable-rebuild.sh cleanstart/python:latest
```

This pulls the CleanStart image, records its digest, attempts to exec a shell into it (there isn't one), and re-pulls the tag to show the digest is the only thing that changes between "before" and "after." Results land in `results/company-b-*.txt`.

### Step 3 — Compare

```bash
python3 compare-drift.py
```

Prints how much Company A's container drifted from its own starting image, versus whether Company B's digest is reproducible across a re-pull.

To run against a different pair, use any line from `images.txt`:

```bash
bash company-a-runtime-patch.sh node:26.7.0
bash company-b-immutable-rebuild.sh cleanstart/node:latest
python3 compare-drift.py
```

---

| Time | Company A — public image, runtime patching | Company B — CleanStart image, immutable rebuild |
|---|---|---|
| **Hour 0** — CVE drops | No single source of truth for what's installed where — 18 months of hosts built by different teams, some patched by hand under past deadlines. "Are we affected?" means an hour of reconciling disagreeing scanners against a fleet nobody has a complete inventory of. | Queries the SBOM attached to the exact digest already running in production. "Are we affected?" is a fifteen-minute SBOM diff. |
| **Hours 1–4** — applying the fix | Execs into each host, runs the package manager, restarts the service, and hopes the running state now matches what configuration management thinks it should — it usually doesn't, everywhere, because manual fixes under past deadlines never made it back into the playbooks. | Rebuilds the base image with the fixed library, gets a new digest, and rolls it out the same way every deployment happens: replace, don't mutate. |
| **Hours 1–4** — rollback path | Reconstructing whatever the pre-patch state was. | Redeploying the previous digest — byte-for-byte identical to what was already running. |
| **Hours 4–8** — proving it | Re-scans the fleet to answer "are we fully patched?" and finds two hosts still vulnerable — an autoscaling group whose base image was never rebuilt spun up new instances mid-incident that came back vulnerable. | Answers with the new digest and its SBOM, verifiable with `cosign verify`; there's no path for a host to silently run anything else, because there's no mechanism for in-place mutation in the first place. |
---

## What's still your responsibility

Neither model — immutable or runtime-patched — removes these:

1. **Application dependencies** — `pip install` / `npm install` bring their own CVE surface regardless of base image; pin and scan in CI
2. **Your application code** — SAST on every PR
3. **Container runtime config** — non-root user, read-only rootfs, dropped capabilities in your pod spec
4. **Network policy** — ingress/egress restrictions
5. **Secrets management** — never bake secrets into images or plain-text environment variables
6. **Runtime detection** — anomaly detection post-deploy, regardless of which base image you run

---

Immutable infrastructure moves the hardest part of incident response — figuring out what's actually running — out of the incident and into the pipeline. For workloads that can support a fast rebuild-and-redeploy pipeline, that's a smaller blast radius and a shorter incident. For stateful systems that can't be replaced wholesale, runtime patching with real drift detection is still the honest answer — this repo demonstrates the tradeoff, not a universal verdict.
