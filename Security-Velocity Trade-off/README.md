# Security-Velocity Trade-off: Why Zero-CVE Doesn't Mean Slow Builds

> A runnable benchmark that measures **security** (CVE count, via trivy) and **velocity**
> (cold pull time, image size, container start latency, via docker) for the same six
> image pairs, in the same run, so the "hardened = slower" assumption can be checked
> against numbers instead of intuition.

---

## The problem and the vision

The most common objection to switching to hardened, patched base images is a velocity
argument, not a security one: *"sure, fewer CVEs — but doesn't that come from more layers,
bigger scanning overhead, slower pulls, slower cold starts?"* It's a reasonable question.
Reducing attack surface sounds like it should cost something somewhere.

It usually doesn't, because the CVE reduction and the velocity gain come from the **same
root cause**: removing packages the application doesn't need. A base image with 400 OS
packages the app never touches isn't just carrying CVE risk from all 400 — it's also
carrying their disk bytes, their layer weight, and their init-time cost. Stripping them
out helps both numbers at once. There's no lever being traded here; it's the same lever.

This repo tests that claim directly: pull time, image size, and container start latency for six public Docker Hub images, measured back-to-back against their CleanStart counterparts.

---

## What's actually being measured

| Metric | What it captures | Tool |
|---|---|---|
| Cold pull time | Time to pull the image with no local cache — the number CI sees on every fresh runner | `docker rmi -f && time docker pull` |
| Compressed image size | Bytes transferred over the network and stored in the registry/cache | `docker image inspect .Size` |
| Layer count | Structural complexity of the image | `docker history` |
| Container start latency | Time from `docker run -d` to the container being exec-able (or `Running` for fully distroless images) | `docker run` + polling `docker exec` |
| CVE count | Security posture at time of scan | `trivy image` |

None of these are proxies or estimates — every number in the dashboard comes from an
actual `docker pull`, `docker run`, and `trivy image` invocation against the real image.

---

## Project structure

```
security-velocity-tradeoff/
├── images.txt          ← 6 image pairs: public | cleanstart
├── benchmark.sh         ← Step 1: pull timing, size, start latency, trivy CVE scan
├── analyze.py           ← Step 2: aggregate results, generate HTML dashboard
├── results/             ← created by benchmark.sh — one .trivy.json per image + summary.json
└── docs/
    └── index.html       ← created by analyze.py — comparison dashboard
```

---

## Prerequisites

**docker** — pulls and runs the images being benchmarked

```bash
# Linux
curl -fsSL https://get.docker.com | sh # Install docker
docker --version
```

**trivy** — scans each image for CVEs

```bash
curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin # Install trivy
trivy --version
```

Python 3.8+ is also required. No extra packages needed.

> Run this on a machine (or CI runner) where you can freely `docker pull` / `docker rmi`
> the images below — the pull-time measurement removes any local copy first to get a
> true cold-cache number.

---

## Run it

### Step 1 — Benchmark all image pairs

```bash
PRUNE_MODE=full bash benchmark.sh
```

For each pair in `images.txt` this runs:

```bash
docker rmi -f <image>                       # force a cold cache
time docker pull <image>                    # pull time
docker image inspect <image> --format '{{.Size}}'   # size
docker run -d <image> sh -c 'sleep 300'     # start latency probe
docker exec <container> true                # polled until it succeeds
trivy image <image> --format json           # CVE scan
```

First run takes several minutes — trivy downloads its vulnerability database (~200 MB)
and every image is pulled twice (once cold, once for the size/start checks). Subsequent
runs are faster since trivy's DB is cached.

To benchmark a single pair, or to average pull time over more than one cold pull:

```bash
bash benchmark.sh redis
RUNS=3 bash benchmark.sh          # average cold pull time over 3 runs
```

### Step 2 — Generate the dashboard

```bash
python3 analyze.py
```

Reads `results/summary.json`, computes per-pair and aggregate deltas, and writes
`docs/index.html`.

### Step 3 — Open the report

```bash
# Linux / WSL
cd docs && python3 -m http.server 8181
# then open http://localhost:8181
```

---

## Run individual commands manually

```bash
# Cold pull time for one image
docker rmi -f cleanstart/postgres:latest
time docker pull cleanstart/postgres:latest

# Compressed size in MB
docker image inspect cleanstart/postgres:latest --format '{{.Size}}' \
  | awk '{printf "%.1f MB\n", $1/1e6}'

# Layer count
docker history -q cleanstart/postgres:latest | grep -vc '<missing>'

# Start latency — run, then measure exec responsiveness
docker run -d --name probe cleanstart/postgres:latest sh -c 'sleep 300'
time (until docker exec probe true 2>/dev/null; do sleep 0.1; done)
docker rm -f probe

# CVE count
trivy image cleanstart/postgres:latest --severity HIGH,CRITICAL
```

---

## Why the numbers move together, not apart

The mechanism is structural, not incidental:

1. **Fewer packages → fewer CVEs.** A CVE can only exist in code that's present in the
   image. CleanStart images ship only what the runtime needs, so most CVE-bearing OS
   utilities were never in the image to begin with.
2. **Fewer packages → fewer bytes.** The same packages that carry CVE risk also carry
   disk weight. Removing them shrinks the image on the same axis it de-risks it.
3. **Smaller image → less to pull.** Pull time is dominated by bytes transferred, not
   layer count. A smaller image pulls faster on the same network, every time.
4. **Less to initialize → faster start.** Container start latency is driven by what the
   entrypoint and init scripts have to touch on disk. Less surface area to initialize
   means less to wait on before the container is usable.

There's no separate "hardening pass" bolted on after the fact that could plausibly slow
things down — the reduction *is* the hardening.

---

## What's still your responsibility

This benchmark isolates the base image layer. It does not measure, and cannot speak to:

1. **Application build time** — your own `RUN pip install` / `npm install` / compile
   steps sit on top of the base image and are unaffected by which base you choose
2. **Application startup time** — your app's own init logic (migrations, cache warmup,
   config loading) dominates real-world cold start far more than the base image does
3. **Network conditions** — pull time numbers here are relative (public vs. CleanStart on
   the same network at the same time), not absolute — re-run in your own environment
4. **Runtime CVEs** — CVEs disclosed after this scan ran aren't reflected; re-run
   `benchmark.sh` periodically rather than treating one report as permanent

---

The base image is the one layer every container shares. Making it both smaller and
safer isn't two projects — it's one.