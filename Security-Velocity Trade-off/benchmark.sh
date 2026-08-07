#!/usr/bin/env bash
# benchmark.sh — measures velocity AND security for every image pair
#
# For each image this collects:
#   1. cold pull time      (docker rmi -f && time docker pull)
#   2. compressed size     (docker inspect .Size)
#   3. layer count         (docker history -q | wc -l)
#   4. container start latency  (docker run -d ... → first successful docker exec)
#   5. CVE count            (trivy image, JSON)
#
# Output: results/<slug>.json (one per image) + results/summary.json (combined)
#
# Usage:
#   bash benchmark.sh              # all pairs
#   bash benchmark.sh redis        # only pairs whose name contains "redis"
#   RUNS=3 bash benchmark.sh       # average pull time over N cold pulls (default 1)

set -uo pipefail

IMAGES_FILE="images.txt"
RESULTS_DIR="results"
FILTER="${1:-}"
RUNS="${RUNS:-1}"
START_TIMEOUT="${START_TIMEOUT:-30}"   # seconds to wait for a container to become execable

# ── dependency check ─────────────────────────────────────────────────────────
check_tool() {
  if ! command -v "$1" &>/dev/null; then
    echo ""
    echo "  ❌  '$1' not found."
    case "$1" in
      docker) echo "  Install: https://docs.docker.com/engine/install/" ;;
      trivy)  echo "  Install: curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin" ;;
      python3) echo "  Install python3 via your package manager." ;;
    esac
    echo ""
    exit 1
  fi
}
check_tool docker
check_tool trivy
check_tool python3

mkdir -p "$RESULTS_DIR"

if grep -q $'\r' "$IMAGES_FILE" 2>/dev/null; then
  echo "  ℹ️   $IMAGES_FILE has Windows-style line endings (CRLF) — handled automatically,"
  echo "      but running 'sed -i \"s/\\r\$//\" $IMAGES_FILE' once will clean it up for good."
fi

# ── slugify: must match the Python version in analyze.py exactly ─────────────
slugify() {
  echo "$1" | tr '[:upper:]' '[:lower:]' | sed 's|[/:.]\+|-|g' | sed 's|[^a-z0-9-]||g'
}

# ── portable high-resolution timer (seconds, float) ───────────────────────────
now() { python3 -c 'import time; print(time.time())'; }
elapsed() { python3 -c "print(round($2 - $1, 2))"; }

# ── cold pull timing, averaged over $RUNS runs ────────────────────────────────
# PRUNE_MODE controls how "cold" the cache is before each timed pull:
#   tag  (default) — docker rmi -f the specific image only. FAST, but layers
#                     shared with any other image already on this host (e.g. a
#                     common Debian base layer pulled earlier in the same run)
#                     stay cached, so this pull can look artificially fast.
#   full            — docker system prune -af --volumes before every single
#                     pull. SLOW (re-downloads shared layers every time) but
#                     gives a genuinely isolated, publishable cold-pull number.
# For a number you're going to put in a report, use: PRUNE_MODE=full bash benchmark.sh
PRUNE_MODE="${PRUNE_MODE:-tag}"

time_pull() {
  local image="$1" total=0 i t0 t1 d err_log attempt
  err_log=$(mktemp)
  for ((i = 1; i <= RUNS; i++)); do
    if [ "$PRUNE_MODE" = "full" ]; then
      docker system prune -af --volumes >/dev/null 2>&1 || true
    else
      docker rmi -f "$image" >/dev/null 2>&1 || true
    fi
    t0=$(now)
    for attempt in 1 2; do
      if docker pull -q "$image" >"$err_log" 2>&1; then
        break
      elif [ "$attempt" = "1" ]; then
        echo "      ↻  pull failed, retrying once (transient network / registry hiccup)..." >&2
        sleep 3
      else
        echo "" >&2
        echo "      ⚠️  docker pull failed for $image after retry:" >&2
        sed 's/^/         /' "$err_log" >&2
        rm -f "$err_log"
        echo "-1"; return
      fi
    done
    t1=$(now)
    d=$(elapsed "$t0" "$t1")
    total=$(python3 -c "print($total + $d)")
  done
  rm -f "$err_log"
  python3 -c "print(round($total / $RUNS, 2))"
}

# ── image size (bytes) and layer count ────────────────────────────────────────
image_size() { docker image inspect "$1" --format '{{.Size}}' 2>/dev/null || echo "0"; }
# RootFS.Layers reflects the actual number of filesystem layers in the pulled
# image, regardless of whether intermediate build IDs are locally known — unlike
# `docker history -q`, which collapses to ~1 for any image you didn't build yourself.
layer_count() { docker image inspect "$1" --format '{{len .RootFS.Layers}}' 2>/dev/null || echo "0"; }

# ── time from `docker run -d` to the first successful `docker exec` ──────────
# Falls back to SKIP (-1) for fully distroless images with no shell at all —
# that's a known architectural characteristic, not a defect.
start_latency() {
  local image="$1" cname="bench_$(slugify "$image")_$$"
  docker rm -f "$cname" >/dev/null 2>&1 || true

  # Try to override the entrypoint with a long-lived shell sleep so we can
  # exec into it repeatedly. If the image has no shell (fully distroless),
  # fall back to running its own entrypoint and timing until State.Running.
  local cid=""
  cid=$(docker run -d --name "$cname" "$image" sh -c "sleep 300" 2>/dev/null)
  local used_shell=1
  if [ -z "$cid" ]; then
    used_shell=0
    # The failed attempt above still registers a container object under
    # $cname (even though it never ran) — remove it before reusing the name,
    # or this second `docker run` fails with "name already in use" too.
    docker rm -f "$cname" >/dev/null 2>&1 || true
    cid=$(docker run -d --name "$cname" "$image" 2>/dev/null)
  fi
  if [ -z "$cid" ]; then
    echo "-1"; return
  fi

  local t0 t1 ready=0
  t0=$(now)
  local deadline=$((SECONDS + START_TIMEOUT))
  while [ $SECONDS -lt $deadline ]; do
    if [ "$used_shell" = "1" ]; then
      # shell-having image: exec success is the readiness signal
      if docker exec "$cname" true >/dev/null 2>&1; then ready=1; break; fi
    else
      # distroless: no shell to exec into — State.Running is the best proxy
      if [ "$(docker inspect -f '{{.State.Running}}' "$cname" 2>/dev/null)" = "true" ]; then
        ready=1; break
      fi
    fi
    sleep 0.2
  done
  t1=$(now)
  docker rm -f "$cname" >/dev/null 2>&1 || true

  if [ "$ready" = "0" ]; then echo "-1"; return; fi
  elapsed "$t0" "$t1"
}

# ── CVE count via trivy image scan ────────────────────────────────────────────
scan_cves() {
  local image="$1" out="$2"
  trivy image "$image" --format json --quiet --output "$out" 2>/dev/null
}

inject_and_print() {
  local file="$1" image="$2" itype="$3" pull="$4" size="$5" layers="$6" start="$7"
  python3 - "$file" "$image" "$itype" "$pull" "$size" "$layers" "$start" << 'PYEOF'
import json, sys
file, image, itype, pull, size, layers, start = sys.argv[1:8]
try:
    d = json.load(open(file))
except Exception:
    d = {"Results": []}
total = sum(len(r.get("Vulnerabilities") or []) for r in d.get("Results", []))
d["_meta"] = {
    "image": image, "image_type": itype, "total_cves": total,
    "pull_time_sec": float(pull), "size_bytes": int(size),
    "layers": int(layers), "start_latency_sec": float(start),
}
json.dump(d, open(file, "w"), indent=2)
print(f"      cves:{total:<4} pull:{float(pull):>6}s  size:{int(size)/1e6:>7.1f}MB  "
      f"layers:{layers:<3} start:{float(start):>5}s")
PYEOF
}

NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  security-velocity-tradeoff"
echo "  docker  $(docker --version)"
echo "  trivy   $(trivy --version 2>/dev/null | head -1)"
echo "  runs per pull: $RUNS"
echo "  prune mode: $PRUNE_MODE$( [ "$PRUNE_MODE" = "tag" ] && echo '  (fast, but shared base layers between images may stay cached — see PRUNE_MODE=full for publishable numbers)' )"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

while IFS='|' read -r pub cs; do
  pub="$(echo "$pub" | xargs)"
  cs="$(echo "$cs"   | xargs)"
  # Strip stray carriage returns (CRLF line endings — common when images.txt
  # has passed through Windows git/editors, e.g. core.autocrlf=true) since a
  # trailing \r baked into the image string makes docker reject it as an
  # "invalid reference format" with no useful clue why.
  pub="${pub//$'\r'/}"
  cs="${cs//$'\r'/}"
  [[ "$pub" =~ ^#.*$ || -z "$pub" ]] && continue
  [[ -n "$FILTER" && "$pub$cs" != *"$FILTER"* ]] && continue

  for entry in "$pub:public" "$cs:cleanstart"; do
    itype="${entry##*:}"      # last colon-separated field: "public" or "cleanstart"
    image="${entry%:*}"       # everything before it — safe even though image tags contain ":"

    slug=$(slugify "$image")
    out="$RESULTS_DIR/${slug}.trivy.json"

    icon="📦"; [ "$itype" = "cleanstart" ] && icon="🛡️ "
    echo ""
    echo "  $icon  ${itype^^}   $image"

    echo "      [1/3] cold pull ×$RUNS"
    pull=$(time_pull "$image")
    if [ "$pull" = "-1" ]; then
      echo "      ⚠️  pull failed — skipping remaining checks for this image"
      continue
    fi

    size=$(image_size "$image")
    layers=$(layer_count "$image")

    echo "      [2/3] container start latency"
    start=$(start_latency "$image")

    echo "      [3/3] trivy CVE scan"
    scan_cves "$image" "$out"

    inject_and_print "$out" "$image" "$itype" "$pull" "$size" "$layers" "$start"
  done

done < <(cat "$IMAGES_FILE"; echo)

# ── build summary.json from actual per-image files on disk ───────────────────
python3 - "$RESULTS_DIR" "$IMAGES_FILE" "$NOW" << 'PYEOF'
import json, os, re, sys

results_dir, images_file, ts = sys.argv[1:]

def slugify(s):
    return re.sub(r'[^a-z0-9-]', '', re.sub(r'[/:.]+', '-', s.lower()))

def load(image):
    path = os.path.join(results_dir, slugify(image) + ".trivy.json")
    if not os.path.exists(path):
        return None
    d = json.load(open(path))
    meta = d.get("_meta", {})
    return {
        "image":             image,
        "image_type":        meta.get("image_type", "unknown"),
        "total_cves":        meta.get("total_cves", 0),
        "pull_time_sec":     meta.get("pull_time_sec", -1),
        "size_bytes":        meta.get("size_bytes", 0),
        "layers":            meta.get("layers", 0),
        "start_latency_sec": meta.get("start_latency_sec", -1),
        "trivy_file":        os.path.basename(path),
    }

pairs, images_out = [], []
with open(images_file) as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith('#') or '|' not in line:
            continue
        pub_img, cs_img = [x.strip() for x in line.split('|', 1)]
        pub_e, cs_e = load(pub_img), load(cs_img)
        if not pub_e or not cs_e:
            print(f"  ⚠️  missing results for {pub_img} / {cs_img} — run benchmark.sh for this pair")
            continue
        images_out.extend([pub_e, cs_e])

        def pct_change(pub_v, cs_v, lower_is_better=True):
            if pub_v is None or cs_v is None or pub_v < 0 or cs_v < 0 or pub_v == 0:
                return None
            change = (cs_v - pub_v) / pub_v * 100
            return round(change, 1)

        pairs.append({
            "public": pub_e, "cleanstart": cs_e,
            "cve_reduction_pct":   round((1 - cs_e["total_cves"] / max(pub_e["total_cves"], 1)) * 100),
            "pull_time_delta_pct": pct_change(pub_e["pull_time_sec"], cs_e["pull_time_sec"]),
            "size_delta_pct":      pct_change(pub_e["size_bytes"], cs_e["size_bytes"]),
            "start_delta_pct":     pct_change(pub_e["start_latency_sec"], cs_e["start_latency_sec"]),
        })

summary = {"scanned_at": ts, "pairs": pairs, "images": images_out}
json.dump(summary, open(os.path.join(results_dir, "summary.json"), "w"), indent=2)

print(f"\n{'━'*52}")
print(f"  Pairs benchmarked: {len(pairs)}")
print(f"  Summary written  : {results_dir}/summary.json")
print(f"{'━'*52}\n")
PYEOF