#!/usr/bin/env bash
# audit.sh — a real, reproducible registry staleness audit.
#
# For every image in targets.txt this asks the registry directly — via
# crane, which speaks the registry API without needing a Docker daemon or
# any local cache:
#
#   crane digest <image>   → the current manifest digest
#   crane config <image>   → the image config, including its real build
#                            ("created") timestamp
#
# From that it computes how many days old the image actually is, and flags
# anything past --stale-after days (default 180). It also checks for a
# cosign signature, if cosign is installed.
#
# Nothing here is estimated or simulated. Every number comes straight from
# the registry the image lives in — Docker Hub, your internal Artifactory /
# Nexus / Harbor / ECR mirror, wherever you point it.
#
# Usage:
#   bash audit.sh                    # audit every image in targets.txt
#   bash audit.sh --stale-after 90   # flag anything not rebuilt in 90+ days
#   bash audit.sh postgres           # only targets whose name contains "postgres"

set -euo pipefail

TARGETS_FILE="targets.txt"
RESULTS_DIR="results"
STALE_AFTER=180
FILTER=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stale-after)
      STALE_AFTER="$2"; shift 2 ;;
    --stale-after=*)
      STALE_AFTER="${1#*=}"; shift ;;
    *)
      FILTER="$1"; shift ;;
  esac
done

check_tool() {
  if ! command -v "$1" &>/dev/null; then
    echo ""
    echo "  ❌  '$1' not found."
    echo "  Install: brew install crane"
    echo "     or:  go install github.com/google/go-containerregistry/cmd/crane@latest"
    echo ""
    exit 1
  fi
}
check_tool crane

COSIGN_OK=1
if ! command -v cosign &>/dev/null; then
  COSIGN_OK=0
  echo ""
  echo "  ⚠️   'cosign' not found — signature checks will be skipped (images"
  echo "       will be reported as unverified rather than confirmed unsigned)."
fi

mkdir -p "$RESULTS_DIR"

slugify() {
  echo "$1" | tr '[:upper:]' '[:lower:]' | sed 's|[/:.]\+|-|g' | sed 's|[^a-z0-9-]||g'
}

# Trim leading/trailing whitespace without invoking an external tool —
# xargs interprets stray quote characters (e.g. an apostrophe in a comment
# line) as shell quoting and fails with "unmatched quote", so this stays
# in pure bash parameter expansion instead.
trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

audit_one() {
  local image="$1"
  local slug created age_days digest signed checked_signature

  slug=$(slugify "$image")
  echo ""
  echo "  🔎  $image"

  if ! digest=$(crane digest "$image" 2>/dev/null); then
    echo "      ❌  could not reach registry for $image — skipping"
    return
  fi
  echo "      digest: $digest"

  created=$(crane config "$image" 2>/dev/null | python3 -c "
import json, sys
try:
    print(json.load(sys.stdin).get('created',''))
except Exception:
    print('')
" 2>/dev/null || echo "")

  age_days=""
  if [ -z "$created" ]; then
    echo "      ⚠️   no build timestamp in image config — age unknown"
  else
    age_days=$(python3 -c "
from datetime import datetime, timezone
try:
    c = datetime.fromisoformat('$created'.replace('Z','+00:00'))
    print(max(0, (datetime.now(timezone.utc) - c).days))
except Exception:
    print('')
")
    if [ -n "$age_days" ]; then
      echo "      built:  $created  →  ${age_days} days ago (~$(( age_days / 30 )) months)"
    fi
  fi

  signed=false
  checked_signature=false
  if [ "$COSIGN_OK" -eq 1 ]; then
    checked_signature=true
    if cosign verify "$image" &>/dev/null; then
      signed=true
      echo "      ✅  cosign signature verified"
    else
      echo "      ⚠️   no verifiable cosign signature"
    fi
  fi

  python3 - "$RESULTS_DIR/${slug}.json" "$image" "$digest" "$age_days" "$signed" "$checked_signature" "$STALE_AFTER" << 'PYEOF'
import json, sys
path, image, digest, age_days, signed, checked_signature, stale_after = sys.argv[1:]
entry = {
    "image":               image,
    "digest":              digest,
    "age_days":            int(age_days) if age_days not in ("", "None") else None,
    "signed":              signed == "true",
    "signature_checked":   checked_signature == "true",
    "stale_after_days":    int(stale_after),
}
entry["stale"] = entry["age_days"] is not None and entry["age_days"] > entry["stale_after_days"]
json.dump(entry, open(path, "w"), indent=2)
PYEOF
}

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  staleness-audit"
echo "  crane $(crane version 2>/dev/null | head -1)"
echo "  stale threshold: ${STALE_AFTER} days"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

while IFS= read -r image || [ -n "$image" ]; do
  image="$(trim "$image")"
  [[ "$image" =~ ^#.*$ || -z "$image" ]] && continue
  [[ -n "$FILTER" && "$image" != *"$FILTER"* ]] && continue
  audit_one "$image"
done < "$TARGETS_FILE"

# ── build summary.json from actual result files on disk ───────────────────────
python3 - "$RESULTS_DIR" << 'PYEOF'
import glob, json, os, sys
from datetime import datetime, timezone

results_dir = sys.argv[1]
entries = []
for path in sorted(glob.glob(os.path.join(results_dir, "*.json"))):
    if os.path.basename(path) == "summary.json":
        continue
    entries.append(json.load(open(path)))

ages = [e["age_days"] for e in entries if e.get("age_days") is not None]
stale = [e for e in entries if e.get("stale")]
unsigned = [e for e in entries if e.get("signature_checked") and not e.get("signed")]

summary = {
    "scanned_at":        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "images":            entries,
    "total_images":      len(entries),
    "stale_count":       len(stale),
    "unsigned_count":    len(unsigned),
    "avg_age_days":      round(sum(ages) / len(ages)) if ages else None,
    "oldest_age_days":   max(ages) if ages else None,
}
json.dump(summary, open(os.path.join(results_dir, "summary.json"), "w"), indent=2)

print(f"\n{'━'*52}")
print(f"  Images audited     : {summary['total_images']}")
print(f"  Stale (> threshold): {summary['stale_count']}")
print(f"  Unsigned           : {summary['unsigned_count']}")
if summary["avg_age_days"] is not None:
    print(f"  Avg age            : {summary['avg_age_days']} days (~{round(summary['avg_age_days']/30)} months)")
    print(f"  Oldest             : {summary['oldest_age_days']} days")
print(f"  Results            : {results_dir}/")
print(f"{'━'*52}\n")
PYEOF
