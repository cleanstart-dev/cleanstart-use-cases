#!/usr/bin/env bash
# scan.sh — syft SBOM → trivy CVE scan for every image pair
#
# Step 1: syft  → sboms/<slug>.sbom.json      (CycloneDX SBOM)
# Step 2: trivy → scan_results/<slug>.trivy.json  (CVE report)
#
# Usage:
#   bash scan.sh              # all pairs
#   bash scan.sh python       # only pairs whose name contains "python"

set -euo pipefail

IMAGES_FILE="images.txt"
SBOM_DIR="sboms"
RESULTS_DIR="scan_results"
FILTER="${1:-}"

# ── dependency check ──────────────────────────────────────────────────────────
check_tool() {
  if ! command -v "$1" &>/dev/null; then
    echo ""
    echo "  ❌  '$1' not found."
    if [ "$1" = "syft" ]; then
      echo "  Install: brew install syft"
      echo "     or:  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin"
    else
      echo "  Install: brew install trivy"
      echo "     or:  curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin"
    fi
    echo ""
    exit 1
  fi
}
check_tool syft
check_tool trivy

mkdir -p "$SBOM_DIR" "$RESULTS_DIR"

# ── slugify: must match the Python version in analyze.py exactly ──────────────
slugify() {
  echo "$1" | tr '[:upper:]' '[:lower:]' | sed 's|[/:.]\+|-|g' | sed 's|[^a-z0-9-]||g'
}

# ── inject _meta into trivy JSON so analyze.py knows image name/type ──────────
inject_meta() {
  local file="$1" image="$2" itype="$3" pub_file="${4:-}"
  python3 - "$file" "$image" "$itype" "$pub_file" << 'PYEOF'
import json, sys
file, image, itype = sys.argv[1], sys.argv[2], sys.argv[3]
pub_file = sys.argv[4] if len(sys.argv) > 4 else ""
d = json.load(open(file))
total = sum(len(r.get("Vulnerabilities") or []) for r in d.get("Results", []))
meta  = {"image": image, "image_type": itype, "total_cves": total}
if pub_file:
    try:
        pub_total = json.load(open(pub_file))["_meta"]["total_cves"]
        meta["reduction_pct"] = round((1 - total / max(pub_total, 1)) * 100)
    except Exception:
        pass
d["_meta"] = meta
json.dump(d, open(file, "w"), indent=2)
PYEOF
}

# ── print CVE counts from a trivy JSON file ───────────────────────────────────
print_counts() {
  python3 - "$1" << 'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
c = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
total = 0
for r in d.get("Results", []):
    for v in r.get("Vulnerabilities") or []:
        s = v.get("Severity","LOW"); c[s]=c.get(s,0)+1; total+=1
extra = f"  |  reduction: {d['_meta']['reduction_pct']}%" if d.get("_meta",{}).get("reduction_pct") is not None else ""
print(f"      {total} CVEs  |  C:{c['CRITICAL']}  H:{c['HIGH']}  M:{c['MEDIUM']}  L:{c['LOW']}{extra}")
PYEOF
}

NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  patch-treadmill"
echo "  syft  $(syft version 2>/dev/null | grep -i 'application version' | awk '{print $NF}' || syft version 2>/dev/null | head -1)"
echo "  trivy $(trivy --version 2>/dev/null | head -1)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── scan loop ─────────────────────────────────────────────────────────────────
while IFS='|' read -r pub cs; do
  pub="$(echo "$pub" | xargs)"
  cs="$(echo "$cs"   | xargs)"
  [[ "$pub" =~ ^#.*$ || -z "$pub" ]] && continue
  [[ -n "$FILTER" && "$pub$cs" != *"$FILTER"* ]] && continue

  PUB_SLUG=$(slugify "$pub")
  CS_SLUG=$(slugify  "$cs")
  PUB_SBOM="$SBOM_DIR/${PUB_SLUG}.sbom.json"
  CS_SBOM="$SBOM_DIR/${CS_SLUG}.sbom.json"
  PUB_TRIVY="$RESULTS_DIR/${PUB_SLUG}.trivy.json"
  CS_TRIVY="$RESULTS_DIR/${CS_SLUG}.trivy.json"

  echo ""
  echo "  📦  PUBLIC     $pub"
  echo "      [1/2] syft → SBOM"
  syft "$pub" --output "cyclonedx-json=$PUB_SBOM" --quiet
  echo "      [2/2] trivy → CVE scan"
  trivy sbom "$PUB_SBOM" --format json --output "$PUB_TRIVY" --quiet
  inject_meta "$PUB_TRIVY" "$pub" "public"
  print_counts "$PUB_TRIVY"

  echo ""
  echo "  🛡️   CLEANSTART  $cs"
  echo "      [1/2] syft → SBOM"
  syft "$cs" --output "cyclonedx-json=$CS_SBOM" --quiet
  echo "      [2/2] trivy → CVE scan"
  trivy sbom "$CS_SBOM" --format json --output "$CS_TRIVY" --quiet
  inject_meta "$CS_TRIVY" "$cs" "cleanstart" "$PUB_TRIVY"
  print_counts "$CS_TRIVY"

done < "$IMAGES_FILE"

# ── build summary.json from actual files on disk ──────────────────────────────
python3 - "$RESULTS_DIR" "$IMAGES_FILE" "$NOW" << 'PYEOF'
import json, os, re, sys

results_dir, images_file, ts = sys.argv[1:]

def slugify(s):
    return re.sub(r'[^a-z0-9-]', '', re.sub(r'[/:.]+', '-', s.lower()))

def load_entry(path, image, itype):
    d = json.load(open(path))
    counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"UNKNOWN":0}
    fixable = 0
    for r in d.get("Results", []):
        for v in r.get("Vulnerabilities") or []:
            s = v.get("Severity","UNKNOWN")
            counts[s] = counts.get(s,0) + 1
            if v.get("FixedVersion"): fixable += 1
    total = d.get("_meta", {}).get("total_cves", sum(counts.values()))
    return {
        "image":       image,
        "image_type":  itype,
        "total_cves":  total,
        "by_severity": counts,
        "fixable":     fixable,
        "trivy_file":  os.path.basename(path),
        "sbom_file":   slugify(image) + ".sbom.json",
    }

pairs_out, images_out = [], []
total_pub, total_cs = 0, 0

with open(images_file) as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith('#') or '|' not in line:
            continue
        pub_img, cs_img = [x.strip() for x in line.split('|', 1)]
        pub_path = os.path.join(results_dir, slugify(pub_img) + ".trivy.json")
        cs_path  = os.path.join(results_dir, slugify(cs_img)  + ".trivy.json")
        if not os.path.exists(pub_path):
            print(f"  ⚠️  missing: {pub_path}"); continue
        if not os.path.exists(cs_path):
            print(f"  ⚠️  missing: {cs_path}");  continue
        pub_e = load_entry(pub_path, pub_img, "public")
        cs_e  = load_entry(cs_path,  cs_img,  "cleanstart")
        reduction = round((1 - cs_e["total_cves"] / max(pub_e["total_cves"], 1)) * 100)
        total_pub += pub_e["total_cves"]
        total_cs  += cs_e["total_cves"]
        images_out.extend([pub_e, cs_e])
        pairs_out.append({"public": pub_e, "cleanstart": cs_e, "reduction_pct": reduction})

avg_red = round((1 - total_cs / max(total_pub, 1)) * 100)
summary = {
    "scanned_at":            ts,
    "pairs":                 pairs_out,
    "images":                images_out,
    "total_public_cves":     total_pub,
    "total_cleanstart_cves": total_cs,
    "avg_reduction_pct":     avg_red,
}
out = os.path.join(results_dir, "summary.json")
json.dump(summary, open(out, "w"), indent=2)

print(f"\n{'━'*52}")
print(f"  Total public CVEs    : {total_pub}")
print(f"  Total CleanStart CVEs: {total_cs}")
print(f"  Average reduction    : {avg_red}%")
print(f"  SBOMs                : sboms/")
print(f"  Scan results         : {results_dir}/")
print(f"{'━'*52}\n")
PYEOF
