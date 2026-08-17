#!/usr/bin/env bash
# scan.sh — syft SBOM + crane runtime config for every image pair
#
# Step 1: syft  → sboms/<slug>.sbom.json     (CycloneDX SBOM — package inventory)
# Step 2: crane → configs/<slug>.config.json (OCI image config — default user, entrypoint)
#
# The SBOM tells us the attack surface (what packages could carry the next
# zero-day). The image config tells us the blast radius (what an attacker gets
# if that package is exploited before a patch exists — root or not, shell or not).
#
# Usage:
#   bash scan.sh              # all pairs
#   bash scan.sh python       # only pairs whose name contains "python"

set -euo pipefail

IMAGES_FILE="images.txt"
SBOM_DIR="sboms"
CONFIG_DIR="configs"
FILTER="${1:-}"

# ── dependency check ──────────────────────────────────────────────────────────
check_tool() {
  if ! command -v "$1" &>/dev/null; then
    echo ""
    echo "  ❌  '$1' not found."
    case "$1" in
      syft)
        echo "  Install: brew install syft"
        echo "     or:  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin"
        ;;
      crane)
        echo "  Install: brew install crane"
        echo "     or:  go install github.com/google/go-containerregistry/cmd/crane@latest"
        ;;
    esac
    echo ""
    exit 1
  fi
}
check_tool syft
check_tool crane

mkdir -p "$SBOM_DIR" "$CONFIG_DIR"

# ── slugify: must match the Python version in exposure_audit.py exactly ───────
slugify() {
  echo "$1" | tr '[:upper:]' '[:lower:]' | sed 's|[/:.]\+|-|g' | sed 's|[^a-z0-9-]||g'
}

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  zero-day-exposure"
echo "  syft  $(syft version 2>/dev/null | grep -i 'application version' | awk '{print $NF}' || true)"
echo "  crane $(crane version 2>/dev/null | head -1 || true)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

scan_one() {
  local image="$1" label="$2"
  local slug; slug=$(slugify "$image")
  local sbom="$SBOM_DIR/${slug}.sbom.json"
  local cfg="$CONFIG_DIR/${slug}.config.json"

  echo ""
  echo "  ${label}  ${image}"
  echo "      [1/2] syft  → SBOM"
  syft "$image" --output "cyclonedx-json=$sbom" --quiet

  echo "      [2/2] crane → image config"
  if crane config "$image" > "$cfg" 2>/dev/null; then
    local user; user=$(python3 -c "import json;print(json.load(open('$cfg')).get('config',{}).get('User',''))" 2>/dev/null || echo "")
    echo "            default user: '${user:-<empty — root>}'"
  else
    echo "            ⚠️  crane config failed (registry auth / arch mismatch) — SKIP, runtime posture will be marked unknown"
    rm -f "$cfg"
  fi
}

while IFS='|' read -r pub cs; do
  pub="$(echo "$pub" | xargs)"
  cs="$(echo "$cs"   | xargs)"
  [[ "$pub" =~ ^#.*$ || -z "$pub" ]] && continue
  [[ -n "$FILTER" && "$pub$cs" != *"$FILTER"* ]] && continue

  scan_one "$pub" "📦  PUBLIC    "
  scan_one "$cs"  "🛡️   CLEANSTART"
done < "$IMAGES_FILE"

echo ""
echo "Done. Run: python3 exposure_audit.py"
echo ""
