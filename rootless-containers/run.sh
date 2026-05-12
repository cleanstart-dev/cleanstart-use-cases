#!/usr/bin/env bash
# ============================================================
#  Rootless Containers — Security Theater or Real Protection?
#  Uses SBOM-based scanning (syft + grype) for proper analysis
# ============================================================
set -e

echo ""
echo "=============================================================="
echo "  Building 2 images..."
echo "=============================================================="

docker build -q -f Dockerfile.rootless   -t demo-rootless:latest   . > /dev/null && echo "  [OK] demo-rootless   (python:3.14 + USER appuser)"
docker build -q -f Dockerfile.cleanstart -t demo-cleanstart:latest . > /dev/null && echo "  [OK] demo-cleanstart (CleanStart + USER clnstrt)"

echo ""
echo "=============================================================="
echo "  TEST 1 — Effective UID inside container"
echo "=============================================================="
echo ""
echo "  -- rootless --"
docker run --rm demo-rootless:latest | sed 's/^/    /'
echo ""
echo "  -- cleanstart --"
docker run --rm demo-cleanstart:latest | sed 's/^/    /'

echo ""
echo "=============================================================="
echo "  TEST 2 — Generating SBOMs with Syft"
echo "=============================================================="
echo ""
syft demo-rootless:latest   -o spdx-json > rootless-sbom.json 2>/dev/null
syft demo-cleanstart:latest -o spdx-json > cleanstart-sbom.json 2>/dev/null
syft demo-rootless:latest   -o table > rootless-sbom.txt 2>/dev/null
syft demo-cleanstart:latest -o table > cleanstart-sbom.txt 2>/dev/null

ROOTLESS_PKGS=$(grep -c "^[a-z]" rootless-sbom.txt || echo "0")
CLEANSTART_PKGS=$(grep -c "^[a-z]" cleanstart-sbom.txt || echo "0")

echo "  Rootless image:   $ROOTLESS_PKGS packages"
echo "  CleanStart image: $CLEANSTART_PKGS packages"
echo ""
REDUCTION=$(awk "BEGIN {printf \"%.1f\", (($ROOTLESS_PKGS - $CLEANSTART_PKGS) / $ROOTLESS_PKGS) * 100}")
echo "  >>> Attack surface reduction: $REDUCTION%"

echo ""
echo "=============================================================="
echo "  TEST 3 — Dangerous binaries inside the image"
echo "=============================================================="
echo ""
printf "  %-8s %-12s %-12s\n" "binary" "rootless" "cleanstart"
printf "  %-8s %-12s %-12s\n" "------" "--------" "----------"

check() {
  local img=$1; local bin=$2
  if docker run --rm --entrypoint="" "$img" sh -c "command -v $bin" >/dev/null 2>&1; then
    echo "PRESENT"
  else
    echo "ABSENT"
  fi
}

for bin in bash sh apt gcc curl wget; do
  printf "  %-8s %-12s %-12s\n" \
    "$bin" \
    "$(check demo-rootless:latest   $bin)" \
    "$(check demo-cleanstart:latest $bin)"
done

echo ""
echo "=============================================================="
echo "  TEST 4 — Vulnerability scan via Grype (SBOM-based)"
echo "=============================================================="
echo ""
echo "  -- rootless --"
grype sbom:rootless-sbom.json 2>/dev/null | tail -5 | head -3
echo ""
echo "  -- cleanstart --"
grype sbom:cleanstart-sbom.json 2>/dev/null | tail -5 | head -3

echo ""
echo "=============================================================="
echo "  Done. SBOM files: rootless-sbom.{json,txt}, cleanstart-sbom.{json,txt}"
echo "=============================================================="
echo ""