#!/usr/bin/env bash
# ============================================================
#  Rootless Containers — Security Theater or Real Protection?
#  Builds 2 images and runs 3 tests
# ============================================================
set -e

echo ""
echo "=============================================================="
echo "  Building 2 images..."
echo "=============================================================="

docker build -q -f Dockerfile.rootless   -t demo-rootless:latest   . > /dev/null && echo "  [OK] demo-rootless   (python:3.14 + USER appuser)"
docker build -q -f Dockerfile.cleanstart -t demo-cleanstart:latest . > /dev/null && echo "  [OK] demo-cleanstart (CleanStart + nonroot)"

# ------------------------------------------------------------
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

# ------------------------------------------------------------
echo ""
echo "=============================================================="
echo "  TEST 2 — Dangerous binaries still inside the image?"
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

# ------------------------------------------------------------
echo ""
echo "=============================================================="
echo "  TEST 3 — Image-level CVEs (HIGH + CRITICAL)"
echo "=============================================================="
echo ""
echo "  -- rootless --"
trivy image --quiet --severity HIGH,CRITICAL demo-rootless:latest | tail -20
echo ""
echo "  -- cleanstart --"
trivy image --quiet --severity HIGH,CRITICAL demo-cleanstart:latest | tail -20

echo ""
echo "=============================================================="
echo "  Done."
echo "=============================================================="
echo ""
