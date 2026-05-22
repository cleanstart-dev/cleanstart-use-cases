#!/usr/bin/env bash
# 01-build-retrofit.sh
# Build the retrofitted Ubuntu image and time the build.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

IMAGE="stig-retrofit:latest"
LOG="results/build-retrofit.log"
mkdir -p results

echo "[*] Building $IMAGE from configs/Dockerfile.retrofit"
echo "[*] (clean cache — ~6 minutes on a typical laptop)"

START=$(date +%s)

# --no-cache to make the timing meaningful and reproducible
docker build \
    --no-cache \
    --progress=plain \
    -f configs/Dockerfile.retrofit \
    -t "$IMAGE" \
    . 2>&1 | tee "$LOG"

END=$(date +%s)
ELAPSED=$((END - START))

SIZE=$(docker images "$IMAGE" --format '{{.Size}}')
PKGS=$(docker run --rm --entrypoint dpkg "$IMAGE" -l 2>/dev/null | grep -c '^ii' || echo "n/a")

echo ""
echo "[+] retrofit build complete"
echo "    image:       $IMAGE"
echo "    size:        $SIZE"
echo "    packages:    $PKGS"
echo "    build time:  ${ELAPSED}s"

# Append to the comparison CSV
echo "retrofit,$ELAPSED,$SIZE,$PKGS" >> results/timings.csv
