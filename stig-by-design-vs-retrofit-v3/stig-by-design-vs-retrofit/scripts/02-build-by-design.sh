#!/usr/bin/env bash
# 02-build-by-design.sh
# Pull the CleanStart hardened base and build the by-design image.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

IMAGE="stig-by-design:latest"
LOG="results/build-by-design.log"
mkdir -p results

# Create a placeholder app so the COPY layer in the Dockerfile has something
# to copy. In a real workload this is your service binary.
mkdir -p app
cat > app/server <<'EOF'
#!/bin/sh
echo "by-design image — placeholder app"
EOF
chmod +x app/server

echo "[*] Building $IMAGE from configs/Dockerfile.by-design"

START=$(date +%s)

docker build \
    --no-cache \
    --progress=plain \
    -f configs/Dockerfile.by-design \
    -t "$IMAGE" \
    . 2>&1 | tee "$LOG"

END=$(date +%s)
ELAPSED=$((END - START))

SIZE=$(docker images "$IMAGE" --format '{{.Size}}')

# The by-design image doesn't ship dpkg; we use the SBOM that ships with
# the base instead. Falls back to "n/a" on hosts without cosign.
PKGS="n/a"
if command -v cosign >/dev/null 2>&1; then
    PKGS=$(cosign download sbom "$IMAGE" 2>/dev/null \
        | jq -r '.packages | length' 2>/dev/null || echo "n/a")
fi

echo ""
echo "[+] by-design build complete"
echo "    image:       $IMAGE"
echo "    size:        $SIZE"
echo "    packages:    $PKGS (from signed SBOM)"
echo "    build time:  ${ELAPSED}s"

echo "by-design,$ELAPSED,$SIZE,$PKGS" >> results/timings.csv
