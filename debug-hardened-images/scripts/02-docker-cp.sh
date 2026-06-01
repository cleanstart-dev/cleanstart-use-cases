#!/usr/bin/env bash
# Technique 2: docker cp — extract files from a hardened container without a shell.
# Creates a demo container from cleanstart/glibc:latest, runs the demo, then cleans up.
# Usage: bash scripts/02-docker-cp.sh

set -euo pipefail

CONTAINER="hardened-demo-cp"
IMAGE="cleanstart/glibc:latest"

cleanup() {
    docker rm -f "$CONTAINER" 2>/dev/null || true
    rm -rf ./extracted
}
trap cleanup EXIT

echo "=== Setup: creating demo container from $IMAGE ==="
docker create --name "$CONTAINER" "$IMAGE" /nonexistent 2>/dev/null
echo "    container: $CONTAINER"

echo ""
echo "=== Attempt 1: Try to run with a shell (will fail — no shell in image) ==="
echo "$ docker run --rm --entrypoint cat $IMAGE /etc/hostname"
docker run --rm --entrypoint cat "$IMAGE" /etc/hostname 2>&1 || true

echo ""
echo "=== Solution: docker cp — pull files out without going in ==="
mkdir -p ./extracted

for f in /etc/hostname /etc/os-release /usr/bin/ldd; do
    out="./extracted/$(basename "$f")"
    echo "$ docker cp $CONTAINER:$f $out"
    if docker cp "$CONTAINER:$f" "$out" 2>/dev/null; then
        echo "  ✓ extracted — $(wc -c < "$out") bytes"
    else
        echo "  ✗ not present in image"
    fi
done

echo ""
echo "=== Inspect extracted files ==="
ls -lh ./extracted/
echo ""
echo "Contents of /etc/hostname:"
cat ./extracted/hostname 2>/dev/null || echo "  (empty)"
echo ""
echo "Contents of /etc/os-release:"
cat ./extracted/os-release 2>/dev/null || echo "  not found"

echo ""
echo "[+] Done — files extracted from hardened container without any shell inside."
