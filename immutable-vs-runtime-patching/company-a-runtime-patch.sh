#!/usr/bin/env bash
# Company A: patch a running container from a public base image, in place.
# This is the "runtime patching" model — the fix is applied to a live
# container with a package manager and a shell, not to a rebuilt artifact.
set -euo pipefail

IMAGE="${1:-python:3.14.7}"
CONTAINER="company-a-demo"
OUT="results"
mkdir -p "$OUT"

echo "== Company A: runtime patching on ${IMAGE} =="

docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" "$IMAGE" sleep infinity >/dev/null

echo "-- package snapshot BEFORE patch --"
docker exec "$CONTAINER" bash -c "dpkg -l 2>/dev/null || apk info -v 2>/dev/null" \
  > "$OUT/company-a-before.txt" || echo "(no package manager output captured)" > "$OUT/company-a-before.txt"

echo "-- applying the patch in place (apt-get upgrade inside the running container) --"
if docker exec "$CONTAINER" bash -c "apt-get update -qq && apt-get -y upgrade -qq" 2>/dev/null; then
  echo "patched in place"
else
  echo "  (patch step failed, or this image has no apt — that inconsistency is itself part of the point:"
  echo "   every public base image patches differently, and someone has to know how each one works.)"
fi

echo "-- package snapshot AFTER patch --"
docker exec "$CONTAINER" bash -c "dpkg -l 2>/dev/null || apk info -v 2>/dev/null" \
  > "$OUT/company-a-after.txt" || echo "(no package manager output captured)" > "$OUT/company-a-after.txt"

echo "-- what artifact represents this patched state? --"
docker inspect "$CONTAINER" --format='{{.Image}}' > "$OUT/company-a-running-image-id.txt"
cat <<'EOF'
The container's live filesystem no longer matches the image it was started
from. Nothing was rebuilt, nothing was re-signed, and there is no digest you
can pull to reproduce this exact patched state on a second host. If this
container is destroyed and replaced from the original image, the patch is
gone. Whoever runs company-b-immutable-rebuild.sh next will not have this
problem.
EOF

docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
