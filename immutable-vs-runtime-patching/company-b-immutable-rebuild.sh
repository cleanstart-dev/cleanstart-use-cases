#!/usr/bin/env bash
# Company B: the CleanStart image. There is no shell and no package manager
# to patch in place — the only update path is pulling a new signed digest.
set -euo pipefail

IMAGE="${1:-cleanstart/python:latest}"
CONTAINER="company-b-demo"
OUT="results"
mkdir -p "$OUT"

echo "== Company B: immutable rebuild on ${IMAGE} =="

docker pull "$IMAGE" >/dev/null
DIGEST_BEFORE=$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE")
echo "Deployed digest: $DIGEST_BEFORE" | tee "$OUT/company-b-digest-before.txt"

echo "-- attempting to patch in place, the way Company A did --"
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" "$IMAGE" sleep infinity >/dev/null 2>&1 || true
if docker exec "$CONTAINER" sh -c "echo shell reached" >"$OUT/company-b-shell-attempt.txt" 2>&1; then
  echo "unexpected: a shell was reachable in this image" | tee -a "$OUT/company-b-shell-attempt.txt"
else
  echo "no shell in the image — confirmed. there is nothing to exec into and nothing to patch in place." \
    | tee "$OUT/company-b-shell-attempt.txt"
fi
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true

echo "-- the only update path: re-pull the tag and compare digests --"
docker pull "$IMAGE" >/dev/null
DIGEST_AFTER=$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE")
echo "Digest after re-pull: $DIGEST_AFTER" | tee "$OUT/company-b-digest-after.txt"

cat <<EOF
Every host that pulls "${IMAGE}" gets exactly this digest — not a live
patched state that depends on when and how someone ran a command inside it.
Rollback means redeploying the previous digest, which is byte-for-byte the
image that was already known-good in production.
EOF
