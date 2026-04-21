#!/usr/bin/env bash
# check_drift.sh
# Checks two things on a golden image:
#   1. Age      — is it stale?
#   2. CVEs     — what's the attack surface?
#
# Usage:
#   ./check_drift.sh <image> [max-age-days]
#
# Example:
#   ./check_drift.sh cleanstart/node:latest 30
#   ./check_drift.sh node:20-bullseye 30        # run both to see the difference

IMAGE="${1:-cleanstart/node:latest}"
MAX_DAYS="${2:-30}"
EXIT=0

echo ""
echo "  Image : $IMAGE"
echo "  ────────────────────────────────"

# ── 1. Image Age ─────────────────────────────────────────────────────────────
# Try OCI label first, then fall back to Docker's own Created field
RAW_DATE=$(docker inspect "$IMAGE" \
  --format '{{index .Config.Labels "org.opencontainers.image.created"}}' 2>/dev/null)

# If label is empty or returns Docker's "<no value>" placeholder, use Created
if [ -z "$RAW_DATE" ] || [[ "$RAW_DATE" == "<no"* ]]; then
  RAW_DATE=$(docker inspect "$IMAGE" --format '{{.Created}}' 2>/dev/null)
fi

BUILD_DATE=$(echo "$RAW_DATE" | cut -c1-10)

if [ -z "$BUILD_DATE" ] || [ "$BUILD_DATE" = "<no" ]; then
  echo "  AGE   WARN  no build date found"
else
  if date --version &>/dev/null 2>&1; then
    EPOCH=$(date -d "$BUILD_DATE" +%s 2>/dev/null || echo 0)   # Linux
  else
    EPOCH=$(date -j -f "%Y-%m-%d" "$BUILD_DATE" +%s 2>/dev/null || echo 0)  # macOS
  fi

  AGE=$(( ( $(date +%s) - EPOCH ) / 86400 ))

  if [ "$AGE" -gt "$MAX_DAYS" ]; then
    echo "  AGE   FAIL  ${AGE} days old (limit: ${MAX_DAYS}) — rebuild required"
    EXIT=1
  else
    echo "  AGE   PASS  ${AGE} days old — within ${MAX_DAYS}-day threshold"
  fi
fi

# ── 2. CVE Scan ───────────────────────────────────────────────────────────────
if ! command -v trivy &>/dev/null; then
  echo "  CVE   SKIP  trivy not installed (brew install aquasecurity/trivy/trivy)"
else
  TRIVY_OUT=$(trivy image "$IMAGE" \
    --severity CRITICAL,HIGH \
    --no-progress \
    --format table 2>/dev/null)

  CRITICAL=$(echo "$TRIVY_OUT" | grep -c '│ CRITICAL' 2>/dev/null || true)
  HIGH=$(echo "$TRIVY_OUT"     | grep -c '│ HIGH    ' 2>/dev/null || true)

  CRITICAL=${CRITICAL:-0}
  HIGH=${HIGH:-0}

  if [ "$CRITICAL" -gt 0 ]; then
    echo "  CVE   FAIL  ${CRITICAL} CRITICAL, ${HIGH} HIGH — run: trivy image $IMAGE"
    [ $EXIT -eq 0 ] && EXIT=2
  elif [ "$HIGH" -gt 0 ]; then
    echo "  CVE   WARN  0 CRITICAL, ${HIGH} HIGH"
  else
    echo "  CVE   PASS  0 CRITICAL, 0 HIGH — minimal attack surface"
  fi
fi

echo "  ────────────────────────────────"
[ $EXIT -eq 0 ] && echo "  RESULT  PASS" || echo "  RESULT  FAIL (exit $EXIT)"
echo ""
exit $EXIT