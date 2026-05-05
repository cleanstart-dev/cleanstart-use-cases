#!/bin/bash
# pipeline-broken.sh
# Simulates a shift-left-only CI pipeline.
# Scans at build time. Passes. Ships. Never checks again.
# This is the failure mode.

set -e

IMAGE="shift-left-demo:latest"
SCAN_REPORT="trivy-report-build-time.json"

echo ""
echo "════════════════════════════════════════"
echo "  CI PIPELINE — Shift Left Only"
echo "════════════════════════════════════════"
echo ""

# ── Stage 1: Build ───────────────────────────────────────────
echo "▶ [1/3] Building image..."
docker build -t "$IMAGE" .
echo "✔ Build complete"
echo ""

# ── Stage 2: Scan at build time ──────────────────────────────
echo "▶ [2/3] Running vulnerability scan (build-time)..."
trivy image --exit-code 0 --severity HIGH,CRITICAL --format json \
    --output "$SCAN_REPORT" "$IMAGE"

# Count findings
CRITICAL=$(cat "$SCAN_REPORT" | python3 -c "
import json, sys
data = json.load(sys.stdin)
results = data.get('Results', [])
total = sum(
    len([v for v in r.get('Vulnerabilities', []) or [] if v.get('Severity') == 'CRITICAL'])
    for r in results
)
print(total)
" 2>/dev/null || echo "0")

HIGH=$(cat "$SCAN_REPORT" | python3 -c "
import json, sys
data = json.load(sys.stdin)
results = data.get('Results', [])
total = sum(
    len([v for v in r.get('Vulnerabilities', []) or [] if v.get('Severity') == 'HIGH'])
    for r in results
)
print(total)
" 2>/dev/null || echo "0")

echo ""
echo "  Scan results at build time:"
echo "  ├─ CRITICAL: $CRITICAL"
echo "  └─ HIGH:     $HIGH"
echo ""

# Pipeline does NOT block on findings — common misconfiguration
echo "  ⚠️  Pipeline configured with --exit-code 0 (non-blocking)"
echo "  ⚠️  Findings logged but deployment proceeds regardless"
echo ""
echo "✔ Scan stage passed (non-blocking)"
echo ""

# ── Stage 3: Deploy ──────────────────────────────────────────
echo "▶ [3/3] Deploying image to production..."
echo ""
echo "  🚀 Image: $IMAGE"
echo "  🚀 Status: DEPLOYED"
echo ""
echo "════════════════════════════════════════"
echo "  ✔ Pipeline complete. Image is live."
echo "════════════════════════════════════════"
echo ""
echo "  What this pipeline missed:"
echo "  ✗ Scan was non-blocking — CVEs logged, not gated"
echo "  ✗ No rescan scheduled — image is never checked again"
echo "  ✗ No runtime monitoring — new CVEs disclosed after"
echo "    deploy are invisible until the next manual build"
echo ""
echo "  Run pipeline-fixed.sh to see the difference."
echo ""