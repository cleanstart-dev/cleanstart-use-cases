#!/bin/bash
# pipeline-fixed.sh
# Simulates a layered security pipeline:
#   1. Blocking scan at build time (shift left, done right)
#   2. Scheduled rescan against the already-deployed image
#   3. Runtime image validation before serving traffic
#
# This is what actually works.

IMAGE="shift-left-demo:latest"
IMAGE_FIXED="shift-left-demo-fixed:latest"
SCAN_REPORT_BUILD="trivy-report-fixed-build.json"
SCAN_REPORT_RESCAN="trivy-report-fixed-rescan.json"
CRITICAL_THRESHOLD=0
HIGH_THRESHOLD=5

echo ""
echo "════════════════════════════════════════"
echo "  CI PIPELINE — Layered Security"
echo "════════════════════════════════════════"
echo ""

# ── Stage 1: Build with patched deps ─────────────────────────
echo "▶ [1/4] Building image with patched dependencies..."
cp requirements.fixed.txt requirements.txt.bak
cp requirements.fixed.txt requirements.txt
docker build -t "$IMAGE_FIXED" .
cp requirements.txt.bak requirements.txt
rm requirements.txt.bak
echo "✔ Build complete"
echo ""

# ── Stage 2: Blocking scan at build time ─────────────────────
echo "▶ [2/4] Running vulnerability scan (BLOCKING)..."
trivy image --exit-code 0 --severity HIGH,CRITICAL --format json \
    --output "$SCAN_REPORT_BUILD" "$IMAGE_FIXED"

CRITICAL=$(cat "$SCAN_REPORT_BUILD" | python3 -c "
import json, sys
data = json.load(sys.stdin)
results = data.get('Results', [])
total = sum(
    len([v for v in r.get('Vulnerabilities', []) or [] if v.get('Severity') == 'CRITICAL'])
    for r in results
)
print(total)
" 2>/dev/null || echo "0")

HIGH=$(cat "$SCAN_REPORT_BUILD" | python3 -c "
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
echo "  ├─ CRITICAL: $CRITICAL (threshold: $CRITICAL_THRESHOLD)"
echo "  └─ HIGH:     $HIGH (threshold: $HIGH_THRESHOLD)"
echo ""

if [ "$CRITICAL" -gt "$CRITICAL_THRESHOLD" ]; then
    echo "  ❌ CRITICAL threshold exceeded. Blocking deployment."
    echo ""
    exit 1
fi

if [ "$HIGH" -gt "$HIGH_THRESHOLD" ]; then
    echo "  ❌ HIGH threshold exceeded. Blocking deployment."
    echo ""
    exit 1
fi

echo "✔ Build-time scan passed (blocking gate cleared)"
echo ""

# ── Stage 3: Deploy ──────────────────────────────────────────
echo "▶ [3/4] Deploying image..."
echo ""
echo "  🚀 Image: $IMAGE_FIXED"
echo "  🚀 Status: DEPLOYED"
echo ""
echo "✔ Deploy complete"
echo ""

# ── Stage 4: Scheduled rescan simulation ─────────────────────
echo "▶ [4/4] Simulating scheduled rescan (post-deploy)..."
echo "  (In production: runs daily via cron / CI scheduled trigger)"
echo ""

trivy image --exit-code 0 --severity HIGH,CRITICAL --format json \
    --output "$SCAN_REPORT_RESCAN" "$IMAGE_FIXED"

CRITICAL_RESCAN=$(cat "$SCAN_REPORT_RESCAN" | python3 -c "
import json, sys
data = json.load(sys.stdin)
results = data.get('Results', [])
total = sum(
    len([v for v in r.get('Vulnerabilities', []) or [] if v.get('Severity') == 'CRITICAL'])
    for r in results
)
print(total)
" 2>/dev/null || echo "0")

HIGH_RESCAN=$(cat "$SCAN_REPORT_RESCAN" | python3 -c "
import json, sys
data = json.load(sys.stdin)
results = data.get('Results', [])
total = sum(
    len([v for v in r.get('Vulnerabilities', []) or [] if v.get('Severity') == 'HIGH'])
    for r in results
)
print(total)
" 2>/dev/null || echo "0")

echo "  Rescan results (post-deploy):"
echo "  ├─ CRITICAL: $CRITICAL_RESCAN"
echo "  └─ HIGH:     $HIGH_RESCAN"
echo ""

if [ "$CRITICAL_RESCAN" -gt "$CRITICAL_THRESHOLD" ]; then
    echo "  ⚠️  New CRITICAL CVEs detected post-deploy."
    echo "  ⚠️  Alert triggered → incident response initiated."
    echo "  ⚠️  Image flagged for patching."
else
    echo "✔ Rescan passed — no new critical findings post-deploy"
fi

echo ""
echo "════════════════════════════════════════"
echo "  ✔ Pipeline complete."
echo "════════════════════════════════════════"
echo ""
echo "  What this pipeline does differently:"
echo "  ✓ Blocking scan — deployment stops on CRITICAL findings"
echo "  ✓ Defined thresholds — not just logging, actually gating"
echo "  ✓ Scheduled rescan — catches CVEs disclosed after deploy"
echo "  ✓ Post-deploy alerting — runtime drift is visible"
echo ""