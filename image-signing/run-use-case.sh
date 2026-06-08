#!/bin/bash
# ============================================================
# CleanStart Use Case: Topic 24 — Container Image Signing
# Demonstrates: signing, verification, and enforcement
# Requirements: cosign, docker, kubectl (optional for policy)
# ============================================================

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo ""
echo "========================================================"
echo " CleanStart Use Case #24 — Image Signing & Verification"
echo "========================================================"
echo ""

# ── Step 1: Pull an unsigned public image ──────────────────
echo -e "${YELLOW}[STEP 1] Pull unsigned nginx:1.25 from Docker Hub${NC}"
docker pull nginx:1.25
echo ""

# ── Step 2: Attempt cosign verify — expect failure ─────────
echo -e "${YELLOW}[STEP 2] Attempt cosign verification on unsigned image${NC}"
cosign verify nginx:1.25 \
  --certificate-identity-regexp=".*" \
  --certificate-oidc-issuer-regexp=".*" 2>&1 || true
echo ""
echo -e "${RED}  ↳ No signature found. Image ran anyway — no enforcement.${NC}"
echo ""

# ── Step 3: Verify CleanStart signed image ─────────────────
echo -e "${YELLOW}[STEP 3] Verify CleanStart hardened Python image (keyless)${NC}"
bash verify-signed.sh
echo ""

# ── Step 4: Apply Kyverno policy (optional) ────────────────
if command -v kubectl &>/dev/null && kubectl get crd clusterpolicies.kyverno.io &>/dev/null 2>&1; then
  echo -e "${YELLOW}[STEP 4] Apply Kyverno ClusterPolicy for signature enforcement${NC}"
  kubectl apply -f kyverno-policy.yaml
  echo ""
  echo -e "${YELLOW}[STEP 5] Attempt to run unsigned image — expect block${NC}"
  kubectl run test-unsigned --image=nginx:1.25 --restart=Never 2>&1 || \
    echo -e "${RED}  ↳ Blocked by admission controller as expected.${NC}"
else
  echo -e "${YELLOW}[STEP 4] kubectl or Kyverno CRDs not found — skipping admission policy demo.${NC}"
  echo "  Install Kyverno first: helm install kyverno kyverno/kyverno -n kyverno --create-namespace"
  echo "  Then re-run to see enforcement in action."
fi

echo ""
echo -e "${GREEN}Use case complete. See README.md for full explanation.${NC}"
echo ""