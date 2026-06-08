#!/bin/bash
# ============================================================
# verify-signed.sh
# Verifies a CleanStart image signature using Cosign keyless
# signing via Google Cloud Workload Identity + Rekor transparency log
# ============================================================

set -euo pipefail

# Avoid docker-credential-desktop.exe errors on Linux/WSL
export DOCKER_CONFIG=/tmp/cosign-docker-cfg
mkdir -p "$DOCKER_CONFIG"

IMAGE="clnstrt-images.cleanstart.com/cleanstartos/python"
EXPECTED_ISSUER="https://accounts.google.com"
EXPECTED_IDENTITY="pkgs-admin-clnstrt-dev@release-build.iam.gserviceaccount.com"

echo "Image   : $IMAGE"
echo "Issuer  : $EXPECTED_ISSUER"
echo "Identity: $EXPECTED_IDENTITY"
echo ""

# Verify signature — keyless (no local key file required)
cosign verify "$IMAGE" \
  --certificate-oidc-issuer="$EXPECTED_ISSUER" \
  --certificate-identity="$EXPECTED_IDENTITY" \
  | jq -r '.[0] | {
      "digest":   .critical.image["docker-manifest-digest"],
      "ref":      .critical.identity["docker-reference"],
      "type":     .critical.type
    }'

echo ""
echo "Transparency log entry confirmed via Rekor."

# Verify SLSA provenance attestation (v0.2)
echo ""
echo "Checking SLSA provenance attestation..."
cosign verify-attestation "$IMAGE" \
  --certificate-oidc-issuer="$EXPECTED_ISSUER" \
  --certificate-identity="$EXPECTED_IDENTITY" \
  --type slsaprovenance02 \
  | jq -r '.payload | @base64d | fromjson | .predicate | {
      "builderId":   .slsaProvenance.builder.id,
      "buildType":   .slsaProvenance.recipe.type,
      "entryPoint":  .slsaProvenance.recipe.entryPoint
    }'

echo ""
echo "SLSA provenance verified."
