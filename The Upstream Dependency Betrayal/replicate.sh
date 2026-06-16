#!/usr/bin/env bash
# ==============================================================================
# replicate.sh
# The Upstream Dependency Betrayal — Full Lab Replication Script
#
# Runs all 5 steps end-to-end in a single script:
#   STEP 1  Establish a trusted baseline (pull by digest, baseline SBOM)
#   STEP 2  Simulate upstream compromise (tag mutation via poisoned image)
#   STEP 3  Downstream victim build (silent inheritance, no errors)
#   STEP 4  Detection gap demonstration (CVE scan misses it; SBOM diff catches it)
#   STEP 5  Verify the attack path (backdoor confirmed inside running container)
#
# Prerequisites:
#   - Docker with BuildKit enabled and a local registry on localhost:5000
#     Start the registry:  docker run -d -p 5000:5000 --name local-registry registry:2
#   - syft   https://github.com/anchore/syft
#   - grype  https://github.com/anchore/grype
#   - jq
#
# Usage:
#   chmod +x replicate.sh
#   ./replicate.sh
#
# ⚠  FOR LAB / EDUCATIONAL USE ONLY. Do not run against production systems.
# ==============================================================================

set -euo pipefail

# ── Shared configuration ───────────────────────────────────────────────────────
REGISTRY="localhost:5000"
IMAGE_NAME="python"
IMAGE_TAG="3.12-slim"
LOCAL_IMAGE="${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}"
POISONED_TAG="${REGISTRY}/${IMAGE_NAME}:poisoned-staging"
APP_IMAGE="myapp:latest"
BASELINE_SBOM="baseline-sbom.json"
CURRENT_SBOM="current-sbom.json"
DIGEST_FILE=".baseline-digest"
WORK_DIR="$(pwd)/lab-workspace"
BACKDOOR_PATH="/tmp/.hidden_backdoor"

# ── Colour helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

banner()  { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════════════════════════${RESET}"; \
            echo -e "${BOLD}${CYAN}  $*${RESET}"; \
            echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════════════${RESET}"; }
ok()      { echo -e "    ${GREEN}✓${RESET}  $*"; }
warn()    { echo -e "    ${YELLOW}⚠️ ${RESET}  $*"; }
alert()   { echo -e "    ${RED}🚨${RESET}  $*"; }
substep() { echo -e "\n${BOLD}[$*]${RESET}"; }

# ── Prerequisite check ─────────────────────────────────────────────────────────
check_prereqs() {
  banner "Prerequisite Check"
  local missing=0
  for cmd in docker syft grype jq; do
    if command -v "$cmd" >/dev/null 2>&1; then
      ok "$cmd found ($(command -v "$cmd"))"
    else
      echo -e "    ${RED}✗${RESET}  $cmd NOT FOUND"
      missing=$((missing + 1))
    fi
  done

  # Verify local registry is reachable
  if docker info --format '{{.Name}}' >/dev/null 2>&1 && \
     curl -sf "http://${REGISTRY}/v2/" >/dev/null 2>&1; then
    ok "Local registry reachable at ${REGISTRY}"
  else
    warn "Local registry at ${REGISTRY} may not be running."
    warn "Start it with: docker run -d -p 5000:5000 --name local-registry registry:2"
    warn "Also add to Docker daemon insecure-registries if needed."
    missing=$((missing + 1))
  fi

  if [[ $missing -gt 0 ]]; then
    echo -e "\n${RED}[ERROR] ${missing} prerequisite(s) missing. Resolve them and re-run.${RESET}\n"
    exit 1
  fi

  # Prepare clean working directory
  mkdir -p "${WORK_DIR}/app"
  cd "${WORK_DIR}"
  ok "Working directory: ${WORK_DIR}"
}

# ── Generate lab files (Dockerfiles, app code) as heredocs ────────────────────
generate_lab_files() {
  banner "Generating Lab Files"

  # ── Dockerfile.poisoned ──────────────────────────────────────────────────────
  cat > Dockerfile.poisoned << 'EOF'
# Dockerfile.poisoned
# Simulates a compromised upstream base image.
# An attacker who gained push access to the registry rebuilds the image under
# the same tag, injecting a hidden backdoor file and a silent pip dependency.
# ⚠  FOR LAB / EDUCATIONAL USE ONLY — contains no real malware.

FROM python:3.12-slim

# Simulated malicious layer — in a real attack this could be a reverse shell,
# a C2 beacon, an env-var exfiltration script, or a backdoored pip package.
RUN echo "malicious_payload: exfiltrate_env_vars" > /tmp/.hidden_backdoor && \
    chmod 644 /tmp/.hidden_backdoor

# Attacker silently adds a new dependency not declared by the application owner
RUN pip install --no-cache-dir requests==2.32.3 --quiet

# Image appearance is unchanged — no CMD or LABEL modification
EOF
  ok "Dockerfile.poisoned"

  # ── Dockerfile (victim app) ──────────────────────────────────────────────────
  cat > Dockerfile << 'EOF'
# Dockerfile — Victim application image
# Typical CI/CD build: trusts the upstream tag without digest-pinning
# or signature verification. After Step 2, the tag resolves to the
# attacker's image and this build silently inherits all injected layers.

FROM localhost:5000/python:3.12-slim

WORKDIR /app
COPY app/ /app/
RUN pip install --no-cache-dir -r /app/requirements.txt
EXPOSE 8080
CMD ["python", "/app/main.py"]
EOF
  ok "Dockerfile"

  # ── app/main.py ──────────────────────────────────────────────────────────────
  cat > app/main.py << 'EOF'
"""
app/main.py — Minimal victim application (HTTP service).

Represents a real workload: reads config from env vars, serves simple
JSON endpoints. In a real compromise the backdoor layer has access to
everything this process can reach — env vars, mounted secrets, service
account tokens, internal network paths.
"""
import http.server
import json
import os
import socketserver

PORT        = int(os.environ.get("APP_PORT", 8080))
APP_NAME    = os.environ.get("APP_NAME", "victim-app")
APP_VERSION = os.environ.get("APP_VERSION", "1.0.0")

class AppHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self._respond(200, {"status": "ok"})
        elif self.path == "/info":
            self._respond(200, {"app": APP_NAME, "version": APP_VERSION})
        else:
            self._respond(404, {"error": "not found"})

    def _respond(self, status, body):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        print(f"[{APP_NAME}] {fmt % args}")

if __name__ == "__main__":
    print(f"[{APP_NAME}] Starting on port {PORT}")
    with socketserver.TCPServer(("", PORT), AppHandler) as httpd:
        httpd.serve_forever()
EOF
  ok "app/main.py"

  # ── app/requirements.txt ─────────────────────────────────────────────────────
  cat > app/requirements.txt << 'EOF'
# app/requirements.txt
# Only dependencies intentionally declared by the developer.
# The poisoned base image silently installs 'requests' on top — not listed
# here, not approved, not audited. The SBOM diff in Step 4 surfaces it.
EOF
  ok "app/requirements.txt"
}

# ==============================================================================
# STEP 1 — Establish a Trusted Baseline
# ==============================================================================
step1_baseline() {
  banner "Step 1 — Establish a Trusted Baseline"
  echo "  Pull a known-good Python image by digest, push it to the local"
  echo "  registry as the trusted upstream, and generate a baseline SBOM."

  substep "1a — Resolving upstream digest for ${IMAGE_NAME}:${IMAGE_TAG}"
  UPSTREAM_DIGEST=$(docker buildx imagetools inspect "${IMAGE_NAME}:${IMAGE_TAG}" \
    --format '{{json .Manifest}}' 2>/dev/null | jq -r '.digest // empty' || true)

  if [[ -z "${UPSTREAM_DIGEST}" ]]; then
    docker pull "${IMAGE_NAME}:${IMAGE_TAG}" --quiet
    UPSTREAM_DIGEST=$(docker inspect "${IMAGE_NAME}:${IMAGE_TAG}" \
      --format '{{index .RepoDigests 0}}' | cut -d'@' -f2)
  fi
  echo "       Digest: ${UPSTREAM_DIGEST}"
  echo "${UPSTREAM_DIGEST}" > "${DIGEST_FILE}"
  ok "Digest saved to ${DIGEST_FILE}"

  substep "1b — Pulling ${IMAGE_NAME}:${IMAGE_TAG}@${UPSTREAM_DIGEST}"
  docker pull "${IMAGE_NAME}:${IMAGE_TAG}@${UPSTREAM_DIGEST}"

  substep "1c — Tagging and pushing to local registry as trusted upstream"
  docker tag "${IMAGE_NAME}:${IMAGE_TAG}@${UPSTREAM_DIGEST}" "${LOCAL_IMAGE}"
  docker push "${LOCAL_IMAGE}"
  ok "Pushed: ${LOCAL_IMAGE}"

  substep "1d — Recording local registry digest"
  LOCAL_DIGEST=$(docker inspect "${LOCAL_IMAGE}" \
    --format '{{index .RepoDigests 0}}' 2>/dev/null | cut -d'@' -f2 || echo "${UPSTREAM_DIGEST}")
  echo "       Local digest: ${LOCAL_DIGEST}"

  substep "1e — Generating baseline SBOM (CycloneDX JSON)"
  syft "${LOCAL_IMAGE}" -o cyclonedx-json="${BASELINE_SBOM}" 2>/dev/null
  BASELINE_COUNT=$(jq '.components | length' "${BASELINE_SBOM}")
  ok "Baseline SBOM: ${BASELINE_SBOM} (${BASELINE_COUNT} components)"

  echo -e "\n${GREEN}  ✅ Baseline established — Image: ${LOCAL_IMAGE} | Components: ${BASELINE_COUNT}${RESET}"
}

# ==============================================================================
# STEP 2 — Simulate the Upstream Compromise
# ==============================================================================
step2_compromise() {
  banner "Step 2 — Simulate the Upstream Compromise"
  echo "  Build the poisoned image and push it under the SAME tag as the"
  echo "  trusted baseline — simulating a tag mutation / registry hijack."

  substep "2a — Recording pre-compromise digest"
  PRE_DIGEST=$(docker inspect "${LOCAL_IMAGE}" \
    --format '{{index .RepoDigests 0}}' 2>/dev/null | cut -d'@' -f2 || \
    cat "${DIGEST_FILE}" 2>/dev/null || echo "<not-recorded>")
  echo "       Pre-compromise digest: ${PRE_DIGEST}"

  substep "2b — Building poisoned image from Dockerfile.poisoned"
  docker build --no-cache -f Dockerfile.poisoned -t "${POISONED_TAG}" . 2>&1 | \
    grep -E '(Step|---|\[|Successfully)' || true
  ok "Poisoned image built: ${POISONED_TAG}"

  substep "2c — Overwriting ${LOCAL_IMAGE} with poisoned image in registry"
  docker tag "${POISONED_TAG}" "${LOCAL_IMAGE}"
  docker push "${LOCAL_IMAGE}"
  ok "Pushed: ${LOCAL_IMAGE} (tag now resolves to poisoned image)"

  substep "2d — Digest comparison before vs after"
  POST_DIGEST=$(docker inspect "${LOCAL_IMAGE}" \
    --format '{{index .RepoDigests 0}}' 2>/dev/null | cut -d'@' -f2 || echo "<unknown>")
  echo "       Before : ${PRE_DIGEST}"
  echo "       After  : ${POST_DIGEST}"
  if [[ "${PRE_DIGEST}" != "${POST_DIGEST}" ]]; then
    warn "DIGEST MISMATCH — tag has been silently mutated"
  fi

  echo -e "\n${YELLOW}  ⚠️  Compromise simulated — tag '${IMAGE_TAG}' now resolves to the attacker's image.${RESET}"
}

# ==============================================================================
# STEP 3 — Downstream Victim Build
# ==============================================================================
step3_victim_build() {
  banner "Step 3 — Downstream Victim Build (Normal Pipeline Simulation)"
  echo "  A typical CI/CD pipeline builds the application image using the tag."
  echo "  No digest pin. No signature check. The build succeeds silently."

  substep "3a — Force-pulling base image from local registry (bypass cache)"
  docker pull "${LOCAL_IMAGE}"
  ok "Pulled: ${LOCAL_IMAGE}"

  substep "3b — Building application image: ${APP_IMAGE}"
  docker build --no-cache --pull=false -t "${APP_IMAGE}" . 2>&1 | \
    grep -E '(Step|---|\[|Successfully)' || true
  ok "Built: ${APP_IMAGE}"

  substep "3c — Build result"
  docker inspect "${APP_IMAGE}" \
    --format $'Image ID : {{.Id}}\nCreated  : {{.Created}}\nLayers   : {{len .RootFS.Layers}}'

  echo -e "\n${YELLOW}  ⚠️  Build succeeded with no errors — but the image is compromised.${RESET}"
  echo -e "  ${YELLOW}The backdoor layer from the poisoned base is now inside ${APP_IMAGE}.${RESET}"
}

# ==============================================================================
# STEP 4 — Detection Gap Demonstration
# ==============================================================================
step4_detection_gap() {
  banner "Step 4 — Detection Gap Demonstration"
  echo "  ❌  CVE scan (grype)     — passes, no known CVEs surface the backdoor"
  echo "  ✅  SBOM component diff  — reveals the unexpected 'requests' addition"
  echo "  ✅  Digest mismatch      — proves the tag resolved to a different image"

  substep "4a — CVE scan with grype (expected: no alert on the backdoor)"
  echo ""
  grype "${APP_IMAGE}" --output table 2>&1 | tail -25 || true
  echo ""
  warn "CVE scan complete — 'requests' carries no CVE. Backdoor file undetected."

  substep "4b — Generating current SBOM for ${APP_IMAGE}"
  syft "${APP_IMAGE}" -o cyclonedx-json="${CURRENT_SBOM}" 2>/dev/null

  echo ""
  echo "       Components present in CURRENT but NOT in BASELINE:"
  echo "       ────────────────────────────────────────────────────"
  ADDED=$(diff \
    <(jq -r '.components[].name' "${BASELINE_SBOM}" | sort -u) \
    <(jq -r '.components[].name' "${CURRENT_SBOM}"  | sort -u) \
    | grep '^>' | sed 's/^> /  + /' || true)
  if [[ -n "${ADDED}" ]]; then
    echo -e "${RED}${ADDED}${RESET}"
  else
    echo "       (no additions detected)"
  fi

  echo ""
  echo "       Components present in BASELINE but NOT in CURRENT:"
  echo "       ────────────────────────────────────────────────────"
  REMOVED=$(diff \
    <(jq -r '.components[].name' "${BASELINE_SBOM}" | sort -u) \
    <(jq -r '.components[].name' "${CURRENT_SBOM}"  | sort -u) \
    | grep '^<' | sed 's/^< /  - /' || true)
  [[ -n "${REMOVED}" ]] && echo "${REMOVED}" || echo "       (none)"

  BASELINE_COUNT=$(jq '.components | length' "${BASELINE_SBOM}")
  CURRENT_COUNT=$(jq  '.components | length' "${CURRENT_SBOM}")
  DELTA=$((CURRENT_COUNT - BASELINE_COUNT))
  echo ""
  echo "       Baseline : ${BASELINE_COUNT} components"
  echo "       Current  : ${CURRENT_COUNT} components"
  [[ $DELTA -gt 0 ]] && alert "Delta: +${DELTA} unexpected addition(s)" || echo "       Delta    : ${DELTA}"

  substep "4c — Digest mismatch check"
  RECORDED_DIGEST=$(cat "${DIGEST_FILE}" 2>/dev/null || echo "<not-recorded>")
  CURRENT_DIGEST=$(docker inspect "${LOCAL_IMAGE}" \
    --format '{{index .RepoDigests 0}}' 2>/dev/null | cut -d'@' -f2 || echo "<unknown>")
  echo "       Recorded baseline digest : ${RECORDED_DIGEST}"
  echo "       Current  registry digest : ${CURRENT_DIGEST}"
  if [[ "${RECORDED_DIGEST}" != "${CURRENT_DIGEST}" && \
        "${RECORDED_DIGEST}" != "<not-recorded>" ]]; then
    echo ""
    alert "DIGEST MISMATCH DETECTED"
    echo "         The tag 'python:3.12-slim' now resolves to a different image."
    echo "         Strong indicator of tag mutation / upstream compromise."
  fi

  echo ""
  echo -e "  ${BOLD}Detection Summary${RESET}"
  echo -e "  CVE scan (grype)          ${RED}❌ No alert — tampered layers invisible to CVE DB${RESET}"
  echo -e "  SBOM component diff       ${GREEN}✅ Surfaced unexpected 'requests' addition${RESET}"
  echo -e "  Digest mismatch check     ${GREEN}✅ Tag resolves to a different image than baseline${RESET}"
}

# ==============================================================================
# STEP 5 — Verify the Attack Path
# ==============================================================================
step5_verify_attack_path() {
  banner "Step 5 — Verify the Attack Path"
  echo "  Confirm the backdoor propagated: upstream → base image → app image → runtime."

  substep "5a — Checking for backdoor file inside ${APP_IMAGE}"
  BACKDOOR_CONTENT=$(docker run --rm "${APP_IMAGE}" cat "${BACKDOOR_PATH}" 2>/dev/null || true)
  if [[ -n "${BACKDOOR_CONTENT}" ]]; then
    echo ""
    alert "BACKDOOR CONFIRMED IN APPLICATION IMAGE"
    echo "         File    : ${BACKDOOR_PATH}"
    echo "         Content : ${BACKDOOR_CONTENT}"
  else
    ok "Backdoor file not found (compromise may not have propagated — re-run from Step 1)"
  fi

  substep "5b — Checking for silently added 'requests' package"
  REQUESTS_VER=$(docker run --rm "${APP_IMAGE}" \
    pip show requests 2>/dev/null | grep "^Version:" | awk '{print $2}' || true)
  if [[ -n "${REQUESTS_VER}" ]]; then
    echo ""
    alert "UNEXPECTED PACKAGE FOUND"
    echo "         Package : requests==${REQUESTS_VER}"
    echo "         Status  : Installed — NOT declared in app/requirements.txt"
  else
    ok "'requests' not present (package did not propagate)"
  fi

  substep "5c — Simulating attacker's access from inside the container"
  echo "       (Read-only diagnostic — not real exfiltration)"
  echo ""
  echo "       Environment variables the backdoor would harvest:"
  docker run --rm \
    -e DB_PASSWORD="super-secret-db-pass" \
    -e AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE" \
    -e APP_SECRET_TOKEN="ghp_exampletoken1234567890abcdef" \
    "${APP_IMAGE}" \
    sh -c 'env | grep -E "(PASSWORD|SECRET|TOKEN|KEY|API)" | sed "s/=.*/=<WOULD BE EXFILTRATED>/"' \
    2>/dev/null || true
  echo ""
  echo "       In a real attack the backdoor layer silently POSTs these values"
  echo "       to an attacker-controlled endpoint — before your app even starts."

  substep "5d — Full attack chain"
  echo ""
  echo -e "  ${BOLD}[ATTACKER]${RESET} Gained push access to upstream registry"
  echo "       ↓"
  echo -e "  ${BOLD}[STEP 2]${RESET}   Pushed poisoned image under trusted tag"
  echo "       ↓"
  echo -e "  ${BOLD}[STEP 3]${RESET}   Downstream CI/CD pulled by tag — silently got poisoned image"
  echo "       ↓"
  echo -e "  ${BOLD}[STEP 3]${RESET}   Application image built on top of poisoned base — no error"
  echo "       ↓"
  echo -e "  ${BOLD}[STEP 5]${RESET}   Backdoor confirmed inside running application container"
  echo "       ↓"
  echo -e "  ${RED}${BOLD}[IMPACT]${RESET}   Attacker has code execution inside the production workload"
  echo ""
  echo "  The entire chain passed through a legitimate-looking build pipeline."
  echo "  No build failures. No CVE alerts. No runtime errors."

  echo -e "\n${GREEN}  ✅ Attack chain fully demonstrated.${RESET}"
  echo -e "  ${BOLD}→ See README.md — 'The CleanStart Solution' for prevention.${RESET}"
}

# ==============================================================================
# MAIN — run all steps in sequence
# ==============================================================================
main() {
  echo -e "\n${BOLD}The Upstream Dependency Betrayal — Lab Replication${RESET}"
  echo    "  ⚠  FOR EDUCATIONAL USE ONLY — controlled local environment"
  echo    "  All artefacts are written to: ./lab-workspace/"
  echo    "  Steps: Prereqs → 1 Baseline → 2 Compromise → 3 Victim Build"
  echo    "         → 4 Detection Gap → 5 Verify Attack Path"

  check_prereqs
  generate_lab_files
  step1_baseline
  step2_compromise
  step3_victim_build
  step4_detection_gap
  step5_verify_attack_path

  banner "Lab Complete"
  echo "  Files generated in: ${WORK_DIR}"
  echo "    ${BASELINE_SBOM}    — trusted baseline SBOM"
  echo "    ${CURRENT_SBOM}     — post-compromise SBOM"
  echo "    ${DIGEST_FILE}       — recorded baseline digest"
  echo "    Dockerfile.poisoned  — attacker's tampered base"
  echo "    Dockerfile           — victim application build"
  echo "    app/main.py          — victim application code"
  echo ""
  echo "  To clean up:"
  echo "    docker rmi ${APP_IMAGE} ${POISONED_TAG} ${LOCAL_IMAGE} 2>/dev/null || true"
  echo "    docker stop local-registry && docker rm local-registry 2>/dev/null || true"
  echo "    rm -rf ${WORK_DIR}"
}

main "$@"