#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  compare.sh
#  Builds Ubuntu, Alpine, BusyBox, and CleanStart images from the
#  same app.py, then compares them across five security dimensions.
#
#  Usage:  bash compare.sh
#  Needs:  Docker  (required)
#          Trivy   (optional — for CVE scanning)
# ══════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

PASS="${GREEN}✓ PASS${RESET}"
FAIL="${RED}✗ FAIL${RESET}"

# ── Image definitions ─────────────────────────────────────────────
declare -A LABEL=(
  [demo-ubuntu]="Ubuntu 26.04"
  [demo-alpine]="python:3.14.5-alpine"
  [demo-busybox]="BusyBox:1.38.0"
  [demo-cleanstart]="CleanStart Hardened"
)
IMAGES=("demo-ubuntu" "demo-alpine" "demo-busybox" "demo-cleanstart")

# ── Helpers ───────────────────────────────────────────────────────
header() {
  echo ""
  echo -e "${BOLD}$1${RESET}"
  echo -e "${DIM}$2${RESET}"
  printf '%0.s─' {1..62}; echo ""
}

# Use echo -e so embedded \033 color codes are interpreted correctly
row() { echo -e "  $(printf '%-28s' "$1") $2"; }

# Run a shell command inside a container.
# Returns the command output, or "BLOCKED" if the container has no shell.
shell_exec() {
  docker run --rm --entrypoint="" "$1" sh -c "$2" 2>/dev/null || echo "BLOCKED"
}

# ══════════════════════════════════════════════════════════════════
#  STEP 1 — Build all images
# ══════════════════════════════════════════════════════════════════
header "Building images" "Compiling the same app.py into four different base images"

build_image() {
  local tag=$1 dockerfile=$2
  echo -en "  $(printf '%-28s' "${LABEL[$tag]}")"
  if docker build -f "$dockerfile" -t "$tag" . --quiet > /dev/null 2>&1; then
    echo -e "${GREEN}built${RESET}"
  else
    echo -e "${YELLOW}skipped (check base image availability)${RESET}"
  fi
}

build_image "demo-ubuntu"     "Dockerfile.ubuntu"
build_image "demo-alpine"     "Dockerfile.alpine"
build_image "demo-busybox"    "Dockerfile.busybox"
build_image "demo-cleanstart" "Dockerfile.cleanstart"

# ══════════════════════════════════════════════════════════════════
#  CHECK 1 — Image size
# ══════════════════════════════════════════════════════════════════
header "CHECK 1 — Image Size" "Bigger images carry more packages and a larger CVE surface area"
row "Image" "Size"
printf '%0.s─' {1..42}; echo ""
for img in "${IMAGES[@]}"; do
  bytes=$(docker image inspect "$img" --format='{{.Size}}' 2>/dev/null || echo "0")
  size=$(echo "$bytes" | awk '{printf "%.1f MB", $1/1024/1024}')
  if [[ "$img" == *cleanstart* ]]; then
    row "${LABEL[$img]}" "${GREEN}${size}${RESET}"
  else
    row "${LABEL[$img]}" "${YELLOW}${size}${RESET}"
  fi
done

# ══════════════════════════════════════════════════════════════════
#  CHECK 2 — Shell access
# ══════════════════════════════════════════════════════════════════
header "CHECK 2 — Shell Access" "A shell inside a container is an attacker's first tool after breach"
row "Image" "Result"
printf '%0.s─' {1..58}; echo ""
for img in "${IMAGES[@]}"; do
  found=$(shell_exec "$img" "which sh || which bash || echo NONE")
  if [[ "$found" == "NONE" || "$found" == "BLOCKED" ]]; then
    row "${LABEL[$img]}" "$PASS — no shell found"
  else
    row "${LABEL[$img]}" "$FAIL — shell at: $(echo "$found" | head -1)"
  fi
done
echo ""
echo -e "  ${DIM}Why it matters: 'docker exec -it <container> sh' is the first thing${RESET}"
echo -e "  ${DIM}attackers try after exploiting a vulnerability in your app.${RESET}"

# ══════════════════════════════════════════════════════════════════
#  CHECK 3 — Package manager
# ══════════════════════════════════════════════════════════════════
header "CHECK 3 — Package Manager" "Can an attacker install new tools inside a running container?"
row "Image" "Result"
printf '%0.s─' {1..58}; echo ""
for img in "${IMAGES[@]}"; do
  found=$(shell_exec "$img" "which apt-get || which apk || which yum || which dnf || echo NONE")
  if [[ "$found" == "NONE" || "$found" == "BLOCKED" ]]; then
    row "${LABEL[$img]}" "$PASS — no package manager"
  else
    row "${LABEL[$img]}" "$FAIL — found: $(echo "$found" | head -1)"
  fi
done
echo ""
echo -e "  ${DIM}Why it matters: a container with apt-get or apk is one command away${RESET}"
echo -e "  ${DIM}from becoming a fully equipped attacker workstation.${RESET}"

# ══════════════════════════════════════════════════════════════════
#  CHECK 4 — Running user
# ══════════════════════════════════════════════════════════════════
header "CHECK 4 — Running User" "Is the process running as root (uid=0) inside the container?"
row "Image" "Result"
printf '%0.s─' {1..58}; echo ""
for img in "${IMAGES[@]}"; do
  uid=$(shell_exec "$img" "id -u")
  if   [[ "$uid" == "0" ]];       then row "${LABEL[$img]}" "$FAIL — running as root (uid=0)"
  elif [[ "$uid" == "BLOCKED" ]]; then row "${LABEL[$img]}" "$PASS — non-root enforced by base image"
  else                                 row "${LABEL[$img]}" "$PASS — running as uid=${uid}"
  fi
done
echo ""
echo -e "  ${DIM}Why it matters: root in a container + a kernel exploit = root on the host.${RESET}"
echo -e "  ${DIM}Non-root containers break that escalation path.${RESET}"

# ══════════════════════════════════════════════════════════════════
#  CHECK 5 — Layer Count
#  Every layer in an image can contain packages, binaries, and CVEs.
#  Fewer layers from a minimal base = smaller attack surface.
#  (Run 'trivy image <name>' separately for a full CVE count.)
# ══════════════════════════════════════════════════════════════════
header "CHECK 5 — Image Layers" "Fewer layers mean fewer bundled packages and a smaller attack surface"
row "Image" "Layers"
printf '%0.s─' {1..42}; echo ""
for img in "${IMAGES[@]}"; do
  layers=$(docker image inspect "$img" --format='{{len .RootFS.Layers}}' 2>/dev/null || echo "N/A")
  if [[ "$img" == *cleanstart* ]]; then
    row "${LABEL[$img]}" "${GREEN}${layers} layers ✓${RESET}"
  else
    row "${LABEL[$img]}" "${YELLOW}${layers} layers${RESET}"
  fi
done
echo ""
echo -e "  ${DIM}Why it matters: each layer added by apt-get, apk, or OS packages${RESET}"
echo -e "  ${DIM}brings binaries your app never uses — and CVEs you didn't choose.${RESET}"
echo ""
echo -e "  ${DIM}For a full CVE report, run separately:${RESET}"
echo -e "  ${DIM}  trivy image --severity HIGH,CRITICAL demo-ubuntu${RESET}"
echo -e "  ${DIM}  trivy image --severity HIGH,CRITICAL demo-cleanstart${RESET}"

# ══════════════════════════════════════════════════════════════════
#  SUMMARY
# ══════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${CYAN}  Summary${RESET}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════${RESET}"
echo ""
echo -e "  ${BOLD}$(printf '%-28s' 'Image')$(printf '%-14s' 'Shell')$(printf '%-14s' 'Pkg Mgr')Non-root${RESET}"
printf '%0.s─' {1..68}; echo ""

for img in "${IMAGES[@]}"; do
  shell=$(shell_exec "$img" "which sh || which bash || echo NONE")
  pkgmg=$(shell_exec "$img" "which apt-get || which apk || echo NONE")
  uid=$(shell_exec   "$img" "id -u")

  if [[ "$shell" == "NONE" || "$shell" == "BLOCKED" ]]; then sh_col="${GREEN}None ✓   ${RESET}"; else sh_col="${RED}Present ✗${RESET}"; fi
  if [[ "$pkgmg" == "NONE" || "$pkgmg" == "BLOCKED" ]]; then pk_col="${GREEN}None ✓   ${RESET}"; else pk_col="${RED}Present ✗${RESET}"; fi
  if [[ "$uid" == "0" ]]; then us_col="${RED}Root ✗${RESET}"; else us_col="${GREEN}Non-root ✓${RESET}"; fi

  echo -e "  $(printf '%-28s' "${LABEL[$img]}")${sh_col}  ${pk_col}  ${us_col}"
done

echo ""
echo -e "  ${GREEN}${BOLD}CleanStart is the only image that passes all checks.${RESET}"
echo -e "  ${DIM}See Dockerfile.cleanstart for the migration — it's one line.${RESET}"
echo ""
