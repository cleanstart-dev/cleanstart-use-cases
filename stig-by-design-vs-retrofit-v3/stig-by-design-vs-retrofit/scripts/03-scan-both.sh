#!/usr/bin/env bash
# 03-scan-both.sh
# Run OpenSCAP STIG profile against both images and capture results.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

mkdir -p results

# Pick the right SSG content for Ubuntu 22.04
SSG_CONTENT="/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml"
PROFILE="xccdf_org.ssgproject.content_profile_stig"

if [ ! -f "$SSG_CONTENT" ]; then
    echo "[!] SCAP Security Guide content not found at $SSG_CONTENT"
    echo "[!] Install with: apt-get install ssg-debderived  (or ssg-base for RHEL)"
    exit 1
fi

if ! command -v oscap-docker >/dev/null 2>&1; then
    echo "[!] oscap-docker not found. Install openscap-utils."
    exit 1
fi

scan_image() {
    local image=$1
    local label=$2
    local out="results/${label}-scan"

    echo ""
    echo "[*] Scanning $image with profile $PROFILE"
    echo "[*] Output: ${out}.{txt,html,xml}"

    local start=$(date +%s)

    # oscap-docker spawns a temporary container, mounts the rootfs,
    # and runs OpenSCAP against it. Image must exist locally.
    oscap-docker image "$image" xccdf eval \
        --profile "$PROFILE" \
        --results "${out}.xml" \
        --report "${out}.html" \
        "$SSG_CONTENT" \
        > "${out}.txt" 2>&1 || true   # exit code is non-zero on any rule failure

    local end=$(date +%s)
    local elapsed=$((end - start))

    # Tally the result counts from the raw output
    local pass=$(grep -c "Result.*pass$"     "${out}.txt" || echo 0)
    local fail=$(grep -c "Result.*fail$"     "${out}.txt" || echo 0)
    local notapp=$(grep -c "Result.*notapplicable$" "${out}.txt" || echo 0)
    local total=$((pass + fail + notapp))

    echo "    duration: ${elapsed}s"
    echo "    rules:    $total total | pass: $pass | fail: $fail | n/a: $notapp"

    echo "${label}_scan,${elapsed},${total},${pass},${fail},${notapp}" \
        >> results/timings.csv
}

scan_image "stig-retrofit:latest"  "retrofit"
scan_image "stig-by-design:latest" "by-design"

echo ""
echo "[+] Both scans complete. Run scripts/04-compare-results.sh for the summary."
