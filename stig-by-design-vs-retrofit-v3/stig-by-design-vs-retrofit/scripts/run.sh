#!/usr/bin/env bash
# run.sh — build both images and print the side-by-side comparison.
# Usage: bash scripts/run.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

mkdir -p results app
cat > app/server <<'EOF'
#!/bin/sh
echo "by-design placeholder"
EOF
chmod +x app/server

build() {
    local label=$1 dockerfile=$2 image=$3
    echo "[*] Building $image ..."
    local start=$(date +%s)
    docker build --no-cache -f "$dockerfile" -t "$image" . > "results/${label}.log" 2>&1
    local elapsed=$(( $(date +%s) - start ))
    local size
    size=$(docker images "$image" --format '{{.Size}}')
    echo "    done — ${elapsed}s  ${size}"
    echo "$label,$elapsed,$size" >> results/timings.csv
}

echo "label,build_seconds,image_size" > results/timings.csv

build retrofit  configs/Dockerfile.retrofit  stig-retrofit:latest
build by-design configs/Dockerfile.by-design stig-by-design:latest

R_SIZE=$(docker images stig-retrofit:latest  --format '{{.Size}}')
B_SIZE=$(docker images stig-by-design:latest --format '{{.Size}}')

# retrofit: package count via dpkg
R_PKGS=$(docker run --rm --entrypoint dpkg stig-retrofit:latest -l 2>/dev/null | grep -c '^ii' || echo "n/a")

# by-design: check if any package manager exists
if docker run --rm stig-by-design:latest dpkg --version >/dev/null 2>&1; then
    B_PKGS=$(docker run --rm stig-by-design:latest dpkg -l 2>/dev/null | grep -c '^ii')
else
    B_PKGS="none (no pkg manager)"
fi

# check user
R_USER=$(docker inspect stig-retrofit:latest  --format '{{.Config.User}}')
B_USER=$(docker inspect stig-by-design:latest --format '{{.Config.User}}')

# check if shell is present
R_SHELL=$(docker run --rm --entrypoint "" stig-retrofit:latest  sh -c "command -v bash || command -v sh" 2>/dev/null || echo "none")
B_SHELL=$(docker run --rm --entrypoint "" stig-by-design:latest sh -c "command -v bash || command -v sh" 2>/dev/null || echo "none")

printf "\n"
printf "%-28s %-28s %-28s\n" "Metric" "Retrofit (Ubuntu+remediation)" "By design (CleanStart)"
printf "%-28s %-28s %-28s\n" "------" "------------------------------" "----------------------"
printf "%-28s %-28s %-28s\n" "Image size"         "$R_SIZE"   "$B_SIZE"
printf "%-28s %-28s %-28s\n" "Packages"           "$R_PKGS"   "$B_PKGS"
printf "%-28s %-28s %-28s\n" "Default user"       "$R_USER"   "$B_USER"
printf "%-28s %-28s %-28s\n" "Shell present"      "$R_SHELL"  "$B_SHELL"
printf "%-28s %-28s %-28s\n" "Remediation script" "354 lines" "none"
printf "\n"
echo "[+] Full build logs: results/retrofit.log  results/by-design.log"
echo "[+] Timings: results/timings.csv"
