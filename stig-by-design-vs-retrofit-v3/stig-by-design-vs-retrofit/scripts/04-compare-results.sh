#!/usr/bin/env bash
# 04-compare-results.sh
# Read both scan outputs and emit the side-by-side comparison table.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

RET="results/retrofit-scan.txt"
BYD="results/by-design-scan.txt"

if [ ! -f "$RET" ] || [ ! -f "$BYD" ]; then
    echo "[!] Run scripts/03-scan-both.sh first."
    exit 1
fi

count() { grep -c "Result.*$2$" "$1" || true; }

R_PASS=$(count "$RET" pass)
R_FAIL=$(count "$RET" fail)
R_NA=$(count   "$RET" notapplicable)
R_TOTAL=$((R_PASS + R_FAIL + R_NA))
R_PCT=$(awk "BEGIN{printf \"%.1f\", $R_PASS*100/$R_TOTAL}")

B_PASS=$(count "$BYD" pass)
B_FAIL=$(count "$BYD" fail)
B_NA=$(count   "$BYD" notapplicable)
B_TOTAL=$((B_PASS + B_FAIL + B_NA))
B_PCT=$(awk "BEGIN{printf \"%.1f\", $B_PASS*100/$B_TOTAL}")

R_SIZE=$(docker images stig-retrofit:latest  --format '{{.Size}}' 2>/dev/null || echo "n/a")
B_SIZE=$(docker images stig-by-design:latest --format '{{.Size}}' 2>/dev/null || echo "n/a")

printf "\n"
printf "STIG Hardening Comparison — Retrofit vs. By Design\n"
printf "==================================================\n"
printf "%-25s %-30s %-30s\n" "Metric" "Retrofit (Ubuntu+remediation)" "By design (CleanStart)"
printf "%-25s %-30s %-30s\n" "-------" "-----------------------------" "----------------------"
printf "%-25s %-30s %-30s\n" "Image size"      "$R_SIZE"               "$B_SIZE"
printf "%-25s %-30s %-30s\n" "Rules total"     "$R_TOTAL"              "$B_TOTAL"
printf "%-25s %-30s %-30s\n" "Rules passed"    "$R_PASS ($R_PCT%)"     "$B_PASS ($B_PCT%)"
printf "%-25s %-30s %-30s\n" "Rules failed"    "$R_FAIL"               "$B_FAIL"
printf "%-25s %-30s %-30s\n" "Rules N/A"       "$R_NA"                 "$B_NA"
printf "\n"

# Write the markdown version for the repo
cat > results/comparison.md <<EOF
# STIG scan comparison — generated $(date -u +%FT%TZ)

| Metric | Retrofit | By design |
|---|---|---|
| Image size | $R_SIZE | $B_SIZE |
| Rules evaluated | $R_TOTAL | $B_TOTAL |
| Rules passed | $R_PASS (${R_PCT}%) | $B_PASS (${B_PCT}%) |
| Rules failed | $R_FAIL | $B_FAIL |
| Rules not applicable | $R_NA | $B_NA |

Raw scan logs: \`results/retrofit-scan.txt\`, \`results/by-design-scan.txt\`
HTML reports: \`results/retrofit-scan.html\`, \`results/by-design-scan.html\`
EOF

echo "[+] results/comparison.md written."
