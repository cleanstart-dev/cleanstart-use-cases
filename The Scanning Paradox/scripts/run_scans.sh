#!/bin/bash
set -e
mkdir -p results/raw

echo "=============================================="
echo " CleanStart Use Cases - Topic 11"
echo " The Scanning Paradox"
echo "=============================================="
echo ""

# -----------------------------------------------
# IMAGE 1: python:3.14 (baseline)
# -----------------------------------------------
echo "[1/4] Trivy scan on python:3.14..."
trivy image python:3.14 --severity HIGH,CRITICAL --format json \
    --output results/raw/trivy_python314.json --quiet
echo "      Done -> results/raw/trivy_python314.json"

echo "[2/4] Grype scan on python:3.14..."
grype python:3.14 --output json \
    --file results/raw/grype_python314.json 2>/dev/null
echo "      Done -> results/raw/grype_python314.json"

# -----------------------------------------------
# IMAGE 2: cleanstart/python (hardened)
# -----------------------------------------------
echo "[3/4] Trivy scan on cleanstart/python:latest..."
trivy image cleanstart/python:latest --severity HIGH,CRITICAL --format json \
    --output results/raw/trivy_cleanstart.json --quiet
echo "      Done -> results/raw/trivy_cleanstart.json"

echo "[4/4] Grype scan on cleanstart/python:latest..."
grype cleanstart/python:latest --output json \
    --file results/raw/grype_cleanstart.json 2>/dev/null
echo "      Done -> results/raw/grype_cleanstart.json"

echo ""
echo "Running overlap analysis..."
python3 scripts/overlap.py