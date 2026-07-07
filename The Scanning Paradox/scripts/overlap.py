#!/usr/bin/env python3
import json, sys, os

TRIVY_P314   = "results/raw/trivy_python314.json"
GRYPE_P314   = "results/raw/grype_python314.json"
TRIVY_CS     = "results/raw/trivy_cleanstart.json"
GRYPE_CS     = "results/raw/grype_cleanstart.json"

def load_trivy(path):
    data = json.load(open(path))
    return set(
        v['VulnerabilityID']
        for r in data.get('Results', [])
        for v in (r.get('Vulnerabilities') or [])
    )

def load_grype(path):
    data = json.load(open(path))
    return set(
        m['vulnerability']['id']
        for m in data.get('matches', [])
        if m['vulnerability']['severity'] in ['Critical', 'High']
    )

def grype_summary(path):
    data = json.load(open(path))
    from collections import Counter
    sev = Counter(
        m['vulnerability']['severity']
        for m in data.get('matches', [])
    )
    return sev

def main():
    for f in [TRIVY_P314, GRYPE_P314, TRIVY_CS, GRYPE_CS]:
        if not os.path.exists(f):
            print(f"ERROR: Missing {f} — run scripts/run_scans.sh first")
            sys.exit(1)

    # python:3.14 analysis
    trivy_p314 = load_trivy(TRIVY_P314)
    grype_p314 = load_grype(GRYPE_P314)
    overlap    = trivy_p314 & grype_p314
    only_trivy = trivy_p314 - grype_p314
    only_grype = grype_p314 - trivy_p314
    consensus  = len(overlap) / max(len(trivy_p314), len(grype_p314)) * 100

    # cleanstart analysis
    trivy_cs   = load_trivy(TRIVY_CS)
    grype_cs   = load_grype(GRYPE_CS)
    grype_cs_summary = grype_summary(GRYPE_CS)

    print("=" * 56)
    print("  SCANNING PARADOX - CVE OVERLAP ANALYSIS")
    print("  May 5, 2026")
    print("=" * 56)
    print()
    print("  IMAGE 1: python:3.14 (baseline)")
    print("  " + "-" * 50)
    print(f"  Trivy  HIGH+CRIT unique CVEs : {len(trivy_p314):>4}")
    print(f"  Grype  HIGH+CRIT unique CVEs : {len(grype_p314):>4}")
    print(f"  Both agree (consensus)       : {len(overlap):>4}")
    print(f"  Only Trivy finds             : {len(only_trivy):>4}")
    print(f"  Only Grype finds             : {len(only_grype):>4}")
    print(f"  Consensus rate               : {consensus:>5.1f}%")
    print()
    print(f"  Sample - only Trivy : {sorted(only_trivy)[:3]}")
    print(f"  Sample - only Grype : {sorted(only_grype)[:3]}")
    print(f"  Sample - both agree : {sorted(overlap)[:3]}")
    print()
    print("  IMAGE 2: cleanstart/python:latest (hardened)")
    print("  " + "-" * 50)
    print(f"  Trivy  HIGH+CRIT CVEs : {len(trivy_cs):>4}  (OS: family=none)")
    print(f"  Grype  CRITICAL       : {grype_cs_summary.get('Critical', 0):>4}")
    print(f"  Grype  HIGH           : {grype_cs_summary.get('High', 0):>4}")
    print(f"  Grype  HIGH+CRIT      : {len(grype_cs):>4}")
    if grype_cs:
        print(f"  Grype findings        : {sorted(grype_cs)}")
    print()
    print("=" * 56)
    print("  COMPARISON SUMMARY")
    print("=" * 56)
    print(f"  {'Image':<30} {'Trivy':>8} {'Grype':>8} {'Consensus':>10}")
    print(f"  {'-'*56}")
    print(f"  {'python:3.14':<30} {len(trivy_p314):>8} {len(grype_p314):>8} {consensus:>9.1f}%")
    cs_consensus = "partial" if grype_cs else "100%"
    print(f"  {'cleanstart/python:latest':<30} {len(trivy_cs):>8} {len(grype_cs):>8} {cs_consensus:>10}")
    print("=" * 56)

if __name__ == "__main__":
    main()