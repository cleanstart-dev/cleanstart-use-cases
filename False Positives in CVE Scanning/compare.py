"""
compare.py — comparison report between grafana/loki and cleanstart/loki.

Standard library only. Just Python 3.8+.

OUTPUT
------
1. CVE counts side-by-side, broken down by severity.
2. Optional package count + executable count from Syft SBOMs.
3. Optional image-size bars.
4. CVEs grouped by package, classified TRUE / LIKELY-FP / DEFINITE-FP relative
   to the Loki binary (a Go service), with a short explanation each.
5. A blunt summary the reader can screenshot.

CLASSIFICATION
--------------
Loki is a Go binary that ships statically linked. Most OS-level packages in
its container image are not reachable from the binary at runtime.

  DEFINITE_FP   kernel headers, build tools, package managers, dev manpages,
                language runtimes other than Go, debug symbols, busybox-style
                utilities. Loki cannot invoke these.
  LIKELY_FP     Other OS shared libraries and utilities (libxml2, libsqlite3,
                bash, curl, perl-base, etc.). Loki doesn't link them.
  TRUE_OR_FP    libc, libcrypto/libssl, ca-certificates, the Go stdlib.
                Marked honestly as "could be real — confirm with `ldd`".

USAGE
-----
    python3 compare.py scans/grafana_loki.json scans/cleanstart_loki.json \
        --label-standard "grafana/loki:3.7.1" \
        --label-cleanstart "cleanstart/loki:latest" \
        --packages-standard <N> --packages-cleanstart <N> \
        --execs-standard <N>    --execs-cleanstart <N> \
        --sizes "grafana/loki:3.7.1=<MB>" "cleanstart/loki:latest=<MB>"
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field


# ─── colors ─────────────────────────────────────────────────────────────────

_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


class C:
    RED   = "\033[91m" if _USE_COLOR else ""
    GREEN = "\033[92m" if _USE_COLOR else ""
    YELL  = "\033[93m" if _USE_COLOR else ""
    BLUE  = "\033[94m" if _USE_COLOR else ""
    CYAN  = "\033[96m" if _USE_COLOR else ""
    GREY  = "\033[90m" if _USE_COLOR else ""
    BOLD  = "\033[1m"  if _USE_COLOR else ""
    DIM   = "\033[2m"  if _USE_COLOR else ""
    END   = "\033[0m"  if _USE_COLOR else ""


# ─── classification rules ───────────────────────────────────────────────────

DEFINITE_FP_EXACT = {
    # Language runtimes other than Go
    "perl-base", "perl-modules-5.36", "perl-modules-5.40", "perl",
    "rsync", "git", "git-man",
    # Package management
    "apt", "dpkg", "libapt-pkg6.0", "libapt-pkg6.0t64", "libdebconfclient0",
    "apk-tools", "alpine-baselayout", "alpine-keys",
    # Editors / TTY
    "vim-common", "vim-tiny", "nano", "less", "bash", "dash", "ash",
    # Archivers / compression utilities
    "gzip", "bzip2", "xz-utils", "tar", "zstd",
    # Network utilities
    "openssh-client", "openssh-server", "iputils-ping", "wget", "curl",
    # Login / shadow / shells
    "login", "passwd", "shadow", "util-linux", "sed",
    # GnuPG
    "gnupg", "gnupg2", "gpgv", "gpg",
    # BusyBox and its sub-packages — common in Alpine images, never reached
    # from a Go binary's runtime.
    "busybox", "busybox-binsh", "busybox-extras", "busybox-static",
    "ssl_client", "scanelf",
}

# Go-module Common-CVE classification.
#
# A Go binary's reachability story for its OWN dependencies is different from
# its reachability for OS packages. If Loki imports github.com/golang-jwt/jwt
# and a CVE is filed against that module, the CVE is genuinely present in the
# binary. We can't suppress it. We mark these as "TRUE" because a code change
# (bump the dep, rebuild) is the actual fix. The cleanstart image has the same
# Loki binary, so it carries the same Go-module CVEs (one in the example).
GO_MODULE_PREFIXES = (
    "github.com/", "golang.org/", "gopkg.in/", "go.opentelemetry.io/",
    "k8s.io/", "sigs.k8s.io/", "cloud.google.com/",
)

DEFINITE_FP_PREFIXES = (
    "linux-libc-dev",
    "linux-headers",
    "binutils",
    "gcc-", "g++-", "cpp-", "libgcc-",
    "libstdc++",
    "make", "automake", "autoconf",
    "manpages", "manpages-dev",
    "libpython", "python3", "python3.",
    "libperl",
    "libllvm",
    "libdebuginfod",
    "lib64",
)

DEFINITE_FP_REGEX = re.compile(
    r"^(libgprofng|libctf|libbinutils|libtinfo|libncurses|libreadline|libpcre"
    r"|libxml2|libxslt|libexpat|libxpm|libxml|libfontconfig|libfreetype"
    r"|libheif|libjpeg|libpng|libwebp|libtiff|libsodium|libldap|libmagic"
    r"|libgcrypt|libgpg|libtasn|libidn|libdb"
    r"|libsystemd|libudev"
    r"|libsqlite|libbz|liblzma|libzstd|libnghttp"
    r"|libkrb5|libgssapi|libk5crypto"
    r"|libfdisk|libmount|libblkid|libsmartcols|libuuid"
    r"|libpam|libnsl|libcap|libacl|libattr"
    r"|libgnutls|libgmp|libnettle|libhogweed|libp11"
    r"|coreutils|findutils|grep|gawk|hostname|debianutils|init-system-helpers"
    r"|debconf|adduser|base-files|base-passwd"
    r"|netbase|tzdata|locales|ncurses-base|ncurses-bin)"
)

# Packages that *could* matter to a Go binary depending on compile flags.
TRUE_OR_FP_EXACT = {
    "libc6", "libc6-dev", "libc-dev-bin",
    "musl", "musl-utils",                                       # Alpine libc
    "libssl3", "libssl3t64", "libcrypto3", "openssl",
    "ca-certificates",
    "stdlib", "net/http", "net/mail", "html/template",
    "golang.org/x/net",
}


def classify(package: str) -> tuple[str, str]:
    if package in TRUE_OR_FP_EXACT:
        if package == "ca-certificates":
            return "TRUE_OR_FP", "TLS roots — used at runtime"
        if package.startswith("libc6") or package == "libc-dev-bin" or package.startswith("musl"):
            return "TRUE_OR_FP", "libc — only reachable if Loki uses cgo path"
        if package in {"libssl3", "libssl3t64", "libcrypto3", "openssl"}:
            return "TRUE_OR_FP", "OpenSSL — only reachable via cgo crypto path"
        return "TRUE_OR_FP", "Go runtime — confirm against your binary"

    if package in DEFINITE_FP_EXACT:
        return "DEFINITE_FP", "OS utility / language runtime not used by Loki"
    if package.startswith(DEFINITE_FP_PREFIXES):
        return "DEFINITE_FP", "kernel/dev/build artifact — never reachable"
    if DEFINITE_FP_REGEX.match(package):
        return "DEFINITE_FP", "OS shared library not linked by static Loki"

    return "LIKELY_FP", "no Loki runtime path observed; treat as FP unless proven"


# ─── data structures ────────────────────────────────────────────────────────

@dataclass
class Vuln:
    cve_id: str
    package: str
    version: str
    severity: str
    title: str = ""


@dataclass
class ScanReport:
    image: str
    vulns: list[Vuln] = field(default_factory=list)
    package_count: int | None = None
    executable_count: int | None = None

    def by_severity(self) -> dict[str, int]:
        out = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for v in self.vulns:
            out[v.severity] = out.get(v.severity, 0) + 1
        return out

    @property
    def total(self) -> int:
        return len(self.vulns)


def load_trivy(path: str, label: str | None = None) -> ScanReport:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    image = label or data.get("ArtifactName") or os.path.basename(path)
    vulns: list[Vuln] = []
    for result in data.get("Results", []) or []:
        for v in result.get("Vulnerabilities", []) or []:
            sev = (v.get("Severity") or "UNKNOWN").upper()
            if sev not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                sev = "UNKNOWN"
            vulns.append(Vuln(
                cve_id=v.get("VulnerabilityID", "?"),
                package=v.get("PkgName", "?"),
                version=v.get("InstalledVersion", "?"),
                severity=sev,
                title=(v.get("Title") or "")[:80],
            ))
    return ScanReport(image=image, vulns=vulns)


def load_sbom_counts(path: str) -> tuple[int | None, int | None]:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        return None, None

    pkg_count = len(data.get("components") or []) or None
    exec_count = None
    for comp in (data.get("components") or []):
        for prop in (comp.get("properties") or []):
            if "executable" in (prop.get("name", "") or "").lower():
                exec_count = (exec_count or 0) + 1
    return pkg_count, exec_count or None


# ─── render helpers ─────────────────────────────────────────────────────────

def _pad(n, width: int = 6) -> str:
    return str(n).rjust(width)


def _sev_count(n: int, sev: str, width: int = 6) -> str:
    text = _pad(n, width)
    if n == 0:
        return f"{C.GREEN}{text}{C.END}"
    if sev == "CRITICAL": return f"{C.RED}{C.BOLD}{text}{C.END}"
    if sev == "HIGH":     return f"{C.RED}{text}{C.END}"
    if sev == "MEDIUM":   return f"{C.YELL}{text}{C.END}"
    return f"{C.DIM}{text}{C.END}"


def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def _verdict_label(verdict: str) -> str:
    return {
        "TRUE_OR_FP":  f"{C.YELL}LIKELY TRUE{C.END}",
        "LIKELY_FP":   f"{C.GREEN}LIKELY FP {C.END}",
        "DEFINITE_FP": f"{C.GREEN}{C.BOLD}DEFINITE FP{C.END}",
    }[verdict]


# ─── main render ────────────────────────────────────────────────────────────

def render(standard: ScanReport, cleanstart: ScanReport, sizes: dict[str, float]) -> None:
    s_counts = standard.by_severity()
    c_counts = cleanstart.by_severity()

    # ── Header ─────────────────────────────────────────────────────────────
    print()
    print(f"{C.BOLD}{C.CYAN}╔════════════════════════════════════════════════════════════════════════════════╗{C.END}")
    print(f"{C.BOLD}{C.CYAN}║   LOKI CVE FALSE-POSITIVE COMPARISON                                           ║{C.END}")
    print(f"{C.BOLD}{C.CYAN}║   Same Loki binary — different base image                                     ║{C.END}")
    print(f"{C.BOLD}{C.CYAN}╚════════════════════════════════════════════════════════════════════════════════╝{C.END}")
    print()

    # ── Side-by-side severity counts ───────────────────────────────────────
    print(f"  {C.BOLD}CVE counts by severity{C.END}")
    print(f"  {'IMAGE':<34}  {'CRIT':>6} {'HIGH':>6} {'MED':>6} {'LOW':>6} {'TOTAL':>8}")
    print(f"  {'-'*34}  {'-'*6} {'-'*6} {'-'*6} {'-'*6} {'-'*8}")
    for label, counts, total in [
        (standard.image, s_counts, standard.total),
        (cleanstart.image, c_counts, cleanstart.total),
    ]:
        total_str = f"{C.GREEN}{C.BOLD}{_pad(total, 8)}{C.END}" if total == 0 else f"{C.BOLD}{_pad(total, 8)}{C.END}"
        print(
            f"  {_truncate(label, 34):<34}  "
            f"{_sev_count(counts['CRITICAL'], 'CRITICAL')} "
            f"{_sev_count(counts['HIGH'], 'HIGH')} "
            f"{_sev_count(counts['MEDIUM'], 'MEDIUM')} "
            f"{_sev_count(counts['LOW'], 'LOW')} "
            f"{total_str}"
        )
    print()

    # ── Attack surface (from SBOM) ─────────────────────────────────────────
    if standard.package_count is not None or standard.executable_count is not None:
        print(f"  {C.BOLD}Attack surface{C.END} {C.DIM}(from SBOM){C.END}")
        print(f"  {'IMAGE':<34}  {'PACKAGES':>10}  {'EXECUTABLES':>13}")
        print(f"  {'-'*34}  {'-'*10}  {'-'*13}")
        for r in (standard, cleanstart):
            pkg = str(r.package_count) if r.package_count is not None else "—"
            exe = str(r.executable_count) if r.executable_count is not None else "—"
            color_pkg = C.GREEN if r.package_count is not None and r.package_count <= 100 else ""
            color_exe = C.GREEN if r.executable_count is not None and r.executable_count <= 500 else ""
            print(f"  {_truncate(r.image, 34):<34}  {color_pkg}{pkg:>10}{C.END}  {color_exe}{exe:>13}{C.END}")
        if standard.package_count and cleanstart.package_count:
            pkg_red = (1 - cleanstart.package_count / standard.package_count) * 100
            print(f"  {C.DIM}→ {pkg_red:.0f}% fewer packages on cleanstart{C.END}")
        print()

    # ── Optional image sizes ───────────────────────────────────────────────
    if sizes:
        print(f"  {C.BOLD}Image size{C.END}")
        max_size = max(sizes.values()) if sizes else 1
        for label, mb in sizes.items():
            ratio = mb / max_size
            bar_w = 32
            filled = int(round(ratio * bar_w))
            color = C.RED if ratio > 0.66 else C.YELL if ratio > 0.33 else C.GREEN
            bar = f"{color}{'█' * filled}{C.END}{C.GREY}{'░' * (bar_w - filled)}{C.END}"
            print(f"  {_truncate(label, 34):<34}  {bar}  {mb:>7.0f} MB")
        print()

    # ── Group standard image's CVEs by package, then classify ──────────────
    pkg_groups: dict[str, list[Vuln]] = defaultdict(list)
    for v in standard.vulns:
        pkg_groups[v.package].append(v)

    classified: dict[str, list[tuple[str, list[Vuln], str]]] = {
        "DEFINITE_FP": [], "LIKELY_FP": [], "TRUE_OR_FP": [],
    }
    for pkg, vulns in pkg_groups.items():
        verdict, reason = classify(pkg)
        classified[verdict].append((pkg, vulns, reason))

    for bucket in classified.values():
        bucket.sort(key=lambda x: -len(x[1]))

    bucket_totals = {k: sum(len(v) for _, v, _ in lst) for k, lst in classified.items()}

    # ── Findings grouped by package ────────────────────────────────────────
    if standard.total > 0:
        print(f"  {C.BOLD}Findings grouped by package{C.END}  {C.DIM}(top 15 packages){C.END}")
        print(f"  {'PACKAGE':<28}  {'CVEs':>6}  {'VERDICT':<14}  REASON")
        print(f"  {'-'*28}  {'-'*6}  {'-'*14}  {'-'*42}")

        flat: list[tuple[str, list[Vuln], str, str]] = []
        for verdict in ("DEFINITE_FP", "LIKELY_FP", "TRUE_OR_FP"):
            for pkg, vulns, reason in classified[verdict]:
                flat.append((verdict, vulns, pkg, reason))
        flat.sort(key=lambda x: -len(x[1]))

        for verdict, vulns, pkg, reason in flat[:15]:
            print(
                f"  {_truncate(pkg, 28):<28}  "
                f"{C.BOLD}{len(vulns):>6}{C.END}  "
                f"{_verdict_label(verdict)}  "
                f"{C.DIM}{_truncate(reason, 42)}{C.END}"
            )
        if len(flat) > 15:
            rest = sum(len(v) for _, v, _, _ in flat[15:])
            print(f"  {C.DIM}... {len(flat) - 15} more packages, {rest} more CVEs{C.END}")
        print()

    # ── Summary ────────────────────────────────────────────────────────────
    eliminated = standard.total - cleanstart.total
    pct = (eliminated / standard.total * 100) if standard.total else 0
    fp_count = bucket_totals["DEFINITE_FP"] + bucket_totals["LIKELY_FP"]
    fp_pct = (fp_count / standard.total * 100) if standard.total else 0

    print(f"  {C.BOLD}SUMMARY{C.END}")
    print(f"  ──────────────────────────────────────────────────────────────────────")
    print(f"  {standard.image:<32}  {C.RED}{C.BOLD}{standard.total:>5}{C.END} CVEs flagged")
    print(f"  {cleanstart.image:<32}  {C.GREEN}{C.BOLD}{cleanstart.total:>5}{C.END} CVEs flagged")
    print(f"  {'CVEs eliminated':<32}  {C.GREEN}{C.BOLD}{eliminated:>5}{C.END}  ({pct:.1f}%)")
    print()
    print(f"  Of the {standard.total} CVEs in {standard.image}, classified by reachability:")
    print(f"    {C.GREEN}{C.BOLD}{bucket_totals['DEFINITE_FP']:>5}{C.END}  {C.GREEN}DEFINITE false positives{C.END} "
          f"(kernel headers, dev tools, OS libs not linked)")
    print(f"    {C.GREEN}{bucket_totals['LIKELY_FP']:>5}{C.END}  {C.GREEN}LIKELY false positives{C.END}   "
          f"(other OS packages Loki doesn't call)")
    print(f"    {C.YELL}{bucket_totals['TRUE_OR_FP']:>5}{C.END}  {C.YELL}LIKELY TRUE positives{C.END}   "
          f"(libc / openssl / ca-certs — confirm with `ldd`)")
    print()
    print(f"  {C.BOLD}~{fp_pct:.0f}% of findings on {standard.image} are not reachable from Loki.{C.END}")
    print(f"  {C.BOLD}{cleanstart.image} ships fewer of those packages, so the CVEs disappear.{C.END}")
    print()
    print(f"  {C.DIM}False positives waste triage time. Filtering helps; eliminating helps more.{C.END}")
    print()


# ─── CLI ────────────────────────────────────────────────────────────────────

def _parse_sizes(args: list[str]) -> dict[str, float]:
    out: dict[str, float] = {}
    for a in args:
        if "=" not in a:
            print(f"warning: ignoring --sizes arg without '=': {a}", file=sys.stderr)
            continue
        name, mb = a.split("=", 1)
        try:
            out[name.strip()] = float(mb)
        except ValueError:
            print(f"warning: ignoring non-numeric size for {name}: {mb}", file=sys.stderr)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Compare CVEs between grafana/loki and cleanstart/loki.",
    )
    ap.add_argument("standard_scan", help="Trivy JSON report for grafana/loki")
    ap.add_argument("cleanstart_scan", help="Trivy JSON report for cleanstart/loki")
    ap.add_argument("--label-standard", help="Override the standard image's label in the report")
    ap.add_argument("--label-cleanstart", help="Override the cleanstart image's label in the report")
    ap.add_argument("--sbom-standard", help="Optional: Syft CycloneDX SBOM for grafana/loki")
    ap.add_argument("--sbom-cleanstart", help="Optional: Syft CycloneDX SBOM for cleanstart/loki")
    ap.add_argument("--packages-standard", type=int, help="Manually set package count for grafana/loki")
    ap.add_argument("--packages-cleanstart", type=int, help="Manually set package count for cleanstart/loki")
    ap.add_argument("--execs-standard", type=int, help="Manually set executable count for grafana/loki")
    ap.add_argument("--execs-cleanstart", type=int, help="Manually set executable count for cleanstart/loki")
    ap.add_argument(
        "--sizes", nargs="*", default=[],
        help="Optional 'name=MB' pairs",
    )
    args = ap.parse_args()

    standard = load_trivy(args.standard_scan, label=args.label_standard)
    cleanstart = load_trivy(args.cleanstart_scan, label=args.label_cleanstart)

    if args.sbom_standard:
        standard.package_count, standard.executable_count = load_sbom_counts(args.sbom_standard)
    if args.sbom_cleanstart:
        cleanstart.package_count, cleanstart.executable_count = load_sbom_counts(args.sbom_cleanstart)

    if args.packages_standard is not None:
        standard.package_count = args.packages_standard
    if args.packages_cleanstart is not None:
        cleanstart.package_count = args.packages_cleanstart
    if args.execs_standard is not None:
        standard.executable_count = args.execs_standard
    if args.execs_cleanstart is not None:
        cleanstart.executable_count = args.execs_cleanstart

    sizes = _parse_sizes(args.sizes)

    render(standard, cleanstart, sizes)
    return 0


if __name__ == "__main__":
    sys.exit(main())