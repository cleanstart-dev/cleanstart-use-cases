#!/usr/bin/env python3
"""
analyze.py
----------
Reads scan_results/summary.json and the individual .trivy.json files
produced by scan.sh, then writes docs/index.html.

Run after scan.sh:
  python3 analyze.py
  python3 analyze.py --min-severity MEDIUM
  python3 analyze.py --no-require-fix
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

SEV_WEIGHT = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


# ── CVE processing ─────────────────────────────────────────────────────────────

def patch_lag(published_date):
    if not published_date:
        return None
    try:
        pub = datetime.fromisoformat(published_date.replace("Z", "+00:00"))
        return max(0, (datetime.now(timezone.utc) - pub).days)
    except Exception:
        return None


def score(severity, lag, has_fix):
    base  = SEV_WEIGHT.get(severity, 0) * 25.0
    bonus = max(0, (lag or 0) - 14) * 0.1
    fix   = 5.0 if has_fix else 0.0
    return round(base + bonus + fix, 1)


def extract_cves(trivy_doc, min_sev, require_fix):
    min_w      = SEV_WEIGHT.get(min_sev.upper(), 3)
    seen       = set()
    result     = []
    image      = trivy_doc.get("_meta", {}).get("image", trivy_doc.get("ArtifactName", "unknown"))
    image_type = trivy_doc.get("_meta", {}).get("image_type", "public")

    for r in trivy_doc.get("Results", []):
        for v in r.get("Vulnerabilities") or []:
            cve_id   = v.get("VulnerabilityID", "")
            pkg      = v.get("PkgName", "")
            severity = v.get("Severity", "UNKNOWN").upper()
            fixed    = v.get("FixedVersion")
            key      = f"{cve_id}::{pkg}"

            if key in seen:           continue
            seen.add(key)
            if SEV_WEIGHT.get(severity, 0) < min_w: continue
            if require_fix and not fixed:            continue

            lag = patch_lag(v.get("PublishedDate"))
            result.append({
                "cve_id":            cve_id,
                "package":           pkg,
                "installed_version": v.get("InstalledVersion", ""),
                "fixed_version":     fixed,
                "severity":          severity,
                "title":             v.get("Title", ""),
                "image":             image,
                "image_type":        image_type,
                "published_date":    v.get("PublishedDate"),
                "patch_lag_days":    lag,
                "priority_score":    score(severity, lag, bool(fixed)),
            })

    return sorted(result, key=lambda c: c["priority_score"], reverse=True)


# ── HTML ───────────────────────────────────────────────────────────────────────

def render_html(summary, all_cves, totals, config):
    ts      = summary["scanned_at"][:16].replace("T", " ")
    avg_red = summary.get("avg_reduction_pct", 0)
    pub_tot = summary.get("total_public_cves", 0)
    cs_tot  = summary.get("total_cleanstart_cves", 0)
    n_pairs = len(summary.get("pairs", []))

    bsev    = totals["by_severity"]
    action  = totals["actionable"]
    eng_hrs = action * 4

    pub_ch = sum(
        p["public"]["by_severity"].get("CRITICAL",0) + p["public"]["by_severity"].get("HIGH",0)
        for p in summary.get("pairs", [])
    )
    cs_ch = sum(
        p["cleanstart"]["by_severity"].get("CRITICAL",0) + p["cleanstart"]["by_severity"].get("HIGH",0)
        for p in summary.get("pairs", [])
    )
    ch_red = round((1 - cs_ch / max(pub_ch, 1)) * 100)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>patch-treadmill — CleanStart vs Public · {ts}</title>
<style>
:root{{--bg:#0d1117;--s1:#161b22;--s2:#21262d;--bd:#30363d;--tx:#e6edf3;--mu:#8b949e;--dim:#484f58;
  --crit:#ff4d6d;--high:#ff9f43;--med:#ffd32a;--low:#56d364;--acc:#58a6ff;--grn:#3fb950;--pur:#bc8cff;
  --pub:#ff9f43;--cs:#3fb950}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--tx);font-family:system-ui,sans-serif;font-size:14px;line-height:1.6}}
.page{{max-width:1080px;margin:0 auto;padding:2.5rem 1.5rem}}
a{{color:var(--acc)}}
.hdr{{display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:1rem;
  padding-bottom:1.5rem;border-bottom:1px solid var(--bd);margin-bottom:2.5rem}}
.hdr h1{{font-size:1.4rem;font-weight:600}}
.hdr .sub{{font-size:.8rem;color:var(--mu);margin-top:.2rem}}
.big{{font-size:2.6rem;font-weight:700;color:var(--grn);line-height:1;text-align:right}}
.big-lbl{{font-size:.7rem;color:var(--mu);text-transform:uppercase;letter-spacing:.05em;text-align:right}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:1rem;margin-bottom:2.5rem}}
.card{{background:var(--s1);border:1px solid var(--bd);border-radius:10px;padding:1.1rem 1.3rem}}
.card .lbl{{font-size:.67rem;color:var(--mu);text-transform:uppercase;letter-spacing:.05em;margin-bottom:.3rem}}
.card .val{{font-size:1.9rem;font-weight:700;line-height:1.1}}
.card .note{{font-size:.7rem;color:var(--mu);margin-top:.2rem}}
.o .val{{color:var(--high)}} .g .val{{color:var(--grn)}} .r .val{{color:var(--crit)}}
.b .val{{color:var(--acc)}} .p .val{{color:var(--pur)}}
.box{{background:var(--s1);border:1px solid var(--bd);border-radius:10px;padding:1.8rem 2rem;margin-bottom:2.5rem}}
.box h2{{font-size:1rem;font-weight:600;color:var(--acc);margin-bottom:1.3rem}}
.pipeline{{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;margin-bottom:1.5rem}}
@media(max-width:640px){{.pipeline{{grid-template-columns:1fr}}}}
.pl-col h3{{font-size:.75rem;font-weight:600;text-transform:uppercase;letter-spacing:.06em;
  padding:.4rem .8rem;border-radius:4px;margin-bottom:.8rem;display:inline-block}}
.pl-col.pub h3{{background:#ff9f4318;color:var(--pub);border:1px solid #ff9f4330}}
.pl-col.cs  h3{{background:#3fb95018;color:var(--cs) ;border:1px solid #3fb95030}}
.pl-steps{{display:flex;flex-direction:column;gap:.6rem}}
.pl-step{{display:flex;gap:.7rem;align-items:flex-start}}
.pl-dot{{width:20px;height:20px;border-radius:50%;font-size:.65rem;font-weight:700;
  display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:.1rem}}
.pl-col.pub .pl-dot{{background:#ff9f4320;color:var(--pub);border:1px solid #ff9f4330}}
.pl-col.cs  .pl-dot{{background:#3fb95020;color:var(--cs) ;border:1px solid #3fb95030}}
.pl-text{{font-size:.8rem;color:var(--mu);line-height:1.55}}
.pl-text strong{{color:var(--tx)}}
.pl-time{{display:inline-block;font-size:.68rem;font-weight:600;padding:.1rem .45rem;
  border-radius:3px;margin-top:.2rem}}
.pl-col.pub .pl-time{{background:#ff9f4315;color:var(--pub)}}
.pl-col.cs  .pl-time{{background:#3fb95015;color:var(--cs)}}
.diff-row{{display:grid;grid-template-columns:1fr 1fr;gap:1rem;padding:.65rem 0;
  border-bottom:1px solid var(--bd);font-size:.8rem}}
.diff-row:last-child{{border-bottom:none}}
.diff-row .aspect{{font-weight:500;color:var(--tx);margin-bottom:.1rem}}
.diff-row .pub-val{{color:var(--high);font-size:.78rem}}
.diff-row .cs-val {{color:var(--grn) ;font-size:.78rem}}
.sec-title{{font-size:.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.07em;
  color:var(--mu);padding-bottom:.5rem;border-bottom:1px solid var(--bd);margin-bottom:1.3rem}}
.sec{{margin-bottom:3rem}}
.cmp-list{{display:flex;flex-direction:column;gap:1rem}}
.cmp-row{{background:var(--s1);border:1px solid var(--bd);border-radius:10px;padding:1.2rem 1.4rem}}
.cmp-hdr{{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.5rem;margin-bottom:1rem}}
.pair{{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}}
.itag{{font-family:monospace;font-size:.75rem;padding:.18rem .6rem;border-radius:4px;font-weight:500}}
.itag.p{{background:#ff9f4315;color:var(--pub);border:1px solid #ff9f4330}}
.itag.c{{background:#3fb95015;color:var(--cs) ;border:1px solid #3fb95030}}
.rbadge{{font-size:.72rem;font-weight:700;padding:.2rem .75rem;border-radius:20px;
  background:#3fb95018;color:var(--grn);border:1px solid #3fb95035}}
.leg{{display:flex;gap:1rem;margin-bottom:.6rem}}
.dot{{width:8px;height:8px;border-radius:50%;display:inline-block;margin-right:.3rem;vertical-align:middle}}
.dot.p{{background:var(--pub)}} .dot.c{{background:var(--cs)}}
.leg-lbl{{font-size:.72rem;color:var(--mu)}}
.bars{{display:flex;flex-direction:column;gap:.4rem}}
.brow{{display:flex;align-items:center;gap:.7rem}}
.blbl{{font-size:.7rem;color:var(--mu);width:50px;text-align:right;flex-shrink:0}}
.bwrap{{flex:1;display:flex;flex-direction:column;gap:2px}}
.bt{{background:var(--s2);border-radius:3px;height:14px;overflow:hidden}}
.bf{{height:100%;border-radius:3px;display:flex;align-items:center;justify-content:flex-end;padding-right:5px}}
.bf span{{font-size:.62rem;font-weight:700;color:#fff;opacity:.9}}
.bf.p{{background:#ff9f43cc}} .bf.c{{background:#3fb950cc}}
.pills{{display:flex;gap:.3rem;flex-wrap:wrap;margin-top:.75rem;padding-top:.7rem;border-top:1px solid var(--bd)}}
.pill{{font-size:.62rem;font-weight:600;padding:.12rem .45rem;border-radius:3px}}
.pill.C{{background:#ff4d6d18;color:var(--crit);border:1px solid #ff4d6d30}}
.pill.H{{background:#ff9f4318;color:var(--high);border:1px solid #ff9f4330}}
.pill.M{{background:#ffd32a18;color:var(--med) ;border:1px solid #ffd32a30}}
.pill.L{{background:#56d36418;color:var(--low) ;border:1px solid #56d36430}}
.clean{{font-size:.75rem;color:var(--grn);font-weight:500}}
table{{width:100%;border-collapse:collapse}}
thead th{{text-align:left;font-size:.67rem;color:var(--mu);text-transform:uppercase;
  letter-spacing:.05em;border-bottom:1px solid var(--bd);padding:.45rem .65rem}}
tbody tr{{border-bottom:1px solid var(--bd)}}
tbody tr:hover{{background:var(--s1)}}
td{{padding:.5rem .65rem;vertical-align:top}}
.badge{{display:inline-block;padding:.12rem .45rem;border-radius:3px;font-size:.64rem;font-weight:700}}
.badge.CRITICAL{{background:#ff4d6d18;color:var(--crit);border:1px solid #ff4d6d30}}
.badge.HIGH    {{background:#ff9f4318;color:var(--high);border:1px solid #ff9f4330}}
.badge.MEDIUM  {{background:#ffd32a18;color:var(--med) ;border:1px solid #ffd32a30}}
.badge.LOW     {{background:#56d36418;color:var(--low) ;border:1px solid #56d36430}}
code{{font-family:monospace;font-size:.76rem}}
.lag{{font-size:.7rem;color:var(--mu)}}
.lag.old{{color:var(--high)}} .lag.stale{{color:var(--crit)}}
footer{{border-top:1px solid var(--bd);padding-top:1rem;font-size:.7rem;color:var(--dim);margin-top:3rem}}
</style>
</head>
<body><div class="page">

<div class="hdr">
  <div>
    <h1>🛡️ patch-treadmill — CleanStart vs Public Images</h1>
    <div class="sub">
      Real scan: syft SBOM → trivy CVE analysis &nbsp;·&nbsp; {ts} &nbsp;·&nbsp;
      {n_pairs} image pairs &nbsp;·&nbsp;
      min severity: {config['min_severity']} &nbsp;·&nbsp;
      require fix: {config['require_fix']}
    </div>
  </div>
  <div>
    <div class="big-lbl">avg CVE reduction</div>
    <div class="big">{avg_red}%</div>
  </div>
</div>

<div class="cards">
  <div class="card o">
    <div class="lbl">Public CVEs</div><div class="val">{pub_tot}</div>
    <div class="note">across {n_pairs} images</div>
  </div>
  <div class="card g">
    <div class="lbl">CleanStart CVEs</div><div class="val">{cs_tot}</div>
    <div class="note">near-zero footprint</div>
  </div>
  <div class="card r">
    <div class="lbl">CVEs eliminated</div><div class="val">{pub_tot - cs_tot}</div>
    <div class="note">by switching</div>
  </div>
  <div class="card p">
    <div class="lbl">Critical+High cut</div><div class="val">{ch_red}%</div>
    <div class="note">highest-risk CVEs</div>
  </div>
  <div class="card b">
    <div class="lbl">Eng-hrs saved / yr</div><div class="val">{eng_hrs}</div>
    <div class="note">vs manual triage+rebuild</div>
  </div>
</div>

<div class="box">
  <h2>🔧 How CleanStart resolves image patching without manual effort</h2>

  <div class="pipeline">
    <div class="pl-col pub">
      <h3>Public image workflow</h3>
      <div class="pl-steps">
        <div class="pl-step">
          <div class="pl-dot">1</div>
          <div class="pl-text"><strong>CVE disclosed</strong><br>
            Scanner fires alert. Engineer opens ticket and starts reading the advisory.</div>
        </div>
        <div class="pl-step">
          <div class="pl-dot">2</div>
          <div class="pl-text"><strong>Manual triage</strong><br>
            Check each image's SBOM — is the package present? Is it in the runtime path? Repeat for every affected image.
            <div><span class="pl-time">~2h per image</span></div>
          </div>
        </div>
        <div class="pl-step">
          <div class="pl-dot">3</div>
          <div class="pl-text"><strong>Rebuild and test</strong><br>
            Update Dockerfile or base tag, push branch, wait for CI, fix regressions.</div>
        </div>
        <div class="pl-step">
          <div class="pl-dot">4</div>
          <div class="pl-text"><strong>Re-deploy</strong><br>
            Merge, deploy, run scanner again to confirm fix.
            <div><span class="pl-time">7–14 day avg patch lag industry-wide</span></div>
          </div>
        </div>
        <div class="pl-step">
          <div class="pl-dot">5</div>
          <div class="pl-text"><strong>Repeat for next CVE</strong><br>
            New CVE drops next week. Cycle starts again.</div>
        </div>
      </div>
    </div>

    <div class="pl-col cs">
      <h3>CleanStart workflow</h3>
      <div class="pl-steps">
        <div class="pl-step">
          <div class="pl-dot">1</div>
          <div class="pl-text"><strong>CVE disclosed</strong><br>
            Agentic system detects affected images automatically from CVE feed. No human involved.</div>
        </div>
        <div class="pl-step">
          <div class="pl-dot">2</div>
          <div class="pl-text"><strong>Automated impact assessment</strong><br>
            Is the package present? Is it runtime-reachable? If the image doesn't include the package
            (most OS utilities aren't in CleanStart minimal images), the CVE doesn't apply.
            <div><span class="pl-time">zero manual triage</span></div>
          </div>
        </div>
        <div class="pl-step">
          <div class="pl-dot">3</div>
          <div class="pl-text"><strong>Automated patch + test</strong><br>
            Patch applied via locked source deps and hermetic build. Automated compatibility tests run.</div>
        </div>
        <div class="pl-step">
          <div class="pl-dot">4</div>
          <div class="pl-text"><strong>Patched image published</strong><br>
            Signed with cosign, updated SBOM generated, image published to CleanStart registry.
            <div><span class="pl-time">same day for CRITICAL, hours for HIGH</span></div>
          </div>
        </div>
        <div class="pl-step">
          <div class="pl-dot">5</div>
          <div class="pl-text"><strong>Teams pull and go</strong><br>
            Update one image tag and re-deploy. No Dockerfile changes, no CI changes, no false-positive triage.</div>
        </div>
      </div>
    </div>
  </div>

  <div style="margin-top:1.5rem;padding-top:1.2rem;border-top:1px solid var(--bd)">
    <div style="font-size:.72rem;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--mu);margin-bottom:.8rem">Side-by-side comparison</div>
    {_diff_table()}
  </div>
</div>

<div class="sec">
  <div class="sec-title">Image-by-image CVE comparison — real syft + trivy data</div>
  <div class="cmp-list">{_comparison_rows(summary.get('pairs', []))}</div>
</div>

<div class="sec">
  <div class="sec-title">Actionable CVEs in public images — ranked by priority score</div>
  <table>
    <thead><tr>
      <th>CVE</th><th>Severity</th><th>Package</th><th>Fix version</th>
      <th>Image</th><th>Patch lag</th><th>Score</th>
    </tr></thead>
    <tbody>{_cve_table(all_cves)}</tbody>
  </table>
</div>

<footer>
  Generated by <strong>patch-treadmill</strong> &nbsp;·&nbsp;
  SBOM: <a href="https://github.com/anchore/syft" target="_blank">syft</a> (CycloneDX JSON) &nbsp;·&nbsp;
  CVE scan: <a href="https://aquasecurity.github.io/trivy" target="_blank">trivy sbom</a> &nbsp;·&nbsp;
  <a href="https://www.cleanstart.com" target="_blank">cleanstart.com</a>
</footer>
</div></body></html>"""


def _diff_table():
    rows = [
        ("Triage effort per CVE",       "~2h per image, manual",              "Zero — automated detection"),
        ("Packages in image",           "Everything in base OS layer",         "Only what the app needs at runtime"),
        ("Patch lag (CRITICAL)",        "7–14 days industry average",          "Same day — agentic workflow"),
        ("Rebuild required by team",    "Yes — Dockerfile + CI + deploy",      "No — pull updated tag"),
        ("SBOM + provenance",           "Manual if documented at all",         "Automatic — signed cosign + SLSA"),
        ("CVE noise",                   "Hundreds of raw findings per image",  "Near zero — structural, not just patched"),
    ]
    html = ""
    for aspect, pub_val, cs_val in rows:
        html += f"""<div class="diff-row">
  <div><div class="aspect">{aspect}</div></div>
  <div><div class="pub-val">⚠ {pub_val}</div></div>
  <div><div class="cs-val">✓ {cs_val}</div></div>
</div>"""
    # header
    header = """<div class="diff-row" style="font-size:.68rem;color:var(--mu);font-weight:600;text-transform:uppercase;letter-spacing:.04em">
  <div>Aspect</div><div style="color:var(--pub)">Public images</div><div style="color:var(--cs)">CleanStart</div>
</div>"""
    return header + html


def _sev_pills(by_sev):
    out = []
    for s, cls in (("CRITICAL","C"),("HIGH","H"),("MEDIUM","M"),("LOW","L")):
        n = by_sev.get(s, 0)
        if n:
            out.append(f'<span class="pill {cls}">{s[0]} {n}</span>')
    return "".join(out) if out else '<span class="clean">✓ Clean</span>'


def _comparison_rows(pairs):
    rows = []
    for p in pairs:
        ps   = p["public"]["by_severity"]
        cs_s = p["cleanstart"]["by_severity"]
        mx   = max(p["public"]["total_cves"], 1)
        bars = ""
        for sev in ("CRITICAL","HIGH","MEDIUM","LOW"):
            pn = ps.get(sev, 0); cn = cs_s.get(sev, 0)
            if not pn and not cn: continue
            pw = int(pn/mx*100); cw = int(cn/mx*100)
            pc = f"<span>{pn}</span>" if pn else ""
            cc = f"<span>{cn}</span>" if cn else ""
            bars += (f'<div class="brow"><span class="blbl">{sev[:3]}</span>'
                     f'<div class="bwrap">'
                     f'<div class="bt"><div class="bf p" style="width:{pw}%">{pc}</div></div>'
                     f'<div class="bt"><div class="bf c" style="width:{cw}%">{cc}</div></div>'
                     f'</div></div>')
        rows.append(f"""<div class="cmp-row">
  <div class="cmp-hdr">
    <div class="pair">
      <span class="itag p">{p['public']['image']}</span>
      <span style="color:#484f58">→</span>
      <span class="itag c">{p['cleanstart']['image']}</span>
    </div>
    <span class="rbadge">↓ {p['reduction_pct']}% CVE reduction</span>
  </div>
  <div class="leg">
    <span><span class="dot p"></span><span class="leg-lbl">Public — {p['public']['total_cves']} CVEs</span></span>
    <span><span class="dot c"></span><span class="leg-lbl">CleanStart — {p['cleanstart']['total_cves']} CVEs</span></span>
  </div>
  <div class="bars">{bars}</div>
  <div class="pills">
    <span style="font-size:.7rem;color:var(--mu);margin-right:.3rem">Public:</span>{_sev_pills(ps)}
    <span style="font-size:.7rem;color:var(--mu);margin-left:.8rem;margin-right:.3rem">CleanStart:</span>{_sev_pills(cs_s)}
  </div>
</div>""")
    return "\n".join(rows)


def _cve_table(cves):
    if not cves:
        return '<tr><td colspan="7" style="text-align:center;color:var(--grn);padding:2rem">✓ No actionable CVEs at this threshold</td></tr>'
    mx   = cves[0]["priority_score"]
    rows = []
    for c in cves:
        lag   = c.get("patch_lag_days")
        lag_s = f"{lag}d" if lag else "—"
        cls   = " stale" if lag and lag > 60 else (" old" if lag and lag > 30 else "")
        bw    = int(min(80, c["priority_score"] / max(mx, 1) * 80))
        rows.append(f"""<tr>
  <td><code>{c['cve_id']}</code></td>
  <td><span class="badge {c['severity']}">{c['severity']}</span></td>
  <td><code>{c['package']}</code><br>
      <span style="font-size:.7rem;color:var(--mu)">{c.get('title','')[:72]}</span></td>
  <td><code style="color:var(--low)">{c.get('fixed_version') or '—'}</code></td>
  <td style="font-size:.75rem">{c['image']}</td>
  <td><span class="lag{cls}">{lag_s}</span></td>
  <td style="font-size:.72rem;color:var(--mu)">{c['priority_score']}
    <div style="background:var(--acc);height:3px;border-radius:2px;width:{bw}px;margin-top:3px"></div>
  </td>
</tr>""")
    return "\n".join(rows)


# ── main ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Analyze SBOM-based Trivy results and generate report")
    ap.add_argument("--scan-dir",       default="scan_results")
    ap.add_argument("--min-severity",   default="HIGH",
                    choices=["CRITICAL","HIGH","MEDIUM","LOW"])
    ap.add_argument("--no-require-fix", action="store_true")
    ap.add_argument("--out",            default="docs/index.html")
    args = ap.parse_args()

    summary_path = os.path.join(args.scan_dir, "summary.json")
    if not os.path.exists(summary_path):
        print(f"\n❌  {summary_path} not found")
        print(f"    Run scan.sh first to generate SBOM + CVE data.\n")
        sys.exit(1)

    with open(summary_path) as f:
        summary = json.load(f)

    require_fix = not args.no_require_fix
    config      = {"min_severity": args.min_severity, "require_fix": require_fix}

    # Only extract actionable CVEs from public images
    all_cves = []
    for entry in summary.get("images", []):
        if entry["image_type"] != "public":
            continue
        path = os.path.join(args.scan_dir, entry["trivy_file"])
        if not os.path.exists(path):
            continue
        with open(path) as f:
            doc = json.load(f)
        all_cves.extend(extract_cves(doc, args.min_severity, require_fix))

    all_cves.sort(key=lambda c: c["priority_score"], reverse=True)

    bsev    = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    fixable = 0
    for c in all_cves:
        k = c["severity"] if c["severity"] in bsev else "LOW"
        bsev[k] += 1
        if c["fixed_version"]:
            fixable += 1

    totals = {"actionable": len(all_cves), "by_severity": bsev, "fixable": fixable}

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        f.write(render_html(summary, all_cves, totals, config))

    s = summary
    print(f"\n{'─'*52}")
    print(f"  Analysis complete")
    print(f"{'─'*52}")
    print(f"  Public CVEs       : {s.get('total_public_cves',0)}")
    print(f"  CleanStart CVEs   : {s.get('total_cleanstart_cves',0)}")
    print(f"  Avg reduction     : {s.get('avg_reduction_pct',0)}%")
    print(f"  Actionable CVEs   : {totals['actionable']}")
    print(f"    Critical        : {bsev.get('CRITICAL',0)}")
    print(f"    High            : {bsev.get('HIGH',0)}")
    print(f"  Fixable now       : {fixable}")
    print(f"  Report            : {args.out}")
    print(f"{'─'*52}\n")


if __name__ == "__main__":
    main()
