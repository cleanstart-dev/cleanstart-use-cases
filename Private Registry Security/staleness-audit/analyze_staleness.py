#!/usr/bin/env python3
"""
analyze_staleness.py
---------------------
Reads results/summary.json produced by audit.sh and writes docs/staleness.html.

This does not scan for CVEs — it reports one thing, directly from the
registry: how old each image actually is, and whether it's signed. Run
cve-comparison/ separately to see what that staleness costs you in CVEs.

Usage:
  python3 analyze_staleness.py
  python3 analyze_staleness.py --stale-after 90
"""

import argparse
import json
import os
import sys


def render_html(summary, stale_after):
    ts = summary["scanned_at"][:16].replace("T", " ")
    total    = summary.get("total_images", 0)
    stale_n  = summary.get("stale_count", 0)
    unsig_n  = summary.get("unsigned_count", 0)
    avg_age  = summary.get("avg_age_days")
    oldest   = summary.get("oldest_age_days")
    avg_mo   = round(avg_age / 30) if avg_age is not None else None
    oldest_mo = round(oldest / 30) if oldest is not None else None

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>staleness-audit — {ts}</title>
<style>
:root{{--bg:#0d1117;--s1:#161b22;--s2:#21262d;--bd:#30363d;--tx:#e6edf3;--mu:#8b949e;--dim:#484f58;
  --crit:#ff4d6d;--high:#ff9f43;--med:#ffd32a;--low:#56d364;--acc:#58a6ff;--grn:#3fb950}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--tx);font-family:system-ui,sans-serif;font-size:14px;line-height:1.6}}
.page{{max-width:920px;margin:0 auto;padding:2.5rem 1.5rem}}
a{{color:var(--acc)}}
.hdr{{display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:1rem;
  padding-bottom:1.5rem;border-bottom:1px solid var(--bd);margin-bottom:2.5rem}}
.hdr h1{{font-size:1.4rem;font-weight:600}}
.hdr .sub{{font-size:.8rem;color:var(--mu);margin-top:.2rem}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1rem;margin-bottom:2.5rem}}
.card{{background:var(--s1);border:1px solid var(--bd);border-radius:10px;padding:1.1rem 1.3rem}}
.card .lbl{{font-size:.67rem;color:var(--mu);text-transform:uppercase;letter-spacing:.05em;margin-bottom:.3rem}}
.card .val{{font-size:1.9rem;font-weight:700;line-height:1.1}}
.card .note{{font-size:.7rem;color:var(--mu);margin-top:.2rem}}
.r .val{{color:var(--crit)}} .o .val{{color:var(--high)}} .g .val{{color:var(--grn)}} .b .val{{color:var(--acc)}}
.sec-title{{font-size:.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.07em;
  color:var(--mu);padding-bottom:.5rem;border-bottom:1px solid var(--bd);margin-bottom:1.3rem}}
.sec{{margin-bottom:3rem}}
table{{width:100%;border-collapse:collapse}}
thead th{{text-align:left;font-size:.67rem;color:var(--mu);text-transform:uppercase;
  letter-spacing:.05em;border-bottom:1px solid var(--bd);padding:.5rem .65rem}}
tbody tr{{border-bottom:1px solid var(--bd)}}
tbody tr:hover{{background:var(--s1)}}
td{{padding:.6rem .65rem;vertical-align:top;font-size:.8rem}}
code{{font-family:monospace;font-size:.74rem;color:var(--mu)}}
.age{{font-weight:600}} .age.stale{{color:var(--crit)}} .age.ok{{color:var(--grn)}} .age.unknown{{color:var(--mu)}}
.badge{{display:inline-block;padding:.15rem .5rem;border-radius:3px;font-size:.66rem;font-weight:700}}
.badge.stale{{background:#ff4d6d18;color:var(--crit);border:1px solid #ff4d6d30}}
.badge.ok{{background:#3fb95018;color:var(--grn);border:1px solid #3fb95030}}
.badge.signed{{background:#3fb95018;color:var(--grn);border:1px solid #3fb95030}}
.badge.unsigned{{background:#ffd32a18;color:var(--med);border:1px solid #ffd32a30}}
.badge.unchecked{{background:var(--s2);color:var(--mu);border:1px solid var(--bd)}}
.note-box{{background:var(--s1);border:1px solid var(--bd);border-radius:10px;padding:1.2rem 1.4rem;
  font-size:.8rem;color:var(--mu);margin-bottom:2.5rem;line-height:1.6}}
.note-box strong{{color:var(--tx)}}
footer{{border-top:1px solid var(--bd);padding-top:1rem;font-size:.7rem;color:var(--dim);margin-top:3rem}}
</style>
</head>
<body><div class="page">

<div class="hdr">
  <div>
    <h1>🕒 staleness-audit — how old is what's actually in your registry</h1>
    <div class="sub">
      Real registry query via crane &nbsp;·&nbsp; {ts} &nbsp;·&nbsp;
      {total} images audited &nbsp;·&nbsp; stale threshold: {stale_after} days
    </div>
  </div>
</div>

<div class="cards">
  <div class="card r">
    <div class="lbl">Stale images</div><div class="val">{stale_n}</div>
    <div class="note">of {total} — not rebuilt within {stale_after}d</div>
  </div>
  <div class="card o">
    <div class="lbl">Unsigned images</div><div class="val">{unsig_n}</div>
    <div class="note">no verifiable cosign signature</div>
  </div>
  <div class="card b">
    <div class="lbl">Avg image age</div><div class="val">{avg_mo if avg_mo is not None else '—'}<span style="font-size:1rem">mo</span></div>
    <div class="note">across all audited images</div>
  </div>
  <div class="card g">
    <div class="lbl">Oldest image</div><div class="val">{oldest_mo if oldest_mo is not None else '—'}<span style="font-size:1rem">mo</span></div>
    <div class="note">since it was last rebuilt</div>
  </div>
</div>

<div class="note-box">
  This report answers exactly one question: <strong>when was each of these images
  actually last rebuilt, and is it signed?</strong> It says nothing about CVEs on
  its own — an image can be perfectly fresh and still carry vulnerabilities, or
  be years old and happen to be fine. Pair this with <code>cve-comparison/</code>
  in this repo to see what staleness like this typically costs in actual CVE
  exposure, and with <code>promotion-policy/</code> to turn the threshold above
  into something that actually blocks a stale or unsigned image from being
  promoted.
</div>

<div class="sec">
  <div class="sec-title">Image-by-image staleness</div>
  <table>
    <thead><tr>
      <th>Image</th><th>Age</th><th>Signature</th><th>Digest</th>
    </tr></thead>
    <tbody>{_image_rows(summary.get('images', []))}</tbody>
  </table>
</div>

<footer>
  Generated by <strong>staleness-audit</strong> &nbsp;·&nbsp;
  Registry queries: <a href="https://github.com/google/go-containerregistry" target="_blank">crane</a> &nbsp;·&nbsp;
  Signature checks: <a href="https://github.com/sigstore/cosign" target="_blank">cosign</a> &nbsp;·&nbsp;
  <a href="https://www.cleanstart.com" target="_blank">cleanstart.com</a>
</footer>
</div></body></html>"""


def _image_rows(images):
    if not images:
        return '<tr><td colspan="4" style="text-align:center;color:var(--mu);padding:2rem">No results yet — run audit.sh first</td></tr>'
    rows = []
    for img in sorted(images, key=lambda x: (x.get("age_days") is None, -(x.get("age_days") or 0))):
        age = img.get("age_days")
        if age is None:
            age_s, age_cls = "unknown", "unknown"
        else:
            months = round(age / 30)
            age_s = f"{age}d (~{months}mo)"
            age_cls = "stale" if img.get("stale") else "ok"

        stale_badge = '<span class="badge stale">STALE</span>' if img.get("stale") else (
            '<span class="badge ok">OK</span>' if age is not None else "")

        if not img.get("signature_checked"):
            sig_badge = '<span class="badge unchecked">not checked</span>'
        elif img.get("signed"):
            sig_badge = '<span class="badge signed">✓ signed</span>'
        else:
            sig_badge = '<span class="badge unsigned">⚠ unsigned</span>'

        digest = img.get("digest", "")
        digest_short = digest.split(":")[-1][:12] if digest else "—"

        rows.append(f"""<tr>
  <td><code style="color:var(--tx);font-weight:600">{img.get('image','')}</code></td>
  <td><span class="age {age_cls}">{age_s}</span> {stale_badge}</td>
  <td>{sig_badge}</td>
  <td><code>sha256:{digest_short}…</code></td>
</tr>""")
    return "\n".join(rows)


def main():
    ap = argparse.ArgumentParser(description="Render a registry staleness report from audit.sh output")
    ap.add_argument("--results-dir", default="results")
    ap.add_argument("--stale-after", type=int, default=None,
                    help="override the stale threshold shown in the report (days)")
    ap.add_argument("--out", default="docs/staleness.html")
    args = ap.parse_args()

    summary_path = os.path.join(args.results_dir, "summary.json")
    if not os.path.exists(summary_path):
        print(f"\n❌  {summary_path} not found")
        print(f"    Run audit.sh first to generate staleness data.\n")
        sys.exit(1)

    with open(summary_path) as f:
        summary = json.load(f)

    images = summary.get("images", [])
    stale_after = args.stale_after
    if stale_after is None:
        stale_after = images[0]["stale_after_days"] if images else 180

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        f.write(render_html(summary, stale_after))

    print(f"\n{'─'*52}")
    print(f"  Analysis complete")
    print(f"{'─'*52}")
    print(f"  Images audited : {summary.get('total_images', 0)}")
    print(f"  Stale          : {summary.get('stale_count', 0)}")
    print(f"  Unsigned       : {summary.get('unsigned_count', 0)}")
    if summary.get("avg_age_days") is not None:
        print(f"  Avg age        : {summary['avg_age_days']} days")
    print(f"  Report         : {args.out}")
    print(f"{'─'*52}\n")


if __name__ == "__main__":
    main()
