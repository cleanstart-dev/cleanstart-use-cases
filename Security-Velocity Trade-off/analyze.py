#!/usr/bin/env python3
"""
analyze.py
----------
Reads results/summary.json (written by benchmark.sh) and writes docs/index.html —
a dashboard that plots CVE reduction against pull time, image size, and container
start latency, side by side, so the trade-off claim can be checked against real
numbers instead of assumed.

Run after benchmark.sh:
  python3 analyze.py
  python3 analyze.py --scan-dir results --out docs/index.html
"""

import argparse
import json
import os
import sys


def fmt_mb(n_bytes):
    return f"{n_bytes / 1e6:.1f} MB"


def fmt_sec(n, decimals=2):
    if n is None or n < 0:
        return "—"
    return f"{n:.{decimals}f}s"


def fmt_delta(pct, lower_is_better=True):
    """Render a percentage delta with a color class. Negative = smaller/faster."""
    if pct is None:
        return '<span class="d-na">—</span>'
    good = pct < 0 if lower_is_better else pct > 0
    cls = "d-good" if good else ("d-flat" if abs(pct) < 3 else "d-bad")
    sign = "" if pct < 0 else "+"
    arrow = "↓" if pct < 0 else ("→" if pct == 0 else "↑")
    return f'<span class="{cls}">{arrow} {sign}{pct}%</span>'


# ── aggregate stats across all pairs ──────────────────────────────────────────

def aggregate(pairs):
    n = len(pairs)
    if n == 0:
        return {}

    def avg(key_path, obj_key):
        vals = [p[obj_key][key_path] for p in pairs if p[obj_key].get(key_path, -1) >= 0]
        return round(sum(vals) / len(vals), 2) if vals else None

    total_pub_cves = sum(p["public"]["total_cves"] for p in pairs)
    total_cs_cves = sum(p["cleanstart"]["total_cves"] for p in pairs)

    deltas = {
        "pull_time_delta_pct": [p["pull_time_delta_pct"] for p in pairs if p["pull_time_delta_pct"] is not None],
        "size_delta_pct":      [p["size_delta_pct"] for p in pairs if p["size_delta_pct"] is not None],
        "start_delta_pct":     [p["start_delta_pct"] for p in pairs if p["start_delta_pct"] is not None],
    }
    avg_deltas = {k: (round(sum(v) / len(v), 1) if v else None) for k, v in deltas.items()}

    # How many pairs got FASTER/SMALLER (not just "not slower") on each axis
    faster_pull  = sum(1 for p in pairs if (p["pull_time_delta_pct"]  or 0) < 0)
    smaller_size = sum(1 for p in pairs if (p["size_delta_pct"]       or 0) < 0)
    faster_start = sum(1 for p in pairs if (p["start_delta_pct"]      or 0) < 0)

    return {
        "n_pairs": n,
        "total_pub_cves": total_pub_cves,
        "total_cs_cves": total_cs_cves,
        "avg_cve_reduction": round(sum(p["cve_reduction_pct"] for p in pairs) / n),
        "avg_pub_pull": avg("pull_time_sec", "public"),
        "avg_cs_pull": avg("pull_time_sec", "cleanstart"),
        "avg_pub_size": avg("size_bytes", "public"),
        "avg_cs_size": avg("size_bytes", "cleanstart"),
        "avg_pub_start": avg("start_latency_sec", "public"),
        "avg_cs_start": avg("start_latency_sec", "cleanstart"),
        "avg_deltas": avg_deltas,
        "faster_pull": faster_pull,
        "smaller_size": smaller_size,
        "faster_start": faster_start,
    }


# ── HTML ───────────────────────────────────────────────────────────────────────

def render_html(summary, agg):
    ts = summary.get("scanned_at", "")[:16].replace("T", " ")
    pairs = summary.get("pairs", [])
    n = agg.get("n_pairs", 0)

    verdict = (
        "no measurable trade-off"
        if (agg.get("faster_pull", 0) + agg.get("smaller_size", 0) + agg.get("faster_start", 0)) >= n
        else "partial trade-off"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>security-velocity-tradeoff — {ts}</title>
<style>
:root{{--bg:#0d1117;--s1:#161b22;--s2:#21262d;--bd:#30363d;--tx:#e6edf3;--mu:#8b949e;--dim:#484f58;
  --crit:#ff4d6d;--acc:#58a6ff;--grn:#3fb950;--pur:#bc8cff;--pub:#ff9f43;--cs:#3fb950;--bad:#ff4d6d}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--tx);font-family:system-ui,sans-serif;font-size:14px;line-height:1.6}}
.page{{max-width:1100px;margin:0 auto;padding:2.5rem 1.5rem}}
a{{color:var(--acc)}}
.hdr{{display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:1rem;
  padding-bottom:1.5rem;border-bottom:1px solid var(--bd);margin-bottom:2.5rem}}
.hdr h1{{font-size:1.4rem;font-weight:600}}
.hdr .sub{{font-size:.8rem;color:var(--mu);margin-top:.2rem}}
.big{{font-size:2.2rem;font-weight:700;color:var(--grn);line-height:1;text-align:right;text-transform:capitalize}}
.big-lbl{{font-size:.7rem;color:var(--mu);text-transform:uppercase;letter-spacing:.05em;text-align:right}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;margin-bottom:2.5rem}}
.card{{background:var(--s1);border:1px solid var(--bd);border-radius:10px;padding:1.1rem 1.3rem}}
.card .lbl{{font-size:.67rem;color:var(--mu);text-transform:uppercase;letter-spacing:.05em;margin-bottom:.3rem}}
.card .val{{font-size:1.7rem;font-weight:700;line-height:1.1}}
.card .note{{font-size:.7rem;color:var(--mu);margin-top:.3rem}}
.o .val{{color:var(--pub)}} .g .val{{color:var(--grn)}} .b .val{{color:var(--acc)}} .p .val{{color:var(--pur)}}
.box{{background:var(--s1);border:1px solid var(--bd);border-radius:10px;padding:1.8rem 2rem;margin-bottom:2.5rem}}
.box h2{{font-size:1rem;font-weight:600;color:var(--acc);margin-bottom:1.3rem}}
.sec{{margin-bottom:3rem}}
.sec-title{{font-size:.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.07em;
  color:var(--mu);padding-bottom:.5rem;border-bottom:1px solid var(--bd);margin-bottom:1.3rem}}
.metric-row{{display:grid;grid-template-columns:1.3fr 1fr 1fr 1fr;gap:1rem;padding:.7rem 0;
  border-bottom:1px solid var(--bd);align-items:center;font-size:.82rem}}
.metric-row:last-child{{border-bottom:none}}
.metric-row.hd{{font-size:.66rem;color:var(--mu);text-transform:uppercase;letter-spacing:.05em;font-weight:600}}
.mname{{font-weight:500}}
.msub{{font-size:.7rem;color:var(--mu)}}
.d-good{{color:var(--grn);font-weight:600}}
.d-bad{{color:var(--bad);font-weight:600}}
.d-flat{{color:var(--mu);font-weight:600}}
.d-na{{color:var(--dim)}}
.cmp-list{{display:flex;flex-direction:column;gap:1rem}}
.cmp-row{{background:var(--s1);border:1px solid var(--bd);border-radius:10px;padding:1.2rem 1.4rem}}
.cmp-hdr{{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.5rem;margin-bottom:1rem}}
.pair{{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}}
.itag{{font-family:monospace;font-size:.75rem;padding:.18rem .6rem;border-radius:4px;font-weight:500}}
.itag.p{{background:#ff9f4315;color:var(--pub);border:1px solid #ff9f4330}}
.itag.c{{background:#3fb95015;color:var(--cs);border:1px solid #3fb95030}}
.rbadge{{font-size:.72rem;font-weight:700;padding:.2rem .75rem;border-radius:20px;
  background:#3fb95018;color:var(--grn);border:1px solid #3fb95035}}
.axes{{display:grid;grid-template-columns:repeat(4,1fr);gap:.9rem;margin-top:.9rem}}
@media(max-width:720px){{.axes{{grid-template-columns:1fr 1fr}}.metric-row{{grid-template-columns:1.1fr 1fr 1fr}}
  .metric-row span.mcol4{{display:none}}}}
.axis{{background:var(--s2);border-radius:8px;padding:.7rem .8rem}}
.axis .al{{font-size:.63rem;color:var(--mu);text-transform:uppercase;letter-spacing:.04em;margin-bottom:.35rem}}
.axis .av{{font-size:.95rem;font-weight:700}}
.axis .as{{font-size:.68rem;color:var(--mu);margin-top:.15rem}}
footer{{border-top:1px solid var(--bd);padding-top:1rem;font-size:.7rem;color:var(--dim);margin-top:3rem}}
</style>
</head>
<body><div class="page">

<div class="hdr">
  <div>
    <h1>⚡ security-velocity-tradeoff</h1>
    <div class="sub">
      Real benchmark: cold pull time · image size · container start latency · CVE count &nbsp;·&nbsp; {ts} &nbsp;·&nbsp;
      {n} image pairs
    </div>
  </div>
  <div>
    <div class="big-lbl">verdict</div>
    <div class="big">{verdict}</div>
  </div>
</div>

<div class="cards">
  <div class="card g">
    <div class="lbl">Avg CVE reduction</div><div class="val">{agg.get('avg_cve_reduction', 0)}%</div>
    <div class="note">{agg.get('total_pub_cves',0)} → {agg.get('total_cs_cves',0)} CVEs total</div>
  </div>
  <div class="card b">
    <div class="lbl">Pull time, avg delta</div><div class="val">{fmt_delta(agg['avg_deltas'].get('pull_time_delta_pct'))}</div>
    <div class="note">{agg.get('faster_pull',0)}/{agg.get('n_pairs',0)} pairs pulled faster</div>
  </div>
  <div class="card p">
    <div class="lbl">Image size, avg delta</div><div class="val">{fmt_delta(agg['avg_deltas'].get('size_delta_pct'))}</div>
    <div class="note">{agg.get('smaller_size',0)}/{agg.get('n_pairs',0)} pairs smaller</div>
  </div>
  <div class="card o">
    <div class="lbl">Start latency, avg delta</div><div class="val">{fmt_delta(agg['avg_deltas'].get('start_delta_pct'))}</div>
    <div class="note">{agg.get('faster_start',0)}/{agg.get('n_pairs',0)} pairs started faster</div>
  </div>
</div>

<div class="box">
  <h2>🔎 Reading this dashboard</h2>
  <p style="color:var(--mu);font-size:.85rem;line-height:1.7">
    The "zero-CVE means slow builds" assumption predicts that hardened images should be
    <em>larger or slower</em> — more scanning, more build steps, more layers to assemble.
    Each row below is one image measured on both sides of that assumption at once:
    fewer CVEs (security) and faster pull / smaller size / quicker start (velocity).
    A negative delta (↓) on any velocity metric means the CleanStart image was
    <strong>faster or smaller</strong>, not slower — the opposite of what the trade-off predicts.
  </p>
</div>

<div class="sec">
  <div class="sec-title">Per-image comparison — security vs. velocity, same measurement run</div>
  <div class="cmp-list">{_comparison_rows(pairs)}</div>
</div>

<footer>
  Generated by <strong>security-velocity-tradeoff</strong> &nbsp;·&nbsp;
  Timing: <code>docker pull</code> / <code>docker run</code> + <code>docker exec</code> polling &nbsp;·&nbsp;
  CVE scan: <a href="https://aquasecurity.github.io/trivy" target="_blank">trivy image</a> &nbsp;·&nbsp;
  <a href="https://www.cleanstart.com" target="_blank">cleanstart.com</a>
</footer>
</div></body></html>"""


def _comparison_rows(pairs):
    rows = []
    for p in pairs:
        pub, cs = p["public"], p["cleanstart"]
        rows.append(f"""<div class="cmp-row">
  <div class="cmp-hdr">
    <div class="pair">
      <span class="itag p">{pub['image']}</span>
      <span style="color:#484f58">→</span>
      <span class="itag c">{cs['image']}</span>
    </div>
    <span class="rbadge">↓ {p['cve_reduction_pct']}% CVEs</span>
  </div>
  <div class="axes">
    <div class="axis">
      <div class="al">CVEs</div>
      <div class="av">{pub['total_cves']} → {cs['total_cves']}</div>
      <div class="as">fewer is safer</div>
    </div>
    <div class="axis">
      <div class="al">Pull time</div>
      <div class="av">{fmt_sec(pub['pull_time_sec'],1)} → {fmt_sec(cs['pull_time_sec'],1)}</div>
      <div class="as">{fmt_delta(p['pull_time_delta_pct'])}</div>
    </div>
    <div class="axis">
      <div class="al">Image size</div>
      <div class="av">{fmt_mb(pub['size_bytes'])} → {fmt_mb(cs['size_bytes'])}</div>
      <div class="as">{fmt_delta(p['size_delta_pct'])}</div>
    </div>
    <div class="axis">
      <div class="al">Start latency</div>
      <div class="av">{fmt_sec(pub['start_latency_sec'])} → {fmt_sec(cs['start_latency_sec'])}</div>
      <div class="as">{fmt_delta(p['start_delta_pct'])}</div>
    </div>
  </div>
</div>""")
    return "\n".join(rows)


# ── main ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Analyze benchmark results and generate the dashboard")
    ap.add_argument("--scan-dir", default="results")
    ap.add_argument("--out", default="docs/index.html")
    args = ap.parse_args()

    summary_path = os.path.join(args.scan_dir, "summary.json")
    if not os.path.exists(summary_path):
        print(f"\n❌  {summary_path} not found")
        print(f"    Run benchmark.sh first to generate velocity + CVE data.\n")
        sys.exit(1)

    with open(summary_path) as f:
        summary = json.load(f)

    pairs = summary.get("pairs", [])
    if not pairs:
        print("\n❌  summary.json has no pairs — check benchmark.sh output for errors.\n")
        sys.exit(1)

    agg = aggregate(pairs)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        f.write(render_html(summary, agg))

    print(f"\n{'─'*52}")
    print(f"  Analysis complete")
    print(f"{'─'*52}")
    print(f"  Pairs                 : {agg['n_pairs']}")
    print(f"  Avg CVE reduction     : {agg['avg_cve_reduction']}%")
    print(f"  Avg pull time delta   : {agg['avg_deltas'].get('pull_time_delta_pct')}%")
    print(f"  Avg size delta        : {agg['avg_deltas'].get('size_delta_pct')}%")
    print(f"  Avg start latency delta: {agg['avg_deltas'].get('start_delta_pct')}%")
    print(f"  Report                : {args.out}")
    print(f"{'─'*52}\n")


if __name__ == "__main__":
    main()