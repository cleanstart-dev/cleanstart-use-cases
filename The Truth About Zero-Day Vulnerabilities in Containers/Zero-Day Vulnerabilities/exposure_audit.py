#!/usr/bin/env python3
"""
exposure_audit.py
------------------
Reads sboms/*.sbom.json (syft CycloneDX output) and, if present,
configs/*.config.json (crane image config output), cross-references them
against zero_days.json, and writes docs/index.html.

This does NOT scan for known CVEs. A zero-day by definition
has no CVE entry and no fix version at the moment it's exploited, so a
trivy-style scan can't help you before disclosure. What this script measures
instead:

  1. Attack surface  — how many packages does this image ship? Fewer
     packages means fewer places the next zero-day can land.
  2. Historical overlap — of 12 real, high-impact zero-days from the last
     decade, how many of their affected packages are present in this image
     today? (Illustrative: these are patched now. The point is exposure
     surface, not a live detection.)
  3. Blast radius — if a package IS present and IS exploited before a patch
     exists, what does the attacker get? Root user? A shell to pivot with?
     (Requires configs/*.config.json from `crane config`; SKIPPED with a
     clear note if not available — never silently assumed.)

Run after scan.sh (or against the SBOMs already checked into sboms/):
  python3 exposure_audit.py
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone

SHELL_PROVIDERS = {"bash", "busybox", "dash", "ash", "zsh", "ksh", "sh", "mksh"}


# ── helpers ──────────────────────────────────────────────────────────────────

def slugify(s):
    return re.sub(r"[^a-z0-9-]", "", re.sub(r"[/:.]+", "-", s.lower()))


def load_sbom_components(path):
    with open(path) as f:
        d = json.load(f)
    return d.get("components", []) or []


def component_names(components):
    return {c.get("name", "").lower() for c in components if c.get("name")}


def days_since(date_str):
    try:
        d = datetime.fromisoformat(date_str).replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - d).days
    except Exception:
        return None


# ── core audit ───────────────────────────────────────────────────────────────

def audit_image(image, itype, sbom_dir, config_dir, zero_days):
    slug = slugify(image)
    sbom_path = os.path.join(sbom_dir, slug + ".sbom.json")
    if not os.path.exists(sbom_path):
        print(f"  ⚠️  missing SBOM for {image} (expected {sbom_path}) — SKIP")
        return None

    components = load_sbom_components(sbom_path)
    names = component_names(components)
    attack_surface = len(components)

    matches = []
    for zd in zero_days:
        hit = None
        for alias in zd["package_aliases"]:
            if alias in names:
                hit = alias
                break
        if hit:
            matches.append({**zd, "matched_alias": hit})

    shell_present = bool(names & SHELL_PROVIDERS)

    # runtime posture — only if crane config data exists; never guessed
    cfg_path = os.path.join(config_dir, slug + ".config.json")
    runs_as_root = None
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path) as f:
                cfg = json.load(f)
            user = (cfg.get("config", {}) or {}).get("User", "")
            runs_as_root = user.strip() in ("", "0", "root", "0:0")
        except Exception:
            runs_as_root = None

    return {
        "image": image,
        "image_type": itype,
        "slug": slug,
        "attack_surface": attack_surface,
        "zero_day_matches": matches,
        "shell_present": shell_present,
        "runs_as_root": runs_as_root,  # None => unknown/SKIP, not "no"
    }


# ── HTML ─────────────────────────────────────────────────────────────────────

def render_html(pairs, zero_days, ts):
    n_pairs = len(pairs)
    pub_surf = sum(p["public"]["attack_surface"] for p in pairs)
    cs_surf  = sum(p["cleanstart"]["attack_surface"] for p in pairs)
    surf_red = round((1 - cs_surf / max(pub_surf, 1)) * 100)

    pub_hits = sum(len(p["public"]["zero_day_matches"]) for p in pairs)
    cs_hits  = sum(len(p["cleanstart"]["zero_day_matches"]) for p in pairs)

    pub_shell = sum(1 for p in pairs if p["public"]["shell_present"])
    cs_shell  = sum(1 for p in pairs if p["cleanstart"]["shell_present"])

    have_root_data = any(
        p[k]["runs_as_root"] is not None for p in pairs for k in ("public", "cleanstart")
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>zero-day-exposure — CleanStart vs Public · {ts}</title>
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
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1rem;margin-bottom:2.5rem}}
.card{{background:var(--s1);border:1px solid var(--bd);border-radius:10px;padding:1.1rem 1.3rem}}
.card .lbl{{font-size:.67rem;color:var(--mu);text-transform:uppercase;letter-spacing:.05em;margin-bottom:.3rem}}
.card .val{{font-size:1.9rem;font-weight:700;line-height:1.1}}
.card .note{{font-size:.7rem;color:var(--mu);margin-top:.2rem}}
.o .val{{color:var(--high)}} .g .val{{color:var(--grn)}} .r .val{{color:var(--crit)}}
.b .val{{color:var(--acc)}} .p .val{{color:var(--pur)}}
.box{{background:var(--s1);border:1px solid var(--bd);border-radius:10px;padding:1.8rem 2rem;margin-bottom:2.5rem}}
.box h2{{font-size:1rem;font-weight:600;color:var(--acc);margin-bottom:1.3rem}}
.truths{{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:1.2rem}}
.truth{{background:var(--s2);border:1px solid var(--bd);border-radius:8px;padding:1.1rem 1.2rem}}
.truth .n{{font-size:.68rem;font-weight:700;color:var(--pur);text-transform:uppercase;letter-spacing:.06em;margin-bottom:.5rem}}
.truth h3{{font-size:.92rem;margin-bottom:.5rem}}
.truth p{{font-size:.78rem;color:var(--mu)}}
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
.bars{{display:flex;flex-direction:column;gap:.5rem;margin-bottom:.9rem}}
.brow{{display:flex;align-items:center;gap:.7rem}}
.blbl{{font-size:.7rem;color:var(--mu);width:90px;text-align:right;flex-shrink:0}}
.bwrap{{flex:1;display:flex;flex-direction:column;gap:2px}}
.bt{{background:var(--s2);border-radius:3px;height:15px;overflow:hidden}}
.bf{{height:100%;border-radius:3px;display:flex;align-items:center;justify-content:flex-end;padding-right:6px}}
.bf span{{font-size:.63rem;font-weight:700;color:#fff;opacity:.9}}
.bf.p{{background:#ff9f43cc}} .bf.c{{background:#3fb950cc}}
.meta-row{{display:flex;gap:1rem;flex-wrap:wrap;font-size:.72rem;color:var(--mu);padding-top:.8rem;border-top:1px solid var(--bd)}}
.meta-row b{{color:var(--tx)}}
table{{width:100%;border-collapse:collapse}}
thead th{{text-align:left;font-size:.67rem;color:var(--mu);text-transform:uppercase;
  letter-spacing:.05em;border-bottom:1px solid var(--bd);padding:.45rem .65rem}}
tbody tr{{border-bottom:1px solid var(--bd)}}
tbody tr:hover{{background:var(--s1)}}
td{{padding:.5rem .65rem;vertical-align:top;font-size:.8rem}}
code{{font-family:monospace;font-size:.76rem}}
.layer{{font-size:.66rem;padding:.1rem .4rem;border-radius:3px;font-weight:600}}
.layer.os-package{{background:#3fb95015;color:var(--grn)}}
.layer.app-dependency{{background:#ffd32a15;color:var(--med)}}
.layer.host-kernel{{background:#ff4d6d15;color:var(--crit)}}
.chk{{font-weight:700}}
.chk.yes{{color:var(--crit)}}
.chk.no{{color:var(--grn)}}
.chk.na{{color:var(--dim)}}
ul.resp{{padding-left:1.3rem;font-size:.82rem;color:var(--mu)}}
ul.resp li{{margin-bottom:.4rem}}
footer{{border-top:1px solid var(--bd);padding-top:1rem;font-size:.7rem;color:var(--dim);margin-top:3rem}}
</style>
</head>
<body><div class="page">

<div class="hdr">
  <div>
    <h1>🕳️ zero-day-exposure — Attack Surface vs Public Images</h1>
    <div class="sub">
      Real syft SBOM data &nbsp;·&nbsp; {ts} &nbsp;·&nbsp;
      {n_pairs} image pairs &nbsp;·&nbsp;
      12 historical zero-days cross-referenced
    </div>
  </div>
  <div>
    <div class="big-lbl">attack surface reduction</div>
    <div class="big">{surf_red}%</div>
  </div>
</div>

<div class="cards">
  <div class="card o">
    <div class="lbl">Public packages</div><div class="val">{pub_surf}</div>
    <div class="note">across {n_pairs} images</div>
  </div>
  <div class="card g">
    <div class="lbl">CleanStart packages</div><div class="val">{cs_surf}</div>
    <div class="note">total attack surface</div>
  </div>
  <div class="card r">
    <div class="lbl">Historical 0-day hits — public</div><div class="val">{pub_hits}</div>
    <div class="note">of 12 tracked incidents</div>
  </div>
  <div class="card p">
    <div class="lbl">Historical 0-day hits — CleanStart</div><div class="val">{cs_hits}</div>
    <div class="note">of 12 tracked incidents</div>
  </div>
  <div class="card b">
    <div class="lbl">Images with a shell</div><div class="val">{pub_shell} / {cs_shell}</div>
    <div class="note">public / CleanStart</div>
  </div>
</div>

<div class="box">
  <h2>The three truths about zero-days</h2>
  <div class="truths">
    <div class="truth">
      <div class="n">Truth 1</div>
      <h3>Patching doesn't stop a zero-day</h3>
      <p>By definition, a zero-day has no CVE, no signature, and no fix at the moment it's used. Trivy, Scout, and every other CVE
      scanner are matching against known databases — they have nothing to match against yet. The patch-treadmill problem and the
      zero-day problem need different defenses.</p>
    </div>
    <div class="truth">
      <div class="n">Truth 2</div>
      <h3>Attack surface is the only defense that works before disclosure</h3>
      <p>You can't patch what you don't know about, but you can ship fewer packages. Every package not in the image is one the next
      Heartbleed, XZ-style backdoor, or PwnKit-class flaw simply cannot land in. The comparisons below are historical, patched
      CVEs used as a proxy: they measure package-presence overlap, not a live detection.</p>
    </div>
    <div class="truth">
      <div class="n">Truth 3</div>
      <h3>Once it's disclosed, velocity still matters</h3>
      <p>The moment a zero-day gets a CVE number, it becomes a race. Log4Shell had a fix within a day of public disclosure; the
      pain came from finding every place log4j was buried, not from waiting on Apache. Minimal images with a small, known package
      list make the "are we affected?" question answerable in minutes instead of days.</p>
    </div>
  </div>
</div>

<div class="sec">
  <div class="sec-title">Attack surface &amp; historical zero-day package overlap — real SBOM data, per pair</div>
  <div class="cmp-list">{_comparison_rows(pairs)}</div>
</div>

<div class="sec">
  <div class="sec-title">12 historical zero-days — which images ship the affected package today</div>
  <table>
    <thead><tr>
      <th>Zero-day</th><th>CVE</th><th>Disclosed</th><th>Layer</th>
      <th>Public images hit</th><th>CleanStart images hit</th>
    </tr></thead>
    <tbody>{_zeroday_table(zero_days, pairs)}</tbody>
  </table>
</div>

<div class="box">
  <h2>Blast radius — what happens if the exploited package IS present</h2>
  {_blast_radius_section(pairs, have_root_data)}
</div>

<div class="sec">
  <div class="sec-title">What this doesn't cover — still your responsibility</div>
  <ul class="resp">
    <li><b>Application-layer zero-days</b> (Log4Shell, Spring4Shell) live in your app's own dependency tree, not the base image's OS packages — scan your SBOM at the application layer too (Maven, npm, pip).</li>
    <li><b>Host-kernel flaws</b> (Dirty COW-class) aren't addressed by any base image choice — that's node/kernel patching, outside the container entirely.</li>
    <li><b>Runtime detection</b> for the exploitation attempt itself — Falco, Sysdig, or eBPF-based anomaly detection catches abnormal behavior a static SBOM comparison never will.</li>
    <li><b>Network policy and secrets management</b> — reducing blast radius further once something IS exploited.</li>
  </ul>
</div>

<footer>
  Generated by <strong>zero-day-exposure</strong> &nbsp;·&nbsp;
  SBOM: <a href="https://github.com/anchore/syft" target="_blank">syft</a> (CycloneDX JSON) &nbsp;·&nbsp;
  Runtime config: <a href="https://github.com/google/go-containerregistry" target="_blank">crane</a> &nbsp;·&nbsp;
  <a href="https://www.cleanstart.com" target="_blank">cleanstart.com</a>
</footer>
</div></body></html>"""


def _comparison_rows(pairs):
    rows = []
    for p in pairs:
        pub, cs = p["public"], p["cleanstart"]
        mx = max(pub["attack_surface"], cs["attack_surface"], 1)
        pw = int(pub["attack_surface"] / mx * 100)
        cw = int(cs["attack_surface"] / mx * 100)
        red = round((1 - cs["attack_surface"] / max(pub["attack_surface"], 1)) * 100)
        rows.append(f"""<div class="cmp-row">
  <div class="cmp-hdr">
    <div class="pair">
      <span class="itag p">{pub['image']}</span>
      <span style="color:#484f58">→</span>
      <span class="itag c">{cs['image']}</span>
    </div>
    <span class="rbadge">{'↓' if red >= 0 else '↑'} {abs(red)}% surface {'reduction' if red >= 0 else 'increase'}</span>
  </div>
  <div class="bars">
    <div class="brow"><span class="blbl">packages</span>
      <div class="bwrap">
        <div class="bt"><div class="bf p" style="width:{pw}%"><span>{pub['attack_surface']}</span></div></div>
        <div class="bt"><div class="bf c" style="width:{cw}%"><span>{cs['attack_surface']}</span></div></div>
      </div>
    </div>
  </div>
  <div class="meta-row">
    <span>0-day package hits — public: <b>{len(pub['zero_day_matches'])}</b></span>
    <span>0-day package hits — CleanStart: <b>{len(cs['zero_day_matches'])}</b></span>
    <span>shell present — public: <b>{'yes' if pub['shell_present'] else 'no'}</b></span>
    <span>shell present — CleanStart: <b>{'yes' if cs['shell_present'] else 'no'}</b></span>
  </div>
</div>""")
    return "\n".join(rows)


def _zeroday_table(zero_days, pairs):
    rows = []
    for zd in zero_days:
        pub_hit_imgs = [p["public"]["image"] for p in pairs
                        if any(m["cve"] == zd["cve"] for m in p["public"]["zero_day_matches"])]
        cs_hit_imgs = [p["cleanstart"]["image"] for p in pairs
                       if any(m["cve"] == zd["cve"] for m in p["cleanstart"]["zero_day_matches"])]
        pub_cell = f"{len(pub_hit_imgs)}" if pub_hit_imgs else "—"
        cs_cell = f"{len(cs_hit_imgs)}" if cs_hit_imgs else "—"
        pub_cls = "yes" if pub_hit_imgs else "no"
        cs_cls = "yes" if cs_hit_imgs else "no"
        rows.append(f"""<tr>
  <td><b>{zd['name']}</b><br><span style="font-size:.7rem;color:var(--mu)">{zd['summary'][:110]}…</span></td>
  <td><code>{zd['cve']}</code></td>
  <td style="font-size:.75rem;color:var(--mu)">{zd['disclosed']}</td>
  <td><span class="layer {zd['layer']}">{zd['layer']}</span></td>
  <td><span class="chk {pub_cls}">{pub_cell}</span></td>
  <td><span class="chk {cs_cls}">{cs_cell}</span></td>
</tr>""")
    return "\n".join(rows)


def _blast_radius_section(pairs, have_root_data):
    if not have_root_data:
        return ('<p style="font-size:.82rem;color:var(--mu)">'
                'SKIP — no <code>configs/*.config.json</code> found. Run '
                '<code>bash scan.sh</code> with <code>crane</code> access to populate runtime '
                'user data before this section can report anything. Not assumed, not filled in.</p>')

    rows = []
    for p in pairs:
        for k, label, cls in (("public", "Public", "p"), ("cleanstart", "CleanStart", "c")):
            e = p[k]
            root_txt = "unknown (no config data)" if e["runs_as_root"] is None else \
                       ("root" if e["runs_as_root"] else "non-root")
            shell_txt = "yes" if e["shell_present"] else "no"
            rows.append(
                f'<div class="meta-row"><span class="itag {cls}">{e["image"]}</span>'
                f'<span>default user: <b>{root_txt}</b></span>'
                f'<span>shell present: <b>{shell_txt}</b></span></div>'
            )
    return "\n".join(rows)


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Cross-reference SBOMs against historical zero-day exposure")
    ap.add_argument("--sbom-dir", default="sboms")
    ap.add_argument("--config-dir", default="configs")
    ap.add_argument("--images-file", default="images.txt")
    ap.add_argument("--zero-days-file", default="zero_days.json")
    ap.add_argument("--out", default="docs/index.html")
    args = ap.parse_args()

    if not os.path.exists(args.zero_days_file):
        print(f"\n❌  {args.zero_days_file} not found\n")
        sys.exit(1)

    with open(args.zero_days_file) as f:
        zero_days = json.load(f)["zero_days"]

    if not os.path.exists(args.images_file):
        print(f"\n❌  {args.images_file} not found\n")
        sys.exit(1)

    pairs = []
    with open(args.images_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "|" not in line:
                continue
            pub_img, cs_img = [x.strip() for x in line.split("|", 1)]
            pub_e = audit_image(pub_img, "public", args.sbom_dir, args.config_dir, zero_days)
            cs_e = audit_image(cs_img, "cleanstart", args.sbom_dir, args.config_dir, zero_days)
            if pub_e and cs_e:
                pairs.append({"public": pub_e, "cleanstart": cs_e})

    if not pairs:
        print("\n❌  no complete pairs found — run scan.sh first\n")
        sys.exit(1)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        f.write(render_html(pairs, zero_days, ts))

    pub_surf = sum(p["public"]["attack_surface"] for p in pairs)
    cs_surf = sum(p["cleanstart"]["attack_surface"] for p in pairs)
    pub_hits = sum(len(p["public"]["zero_day_matches"]) for p in pairs)
    cs_hits = sum(len(p["cleanstart"]["zero_day_matches"]) for p in pairs)

    print(f"\n{'─'*52}")
    print("  Zero-day exposure audit complete")
    print(f"{'─'*52}")
    print(f"  Pairs analyzed          : {len(pairs)}")
    print(f"  Public attack surface   : {pub_surf} packages")
    print(f"  CleanStart attack surf. : {cs_surf} packages")
    print(f"  Surface reduction       : {round((1 - cs_surf/max(pub_surf,1))*100)}%")
    print(f"  Historical 0-day hits   : public {pub_hits}  |  cleanstart {cs_hits}")
    print(f"  Report                  : {args.out}")
    print(f"{'─'*52}\n")


if __name__ == "__main__":
    main()
