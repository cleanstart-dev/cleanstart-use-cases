#!/usr/bin/env node
// scripts/dep-tree.js
// Reads live npm audit + package-lock and prints color-coded dependency
// chains for every vulnerability found — not just the hardcoded ones.
// Run: node scripts/dep-tree.js

const { execSync } = require('child_process');
const fs   = require('fs');
const path = require('path');

const RED    = (s) => `\x1b[31m${s}\x1b[0m`;
const YELLOW = (s) => `\x1b[33m${s}\x1b[0m`;
const GREEN  = (s) => `\x1b[32m${s}\x1b[0m`;
const CYAN   = (s) => `\x1b[36m${s}\x1b[0m`;
const BOLD   = (s) => `\x1b[1m${s}\x1b[0m`;
const DIM    = (s) => `\x1b[2m${s}\x1b[0m`;

function sevColor(sev, text) {
  if (sev === 'critical') return RED(BOLD(text));
  if (sev === 'high')     return RED(text);
  if (sev === 'moderate') return YELLOW(text);
  return DIM(text);
}

// ─── Load live audit data ─────────────────────────────────────────────────────
let auditData = { vulnerabilities: {}, metadata: { vulnerabilities: {} } };
try {
  const raw = execSync('npm audit --json 2>/dev/null', { encoding: 'utf8' });
  auditData = JSON.parse(raw);
} catch (e) {
  try { auditData = JSON.parse(e.stdout || '{}'); } catch (_) {}
}

// ─── Load lock file ───────────────────────────────────────────────────────────
const lockPath = path.join(process.cwd(), 'package-lock.json');
if (!fs.existsSync(lockPath)) {
  console.error(RED('package-lock.json not found. Run `npm install` first.'));
  process.exit(1);
}
const lock     = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
const pkgJson  = JSON.parse(fs.readFileSync('package.json', 'utf8'));
const packages = lock.packages || {};
const directSet = new Set(Object.keys(pkgJson.dependencies || {}));

// Build name→version map
const pkgMap = {};
for (const [p, meta] of Object.entries(packages)) {
  if (!p) continue;
  const name = p.replace(/^.*node_modules\//, '');
  if (name && meta.version) pkgMap[name] = meta.version;
}

const totalPkgs     = Object.keys(pkgMap).length;
const transitiveCount = totalPkgs - directSet.size;

// ─── Parse vulnerabilities ────────────────────────────────────────────────────
const vulns = auditData.vulnerabilities || {};
const meta  = auditData.metadata?.vulnerabilities || {};
const SEV_ORDER = { critical: 0, high: 1, moderate: 2, low: 3, info: 4 };

const vulnList = Object.entries(vulns)
  .map(([name, v]) => {
    const viaObjs = (v.via || []).filter(x => typeof x === 'object');
    const titles  = viaObjs.map(x => x.title || x.name).filter(Boolean);
    const cves    = viaObjs.map(x => x.url?.split('/').pop() || x.name).filter(Boolean);
    return { name, severity: v.severity, titles, cves, via: v.via };
  })
  .sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5));

// ─── Header ───────────────────────────────────────────────────────────────────
console.log('\n' + BOLD('═'.repeat(68)));
console.log(BOLD('  DEPENDENCY TREE — LIVE VULNERABILITY ANALYSIS'));
console.log(BOLD('═'.repeat(68)));
console.log(DIM(`  Total packages : ${totalPkgs}  (${directSet.size} direct, ${transitiveCount} transitive)`));
console.log(DIM(`  Vulnerabilities: ${RED((meta.critical||0) + ' critical')}  ${YELLOW((meta.high||0) + ' high')}  ${(meta.moderate||0)} moderate  ${(meta.low||0)} low`));
console.log(BOLD('─'.repeat(68)) + '\n');

if (vulnList.length === 0) {
  console.log(GREEN('  ✔ No vulnerabilities found.\n'));
  process.exit(0);
}

// ─── Per-vulnerability chain display ─────────────────────────────────────────
console.log(BOLD('  VULNERABLE PACKAGES & THEIR CHAINS\n'));

for (const vuln of vulnList) {
  const isTransitive = !directSet.has(vuln.name);
  const tag   = isTransitive ? RED('[transitive]') : CYAN('[direct]');
  const sev   = vuln.severity.toUpperCase().padEnd(8);
  const label = sevColor(vuln.severity, `● ${sev}`);

  console.log(`  ${label} ${BOLD(vuln.name)}  ${tag}`);

  if (vuln.titles.length) {
    for (const t of vuln.titles) {
      console.log(`    ${DIM('└─')} ${vuln.severity === 'critical' || vuln.severity === 'high' ? RED(t) : YELLOW(t)}`);
    }
  }

  // Show which direct deps pull this package in
  if (isTransitive) {
    const parents = [];
    for (const [depName, depMeta] of Object.entries(vulns)) {
      if (depName === vuln.name) continue;
      const depVia = (depMeta.via || []).filter(x => typeof x === 'string');
      if (depVia.includes(vuln.name)) parents.push(depName);
    }
    // Also check direct deps that match via strings
    for (const [, depMeta] of Object.entries(vulns)) {
      const viaStrings = (depMeta.via || []).filter(x => typeof x === 'string');
      if (viaStrings.includes(vuln.name)) {
        const directParents = [...directSet].filter(d => {
          const node = packages[`node_modules/${d}`];
          return node?.dependencies?.[vuln.name] !== undefined ||
                 node?.peerDependencies?.[vuln.name] !== undefined;
        });
        directParents.forEach(p => { if (!parents.includes(p)) parents.push(p); });
      }
    }
    if (parents.length) {
      console.log(`    ${DIM('pulled in by:')} ${parents.map(p => directSet.has(p) ? CYAN(p) : DIM(p)).join(', ')}`);
    }
  }
  console.log();
}

// ─── Summary ──────────────────────────────────────────────────────────────────
const transVulns = vulnList.filter(v => !directSet.has(v.name));
console.log(BOLD('─'.repeat(68)));
console.log(`\n  ${BOLD('Summary:')}`);
console.log(`  ${vulnList.length} vulnerable packages  |  ${RED(transVulns.length + ' are transitive')} (you never installed them directly)`);
console.log(`\n  ${BOLD('Key point:')} ${CYAN('cleanstart/node:latest')} has near-zero OS CVEs.`);
console.log(`  These ${vulnList.length} vulnerabilities all live in ${CYAN('node_modules')} — above the hardened base.\n`);
console.log(`  Next: ${CYAN('node scripts/apply-overrides.js')}  — generate the fix`);
console.log(`        ${CYAN('node scripts/full-report.js')}      — export full report\n`);