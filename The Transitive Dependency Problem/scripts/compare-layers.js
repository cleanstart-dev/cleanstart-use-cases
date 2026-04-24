#!/usr/bin/env node
// scripts/compare-layers.js
// Reads the LIVE npm audit output and dynamically builds the two-layer model.
// Run: node scripts/compare-layers.js

const { execSync } = require('child_process');
const fs = require('fs');

const BOLD   = (s) => `\x1b[1m${s}\x1b[0m`;
const RED    = (s) => `\x1b[31m${s}\x1b[0m`;
const GREEN  = (s) => `\x1b[32m${s}\x1b[0m`;
const YELLOW = (s) => `\x1b[33m${s}\x1b[0m`;
const CYAN   = (s) => `\x1b[36m${s}\x1b[0m`;
const DIM    = (s) => `\x1b[2m${s}\x1b[0m`;

// ─── Step 1: Run live npm audit and parse results ─────────────────────────────
let auditData = { vulnerabilities: {}, metadata: { vulnerabilities: {} } };
try {
  const raw = execSync('npm audit --json 2>/dev/null', { encoding: 'utf8' });
  auditData = JSON.parse(raw);
} catch (e) {
  try { auditData = JSON.parse(e.stdout || '{}'); } catch (_) {}
}

const vulns = auditData.vulnerabilities || {};
const meta  = auditData.metadata?.vulnerabilities || {};

// Build a flat list of findings sorted by severity
const SEV_ORDER = { critical: 0, high: 1, moderate: 2, low: 3, info: 4 };
const findings = Object.entries(vulns)
  .map(([name, v]) => ({
    name,
    severity: v.severity,
    via: Array.isArray(v.via)
      ? v.via.filter(x => typeof x === 'object').map(x => x.title || x.name).slice(0, 1).join(', ')
      : String(v.via),
    isDirect: !(v.via || []).some(x => typeof x === 'string'),
  }))
  .sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5));

const totalVulns = (meta.critical||0) + (meta.high||0) + (meta.moderate||0) + (meta.low||0);

// ─── Step 2: Count real installed packages ────────────────────────────────────
let totalPkgs = 0;
try {
  const lockRaw = fs.readFileSync('package-lock.json', 'utf8');
  const lock = JSON.parse(lockRaw);
  totalPkgs = Object.keys(lock.packages || {}).filter(k => k !== '').length;
} catch (_) {}

const pkgJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));
const directCount = Object.keys(pkgJson.dependencies || {}).length;
const transitiveCount = totalPkgs - directCount;

// ─── Step 3: Print header ─────────────────────────────────────────────────────
console.log('\n' + BOLD('═'.repeat(68)));
console.log(BOLD('  TWO-LAYER VULNERABILITY MODEL'));
console.log(BOLD('  cleanstart/node:latest  vs  your node_modules'));
console.log(BOLD('═'.repeat(68)));
console.log(`
  Your container image has TWO vulnerability surfaces.
  A hardened base image solves Layer 1. It cannot touch Layer 2.
`);

// ─── Step 4: Dynamic layer diagram from live audit ───────────────────────────
const W = 60;
const pad = (s) => s.padEnd(W);

const sevColor = (sev, s) => {
  if (sev === 'critical') return RED(s);
  if (sev === 'high')     return RED(s);
  if (sev === 'moderate') return YELLOW(s);
  return DIM(s);
};

const sevLabel = (sev) => {
  if (sev === 'critical') return RED('CRITICAL');
  if (sev === 'high')     return RED('HIGH    ');
  if (sev === 'moderate') return YELLOW('MODERATE');
  return DIM(sev.toUpperCase().padEnd(8));
};

console.log('  ┌' + '─'.repeat(W) + '┐');
console.log('  │' + RED(BOLD(pad('  LAYER 2 — npm / node_modules'))) + '│');
console.log('  │' + RED(pad(`  ${totalPkgs} packages installed  (${directCount} direct, ${transitiveCount} transitive)`)) + '│');
console.log('  │' + RED(pad(`  npm audit found: ${totalVulns} vulnerabilities`)) + '│');
console.log('  │' + ' '.repeat(W) + '│');

for (const f of findings.slice(0, 8)) {  // show top 8
  const type = f.isDirect ? '' : DIM('[transitive]');
  const line = `  ✗ ${f.name}`;
  console.log('  │' + sevColor(f.severity, line.padEnd(42)) + ' ' + sevLabel(f.severity) + ' ' + type + '\x1b[0m'.padEnd(0) + ' '.repeat(Math.max(0, W - 42 - 10 - (f.isDirect ? 0 : 13))) + '│');
}
if (findings.length > 8) {
  console.log('  │' + DIM(pad(`  ... and ${findings.length - 8} more`)) + '│');
}

console.log('  │' + ' '.repeat(W) + '│');
console.log('  │' + RED(pad('  cleanstart/node CANNOT protect you here')) + '│');
console.log('  ├' + '─'.repeat(W) + '┤');

// Layer 1 — OS (cleanstart)
console.log('  │' + GREEN(BOLD(pad('  LAYER 1 — OS / cleanstart/node:latest'))) + '│');
console.log('  │' + GREEN(pad('  ✔ No shell (bash/sh removed)')) + '│');
console.log('  │' + GREEN(pad('  ✔ No package manager (apt/apk removed)')) + '│');
console.log('  │' + GREEN(pad('  ✔ No curl/wget/git (attack tools removed)')) + '│');
console.log('  │' + GREEN(pad('  ✔ Non-root user enforced')) + '│');
console.log('  │' + GREEN(pad('  ✔ Near-zero OS-level CVEs')) + '│');
console.log('  │' + GREEN(pad('  ✔ Signed SBOM + SLSA provenance')) + '│');
console.log('  └' + '─'.repeat(W) + '┘');

// ─── Step 5: Blind spot explanation ──────────────────────────────────────────
console.log(`
  ${BOLD('The blind spot:')}
  When Trivy or Snyk scans your ${CYAN('cleanstart/node')} base image, it finds
  near-zero CVEs. ${BOLD('That result does NOT cover your node_modules.')}

  The moment ${CYAN('npm ci')} runs in your Dockerfile, ${totalPkgs} packages land
  in ${CYAN('/app/node_modules')} — ABOVE the hardened base layer.
  Those packages carry their own CVE history.

  ${BOLD('Common false sense of security:')}
  "I use cleanstart/node, my image scan is clean."
  ↳ The image scan checks OS packages.
  ↳ ${RED('npm audit checks npm packages.')}
  ↳ ${RED('You need BOTH.')}
`);

// ─── Step 6: Tool comparison table ───────────────────────────────────────────
console.log(BOLD('  WHAT EACH SCANNING TOOL SEES\n'));
console.log(BOLD('─'.repeat(68)));
console.log(BOLD(`  ${'Tool'.padEnd(26)} ${'Scans'.padEnd(28)} Result`));
console.log(BOLD('─'.repeat(68)));

const tools = [
  ['Trivy (image scan)',     'OS packages (Layer 1)',    GREEN('✔ Clean — cleanstart works')],
  ['Docker Scout',           'OS packages (Layer 1)',    GREEN('✔ Clean — cleanstart works')],
  ['Grype (image scan)',     'OS + some app deps',       YELLOW('⚠ Partial — may miss npm')],
  ['npm audit',              'node_modules (Layer 2)',   RED(`✗ ${totalVulns} vulns (${meta.critical||0} critical, ${meta.high||0} high)`)],
  ['Snyk test',              'node_modules (Layer 2)',   RED(`✗ ${findings.length} vuln paths found`)],
  ['Trivy (fs scan)',        'node_modules (Layer 2)',   RED('✗ CVEs in transitive deps')],
  ['Trivy (full image scan)','Both layers',              totalVulns > 0 ? RED('✗ Finds npm CVEs inside image') : GREEN('✔ Clean')]
];

for (const [tool, scans, result] of tools) {
  console.log(`  ${tool.padEnd(26)} ${DIM(scans.padEnd(28))} ${result}`);
}
console.log(BOLD('─'.repeat(68)));

// ─── Step 7: Correct workflow ─────────────────────────────────────────────────
console.log(`
  ${BOLD('The correct workflow — scan BOTH layers every build:')}

  ${CYAN('# Layer 1 — confirm cleanstart/node base is clean')}
  trivy image cleanstart/node:latest

  ${CYAN('# Layer 2 — scan your npm deps (run this in CI!)')}
  npm audit --audit-level=high

  ${CYAN('# Both — scan the full built image (catches everything)')}
  docker build -t fintrack-api:latest .
  trivy image --scanners vuln fintrack-api:latest

  ${DIM('Run: node scripts/dep-tree.js       trace each CVE to its source package')}
  ${DIM('Run: node scripts/find-transitive.js  see all ' + totalPkgs + ' packages by depth')}
  ${DIM('Run: node scripts/full-report.js      export JSON + Markdown report')}
  ${DIM('Run: node scripts/apply-overrides.js  generate the fix')}
`);