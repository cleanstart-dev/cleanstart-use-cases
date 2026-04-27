#!/usr/bin/env node
// scripts/full-report.js
// Generates a full security report combining dep tree + audit output.
// Saves a machine-readable JSON report to reports/security-report.json
// Run: node scripts/full-report.js

const { execSync } = require('child_process');
const fs   = require('fs');
const path = require('path');

const BOLD  = (s) => `\x1b[1m${s}\x1b[0m`;
const RED   = (s) => `\x1b[31m${s}\x1b[0m`;
const GREEN = (s) => `\x1b[32m${s}\x1b[0m`;
const CYAN  = (s) => `\x1b[36m${s}\x1b[0m`;
const DIM   = (s) => `\x1b[2m${s}\x1b[0m`;

if (!fs.existsSync('reports')) fs.mkdirSync('reports');

console.log('\n' + BOLD('═'.repeat(60)));
console.log(BOLD('  FULL SECURITY REPORT GENERATOR'));
console.log(BOLD('═'.repeat(60)) + '\n');

// ─── Step 1: npm audit ───────────────────────────────────────────────────────
console.log(CYAN('  [1/4] Running npm audit...'));
let auditData = { vulnerabilities: {}, metadata: {} };
try {
  const raw = execSync('npm audit --json 2>/dev/null', { encoding: 'utf8' });
  auditData = JSON.parse(raw);
} catch (e) {
  // npm audit exits non-zero when vulns found — catch and parse output
  try {
    auditData = JSON.parse(e.stdout || '{}');
  } catch (_) {
    console.log(RED('  Could not run npm audit. Is npm available?'));
  }
}

// ─── Step 2: parse lock file ─────────────────────────────────────────────────
console.log(CYAN('  [2/4] Parsing package-lock.json...'));
const lock    = JSON.parse(fs.readFileSync('package-lock.json', 'utf8'));
const pkgJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));
const packages = lock.packages || {};
const directDeps = Object.keys(pkgJson.dependencies || {});

const allPkgs = [];
for (const [p, meta] of Object.entries(packages)) {
  if (!p) continue;
  const name  = p.replace(/^.*node_modules\//, '');
  const depth = (p.match(/node_modules/g) || []).length;
  if (name && meta.version) {
    allPkgs.push({ name, version: meta.version, depth, isDirect: directDeps.includes(name) });
  }
}

// ─── Step 3: build report object ────────────────────────────────────────────
console.log(CYAN('  [3/4] Building report object...'));

const vulnEntries = Object.entries(auditData.vulnerabilities || {});
const vulnsBySeverity = { critical: [], high: [], moderate: [], low: [], info: [] };

for (const [name, vuln] of vulnEntries) {
  const sev = vuln.severity || 'info';
  if (vulnsBySeverity[sev]) {
    vulnsBySeverity[sev].push({
      name,
      severity: sev,
      via: Array.isArray(vuln.via)
        ? vuln.via.filter(v => typeof v === 'object').map(v => v.title || v.name).filter(Boolean)
        : [vuln.via],
      fixAvailable: vuln.fixAvailable,
      isDirect: directDeps.includes(name),
    });
  }
}

const report = {
  generatedAt: new Date().toISOString(),
  project: pkgJson.name,
  version: pkgJson.version,
  summary: {
    totalPackages: allPkgs.length,
    directDeps: directDeps.length,
    transitiveDeps: allPkgs.length - directDeps.length,
    vulnerabilities: {
      critical: vulnsBySeverity.critical.length,
      high:     vulnsBySeverity.high.length,
      moderate: vulnsBySeverity.moderate.length,
      low:      vulnsBySeverity.low.length,
    },
    allVulnsInTransitiveDeps: vulnEntries.every(([name]) => !directDeps.includes(name)),
  },
  vulnerabilities: vulnsBySeverity,
  depsByDepth: allPkgs.reduce((acc, p) => {
    acc[p.depth] = (acc[p.depth] || 0) + 1;
    return acc;
  }, {}),
  directDependencies: directDeps,
};

// ─── Step 4: write files ─────────────────────────────────────────────────────
console.log(CYAN('  [4/4] Writing report files...\n'));

fs.writeFileSync('reports/security-report.json', JSON.stringify(report, null, 2));

// Human-readable markdown report
const md = `# Security Report — ${report.project}@${report.version}

Generated: ${report.generatedAt}

## Summary

| Metric | Value |
|--------|-------|
| Total packages | ${report.summary.totalPackages} |
| Direct dependencies | ${report.summary.directDeps} |
| Transitive dependencies | ${report.summary.transitiveDeps} |
| Critical vulnerabilities | ${report.summary.vulnerabilities.critical} |
| High vulnerabilities | ${report.summary.vulnerabilities.high} |
| Moderate vulnerabilities | ${report.summary.vulnerabilities.moderate} |
| All vulns in transitive deps? | **${report.summary.allVulnsInTransitiveDeps ? 'YES — none of your direct packages are vulnerable' : 'No — some direct deps are vulnerable'}** |

## Vulnerability Details

${Object.entries(vulnsBySeverity)
  .filter(([, arr]) => arr.length > 0)
  .map(([sev, arr]) => `### ${sev.toUpperCase()} (${arr.length})\n\n${arr.map(v =>
    `- **${v.name}** — ${v.via.join(', ') || 'unknown'} — Fix available: ${v.fixAvailable ? 'Yes' : 'No'}`
  ).join('\n')}`)
  .join('\n\n')}

## Dependency Depth Distribution

${Object.entries(report.depsByDepth)
  .sort(([a],[b]) => Number(a)-Number(b))
  .map(([d,c]) => `- Depth ${d}: ${c} packages`)
  .join('\n')}

## Remediation

\`\`\`bash
# Quick fix — patches known transitive vulnerabilities
npm audit fix

# Nuclear option — breaks semver but fixes everything
npm audit fix --force

# Manual override in package.json for unfixable transitive deps
# See overrides section in README.md
\`\`\`
`;

fs.writeFileSync('reports/security-report.md', md);

// ─── Print summary ───────────────────────────────────────────────────────────
console.log(BOLD('  ┌─ SECURITY REPORT SUMMARY ──────────────────────────┐'));
console.log(`  │  Project     : ${pkgJson.name}@${pkgJson.version}`.padEnd(57) + '│');
console.log(`  │  Total pkgs  : ${report.summary.totalPackages}`.padEnd(57) + '│');
console.log(`  │  Direct deps : ${report.summary.directDeps}`.padEnd(57) + '│');
console.log(`  │  Transitive  : ${report.summary.transitiveDeps}`.padEnd(57) + '│');
console.log('  ├────────────────────────────────────────────────────────┤');
console.log(`  │  ${RED('Critical')}     : ${report.summary.vulnerabilities.critical}`.padEnd(66) + '│');
console.log(`  │  ${RED('High     ')}    : ${report.summary.vulnerabilities.high}`.padEnd(66) + '│');
console.log(`  │  Moderate    : ${report.summary.vulnerabilities.moderate}`.padEnd(57) + '│');
console.log('  ├────────────────────────────────────────────────────────┤');
console.log(`  │  ${GREEN('Report saved to reports/security-report.json')}`.padEnd(66) + '│');
console.log(`  │  ${GREEN('Report saved to reports/security-report.md  ')}`.padEnd(66) + '│');
console.log('  └────────────────────────────────────────────────────────┘\n');