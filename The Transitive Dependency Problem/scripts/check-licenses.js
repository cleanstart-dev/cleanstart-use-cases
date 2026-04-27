#!/usr/bin/env node
// scripts/check-licenses.js
// Scans all installed packages for their licenses.
// Flags GPL/AGPL licenses that could create legal issues in commercial code.
// Run: node scripts/check-licenses.js

const fs   = require('fs');
const path = require('path');

const BOLD   = (s) => `\x1b[1m${s}\x1b[0m`;
const RED    = (s) => `\x1b[31m${s}\x1b[0m`;
const YELLOW = (s) => `\x1b[33m${s}\x1b[0m`;
const GREEN  = (s) => `\x1b[32m${s}\x1b[0m`;
const CYAN   = (s) => `\x1b[36m${s}\x1b[0m`;
const DIM    = (s) => `\x1b[2m${s}\x1b[0m`;

// Risk levels
const LICENSE_RISK = {
  'MIT':         { risk: 'safe',    label: GREEN('SAFE    ') },
  'ISC':         { risk: 'safe',    label: GREEN('SAFE    ') },
  'BSD-2-Clause':{ risk: 'safe',    label: GREEN('SAFE    ') },
  'BSD-3-Clause':{ risk: 'safe',    label: GREEN('SAFE    ') },
  'Apache-2.0':  { risk: 'safe',    label: GREEN('SAFE    ') },
  'CC0-1.0':     { risk: 'safe',    label: GREEN('SAFE    ') },
  'Unlicense':   { risk: 'safe',    label: GREEN('SAFE    ') },
  'CC-BY-4.0':   { risk: 'review',  label: YELLOW('REVIEW  ') },
  'LGPL-2.0':    { risk: 'review',  label: YELLOW('REVIEW  ') },
  'LGPL-2.1':    { risk: 'review',  label: YELLOW('REVIEW  ') },
  'LGPL-3.0':    { risk: 'review',  label: YELLOW('REVIEW  ') },
  'GPL-2.0':     { risk: 'danger',  label: RED('DANGER  ') },
  'GPL-3.0':     { risk: 'danger',  label: RED('DANGER  ') },
  'AGPL-3.0':    { risk: 'danger',  label: RED('DANGER  ') },
  'UNLICENSED':  { risk: 'unknown', label: RED('UNLICENSED') },
};

const lockPath = path.join(process.cwd(), 'package-lock.json');
if (!fs.existsSync(lockPath)) {
  console.error(RED('package-lock.json not found.'));
  process.exit(1);
}

const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
const nodeModules = path.join(process.cwd(), 'node_modules');

if (!fs.existsSync(nodeModules)) {
  console.error(RED('node_modules not found. Run `npm install` first.'));
  process.exit(1);
}

const results = [];
const packages = lock.packages || {};

for (const [pkgPath_, meta] of Object.entries(packages)) {
  if (!pkgPath_) continue;
  const name = pkgPath_.replace(/^.*node_modules\//, '');
  if (!name) continue;

  // Read the package's own package.json for license info
  const pkgJsonPath = path.join(process.cwd(), pkgPath_, 'package.json');
  let license = 'UNKNOWN';

  if (fs.existsSync(pkgJsonPath)) {
    try {
      const pkgData = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
      license = pkgData.license || (pkgData.licenses && pkgData.licenses[0] && pkgData.licenses[0].type) || 'UNKNOWN';
      if (typeof license === 'object') license = license.type || 'UNKNOWN';
    } catch (e) {
      license = 'PARSE_ERROR';
    }
  }

  const riskInfo = LICENSE_RISK[license] || { risk: 'unknown', label: YELLOW('UNKNOWN ') };
  results.push({ name, version: meta.version || '?', license, ...riskInfo });
}

results.sort((a, b) => {
  const order = { danger: 0, unknown: 1, review: 2, safe: 3 };
  return (order[a.risk] ?? 4) - (order[b.risk] ?? 4);
});

// ─── Stats ───────────────────────────────────────────────────────────────────
const safe    = results.filter(r => r.risk === 'safe').length;
const review  = results.filter(r => r.risk === 'review').length;
const danger  = results.filter(r => r.risk === 'danger').length;
const unknown = results.filter(r => r.risk === 'unknown').length;

console.log('\n' + BOLD('═'.repeat(68)));
console.log(BOLD('  LICENSE AUDIT — TRANSITIVE DEPENDENCY SCAN'));
console.log(BOLD('═'.repeat(68)));
console.log(`\n  Packages scanned : ${BOLD(results.length)}`);
console.log(`  Safe licenses    : ${GREEN(safe)}`);
console.log(`  Needs review     : ${YELLOW(review)}`);
console.log(`  Dangerous (GPL)  : ${RED(danger)}`);
console.log(`  Unknown          : ${unknown}\n`);

if (danger > 0 || unknown > 0 || review > 0) {
  console.log(BOLD('  PACKAGES NEEDING ATTENTION:\n'));
  console.log(BOLD('─'.repeat(68)));
  console.log(BOLD(`  ${'Package'.padEnd(38)} ${'License'.padEnd(14)} Status`));
  console.log(BOLD('─'.repeat(68)));
  for (const r of results.filter(r => r.risk !== 'safe')) {
    console.log(`  ${(r.name + '@' + r.version).padEnd(38)} ${r.license.padEnd(14)} ${r.label}`);
  }
  console.log(BOLD('─'.repeat(68)));
}

console.log('\n  ' + DIM('Full license list (safe packages):'));
const safeList = results.filter(r => r.risk === 'safe');
const cols = 3;
for (let i = 0; i < Math.min(safeList.length, 30); i += cols) {
  const row = safeList.slice(i, i + cols).map(r => DIM((r.name + '@' + r.version).padEnd(28))).join('  ');
  console.log('  ' + row);
}
if (safeList.length > 30) console.log(DIM(`  ... and ${safeList.length - 30} more safe packages`));

console.log();