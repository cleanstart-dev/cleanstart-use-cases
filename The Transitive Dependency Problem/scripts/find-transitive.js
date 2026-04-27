#!/usr/bin/env node
// scripts/find-transitive.js
// Lists ALL transitive dependencies sorted by nesting depth.
// Highlights packages that are NOT in your package.json but are installed.
// Run: node scripts/find-transitive.js

const fs   = require('fs');
const path = require('path');

const BOLD  = (s) => `\x1b[1m${s}\x1b[0m`;
const DIM   = (s) => `\x1b[2m${s}\x1b[0m`;
const RED   = (s) => `\x1b[31m${s}\x1b[0m`;
const CYAN  = (s) => `\x1b[36m${s}\x1b[0m`;
const GREEN = (s) => `\x1b[32m${s}\x1b[0m`;

const KNOWN_VULNS = new Set([
  'path-to-regexp@0.1.7',
  'path-to-regexp@6.2.1',
  'follow-redirects@1.15.2',
  'semver@7.3.8',
]);

// ─── Load files ──────────────────────────────────────────────────────────────
const lockPath = path.join(process.cwd(), 'package-lock.json');
const pkgPath  = path.join(process.cwd(), 'package.json');

if (!fs.existsSync(lockPath)) {
  console.error(RED('package-lock.json not found. Run `npm install` first.'));
  process.exit(1);
}

const lock    = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
const pkgJson = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
const directSet = new Set(Object.keys(pkgJson.dependencies || {}));

// ─── Parse all installed packages from package-lock ─────────────────────────
const allPkgs = [];
const packages = lock.packages || {};

for (const [pkgPath_, meta] of Object.entries(packages)) {
  if (!pkgPath_) continue;

  // Depth = number of "node_modules" segments in path
  const depth = (pkgPath_.match(/node_modules/g) || []).length;
  const name  = pkgPath_.replace(/^.*node_modules\//, '');

  if (!name || !meta.version) continue;

  allPkgs.push({
    name,
    version: meta.version,
    depth,
    isDirect: directSet.has(name),
    isVuln: KNOWN_VULNS.has(`${name}@${meta.version}`),
    path: pkgPath_,
  });
}

// Sort: direct first, then by depth, then alphabetical
allPkgs.sort((a, b) => {
  if (a.isDirect !== b.isDirect) return a.isDirect ? -1 : 1;
  if (a.depth !== b.depth) return a.depth - b.depth;
  return a.name.localeCompare(b.name);
});

// ─── Stats ───────────────────────────────────────────────────────────────────
const directCount     = allPkgs.filter(p => p.isDirect).length;
const transitiveCount = allPkgs.filter(p => !p.isDirect).length;
const vulnCount       = allPkgs.filter(p => p.isVuln).length;

const maxDepth = Math.max(...allPkgs.map(p => p.depth));
const byDepth  = Array.from({ length: maxDepth + 1 }, (_, d) =>
  allPkgs.filter(p => p.depth === d).length
);

console.log('\n' + BOLD('═'.repeat(68)));
console.log(BOLD('  TRANSITIVE DEPENDENCY DEPTH ANALYSIS'));
console.log(BOLD('═'.repeat(68)));
console.log(`\n  ${'Package count'.padEnd(26)} ${BOLD(allPkgs.length)}`);
console.log(`  ${'Direct (package.json)'.padEnd(26)} ${GREEN(directCount)}`);
console.log(`  ${'Transitive (hidden)'.padEnd(26)} ${CYAN(transitiveCount)}`);
console.log(`  ${'Vulnerable'.padEnd(26)} ${RED(vulnCount)}`);
console.log(`  ${'Max nesting depth'.padEnd(26)} ${maxDepth}`);

console.log('\n  ' + BOLD('Packages by depth:'));
byDepth.forEach((count, depth) => {
  const bar = '█'.repeat(Math.round(count / 2));
  const label = depth === 0 ? '  root (you)' : `  depth ${depth}  `;
  console.log(`  ${label.padEnd(14)} ${String(count).padStart(3)}  ${DIM(bar)}`);
});

// ─── Print table ─────────────────────────────────────────────────────────────
console.log('\n' + BOLD('─'.repeat(68)));
console.log(BOLD(`  ${'Package'.padEnd(36)} ${'Version'.padEnd(12)} ${'Depth'.padEnd(7)} Type`));
console.log(BOLD('─'.repeat(68)));

for (const pkg of allPkgs) {
  const vuln   = pkg.isVuln ? RED(' ◄ VULN') : '';
  const type   = pkg.isDirect ? GREEN('direct') : DIM('transitive');
  const name   = pkg.isVuln ? RED(BOLD(pkg.name.padEnd(36))) : pkg.name.padEnd(36);
  const ver    = pkg.isVuln ? RED(pkg.version.padEnd(12)) : DIM(pkg.version.padEnd(12));
  const depth  = String(pkg.depth).padEnd(7);
  console.log(`  ${name} ${ver} ${depth} ${type}${vuln}`);
}

console.log(BOLD('─'.repeat(68)));
console.log(DIM(`\n  ${vulnCount} vulnerable packages found. Run ${CYAN('npm run audit:json')} for details.\n`));