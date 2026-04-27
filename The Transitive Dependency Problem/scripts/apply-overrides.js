#!/usr/bin/env node
// scripts/apply-overrides.js
// Shows you exactly what overrides to add to package.json to fix
// transitive vulnerabilities you can't fix by upgrading direct deps.
// Run: node scripts/apply-overrides.js

const fs   = require('fs');

const BOLD  = (s) => `\x1b[1m${s}\x1b[0m`;
const GREEN = (s) => `\x1b[32m${s}\x1b[0m`;
const CYAN  = (s) => `\x1b[36m${s}\x1b[0m`;
const DIM   = (s) => `\x1b[2m${s}\x1b[0m`;

// Remediation map: what to override and why
const REMEDIATIONS = [
  {
    pkg: 'path-to-regexp',
    currentVuln: '0.1.7',
    fix: '>=8.1.0',
    why: 'ReDoS — CVE-2024-29041 (CRITICAL 9.1)',
    pulledBy: 'express → router',
    note: 'express@5 bundles a safe version; prefer upgrading express itself.',
  },
  {
    pkg: 'path-to-regexp',
    currentVuln: '6.2.1',
    fix: '>=8.1.0',
    why: 'ReDoS — CVE-2024-45296 (CRITICAL 9.1)',
    pulledBy: 'express-rate-limit',
    note: 'override forces npm to hoist a safe version for all dependents.',
  },
  {
    pkg: 'semver',
    currentVuln: '7.3.8',
    fix: '>=7.5.2',
    why: 'ReDoS — CVE-2022-25883 (HIGH 7.5)',
    pulledBy: 'jsonwebtoken',
    note: 'Small patch version bump — low breakage risk.',
  },
];

console.log('\n' + BOLD('═'.repeat(64)));
console.log(BOLD('  REMEDIATION GUIDE — TRANSITIVE DEPENDENCY OVERRIDES'));
console.log(BOLD('═'.repeat(64)));

console.log(`
  ${BOLD('Why overrides?')}
  When a vulnerable package is pulled in by a third-party library
  (not directly by you), you can't fix it by upgrading your own code.
  npm's "overrides" field lets you force a specific version for any
  transitive dependency, regardless of what the parent package wants.
`);

for (const r of REMEDIATIONS) {
  console.log(BOLD('─'.repeat(64)));
  console.log(`  ${BOLD('Package:')}   ${r.pkg}  ${r.currentVuln} → ${GREEN(r.fix)}`);
  console.log(`  ${BOLD('Severity:')}  ${r.why}`);
  console.log(`  ${BOLD('Pulled by:')} ${r.pulledBy}`);
  console.log(`  ${BOLD('Note:')}      ${DIM(r.note)}`);
}

console.log(BOLD('─'.repeat(64)));

// Generate the overrides block
const overrides = {};
for (const r of REMEDIATIONS) {
  overrides[r.pkg] = r.fix;
}

const upgradeDirectDeps = {
  express: '^5.0.0',
  axios:   '^1.7.4',
};

console.log(`\n  ${BOLD('Step 1 — Upgrade direct deps where possible:')}`);
console.log(`\n  ${CYAN('npm install ' + Object.entries(upgradeDirectDeps).map(([k,v]) => `${k}@"${v}"`).join(' '))}\n`);

console.log(`  ${BOLD('Step 2 — Add overrides to package.json for remaining issues:')}\n`);
const snippet = JSON.stringify({ overrides }, null, 2).split('\n').map(l => '    ' + l).join('\n');
console.log(CYAN(snippet));

console.log(`\n  ${BOLD('Step 3 — Reinstall to apply overrides:')}`);
console.log(`  ${CYAN('npm install')}`);

console.log(`\n  ${BOLD('Step 4 — Verify the fix:')}`);
console.log(`  ${CYAN('npm audit')}`);
console.log(`  ${CYAN('node scripts/dep-tree.js')}\n`);

// Optionally write a fixed package.json
const pkgJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));
const fixedPkg = {
  ...pkgJson,
  overrides,
  dependencies: {
    ...pkgJson.dependencies,
    ...upgradeDirectDeps,
  },
};

fs.writeFileSync('package-fixed.json', JSON.stringify(fixedPkg, null, 2));
console.log(GREEN('  ✔  package-fixed.json written.'));
console.log(DIM('     Review it, then: cp package-fixed.json package.json && npm install\n'));