#!/usr/bin/env node
// scripts/demo-redos.js
// SAFE DEMONSTRATION of the ReDoS vulnerability pattern.
// Shows WHY path-to-regexp@0.1.7 is dangerous using a controlled local test.
// Does NOT send any network requests. No real damage possible.
// Run: node scripts/demo-redos.js

const BOLD   = (s) => `\x1b[1m${s}\x1b[0m`;
const RED    = (s) => `\x1b[31m${s}\x1b[0m`;
const GREEN  = (s) => `\x1b[32m${s}\x1b[0m`;
const YELLOW = (s) => `\x1b[33m${s}\x1b[0m`;
const CYAN   = (s) => `\x1b[36m${s}\x1b[0m`;
const DIM    = (s) => `\x1b[2m${s}\x1b[0m`;

// ─── What is ReDoS? ──────────────────────────────────────────────────────────
console.log('\n' + BOLD('═'.repeat(64)));
console.log(BOLD('  ReDoS (Regular Expression Denial of Service) — Demo'));
console.log(BOLD('  CVE-2024-29041  |  path-to-regexp@0.1.7'));
console.log(BOLD('═'.repeat(64)));

console.log(`
  ${BOLD('What is it?')}
  When a regex engine tries to match a string against certain patterns,
  it can fall into "catastrophic backtracking" — trying every possible
  combination of matches. Time complexity: O(2ⁿ) or worse.

  ${BOLD('Why does it matter in Express?')}
  path-to-regexp converts route strings like "/user/:id" into regex.
  In version 0.1.7, a URL with repeated slashes triggers the bug.
  A single HTTP request can freeze Node.js for seconds.
`);

// ─── Demonstrate the timing difference ──────────────────────────────────────
console.log(BOLD('  TIMING DEMONSTRATION\n'));
console.log('  We test two regex patterns against increasingly long inputs.');
console.log('  Watch how "safe" stays fast while "unsafe" grows exponentially.\n');

// SAFE regex — linear match, similar purpose
const safeRegex = /^\/([^/]+)(\/([^/]+))*$/;

// UNSAFE pattern — this is the class of regex path-to-regexp 0.1.7 generates
// for routes when a greedy group can match overlapping substrings.
// We use a SCALED DOWN version (length capped at 25) so it demonstrates
// the growth WITHOUT actually hanging your terminal for minutes.
const unsafeRegex = /^(\/[a-z]+)+$/;

console.log(BOLD('─'.repeat(64)));
console.log(BOLD(`  ${'Input length'.padEnd(14)} ${'Safe regex (ms)'.padEnd(18)} ${'Unsafe regex (ms)'.padEnd(18)} Risk`));
console.log(BOLD('─'.repeat(64)));

for (let n = 5; n <= 30; n += 5) {
  // Build an input that does NOT match (forces full backtrack)
  const input = '/' + 'ab/'.repeat(n) + '1'; // trailing "1" forces mismatch

  const t1 = process.hrtime.bigint();
  safeRegex.test(input);
  const safeMs = Number(process.hrtime.bigint() - t1) / 1e6;

  const t2 = process.hrtime.bigint();
  unsafeRegex.test(input);
  const unsafeMs = Number(process.hrtime.bigint() - t2) / 1e6;

  const risk = unsafeMs > 100  ? RED('CRITICAL — event loop frozen!')
             : unsafeMs > 10   ? RED('HIGH — noticeable freeze')
             : unsafeMs > 1    ? YELLOW('MEDIUM — slowing down')
             : GREEN('OK — fast');

  console.log(
    `  n=${String(n).padEnd(12)} ${String(safeMs.toFixed(3) + ' ms').padEnd(18)} ${String(unsafeMs.toFixed(3) + ' ms').padEnd(18)} ${risk}`
  );
}

console.log(BOLD('─'.repeat(64)));

// ─── The actual vulnerable pattern ──────────────────────────────────────────
console.log(`
  ${BOLD('What does path-to-regexp@0.1.7 actually generate?')}

  For a route like:  ${CYAN("app.get('/:foo*', handler)")}

  It generates a regex similar to:
    ${RED("/^\\/((?:[^\\/]+?)\\/(?:[^\\/]+?))*(?:\\/)?$/i")}

  The nested optional groups + wildcards create catastrophic backtracking
  when the input contains many slashes and doesn't match cleanly.

  ${BOLD('The attack — one HTTP request to freeze your server:')}
    ${RED("GET /" + "a/".repeat(20) + "b HTTP/1.1")}

  ${BOLD('Impact:')}
    • Node.js single-threaded event loop is blocked
    • All other requests queue up (your API goes dark)
    • 1 request from 1 unauthenticated attacker = full DoS
    • No authentication needed, no special tools needed
`);

// ─── Show what the fix looks like ───────────────────────────────────────────
console.log(BOLD('  THE FIX\n'));
console.log(`  Option A (Recommended): Upgrade to Express 5`);
console.log(`    ${CYAN('npm install express@^5.0.0')}`);
console.log(`    Express 5 uses path-to-regexp@8.x which rewrote the regex engine.\n`);

console.log(`  Option B: Pin the transitive dep via npm overrides`);
console.log(`    In package.json:`);
console.log(`    ${CYAN('{ "overrides": { "path-to-regexp": ">=8.1.0" } }')}`);
console.log(`    Then: ${CYAN('npm install')}\n`);

console.log(`  Option C: Add input validation middleware`);
console.log(`    Block requests with >10 consecutive slashes before routing:`);
console.log(`    ${CYAN(`app.use((req, res, next) => {`)}`);
console.log(`    ${CYAN(`  if (/\\/{5,}/.test(req.path)) return res.status(400).end();`)}`);
console.log(`    ${CYAN(`  next();`)}`);
console.log(`    ${CYAN(`});`)}`);
console.log(`\n  Run ${CYAN('npm run scan:tree')} to see all vulnerable dependency chains.\n`);