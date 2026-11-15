#!/usr/bin/env node
// pkgdiff.js — compare dependency trees between two manifests or lockfiles.
// Copyright (c) 2026 0xnothings
// @tool pkgdiff
// @desc Diff dependencies between two package.json/composer.json/lockfiles: added, removed, bumped, risky majors
// @usage node tools/pkgdiff.js old/package.json new/package.json --json
// @tags devops,dependencies,ci
import { readFileSync, existsSync } from 'node:fs';
import { args, flag, die, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`pkgdiff — dependency diff between two states (good for PR review)

  node tools/pkgdiff.js <old.json> <new.json> [options]

  --majors-only   only report semver-major changes
  --json          machine-readable output
  -h, --help      this text

  Understands package.json (deps+devDeps), package-lock v2/v3,
  composer.json, requirements.txt (name==version).`);
  process.exit(0);
}

function load(file) {
  if (!existsSync(file)) die(`${file} not found`);
  const txt = readFileSync(file, 'utf8');
  const base = file.split(/[\\/]/).pop();
  const deps = new Map();
  if (base.endsWith('.txt')) {
    for (const l of txt.split('\n')) { const m = l.trim().match(/^([A-Za-z0-9_.\-]+)\s*==\s*([\w.]+)/); if (m) deps.set(m[1], m[2]); }
    return { base, deps, kind: 'pip' };
  }
  let j; try { j = JSON.parse(txt); } catch (e) { die(`${file}: ${e.message}`); }
  if (j.packages) {
    for (const [k, v] of Object.entries(j.packages)) {
      if (!k || k === '') continue;
      const name = k.replace(/^node_modules\//, '').replace(/^.*node_modules\//, '');
      if (v.version) deps.set(name, v.version);
    }
    return { base, deps, kind: 'lockfile' };
  }
  if (j.dependencies || j.devDependencies) {
    for (const [name, ver] of Object.entries({ ...(j.dependencies || {}), ...(j.devDependencies || {}) })) if (typeof ver === 'string') deps.set(name, ver);
    return { base, deps, kind: 'manifest' };
  }
  if (j.require) {
    for (const [name, ver] of Object.entries({ ...(j.require || {}), ...(j['require-dev'] || {}) })) if (typeof ver === 'string') deps.set(name, ver);
    return { base, deps, kind: 'composer' };
  }
  die(`${file}: unsupported manifest shape`);
}

const oldF = load(o._[0]), newF = load(o._[1]);
if (!o._[1]) die('need two files: old and new');

const clean = (v) => String(v).replace(/^[\^~>=<\s]+/, '').split(' ')[0].split('|')[0].replace(/^v/, '');
const major = (v) => { const m = clean(v).match(/^(\d+)/); return m ? Number(m[1]) : null; };

const rows = [];
for (const [name, newVer] of newF.deps) {
  if (!oldF.deps.has(name)) rows.push({ change: 'added', pkg: name, from: '-', to: newVer, risk: '' });
  else {
    const oldVer = oldF.deps.get(name);
    if (clean(oldVer) === clean(newVer)) continue;
    const [mo, mn] = [major(oldVer), major(newVer)];
    const risk = mo !== null && mn !== null ? (mn > mo ? 'MAJOR (breaking)' : mn < mo ? 'downgrade' : 'minor/patch') : 'unparsed';
    rows.push({ change: risk === 'MAJOR (breaking)' ? 'major-bump' : risk === 'downgrade' ? 'downgrade' : 'bump', pkg: name, from: oldVer, to: newVer, risk });
  }
}
for (const [name, oldVer] of oldF.deps) if (!newF.deps.has(name)) rows.push({ change: 'removed', pkg: name, from: oldVer, to: '-', risk: '' });

const order = { 'major-bump': 0, 'downgrade': 1, added: 2, bump: 3, removed: 4 };
rows.sort((a, b) => order[a.change] - order[b.change] || a.pkg.localeCompare(b.pkg));
let out = rows;
if (flag(o, 'majors-only')) out = rows.filter((r) => r.change === 'major-bump' || r.change === 'downgrade');

const counts = rows.reduce((acc, r) => (acc[r.change] = (acc[r.change] || 0) + 1, acc), {});
if (flag(o, 'json')) console.log(JSON.stringify({ old: { file: oldF.base, deps: oldF.deps.size, kind: oldF.kind }, new: { file: newF.base, deps: newF.deps.size, kind: newF.kind }, counts, changes: out }, null, 2));
else {
  console.log(`${oldF.base} (${oldF.deps.size} deps)  ->  ${newF.base} (${newF.deps.size} deps)\n`);
  console.log(table(out));
  console.log(`\n${rows.length} change(s): ${Object.entries(counts).map(([k, v]) => `${v} ${k}`).join(', ')}`);
  const risky = rows.filter((r) => r.change === 'major-bump' || r.change === 'downgrade');
  if (risky.length) console.log(`\nreview before merge: ${risky.map((r) => `${r.pkg} ${r.from}->${r.to}`).join(', ')}`);
}
