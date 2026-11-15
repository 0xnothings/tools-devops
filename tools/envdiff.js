#!/usr/bin/env node
// envdiff.js — diff two environment dumps by key, masking secrets.
// Copyright (c) 2026 0xnothings
// @tool envdiff
// @desc Diff two environments (dotenv files or KEY=value dumps): added, removed, changed keys with secret values masked
// @usage node tools/envdiff.js .env.staging .env.prod --json
// @tags devops,config,drift
import { readFileSync, existsSync } from 'node:fs';
import { args, flag, die, emit, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`envdiff — environment drift checker

  node tools/envdiff.js <left> <right> [options]

  --json          machine-readable output
  --no-mask       show raw values (off by default, secrets are masked)
  --keys <a,b>    only compare these keys
  --strict        also fail on values that differ only by whitespace/case in the key
  -h, --help      this text

  Left = baseline (e.g. .env.example), right = actual. Files or "KEY=val" via stdin with -`);
  process.exit(0);
}

const [left, right] = o._;
if (!left || !right) die('usage: node tools/envdiff.js <left> <right> [--json]');
function load(p) {
  if (!existsSync(p)) die(`no such file: ${p}`);
  return readFileSync(p, 'utf8');
}
const SECRET_RE = /(pass|passwd|password|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential|auth|salt|pepper|dsn|conn(ection)?[_-]?string|smtp_url|webhook)/i;
const mask = (k, v) => {
  if (flag(o, 'no-mask')) return v;
  if (!SECRET_RE.test(k)) return v;
  if (!v) return '';
  if (v.length <= 6) return '*'.repeat(v.length);
  return `${v.slice(0, 2)}${'*'.repeat(Math.min(12, v.length - 4))}${v.slice(-2)} (len ${v.length})`;
};

function parse(text, label) {
  const map = new Map();
  const dupes = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;
    const m = line.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*)$/);
    if (!m) continue;
    let v = m[2].trim();
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
    if (map.has(m[1])) dupes.push({ key: m[1], line: i + 1, file: label });
    else map.set(m[1], { value: v, line: i + 1 });
  }
  return { map, dupes };
}

const A = parse(load(left), left);
const B = parse(load(right), right);
const onlyKeys = o.f.keys ? String(o.f.keys).split(',').map((s) => s.trim()).filter(Boolean) : null;

const rows = [];
const allKeys = [...new Set([...A.map.keys(), ...B.map.keys()])].sort();
for (const k of allKeys) {
  if (onlyKeys && !onlyKeys.includes(k)) continue;
  const a = A.map.get(k), b = B.map.get(k);
  if (a && !b) rows.push({ key: k, status: 'removed', left: mask(k, a.value), right: '-' });
  else if (!a && b) rows.push({ key: k, status: 'added', left: '-', right: mask(k, b.value) });
  else if (a.value !== b.value) {
    const status = flag(o, 'strict') && a.value.trim().toLowerCase() === b.value.trim().toLowerCase() ? 'case/whitespace' : 'changed';
    rows.push({ key: k, status, left: mask(k, a.value), right: mask(k, b.value) });
  }
}
const dupFindings = [...A.dupes, ...B.dupes];

if (flag(o, 'json')) {
  emit({
    left: { file: left, keys: A.map.size }, right: { file: right, keys: B.map.size },
    diffs: rows, duplicateKeys: dupFindings,
    counts: { added: rows.filter((r) => r.status === 'added').length, removed: rows.filter((r) => r.status === 'removed').length, changed: rows.filter((r) => r.status === 'changed').length, duplicates: dupFindings.length },
    inSync: rows.length === 0 && dupFindings.length === 0,
  });
  process.exit(rows.length ? 1 : 0);
}

console.log(`envdiff: ${left} (${A.map.size} keys)  vs  ${right} (${B.map.size} keys)`);
console.log(`added: ${rows.filter((r) => r.status === 'added').length}  removed: ${rows.filter((r) => r.status === 'removed').length}  changed: ${rows.filter((r) => r.status === 'changed').length}`);
if (!rows.length && !dupFindings.length) console.log('\nin sync — no drift detected');
else {
  if (rows.length) { console.log(''); console.log(table(rows, ['key', 'status', 'left', 'right'])); }
  if (dupFindings.length) { console.log('\nduplicate keys (last wins, easy to misread):'); console.log(table(dupFindings, ['file', 'key', 'line'])); }
}
process.exit(rows.length ? 1 : 0);
