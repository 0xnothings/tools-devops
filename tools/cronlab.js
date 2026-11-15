#!/usr/bin/env node
// cronlab.js — cron expression explainer and validator.
// Copyright (c) 2026 0xnothings
// @tool cronlab
// @desc Explain/validate cron expressions in English, compute next run times, and convert between formats
// @usage node tools/cronlab.js "*/15 9-17 * * 1-5" --next 5 --json
// @tags devops,cron,scheduler
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`cronlab — cron expression explainer

  node tools/cronlab.js "<expr>" [options]

  --next <n>     show the next n run times (default: 5)
  --json         machine-readable output
  --list <file>  validate every expression in a file
  -h, --help     this text

  Supports 5-field cron and 6-field (with seconds).
  Fields: min hour dom month dow [sec]`);
  process.exit(0);
}

const FIELDS = [
  { name: 'minute', min: 0, max: 59 },
  { name: 'hour', min: 0, max: 23 },
  { name: 'day of month', min: 1, max: 31 },
  { name: 'month', min: 1, max: 12 },
  { name: 'day of week', min: 0, max: 7 },
  { name: 'second', min: 0, max: 59 },
];
const ALIASES = {
  '@yearly': '0 0 1 1 *', '@annually': '0 0 1 1 *', '@monthly': '0 0 1 * *',
  '@weekly': '0 0 * * 0', '@daily': '0 0 * * *', '@midnight': '0 0 * * *', '@hourly': '0 * * * *',
  '@every_minute': '* * * * *',
};
const NAME_MAP = { jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12, sun: 0, mon: 1, tue: 2, wed: 3, thu: 4, fri: 5, sat: 6 };

function norm(token, f) {
  let t = token.toLowerCase();
  if (NAME_MAP[t] !== undefined) return [NAME_MAP[t]];
  if (t === '*' || t === '?') return Array.from({ length: f.max - f.min + 1 }, (_, i) => f.min + i);
  if (/^\*\/\d+$/.test(t)) { const s = +t.split('/')[1]; return s ? Array.from({ length: f.max - f.min + 1 }, (_, i) => f.min + i).filter((v) => (v - f.min) % s === 0) : []; }
  if (/^\d+-\d+$/.test(t)) { const [a, b] = t.split('-').map(Number); return a <= b ? Array.from({ length: b - a + 1 }, (_, i) => a + i) : []; }
  if (/^\d+-\d+\/\d+$/.test(t)) { const [r, s] = t.split('/'); const [a, b] = r.split('-').map(Number); return Array.from({ length: b - a + 1 }, (_, i) => a + i).filter((v) => (v - a) % +s === 0); }
  if (/^\d+(,\d+)+$/.test(t)) return t.split(',').map(Number);
  if (/^\d+$/.test(t)) return [Number(t)];
  return null;
}

function parse(expr) {
  const raw = expr.trim();
  const expanded = ALIASES[raw] || raw;
  const parts = expanded.split(/\s+/);
  if (parts.length < 5 || parts.length > 6) return { error: `expected 5 or 6 fields, got ${parts.length}` };
  const fields = parts.map((p, i) => {
    const f = FIELDS[i];
    const values = norm(p, f);
    if (!values) return { error: `field ${i + 1} (${f.name}) cannot parse "${p}"` };
    const bad = values.filter((v) => v < f.min || v > f.max);
    if (bad.length) return { error: `field ${i + 1} (${f.name}) out of range ${f.min}-${f.max}: ${bad.join(',')}` };
    return { name: f.name, raw: p, values: [...new Set(values)].sort((a, b) => a - b) };
  });
  const err = fields.find((f) => f.error);
  return err ? err : { fields, expanded, hasSeconds: parts.length === 6 };
}

function nextRuns(parsed, count) {
  const f = parsed.fields;
  const minutes = f[0].values, hours = f[1].values, doms = f[2].values, months = f[3].values, dows = f[4].values.map((d) => (d === 7 ? 0 : d));
  const seconds = parsed.hasSeconds ? f[5].values : [0];
  const out = [];
  const now = new Date();
  let cur = new Date(Math.ceil(now.getTime() / 60000) * 60000);
  for (let i = 0; i < 366 * 24 * 4 && out.length < count; i++) {
    const m = cur.getUTCMonth() + 1, d = cur.getUTCDate(), hh = cur.getUTCHours(), mm = cur.getUTCMinutes(), dw = cur.getUTCDay();
    const domOk = doms.includes(d), dowOk = dows.includes(dw);
    const dayOk = doms.length === 31 && dows.length === 8 ? true : (doms.length === 31 ? dowOk : dows.length === 8 ? domOk : domOk || dowOk);
    if (months.includes(m) && dayOk && hours.includes(hh) && minutes.includes(mm)) {
      for (const s of seconds) out.push(new Date(Date.UTC(cur.getUTCFullYear(), cur.getUTCMonth(), d, hh, mm, s)).toISOString());
      if (out.length >= count) break;
    }
    cur = new Date(cur.getTime() + 60000);
  }
  return out.slice(0, count);
}

function explain(parsed) {
  const [mi, ho, dom, mo, dow] = parsed.fields;
  const pick = (vals, unit, max) => vals.length === max ? `every ${unit}` : vals.length === 1 ? `at ${unit} ${vals[0]}` : `at ${unit}s ${vals.join(', ')}`;
  const dayPart = dom.raw === '*' && dow.raw === '*' ? 'every day'
    : dom.raw !== '*' && dow.raw === '*' ? `on day-of-month ${dom.values.join(',')}`
    : dom.raw === '*' && dow.raw !== '*' ? `on ${dow.values.map((d) => ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'][d]).join(',')}`
    : `when dom ${dom.values.join(',')} or dow ${dow.values.join(',')}`;
  const monPart = mo.values.length === 12 ? '' : ` in month(s) ${mo.values.join(',')}`;
  const secPart = parsed.hasSeconds && parsed.fields[5].values.length < 60 ? ` (seconds ${parsed.fields[5].values.join(',')})` : '';
  return `${pick(ho.values, 'hour', 24)}, ${pick(mi.values, 'minute', 60)}${secPart}, ${dayPart}${monPart}`;
}

const inputs = o.f.list ? await inputLines(String(get(o, 'list'))) : [o._[0]];
if (!inputs[0]) die('usage: node tools/cronlab.js "<expr>" [--next 5]');
const count = num(get(o, 'next'), 5);
const results = [];
let bad = 0;

for (const expr of inputs.filter(Boolean)) {
  const parsed = parse(expr);
  if (parsed.error) { bad++; results.push({ expr, error: parsed.error }); continue; }
  results.push({ expr, expanded: parsed.expanded, fields: parsed.fields.map((f) => `${f.name}: ${f.raw}`), human: explain(parsed), next: nextRuns(parsed, count) });
}

if (flag(o, 'json')) { console.log(JSON.stringify(results, null, 2)); process.exit(bad ? 1 : 0); }
for (const r of results) {
  console.log(`\n${r.expr}`);
  if (r.error) { console.log(`  INVALID: ${r.error}`); continue; }
  console.log(`  means: ${r.human}`);
  console.log(`  fields: ${r.fields.join('  |  ')}`);
  console.log(`  next ${r.next.length} (UTC):`);
  r.next.forEach((n) => console.log('    ' + n.replace('T', ' ').replace('Z', '') + ' UTC'));
}
if (bad) console.log(`\n${bad} invalid expression(s)`);
process.exit(bad ? 1 : 0);
