#!/usr/bin/env node
// cronconvert.js — convert between cron, systemd OnCalendar and English.
// Copyright (c) 2026 0xnothings
// @tool cronconvert
// @desc Convert schedules both ways: cron expression to systemd OnCalendar and English, OnCalendar to cron, and next-run previews
// @usage node tools/cronconvert.js "*/15 9-17 * * 1-5" --to systemd --json
// @tags devops,cron,systemd,scheduler
import { args, get, num, flag, die, emit, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`cronconvert — schedule format converter

  node tools/cronconvert.js "<schedule>" [options]
  node tools/cronconvert.js --from systemd --input "Mon..Fri *-*-* 09..17:00/15:00"

  --to <fmt>      cron | systemd | english   (default: all)
  --from <fmt>    auto | cron | systemd      (default auto)
  --input <s>     schedule text (alternative to the positional arg)
  --next <n>      preview N next runs (default 5)
  --json          machine-readable output
  -h, --help      this text

  Cron: 5 or 6 fields plus @hourly-style macros. Systemd: OnCalendar syntax
  (Mon..Fri, *-*-*, HH:MM/step, daily/weekly shorthands).`);
  process.exit(0);
}

const input = o.f.input ? String(o.f.input) : o._.join(' ');
if (!input) die('usage: node tools/cronconvert.js "<schedule>" [--to systemd] [--json]');
const toFmt = o.f.to ? String(o.f.to).toLowerCase() : 'all';
const fromFmtGiven = o.f.from ? String(o.f.from).toLowerCase() : 'auto';
const fromFmt = fromFmtGiven !== 'auto' ? fromFmtGiven : (/^[A-Za-z]{3}(\.\.|\*|-)/.test(input) || /\d{2}:\d{2}/.test(input) && !/^\S+\s+\S+\s+\S+/.test(input) ? 'systemd' : 'cron');

const DOW = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const MACROS = {
  '@yearly': '0 0 1 1 *', '@annually': '0 0 1 1 *', '@monthly': '0 0 1 * *', '@weekly': '0 0 * * 0',
  '@daily': '0 0 * * *', '@midnight': '0 0 * * *', '@hourly': '0 * * * *',
};

function expandField(field, min, max, names) {
  const out = new Set();
  for (const part of field.split(',')) {
    let m;
    if ((m = part.match(/^(\*|\d+(?:-[A-Za-z0-9]+)?)(?:\/(\d+))?$/))) {
      const [, base, stepRaw] = m;
      const step = stepRaw ? Number(stepRaw) : 1;
      let lo = min, hi = max;
      if (base !== '*') {
        const [a, b] = base.split('-');
        lo = names ? names.indexOf(a) >= 0 ? names.indexOf(a) : Number(a) : Number(a);
        hi = b !== undefined ? (names ? (names.indexOf(b) >= 0 ? names.indexOf(b) : Number(b)) : Number(b)) : lo;
        if (b === undefined) hi = base.includes('*') ? max : lo;
      }
      for (let v = lo; v <= hi; v += step) out.add(v);
    } else if (/^[A-Za-z]/.test(part) && names) {
      const i = names.indexOf(part);
      if (i >= 0) out.add(i);
    }
  }
  return [...out].sort((a, b) => a - b);
}

function cronToSystemd(expr) {
  let e = expr.trim().replace(/\s+/g, ' ');
  if (MACROS[e]) e = MACROS[e];
  const parts = e.split(' ');
  if (parts.length === 6) parts.shift(); // drop seconds field
  if (parts.length !== 5) return { error: `expected 5 fields, got ${parts.length}` };
  const [mi, hr, dom, mon, dow] = parts;
  const hasStep = /\//.test(mi) || /\//.test(hr);
  const simple = dom === '*' && mon === '*' && dow === '*';
  const allSame = (f) => /^\d+$/.test(f);

  const timeDay = (() => {
    if (allSame(mi) && allSame(hr) && simple) return null;
    return null;
  })();

  // build the date part
  let datePart = '';
  if (mon === '*' && dom === '*' && dow === '*') datePart = '*-*-*';
  else if (mon === '*' && dom === '*' && dow !== '*') {
    const days = expandField(dow, 0, 6, DOW).map((d) => DOW[d]);
    datePart = `${days.length === 1 ? days[0] : `${days[0]}..${days[days.length - 1]}`} *-*-*`;
  } else if (mon === '*' && dom !== '*' && dow === '*') {
    const doms = expandField(dom, 1, 31);
    datePart = `*-*-${doms.length === 1 ? doms[0] : String(doms[0]).padStart(2, '0')}`;
  } else if (mon !== '*' && dom !== '*' && dow === '*') {
    const mons = expandField(mon, 1, 12, MONTHS).map((m) => MONTHS[m - 1]);
    const doms = expandField(dom, 1, 31);
    datePart = `*-${mons.length === 1 ? mons[0] : `${mons[0]}..${mons[mons.length - 1]}`}-${String(doms[0]).padStart(2, '0')}`;
  } else {
    return { error: 'this cron expression combines DOM and DOW or month ranges that OnCalendar cannot express in one calendar spec; split it into two timers' };
  }

  let timePart;
  if (hr === '*' && mi === '*') timePart = '*:*';
  else if (hr === '*' && /^\d+$/.test(mi)) timePart = `*:${String(mi).padStart(2, '0')}`;
  else if (/^\*\/\d+$/.test(mi) && hr === '*') timePart = `*:00/${mi.split('/')[1]}`;
  else if (allSame(hr) && /^\*\/\d+$/.test(mi)) timePart = `${String(hr).padStart(2, '0')}:00/${mi.split('/')[1]}`;
  else if (allSame(hr) && allSame(mi)) timePart = `${String(hr).padStart(2, '0')}:${String(mi).padStart(2, '0')}`;
  else if (/^\d+-\d+$/.test(hr) && allSame(mi)) {
    const [a, b] = hr.split('-');
    timePart = `${String(a).padStart(2, '0')}..${String(b).padStart(2, '0')}:${String(mi).padStart(2, '0')}`;
  } else if (/^\d+-\d+$/.test(hr) && /^\*\/\d+$/.test(mi)) {
    const [a, b] = hr.split('-');
    const st = String(mi.split('/')[1]).padStart(2, '0');
    timePart = `${String(a).padStart(2, '0')}..${String(b).padStart(2, '0')}:00/${st}:00`;
  } else if (/^\d+,\d+/.test(hr)) timePart = hr.split(',').map((h) => `${String(h).padStart(2, '0')}:${String(mi).padStart(2, '0')}`).join(',');
  else if (allSame(hr) && /^\d+(,\d+)+$/.test(mi)) timePart = mi.split(',').map((m) => `${String(hr).padStart(2, '0')}:${String(m).padStart(2, '0')}`).join(',');
  else if (/^\*\/\d+$/.test(hr) && allSame(mi)) timePart = `00/${hr.split('/')[1]}:${String(mi).padStart(2, '0')}`;
  else return { error: `cannot express hour/minute "${hr} ${mi}" as a single OnCalendar spec` };

  const shortcut = (() => {
    if (e === '0 0 * * *') return 'daily';
    if (e === '0 0 * * 0') return 'weekly';
    if (e === '0 0 1 * *') return 'monthly';
    if (e === '0 0 1 1 *') return 'yearly';
    if (e === '0 * * * *') return 'hourly';
    return null;
  })();

  return { systemd: shortcut ? shortcut : (datePart === '*-*-*' ? timePart : `${datePart} ${timePart}`), simple };
}

function systemdToCron(spec) {
  const s = spec.trim();
  const shortcuts = { hourly: '0 * * * *', daily: '0 0 * * *', weekly: '0 0 * * 0', monthly: '0 0 1 * *', yearly: '0 0 1 1 *', quarterly: '0 0 1 1,4,7,10 *', semiannually: '0 0 1 1,7 *' };
  if (shortcuts[s]) return { cron: shortcuts[s], note: 'systemd shorthand' };
  const m = s.match(/^(?:([A-Za-z,.*]+)\s+)?([A-Za-z*0-9.-]+)-([A-Za-z*0-9.-]+)-([A-Za-z*0-9.,]+)\s+(.+)$/);
  if (!m) return { error: 'not a recognisable OnCalendar spec' };
  const [, dowPart, y, mon, dom, time] = m;
  let dow = '*';
  if (dowPart && dowPart !== '*') {
    const idx = (name) => DOW.findIndex((d) => d.toLowerCase() === name.slice(0, 3).toLowerCase());
    if (/\.\./.test(dowPart)) { const [a, b] = dowPart.split('..'); dow = `${idx(a)}-${idx(b)}`; }
    else dow = String(idx(dowPart));
  }
  let monPart = '*';
  if (mon !== '*' && !/^\*$/.test(mon)) {
    if (/\.\./.test(mon)) { const [a, b] = mon.split('..'); monPart = `${MONTHS.indexOf(a) + 1}-${MONTHS.indexOf(b) + 1}`; }
    else monPart = String(MONTHS.indexOf(mon.slice(0, 3)) + 1);
  }
  let domPart = dom === '*' || dom === '*-*' ? '*' : dom.replace(/^0/, '');
  if (/\.\./.test(dom)) { const [a, b] = dom.split('..'); domPart = `${Number(a)}-${Number(b)}`; }

  let mi = '0', hr = '*';
  if (time === '*:*') { mi = '*'; hr = '*'; }
  else if (/^\*:\d+$/.test(time)) { mi = String(Number(time.split(':')[1])); hr = '*'; }
  else if (/^\*:00\/(\d+)$/.test(time)) { mi = `*/${time.split('/')[1]}`; hr = '*'; }
  else if (/^(\d+):00\/(\d+)$/.test(time)) { const [, h, st] = time.match(/^(\d+):00\/(\d+)$/); hr = String(Number(h)); mi = `*/${st}`; }
  else if (/^(\d+)\.\.(\d+):(\d+)$/.test(time)) { const [, a, b, mm] = time.match(/^(\d+)\.\.(\d+):(\d+)$/); hr = `${Number(a)}-${Number(b)}`; mi = String(Number(mm)); }
  else if (/^(\d+)\.\.(\d+):(\d+)\/(\d+)(?::(\d+))?$/.test(time)) {
    const [, a, b, mm, st] = time.match(/^(\d+)\.\.(\d+):(\d+)\/(\d+)(?::(\d+))?$/);
    hr = `${Number(a)}-${Number(b)}`;
    mi = Number(mm) === 0 ? `*/${Number(st)}` : `${Number(mm)}/${Number(st)}`;
  }
  else if (/^(\d+):(\d+)\/(\d+)(?::(\d+))?$/.test(time)) {
    const [, hh, mm, st] = time.match(/^(\d+):(\d+)\/(\d+)(?::(\d+))?$/);
    hr = String(Number(hh)); mi = Number(mm) === 0 ? `*/${Number(st)}` : `${Number(mm)}/${Number(st)}`;
  }
  else if (/^\d+:\d+$/.test(time)) { const [hh, mm] = time.split(':'); hr = String(Number(hh)); mi = String(Number(mm)); }
  else if (time.includes(',')) {
    const pairs = time.split(',').map((t) => t.split(':').map(Number));
    hr = pairs.map((p) => p[0]).join(',');
    mi = pairs.every((p) => p[1] === pairs[0][1]) ? String(pairs[0][1]) : pairs.map((p) => p[1]).join(',');
  }
  else if (/^00\/(\d+):(\d+)$/.test(time)) { const [, st, mm] = time.match(/^00\/(\d+):(\d+)$/); hr = `*/${st}`; mi = String(Number(mm)); }
  else return { error: `cannot express time part "${time}" in cron` };
  return { cron: `${mi} ${hr} ${domPart} ${monPart} ${dow}` };
}

function describeCron(expr) {
  let e = expr.trim();
  if (MACROS[e]) { const m = e.replace('@', ''); return `every ${m === 'midnight' ? 'day at midnight' : m === 'annually' ? 'year' : m}`; }
  const parts = e.split(/\s+/);
  if (parts.length === 6) parts.shift();
  if (parts.length !== 5) return 'unrecognised cron expression';
  const [mi, hr, dom, mon, dow] = parts;
  const bits = [];
  if (mi === '*' && hr === '*') bits.push('every minute');
  else if (/^\*\/\d+$/.test(mi) && hr === '*') bits.push(`every ${mi.split('/')[1]} minutes`);
  else if (/^\d+$/.test(mi) && hr === '*') bits.push(`at minute ${mi} of every hour`);
  else if (/^\d+$/.test(mi) && /^\d+$/.test(hr)) bits.push(`at ${String(hr).padStart(2, '0')}:${String(mi).padStart(2, '0')}`);
  else if (/^\d+$/.test(mi) && /^\d+-\d+$/.test(hr)) bits.push(`at minute ${mi} of hours ${hr}`);
  else if (/^\*\/\d+$/.test(mi) && /^\d+-\d+$/.test(hr)) bits.push(`every ${mi.split('/')[1]} minutes during hours ${hr}`);
  else if (/^\*\/\d+$/.test(mi) && /^\d+(,\d+)+$/.test(hr)) bits.push(`every ${mi.split('/')[1]} minutes during listed hours ${hr}`);
  else if (/^\*\/\d+$/.test(mi) && /^\d+$/.test(hr)) bits.push(`every ${mi.split('/')[1]} minutes during hour ${hr}`);
  else if (/^\d+$/.test(mi) && /\*\/\d+/.test(hr)) bits.push(`at minute ${mi} every ${hr.split('/')[1]} hours`);
  else bits.push(`${mi} ${hr}`);
  if (dow !== '*') {
    const days = expandField(dow, 0, 6, DOW).map((d) => DOW[d]);
    bits.push(`on ${days.join(', ')}`);
  } else if (dom !== '*') bits.push(`on day ${dom} of the month`);
  if (mon !== '*') bits.push(`in ${expandField(mon, 1, 12, MONTHS).map((m) => MONTHS[m - 1]).join(', ')}`);
  return bits.join(' ');
}

function nextRunsCron(expr, n) {
  let e = expr;
  if (MACROS[e]) e = MACROS[e];
  const parts = e.split(/\s+/);
  if (parts.length === 6) parts.shift();
  if (parts.length !== 5) return [];
  const mins = expandField(parts[0], 0, 59), hrs = expandField(parts[1], 0, 23);
  const doms = expandField(parts[2] === '*' ? '1-31' : parts[2], 1, 31, null);
  const mons = expandField(parts[3] === '*' ? '1-12' : parts[3], 1, 12, MONTHS);
  const dows = expandField(parts[4] === '*' ? '0-6' : parts[4], 0, 6, DOW);
  const out = [];
  const d = new Date();
  d.setSeconds(0, 0);
  d.setMinutes(d.getMinutes() + 1);
  for (let guard = 0; guard < 366 * 24 * 60 && out.length < n; guard++) {
    if (mins.includes(d.getMinutes()) && hrs.includes(d.getHours()) && doms.includes(d.getDate()) && mons.includes(d.getMonth() + 1) && dows.includes(d.getDay())) {
      out.push(new Date(d));
    }
    d.setMinutes(d.getMinutes() + 1);
  }
  return out;
}

let cron = null, systemd = null, error = null;
if (fromFmt === 'cron') {
  cron = input.trim();
  const conv = cronToSystemd(cron);
  if (conv.error) error = conv.error; else systemd = conv.systemd;
} else {
  systemd = input.trim();
  const conv = systemdToCron(systemd);
  if (conv.error) error = conv.error; else cron = conv.cron;
}
const english = cron ? describeCron(cron) : null;
const preview = cron ? nextRunsCron(cron, num(get(o, 'next'), 5)) : [];

if (flag(o, 'json')) {
  emit({ input, from: fromFmt, cron, systemd, english, error, next: preview.map((d) => d.toISOString()) });
  process.exit(error ? 1 : 0);
}

if (toFmt === 'cron') { if (cron) console.log(cron); else { console.error(error); process.exit(1); } process.exit(0); }
if (toFmt === 'systemd') { if (systemd) console.log(systemd); else { console.error(error); process.exit(1); } process.exit(0); }
if (toFmt === 'english') { if (english) console.log(english); else { console.error(error); process.exit(1); } process.exit(0); }

console.log(`cronconvert: ${input}`);
if (error) console.log(`conversion: ${error}`);
console.log('');
console.log(table([{ format: 'cron', value: cron || '(not expressible)' }, { format: 'systemd', value: systemd || '(not expressible)' }, { format: 'english', value: english || '-' }], ['format', 'value']));
if (preview.length) {
  console.log('\nnext runs:');
  console.log(table(preview.map((d, i) => ({ n: i + 1, when: d.toISOString().replace('T', ' ').slice(0, 19) + 'Z', weekday: DOW[d.getUTCDay()] })), ['n', 'when', 'weekday']));
}
process.exit(error ? 1 : 0);
