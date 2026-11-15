#!/usr/bin/env node
// uptimecalc.js — SLO budget and burn-rate calculator.
// Copyright (c) 2026 0xnothings
// @tool uptimecalc
// @desc Compute availability, error budget, remaining budget and burn rate from a list of incident durations and an SLO target
// @usage node tools/uptimecalc.js incidents.csv --slo 99.9 --window 30d --json
// @tags devops,sre,slo,oncall
import { readFileSync, existsSync } from 'node:fs';
import { args, get, num, flag, die, emit, table, parseDuration } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`uptimecalc — availability and error-budget maths

  node tools/uptimecalc.js [incidents.csv] [options]

  Incidents input (CSV or plain text, one per line):
    start,duration,end_user_impact_percent,name
    2026-02-01T10:00Z,45m,100,api outage
    2026-02-03T02:00Z,2h,25,degraded reads

  The third column is optional and defaults to 100 (fully down).
  Plain durations also work if the start is unknown:  "45m,100,api outage"

  --slo <pct>        SLO target (default 99.9)
  --window <dur>     measurement window (default 30d)
  --json             machine-readable output
  --burn-windows <csv>  burn-rate evaluation windows (default 1h,6h,1d,3d)
  -h, --help         this text

  Also reports the downtime budget in seconds and the per-window burn rate
  with the standard fast-burn (14.4x) and slow-burn (6x) alert thresholds.`);
  process.exit(0);
}

const slo = Number(get(o, 'slo', 99.9));
if (!(slo > 0 && slo < 100)) die('--slo must be between 0 and 100');
const winMs = parseDuration(String(get(o, 'window', '30d')));
if (!winMs) die('--window must look like 30d, 24h, 90m');
const file = o._[0];
let text = '';
if (file) { if (!existsSync(file)) die(`no such file: ${file}`); text = readFileSync(file, 'utf8'); }
else if (!process.stdin.isTTY) { text = readFileSync(0, 'utf8'); }
if (!text.trim()) die('no incidents given: pass a file or pipe lines in');

const rows = [];
const problems = [];
const raw = text.split(/\r?\n/);
const createdMatch = text.match(/^[#;\s]*created[_-]?at\s*[=:]\s*(\S+)/im);
const createdAt = createdMatch ? Date.parse(createdMatch[1].replace(' ', 'T')) : null;
for (let i = 0; i < raw.length; i++) {
  const line = raw[i].trim();
  if (!line || line.startsWith('#') || /^start\s*,/.test(line)) continue;
  const cells = line.split(',').map((c) => c.trim());
  let start = null, dur = null, impact = 100, label = '';
  if (/^\d{4}-\d{2}-\d{2}/.test(cells[0])) {
    start = Date.parse(cells[0].replace(' ', 'T'));
    dur = parseDuration(cells[1]);
    impact = cells[2] ? Number(cells[2]) : 100;
    label = cells[3] || '';
    if (!Number.isFinite(start)) problems.push({ line: i + 1, issue: `unparsable timestamp "${cells[0]}"` });
  } else {
    dur = parseDuration(cells[0]);
    impact = cells[1] ? Number(cells[1]) : 100;
    label = cells[2] || '';
  }
  if (!dur) { problems.push({ line: i + 1, issue: `unparsable duration "${cells[0] || cells[1]}"` }); continue; }
  if (!(impact > 0 && impact <= 100)) { problems.push({ line: i + 1, issue: `impact ${impact} outside 1-100, clamped` }); }
  const eff = Math.min(100, Math.max(1, Number.isFinite(impact) ? impact : 100));
  rows.push({ startMs: start, start: start ? new Date(start).toISOString() : null, durMs: dur, impact: eff, label, line: i + 1, lostMs: dur * (eff / 100) });
}

// the window is the winMs period ENDING at "now" (or at an explicit # created_at marker)
const windowEnd = Number.isFinite(createdAt) ? createdAt : Date.now();
const windowStart = windowEnd - winMs;
const scoped = rows.filter((r) => r.startMs === null || (r.startMs >= windowStart && r.startMs <= windowEnd));
const totalLostMs = scoped.reduce((a, r) => a + r.lostMs, 0);
const availability = ((winMs - totalLostMs) / winMs) * 100;
const budgetMs = winMs * (1 - slo / 100);
const consumedMs = totalLostMs;
const remainingMs = budgetMs - consumedMs;
const consumedPct = budgetMs ? (consumedMs / budgetMs) * 100 : 0;

const fmtDur = (ms) => {
  if (ms < 0) return `-${fmtDur(-ms)}`;
  const s = Math.floor(ms / 1000);
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60), ss = s % 60;
  return [d ? `${d}d` : '', h ? `${h}h` : '', m ? `${m}m` : '', !d && !h ? `${ss}s` : ''].filter(Boolean).join(' ') || '0s';
};

const burnWindows = String(get(o, 'burn-windows', '1h,6h,1d,3d')).split(',').map((s) => ({ label: s.trim(), ms: parseDuration(s.trim()) })).filter((x) => x.ms);
const burn = burnWindows.map((b) => {
  const wStart = windowEnd - b.ms;
  const lost = rows.filter((r) => r.startMs !== null && r.startMs >= wStart && r.startMs <= windowEnd).reduce((a, r) => a + r.lostMs, 0);
  const allowed = b.ms * (1 - slo / 100);
  const rate = allowed > 0 ? lost / allowed : 0;
  const byMs = allowed > 0 ? (b.ms * (1 - slo / 100)) / (1 - slo / 100) : 0;
  // projected time to exhaust the full window budget at this rate
  const ratePerMs = lost / b.ms;
  const exhaustMs = ratePerMs > 0 ? remainingMs / ratePerMs : null;
  return { window: b.label, lost, lostHuman: fmtDur(lost), allowedHuman: fmtDur(allowed), burnRate: rate, estExhaustion: exhaustMs && exhaustMs > 0 ? fmtDur(exhaustMs) : (ratePerMs > 0 ? 'already exhausted' : 'never') };
});

const incidents = rows.filter((r) => r.lostMs > 0).sort((a, b) => (b.start || '').localeCompare(a.start || ''));

if (flag(o, 'json')) {
  emit({
    slo, window: String(get(o, 'window', '30d')),
    incidents: incidents.map((r) => ({ start: r.start, durationMs: r.durMs, impactPct: r.impact, label: r.label, lostMs: r.lostMs, lostHuman: fmtDur(r.lostMs) })),
    totalDowntimeMs: totalLostMs, totalDowntime: fmtDur(totalLostMs),
    availability: Number(availability.toFixed(5)),
    budgetMs, budget: fmtDur(budgetMs), consumedMs, consumed: fmtDur(consumedMs), consumedPct: Number(consumedPct.toFixed(2)),
    remainingMs, remaining: fmtDur(remainingMs),
    breached: consumedMs > budgetMs,
    burn: burn.map((b) => ({ window: b.window, burnRate: Number(b.burnRate.toFixed(3)), projectedExhaustion: b.estExhaustion })),
    parseIssues: problems,
  });
  process.exit(consumedMs > budgetMs ? 1 : 0);
}

console.log(`uptimecalc: SLO ${slo}% over ${get(o, 'window', '30d')}`);
console.log(`incidents in window: ${incidents.length}  total downtime: ${fmtDur(totalLostMs)}`);
console.log(`availability: ${availability.toFixed(4)}%  (SLO ${slo}% → ${availability >= slo ? 'MEETING' : 'BREACHING'})`);
console.log(`budget: ${fmtDur(budgetMs)}  consumed: ${fmtDur(consumedMs)} (${consumedPct.toFixed(1)}%)  remaining: ${fmtDur(remainingMs)}`);
if (problems.length) console.log(`parse issues: ${problems.length} (see --json)`);

if (incidents.length) {
  console.log('');
  console.log(table(incidents.map((r) => ({ start: r.start || '(unknown)', duration: fmtDur(r.durMs), impact: `${r.impact}%`, lost: fmtDur(r.lostMs), label: r.label || '-', line: r.line })), ['start', 'duration', 'impact', 'lost', 'label', 'line']));
}
console.log('\nburn rate:');
console.log(table(burn.map((b) => ({ window: b.window, lost: b.lostHuman, allowed: b.allowedHuman, burn: b.burnRate.toFixed(2) + 'x', severity: b.burnRate >= 14.4 ? 'FAST BURN (page)' : b.burnRate >= 6 ? 'SLOW BURN (ticket)' : b.burnRate >= 1 ? 'burning' : 'ok', exhausted_in: b.estExhaustion })), ['window', 'lost', 'allowed', 'burn', 'severity', 'exhausted_in']));

const breach = consumedMs > budgetMs;
console.log(`\nverdict: ${breach ? `BUDGET EXHAUSTED — ${fmtDur(consumedMs - budgetMs)} over. Freeze non-critical releases.` : `${fmtDur(remainingMs)} of budget left; ${burn.some((b) => b.burnRate >= 14.4) ? 'a fast-burn window is active' : 'no fast burn detected'}`}`);
process.exit(breach ? 1 : 0);
