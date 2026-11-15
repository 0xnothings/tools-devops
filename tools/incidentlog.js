#!/usr/bin/env node
// incidentlog.js — normalise incident logs into a timeline with MTTR/MTTD.
// Copyright (c) 2026 0xnothings
// @tool incidentlog
// @desc Parse incident logs into a normalised timeline, compute MTTD/MTTA/MTTR, and detect recurrence patterns by service and cause
// @usage node tools/incidentlog.js incidents.log --json
// @tags devops,incident,sre,postmortem
import { readFileSync, existsSync } from 'node:fs';
import { args, get, num, flag, die, emit, table, parseDuration } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`incidentlog — incident timeline and MTTR analytics

  node tools/incidentlog.js <file> [options]

  Accepts several shapes, auto-detected per line:
    2026-02-01T10:00Z DETECTED api 5xx spike
    2026-02-01 10:05 ACK api = alice
    2026-02-01T10:12Z MITIGATED api rolled back deploy 1234
    2026-02-01T10:30Z RESOLVED api

  --json         machine-readable output
  --mttr-only    print only the summary numbers
  --since <date> ignore events before this date
  --json-ndjson  emit one JSON object per incident
  -h, --help     this text

  Stages recognised: DETECTED/ALERT, ACK/ACKED, INVESTIGATING, MITIGATED, RESOLVED/CLOSED.
  A new incident starts whenever DETECTED appears for a service that has no open incident.`);
  process.exit(0);
}

const file = o._[0];
if (!file) die('usage: node tools/incidentlog.js <file> [--json]');
if (!existsSync(file)) die(`no such file: ${file}`);

const STAGES = [
  [/^(detected|alert(ed)?|alarm|triggered|fired)\b/i, 'detected'],
  [/^(ack(ed|nowledged)?|claimed|assigned|taken)\b/i, 'acked'],
  [/^(investigat(ing|ion)|diagnos)/i, 'investigating'],
  [/^(mitigated|mitigation|workaround|rolled\s*back|hotfix)/i, 'mitigated'],
  [/^(resolved|closed|recovered|restored|fixed|green)\b/i, 'resolved'],
  [/^(note|update)\b/i, 'note'],
];

const raw = readFileSync(file, 'utf8').split(/\r?\n/);
const events = [];
const unparsed = [];
const sinceArg = o.f.since ? Date.parse(String(o.f.since)) : null;

for (let i = 0; i < raw.length; i++) {
  const line = raw[i].trim();
  if (!line || line.startsWith('#') || line.startsWith('//')) continue;
  const tsMatch = line.match(/^\[?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:?\d{2})?)\]?\s*(.*)$/);
  if (!tsMatch) { unparsed.push({ line: i + 1, text: line.slice(0, 80) }); continue; }
  const when = Date.parse(tsMatch[1].replace(' ', 'T').replace(/(\d{2}:\d{2})$/, '$1:00'));
  if (!Number.isFinite(when)) { unparsed.push({ line: i + 1, text: line.slice(0, 80) }); continue; }
  const rest = tsMatch[2].trim();
  let stage = null, body = rest;
  for (const [re, s] of STAGES) { if (re.test(rest)) { stage = s; body = rest.replace(re, '').trim(); break; } }
  if (!stage) { stage = 'note'; }
  // service token: first bare word, or after a known separator
  const svcMatch = body.match(/^([A-Za-z0-9_.:-]+)/);
  const service = svcMatch ? svcMatch[1].replace(/:$/, '') : '(unscoped)';
  const detail = body.replace(/^[=\-:]\s*/, '').replace(/^[A-Za-z0-9_.:-]+\s*[=\-:]?\s*/, '').trim() || rest;
  let who = (body.match(/([A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+)/) || body.match(/(?:by|owner|assignee)[=:\s]+([A-Za-z0-9_.-]+)/i) || [])[1] || null;
  if (!who) {
    const rest = body.replace(/^[A-Za-z0-9_.:-]+\s*/, '').replace(/^[=\-:]\s*/, '').trim();
    if (/^[A-Za-z][A-Za-z0-9_.-]{1,30}$/.test(rest) && /^(acked|resolved|mitigated|detected|investigating|note)$/.test(stage)) who = rest;
  }
  if (sinceArg && when < sinceArg) continue;
  events.push({ when, iso: new Date(when).toISOString().replace(/\.\d+Z$/, 'Z'), stage, service, detail, who, line: i + 1 });
}
events.sort((a, b) => a.when - b.when);

// build incidents
const open = new Map();
const incidents = [];
for (const e of events) {
  if (e.stage === 'detected') {
    if (open.has(e.service)) {
      const cur = open.get(e.service);
      cur.notes.push({ when: e.iso, stage: 'redetected', detail: e.detail });
      continue;
    }
    const inc = { id: incidents.length + 1, service: e.service, detected: e.when, detectedISO: e.iso, acked: null, mitigated: null, resolved: null, events: [e], notes: [], causes: [], owners: new Set(e.who ? [e.who] : []) };
    open.set(e.service, inc);
    incidents.push(inc);
    continue;
  }
  let inc = open.get(e.service);
  if (!inc) {
    // orphan stage without detection: create an incident beginning here
    inc = { id: incidents.length + 1, service: e.service, detected: null, detectedISO: null, acked: null, mitigated: null, resolved: null, events: [], notes: [{ when: e.iso, stage: 'orphan', detail: `${e.stage} with no preceding detection` }], causes: [], owners: new Set(e.who ? [e.who] : []) };
    open.set(e.service, inc);
    incidents.push(inc);
  }
  inc.events.push(e);
  if (e.who) inc.owners.add(e.who);
  if (e.stage === 'acked' && !inc.acked) inc.acked = e.when;
  else if (e.stage === 'mitigated' && !inc.mitigated) inc.mitigated = e.when;
  else if (e.stage === 'resolved') { if (!inc.resolved) { inc.resolved = e.when; } if (open.get(e.service) === inc) open.delete(e.service); }
  else if (e.stage === 'note' || e.stage === 'investigating') inc.notes.push({ when: e.iso, stage: e.stage, detail: e.detail });
}

// cause extraction from the resolved/mitigated detail
const CAUSE_RE = /(deploy|release|rollback|config|migration|disk|cpu|memory|oom|network|dns|latency|timeout|tls|cert|expir|quota|dependency|third[- ]party|db|database|replica|lock|permission|auth|rate ?limit|dos|attack|hardware|power|deploy)/i;
for (const inc of incidents) {
  for (const e of inc.events) {
    const m = e.detail.match(CAUSE_RE);
    if (m) inc.causes.push(m[1].toLowerCase());
  }
  inc.causes = [...new Set(inc.causes)];
}

const d = (a, b) => (a && b ? b - a : null);
for (const inc of incidents) {
  inc.mttdMs = null; // cannot detect without an external signal time; reported as null unless a "detected" event is preceded by a note
  inc.mttaMs = d(inc.detected, inc.acked);
  inc.mttmMs = d(inc.detected, inc.mitigated);
  inc.mttrMs = d(inc.detected, inc.resolved);
}

const fmtDur = (ms) => {
  if (ms === null || ms === undefined) return '-';
  const s = Math.round(ms / 1000);
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), ss = s % 60;
  return [h ? `${h}h` : '', m ? `${m}m` : '', !h ? `${ss}s` : ''].filter(Boolean).join(' ');
};
const avg = (arr) => arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : null;
const pct = (arr, p) => { if (!arr.length) return null; const s = [...arr].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor(s.length * p))]; };

const resolved = incidents.filter((i) => i.mttrMs !== null && i.mttrMs >= 0);
const mttr = avg(resolved.map((i) => i.mttrMs));
const mtta = avg(incidents.map((i) => i.mttaMs).filter((x) => x !== null));
const mttm = avg(incidents.map((i) => i.mttmMs).filter((x) => x !== null));

// recurrence
const byService = new Map();
for (const i of incidents) { byService.set(i.service, (byService.get(i.service) || 0) + 1); }
const periodic = [];
const sorted = [...incidents].sort((a, b) => a.detected - b.detected);
for (let i = 1; i < sorted.length; i++) {
  if (sorted[i].service !== sorted[i - 1].service) continue;
  periodic.push({ service: sorted[i].service, gapHours: Math.round((sorted[i].detected - sorted[i - 1].detected) / 3600000), from: sorted[i - 1].detectedISO, to: sorted[i].detectedISO });
}
const causeCount = new Map();
for (const i of incidents) for (const c of i.causes) causeCount.set(c, (causeCount.get(c) || 0) + 1);

const repeatServices = [...byService.entries()].filter(([, n]) => n > 1).sort((a, b) => b[1] - a[1]);
const extra = [];

if (o.f['json-ndjson'] || flag(o, 'json-ndjson')) {
  for (const i of incidents) console.log(JSON.stringify({ id: i.id, service: i.service, detected: i.detectedISO, acked: i.acked ? new Date(i.acked).toISOString() : null, mitigated: i.mitigated ? new Date(i.mitigated).toISOString() : null, resolved: i.resolved ? new Date(i.resolved).toISOString() : null, mtta: fmtDur(i.mttaMs), mttr: fmtDur(i.mttrMs), causes: i.causes, owners: [...i.owners] }));
  process.exit(0);
}

const openNow = incidents.filter((i) => i.resolved === null);

if (flag(o, 'json')) {
  emit({
    file, events: events.length, incidents: incidents.length, unparsed,
    summary: { mttrMs: mttr, mttr: fmtDur(mttr), mtta: fmtDur(mtta), mttm: fmtDur(mttm), resolvedCount: resolved.length, openCount: openNow.length, p50Mttr: fmtDur(pct(resolved.map((i) => i.mttrMs), 0.5)), p95Mttr: fmtDur(pct(resolved.map((i) => i.mttrMs), 0.95)) },
    incidentsDetail: incidents.map((i) => ({ id: i.id, service: i.service, detected: i.detectedISO, acked: i.acked ? new Date(i.acked).toISOString() : null, mitigated: i.mitigated ? new Date(i.mitigated).toISOString() : null, resolved: i.resolved ? new Date(i.resolved).toISOString() : null, mtta: fmtDur(i.mttaMs), mttm: fmtDur(i.mttmMs), mttr: fmtDur(i.mttrMs), causes: i.causes, owners: [...i.owners], notes: i.notes })),
    recurrence: { repeatedServices: repeatServices.map(([s, n]) => ({ service: s, count: n })), gaps: periodic, topCauses: [...causeCount.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([c, n]) => ({ cause: c, count: n })) },
  });
  process.exit(openNow.length ? 1 : 0);
}

console.log(`incidentlog: ${file}`);
console.log(`events: ${events.length}  incidents: ${incidents.length}  open: ${openNow.length}${unparsed.length ? `  unparsed: ${unparsed.length}` : ''}`);
console.log(`MTTA: ${fmtDur(mtta)}   MTTM: ${fmtDur(mttm)}   MTTR: ${fmtDur(mttr)}  (p50 ${fmtDur(pct(resolved.map((i) => i.mttrMs), 0.5))}, p95 ${fmtDur(pct(resolved.map((i) => i.mttrMs), 0.95))})`);

console.log('');
console.log(table(incidents.map((i) => ({ id: i.id, service: i.service, detected: i.detectedISO, acked: i.acked ? fmtDur(i.mttaMs) : '-', mitigated: i.mitigated ? fmtDur(i.mttmMs) : '-', mttr: fmtDur(i.mttrMs), causes: i.causes.join(',') || '-', owners: [...i.owners].join(',') || '-' })), ['id', 'service', 'detected', 'acked', 'mitigated', 'mttr', 'causes', 'owners']));

if (repeatServices.length) {
  console.log('\nrecurrence:');
  console.log(table(repeatServices.map(([s, n]) => ({ service: s, incidents: n, verdict: n >= 3 ? 'CHRONIC — needs a permanent fix, not a restart' : 'repeat' })), ['service', 'incidents', 'verdict']));
}
if (periodic.length) {
  console.log('\ngaps between repeat incidents:');
  console.log(table(periodic.map((p) => ({ service: p.service, gap: `${p.gapHours}h`, from: p.from, to: p.to })), ['service', 'gap', 'from', 'to']));
}
const topCauses = [...causeCount.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
if (topCauses.length) {
  console.log('\ntop causes:');
  console.log(table(topCauses.map(([c, n]) => ({ cause: c, count: n })), ['cause', 'count']));
}
if (openNow.length) { console.log(`\nSTILL OPEN: ${openNow.map((i) => `#${i.id} ${i.service}`).join(', ')}`); }
process.exit(openNow.length ? 1 : 0);
