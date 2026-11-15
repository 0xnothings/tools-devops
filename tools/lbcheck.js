#!/usr/bin/env node
// lbcheck.js — probe a set of load-balancer upstreams for health and consistency.
// Copyright (c) 2026 0xnothings
// @tool lbcheck
// @desc Probe upstream backends over HTTP(S), report status/serving state, pairwise response consistency and retry-aware flapping detection
// @usage node tools/lbcheck.js upstreams.txt --path /healthz --json
// @tags devops,loadbalancer,healthcheck
import { readFileSync, existsSync } from 'node:fs';
import { request } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { createHash } from 'node:crypto';
import { args, get, num, flag, die, emit, table, sleep } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`lbcheck — load-balancer backend prober

  node tools/lbcheck.js <upstreams.txt|"host:port host:port"> [options]

  Each line: host[:port][/path]  or a full URL. Comments with # are skipped.

  --path <p>        health path when the line does not specify one (default /healthz)
  --header <h>      extra header, repeatable as "K: V" quoted, or comma list
  --timeout <ms>    per-request timeout (default 5000)
  --retries <n>     retries per upstream before calling it down (default 1)
  --attempts <n>    probe rounds to detect flapping (default 1)
  --expect <code>   required status code (default 200)
  --json            machine-readable output
  -h, --help        this text

  Reports: per-upstream status, latency, body hash (for consistency comparison),
  flapping across rounds, and a verdict on whether the pool is uniform.`);
  process.exit(0);
}

const src = o._[0];
if (!src) die('usage: node tools/lbcheck.js <upstreams.txt|"host:port"> [--json]');
let text = existsSync(src) ? readFileSync(src, 'utf8') : src;
const lines = text.split(/\r?\n/).map((s) => s.trim()).filter((s) => s && !s.startsWith('#'));
const pathArg = String(get(o, 'path', '/healthz'));
const timeout = num(get(o, 'timeout'), 5000);
const retries = num(get(o, 'retries'), 1);
const rounds = Math.max(1, num(get(o, 'attempts'), 1));
const expect = num(get(o, 'expect'), 200);
const headerArg = o.f.header ? String(o.f.header).split(',').map((s) => s.trim()) : [];
const headers = { 'user-agent': 'lbcheck/1.0', accept: '*/*' };
for (const h of headerArg) { const i = h.indexOf(':'); if (i > 0) headers[h.slice(0, i).trim().toLowerCase()] = h.slice(i + 1).trim(); }

function parseTarget(line) {
  let url;
  if (/^https?:\/\//.test(line)) url = line;
  else {
    const [hostpart, ...rest] = line.split('/');
    const p = rest.length ? '/' + rest.join('/') : pathArg;
    url = `http://${hostpart}${p.startsWith('/') ? p : '/' + p}`;
  }
  try { const u = new URL(url); return { url, host: u.hostname, port: Number(u.port || (u.protocol === 'https:' ? 443 : 80)), scheme: u.protocol.replace(':', ''), path: u.pathname + u.search }; }
  catch { return { url, error: 'unparseable' }; }
}

function probeOne(t) {
  return new Promise((resolve) => {
    const started = Date.now();
    const mod = t.scheme === 'https' ? httpsRequest : request;
    let settled = false;
    const done = (x) => { if (!settled) { settled = true; resolve(x); } };
    let req;
    try {
      req = mod({ host: t.host, port: t.port, path: t.path, method: 'GET', headers, timeout, servername: t.scheme === 'https' ? t.host : undefined, rejectUnauthorized: false });
    } catch (e) { return done({ ok: false, error: e.message, ms: Date.now() - started }); }
    req.on('timeout', () => { req.destroy(); done({ ok: false, error: 'timeout', ms: Date.now() - started }); });
    req.on('error', (e) => done({ ok: false, error: e.code || e.message, ms: Date.now() - started }));
    req.on('response', (res) => {
      const chunks = [];
      res.on('data', (c) => { if (chunks.reduce((a, b) => a + b.length, 0) < 65536) chunks.push(c); });
      res.on('end', () => {
        const body = Buffer.concat(chunks);
        done({
          ok: true, status: res.statusCode, ms: Date.now() - started,
          bytes: body.length,
          hash: createHash('sha256').update(body).digest('hex').slice(0, 16),
          server: res.headers.server || null,
          contentType: res.headers['content-type'] || null,
          bodyHead: body.toString('utf8').replace(/\s+/g, ' ').slice(0, 100),
        });
      });
      res.on('error', (e) => done({ ok: false, error: e.message, ms: Date.now() - started }));
    });
    req.end();
  });
}

async function probeWithRetry(t) {
  const attempts = [];
  for (let a = 0; a <= retries; a++) {
    const r = await probeOne(t);
    attempts.push(r);
    const good = r.ok && r.status === expect;
    if (good || a === retries) return { ...r, attempts: attempts.length, recovered: a > 0 && good, history: attempts.map((x) => (x.ok ? x.status : x.error)) };
    await sleep(150 * (a + 1));
  }
}

const targets = lines.map(parseTarget);
const goodTargets = targets.filter((t) => !t.error);
if (!goodTargets.length) die('no parseable upstreams');

const results = [];
for (const t of goodTargets) {
  const roundsData = [];
  for (let r = 0; r < rounds; r++) {
    roundsData.push(await probeWithRetry(t));
    if (r < rounds - 1) await sleep(200);
  }
  const statuses = roundsData.map((x) => (x.ok ? x.status : x.error));
  const unique = [...new Set(statuses.map(String))];
  const hashSet = [...new Set(roundsData.filter((x) => x.ok).map((x) => x.hash))];
  const latencies = roundsData.filter((x) => x.ok).map((x) => x.ms).sort((a, b) => a - b);
  results.push({
    target: `${t.host}:${t.port}${t.path}`,
    url: t.url,
    rounds: roundsData.map((x) => ({ status: x.ok ? x.status : null, error: x.error || null, ms: x.ms, hash: x.hash || null, bytes: x.bytes || 0, bodyHead: x.bodyHead || null, attempts: x.attempts, recovered: !!x.recovered })),
    statuses, flapping: unique.length > 1,
    healthy: roundsData.every((x) => x.ok && x.status === expect),
    serving: roundsData.some((x) => x.ok && x.status === expect),
    latency: { min: latencies[0] ?? null, p50: latencies.length ? latencies[Math.floor(latencies.length / 2)] : null, max: latencies[latencies.length - 1] ?? null },
    bodyHashes: hashSet,
    bodyConsistent: hashSet.length <= 1,
    server: roundsData.find((x) => x.ok)?.server || null,
    contentType: roundsData.find((x) => x.ok)?.contentType || null,
    bodyHead: roundsData.find((x) => x.ok)?.bodyHead || null,
    recoveredAfterRetry: roundsData.some((x) => x.recovered),
  });
}

const healthy = results.filter((r) => r.healthy);
const serving = results.filter((r) => r.serving);
const down = results.filter((r) => !r.serving);
const flapping = results.filter((r) => r.flapping);
const inconsistentBodies = results.filter((r) => r.serving && !r.bodyConsistent);
const allStatuses = [...new Set(results.filter((r) => r.serving).map((r) => r.rounds.find((x) => x.status)?.status))];
const allHashes = [...new Set(results.filter((r) => r.serving).flatMap((r) => r.bodyHashes))];

const findings = [];
if (down.length) findings.push({ severity: 'CRITICAL', rule: 'backend-down', message: `${down.length}/${results.length} upstream(s) not serving: ${down.map((d) => d.target).join(', ')}` });
if (flapping.length) findings.push({ severity: 'HIGH', rule: 'flapping', message: `${flapping.length} upstream(s) changed status between rounds — the health check is borderline or the backend is crash-looping` });
if (inconsistentBodies.length) findings.push({ severity: 'HIGH', rule: 'inconsistent-body', message: `${inconsistentBodies.length} upstream(s) returned different bodies between rounds — one replica is behind a deploy or has different config` });
if (allHashes.length > 1 && !inconsistentBodies.length) findings.push({ severity: 'MEDIUM', rule: 'pool-divergence', message: `the pool returns ${allHashes.length} distinct body hashes — replicas are not identical (rollout in progress?)` });
if (allStatuses.length > 1) findings.push({ severity: 'MEDIUM', rule: 'status-divergence', message: `upstreams disagree on status: ${allStatuses.join(', ')}` });
if (results.some((r) => r.recoveredAfterRetry)) findings.push({ severity: 'LOW', rule: 'retry-recovered', message: 'at least one upstream only answered after a retry — the pool is at capacity or the network is lossy' });
const latencies = results.filter((r) => r.serving).map((r) => r.latency.p50).filter((x) => x !== null);
if (latencies.length > 1) {
  const min = Math.min(...latencies), max = Math.max(...latencies);
  if (max > min * 4 && max - min > 50) findings.push({ severity: 'MEDIUM', rule: 'latency-skew', message: `p50 latency varies ${min}ms..${max}ms across upstreams — one replica is hot or far away` });
}
const noHealthcheckPath = results.filter((r) => r.serving && /<html/i.test(r.bodyHead || ''));
if (noHealthcheckPath.length) findings.push({ severity: 'LOW', rule: 'serving-html', message: `${noHealthcheckPath.length} upstream(s) returned an HTML page on the health path — you are probing the app, not a health endpoint` });

const verdict = down.length ? 'DEGRADED' : findings.length ? 'INCONSISTENT' : 'HEALTHY';

if (flag(o, 'json')) {
  emit({ upstreams: results.length, healthy: healthy.length, serving: serving.length, verdict, results, poolConsistency: { distinctStatuses: allStatuses, distinctBodyHashes: allHashes.length, uniform: allStatuses.length === 1 && allHashes.length === 1 }, findings });
  process.exit(down.length ? 2 : findings.length ? 1 : 0);
}

console.log(`lbcheck: ${results.length} upstream(s), ${rounds} round(s), expect ${expect}`);
console.log(`healthy: ${healthy.length}/${results.length}  serving: ${serving.length}  verdict: ${verdict}`);
console.log('');
console.log(table(results.map((r) => ({
  upstream: r.target,
  status: r.statuses.join('/'),
  healthy: r.healthy ? 'yes' : r.serving ? 'partial' : 'NO',
  p50: r.latency.p50 !== null ? `${r.latency.p50}ms` : '-',
  bytes: r.rounds[0]?.bytes ?? 0,
  hash: r.bodyHashes[0] || '-',
  server: (r.server || '-').slice(0, 18),
})), ['upstream', 'status', 'healthy', 'p50', 'bytes', 'hash', 'server']));

if (results.some((r) => r.rounds[0]?.bodyHead)) {
  console.log('\nresponse bodies:');
  for (const r of results) console.log(`  ${r.target.padEnd(28)} ${(r.rounds.find((x) => x.bodyHead)?.bodyHead || '-').slice(0, 70)}`);
}
if (findings.length) {
  console.log('\nfindings:');
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  console.log(table(findings.sort((a, b) => order[a.severity] - order[b.severity]).map((f) => ({ severity: f.severity, rule: f.rule, detail: f.message })), ['severity', 'rule', 'detail']));
} else console.log('\npool is uniform and healthy');
process.exit(down.length ? 2 : findings.length ? 1 : 0);
