// healthcheck.js — poll an HTTP health endpoint until it is healthy.
// Copyright (c) 2026 0xnothings
// @tool healthcheck
// @desc Poll a URL until it returns expected status/body, with interval, retries and total-time budget
// @usage node tools/healthcheck.js http://localhost:3000/healthz --expect 200 --retries 30 --json
// @tags devops,monitoring,ci
import { args, get, num, flag, die } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`healthcheck — wait for an endpoint to become healthy

  node tools/healthcheck.js <url> [options]

  --expect <codes>     acceptable status codes (default: 200,204)
  --body <regex>       require the body to match this regex
  --interval <ms>      poll interval (default: 1000)
  --retries <n>        max attempts (default: 30)
  --timeout <ms>       per-request timeout (default: 5000)
  --method <m>         GET (default) | HEAD | POST
  --json               machine-readable output
  -h, --help           this text

  exit 0 healthy, exit 1 exhausted retries`);
  process.exit(0);
}

const url = o._[0];
if (!url) die('usage: node tools/healthcheck.js <url> [--expect 200] [--retries 30]');
const expect = new Set(String(get(o, 'expect', '200,204')).split(',').map((s) => Number(s.trim())));
const bodyRe = o.f.body ? new RegExp(String(get(o, 'body'))) : null;
const interval = num(get(o, 'interval'), 1000);
const retries = num(get(o, 'retries'), 30);
const timeout = num(get(o, 'timeout'), 5000);
const method = String(get(o, 'method', 'GET')).toUpperCase();

const attempts = [];
const t0 = Date.now();
let healthy = false;
for (let i = 1; i <= retries; i++) {
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), timeout);
  const tick = Date.now();
  let rec;
  try {
    const res = await fetch(url, { method, signal: ctl.signal, headers: { 'user-agent': '0xnothings-healthcheck/1.0' } });
    const body = method === 'HEAD' ? '' : await res.text().catch(() => '');
    const okStatus = expect.has(res.status);
    const okBody = bodyRe ? bodyRe.test(body) : true;
    rec = { attempt: i, status: res.status, ms: Date.now() - tick, bodyOk: okBody, healthy: okStatus && okBody, note: okStatus ? (okBody ? 'ok' : 'body mismatch') : 'unexpected status' };
  } catch (e) {
    rec = { attempt: i, status: 'ERR', ms: Date.now() - tick, bodyOk: false, healthy: false, note: e.name === 'AbortError' ? 'timeout' : String(e.cause?.code || e.message) };
  } finally { clearTimeout(t); }
  attempts.push(rec);
  if (!flag(o, 'json')) process.stdout.write(`[${String(i).padStart(3)}] ${String(rec.status).padEnd(4)} ${String(rec.ms).padStart(5)}ms  ${rec.note}\n`);
  if (rec.healthy) { healthy = true; break; }
  if (i < retries) await new Promise((r) => setTimeout(r, interval));
}

const totalMs = Date.now() - t0;
if (flag(o, 'json')) console.log(JSON.stringify({ url, healthy, attempts: attempts.length, total_ms: totalMs, history: attempts }, null, 2));
else console.log(healthy ? `\nhealthy after ${attempts.length} attempt(s) in ${totalMs}ms` : `\nFAILED after ${attempts.length} attempt(s) in ${totalMs}ms`);
process.exit(healthy ? 0 : 1);
