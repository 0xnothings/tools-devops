#!/usr/bin/env node
// dnspropagate.js — check one record across many public resolvers.
// Copyright (c) 2026 0xnothings
// @tool dnspropagate
// @desc Query a record type across public resolvers over UDP, report answer disagreement, per-resolver latency and an overall propagation verdict
// @usage node tools/dnspropagate.js example.com A --json
// @tags devops,dns,network
import { createSocket } from 'node:dgram';
import { randomBytes } from 'node:crypto';
import { args, get, num, flag, die, emit, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`dnspropagate — multi-resolver DNS consistency check

  node tools/dnspropagate.js <name> [type] [options]

  --type <T>        record type: A AAAA CNAME MX TXT NS SOA CAA SRV (default A)
  --resolvers <csv> override the built-in list
  --timeout <ms>    per-query timeout (default 4000)
  --json            machine-readable output
  --expect <value>  fail unless every resolver returns this value (comma list allowed)
  -h, --help        this text

  Sends a raw DNS query over UDP and decodes the answer (compression pointers
  handled). No dependencies, no system resolver involved.`);
  process.exit(0);
}

const name = o._[0];
if (!name) die('usage: node tools/dnspropagate.js <name> [type] [--json]');
const qtype = String(o.f.type || o._[1] || 'A').toUpperCase();
const timeout = num(get(o, 'timeout'), 4000);
const DEFAULT_RESOLVERS = [
  ['1.1.1.1', 'Cloudflare'], ['1.0.0.1', 'Cloudflare-2'],
  ['8.8.8.8', 'Google'], ['8.8.4.4', 'Google-2'],
  ['9.9.9.9', 'Quad9'], ['149.112.112.112', 'Quad9-2'],
  ['208.67.222.222', 'OpenDNS'], ['208.67.220.220', 'OpenDNS-2'],
  ['64.6.64.6', 'Verisign'], ['77.88.8.8', 'Yandex'],
  ['94.140.14.14', 'AdGuard'], ['76.76.2.0', 'ControlD'],
];
const resolvers = o.f.resolvers ? String(o.f.resolvers).split(',').map((s) => [s.trim(), 'custom']) : DEFAULT_RESOLVERS;

const TYPES = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33, CAA: 257 };
if (!TYPES[qtype]) die(`unsupported type ${qtype}; try ${Object.keys(TYPES).join(' ')}`);

function encodeName(n) {
  const parts = n.replace(/\.$/, '').split('.').filter(Boolean);
  const bufs = [];
  for (const p of parts) {
    const label = Buffer.from(p, 'ascii');
    bufs.push(Buffer.from([label.length]), label);
  }
  bufs.push(Buffer.from([0]));
  return Buffer.concat(bufs);
}

function buildQuery(id) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0100, 2); // RD
  header.writeUInt16BE(1, 4);
  const tail = Buffer.alloc(4);
  tail.writeUInt16BE(TYPES[qtype], 0);
  tail.writeUInt16BE(1, 2);
  return Buffer.concat([header, encodeName(name), tail]);
}

function readName(buf, off, depth = 0) {
  if (depth > 12) return { name: '<loop>', off };
  const labels = [];
  let jumped = false, endOff = off;
  let p = off;
  while (p < buf.length) {
    const len = buf[p];
    if (len === 0) { p++; if (!jumped) endOff = p; break; }
    if ((len & 0xc0) === 0xc0) {
      const ptr = ((len & 0x3f) << 8) | buf[p + 1];
      const sub = readName(buf, ptr, depth + 1);
      labels.push(sub.name);
      p += 2;
      if (!jumped) endOff = p;
      jumped = true;
      break;
    }
    labels.push(buf.slice(p + 1, p + 1 + len).toString('utf8'));
    p += 1 + len;
    if (!jumped) endOff = p;
  }
  return { name: labels.filter(Boolean).join('.'), off: endOff };
}

function decode(buf) {
  if (buf.length < 12) return { error: 'short response' };
  const flags = buf.readUInt16BE(2);
  const rcode = flags & 0x0f;
  const qd = buf.readUInt16BE(4), an = buf.readUInt16BE(6);
  let off = 12;
  for (let i = 0; i < qd; i++) { const r = readName(buf, off); off = r.off + 4; }
  const answers = [];
  for (let i = 0; i < an && off < buf.length; i++) {
    const r = readName(buf, off);
    off = r.off;
    const type = buf.readUInt16BE(off); off += 2;
    off += 2; // class
    const ttl = buf.readUInt32BE(off); off += 4;
    const rdlen = buf.readUInt16BE(off); off += 2;
    const rdata = buf.slice(off, off + rdlen); off += rdlen;
    let value = '';
    if (type === 1 && rdlen === 4) value = [...rdata].join('.');
    else if (type === 28 && rdlen === 16) value = [...rdata].reduce((acc, b, i) => acc + ((i % 2 === 0 ? '' : '') + b.toString(16).padStart(2, '0')) + (i % 2 === 1 && i !== 15 ? ':' : ''), '');
    else if (type === 5 || type === 2 || type === 12) value = readName(buf, off - rdlen).name;
    else if (type === 15) { const pref = rdata.readUInt16BE(0); value = `${pref} ${readName(buf, off - rdlen + 2).name}`; }
    else if (type === 16) { let s = '', p2 = 0; while (p2 < rdata.length) { const l = rdata[p2]; s += rdata.slice(p2 + 1, p2 + 1 + l).toString('utf8'); p2 += 1 + l; } value = `"${s}"`; }
    else if (type === 6) { const mname = readName(buf, off - rdlen).name; value = `${mname} (SOA)`; }
    else if (type === 257) { const fl = rdata[0]; const tagLen = rdata[1]; const tag = rdata.slice(2, 2 + tagLen).toString(); const val = rdata.slice(2 + tagLen).toString(); value = `${fl} ${tag}="${val}"`; }
    else value = rdata.toString('hex');
    answers.push({ name: r.name, type, ttl, value });
  }
  return { rcode, answers, truncated: !!(flags & 0x0200) };
}

function queryOne(resolver) {
  return new Promise((resolve) => {
    const sock = createSocket('udp4');
    const id = randomBytes(2).readUInt16BE(0);
    const started = Date.now();
    let done = false;
    const finish = (x) => { if (done) return; done = true; try { sock.close(); } catch {} resolve(x); };
    const timer = setTimeout(() => finish({ ok: false, error: 'timeout', ms: Date.now() - started }), timeout);
    sock.on('error', (e) => { clearTimeout(timer); finish({ ok: false, error: e.code || e.message, ms: Date.now() - started }); });
    sock.on('message', (msg) => {
      clearTimeout(timer);
      const decoded = decode(msg);
      finish({ ok: decoded.rcode === 0, rcode: decoded.rcode, answers: decoded.answers || [], truncated: decoded.truncated, ms: Date.now() - started });
    });
    try { sock.send(buildQuery(id), 53, resolver[0]); }
    catch (e) { clearTimeout(timer); finish({ ok: false, error: e.message, ms: Date.now() - started }); }
  });
}

const RCODE = { 0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED' };
const results = await Promise.all(resolvers.map(async ([ip, label]) => {
  const r = await queryOne([ip, label]);
  const values = (r.answers || []).filter((a) => a.type === TYPES[qtype] || (qtype === 'A' && a.type === 5)).map((a) => a.value);
  return { resolver: ip, provider: label, ok: r.ok, rcode: r.rcode !== undefined ? (RCODE[r.rcode] || String(r.rcode)) : null, ms: r.ms, values: [...new Set(values)].sort(), error: r.error || null, ttl: (r.answers || []).map((a) => a.ttl).sort((a, b) => a - b)[0] ?? null };
}));

const okResults = results.filter((r) => r.ok);
const valueSets = new Map();
for (const r of okResults) {
  const k = r.values.join('|') || '(no answer)';
  if (!valueSets.has(k)) valueSets.set(k, []);
  valueSets.get(k).push(r.resolver);
}
const expect = o.f.expect ? String(o.f.expect).split(',').map((s) => s.trim()).filter(Boolean) : null;
const agreed = valueSets.size <= 1 && okResults.length > 0;
const allResolve = okResults.length === resolvers.length;
const mismatched = expect ? okResults.filter((r) => !r.values.some((v) => expect.includes(v))) : [];
const latencies = okResults.map((r) => r.ms).sort((a, b) => a - b);
const p50 = latencies.length ? latencies[Math.floor(latencies.length / 2)] : null;
const failed = !agreed || mismatched.length > 0 || (expect && okResults.length !== resolvers.length);

if (flag(o, 'json')) {
  emit({
    name, type: qtype, resolversQueried: resolvers.length, responded: okResults.length,
    agreement: agreed, distinctAnswerSets: valueSets.size,
    answers: [...valueSets.entries()].map(([v, rs]) => ({ values: v.split('|'), resolvers: rs })),
    results, latency: { p50, min: latencies[0] ?? null, max: latencies[latencies.length - 1] ?? null },
    expect: expect || null, expectMismatch: mismatched.map((m) => m.resolver),
    verdict: failed ? 'INCONSISTENT' : 'CONSISTENT',
  });
  process.exit(0);
}

console.log(`dnspropagate: ${name} ${qtype}`);
console.log(`${okResults.length}/${resolvers.length} resolvers answered  agreement=${agreed ? 'yes' : 'NO'}  distinct answer sets=${valueSets.size}${p50 !== null ? `  p50=${p50}ms` : ''}`);
console.log('');
console.log(table(results.map((r) => ({ resolver: r.resolver, provider: r.provider, status: r.error ? `ERR ${r.error}` : r.rcode, ms: r.ms, ttl: r.ttl ?? '-', values: r.values.join(', ').slice(0, 48) || '-' })), ['resolver', 'provider', 'status', 'ms', 'ttl', 'values']));

if (valueSets.size > 1) {
  console.log('\ndisagreement:');
  for (const [v, rs] of valueSets) console.log(`  ${v === '(no answer)' ? '(empty)' : v}  <-  ${rs.join(', ')}`);
}
if (mismatched.length) {
  console.log('\nexpected value not seen at:');
  console.log(table(mismatched.map((m) => ({ resolver: m.resolver, got: m.values.join(',') || '(none)', expected: expect.join(',') })), ['resolver', 'got', 'expected']));
}
console.log(`\nverdict: ${failed ? 'INCONSISTENT — do not rely on this record yet' : 'CONSISTENT across all responding resolvers'}`);
process.exit(failed ? 1 : 0);
