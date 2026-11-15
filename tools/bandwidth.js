#!/usr/bin/env node
// bandwidth.js — turn interface counters into rates, totals and error deltas.
// Copyright (c) 2026 0xnothings
// @tool bandwidth
// @desc Parse ifconfig / ip -s / vnstat / /proc/net/dev counters, compute throughput rates from two samples, and surface drops and errors
// @usage node tools/bandwidth.js sample1.txt sample2.txt --json
// @tags devops,network,metrics
import { readFileSync, existsSync } from 'node:fs';
import { args, get, num, flag, die, emit, table, parseDuration } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`bandwidth — interface counter analyser

  node tools/bandwidth.js <sampleA> [sampleB] [options]

  Samples are any of: ifconfig -a, ip -s link, /proc/net/dev, or vnstat output.
  With two samples the tool computes per-interface rates from the wall-clock delta.

  --elapsed <dur>   seconds between samples when it is not embedded ("30s", "5m")
  --bytes           print raw byte counters instead of rates
  --json            machine-readable output
  -h, --help        this text

  Reports for each interface: rx/tx totals, rates, errors, drops and a
  per-interface health verdict.`);
  process.exit(0);
}

const paths = o._.filter((p) => !/^--/.test(p));
if (!paths.length) die('usage: node tools/bandwidth.js <sampleA> [sampleB] [--elapsed 30s] [--json]');

const IFACE_LINE = /^([A-Za-z0-9_.:@-]+)[:\s]/;

function parseCounter(line, style) {
  const nums = (line.match(/\d+/g) || []).map(Number);
  if (style === 'proc') {
    // eth0: bytes packets errs drop fifo frame compressed multicast | bytes packets errs drop fifo colls carrier compressed
    if (nums.length < 16) return null;
    return { rx: { bytes: nums[0], packets: nums[1], errs: nums[2], drop: nums[3] }, tx: { bytes: nums[8], packets: nums[9], errs: nums[10], drop: nums[11] } };
  }
  if (style === 'ip') {
    // "RX: bytes packets errors dropped overrun mcast"
    if (nums.length < 4) return null;
    return { rx: { bytes: nums[0], packets: nums[1], errs: nums[2], drop: nums[3] }, tx: { bytes: nums[0], packets: nums[1], errs: nums[2], drop: nums[3] } };
  }
  // ifconfig: "RX packets 123 errors 0 dropped 0 overruns 0 frame 0" / "RX bytes:1 TB (1,099,511,627,776 B) TX bytes:..."
  const pairs = {};
  const re = /([A-Za-z]+)[:\s]+([\d,]+)/g;
  let m;
  while ((m = re.exec(line))) pairs[m[1].toLowerCase()] = Number(m[2].replace(/,/g, ''));
  if (pairs.bytes !== undefined) return { rx: { bytes: pairs.bytes, packets: pairs.packets || 0, errs: pairs.errors || 0, drop: pairs.dropped || 0 }, tx: { bytes: pairs.txbytes || 0, packets: pairs.txpackets || 0, errs: pairs.txerrors || 0, drop: pairs.txdropped || 0 } };
  return null;
}

function parseFile(p) {
  if (!existsSync(p)) die(`no such file: ${p}`);
  const text = readFileSync(p, 'utf8');
  const out = {};
  const meta = { timestamp: null, elapsedHint: null };
  const ts = text.match(/(\d{4}-\d{2}-\d{2}[T ][\d:.]+)/);
  if (ts) meta.timestamp = ts[1];
  const el = text.match(/elapsed[:\s]+([\d.]+)\s*(s|sec|seconds|m|min)?/i);
  if (el) meta.elapsedHint = parseDuration(`${el[1]}${el[2] || 's'}`);

  const raw = text.split(/\r?\n/);
  let curIface = null;
  const blank = () => ({ rx: { bytes: 0, packets: 0, errs: 0, drop: 0 }, tx: { bytes: 0, packets: 0, errs: 0, drop: 0 } });

  for (const line of raw) {
    if (!line.trim()) continue;
    if (/^\s*Inter-|^\s*face\b/.test(line)) continue;

    // /proc/net/dev: "  eth0: 1234 12 0 0 ... 5678 34 0 0 ..."
    const proc = line.match(/^\s*([A-Za-z0-9_.:@-]+):\s*((?:\d+\s*){16})\s*$/);
    if (proc) {
      const n = proc[2].trim().split(/\s+/).map(Number);
      out[proc[1]] = { rx: { bytes: n[0], packets: n[1], errs: n[2], drop: n[3] }, tx: { bytes: n[8], packets: n[9], errs: n[10], drop: n[11] } };
      curIface = proc[1];
      continue;
    }

    // ip -s link: "2: eth0: <BROADCAST,...>" then indented RX:/TX: counter lines
    const ipHead = line.match(/^\d+:\s+([^:@\s]+)[:@]/);
    if (ipHead) { curIface = ipHead[1]; if (!out[curIface]) out[curIface] = blank(); continue; }
    const ipCounters = line.match(/^\s+(RX|TX):\s+((?:\d+\s*){2,})/);
    if (ipCounters && curIface) {
      const n = ipCounters[2].trim().split(/\s+/).map(Number);
      const side = ipCounters[1].toLowerCase();
      out[curIface][side] = { bytes: n[0] || 0, packets: n[1] || 0, errs: n[2] || 0, drop: n[3] || 0 };
      continue;
    }

    // ifconfig: interface header at column 0
    const head = line.match(/^([A-Za-z0-9_.:@-]+):\s/);
    if (head && !/^\s/.test(line)) { curIface = head[1]; if (!out[curIface]) out[curIface] = blank(); continue; }

    if (!curIface) continue;
    const side = /^\s*TX\b/.test(line) ? 'tx' : /^\s*RX\b/.test(line) ? 'rx' : null;
    if (!side) {
      // continuation line: "RX packets 10 bytes 200 (...)": handled below; anything else ignored
      const pk = line.match(/(RX|TX)?\s*packets[:\s]+(\d+)/);
      if (pk && /^\s*(packets|RX|TX)/.test(line)) { /* fallthrough */ } else continue;
    }
    const sideName = side || (/TX\s+packets/i.test(line) ? 'tx' : 'rx');
    const b = line.match(/(?:^|\s)bytes[:\s]+(\d+)/);
    const pk = line.match(/packets[:\s]+(\d+)/);
    const er = line.match(/errors[:\s]+(\d+)/);
    const dr = line.match(/dropped[:\s]+(\d+)/);
    if (b) out[curIface][sideName].bytes = Number(b[1]);
    if (pk) out[curIface][sideName].packets = Number(pk[1]);
    if (er) out[curIface][sideName].errs = Number(er[1]);
    if (dr) out[curIface][sideName].drop = Number(dr[1]);
  }
  return { ifaces: out, meta };
}

const A = parseFile(paths[0]);
const B = paths[1] ? parseFile(paths[1]) : null;

let elapsed = num(get(o, 'elapsed'), 0);
if (!elapsed && B && A.meta.timestamp && B.meta.timestamp) {
  const t0 = Date.parse(A.meta.timestamp.replace(' ', 'T'));
  const t1 = Date.parse(B.meta.timestamp.replace(' ', 'T'));
  if (Number.isFinite(t0) && Number.isFinite(t1) && t1 > t0) elapsed = (t1 - t0) / 1000;
}
if (!elapsed && B && A.meta.elapsedHint && B.meta.elapsedHint) elapsed = (B.meta.elapsedHint - A.meta.elapsedHint) / 1000;
if (!elapsed) elapsed = 0;

const bps = (n) => {
  const u = ['bps', 'Kbps', 'Mbps', 'Gbps'];
  let i = 0, v = n * 8;
  while (v >= 1000 && i < u.length - 1) { v /= 1000; i++; }
  return `${v >= 100 ? Math.round(v) : v.toFixed(2)} ${u[i]}`;
};

const names = [...new Set([...Object.keys(A.ifaces), ...(B ? Object.keys(B.ifaces) : [])])].sort();
const rows = [];
const findings = [];
for (const n of names) {
  const a = A.ifaces[n], b = B ? B.ifaces[n] : null;
  if (!a) continue;
  const rx = b?.rx || a.rx, tx = b?.tx || a.tx;
  const dRx = b ? Math.max(0, b.rx.bytes - a.rx.bytes) : 0;
  const dTx = b ? Math.max(0, b.tx.bytes - a.tx.bytes) : 0;
  const dRxE = b ? Math.max(0, b.rx.errs - a.rx.errs) : 0;
  const dTxE = b ? Math.max(0, b.tx.errs - a.tx.errs) : 0;
  const dRxD = b ? Math.max(0, b.rx.drop - a.rx.drop) : 0;
  const dTxD = b ? Math.max(0, b.tx.drop - a.tx.drop) : 0;
  const rxBps = elapsed ? (dRx / elapsed) : 0;
  const txBps = elapsed ? (dTx / elapsed) : 0;

  if (tx.errs > 0) findings.push({ iface: n, severity: tx.errs > 100 ? 'HIGH' : 'MEDIUM', rule: 'tx-errors', message: `${tx.errs} TX errors (${dTxE} new) — usually a duplex mismatch or a bad cable` });
  if (rx.errs > 0) findings.push({ iface: n, severity: rx.errs > 100 ? 'HIGH' : 'MEDIUM', rule: 'rx-errors', message: `${rx.errs} RX errors (${dRxE} new)` });
  if (rx.drop > 0) findings.push({ iface: n, severity: rx.drop > 1000 ? 'HIGH' : 'LOW', rule: 'rx-drops', message: `${rx.drop} RX drops (${dRxD} new) — the kernel ring buffer is too small or the host is CPU-bound` });
  if (tx.drop > 0) findings.push({ iface: n, severity: 'LOW', rule: 'tx-drops', message: `${tx.drop} TX drops (${dTxD} new)` });
  if (b && b.rx.bytes < a.rx.bytes) findings.push({ iface: n, severity: 'MEDIUM', rule: 'counter-reset', message: 'counter went backwards — the interface was reset or the sample order is wrong' });
  if (b && elapsed && elapsed > 3600 && (rxBps + txBps) > 0) findings.push({ iface: n, severity: 'LOW', rule: 'sample-gap', message: `samples are ${Math.round(elapsed)}s apart; rates are averages, not peaks` });

  rows.push({
    iface: n,
    rxBytes: rx.bytes, txBytes: tx.bytes,
    rxHuman: `${(rx.bytes / 1e9).toFixed(2)} GB`, txHuman: `${(tx.bytes / 1e9).toFixed(2)} GB`,
    deltaRx: dRx, deltaTx: dTx, rxBps, txBps,
    rxRate: elapsed ? bps(rxBps) : '-', txRate: elapsed ? bps(txBps) : '-',
    rxErr: rx.errs, txErr: tx.errs, rxDrop: rx.drop, txDrop: tx.drop,
    newErrors: dRxE + dTxE, newDrops: dRxD + dTxD,
  });
}

if (flag(o, 'json')) {
  emit({
    samples: paths, elapsedSeconds: elapsed || null,
    interfaces: rows.map((r) => ({ name: r.iface, rxBytes: r.rxBytes, txBytes: r.txBytes, rxBps: Math.round(r.rxBps), txBps: Math.round(r.txBps), rxErr: r.rxErr, txErr: r.txErr, rxDrop: r.rxDrop, txDrop: r.txDrop })),
    findings, counts: { interfaces: rows.length, findings: findings.length },
  });
  process.exit(0);
}

console.log(`bandwidth: ${paths.join('  vs  ')}`);
console.log(elapsed ? `window: ${elapsed.toFixed(1)}s` : 'single sample — totals only, pass a second sample for rates');
console.log('');
console.log(table(rows.map((r) => ({
  iface: r.iface, rxTotal: r.rxHuman, txTotal: r.txHuman,
  rxRate: r.rxRate, txRate: r.txRate,
  rxErr: r.rxErr, txErr: r.txErr, rxDrop: r.rxDrop, txDrop: r.txDrop,
})), ['iface', 'rxTotal', 'txTotal', 'rxRate', 'txRate', 'rxErr', 'txErr', 'rxDrop', 'txDrop']));

if (findings.length) {
  console.log('\nfindings:');
  const order = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  console.log(table(findings.sort((a, b) => order[a.severity] - order[b.severity]).map((f) => ({ severity: f.severity, iface: f.iface, rule: f.rule, detail: f.message })), ['severity', 'iface', 'rule', 'detail']));
} else console.log('\nno counter anomalies');
process.exit(findings.some((f) => f.severity === 'HIGH') ? 1 : 0);
