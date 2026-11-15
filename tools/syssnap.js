#!/usr/bin/env node
// syssnap.js — one-shot system health snapshot.
// Copyright (c) 2026 0xnothings
// @tool syssnap
// @desc Collect CPU, memory, disk, load, uptime, top processes into one snapshot with a health verdict
// @usage node tools/syssnap.js --interval 1000 --json
// @tags devops,monitoring,diagnostics
import { cpus, totalmem, freemem, loadavg, uptime, platform, arch, hostname, release } from 'node:os';
import { execFileSync } from 'node:child_process';
import { args, get, num, flag, die, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`syssnap — system health snapshot

  node tools/syssnap.js [options]

  --interval <ms>   CPU sampling window (default: 500)
  --disk <path>     filesystem to check (default: /)
  --top <n>         top processes by cpu (default: 8)
  --json            machine-readable output
  -h, --help        this text`);
  process.exit(0);
}

const sh = (cmd, a) => { try { return execFileSync(cmd, a, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }); } catch { return ''; } };

function cpuSample(ms) {
  return new Promise((resolve) => {
    const snap = () => cpus().map((c) => ({ ...c.times }));
    const a = snap();
    setTimeout(() => {
      const b = snap();
      let idle = 0, total = 0;
      a.forEach((prev, i) => {
        const cur = b[i];
        const t = ['user', 'nice', 'sys', 'irq', 'idle'].reduce((s, k) => s + (cur[k] - prev[k]), 0);
        total += t; idle += cur.idle - prev.idle;
      });
      resolve(total ? +(((total - idle) / total) * 100).toFixed(1) : 0);
    }, ms);
  });
}

const diskPath = String(get(o, 'disk', '/'));
const dfOut = sh('df', ['-k', diskPath]).split('\n')[1] || '';
const df = dfOut.split(/\s+/);
const disk = df.length > 3 ? { total: Number(df[1]) * 1024, used: Number(df[2]) * 1024, avail: Number(df[3]) * 1024, mount: df[5] || diskPath } : null;
const diskPct = disk ? +((disk.used / disk.total) * 100).toFixed(1) : null;

const memTotal = totalmem(), memFree = freemem();
const memPct = +(((memTotal - memFree) / memTotal) * 100).toFixed(1);
const la = loadavg();
const cores = cpus().length;
const loadPct = +((la[0] / cores) * 100).toFixed(1);
const cpuPct = await cpuSample(num(get(o, 'interval'), 500));

const top = (sh('ps', ['-eo', 'pcpu,pmem,pid,comm', '--sort=-pcpu']).split('\n').slice(1, num(get(o, 'top'), 8) + 1) || [])
  .filter(Boolean).map((l) => { const p = l.trim().split(/\s+/); return { cpu: p[0], mem: p[1], pid: p[2], comm: p.slice(3).join(' ') }; });

const issues = [];
if (cpuPct > 85) issues.push(`CPU at ${cpuPct}%`);
if (memPct > 90) issues.push(`memory at ${memPct}%`);
if (diskPct !== null && diskPct > 85) issues.push(`disk at ${diskPct}% on ${disk.mount}`);
if (loadPct > 100) issues.push(`load ${la[0]} exceeds ${cores} cores`);
const verdict = issues.length === 0 ? 'healthy' : issues.length <= 2 ? 'degraded' : 'critical';

const snap = {
  host: hostname(), platform: `${platform()} ${release()} ${arch()}`, cores,
  uptime_hours: +(uptime() / 3600).toFixed(1), sampled_at: new Date().toISOString(),
  cpu_pct: cpuPct, load: la.map((n) => +n.toFixed(2)), load_pct: loadPct,
  memory: { total_gb: +(memTotal / 1073741824).toFixed(2), free_gb: +(memFree / 1073741824).toFixed(2), used_pct: memPct },
  disk, disk_pct: diskPct, top_processes: top, verdict, issues,
};

if (flag(o, 'json')) { console.log(JSON.stringify(snap, null, 2)); process.exit(issues.length ? 1 : 0); }
console.log(`${snap.host} — ${snap.platform}`);
console.log(`  uptime   ${snap.uptime_hours} h`);
console.log(`  cpu      ${snap.cpu_pct}%  (load ${snap.load.join(' / ')} on ${cores} cores = ${snap.load_pct}%)`);
console.log(`  memory   ${snap.memory.used_pct}% used  (${snap.memory.free_gb} GB free of ${snap.memory.total_gb} GB)`);
if (disk) console.log(`  disk     ${diskPct}% used  (${(disk.avail / 1073741824).toFixed(1)} GB free on ${disk.mount})`);
if (top.length) { console.log('\ntop processes:'); console.log(table(top.map((t) => ({ cpu: t.cpu + '%', mem: t.mem + '%', pid: t.pid, command: t.comm.slice(0, 40) })))); }
console.log(`\nverdict: ${verdict.toUpperCase()}${issues.length ? ' — ' + issues.join('; ') : ''}`);
process.exit(issues.length ? 1 : 0);
