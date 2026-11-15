#!/usr/bin/env node
// portmap.js — local listening port to process mapper.
// Copyright (c) 2026 0xnothings
// @tool portmap
// @desc Map listening sockets to owning processes and flag unexpected public binds
// @usage node tools/portmap.js --json
// @tags devops,network,diagnostics
import { execFileSync } from 'node:child_process';
import { args, get, num, flag, die, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`portmap — listening port to process map

  node tools/portmap.js [options]

  --expect <ports>   ports that should be listening (comma separated)
  --public-only      only show sockets bound to 0.0.0.0 / ::
  --json             machine-readable output
  -h, --help         this text

  Uses ss/lsof/netstat, whichever exists. Read-only.`);
  process.exit(0);
}

function tryCmd(cmd, argsArr) {
  try { return execFileSync(cmd, argsArr, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }); } catch { return null; }
}

let rows = [];
const ss = tryCmd('ss', ['-tulpnH']);
if (ss !== null) {
  for (const line of ss.split('\n').filter(Boolean)) {
    const parts = line.trim().split(/\s+/);
    const proto = parts[0];
    const local = parts[4] || '';
    const proc = (line.match(/users:\(\("([^"]+)",pid=(\d+)/) || [, '', '']);
    const [addr, port] = [local.replace(/^\[|\]$/g, '').split(':').slice(0, -1).join(':') || '*', local.split(':').pop()];
    rows.push({ proto, addr: addr || '*', port, process: proc[1] || '-', pid: proc[2] || '-' });
  }
} else {
  const lsof = tryCmd('lsof', ['-nP', '-iTCP', '-sTCP:LISTEN']);
  if (lsof === null) die('neither ss nor lsof available');
  for (const line of lsof.split('\n').slice(1).filter(Boolean)) {
    const p = line.split(/\s+/);
    const [addr, port] = (p[8] || '').split(':');
    rows.push({ proto: 'tcp', addr, port, process: p[0], pid: p[1] });
  }
}

rows = [...new Map(rows.map((r) => [`${r.proto}:${r.addr}:${r.port}`, r])).values()]
  .sort((a, b) => Number(a.port) - Number(b.port));

const isPublic = (r) => /^(0\.0\.0\.0|\*|::|\[::\])$/.test(r.addr) || r.addr === '';
if (flag(o, 'public-only')) rows = rows.filter(isPublic);

const expected = o.f.expect ? new Set(String(get(o, 'expect')).split(',').map((s) => s.trim())) : null;
const EXPECTED_COMMON = new Set(['22', '80', '443', '3306', '5432', '6379', '27017']);
const findings = rows.filter((r) => isPublic(r) && !EXPECTED_COMMON.has(r.port) && !(expected && expected.has(r.port)))
  .map((r) => ({ ...r, note: 'publicly bound, not a standard service port' }));

if (flag(o, 'json')) console.log(JSON.stringify({ count: rows.length, unexpected: findings.length, sockets: rows, findings }, null, 2));
else {
  console.log(table(rows.map((r) => ({ proto: r.proto, bind: r.addr, port: r.port, pid: r.pid, process: r.process.slice(0, 30), exposure: isPublic(r) ? 'PUBLIC' : 'local' }))));
  if (findings.length) {
    console.log(`\n${findings.length} port(s) bound publicly without being a standard service:`);
    findings.forEach((f) => console.log(`  ${f.addr}:${f.port}  ${f.process} (pid ${f.pid})`));
    console.log('\nif these are development servers, bind them to 127.0.0.1 instead.');
  }
  if (expected) {
    const missing = [...expected].filter((p) => !rows.some((r) => r.port === p));
    if (missing.length) console.log(`\nexpected but not listening: ${missing.join(', ')}`);
  }
  console.log(`\n${rows.length} listening socket(s)`);
}
