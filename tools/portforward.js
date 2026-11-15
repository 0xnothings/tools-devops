#!/usr/bin/env node
// portforward.js — generate SSH tunnel command lines from a JSON spec.
// Copyright (c) 2026 0xnothings
// @tool portforward
// @desc Build ssh -L/-R/-D tunnel commands plus jump-host chains from a declarative JSON spec, with ready-to-paste config blocks
// @usage node tools/portforward.js tunnels.json --json
// @tags devops,ssh,tunneling
import { readFileSync, existsSync } from 'node:fs';
import { args, flag, die, emit, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`portforward — SSH tunnel command generator

  node tools/portforward.js <spec.json> [options]

  spec:
  {
    "defaults": { "user": "deploy", "identity": "~/.ssh/id_ed25519", "keepalive": 30 },
    "tunnels": [
      { "name": "db",   "type": "local",  "listen": "15432", "to": "db.internal:5432",
        "host": "bastion.example.com", "jump": ["jump1.example.com"], "background": true },
      { "name": "socks","type": "dynamic","listen": "1080", "host": "bastion.example.com" },
      { "name": "push", "type": "remote", "listen": "8080", "to": "127.0.0.1:3000", "host": "bastion.example.com" }
    ]
  }

  --json        machine-readable output
  --config      emit an ~/.ssh/config block instead of commands
  --dry-run     print what would be executed (default anyway)
  -h, --help    this text`);
  process.exit(0);
}

const file = o._[0];
if (!file) die('usage: node tools/portforward.js <spec.json> [--json]');
if (!existsSync(file)) die(`no such file: ${file}`);
let spec;
try { spec = JSON.parse(readFileSync(file, 'utf8')); } catch (e) { die(`invalid JSON in ${file}: ${e.message}`); }

const d = spec.defaults || {};
const tunnels = Array.isArray(spec.tunnels) ? spec.tunnels : [];
if (!tunnels.length) die('spec has no "tunnels" array');

const built = [];
for (const t of tunnels) {
  if (!t.host) die(`tunnel "${t.name || '?'}" is missing "host"`);
  const type = (t.type || 'local').toLowerCase();
  if (!['local', 'remote', 'dynamic'].includes(type)) die(`tunnel "${t.name}": unknown type "${t.type}" (local|remote|dynamic)`);
  const user = t.user || d.user;
  const identity = t.identity || d.identity;
  const keepalive = Number(t.keepalive ?? d.keepalive ?? 30);
  const target = user ? `${user}@${t.host}` : t.host;

  const argv = ['ssh', '-N'];
  if (type === 'dynamic') {
    if (!t.listen) die(`tunnel "${t.name}": dynamic tunnels need "listen"`);
    argv.push('-D', `127.0.0.1:${t.listen}`);
  } else if (type === 'local') {
    if (!t.listen || !t.to) die(`tunnel "${t.name}": local tunnels need "listen" and "to"`);
    const bind = t.bind || '127.0.0.1';
    argv.push('-L', `${bind}:${t.listen}:${t.to}`);
  } else {
    if (!t.listen || !t.to) die(`tunnel "${t.name}": remote tunnels need "listen" and "to"`);
    const bind = t.bind || '127.0.0.1';
    argv.push('-R', `${bind}:${t.listen}:${t.to}`);
  }
  if (t.jump && t.jump.length) argv.push('-J', t.jump.join(','));
  if (identity) argv.push('-i', identity);
  if (t.port) argv.push('-p', String(t.port));
  if (keepalive) { argv.push('-o', 'ServerAliveInterval=' + keepalive); argv.push('-o', 'ServerAliveCountMax=3'); }
  if (t.background || d.background) argv.push('-f');
  if (t.autossh) argv.push('-o', 'ExitOnForwardFailure=yes');
  argv.push(t.extra && t.extra.length ? '' : '', target);
  const cmd = argv.filter((x) => x !== '').map((a) => (/[\s"$]/.test(a) ? `"${a}"` : a)).join(' ');

  const check = type === 'local' ? `nc -vz 127.0.0.1 ${t.listen}` : type === 'remote' ? `ssh ${target} "ss -ltnp | grep :${t.listen}"` : `curl --socks5 127.0.0.1:${t.listen} https://ifconfig.me`;

  const notes = [];
  if ((t.bind || '127.0.0.1') === '0.0.0.0') notes.push('listens on every interface — anyone on this LAN can use the tunnel');
  if (type === 'remote' && !(t.to || '').startsWith('127.0.0.1')) notes.push('remote forward target is not loopback — the far side can reach it');
  if (!identity && !d.identity) notes.push('no identity file; relies on the agent or a password');
  if (!t.jump || !t.jump.length) notes.push('direct connection; add "jump" if the host is not reachable from here');

  built.push({ name: t.name || type, type, host: target, listen: t.listen || '-', to: t.to || '-', jumps: (t.jump || []).join(' > ') || '-', command: cmd, verify: check, notes });
}

if (flag(o, 'json')) { emit({ spec: file, tunnels: built, counts: { tunnels: built.length } }); process.exit(0); }

if (flag(o, 'config')) {
  console.log('# --- generated ~/.ssh/config block ---');
  for (const t of built) {
    console.log(`Host ${t.name}`);
    console.log(`  HostName ${t.host.includes('@') ? t.host.split('@')[1] : t.host}`);
    if (t.host.includes('@')) console.log(`  User ${t.host.split('@')[0]}`);
    if (t.jumps !== '-') console.log(`  ProxyJump ${t.jumps.replace(/ > /g, ',')}`);
    console.log(`  ServerAliveInterval 30`);
    console.log(`  ServerAliveCountMax 3`);
    if (t.type === 'local') console.log(`  LocalForward ${t.listen} ${t.to}`);
    else if (t.type === 'remote') console.log(`  RemoteForward ${t.listen} ${t.to}`);
    else console.log(`  DynamicForward ${t.listen}`);
    console.log('');
  }
  process.exit(0);
}

console.log(`portforward: ${file}`);
console.log(`tunnels: ${built.length}`);
for (const t of built) {
  console.log(`\n[${t.name}] ${t.type}  ${t.host}  ${t.listen}${t.to !== '-' ? ' -> ' + t.to : ''}${t.jumps !== '-' ? '  via ' + t.jumps : ''}`);
  console.log(`  ${t.command}`);
  console.log(`  verify: ${t.verify}`);
  for (const n of t.notes) console.log(`  note: ${n}`);
}
const risky = built.filter((t) => t.notes.some((n) => /every interface|far side/.test(n)));
if (risky.length) { console.log('\nexposure warnings:'); console.log(table(risky.map((t) => ({ tunnel: t.name, detail: t.notes.join('; ') })), ['tunnel', 'detail'])); }
process.exit(0);
