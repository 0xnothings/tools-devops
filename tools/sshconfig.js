#!/usr/bin/env node
// sshconfig.js — audit and map an ssh_config.
// Copyright (c) 2026 0xnothings
// @tool sshconfig
// @desc Map jump-host topology and audit ssh_config security/keepalive options, reporting which Host entries are unreachable or unsafe
// @usage node tools/sshconfig.js ~/.ssh/config --json
// @tags devops,ssh,audit
import { readFileSync, existsSync } from 'node:fs';
import { args, flag, die, emit, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`sshconfig — ssh_config topology mapper and auditor

  node tools/sshconfig.js [~/.ssh/config] [options]

  --json        machine-readable output
  --host <pat>  dump the resolved options for one Host entry
  -h, --help    this text

  checks: StrictHostKeyChecking, weak/legacy algorithms, agent forwarding,
           ProxyJump chains, keepalive gaps, duplicate Host shadows, wildcard ordering`);
  process.exit(0);
}

const file = o._[0] || `${process.env.HOME || process.env.USERPROFILE || '.'}/.ssh/config`;
if (!existsSync(file)) die(`no such file: ${file}`);

const raw = readFileSync(file, 'utf8').split(/\r?\n/);
const blocks = [];
let cur = null;
for (let i = 0; i < raw.length; i++) {
  const line = raw[i].replace(/\s*#.*$/, '').trim();
  if (!line) continue;
  const h = line.match(/^Host\s+(.+)$/i);
  if (h) { cur = { patterns: h[1].split(/\s+/).filter(Boolean), line: i + 1, opts: {}, order: blocks.length }; blocks.push(cur); continue; }
  const kv = line.match(/^([A-Za-z][A-Za-z0-9]*)\s+(.+)$/);
  if (kv && cur) {
    const k = kv[1].toLowerCase();
    if (!(k in cur.opts)) cur.opts[k] = { value: kv[2].trim(), line: i + 1 };
  } else if (kv && !cur) {
    if (!blocks.global) { blocks.global = { patterns: ['*'], line: i + 1, opts: {}, order: -1 }; blocks.unshift(blocks.global); cur = blocks.global; }
    ((cur = cur || blocks.global).opts)[kv[1].toLowerCase()] = { value: kv[2].trim(), line: i + 1 };
  }
}
const global = blocks.find((b) => b.order === -1);
const hosts = blocks.filter((b) => b.order !== -1);

const findings = [];
const add = (host, opt, sev, msg) => findings.push({ host, option: opt, severity: sev, message: msg });

function resolve(hostEntry, key) {
  if (hostEntry.opts[key]) return { ...hostEntry.opts[key], from: 'host' };
  if (global && global.opts[key]) return { ...global.opts[key], from: 'global' };
  return null;
}

for (const h of hosts) {
  const nm = h.patterns.join(' ');
  const shk = resolve(h, 'stricthostkeychecking');
  if (shk && /^(no|off|false)$/i.test(shk.value)) add(nm, 'StrictHostKeyChecking', 'CRITICAL', 'host key verification disabled — any MITM is silently accepted');
  else if (!shk) add(nm, 'StrictHostKeyChecking', 'LOW', 'not set explicitly; inherits the global/default');
  else if (/^(accept-new|ask)$/i.test(shk.value)) add(nm, 'StrictHostKeyChecking', 'LOW', `set to ${shk.value} — new keys auto-added, changed keys rejected only if known_hosts is strict`);

  const ukh = resolve(h, 'userknownhostsfile');
  if (ukh && /\/dev\/null/.test(ukh.value)) add(nm, 'UserKnownHostsFile', 'CRITICAL', '/dev/null discards known_hosts — no protection against key changes');

  const ua = resolve(h, 'userauthentication');
  if (ua && !/password/i.test(ua.value) && !/keyboard-interactive/i.test(ua.value)) { /* good */ }
  const pw = resolve(h, 'passwordauthentication');
  if (pw && /yes/i.test(pw.value)) add(nm, 'PasswordAuthentication', 'MEDIUM', 'password auth enabled; prefer publickey-only');
  const kbi = resolve(h, 'kbdinteractiveauthentication');
  if (kbi && /yes/i.test(kbi.value)) add(nm, 'KbdInteractiveAuthentication', 'LOW', 'interactive auth enabled (bypasses some password policies)');

  const fa = resolve(h, 'forwardagent');
  if (fa && /yes/i.test(fa.value)) add(nm, 'ForwardAgent', 'HIGH', 'agent forwarding lets a compromised host sign with your keys — use ProxyJump instead');

  const kai = resolve(h, 'serveraliveinterval');
  const kac = resolve(h, 'serveralivecountmax');
  if (!kai) add(nm, 'ServerAliveInterval', 'LOW', 'no keepalive; long-idle sessions die mid-transfer');
  else if (Number(kai.value) > 120) add(nm, 'ServerAliveInterval', 'LOW', `keepalive ${kai.value}s is long; 30-60s is typical`);
  if (kai && !kac) add(nm, 'ServerAliveCountMax', 'LOW', 'ServerAliveInterval set without ServerAliveCountMax');

  const ca = (resolve(h, 'ciphers') || {}).value;
  if (ca && /(3des|arcfour|blowfish|cast128|des-cbc)/i.test(ca)) add(nm, 'Ciphers', 'HIGH', `legacy cipher list: ${ca}`);
  const mac = (resolve(h, 'macs') || {}).value;
  if (mac && /(hmac-md5|hmac-sha1)/i.test(mac)) add(nm, 'MACs', 'MEDIUM', `weak MAC list: ${mac}`);
  const kex = (resolve(h, 'kexalgorithms') || {}).value;
  if (kex && /(diffie-hellman-group1|group14-sha1|sha1$)/i.test(kex)) add(nm, 'KexAlgorithms', 'MEDIUM', `weak KEX list: ${kex}`);
  const ha = (resolve(h, 'hostkeyalgorithms') || {}).value;
  if (ha && /ssh-rsa\b(?!.*rsa-sha2)/.test(ha)) add(nm, 'HostKeyAlgorithms', 'LOW', `ssh-rsa (SHA-1) permitted: ${ha}`);

  const ep = (resolve(h, 'proxycommand') || {}).value;
  if (ep && /nc\s+-X|netcat/.test(ep)) add(nm, 'ProxyCommand', 'LOW', 'netcat ProxyCommand; -W (socat/ssh) or ProxyJump is more reliable');

  const idf = (resolve(h, 'identityfile') || {}).value;
  if (idf && /\.ppk|id_rsa$/.test(idf) && /id_rsa$/.test(idf)) add(nm, 'IdentityFile', 'LOW', 'id_rsa (RSA/legacy PEM) — ed25519 keys are smaller and faster');

  const port = (resolve(h, 'port') || {}).value;
  if (port && /^22$/.test(port)) { /* default, fine */ }
}

// wildcard shadowing check
const wildcards = hosts.filter((h) => h.patterns.some((p) => p.includes('*') || p.includes('?')));
for (const w of wildcards) {
  for (const h of hosts) {
    if (h === w) continue;
    if (h.order > w.order) continue;
    for (const p of h.patterns) {
      for (const wp of w.patterns) {
        if (wp === '*') { add(w.patterns.join(' '), 'Order', 'MEDIUM', `Host * at line ${w.line} precedes ${p} (line ${h.line}); ssh uses the FIRST matching entry, so ${p} may never apply`); }
      }
    }
  }
}

// duplicate host patterns
const seenPat = new Map();
for (const h of hosts) for (const p of h.patterns) {
  if (seenPat.has(p)) add(p, 'Duplicate', 'MEDIUM', `Host ${p} declared twice (lines ${seenPat.get(p)} and ${h.line}); the first wins and the second is dead config`);
  else seenPat.set(p, h.line);
}

// ProxyJump topology
const jumps = {};
for (const h of hosts) {
  const pj = (resolve(h, 'proxyjump') || {}).value || null;
  const pc = (resolve(h, 'proxycommand') || {}).value || null;
  jumps[h.patterns[0]] = { proxyJump: pj, proxyCommand: pc };
}
const chainDepth = (name, seen) => {
  if (!name || seen.has(name)) return seen.size;
  seen.add(name);
  const j = jumps[name];
  if (!j || !j.proxyJump) return seen.size;
  for (const hop of j.proxyJump.split(',')) chainDepth(hop.trim(), seen);
  return seen.size;
};
const topo = Object.entries(jumps).filter(([, j]) => j.proxyJump).map(([n, j]) => ({ host: n, via: j.proxyJump, depth: chainDepth(n, new Set()) }));

if (flag(o, 'json')) {
  emit({ file, global: global ? global.opts : {}, hosts: hosts.map((h) => ({ patterns: h.patterns, line: h.line, options: Object.fromEntries(Object.entries(h.opts).map(([k, v]) => [k, v.value])) })), topology: topo, findings, counts: { hosts: hosts.length, findings: findings.length } });
  process.exit(0);
}

const wantHost = o.f.host;
if (wantHost) {
  const h = hosts.find((x) => x.patterns.includes(String(wantHost)));
  if (!h) die(`no Host entry matching "${wantHost}"`);
  const merged = {};
  if (global) for (const [k, v] of Object.entries(global.opts)) merged[k] = { value: v.value, from: 'global', line: v.line };
  for (const [k, v] of Object.entries(h.opts)) merged[k] = { value: v.value, from: 'host', line: v.line };
  console.log(`Host ${h.patterns.join(' ')} (line ${h.line})`);
  console.log(table(Object.entries(merged).sort().map(([k, v]) => ({ option: k, value: v.value, source: v.from, line: v.line })), ['option', 'value', 'source', 'line']));
  process.exit(0);
}

console.log(`sshconfig: ${file}`);
console.log(`host entries: ${hosts.length}  findings: ${findings.length}`);
if (global && Object.keys(global.opts).length) {
  console.log('\nglobal defaults:');
  console.log(table(Object.entries(global.opts).map(([k, v]) => ({ option: k, value: v.value, line: v.line })), ['option', 'value', 'line']));
}
if (hosts.length) {
  console.log('\nhosts:');
  console.log(table(hosts.map((h) => ({ host: h.patterns.join(' '), hostname: (resolve(h, 'hostname') || {}).value || h.patterns[0], user: (resolve(h, 'user') || {}).value || '-', port: (resolve(h, 'port') || {}).value || '22', jump: (resolve(h, 'proxyjump') || {}).value || '-', line: h.line })), ['host', 'hostname', 'user', 'port', 'jump', 'line']));
}
if (topo.length) {
  console.log('\njump topology:');
  console.log(table(topo.map((t) => ({ host: t.host, via: t.via, depth: t.depth })), ['host', 'via', 'depth']));
}
if (findings.length) {
  console.log('\nfindings:');
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  console.log(table(findings.sort((a, b) => order[a.severity] - order[b.severity]).map((f) => ({ severity: f.severity, host: f.host, option: f.option, detail: f.message })), ['severity', 'host', 'option', 'detail']));
} else console.log('\nno findings');
process.exit(0);
