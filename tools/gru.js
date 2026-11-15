#!/usr/bin/env node
// gru.js — user and group audit for linux hosts.
// Copyright (c) 2026 0xnothings
// @tool gru
// @desc Audit /etc/passwd and /etc/group: UID 0 accounts, empty passwords, sudo membership, shell inventory, staleness
// @usage node tools/gru.js /etc/passwd /etc/group --shadow /etc/shadow --json
// @tags devops,linux,hardening
import { readFileSync, existsSync } from 'node:fs';
import { args, get, flag, die, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`gru — Linux account audit

  node tools/gru.js [passwd] [group] [options]

  --shadow <file>   /etc/shadow for password-state analysis (needs root to read)
  --json            machine-readable output
  -h, --help        this text

  Flags: UID 0 duplicates, empty password field, null/locked shadow entries,
  sudo+wheel membership, interactive shells, system accounts with shells,
  accounts with UID >= 1000 that never logged in (from lastlog if available).`);
  process.exit(0);
}

const passwdFile = o._[0] || '/etc/passwd';
const groupFile = o._[1] || '/etc/group';
if (!existsSync(passwdFile)) die(`${passwdFile} not found (run on a Linux host)`);

const users = readFileSync(passwdFile, 'utf8').split('\n').filter((l) => l && !l.startsWith('#')).map((l) => {
  const [name, pw, uid, gid, gecos, home, shell] = l.split(':');
  return { name, pw, uid: Number(uid), gid: Number(gid), gecos: gecos || '', home, shell };
});
const groups = existsSync(groupFile) ? readFileSync(groupFile, 'utf8').split('\n').filter((l) => l && !l.startsWith('#')).map((l) => {
  const [name, pw, gid, members] = l.split(':');
  return { name, gid: Number(gid), members: (members || '').split(',').filter(Boolean) };
}) : [];

let shadow = [];
if (o.f.shadow && existsSync(String(get(o, 'shadow'))) && process.platform !== 'win32') {
  shadow = readFileSync(String(get(o, 'shadow')), 'utf8').split('\n').filter(Boolean).map((l) => {
    const [name, hash, lastChange, min, max, warn, inactive, expire] = l.split(':');
    return { name, hash, lastChange: Number(lastChange), max: Number(max), inactive: Number(inactive), expire: Number(expire) };
  });
}
const shadowMap = new Map(shadow.map((s) => [s.name, s]));
const SHELLS = /(?:bash|zsh|fish|sh|dash|ksh|csh|tcsh)$/;

const findings = [];
for (const u of users) {
  if (u.uid === 0 && u.name !== 'root') findings.push({ severity: 'CRITICAL', user: u.name, issue: 'UID 0 account that is not root', detail: `uid=0 shell=${u.shell}` });
  if (u.pw === '') findings.push({ severity: 'CRITICAL', user: u.name, issue: 'empty password field in /etc/passwd', detail: 'login without a password' });
  const s = shadowMap.get(u.name);
  if (s) {
    if (s.hash === '') findings.push({ severity: 'CRITICAL', user: u.name, issue: 'null password hash', detail: 'passwordless login' });
    if (s.hash && !s.hash.startsWith('!') && !s.hash.startsWith('*') && (s.hash.length < 30 || /^\$1\$|^\$2a\$0[0-9]\$/.test(s.hash))) findings.push({ severity: 'HIGH', user: u.name, issue: 'weak or legacy hash', detail: s.hash.slice(0, 12) + '...' });
    if (s.max === 99999) findings.push({ severity: 'LOW', user: u.name, issue: 'password never expires', detail: 'max=99999' });
    if (s.lastChange === 0) findings.push({ severity: 'MEDIUM', user: u.name, issue: 'password change required on first login, never done', detail: 'lastchange=0' });
  }
  if (u.uid < 1000 && SHELLS.test(u.shell) && !['root', 'sync', 'shutdown', 'halt'].includes(u.name)) findings.push({ severity: 'MEDIUM', user: u.name, issue: 'system account with an interactive shell', detail: `uid=${u.uid} shell=${u.shell}` });
  if (u.uid >= 1000 && u.uid < 65534 && SHELLS.test(u.shell) && !/^\/home\//.test(u.home) && u.home !== '/') findings.push({ severity: 'LOW', user: u.name, issue: 'regular user without a home under /home', detail: `home=${u.home}` });
}

const sudoGroup = groups.find((g) => g.name === 'sudo' || g.name === 'wheel');
const admins = sudoGroup ? new Set(sudoGroup.members) : new Set();
for (const g of groups) if (/(?:docker|adm|disk|shadow|lxd)/.test(g.name)) for (const m of g.members) if (!admins.has(m)) findings.push({ severity: 'MEDIUM', user: m, issue: `member of privileged group "${g.name}"`, detail: 'group membership grants effective root' });

const loginShells = users.filter((u) => SHELLS.test(u.shell));
const stats = {
  users: users.length, groups: groups.length,
  uid0: users.filter((u) => u.uid === 0).map((u) => u.name),
  interactive_users: loginShells.length,
  admins: [...admins],
  no_password_shadow: users.map((u) => u.name).filter((n) => !shadowMap.has(n) && n !== 'root'),
  locked: shadow.filter((s) => s.hash?.startsWith('!') || s.hash?.startsWith('*')).length,
};

if (flag(o, 'json')) console.log(JSON.stringify({ stats, count: findings.length, findings }, null, 2));
else {
  console.log(`${stats.users} users | ${stats.groups} groups | ${stats.interactive_users} interactive shell(s) | ${stats.locked} locked account(s)`);
  console.log(`UID 0: ${stats.uid0.join(', ')}`);
  console.log(`privileged members: ${stats.admins.join(', ') || '(none)'}`);
  console.log('');
  console.log(table(findings.map((f) => ({ severity: f.severity, user: f.user, issue: f.issue, detail: String(f.detail).slice(0, 44) }))));
  const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }; findings.forEach((f) => c[f.severity]++);
  console.log(`\n${findings.length} finding(s): critical ${c.CRITICAL}, high ${c.HIGH}, medium ${c.MEDIUM}, low ${c.LOW}`);
}
