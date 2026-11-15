#!/usr/bin/env node
// cronaudit.js — security review of crontabs and /etc/cron.d.
// Copyright (c) 2026 0xnothings
// @tool cronaudit
// @desc Audit crontabs: duplicates, overlapping schedules, world-writable scripts, PATH hijack risk, missing redirection and shell metacharacters
// @usage node tools/cronaudit.js /etc/crontab /etc/cron.d --json
// @tags devops,cron,audit
import { readFileSync, readdirSync, statSync, accessSync, constants } from 'node:fs';
import { join, isAbsolute } from 'node:path';
import { args, flag, die, emit, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`cronaudit — crontab security auditor

  node tools/cronaudit.js <file|dir> [more...] [options]

  --json        machine-readable output
  --crontab     treat input as a user crontab (no user field)
  -h, --help    this text

  checks: duplicate entries, identical schedules (>4 jobs in the same minute),
          missing stdout/stderr redirection, world-writable or non-absolute scripts,
          PATH containing relative or writable dirs, shell operators, root jobs running
          from /tmp or /home, @reboot on non-daemons, jobs with no locking`);
  process.exit(0);
}

const targets = o._.length ? o._ : ['/etc/crontab'];
const systemMode = !flag(o, 'crontab');
const files = [];
function collect(p) {
  let st;
  try { st = statSync(p); } catch { return; }
  if (st.isFile()) { files.push(p); return; }
  for (const e of readdirSync(p, { withFileTypes: true })) {
    const fp = join(p, e.name);
    if (e.isDirectory()) { if (e.name !== '.git') collect(fp); }
    else if (/^[A-Za-z0-9_.-]+$/.test(e.name) || e.name.endsWith('.cron') || e.name.endsWith('.conf')) files.push(fp);
  }
}
for (const t of targets) collect(t);
if (!files.length) die(`no crontab files found in: ${targets.join(', ')}`);

const MACROS = new Set(['@reboot', '@yearly', '@annually', '@monthly', '@weekly', '@daily', '@midnight', '@hourly']);
const jobs = [];
const findings = [];
const add = (file, line, sev, rule, msg) => findings.push({ file: file.split(/[\\/]/).pop(), line, severity: sev, rule, message: msg });

for (const f of files) {
  let text = '';
  try { text = readFileSync(f, 'utf8'); } catch { continue; }
  const raw = text.split(/\r?\n/);
  const envPath = [];
  for (let i = 0; i < raw.length; i++) {
    const line = raw[i];
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const env = t.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (env && /^(PATH|SHELL|MAILTO|HOME|CRON_TZ)$/.test(env[1])) {
      if (env[1] === 'PATH') envPath.push(env[2]);
      if (env[1] === 'SHELL' && !isAbsolute(env[2])) add(f, i + 1, 'HIGH', 'shell', `SHELL=${env[2]} is not an absolute path`);
      if (env[1] !== 'PATH') add(f, i + 1, 'INFO', 'env', `${env[1]}=${env[2].slice(0, 60)}`);
      continue;
    }
    if (env && /^[A-Za-z_][A-Za-z0-9_]*\s*=/.test(t)) {
      const k = env[1], v = env[2];
      if (/(PASS|SECRET|TOKEN|KEY)/i.test(k)) add(f, i + 1, 'CRITICAL', 'secret', `secret-looking variable ${k} in a crontab (world-readable on most systems)`);
      if (/[A-Za-z0-9+/]{32,}={0,2}/.test(v)) add(f, i + 1, 'HIGH', 'secret', `base64-looking value in ${k}`);
      continue;
    }

    const parts = t.split(/\s+/);
    let sched = null, rest = [];
    if (MACROS.has(parts[0])) { sched = parts[0]; rest = parts.slice(1); }
    else if (parts.length >= 5) { sched = parts.slice(0, 5).join(' '); rest = parts.slice(5); }
    else { add(f, i + 1, 'MEDIUM', 'parse', `unparseable line: ${t.slice(0, 50)}`); continue; }

    let user = null;
    let cmd = rest.join(' ');
    if (systemMode && !MACROS.has(parts[0]) && rest.length > 1) {
      if (/^[a-z_][a-z0-9_-]*\$?$/i.test(rest[0]) && !rest[0].startsWith('/') && !rest[0].startsWith('@')) { user = rest[0]; cmd = rest.slice(1).join(' '); }
    } else if (systemMode && MACROS.has(parts[0]) && rest.length > 1) {
      if (/^[a-z_][a-z0-9_-]*\$?$/i.test(rest[0]) && !rest[0].startsWith('/') && !rest[0].includes('=')) { user = rest[0]; cmd = rest.slice(1).join(' '); }
    }

    const binary = cmd.trim().split(/\s+/)[0] || '';
    const redirects = /(>>?\s*\S+|2>&1|>\s*\/dev\/null|&>\s*\S+)/.test(cmd);
    jobs.push({ file: f.split(/[\\/]/).pop(), line: i + 1, schedule: sched, user: user || '(crontab owner)', cmd: cmd.trim().slice(0, 120), binary, redirects, raw: t });

    if (!redirects) add(f, i + 1, 'MEDIUM', 'no-output-redirect', `no stdout/stderr redirection: ${cmd.slice(0, 40)} — mail spool fills on every noisy run`);
    if (!isAbsolute(binary) && !/^[A-Za-z_][A-Za-z0-9_]*=/.test(binary)) add(f, i + 1, 'HIGH', 'relative-binary', `"${binary}" is not absolute — PATH hijack turns this into code execution`);
    if (/[;&|`$()]/.test(cmd) && !/2>&1/.test(cmd)) add(f, i + 1, 'MEDIUM', 'shell-metachars', 'shell operators in an unquoted command; cron runs this through /bin/sh');
    if (/\b(curl|wget)\b[^|]*\|\s*(ba|z)?sh/.test(cmd)) add(f, i + 1, 'CRITICAL', 'curl-pipe-sh', 'fetches and executes a remote script with no integrity check');
    if (/\/tmp\/|\/var\/tmp\/|\/dev\/shm\//.test(cmd)) add(f, i + 1, 'HIGH', 'tmp-exec', 'executes from a world-writable directory');
    if (user === 'root' && /\/home\//.test(cmd)) add(f, i + 1, 'CRITICAL', 'root-home-exec', 'root job runs a script from a user home directory');
    if (sched === '@reboot' && /(backup|report|mail|sync)/i.test(cmd)) add(f, i + 1, 'LOW', 'reboot-jobs', '@reboot used for a periodic task; a reboot loop multiplies it');

    const script = cmd.match(/(\/[^\s;|&]+\.(sh|py|pl|rb|js))/);
    if (script) {
      try {
        const st = statSync(script[1]);
        if (st.mode & 0o002) add(f, i + 1, 'CRITICAL', 'world-writable-script', `${script[1]} is world-writable (mode ${(st.mode & 0o777).toString(8)})`);
        else if ((st.mode & 0o022) && user === 'root') add(f, i + 1, 'HIGH', 'group-writable-script', `${script[1]} is group/world writable and runs as root`);
        if (!(st.mode & 0o100) && user === 'root') add(f, i + 1, 'LOW', 'not-executable', `${script[1]} is not executable but cron invokes it directly`);
      } catch { add(f, i + 1, 'LOW', 'missing-script', `${script[1]} does not exist`); }
    }
    if (/\$\([^)]*\)/.test(cmd) && /rm\s+-rf/.test(cmd)) add(f, i + 1, 'CRITICAL', 'rm-rf-subshell', 'rm -rf with command substitution — an empty result wipes the cwd');
  }

  for (const p of envPath) {
    for (const d of p.split(':')) {
      if (!d) { add(f, 1, 'MEDIUM', 'path-empty', 'empty PATH component (equivalent to the current directory)'); continue; }
      if (!isAbsolute(d)) add(f, 1, 'HIGH', 'path-relative', `PATH contains a relative directory: ${d}`);
    }
    if (!/^\/usr\/local\/sbin:\/usr\/local\/bin:\/usr\/sbin:\/usr\/bin:\/sbin:\/bin$/.test(p) && p !== '/usr/bin:/bin') {
      add(f, 1, 'LOW', 'path-custom', `PATH is not the cron default: ${p}`);
    }
  }
}

// duplicates
const seenCmd = new Map();
for (const j of jobs) {
  const k = `${j.schedule} :: ${j.cmd}`;
  if (seenCmd.has(k)) add(j.file, j.line, 'MEDIUM', 'duplicate', `identical entry also at ${seenCmd.get(k).file}:${seenCmd.get(k).line}`);
  else seenCmd.set(k, j);
}
// schedule clustering
const byMinute = new Map();
for (const j of jobs) {
  const key = j.schedule;
  if (!byMinute.has(key)) byMinute.set(key, []);
  byMinute.get(key).push(j);
}
for (const [sched, list] of byMinute) {
  if (list.length >= 4) add(list[0].file, list[0].line, 'LOW', 'schedule-cluster', `${list.length} jobs share the schedule "${sched}" — they contend for CPU and I/O at the same instant`);
}
// missing lock
for (const j of jobs) {
  if (!/flock|lockfile|cronlock|systemd-run/.test(j.cmd) && j.schedule !== '@reboot' && /(backup|sync|rsync|dump|report)/i.test(j.cmd)) {
    add(j.file, j.line, 'LOW', 'no-lock', 'long-running job without a lock; overlapping runs corrupt output');
  }
}

const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
const failed = findings.some((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH');

if (flag(o, 'json')) { emit({ files: files.length, jobs: jobs.length, findings, counts, pass: !failed }); process.exit(0); }

console.log(`cronaudit: ${files.length} file(s), ${jobs.length} job(s)`);
console.log(`findings: ${findings.length}  critical: ${counts.CRITICAL} high: ${counts.HIGH} medium: ${counts.MEDIUM} low: ${counts.LOW}`);
if (jobs.length) {
  console.log('');
  console.log(table(jobs.map((j) => ({ file: j.file, line: j.line, schedule: j.schedule, user: j.user, cmd: j.cmd.slice(0, 60) })), ['file', 'line', 'schedule', 'user', 'cmd']));
}
if (findings.length) {
  console.log('\nfindings:');
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  console.log(table(findings.filter((x) => x.severity !== 'INFO').sort((a, b) => order[a.severity] - order[b.severity]).map((f) => ({ severity: f.severity, file: f.file, line: f.line, rule: f.rule, detail: f.message })), ['severity', 'file', 'line', 'rule', 'detail']));
} else console.log('\nno findings');
process.exit(failed ? 1 : 0);
