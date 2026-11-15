// systemdunit.js — audit a systemd unit file for hardening gaps.
// Copyright (c) 2026 0xnothings
// @tool systemdunit
// @desc Analyse .service units: sandboxing directives present/missing, restart policy, resource limits and capability scope
// @usage node tools/systemdunit.js /etc/systemd/system/app.service --json
// @tags devops,systemd,hardening
import { readFileSync, existsSync } from 'node:fs';
import { args, flag, die, emit, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`systemdunit — systemd unit hardening auditor

  node tools/systemdunit.js <unit.service> [options]

  --json          machine-readable output
  --recommend     print the hardening block to append
  -h, --help      this text

  checks: NoNewPrivileges, ProtectSystem/Home/Kernel*, PrivateTmp/Devices/Network,
          CapabilityBoundingSet, Restart policy, TimeoutStopSec, resource limits, DynamicUser`);
  process.exit(0);
}

const file = o._[0];
if (!file) die('usage: node tools/systemdunit.js <unit.service> [--json]');
if (!existsSync(file)) die(`no such file: ${file}`);

const text = readFileSync(file, 'utf8');
const sections = {};
let cur = null;
const raw = text.split(/\r?\n/);
for (let i = 0; i < raw.length; i++) {
  const line = raw[i].replace(/\s*[#;].*$/, '').trim();
  if (!line) continue;
  const sec = line.match(/^\[([^\]]+)\]$/);
  if (sec) { cur = sec[1]; sections[cur] = sections[cur] || {}; continue; }
  if (!cur) continue;
  const kv = line.match(/^([A-Za-z][A-Za-z0-9_]*)=?(.*)$/);
  if (!kv) continue;
  const k = kv[1], v = (kv[2] || '').trim();
  if (!(k in sections[cur])) sections[cur][k] = v;
  else sections[cur][k] += ' ' + v;
}

const unit = sections.Unit || {};
const svc = sections.Service || {};
const install = sections.Install || {};
const get = (k) => (k in svc ? svc[k] : null);
const yes = (k) => { const v = get(k); return v !== null && /^(yes|true|on|1)$/i.test(v); };
const no = (k) => { const v = get(k); return v !== null && /^(no|false|off|0)$/i.test(v); };

const checks = [];
const rec = (id, state, weight, detail) => checks.push({ id, state, weight, detail });

rec('Type', get('Type') ? 'ok' : 'missing', 'LOW', `Type=${get('Type') || 'simple (default)'} — forking processes usually want Type=notify`);
if (!get('User') && !yes('DynamicUser')) rec('User', 'missing', 'HIGH', 'no User= directive; the unit runs as root. Set User= or DynamicUser=yes');
else if (/^root$/i.test(get('User') || '')) rec('User', 'weak', 'HIGH', 'User=root — run the service under a dedicated unprivileged account');
else rec('User', 'ok', 'INFO', `User=${get('User')}${yes('DynamicUser') ? ' DynamicUser=yes' : ''}`);

rec('NoNewPrivileges', yes('NoNewPrivileges') ? 'ok' : 'missing', 'HIGH', 'NoNewPrivileges=yes blocks setuid escalation');
const ps = get('ProtectSystem');
if (ps && /strict/.test(ps)) rec('ProtectSystem', 'ok', 'INFO', 'ProtectSystem=strict (whole FS read-only)');
else if (ps && /full/.test(ps)) rec('ProtectSystem', 'weak', 'MEDIUM', 'ProtectSystem=full leaves /home and /run writable');
else if (ps) rec('ProtectSystem', 'weak', 'MEDIUM', `ProtectSystem=${ps} is weaker than strict`);
else rec('ProtectSystem', 'missing', 'HIGH', 'without ProtectSystem the service can rewrite system files');
rec('ProtectHome', yes('ProtectHome') ? 'ok' : 'missing', 'MEDIUM', 'ProtectHome=yes hides /home,/root,/run/user');
rec('PrivateTmp', yes('PrivateTmp') ? 'ok' : 'missing', 'MEDIUM', 'PrivateTmp=yes isolates /tmp between units');
rec('PrivateDevices', yes('PrivateDevices') ? 'ok' : 'missing', 'LOW', 'PrivateDevices=yes removes raw device access');
rec('ProtectKernelTunables', yes('ProtectKernelTunables') ? 'ok' : 'missing', 'MEDIUM', 'ProtectKernelTunables=yes blocks sysctl writes');
rec('ProtectKernelModules', yes('ProtectKernelModules') ? 'ok' : 'missing', 'MEDIUM', 'ProtectKernelModules=yes blocks module loading');
rec('ProtectControlGroups', yes('ProtectControlGroups') ? 'ok' : 'missing', 'LOW', 'ProtectControlGroups=yes makes cgroupfs read-only');
rec('RestrictSUIDSGID', yes('RestrictSUIDSGID') ? 'ok' : 'missing', 'MEDIUM', 'RestrictSUIDSGID=yes drops setuid/setgid creation');
rec('RestrictNamespaces', yes('RestrictNamespaces') ? 'ok' : 'missing', 'LOW', 'RestrictNamespaces=yes blocks new namespaces (container escape)');
rec('LockPersonality', yes('LockPersonality') ? 'ok' : 'missing', 'LOW', 'LockPersonality=yes blocks personality(2) surprises');
rec('MemoryDenyWriteExecute', yes('MemoryDenyWriteExecute') ? 'ok' : 'missing', 'LOW', 'MemoryDenyWriteExecute=yes blocks JIT/writable-code pages');
rec('SystemCallFilter', get('SystemCallFilter') ? 'ok' : 'missing', 'MEDIUM', 'SystemCallFilter=~@privileged @resources narrows the syscall surface');

const caps = get('CapabilityBoundingSet');
const amb = get('AmbientCapabilities');
if (!caps && !amb) rec('CapabilityBoundingSet', 'missing', 'HIGH', 'no capability bounding set; the unit inherits all caps when running as root');
else if (/^$/m.test(caps)) rec('CapabilityBoundingSet', 'ok', 'INFO', 'CapabilityBoundingSet= (empty) drops every capability');
else rec('CapabilityBoundingSet', 'ok', 'INFO', `CapabilityBoundingSet=${caps}`);

const restart = get('Restart');
if (!restart || /^no$/i.test(restart)) rec('Restart', 'missing', 'HIGH', 'no restart policy; a crash leaves the service down');
else if (/^(always|on-failure)$/i.test(restart)) rec('Restart', 'ok', 'INFO', `Restart=${restart} RestartSec=${get('RestartSec') || '(default 100ms)'}`);
else if (/^on-abnormal/.test(restart)) rec('Restart', 'weak', 'LOW', `Restart=${restart} ignores clean exits`);

if (!get('TimeoutStopSec')) rec('TimeoutStopSec', 'missing', 'LOW', 'no TimeoutStopSec; a hung process delays every deploy by 90s');
if (!get('WatchdogSec') && get('Type') !== 'oneshot') rec('WatchdogSec', 'missing', 'LOW', 'no WatchdogSec; hung-but-alive processes are invisible');

const limits = ['MemoryMax', 'MemoryLimit', 'CPUQuota', 'TasksMax', 'LimitNOFILE'];
const present = limits.filter((k) => get(k));
if (!present.length) rec('ResourceLimits', 'missing', 'MEDIUM', 'no MemoryMax/CPUQuota/TasksMax; a leak can take the host down');
else rec('ResourceLimits', 'ok', 'INFO', present.map((k) => `${k}=${get(k)}`).join(' '));

if (/^root$/i.test(get('User') || '') && get('WorkingDirectory') === '/') rec('WorkingDirectory', 'weak', 'LOW', 'WorkingDirectory=/ with root user');
if (install.WantedBy) rec('Install', 'ok', 'INFO', `WantedBy=${install.WantedBy}`);
else rec('Install', 'missing', 'LOW', 'no [Install] WantedBy=; enable will not work');

const envs = (get('Environment') || '').match(/(PASS|SECRET|TOKEN|KEY)=/gi) || [];
if (envs.length) rec('Environment', 'weak', 'HIGH', `${envs.length} secret-looking Environment= entr${envs.length === 1 ? 'y' : 'ies'}; use EnvironmentFile= with mode 0600`);

const WEIGHT = { HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
const score = 100 - checks.reduce((a, c) => a + (c.state === 'ok' || c.state === 'INFO' ? 0 : WEIGHT[c.weight]), 0);
const problems = checks.filter((c) => c.state !== 'ok' && c.state !== 'INFO');

if (flag(o, 'json')) { emit({ file, unit: unit.Description || '', checks, problems: problems.length, score: Math.max(0, score) }); process.exit(0); }

console.log(`systemdunit: ${file}`);
console.log(`description: ${unit.Description || '(none)'}`);
console.log(`hardening score: ${Math.max(0, score)}/100  problems: ${problems.length}`);

if (flag(o, 'recommend')) {
  console.log('\n# append to [Service]');
  const block = [
    'NoNewPrivileges=yes', 'ProtectSystem=strict', 'ProtectHome=yes', 'PrivateTmp=yes', 'PrivateDevices=yes',
    'ProtectKernelTunables=yes', 'ProtectKernelModules=yes', 'ProtectControlGroups=yes', 'RestrictSUIDSGID=yes',
    'RestrictNamespaces=yes', 'LockPersonality=yes', 'MemoryDenyWriteExecute=yes', 'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX',
    'CapabilityBoundingSet=', 'SystemCallFilter=~@privileged @resources @raw-io',
    'Restart=on-failure', 'RestartSec=3', 'TimeoutStopSec=20', 'MemoryMax=512M', 'TasksMax=256',
    '# Writable paths the service genuinely needs:',
    '# ReadWritePaths=/var/lib/app /var/log/app',
  ];
  for (const b of block) console.log(b);
  process.exit(0);
}

const order = { HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3 };
console.log('');
console.log(table(checks.sort((a, b) => order[a.state === 'ok' ? 'INFO' : a.weight] - order[b.state === 'ok' ? 'INFO' : b.weight]).map((c) => ({ directive: c.id, state: c.state, severity: c.weight, detail: c.detail })), ['directive', 'state', 'severity', 'detail']));
process.exit(problems.some((p) => p.weight === 'HIGH') ? 1 : 0);
