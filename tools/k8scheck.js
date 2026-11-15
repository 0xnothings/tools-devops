#!/usr/bin/env node
// k8scheck.js — audit Kubernetes manifests for security and reliability gaps.
// Copyright (c) 2026 0xnothings
// @tool k8scheck
// @desc Audit Kubernetes YAML manifests for privileged containers, root users, latest tags, missing probes/limits and hostPath mounts
// @usage node tools/k8scheck.js deploy.yaml --json
// @tags devops,kubernetes,audit
import { readFileSync } from 'node:fs';
import { args, flag, die, emit, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`k8scheck — Kubernetes manifest auditor

  node tools/k8scheck.js <manifest.yaml> [more.yaml ...] [options]

  --json        machine-readable output
  --strict      treat MEDIUM findings as failures
  -h, --help    this text

  checks: securityContext, runAsNonRoot, image tags, resources, probes, hostPath, privileged, capabilities, hostNetwork`);
  process.exit(0);
}

const paths = o._.length ? o._ : [];
if (!paths.length) die('usage: node tools/k8scheck.js <manifest.yaml> [--json]');

let src = '';
for (const p of paths) {
  try { src += '\n---\n' + readFileSync(p, 'utf8'); }
  catch (e) { die(`cannot read ${p}: ${e.message}`); }
}

// split multi-doc YAML
const docs = src.split(/^---\s*$/m).map((d) => d.trim()).filter(Boolean);

function indentOf(l) { return l.length - l.trimStart().length; }

// Extremely small YAML walker: tracks a stack of {indent,key} to produce dotted paths.
function flatten(text) {
  const out = [];
  const stack = [];
  const raw = text.split(/\r?\n/);
  for (let i = 0; i < raw.length; i++) {
    const line = raw[i].replace(/\s+#.*$/, '');
    if (!line.trim() || /^\s*#/.test(line)) continue;
    const ind = indentOf(line);
    const t = line.trim();
    while (stack.length && stack[stack.length - 1].indent >= ind) stack.pop();
    const parent = stack.map((s) => s.key).join('.');
    const listItem = t.match(/^-\s*(.*)$/);
    let key = null, val = null;
    if (listItem) {
      const body = listItem[1];
      const inner = body.match(/^([A-Za-z0-9_.\-\/]+):\s*(.*)$/);
      if (inner) { key = inner[1]; val = inner[2]; }
      else { val = body; }
      const p = parent ? parent.split('.').filter(Boolean) : [];
      out.push({ path: p.join('.'), key: '-', value: body, indent: ind, line: i + 1 });
      if (inner) stack.push({ indent: ind + 2, key: inner[1] });
      continue;
    }
    const kv = t.match(/^([A-Za-z0-9_.\-\/\$]+):\s*(.*)$/);
    if (!kv) continue;
    key = kv[1]; val = kv[2];
    const full = parent ? `${parent}.${key}` : key;
    out.push({ path: full, key, value: val, indent: ind, line: i + 1 });
    if (val === '' || val === '|' || val === '>') stack.push({ indent: ind, key });
  }
  return out;
}

const findings = [];
const add = (kind, sev, where, msg) => findings.push({ object: where, severity: sev, message: msg });

for (const doc of docs) {
  const flat = flatten(doc);
  const kindLine = flat.find((f) => f.path === 'kind');
  const kind = kindLine ? kindLine.value.trim() : 'unknown';
  const nameLine = flat.find((f) => /^metadata\.name$/.test(f.path));
  const objName = nameLine ? nameLine.value.trim() : '(unnamed)';
  if (kind !== 'Pod' && kind !== 'Deployment' && kind !== 'StatefulSet' && kind !== 'DaemonSet' && kind !== 'Job' && kind !== 'CronJob' && kind !== 'ReplicaSet') {
    continue;
  }
  const where = `${kind}/${objName}`;

  const images = flat.filter((f) => /image$/.test(f.path));
  for (const im of images) {
    const v = im.value.trim().replace(/^['"]|['"]$/g, '');
    if (!v) continue;
    const tag = v.includes('@') ? 'digest' : (v.split('/').pop().split(':')[1] || '');
    if (tag === 'latest' || tag === '') add('image', 'HIGH', where, `image "${v}" uses a mutable tag (${tag || 'none'}); pin a version or digest`);
  }

  const hasSecurityContext = flat.some((f) => /securityContext$/.test(f.path));
  if (!hasSecurityContext) add('securityContext', 'MEDIUM', where, 'no securityContext defined');

  const runAsNonRoot = flat.find((f) => /^(spec\.)?[A-Za-z0-9.]*runAsNonRoot$/.test(f.path));
  if (!runAsNonRoot || !/true/.test(runAsNonRoot.value)) add('runAsNonRoot', 'MEDIUM', where, 'runAsNonRoot not set to true');

  const privileged = flat.filter((f) => /privileged$/.test(f.path) && /true/i.test(f.value));
  for (const p of privileged) add('privileged', 'CRITICAL', where, `privileged: true at ${p.path} (line ~${p.line})`);

  const allowPrivEsc = flat.filter((f) => /allowPrivilegeEscalation$/.test(f.path));
  for (const a of allowPrivEsc) if (!/false/.test(a.value)) add('allowPrivEsc', 'MEDIUM', where, 'allowPrivilegeEscalation should be false');
  if (!allowPrivEsc.length && hasSecurityContext) add('allowPrivEsc', 'LOW', where, 'allowPrivilegeEscalation not set (defaults true)');

  const hostPath = flat.filter((f) => /hostPath$/.test(f.path));
  if (hostPath.length) add('hostPath', 'HIGH', where, `${hostPath.length} hostPath volume(s) mount the node filesystem`);

  const hostNetwork = flat.find((f) => /hostNetwork$/.test(f.path) && /true/.test(f.value));
  if (hostNetwork) add('hostNetwork', 'HIGH', where, 'hostNetwork: true shares the node network namespace');

  const hostPID = flat.find((f) => /hostPID$/.test(f.path) && /true/.test(f.value));
  if (hostPID) add('hostPID', 'CRITICAL', where, 'hostPID: true can read/inject other processes on the node');

  const caps = flat.filter((f) => /capabilities\.add$/.test(f.path));
  if (caps.length) {
    const items = flat.filter((f) => f.key === '-' && /capabilities\.add$/.test(f.path));
    const names = items.map((i) => i.value.trim()).filter(Boolean);
    if (names.some((c) => /^(ALL|SYS_ADMIN|NET_ADMIN|SYS_PTRACE)$/i.test(c))) {
      add('capabilities', 'HIGH', where, `dangerous capabilities added: ${names.join(',')}`);
    } else if (names.length) add('capabilities', 'LOW', where, `capabilities added: ${names.join(',')}`);
  }

  const limits = flat.some((f) => /resources\.limits\.(cpu|memory)$/.test(f.path));
  const requests = flat.some((f) => /resources\.requests\.(cpu|memory)$/.test(f.path));
  if (!limits) add('resources', 'MEDIUM', where, 'no resource limits (a noisy pod can evict neighbours)');
  if (!requests) add('resources', 'MEDIUM', where, 'no resource requests (scheduler cannot place the pod)');

  const hasLiveness = flat.some((f) => /livenessProbe$/.test(f.path));
  const hasReadiness = flat.some((f) => /readinessProbe$/.test(f.path));
  if (!hasLiveness) add('probe', 'MEDIUM', where, 'no livenessProbe');
  if (!hasReadiness) add('probe', 'MEDIUM', where, 'no readinessProbe');

  const reads = flat.some((f) => /readOnlyRootFilesystem$/.test(f.path) && /true/.test(f.value));
  if (!reads) add('readOnlyRootFS', 'LOW', where, 'readOnlyRootFilesystem not enabled');
}

const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
for (const f of findings) counts[f.severity]++;
const strict = flag(o, 'strict');
const failed = findings.some((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH' || (strict && f.severity === 'MEDIUM'));

if (flag(o, 'json')) { emit({ files: paths, findings, counts, pass: !failed }); process.exit(0); }

console.log(`k8scheck: ${paths.join(', ')}`);
console.log(`findings: ${findings.length}  critical: ${counts.CRITICAL} high: ${counts.HIGH} medium: ${counts.MEDIUM} low: ${counts.LOW}`);
if (findings.length) {
  console.log('');
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  console.log(table([...findings].sort((a, b) => order[a.severity] - order[b.severity]).map((f) => ({ severity: f.severity, object: f.object, detail: f.message })), ['severity', 'object', 'detail']));
} else console.log('\nno issues found');
process.exit(failed ? 1 : 0);
