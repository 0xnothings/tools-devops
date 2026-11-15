// composecheck.js — lint docker-compose.yml for security and reliability gaps.
// Copyright (c) 2026 0xnothings
// @tool composecheck
// @desc Lint docker-compose files for privileged mode, host-exposed ports, missing restart/healthcheck/resource limits and inline secrets
// @usage node tools/composecheck.js docker-compose.yml --json
// @tags devops,docker,audit
import { readFileSync } from 'node:fs';
import { args, get, flag, die, emit, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`composecheck — docker-compose linter

  node tools/composecheck.js <docker-compose.yml> [options]

  --json            machine-readable output
  --no-policy       skip restart-policy check
  --only <list>     comma list of rules to run
  -h, --help        this text

  rules: restart, ports, privileged, healthcheck, secrets, limits, volumes, user, network`);
  process.exit(0);
}

const path = o._[0];
if (!path) die('usage: node tools/composecheck.js <docker-compose.yml> [--json]');
let src;
try { src = readFileSync(path, 'utf8'); } catch (e) { die(`cannot read ${path}: ${e.message}`); }

const SECRET_RE = /(pass(word)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)/i;
const KNOWN_SECRET_VALUE = /(AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|ghp_[A-Za-z0-9]{20,}|xox[baprs]-)/;

function parseCompose(text) {
  const services = {};
  let inServices = false, cur = null, curIndent = -1;
  const raw = text.split(/\r?\n/);
  const blocks = {};
  for (let i = 0; i < raw.length; i++) {
    const line = raw[i];
    const noComment = line.replace(/\s+#.*$/, '');
    if (!noComment.trim()) continue;
    const indent = noComment.length - noComment.trimStart().length;
    const trimmed = noComment.trim();
    if (/^services:\s*$/.test(trimmed)) { inServices = true; cur = null; curIndent = -1; continue; }
    if (inServices && indent === 0 && /^[A-Za-z0-9_.-]+:\s*$/.test(trimmed)) { inServices = false; cur = null; continue; }
    if (!inServices) continue;
    const svcMatch = trimmed.match(/^([A-Za-z0-9_.-]+):\s*$/);
    if (svcMatch && (curIndent === -1 || indent <= curIndent)) {
      cur = svcMatch[1]; curIndent = indent;
      services[cur] = { name: cur, keyIndent: null, body: [] };
      continue;
    }
    if (cur) services[cur].body.push({ indent, text: trimmed });
  }
  for (const s of Object.values(services)) {
    let base = null;
    for (const b of s.body) { if (base === null) base = b.indent; if (b.indent === base) { s.keyIndent = base; break; } }
  }
  return services;
}

function svcGet(svc, key) {
  const b = svc.keyIndent;
  if (b === null) return null;
  const idx = svc.body.findIndex((l) => l.indent === b && l.text.startsWith(key + ':'));
  if (idx === -1) return null;
  const head = svc.body[idx].text.slice(key.length + 1).trim();
  const items = [];
  for (let j = idx + 1; j < svc.body.length; j++) {
    if (svc.body[j].indent <= b) break;
    items.push(svc.body[j]);
  }
  return { head, items };
}

function listValues(entry) {
  if (!entry) return [];
  const out = [];
  if (entry.head && entry.head !== '') out.push(...entry.head.replace(/^\[|\]$/g, '').split(',').map((x) => x.trim().replace(/^['"]|['"]$/g, '')).filter(Boolean));
  for (const it of entry.items) {
    const m = it.text.match(/^-\s*(.+)$/);
    if (m) out.push(m[1].trim().replace(/^['"]|['"]$/g, ''));
  }
  return out;
}

function kvMap(entry) {
  const out = {};
  if (!entry) return out;
  for (const it of entry.items) {
    const m = it.text.match(/^([A-Za-z0-9_.-]+):\s*(.*)$/);
    if (m) out[m[1]] = m[2].trim().replace(/^['"]|['"]$/g, '');
  }
  return out;
}

const services = parseCompose(src);
const findings = [];
const add = (svc, rule, sev, msg) => findings.push({ service: svc, rule, severity: sev, message: msg });

const onlyRaw = get(o, 'only', '');
const only = onlyRaw ? String(onlyRaw).split(',').map((s) => s.trim()).filter(Boolean) : null;
const want = (r) => !only || only.includes(r);

for (const svc of Object.values(services)) {
  const restart = svcGet(svc, 'restart');
  if (want('restart') && !restart) add(svc.name, 'restart', 'MEDIUM', 'no restart policy (add restart: unless-stopped)');
  if (want('restart') && restart && /^(no|false)$/i.test((restart.head || '').trim())) add(svc.name, 'restart', 'MEDIUM', 'restart: no — a crash leaves the container down until someone notices');

  const ports = listValues(svcGet(svc, 'ports'));
  for (const p of ports) {
    const clean = p.replace(/^['"]|['"]$/g, '');
    if (!want('ports')) break;
    const host = clean.split(':');
    const containerPort = host[host.length - 1].split('/')[0];
    const ipPart = host.length >= 3 ? host[0] : null;
    if (host.length === 1) add(svc.name, 'ports', 'HIGH', `port ${clean} publishes on every interface; bind 127.0.0.1:${containerPort}`);
    else if (ipPart === null && host.length === 2) add(svc.name, 'ports', 'HIGH', `port ${clean} publishes on every interface (docker defaults to 0.0.0.0); bind 127.0.0.1:${clean}`);
    else if (ipPart === '' || ipPart === '0.0.0.0' || ipPart === '::') add(svc.name, 'ports', 'HIGH', `port ${clean} publishes on every interface; bind 127.0.0.1:${containerPort}`);
  }

  const priv = listValues(svcGet(svc, 'privileged'));
  const privHead = svcGet(svc, 'privileged');
  if (want('privileged') && privHead && /true/i.test(privHead.head || '')) add(svc.name, 'privileged', 'CRITICAL', 'privileged: true gives full host device access');

  const hc = svcGet(svc, 'healthcheck');
  if (want('healthcheck') && !hc) add(svc.name, 'healthcheck', 'LOW', 'no healthcheck (orchestrator cannot detect a hung container)');

  const env = listValues(svcGet(svc, 'environment'));
  for (const e of env) {
    const m = e.match(/^([A-Za-z0-9_.-]+)\s*[=:]\s*(.+)$/);
    if (!m) continue;
    const [, k, v] = m;
    if (want('secrets') && (SECRET_RE.test(k) || KNOWN_SECRET_VALUE.test(v)) && !/^\$\{/.test(v)) {
      add(svc.name, 'secrets', 'HIGH', `secret in environment (${k}); use docker secrets or an env_file outside VCS`);
    }
  }

  const limits = svcGet(svc, 'deploy');
  const memLimit = svcGet(svc, 'mem_limit');
  const cpus = svcGet(svc, 'cpus');
  if (want('limits') && !limits && !memLimit && !cpus) add(svc.name, 'limits', 'MEDIUM', 'no memory/cpu limits (a runaway container can starve the host)');

  const vols = listValues(svcGet(svc, 'volumes'));
  for (const v of vols) {
    if (/^\/var\/run\/docker\.sock/.test(v)) add(svc.name, 'volumes', 'CRITICAL', 'docker.sock mounted; container effectively root on host');
    else if (/^\/:\//.test(v) || /:\/($|\s)/.test(v) && v.startsWith('/')) add(svc.name, 'volumes', 'HIGH', `host root path mounted: ${v}`);
  }

  const user = svcGet(svc, 'user');
  if (want('user') && (!user || /^(root|0)$/.test((user.head || '').trim()))) add(svc.name, 'user', 'MEDIUM', 'runs as root (set user: "1000:1000")');

  const net = svcGet(svc, 'network_mode');
  if (want('network') && net && /host/.test(net.head || '')) add(svc.name, 'network', 'HIGH', 'network_mode: host bypasses container network isolation');
}

const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;

if (flag(o, 'json')) {
  emit({ file: path, services: Object.keys(services).length, findings, counts, pass: findings.length === 0 });
  process.exit(0);
}

console.log(`composecheck: ${path}`);
console.log(`services: ${Object.keys(services).length}  findings: ${findings.length}  critical: ${counts.CRITICAL} high: ${counts.HIGH} medium: ${counts.MEDIUM} low: ${counts.LOW}`);
if (!findings.length) console.log('\nno issues found');
else {
  console.log('');
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const sorted = [...findings].sort((a, b) => order[a.severity] - order[b.severity]);
  console.log(table(sorted.map((f) => ({ severity: f.severity, service: f.service, rule: f.rule, detail: f.message })), ['severity', 'service', 'rule', 'detail']));
}
process.exit(findings.some((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH') ? 1 : 0);
