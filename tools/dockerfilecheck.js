#!/usr/bin/env node
// dockerfilecheck.js — lint a Dockerfile.
// Copyright (c) 2026 0xnothings
// @tool dockerfilecheck
// @desc Dockerfile lint: latest tags, root user, ADD vs COPY, secrets in ARG/ENV, layer bloat, missing HEALTHCHECK and multi-stage opportunities
// @usage node tools/dockerfilecheck.js Dockerfile --json
// @tags devops,docker,dockerfile,audit
import { readFileSync, existsSync } from 'node:fs';
import { args, flag, die, emit, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`dockerfilecheck — Dockerfile linter

  node tools/dockerfilecheck.js <Dockerfile> [options]

  --json        machine-readable output
  --ignore <list>  comma list of rules to skip
  -h, --help    this text

  rules: latest-tag, root-user, add-instead-of-copy, secret-in-env, secret-in-arg,
         apt-no-clean, no-healthcheck, no-user, run-as-root-after-user, layer-count,
         multi-stage-hint, unpinned-package, curl-pipe-sh, no-sigcheck, copy-all,
         no-workdir, chmod-777, sudo-in-build, cache-invalidation`);
  process.exit(0);
}

const file = o._[0] || 'Dockerfile';
if (!existsSync(file)) die(`no such file: ${file}`);
const src = readFileSync(file, 'utf8');
const raw = src.split(/\r?\n/);

// join continuation lines (backslash at EOL outside of comments)
const instructions = [];
let buf = '', startLine = 0;
for (let i = 0; i < raw.length; i++) {
  const line = raw[i];
  if (!buf && (!line.trim() || /^\s*#/.test(line))) continue;
  if (!buf) startLine = i + 1;
  if (/\\\s*$/.test(line)) { buf += line.replace(/\\\s*$/, ' ') ; continue; }
  buf += line;
  instructions.push({ line: startLine, text: buf.trim() });
  buf = '';
}
if (buf.trim()) instructions.push({ line: startLine, text: buf.trim() });

const findings = [];
const ignoreRaw = o.f.ignore ? String(o.f.ignore).split(',').map((s) => s.trim()) : [];
const add = (rule, sev, line, msg) => { if (!ignoreRaw.includes(rule)) findings.push({ rule, severity: sev, line, message: msg }); };
const SECRET_NAME = /(PASS|PASSWD|PASSWORD|SECRET|TOKEN|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)/i;

let stageCount = 0;
const stages = [];
let currentStage = null;
let sawUser = false;
let userIsRoot = true;
let hasHealthcheck = false;
let runCount = 0, copyCount = 0;

for (const ins of instructions) {
  const m = ins.text.match(/^([A-Za-z]+)\s*(.*)$/s);
  if (!m) continue;
  const cmd = m[1].toUpperCase();
  const rest = m[2].trim();

  if (cmd === 'FROM') {
    stageCount++;
    const parts = rest.split(/\s+/);
    const image = parts[0];
    const asName = /as/i.test(parts[1] || '') ? parts[2] : null;
    if (asName) stageCount = stageCount; // named stage
    currentStage = { image, name: asName, line: ins.line, kind: parts[0] === 'scratch' ? 'scratch' : 'base' };
    stages.push(currentStage);
    sawUser = false; userIsRoot = true;
    const tag = image.includes('@sha256:') ? 'digest' : (image.split(':')[1] || '');
    if (tag === 'latest' || tag === '') add('latest-tag', 'MEDIUM', ins.line, `FROM ${image} — mutable tag; pin a version or use @sha256 digest for reproducible builds`);
    if (/^(ubuntu|debian|centos|alpine|python|node|golang)/i.test(image) && /:(latest|[0-9]+)$/.test(image)) add('unpinned-package', 'LOW', ins.line, `FROM ${image} — a major-only tag changes under you; pin the full version`);
    if (/as\s+\S+/i.test(rest) === false && stageCount === 1) add('multi-stage-hint', 'LOW', ins.line, 'no named build stage detected; multi-stage builds keep compilers and source out of the runtime image');
  }

  if (cmd === 'USER') {
    sawUser = true;
    userIsRoot = /^(root|0)(:|\s|$)/i.test(rest) || rest === 'root';
    if (userIsRoot) add('root-user', 'HIGH', ins.line, 'USER root — the container will run as root');
  }

  if (cmd === 'ADD') add('add-instead-of-copy', 'MEDIUM', ins.line, 'ADD does implicit tar extraction and remote fetch; use COPY unless you need those');

  if (cmd === 'ENV' || cmd === 'ARG') {
    for (const line of rest.split(/\n/)) {
      const kv = line.replace(/^\s*/, '').match(/^([A-Za-z_][A-Za-z0-9_]*)=(.+)$/);
      if (!kv) continue;
      const [, k, v] = kv;
      if (SECRET_NAME.test(k) || /^(AKIA[0-9A-Z]{16}|ghp_|sk_live)/.test(v)) {
        add(cmd === 'ARG' ? 'secret-in-arg' : 'secret-in-env', 'CRITICAL', ins.line, `${cmd} ${k}=... bakes a secret into the image layer; ARG values also persist in image history. Use BuildKit --secret or mount at runtime`);
      }
    }
  }

  if (cmd === 'RUN') {
    runCount++;
    const lines = [rest];
    if (/apt-get\s+install|apt\s+install/.test(rest) && !/rm -rf \/var\/lib\/apt\/lists/.test(rest)) {
      add('apt-no-clean', 'LOW', ins.line, 'apt-get install without cleaning /var/lib/apt/lists — bloats the layer by tens of MB');
    }
    if (!/--no-install-recommends/.test(rest) && /apt-get\s+install/.test(rest)) add('apt-no-clean', 'LOW', ins.line, 'apt-get install without --no-install-recommends pulls unnecessary packages');
    if (/curl[^|]*\|\s*(ba|z)?sh|wget[^|]*\|\s*(ba|z)?sh/.test(rest)) add('curl-pipe-sh', 'HIGH', ins.line, 'pipes a remote script straight into a shell with no integrity check');
    if (/apt-get\s+install(?![\s\S]*--no-install-recommends)/.test(rest) && !/apt-get\s+update/.test(rest) && !/apt-get\s+update/.test(src)) add('apt-no-clean', 'LOW', ins.line, 'apt-get install without a preceding apt-get update in the same RUN');
    if (/\bsudo\b/.test(rest)) add('sudo-in-build', 'MEDIUM', ins.line, 'sudo in a build is unnecessary — the builder already runs as root');
    if (/chmod\s+777/.test(rest)) add('chmod-777', 'HIGH', ins.line, 'chmod 777 inside the image');
    if (/npm\s+(install|i)\b(?![^|]*--production|.*--omit=dev)/.test(rest) && /node/.test(stages[0]?.image || '')) add('cache-invalidation', 'LOW', ins.line, 'npm install without --omit=dev installs devDependencies into the runtime image');
    if (/pip\s+install(?![^|]*--no-cache-dir)/.test(rest)) add('cache-invalidation', 'LOW', ins.line, 'pip install without --no-cache-dir leaves the wheel cache in the layer');
    if (/rm\s+-rf\s+\/(?!var\/lib\/apt|tmp|root\/\.cache)/.test(rest)) add('chmod-777', 'MEDIUM', ins.line, 'rm -rf against a broad root path inside the build');
  }

  if (cmd === 'COPY') {
    copyCount++;
    if (/^\S*\s+\.\s*$/.test(rest) || /^\S*\s+\.\/?\s*$/.test(rest) || /\s\.\s+/.test(rest)) add('copy-all', 'LOW', ins.line, 'COPY of the whole build context — use a .dockerignore and copy only what the layer needs');
  }

  if (cmd === 'HEALTHCHECK') hasHealthcheck = true;
  if (cmd === 'WORKDIR') { /* fine */ }
}

if (!hasHealthcheck) add('no-healthcheck', 'LOW', 0, 'no HEALTHCHECK — orchestrators cannot tell a hung container from a healthy one');
if (!instructions.some((i) => /^WORKDIR\b/i.test(i.text))) add('no-workdir', 'LOW', 0, 'no WORKDIR; files land in / and relative paths break');
const finalUser = [...instructions].reverse().find((i) => /^USER\b/i.test(i.text));
if (!finalUser) add('no-user', 'HIGH', 0, 'no USER instruction — the container runs as root by default');
else if (/^(root|0)\b/i.test(finalUser.text.replace(/^USER\s+/i, ''))) add('run-as-root-after-user', 'HIGH', finalUser.line, 'the last USER instruction is root; the runtime process runs as root');
if (runCount > 8) add('layer-count', 'LOW', 0, `${runCount} RUN instructions — combine related steps and lean on the build cache`);
if (copyCount > 4) add('layer-count', 'LOW', 0, `${copyCount} COPY instructions — each one is a layer and a cache boundary`);
if (!/^# syntax=docker\/dockerfile/m.test(src)) add('no-sigcheck', 'LOW', 0, 'no "# syntax=docker/dockerfile:1" directive; BuildKit features (--mount=type=cache, secrets) stay unavailable');
if (/FROM\s+\S+\s+as\s+build/i.test(src) === false && runCount > 3) add('multi-stage-hint', 'LOW', 0, 'build tooling appears to live in the same stage as runtime; a multi-stage build would shrink the image');

const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
for (const f of findings) counts[f.severity]++;
const failed = counts.CRITICAL > 0 || counts.HIGH > 0;

if (flag(o, 'json')) { emit({ file, stages: stages.map((s) => ({ image: s.image, name: s.name, line: s.line })), instructions: instructions.length, runSteps: runCount, copySteps: copyCount, findings, counts, pass: !failed }); process.exit(0); }

console.log(`dockerfilecheck: ${file}`);
console.log(`stages: ${stages.length}  instructions: ${instructions.length}  findings: ${findings.length}  critical: ${counts.CRITICAL} high: ${counts.HIGH} medium: ${counts.MEDIUM} low: ${counts.LOW}`);
console.log('');
console.log(table(stages.map((s, i) => ({ stage: i + 1, image: s.image, name: s.name || '-' })), ['stage', 'image', 'name']));
if (findings.length) {
  console.log('\nfindings:');
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  console.log(table(findings.sort((a, b) => order[a.severity] - order[b.severity]).map((f) => ({ severity: f.severity, line: f.line || '-', rule: f.rule, detail: f.message })), ['severity', 'line', 'rule', 'detail']));
} else console.log('\nno findings');
process.exit(failed ? 1 : 0);
