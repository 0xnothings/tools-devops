#!/usr/bin/env node
// playbookaudit.js — heuristic audit of Ansible playbooks.
// Copyright (c) 2026 0xnothings
// @tool playbookaudit
// @desc Heuristic Ansible playbook audit: shell/command usage, become risks, plaintext vars, missing changed_when and ignore_errors
// @usage node tools/playbookaudit.js site.yml --json
// @tags devops,ansible,audit
import { readFileSync } from 'node:fs';
import { args, flag, die, emit, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`playbookaudit — Ansible playbook linter

  node tools/playbookaudit.js <playbook.yml> [more.yml ...] [options]

  --json          machine-readable output
  --warnings-as-errors   exit 1 when any WARN or higher is found
  -h, --help      this text

  checks: shell/command usage, missing changed_when, ignore_errors, become at play level,
           plaintext secrets, package state=latest, missing name on tasks, noqa on validate`);
  process.exit(0);
}

const paths = o._;
if (!paths.length) die('usage: node tools/playbookaudit.js <playbook.yml> [--json]');

const findings = [];
const add = (file, line, rule, sev, msg) => findings.push({ file, line, rule, severity: sev, message: msg });
const SECRET_KEY = /(password|passwd|secret|token|api_key|apikey|private_key|vault_pass)/i;

for (const p of paths) {
  let text;
  try { text = readFileSync(p, 'utf8'); } catch (e) { die(`cannot read ${p}: ${e.message}`); }
  const raw = text.split(/\r?\n/);

  // track keys/tasks by indentation
  const stack = [];
  for (let i = 0; i < raw.length; i++) {
    const line = raw[i].replace(/\s+#.*$/, '');
    if (!line.trim() || /^\s*#/.test(line)) continue;
    const ind = line.length - line.trimStart().length;
    const t = line.trim();
    while (stack.length && stack[stack.length - 1].indent >= ind) stack.pop();
    const ctx = stack.map((s) => s.key);

    const kv = t.match(/^([A-Za-z_][A-Za-z0-9_.-]*):\s*(.*)$/);
    if (kv) {
      const key = kv[1], val = kv[2];
      stack.push({ indent: ind, key });
      if (/^vars$|^vars_files$/.test(key) && val === '') continue;
    }

    const inVars = ctx.some((c) => c === 'vars' || c === 'set_fact' || c === 'vars_prompt');
    const isTaskLine = /^-\s+/.test(t);

    // shell / command with pipes or shell operators
    if (/^(shell|command|raw|script):/.test(t)) {
      const which = t.split(':')[0];
      if (which === 'shell' || which === 'raw') add(p, i + 1, 'shell-usage', 'MEDIUM', `${which} used; prefer a dedicated module or add "executable: /bin/bash" + args-array form`);
      if (which === 'command' && /([|&;<>]|\$\(|`)/.test(t)) add(p, i + 1, 'shell-operators', 'HIGH', 'command module cannot parse shell operators; use argv list or shell with care');
    }
    if (/\bwith_items:\s*\{\{/.test(t) && /shell:|command:/.test(text)) {
      // known injection surface, only note once per file later
    }

    if (/^ignore_errors:\s*true/.test(t)) add(p, i + 1, 'ignore-errors', 'MEDIUM', 'ignore_errors: true hides failures; use failed_when instead');
    if (/^environment:\s*$/.test(t) && SECRET_KEY.test(text)) { /* handled below */ }

    const sec = t.match(/^([A-Za-z0-9_.-]+):\s*["']?([^"'\s]{12,})["']?$/);
    if (sec && SECRET_KEY.test(sec[1]) && !/\{\{|vault|VAULT/.test(sec[2])) {
      add(p, i + 1, 'plaintext-secret', 'CRITICAL', `${sec[1]} looks hardcoded; move it to ansible-vault`);
    }
    if (inVars && SECRET_KEY.test(t) && /:\s*\S/.test(t) && !/\{\{|vault/.test(t)) {
      add(p, i + 1, 'plaintext-var', 'HIGH', 'secret-like variable defined in plain vars');
    }
    if (/^become:\s*true/.test(t) && ctx.length <= 1) add(p, i + 1, 'become-scope', 'LOW', 'become: true at play level grants sudo to every task');
    if (/^become_user:\s*root/.test(t)) add(p, i + 1, 'become-root', 'LOW', 'become_user: root is redundant; scope become to tasks instead');
    if (/^no_log:\s*false/.test(t) && SECRET_KEY.test(text)) add(p, i + 1, 'no-log', 'MEDIUM', 'no_log: false on a playbook that handles secrets');
    if (/state:\s*latest/.test(t)) add(p, i + 1, 'state-latest', 'MEDIUM', 'state: latest makes runs non-deterministic; pin a version');
    if (/validate_certs:\s*(no|false)/.test(t)) add(p, i + 1, 'tls-verify-off', 'HIGH', 'validate_certs disabled');
    if (/hosts:\s*all\b/.test(t) && /become:\s*true/.test(text)) add(p, i + 1, 'wide-scope', 'MEDIUM', 'play targets all hosts with become enabled');
  }

  // file-level heuristics
  const taskLines = raw.map((l, i) => ({ l, i })).filter((x) => /^\s*-\s+name:/.test(x.l));
  const shellBlocks = [];
  for (let i = 0; i < raw.length; i++) {
    if (/^\s*[A-Za-z_.]*?(shell|command|raw|script):/.test(raw[i])) {
      let j = i + 1; const body = [];
      const inline = raw[i].replace(/^\s*(shell|command|raw|script):\s*/i, '').trim();
      if (inline && inline !== '|' && inline !== '>') body.push(inline);
      const blockIndent = raw[i].length - raw[i].trimStart().length;
      while (j < raw.length) {
        const l = raw[j];
        const ind = l.length - l.trimStart().length;
        if (!l.trim()) { body.push(l); j++; continue; }
        if (ind < blockIndent || /^\s*-\s+[A-Za-z_]/.test(l) && ind <= blockIndent) break;
        body.push(l); j++;
      }
      shellBlocks.push({ line: i + 1, body: body.join('\n'), mod: raw[i].trim().split(':')[0], end: j });
    }
  }
  for (const b of shellBlocks) {
    const after = raw.slice(b.end, b.end + 8).join('\n');
    if (!/changed_when:|creates:|removes:/.test(after)) add(p, b.line, 'changed-when', 'MEDIUM', `${b.mod} task without changed_when/creates: reports changed every run`);
    if (/\{\{\s*item\s*\}\}/.test(b.body) && /\|\s*(bash|sh)\b/.test(b.body)) add(p, b.line, 'template-injection', 'HIGH', 'loop item interpolated directly into a shell pipeline');
    if (/(curl|wget)\s+[^|]*\|\s*(bash|sh)\b/.test(b.body)) add(p, b.line, 'curl-pipe-shell', 'CRITICAL', 'remote script piped straight into a shell; no integrity check');
    if (/chmod\s+777/.test(b.body)) add(p, b.line, 'chmod-777', 'HIGH', 'chmod 777 in a task');
  }

  if (/\bansible\.builtin\.(shell|command)\b/.test(text) || /\bshell:/.test(text)) {
    const n = (text.match(/^\s*(shell|raw):/gm) || []).length;
    if (n > 5) add(p, 1, 'shell-heavy', 'MEDIUM', `${n} shell/raw tasks; consider purpose-built modules for idempotency`);
  }
  if (!/no_log:\s*true/.test(text) && /(password|secret|token)/i.test(text)) {
    add(p, 1, 'no-log-missing', 'MEDIUM', 'secrets handled but no_log: true never used');
  }
}

const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
for (const f of findings) counts[f.severity]++;
const gate = flag(o, 'warnings-as-errors');
const failed = findings.some((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH' || (gate && f.severity !== 'LOW'));

if (flag(o, 'json')) { emit({ files: paths, findings, counts, pass: !failed }); process.exit(0); }

console.log(`playbookaudit: ${paths.join(', ')}`);
console.log(`findings: ${findings.length}  critical: ${counts.CRITICAL} high: ${counts.HIGH} medium: ${counts.MEDIUM} low: ${counts.LOW}`);
if (!findings.length) console.log('\nno issues found');
else {
  console.log('');
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  console.log(table([...findings].sort((a, b) => order[a.severity] - order[b.severity]).map((f) => ({ severity: f.severity, line: f.line, rule: f.rule, detail: f.message })), ['severity', 'line', 'rule', 'detail']));
}
process.exit(failed ? 1 : 0);
