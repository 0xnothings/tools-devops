#!/usr/bin/env node
// envrc.js — explain a direnv .envrc and flag dangerous operations.
// Copyright (c) 2026 0xnothings
// @tool envrc
// @desc Parse .envrc: list exports and PATH changes, flag arbitrary shell execution, network fetches and missing `use` allow directives
// @usage node tools/envrc.js .envrc --json
// @tags devops,direnv,shell,audit
import { readFileSync, existsSync } from 'node:fs';
import { args, flag, die, emit, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`envrc — direnv config explainer

  node tools/envrc.js [.envrc] [options]

  --json        machine-readable output
  --resolve     also list which variables would be exported at the end
  -h, --help    this text

  Reports: exports, PATH mutations, load_dotenv/use directives, layout calls,
  and flags source/eval/curl-pipe-shell, secrets in plaintext and missing
  use/layout allow-listing.`);
  process.exit(0);
}

const file = o._[0] || '.envrc';
if (!existsSync(file)) die(`no such file: ${file} (pass a path)`);
const raw = readFileSync(file, 'utf8').split(/\r?\n/);

const exports_ = [];
const paths = [];
const uses = [];
const layouts = [];
const sources = [];
const findings = [];
const add = (sev, line, rule, msg) => findings.push({ severity: sev, line, rule, message: msg });

const SECRET = /(PASS|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL|DSN|CONN)/i;

for (let i = 0; i < raw.length; i++) {
  const line = raw[i];
  const t = line.trim();
  if (!t || t.startsWith('#')) continue;

  const exp = t.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
  if (exp) {
    let v = exp[2].trim();
    const quoted = /^['"]/.test(v);
    if (quoted) v = v.slice(1, -1);
    exports_.push({ name: exp[1], value: v, line: i + 1, quoted, expands: /\$\(|\$\{/.test(v) });
    if (SECRET.test(exp[1]) && !v.startsWith('$(') && !v.startsWith('op://') && !v.startsWith('$(pass')) {
      add('HIGH', i + 1, 'secret-inline', `${exp[1]} is set to a literal value in a file that is usually committed`);
    }
    if (/^PATH$/.test(exp[1])) {
      const dirs = v.split(':').filter(Boolean);
      paths.push({ line: i + 1, value: v, dirs });
      if (dirs.some((d) => d === '.' || d === '')) add('CRITICAL', i + 1, 'path-dot', 'PATH includes . or an empty component — any binary in the repo cwd wins');
    }
    continue;
  }

  const use = t.match(/^use\s+(\S+)\s*(.*)$/);
  if (use) { uses.push({ line: i + 1, helper: use[1], args: use[2] }); continue; }
  const layout = t.match(/^layout\s+(\S+)\s*(.*)$/);
  if (layout) { layouts.push({ line: i + 1, helper: layout[1], args: layout[2] }); continue; }
  const dotenv = t.match(/^dotenv(_if_exists)?\s*(\S*)$/);
  if (dotenv) { exports_.push({ name: `(load ${dotenv[2] || '.env'})`, value: '', line: i + 1, dotenv: true }); continue; }
  const watch = t.match(/^watch_file\s+(.+)$/);
  if (watch) continue;
  const src = t.match(/^(source|\.)\s+(.+)$/);
  if (src) { sources.push({ line: i + 1, target: src[2] }); add('HIGH', i + 1, 'source-external', `sources ${src[2]} — direnv executes any shell file it is pointed at, including a world-writable one`); continue; }
  if (/^PATH_add\s+(\S+)/.test(t)) { paths.push({ line: i + 1, value: t.split(/\s+/)[1], dirs: [t.split(/\s+/)[1]] }); continue; }

  if (/\beval\b/.test(t)) add('HIGH', i + 1, 'eval', 'eval of generated text — arbitrary code execution from whatever produced the string');
  if (/\$\(/.test(t)) add('MEDIUM', i + 1, 'command-substitution', 'command substitution runs at `direnv allow` time and again on every cd');
  if (/(curl|wget)[^|]*\|\s*(ba|z)?sh/.test(t)) add('CRITICAL', i + 1, 'curl-pipe-sh', 'fetches and executes a remote script on every directory entry');
  if (/\bsudo\b/.test(t)) add('CRITICAL', i + 1, 'sudo', 'sudo inside .envrc — directory entry triggers a privilege escalation prompt');
  if (/rm\s+-rf/.test(t)) add('HIGH', i + 1, 'rm-rf', 'rm -rf in .envrc runs whenever you cd here');
  if (/\bcd\s+\S+/.test(t)) add('LOW', i + 1, 'cd', 'changing directory inside .envrc surprises every tool that assumes cwd');
  if (/chmod\s+777/.test(t)) add('HIGH', i + 1, 'chmod-777', 'chmod 777');
  if (/export\s+PATH=/.test(t) && !/:\$PATH/.test(t)) add('MEDIUM', i + 1, 'path-overwrite', 'PATH overwritten rather than appended — system binaries disappear');
}

const hasAllow = existsSync('.envrc.allow') || (() => { try { return readFileSync('.envrc', 'utf8').includes('# allow:'); } catch { return false; } })();
const usesNet = exports_.some((e) => /https?:\/\//.test(e.value));
if (exports_.some((e) => /^https?:\/\//.test(e.value))) add('LOW', 0, 'remote-url', 'a remote URL is exported; make sure it is not fetched automatically');
if (!uses.length && !layouts.length) add('LOW', 0, 'no-use-helper', 'no `use` or `layout` helper; raw shell is harder to audit than the built-in helpers');

// final export resolution
const resolved = new Map();
for (const e of exports_) { if (e.dotenv) continue; if (!e.expands) resolved.set(e.name, e.value); else resolved.set(e.name, `<dynamic: ${e.value.slice(0, 40)}>`); }

const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
for (const f of findings) counts[f.severity]++;

if (flag(o, 'json')) {
  emit({
    file, exports: exports_.map((e) => ({ name: e.name, value: SECRET.test(e.name) ? '***' : e.value, line: e.line, dynamic: e.expands })).map((e) => ({ ...e })),
    pathChanges: paths, use: uses, layout: layouts, sources, findings, counts,
    resolved: flag(o, 'resolve') ? Object.fromEntries([...resolved].map(([k, v]) => [k, SECRET.test(k) ? '***' : v])) : undefined,
    worst: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].find((s) => counts[s]) || 'NONE',
  });
  process.exit(counts.CRITICAL ? 2 : counts.HIGH ? 1 : 0);
}

console.log(`envrc: ${file}`);
console.log(`exports: ${exports_.length}  path changes: ${paths.length}  use: ${uses.length}  findings: ${findings.length}`);
if (exports_.length) {
  console.log('');
  console.log(table(exports_.map((e) => ({ line: e.line, name: e.name, value: SECRET.test(e.name) ? '*** masked ***' : (e.value.length > 44 ? e.value.slice(0, 41) + '...' : e.value) || '(empty)' })), ['line', 'name', 'value']));
}
if (paths.length) {
  console.log('\nPATH changes:');
  console.log(table(paths.map((p) => ({ line: p.line, dirs: p.dirs.join(' ') || '(empty)' })), ['line', 'dirs']));
}
if (uses.length || layouts.length) {
  console.log('\nhelpers:');
  console.log(table([...uses.map((u) => ({ line: u.line, kind: 'use', target: `${u.helper} ${u.args}`.trim() })), ...layouts.map((l) => ({ line: l.line, kind: 'layout', target: `${l.helper} ${l.args}`.trim() }))], ['line', 'kind', 'target']));
}
if (findings.length) {
  console.log('\nfindings:');
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  console.log(table(findings.sort((a, b) => order[a.severity] - order[b.severity]).map((f) => ({ severity: f.severity, line: f.line || '-', rule: f.rule, detail: f.message })), ['severity', 'line', 'rule', 'detail']));
} else console.log('\nno findings');
if (flag(o, 'resolve')) {
  console.log('\nwould export:');
  for (const [k, v] of resolved) console.log(`  ${k}=${SECRET.test(k) ? '***' : v}`);
}
process.exit(counts.CRITICAL ? 2 : counts.HIGH ? 1 : 0);
