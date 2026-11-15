// makefile.js — parse and explain a Makefile.
// Copyright (c) 2026 0xnothings
// @tool makefile
// @desc Parse a Makefile: list targets with doc comments, show variables, and flag .PHONY gaps plus dangerous targets
// @usage node tools/makefile.js Makefile --json
// @tags devops,make,build
import { readFileSync, existsSync } from 'node:fs';
import { args, flag, die, emit, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`makefile — Makefile explainer

  node tools/makefile.js [Makefile] [options]

  --json            machine-readable output
  --target <name>   print the recipe for one target
  --list            print only the target list (tab-completion friendly)
  -h, --help        this text

  Reports: targets (with ## doc comments), variables, .PHONY coverage,
           dangerous recipes (rm -rf, sudo, curl|sh) and missing .DEFAULT_GOAL`);
  process.exit(0);
}

const file = o._[0] || 'Makefile';
if (!existsSync(file)) die(`no such file: ${file} (pass a path or run from the repo root)`);

const raw = readFileSync(file, 'utf8').split(/\r?\n/);
const targets = [];
const vars = new Map();
const phony = new Set();
const includes = [];
const dangerous = [];

const SPECIAL = new Set(['.PHONY', '.DEFAULT_GOAL', '.SUFFIXES', '.INTERMEDIATE', '.PRECIOUS', '.SECONDARY', '.DELETE_ON_ERROR', '.ONESHELL', '.NOTPARALLEL', '.EXPORT_ALL_VARIABLES']);

for (let i = 0; i < raw.length; i++) {
  const line = raw[i];
  if (/^\s*#/.test(line)) continue;
  if (!line.trim()) continue;

  const inc = line.match(/^-?include\s+(.+)$/);
  if (inc) { includes.push(inc[1].trim()); continue; }

  const assign = line.match(/^\s*(?:export\s+|override\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*(\?=|:=|::=|\+=|!=|=)\s*(.*)$/);
  if (assign && !line.includes(':') || assign && assign[2].startsWith(':')) {
    const [, k, op, v] = assign;
    if (!vars.has(k)) vars.set(k, { key: k, op, value: v.trim(), line: i + 1 });
    continue;
  }

  const ph = line.match(/^\.PHONY:\s*(.*)$/);
  if (ph) { ph[1].split(/\s+/).filter(Boolean).forEach((x) => phony.add(x)); continue; }

  const rule = line.match(/^([A-Za-z0-9_%$()\{\}.\/\-][^:=]*?)\s*::?\s*(.*)$/);
  if (rule && !/^\t/.test(line)) {
    const tname = rule[1].trim();
    if (SPECIAL.has(tname)) continue;
    if (!tname || tname.includes('=')) continue;
    const docAbove = raw.slice(Math.max(0, i - 5), i).reverse().find((l) => /^#/.test(l.trim()));
    const docInline = rule[2].match(/##\s*(.+)$/);
    const deps = rule[2].replace(/##.*$/, '').trim();
    // gather recipe
    const recipe = [];
    let j = i + 1;
    while (j < raw.length && (/^\t/.test(raw[j]) || (raw[j].trim() === '' && raw[j + 1] && /^\t/.test(raw[j + 1])))) { recipe.push(raw[j]); j++; }
    targets.push({
      name: tname,
      deps,
      doc: docInline ? docInline[1].trim() : (docAbove ? docAbove.replace(/^#+\s?/, '').trim() : ''),
      line: i + 1,
      recipe: recipe.join('\n'),
    });
    for (const r of recipe) {
      const txt = r.replace(/^[\t@+\-]+/, '');
      if (/rm\s+-[a-z]*r[a-z]*f|rm\s+-[a-z]*f[a-z]*r/.test(txt)) {
        if (/\$\(\w+\)/.test(txt) || /\$\{\w+\}/.test(txt)) {
          const v = txt.match(/\$\((\w+)\)|\$\{(\w+)\}/)[1] || txt.match(/\$\((\w+)\)|\$\{(\w+)\}/)[2];
          const val = vars.get(v);
          if (!val || !val.value || /^\/?$/.test(val.value)) dangerous.push({ target: tname, line: i + 1, severity: 'CRITICAL', message: `rm -rf on $(${v}) with ${val ? 'undefined' : 'empty'} value` });
        } else if (/rm\s+-[a-z]*r[a-z]*f\s+(\/|\*|~|\$HOME)\b/.test(txt)) dangerous.push({ target: tname, line: i + 1, severity: 'CRITICAL', message: 'rm -rf against a root/glob/home path' });
      }
      if (/curl[^|]*\|\s*(ba|z)?sh/.test(txt)) dangerous.push({ target: tname, line: i + 1, severity: 'HIGH', message: 'pipes a remote script into a shell' });
      if (/^\s*sudo\s/.test(txt)) dangerous.push({ target: tname, line: i + 1, severity: 'MEDIUM', message: 'recipe calls sudo (build should not need it)' });
      if (/chmod\s+777/.test(txt)) dangerous.push({ target: tname, line: i + 1, severity: 'MEDIUM', message: 'chmod 777 in recipe' });
    }
    i = j - 1;
  }
}

const defaultGoal = raw.map((l) => l.match(/^\.DEFAULT_GOAL\s*:?=\s*(\S+)/)).filter(Boolean).map((m) => m[1])[0] || (targets[0] ? targets[0].name : null);
const fileTargets = targets.filter((t) => t.name.includes('.') || t.name.includes('/'));
const missingPhony = targets.filter((t) => !phony.has(t.name) && !existsSync(t.name) && !t.name.includes('%') && !t.name.includes('$'));

if (flag(o, 'json')) {
  emit({
    file, targets: targets.map(({ name, deps, doc, line }) => ({ name, deps, doc, line })),
    variables: [...vars.values()], phony: [...phony], includes, defaultGoal,
    dangerous, missingPhony: missingPhony.map((t) => t.name),
    counts: { targets: targets.length, variables: vars.size, dangerous: dangerous.length, missingPhony: missingPhony.length },
  });
  process.exit(0);
}

if (flag(o, 'list')) {
  for (const t of targets) console.log(t.doc ? `${t.name}\t${t.doc}` : t.name);
  process.exit(0);
}

const wantTarget = o.f.target;
if (wantTarget) {
  const t = targets.find((x) => x.name === String(wantTarget));
  if (!t) die(`no target named "${wantTarget}"`);
  console.log(`target: ${t.name}  (line ${t.line})`);
  if (t.deps) console.log(`prerequisites: ${t.deps}`);
  if (t.doc) console.log(`doc: ${t.doc}`);
  console.log(`\n${t.recipe || '(no recipe)'}`);
  process.exit(0);
}

console.log(`makefile: ${file}`);
console.log(`targets: ${targets.length}  variables: ${vars.size}  phony: ${phony.size}  default goal: ${defaultGoal || '(none)'}`);
if (includes.length) console.log(`includes: ${includes.join(' ')}`);
console.log('');
console.log(table(targets.map((t) => ({ target: t.name, deps: t.deps.slice(0, 40), doc: t.doc || '-', line: t.line })), ['target', 'deps', 'doc', 'line']));

if (vars.size) {
  console.log('\nvariables:');
  console.log(table([...vars.values()].map((v) => ({ name: v.key, op: v.op, value: v.value.length > 50 ? v.value.slice(0, 47) + '...' : v.value, line: v.line })), ['name', 'op', 'value', 'line']));
}

const problems = [
  ...dangerous,
  ...missingPhony.map((t) => ({ target: t.name, line: t.line, severity: 'LOW', message: 'real target not listed in .PHONY (stale-file hazard)' })),
];
if (!raw.some((l) => /^\.DEFAULT_GOAL/.test(l))) problems.push({ target: '-', line: 1, severity: 'LOW', message: 'no .DEFAULT_GOAL declared; first target wins implicitly' });

if (problems.length) {
  console.log('\nproblems:');
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  console.log(table(problems.sort((a, b) => order[a.severity] - order[b.severity]).map((p) => ({ severity: p.severity, target: p.target, line: p.line, detail: p.message })), ['severity', 'target', 'line', 'detail']));
} else console.log('\nno problems found');
process.exit(dangerous.some((d) => d.severity === 'CRITICAL' || d.severity === 'HIGH') ? 1 : 0);
