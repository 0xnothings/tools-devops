// envcheck.js — compare .env against a template.
// Copyright (c) 2026 0xnothings
// @tool envcheck
// @desc Diff a .env against .env.example: find missing, extra, empty and duplicate keys (CI gate)
// @usage node tools/envcheck.js .env --template .env.example --json
// @tags devops,config,ci
import { readFileSync, existsSync } from 'node:fs';
import { args, get, flag, die, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`envcheck — .env vs template diff

  node tools/envcheck.js <env-file> [options]

  --template <f>   template file (default: .env.example)
  --allow-extra    don't fail on keys absent from the template
  --quiet          only non-zero exit on problems
  --json           machine-readable output
  -h, --help       this text`);
  process.exit(0);
}

function parse(file) {
  if (!existsSync(file)) return null;
  const map = new Map();
  const dupes = [];
  readFileSync(file, 'utf8').split(/\r?\n/).forEach((line, i) => {
    const m = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!m) return;
    const [, key, raw] = m;
    const val = raw.trim().replace(/^(['"])(.*)\1$/, '$2');
    if (map.has(key)) dupes.push(key);
    map.set(key, { key, value: val, line: i + 1, empty: val === '' || /^(your|changeme|xxx|todo|placeholder)/i.test(val) });
  });
  return { map, dupes };
}

const envFile = o._[0] || '.env';
const tplFile = String(get(o, 'template', '.env.example'));
const env = parse(envFile);
const tpl = parse(tplFile);
if (!env) die(`${envFile} not found`);
if (!tpl) die(`${tplFile} not found (pass --template)`);

const missing = [...tpl.map.keys()].filter((k) => !env.map.has(k));
const extra = [...env.map.keys()].filter((k) => !tpl.map.has(k));
const empty = [...env.map.values()].filter((v) => v.empty);
const driftKeys = [...env.map.keys()].filter((k) => tpl.map.has(k) && /^(\d+|true|false)$/i.test(env.map.get(k).value) && !/^(\d+|true|false)$/i.test(tpl.map.get(k).value));

const problems = missing.length + empty.length + env.dupes.length + (flag(o, 'allow-extra') ? 0 : extra.length);
const report = { env_file: envFile, template: tplFile, keys: { env: env.map.size, template: tpl.map.size }, missing, extra, empty: empty.map((e) => e.key), duplicates: env.dupes, type_drift: driftKeys, ok: problems === 0 };

if (flag(o, 'json')) console.log(JSON.stringify(report, null, 2));
else if (!flag(o, 'quiet')) {
  console.log(`${envFile} has ${env.map.size} keys, ${tplFile} declares ${tpl.map.size}`);
  if (missing.length) console.log(`  MISSING in ${envFile}: ${missing.join(', ')}`);
  if (extra.length) console.log(`  EXTRA (not in template): ${extra.join(', ')}`);
  if (empty.length) console.log(`  EMPTY/PLACEHOLDER values: ${empty.map((e) => `${e.key} (line ${e.line})`).join(', ')}`);
  if (env.dupes.length) console.log(`  DUPLICATE keys: ${[...new Set(env.dupes)].join(', ')}`);
  if (driftKeys.length) console.log(`  TYPE DRIFT (env literal vs template placeholder): ${driftKeys.join(', ')}`);
  console.log(problems ? `\n${problems} problem(s)` : '\nconfig matches the template');
}
process.exit(problems ? 1 : 0);
