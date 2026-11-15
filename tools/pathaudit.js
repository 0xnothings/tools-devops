// pathaudit.js — audit PATH for hijack and shadowing risk.
// Copyright (c) 2026 0xnothings
// @tool pathaudit
// @desc Analyse PATH (or an explicit list) for world-writable directories, relative entries, duplicate binaries and shadowed system commands
// @usage node tools/pathaudit.js --json
// @tags devops,security,path,audit
import { statSync, readdirSync, accessSync, constants, realpathSync } from 'node:fs';
import { join, delimiter } from 'node:path';
import { args, get, flag, die, emit, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`pathaudit — PATH hijack auditor

  node tools/pathaudit.js [options]

  --path <list>     audit this PATH instead of the current one (${delimiter} separated)
  --shadow <cmds>   comma list of commands to check for shadowing (default: a curated set)
  --max <n>         files to inspect per directory (default 4000)
  --json            machine-readable output
  -h, --help        this text

  Flags: relative or empty components, world/group-writable directories, directories
  that appear twice, the same binary name resolving to different files, and ordering
  that lets a writable directory shadow /usr/bin.`);
  process.exit(0);
}

const rawPath = o.f.path ? String(o.f.path) : (process.env.PATH || '');
if (!rawPath) die('PATH is empty — nothing to audit');
const splitRe = rawPath.includes(';') && rawPath.includes(':') && process.platform === 'win32' ? /[;]/ : /[:,;]/;
const entries = rawPath.split(splitRe);
const maxFiles = Number(o.f.max || 4000);
const DEFAULT_SHADOW = ['ls', 'cat', 'grep', 'sed', 'awk', 'curl', 'wget', 'git', 'ssh', 'scp', 'tar', 'python', 'python3', 'node', 'npm', 'php', 'bash', 'sh', 'env', 'sudo', 'openssl', 'docker', 'kubectl'];
const shadowList = o.f.shadow ? String(o.f.shadow).split(',').map((s) => s.trim()).filter(Boolean) : DEFAULT_SHADOW;

const findings = [];
const add = (sev, dir, rule, msg) => findings.push({ severity: sev, dir, rule, message: msg });

const seenDirs = new Map();
const dirInfo = [];

for (let idx = 0; idx < entries.length; idx++) {
  const dir = entries[idx];
  if (!dir) { add('CRITICAL', '(empty)', 'empty-component', `entry ${idx} is empty — an empty PATH component means the current directory`); continue; }
  if (!/^([A-Za-z]:[\\/]|[\\/]|~)/.test(dir)) { add('CRITICAL', dir, 'relative-entry', `entry ${idx} is relative — resolved against the cwd, so any repo can inject binaries`); }
  if (dir === '.' || dir === './' || /^\.\.[\\/]|^\.\.$/.test(dir)) { add('CRITICAL', dir, 'dot-entry', `entry ${idx} is "${dir}" — every command would be resolved from the cwd`); }

  const key = dir.replace(/[\\/]+$/, '').toLowerCase();
  if (seenDirs.has(key)) add('MEDIUM', dir, 'duplicate-entry', `directory appears twice (entries ${seenDirs.get(key)} and ${idx}); harmless but signals a broken profile`);
  else seenDirs.set(key, idx);

  let st;
  try { st = statSync(dir); } catch { add('LOW', dir, 'missing-dir', 'directory does not exist (dead PATH entry slows every lookup)'); dirInfo.push({ idx, dir, exists: false, files: [] }); continue; }
  if (!st.isDirectory()) { add('MEDIUM', dir, 'not-a-dir', 'PATH entry is a file, not a directory'); dirInfo.push({ idx, dir, exists: false, files: [] }); continue; }

  const mode = st.mode & 0o777;
  const worldWritable = !!(st.mode & 0o002);
  const groupWritable = !!(st.mode & 0o020);
  if (worldWritable) add('CRITICAL', dir, 'world-writable', `mode ${mode.toString(8)} — any local user can drop a binary that shadows a system one`);
  else if (groupWritable) add('HIGH', dir, 'group-writable', `mode ${mode.toString(8)} — anyone in the group can plant executables`);

  let files = [];
  try { files = readdirSync(dir, { withFileTypes: true }).slice(0, maxFiles).filter((e) => e.isFile() || e.isSymbolicLink()).map((e) => e.name); }
  catch { add('LOW', dir, 'unreadable', 'directory cannot be listed'); }

  // owned-by-non-root writable check on individual binaries
  if (!worldWritable && !groupWritable) {
    for (const f of files.slice(0, 200)) {
      try {
        const fs2 = statSync(join(dir, f));
        if (fs2.mode & 0o002) add('HIGH', dir, 'writable-binary', `${f} is world-writable (mode ${(fs2.mode & 0o777).toString(8)})`);
      } catch { /* ignore */ }
    }
  }

  dirInfo.push({ idx, dir, exists: true, mode: mode.toString(8), files, worldWritable, groupWritable });
}

// shadowing: which dir wins for each command, and whether a less-trusted dir precedes a more trusted one
const shadowRows = [];
for (const cmd of shadowList) {
  const hits = [];
  for (const d of dirInfo) {
    if (!d.exists || !d.files.includes(cmd)) continue;
    hits.push({ idx: d.idx, dir: d.dir, worldWritable: d.worldWritable, groupWritable: d.groupWritable });
  }
  // on windows also consider .exe
  if (!hits.length && process.platform === 'win32') {
    for (const d of dirInfo) {
      if (!d.exists) continue;
      const alt = d.files.find((f) => f.toLowerCase() === `${cmd}.exe`.toLowerCase() || f.toLowerCase() === `${cmd}.cmd`.toLowerCase());
      if (alt) hits.push({ idx: d.idx, dir: d.dir, file: alt, worldWritable: d.worldWritable, groupWritable: d.groupWritable });
    }
  }
  if (hits.length > 1) {
    const winner = hits[0];
    shadowRows.push({ command: cmd, winner: winner.dir, winnerIndex: winner.idx, alternatives: hits.slice(1).map((h) => h.dir), risky: hits.slice(1).some((h) => /usr\/(s?bin)|Program Files/i.test(h.dir)) || !!winner.worldWritable });
    if (winner.worldWritable) add('CRITICAL', winner.dir, 'shadow-hijack', `${cmd} resolves to a world-writable directory before any system path`);
    else if (hits.slice(1).some((h) => /usr\/(s?bin)/i.test(h.dir))) add('MEDIUM', winner.dir, 'shadow-system', `${cmd} from ${winner.dir} shadows the system copy in ${hits.slice(1).map((h) => h.dir).join(', ')}`);
  }
}

// writable dir before the first system dir
const firstSystem = dirInfo.findIndex((d) => /^(\/usr\/(s?bin)|\/bin|\/usr\/local\/bin|C:\\Windows)/i.test(d.dir));
if (firstSystem > 0) {
  const before = dirInfo.slice(0, firstSystem).filter((d) => d.worldWritable || d.groupWritable);
  if (before.length) add('CRITICAL', before[0].dir, 'writable-before-system', `a writable directory precedes the first system directory (${dirInfo[firstSystem].dir})`);
}

const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
for (const f of findings) counts[f.severity]++;
const failed = counts.CRITICAL > 0 || counts.HIGH > 0;

if (flag(o, 'json')) {
  emit({
    entryCount: entries.length, entries: dirInfo.map((d) => ({ index: d.idx, dir: d.dir, exists: d.exists, mode: d.mode || null, writable: !!(d.worldWritable || d.groupWritable), files: d.files.length })),
    shadowing: shadowRows, findings, counts, pass: !failed,
  });
  process.exit(0);
}

console.log(`pathaudit: ${entries.length} entr${entries.length === 1 ? 'y' : 'ies'}`);
console.log(`findings: ${findings.length}  critical: ${counts.CRITICAL} high: ${counts.HIGH} medium: ${counts.MEDIUM} low: ${counts.LOW}`);
console.log('');
console.log(table(dirInfo.map((d) => ({ idx: d.idx, dir: d.dir.length > 46 ? '...' + d.dir.slice(-43) : d.dir, exists: d.exists ? 'yes' : 'NO', mode: d.mode || '-', files: d.files.length, writable: d.worldWritable ? 'world' : d.groupWritable ? 'group' : 'no' })), ['idx', 'dir', 'exists', 'mode', 'files', 'writable']));
if (shadowRows.length) {
  console.log('\nshadowing:');
  console.log(table(shadowRows.map((s) => ({ command: s.command, resolves: s.winner, index: s.winnerIndex, also: s.alternatives.join(', '), risk: s.risky ? 'SHADOWED' : 'ok' })), ['command', 'resolves', 'index', 'also', 'risk']));
}
if (findings.length) {
  console.log('\nfindings:');
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  console.log(table(findings.sort((a, b) => order[a.severity] - order[b.severity]).map((f) => ({ severity: f.severity, rule: f.rule, dir: f.dir.length > 40 ? '...' + f.dir.slice(-37) : f.dir, detail: f.message })), ['severity', 'rule', 'dir', 'detail']));
} else console.log('\nno findings');
process.exit(failed ? 1 : 0);
