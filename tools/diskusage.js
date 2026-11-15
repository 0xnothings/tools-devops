#!/usr/bin/env node
// diskusage.js — directory space analyser with baseline growth tracking.
// Copyright (c) 2026 0xnothings
// @tool diskusage
// @desc Walk directories for size and inode usage, report the biggest files and directories, and diff against a saved baseline snapshot
// @usage node tools/diskusage.js /var --top 20 --save baseline.json --json
// @tags devops,disk,capacity
import { readdirSync, statSync, lstatSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { args, get, num, flag, die, emit, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`diskusage — space and inode analyser

  node tools/diskusage.js <dir> [more...] [options]

  --top <n>         rows per table (default 15)
  --depth <n>       directory rollup depth (default 2)
  --min <bytes>     ignore files smaller than this (default 1 MiB)
  --save <file>     write a snapshot for later comparison
  --compare <file>  diff against a snapshot (growth per subtree)
  --json            machine-readable output
  -h, --help        this text

  Uses lstat (never follows symlinks out of the tree) and reports apparent size.
  Inode pressure is measured too, since a filesystem can be full of inodes but empty of bytes.`);
  process.exit(0);
}

const roots = o._.length ? o._ : ['.'];
const top = num(get(o, 'top'), 15);
const maxDepth = num(get(o, 'depth'), 2);
const minBytes = num(get(o, 'min'), 1048576);

function human(n) {
  const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0, v = Number(n) || 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)}${u[i]}`;
}

const files = [];
const dirTotals = new Map();
const errs = [];
let totalBytes = 0, totalInodes = 0, scanned = 0;

function walk(p, depth) {
  if (depth > maxDepth + 4) return 0;
  let ents;
  try { ents = readdirSync(p, { withFileTypes: true }); }
  catch (e) { errs.push({ path: p, error: e.code || e.message }); return 0; }
  let sum = 0;
  for (const e of ents) {
    const fp = join(p, e.name);
    let st;
    try { st = lstatSync(fp); } catch { continue; }
    totalInodes++;
    if (st.isSymbolicLink()) continue;
    if (st.isDirectory()) {
      const sub = walk(fp, depth + 1);
      sum += sub;
      if (depth < maxDepth) dirTotals.set(fp, (dirTotals.get(fp) || 0) + sub);
    } else if (st.isFile()) {
      sum += st.size;
      scanned++;
      if (st.size >= minBytes) files.push({ path: fp, bytes: st.size, modified: st.mtime.toISOString().slice(0, 10) });
    }
  }
  if (depth <= maxDepth) dirTotals.set(p, (dirTotals.get(p) || 0) + sum);
  totalBytes += sum;
  return sum;
}

for (const r of roots) {
  if (!existsSync(r)) { errs.push({ path: r, error: 'ENOENT' }); continue; }
  const st = statSync(r);
  if (st.isFile()) { totalBytes += st.size; scanned++; files.push({ path: r, bytes: st.size, modified: st.mtime.toISOString().slice(0, 10) }); continue; }
  walk(r, 0);
}

const bigFiles = [...files].sort((a, b) => b.bytes - a.bytes).slice(0, top);
const bigDirs = [...dirTotals.entries()].map(([p, b]) => ({ dir: p, bytes: b })).sort((a, b) => b.bytes - a.bytes).slice(0, top);
const byExt = new Map();
for (const f of files) {
  const ext = (f.path.match(/\.([A-Za-z0-9]{1,10})$/) || [, '(none)'])[1].toLowerCase();
  const cur = byExt.get(ext) || { ext, count: 0, bytes: 0 };
  cur.count++; cur.bytes += f.bytes;
  byExt.set(ext, cur);
}
const extRows = [...byExt.values()].sort((a, b) => b.bytes - a.bytes).slice(0, top);

const saveFile = o.f.save && o.f.save !== true ? String(o.f.save) : null;
const snapshot = {
  when: new Date().toISOString(),
  roots,
  totalBytes,
  totalInodes,
  files: files.length,
  dirs: Object.fromEntries([...dirTotals.entries()].map(([k, v]) => [k, v])),
  topFiles: bigFiles.map((f) => ({ path: f.path, bytes: f.bytes })),
};
if (saveFile) writeFileSync(saveFile, JSON.stringify(snapshot, null, 2));

let growth = null;
const cmpFile = o.f.compare && o.f.compare !== true ? String(o.f.compare) : null;
if (cmpFile && existsSync(cmpFile)) {
  const base = JSON.parse(readFileSync(cmpFile, 'utf8'));
  const keys = new Set([...Object.keys(base.dirs || {}), ...Object.keys(snapshot.dirs)]);
  const rows = [];
  for (const k of keys) {
    const before = (base.dirs || {})[k] || 0;
    const after = snapshot.dirs[k] || 0;
    const delta = after - before;
    if (Math.abs(delta) < 1024) continue;
    rows.push({ dir: k, before, after, delta, pct: before ? Math.round((delta / before) * 100) : null });
  }
  rows.sort((a, b) => b.delta - a.delta);
  const baseFiles = new Map((base.topFiles || []).map((f) => [f.path, f.bytes]));
  const newFiles = files.filter((f) => !baseFiles.has(f.path)).sort((a, b) => b.bytes - a.bytes).slice(0, top);
  const goneFiles = (base.topFiles || []).filter((f) => !files.some((x) => x.path === f.path));
  growth = {
    since: base.when, from: cmpFile,
    totalDelta: totalBytes - (base.totalBytes || 0),
    totalBefore: base.totalBytes || 0,
    rows, newFiles, goneFiles: goneFiles.slice(0, top),
  };
}

if (flag(o, 'json')) {
  emit({ roots, totalBytes, totalHuman: human(totalBytes), inodes: totalInodes, fileCount: scanned, bigFiles, bigDirs, byExt: extRows, dirTotals: Object.fromEntries(dirTotals), growth, snapshotSaved: saveFile, errors: errs });
  process.exit(0);
}

console.log(`diskusage: ${roots.join(', ')}`);
console.log(`total: ${human(totalBytes)} across ${scanned} files, ${totalInodes} inodes`);
if (errs.length) console.log(`unreadable: ${errs.length} path(s) (run with --json for detail)`);
console.log('');
console.log('top directories:');
console.log(table(bigDirs.map((d) => ({ size: human(d.bytes), dir: d.dir })), ['size', 'dir']));
console.log('\nlargest files:');
console.log(table(bigFiles.map((f) => ({ size: human(f.bytes), modified: f.modified, path: f.path })), ['size', 'modified', 'path']));
console.log('\nby extension:');
console.log(table(extRows.map((e) => ({ ext: e.ext, count: e.count, size: human(e.bytes) })), ['ext', 'count', 'size']));

if (growth) {
  console.log(`\ngrowth since ${growth.since} (${cmpFile}):`);
  console.log(`  total ${growth.totalDelta >= 0 ? '+' : ''}${human(Math.abs(growth.totalDelta))} (was ${human(growth.totalBefore)})`);
  if (growth.rows.length) {
    console.log(table(growth.rows.slice(0, top).map((r) => ({ delta: (r.delta >= 0 ? '+' : '-') + human(Math.abs(r.delta)), dir: r.dir, now: human(r.after) })), ['delta', 'dir', 'now']));
  }
  if (growth.newFiles.length) {
    console.log('\nnew large files:');
    console.log(table(growth.newFiles.map((f) => ({ size: human(f.bytes), path: f.path })), ['size', 'path']));
  }
  if (growth.goneFiles.length) {
    console.log('\nremoved files:');
    console.log(table(growth.goneFiles.map((f) => ({ was: human(f.bytes), path: f.path })), ['was', 'path']));
  }
}
if (saveFile) console.log(`\nsnapshot written: ${saveFile}`);
process.exit(0);
