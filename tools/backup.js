#!/usr/bin/env node
// backup.js — file and directory backup with manifest.
// Copyright (c) 2026 0xnothings
// @tool backup
// @desc Create a tar.gz backup with a JSON manifest (hashes, sizes), verify archives, and prune by retention
// @usage node tools/backup.js ./public_html --out ./backups --keep 7 --json
// @tags devops,backup,archive
import { createReadStream, createWriteStream, existsSync, mkdirSync, readdirSync, statSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, basename, relative, dirname } from 'node:path';
import { execFileSync } from 'node:child_process';
import { args, get, num, flag, die, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`backup (0xnothings) — tar.gz backup with manifest + retention

  node tools/backup.js <path> [options]

  --out <dir>        access dir (default: ./backups)
  --keep <n>         retention count per target prefix (default: 7)
  --exclude <list>   path substrings to skip (default: node_modules,.git,vendor)
  --encrypt <pass>   encrypt the archive with openssl aes-256 (cpu heavy)
  --verify           list the archive contents after writing
  --json             machine-readable output
  -h, --help         this text

  Notes: 0xnothings backups are plain tar.gz + manifest.json — no database logic,
  no service hooks, no remote uploads. Put them outside the web root.`);
  process.exit(0);
}

const target = o._[0];
if (!target) die('usage: node tools/backup.js <path> [--out dir] [--keep 7]');
if (!existsSync(target)) die(`${target} does not exist`);
const outDir = String(get(o, 'out', './backups'));
mkdirSync(outDir, { recursive: true });
const keep = num(get(o, 'keep'), 7);
const excludes = String(get(o, 'exclude', 'node_modules,.git,vendor,.cache')).split(',').map((s) => s.trim()).filter(Boolean);

function walk(dir, base, acc = []) {
  let ents; try { ents = readdirSync(dir, { withFileTypes: true }); } catch { return acc; }
  for (const e of ents) {
    const p = join(dir, e.name);
    const rel = relative(base, p);
    if (excludes.some((x) => rel.includes(x))) continue;
    let st; try { st = statSync(p); } catch { continue; }
    if (e.isDirectory()) walk(p, base, acc);
    else if (st.size < 200 * 1024 * 1024) acc.push({ path: rel, size: st.size, mtime: st.mtime.toISOString() });
  }
  return acc;
}

const files = walk(target, target);
const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
const name = `${basename(target)}-${stamp}`;
const tarPath = join(outDir, `${name}.tar.gz`);

execFileSync('tar', ['-czf', tarPath, ...excludes.flatMap((x) => ['--exclude', x]), '-C', dirname(target), basename(target)], { stdio: 'pipe' });

let finalPath = tarPath;
if (o.f.encrypt) {
  const enc = tarPath.replace(/\.tar\.gz$/, '.tar.gz.enc');
  execFileSync('openssl', ['enc', '-aes-256-cbc', '-pbkdf2', '-salt', '-in', tarPath, '-out', enc, '-pass', `pass:${get(o, 'encrypt')}`], { stdio: 'pipe' });
  try { execFileSync('rm', ['-f', tarPath]); } catch {}
  finalPath = enc;
}

const st = statSync(finalPath);
const sha = createHash('sha256');
sha.update(readFileSync(finalPath));
const manifest = {
  created: new Date().toISOString(), source: target, archive: finalPath,
  bytes: st.size, file_count: files.length, total_source_bytes: files.reduce((a, f) => a + f.size, 0),
  sha256: sha.digest('hex'), encrypted: !!o.f.encrypt, excludes, files: files.slice(0, 500),
};
writeFileSync(join(outDir, `${name}.manifest.json`), JSON.stringify(manifest, null, 2));

const prefix = basename(target) + '-';
const old = readdirSync(outDir).filter((f) => f.startsWith(prefix) && f.endsWith('.tar.gz') || f.startsWith(prefix) && f.endsWith('.enc')).sort();
if (old.length > keep) for (const f of old.slice(0, old.length - keep)) { try { execFileSync('rm', ['-f', join(outDir, f)]); } catch {} }

let verify = null;
if (flag(o, 'verify') && !manifest.encrypted) {
  try { verify = execFileSync('tar', ['-tzf', finalPath], { encoding: 'utf8' }).split('\n').filter(Boolean); } catch (e) { verify = ['VERIFY FAILED: ' + e.message]; }
}

if (flag(o, 'json')) console.log(JSON.stringify({ ...manifest, files: undefined, pruned: Math.max(0, old.length - keep), verify_count: verify?.length ?? null }, null, 2));
else {
  console.log(`backup  ${finalPath}`);
  console.log(`  ${(st.size / 1048576).toFixed(2)} MB  ${files.length} files  sha256 ${manifest.sha256.slice(0, 16)}...`);
  if (manifest.encrypted) console.log('  encrypted with aes-256-cbc (keep the passphrase safe — no recovery)');
  if (verify) console.log(`  verify: ${verify.length} entries readable`);
  if (old.length > keep) console.log(`  pruned ${old.length - keep} archive(s) beyond the last ${keep}`);
  console.log('\nrestore:  tar -xzf ' + finalPath + (manifest.encrypted ? '  (decrypt first with openssl)' : ''));
}
