#!/usr/bin/env node
// dockerclean.js — find Docker space hogs and generate a cleanup plan.
// Copyright (c) 2026 0xnothings
// @tool dockerclean
// @desc Report dangling images, stopped containers, orphan volumes and build cache; emit a safe/aggressive cleanup plan
// @usage node tools/dockerclean.js --mode plan --json
// @tags devops,docker,cleanup
import { execFileSync } from 'node:child_process';
import { args, get, num, flag, die, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`dockerclean — Docker disk usage analysis + cleanup plan

  node tools/dockerclean.js [options]

  --mode <plan|safe|aggressive>   plan (default) | safe | aggressive
  --min-size <mb>                 only report items above this (default: 1)
  --json                          machine-readable output
  -h, --help                      this text

  plan        = analysis only, no changes
  safe        = prune stopped containers, dangling images, unused build cache
  aggressive  = also remove unused volumes and images not used by any container

  Requires the docker CLI on PATH. Never auto-runs destructive prunes.`);
  process.exit(0);
}

const mode = String(get(o, 'mode', 'plan'));
const minSize = num(get(o, 'min-size'), 1) * 1024 * 1024;

const dk = (a) => { try { return execFileSync('docker', a, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim(); } catch (e) { return null; } };

if (dk(['version', '--format', '{{.Server.Version}}']) === null) die('docker CLI not available (or daemon not running)');

function parseHuman(s) {
  const m = String(s).match(/([\d.]+)\s*(B|kB|KB|MB|GB|TB)/i);
  if (!m) return 0;
  const n = parseFloat(m[1]);
  const unit = m[2].toUpperCase();
  return n * ({ B: 1, KB: 1e3, MB: 1e6, GB: 1e9, TB: 1e12 }[unit] || 1);
}

const fmt = (bytes) => bytes > 1e9 ? `${(bytes / 1e9).toFixed(2)} GB` : `${(bytes / 1e6).toFixed(1)} MB`;

// containers
const containers = (dk(['ps', '-a', '--format', '{{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Image}}\t{{.Size}}']) || '')
  .split('\n').filter(Boolean).map((l) => { const [id, name, status, image, size] = l.split('\t'); return { id, name, status, image, size, bytes: parseHuman((size || '').split(' ')[0]), stopped: /Exited|Created/i.test(status) }; });
const stopped = containers.filter((c) => c.stopped);

// images
const images = (dk(['images', '-a', '--format', '{{.ID}}\t{{.Repository}}:{{.Tag}}\t{{.Size}}']) || '')
  .split('\n').filter(Boolean).map((l) => { const [id, tag, size] = l.split('\t'); return { id, tag, size, bytes: parseHuman(size), dangling: tag.startsWith('<none>') }; });
const dangling = images.filter((i) => i.dangling);

// volumes
const volumes = (dk(['volume', 'ls', '-f', 'dangling=true', '-q']) || '').split('\n').filter(Boolean).map((name) => ({ name }));

// build cache + total
const cacheLines = (dk(['system', 'df']) || '').split('\n');
const reclaimLine = cacheLines.find((l) => /Total Reclaimable|Reclaimable/i.test(l));
const systemDf = cacheLines.slice(0, 12).join('\n');

const reclaim = {
  stopped_containers: stopped.reduce((a, c) => a + c.bytes, 0),
  dangling_images: dangling.reduce((a, i) => a + i.bytes, 0),
  orphan_volumes: volumes.length,
};
const plan = {
  mode,
  stopped_containers: stopped.filter((c) => c.bytes >= minSize || true),
  dangling_images: dangling,
  orphan_volumes: volumes,
  commands: mode === 'plan' ? [] : mode === 'safe' ? [
    'docker container prune -f',
    'docker image prune -f',
    'docker builder prune -f',
  ] : [
    'docker container prune -f',
    'docker image prune -a -f',
    'docker volume prune -f',
    'docker builder prune -a -f',
  ],
};

if (flag(o, 'json')) { console.log(JSON.stringify({ ...plan, reclaim_estimate_bytes: reclaim }, null, 2)); }
else {
  console.log('docker system df:\n' + systemDf + '\n');
  if (stopped.length) { console.log(`stopped containers (${stopped.length}):`); console.log(table(stopped.map((c) => ({ id: c.id.slice(0, 12), name: c.name, size: c.size, status: c.status })))); }
  if (dangling.length) { console.log(`\ndangling images (${dangling.length}):`); console.log(table(dangling.map((i) => ({ id: i.id.replace('sha256:', '').slice(0, 12), size: i.size })))); }
  if (volumes.length) console.log(`\norphan volumes: ${volumes.length}  (${volumes.slice(0, 10).join(', ')}${volumes.length > 10 ? ' ...' : ''})`);
  console.log(`\nreclaimable estimate: containers ${fmt(reclaim.stopped_containers)}, images ${fmt(reclaim.dangling_images)}`);
  if (plan.commands.length) { console.log('\ncommands to run:'); plan.commands.forEach((c) => console.log('  ' + c)); }
  else console.log('\nmode=plan — nothing changed. Re-run with --mode safe or --mode aggressive to get commands.');
  if (mode !== 'plan') console.log('\n0xnothings did NOT execute these. Review, then run them yourself.');
}
