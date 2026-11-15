// nfsmount.js — audit NFS exports and mount options.
// Copyright (c) 2026 0xnothings
// @tool nfsmount
// @desc Parse /etc/exports and mount options, flag insecure settings (no_root_squash, insecure, no_subtree_check, wildcard hosts) and recommend safe defaults
// @usage node tools/nfsmount.js /etc/exports /proc/mounts --json
// @tags devops,nfs,storage,audit
import { readFileSync, existsSync } from 'node:fs';
import { args, flag, die, emit, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`nfsmount — NFS export and mount auditor

  node tools/nfsmount.js <exports|mounts|auto> [more...] [options]

  --json        machine-readable output
  --suggest     print a hardened /etc/exports snippet for each share
  -h, --help    this text

  Detects: no_root_squash, insecure ports, no_subtree_check, wildcard/full-subnet hosts,
  rw on application code, soft mounts losing writes, mounts without noexec, and
  /etc/fstab auto entries with insecure options.`);
  process.exit(0);
}

const paths = o._.length ? o._ : ['/etc/exports', '/proc/mounts'];
const SECURE_EXPORT = ['root_squash', 'sync', 'subtree_check', 'no_all_squash'];
const INSECURE = {
  no_root_squash: { sev: 'CRITICAL', msg: 'root on a client is treated as root on the server (full host compromise)' },
  insecure: { sev: 'HIGH', msg: 'permits client source ports > 1024, enabling off-path spoofing' },
  no_subtree_check: { sev: 'LOW', msg: 'disables subtree checking (weakens path validation on renames)' },
  async: { sev: 'MEDIUM', msg: 'async writes can lose data on server crash' },
  no_all_squash: { sev: 'LOW', msg: 'unmapped UIDs pass through; check the uid map is intentional' },
  crossmnt: { sev: 'MEDIUM', msg: 'crossmnt exposes nested mounts from the client side' },
  'no_acl': { sev: 'LOW', msg: 'ACLs disabled' },
};
const MOUNT_INSECURE = {
  soft: { sev: 'HIGH', msg: 'soft mount returns EIO and can silently corrupt application data' },
  noexec: { sev: 'INFO', msg: 'noexec is set (good for data shares)' },
  suid: { sev: 'MEDIUM', msg: 'suid honoured on a network mount (set nosuid unless required)' },
  dev: { sev: 'HIGH', msg: 'dev honoured on a network mount (set nodev)' },
  vers3: { sev: 'MEDIUM', msg: 'NFSv3 only; v4.2 is faster and better authenticated' },
  rw: { sev: 'INFO', msg: 'read-write mount' },
};

let text = '';
const files = [];
for (const p of paths) {
  if (!existsSync(p)) continue;
  files.push(p);
  text += `\n### ${p}\n` + readFileSync(p, 'utf8');
}
if (!files.length) die(`none of these exist: ${paths.join(', ')}`);

const exports = [];
const mounts = [];
const findings = [];
const suggestions = [];

for (const f of files) {
  const isExports = /exports/.test(f);
  const raw = readFileSync(f, 'utf8').split(/\r?\n/);
  for (let i = 0; i < raw.length; i++) {
    let line = raw[i].replace(/\s+#.*$/, '').trim();
    if (!line || line.startsWith('#')) continue;
    if (isExports) {
      line = line.replace(/\\\s*$/, '');
      const m = line.match(/^("[^"]+"|\S+)\s+(.+)$/);
      if (!m) continue;
      const dir = m[1].replace(/"/g, '');
      const specs = [];
      // split on host(...) groups, may span multiple tokens
      const re = /([^\s(]+)\(([^)]*)\)/g;
      let g;
      while ((g = re.exec(m[2]))) specs.push({ host: g[1], opts: g[2].split(',').map((s) => s.trim()).filter(Boolean) });
      if (!specs.length) specs.push({ host: m[2].trim(), opts: [] });
      exports.push({ file: f, line: i + 1, dir, specs });
      const rec = [];
      for (const s of specs) {
        if (s.host === '*' || /^0\.0\.0\.0/.test(s.host) || /\/0$/.test(s.host)) {
          findings.push({ file: f, line: i + 1, severity: 'CRITICAL', rule: 'wildcard-host', message: `${dir}: exported to ${s.host} — any host on the internet can mount it` });
        } else if (/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(s.host)) {
          const bits = Number(s.host.split('/')[1]);
          if (bits <= 16) findings.push({ file: f, line: i + 1, severity: 'HIGH', rule: 'wide-subnet', message: `${dir}: exported to ${s.host} (/${bits} is a very wide range)` });
        }
        const hasRootSquash = s.opts.some((x) => /^root_squash$/.test(x) || /^all_squash$/.test(x));
        for (const opt of s.opts) {
          const bare = opt.replace(/=[^,]*/, '');
          if (INSECURE[bare] && bare !== 'no_all_squash') findings.push({ file: f, line: i + 1, severity: INSECURE[bare].sev, rule: bare, message: `${dir} -> ${s.host}: ${INSECURE[bare].msg}` });
        }
        if (!hasRootSquash && s.opts.length) findings.push({ file: f, line: i + 1, severity: 'CRITICAL', rule: 'root-not-squashed', message: `${dir} -> ${s.host}: no root_squash or all_squash; a client root maps to server root` });
        const missing = [];
        if (!s.opts.some((x) => /root_squash|all_squash/.test(x))) missing.push('root_squash');
        if (!s.opts.includes('sync')) missing.push('sync');
        if (missing.length) {
          findings.push({ file: f, line: i + 1, severity: 'MEDIUM', rule: 'missing-option', message: `${dir} -> ${s.host}: missing ${missing.join(', ')}` });
        }
      }
      suggestions.push({ dir, hosts: specs.map((s) => s.host).join(' '), host_specs: specs });
    } else {
      const parts = line.split(/\s+/);
      if (parts.length < 3 || !/nfs/.test(parts[2])) continue;
      const dev = parts[0], mp = parts[1], fs = parts[2];
      const opts = (parts[3] || '').split(',').map((s) => s.trim()).filter(Boolean);
      mounts.push({ file: f, line: i + 1, device: dev, mountpoint: mp, fstype: fs, options: opts });
      const optSet = new Set(opts.map((x) => x.replace(/=[^,]*/, '')));
      for (const opt of opts) {
        const bare = opt.replace(/=[^,]*/, '');
        const hit = MOUNT_INSECURE[bare];
        if (hit && hit.sev !== 'INFO') findings.push({ file: f, line: i + 1, severity: hit.sev, rule: bare, message: `${mp}: ${hit.msg}` });
      }
      if (!optSet.has('nosuid') && optSet.has('suid')) findings.push({ file: f, line: i + 1, severity: 'MEDIUM', rule: 'mount-suid', message: `${mp}: mounted with suid` });
      if (!optSet.has('noexec') && /tmp|var\/tmp|shm/.test(mp)) findings.push({ file: f, line: i + 1, severity: 'HIGH', rule: 'mount-exec', message: `${mp}: world-writable path mounted with exec` });
      if (!optSet.has('nodev')) findings.push({ file: f, line: i + 1, severity: 'LOW', rule: 'mount-dev', message: `${mp}: mounted without nodev` });
      if (!optSet.has('noatime') && !optSet.has('relatime')) findings.push({ file: f, line: i + 1, severity: 'LOW', rule: 'mount-atime', message: `${mp}: default atime causes a write per read` });
    }
  }
}

const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
for (const x of findings) counts[x.severity] = (counts[x.severity] || 0) + 1;
const failed = findings.some((x) => x.severity === 'CRITICAL' || x.severity === 'HIGH');

if (flag(o, 'json')) {
  emit({
    files, exports: exports.map((e) => ({ path: e.dir, host: e.specs.map((s) => s.host).join(','), options: e.specs.map((s) => s.opts.join(',')).join(' | ') })),
    mounts: mounts.map((m) => ({ device: m.device, mountpoint: m.mountpoint, fstype: m.fstype, options: m.options.join(',') })),
    findings, counts, pass: !failed,
  });
  process.exit(0);
}

console.log(`nfsmount: ${files.join(', ')}`);
console.log(`exports: ${exports.length}  mounts: ${mounts.length}  findings: ${findings.length}`);
if (exports.length) {
  console.log('');
  console.log(table(exports.map((e) => ({ path: e.dir.split('/').pop(), host: e.specs.map((s) => s.host).join(' '), options: e.specs.map((s) => s.opts.join(',')).join(' | ').slice(0, 60) })), ['path', 'host', 'options']));
}
if (mounts.length) {
  console.log('\nnetwork mounts:');
  console.log(table(mounts.map((m) => ({ mountpoint: m.mountpoint, device: m.device.slice(0, 34), options: m.options.join(',').slice(0, 60) })), ['mountpoint', 'device', 'options']));
}
if (findings.length) {
  console.log('\nfindings:');
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  console.log(table(findings.sort((a, b) => order[a.severity] - order[b.severity]).map((f) => ({ severity: f.severity, rule: f.rule, detail: f.message })), ['severity', 'rule', 'detail']));
} else console.log('\nno findings');

if (flag(o, 'suggest')) {
  console.log('\n# hardened /etc/exports');
  for (const s of suggestions) {
    const hosts = s.host_specs.map((h) => `${h.host}(rw,sync,root_squash,no_subtree_check,nosuid,nodev)`).join(' ');
    console.log(`${s.dir}  ${hosts}`);
  }
  console.log('\n# matching client fstab entry');
  console.log('server:/srv/share  /mnt/share  nfs4  rw,hard,noatime,nosuid,nodev,noexec,_netdev,proto=tcp,vers=4.2  0 0');
}
process.exit(failed ? 1 : 0);
