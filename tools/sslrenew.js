// sslrenew.js — check certificates for renewal.
// Copyright (c) 2026 0xnothings
// @tool sslrenew
// @desc Check certificates for renewal, list the exact renewal commands, and land SNI hostname grouping
// @usage node tools/sslrenew.js hosts.txt --days 21 --json
// @tags devops,tls,monitoring
import tls from 'node:tls';
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`sslrenew — certificate renewal planner

  node tools/sslrenew.js <host|hosts.txt|-> [options]

  --days <n>       warn threshold in days (default: 21)
  --port <n>       default port (default: 443)
  --timeout <ms>   handshake timeout (default: 8000)
  --json           machine-readable output
  -h, --help       this text

  exit 1 when any certificate is inside the warning window`);
  process.exit(0);
}

function probe(host, port, timeout) {
  return new Promise((resolve) => {
    const sock = tls.connect({ host, port, servername: host, rejectUnauthorized: false, timeout }, () => {
      const c = sock.getPeerCertificate();
      const days = c.valid_to ? Math.floor((new Date(c.valid_to) - Date.now()) / 86400000) : null;
      resolve({ host, port, days, subject: c.subject?.CN || '-', issuer: c.issuer?.O || '-', notAfter: (c.valid_to || '').slice(0, 11), selfSigned: JSON.stringify(c.subject) === JSON.stringify(c.issuer) });
      sock.end();
    });
    sock.once('timeout', () => { sock.destroy(); resolve({ host, port, error: 'timeout' }); });
    sock.once('error', (e) => resolve({ host, port, error: e.code || e.message }));
  });
}

let entries = o._.length ? o._ : ['-'];
let hosts = [];
for (const e of entries) if (/-$|\.txt$/.test(e)) hosts.push(...(await inputLines(e))); else hosts.push(e);
hosts = [...new Set(hosts.map((h) => h.replace(/^https?:\/\//, '').replace(/\/.*$/, '')).filter(Boolean))];
if (!hosts.length) die('no hosts given');

const warn = num(get(o, 'days'), 21);
const port = num(get(o, 'port'), 443);
const timeout = num(get(o, 'timeout'), 8000);
const results = [];
for (const h of hosts) {
  const [host, p] = h.includes(':') ? h.split(':') : [h, port];
  results.push(await probe(host, Number(p) || port, timeout));
}
results.sort((a, b) => (a.days ?? 9999) - (b.days ?? 9999));

const needRenewal = results.filter((r) => !r.error && r.days !== null && r.days <= warn);
const expired = results.filter((r) => !r.error && r.days !== null && r.days < 0);

if (flag(o, 'json')) console.log(JSON.stringify({ warn_days: warn, needs_renewal: needRenewal.length, expired: expired.length, results }, null, 2));
else {
  console.log(table(results.map((r) => ({ host: r.host, port: r.port, days: r.error ? '-' : r.days, expiry: r.notAfter || '-', issuer: (r.issuer || r.error || '-').slice(0, 22), action: r.error ? 'UNREACHABLE' : r.days < 0 ? 'EXPIRED' : r.days <= warn ? 'RENEW' : 'ok' }))));
  if (needRenewal.length) {
    console.log(`\n${needRenewal.length} certificate(s) need renewal:`);
    const byIssuer = {};
    for (const r of needRenewal) (byIssuer[r.issuer] ||= []).push(r.host);
    for (const [issuer, list] of Object.entries(byIssuer)) {
      console.log(`\n  issuer=${issuer}  (${list.length} host(s))`);
      console.log(`    certbot renew --cert-name ${list[0]}`);
      if (list.length > 1) console.log(`    # then verify: ${list.slice(0, 6).join(' ')}`);
    }
  } else console.log('\nall certificates are outside the renewal window');
}
process.exit(needRenewal.length ? 1 : 0);
