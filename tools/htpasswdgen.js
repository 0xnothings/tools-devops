// htpasswdgen.js — generate and verify .htpasswd lines.
// Copyright (c) 2026 0xnothings
// @tool htpasswdgen
// @desc Generate .htpasswd entries (apr1, sha1, scrypt, pbkdf2) as a batch from a CSV or prompts, with a verify mode and duplicate detection
// @usage node tools/htpasswdgen.js --users users.csv --scheme apr1 --out .htpasswd --json
// @tags devops,htpasswd,security
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { randomBytes, scryptSync, timingSafeEqual, createHash, pbkdf2Sync } from 'node:crypto';
import { args, get, flag, die, emit, table, inputLines } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`htpasswdgen — .htpasswd batch generator

  node tools/htpasswdgen.js [options]

  --users <file>      CSV "user,password" (or "user,passwordfile"); "-" reads stdin
  --user <u> --pass <p>   single entry
  --scheme <s>        apr1 | sha1 | scrypt | pbkdf2   (default apr1)
  --cost <n>          scrypt log2(N) (12-18) or pbkdf2 rounds in thousands (default 14 / 100)
  --out <file>        write the .htpasswd (default stdout)
  --merge <file>      merge with an existing .htpasswd, replacing duplicates
  --verify <file>     verify entries in a .htpasswd against --check (user=pass,user2=pass2)
  --check <pairs>     comma list of user=password pairs for --verify
  --json              machine-readable output
  -h, --help          this text

  apr1 (Apache "htpasswd -m") is implemented from scratch — Apache accepts it natively.
  bcrypt cannot be produced by node:crypto; scrypt is offered as the modern equivalent.`);
  process.exit(0);
}

const B64 = (b) => Buffer.from(b).toString('base64').replace(/=+$/, '');
const ITOA64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
function to64(v, n) { let s = ''; while (--n >= 0) { s += ITOA64[v & 0x3f]; v >>>= 6; } return s; }
const md5 = (b) => createHash('md5').update(b).digest();
function apr1(password, salt) {
  const pw = Buffer.from(password, 'utf8');
  const sl = Buffer.from(salt.slice(0, 8), 'utf8');
  const alt = md5(Buffer.concat([pw, sl, pw]));
  // Apache accumulates one buffer: pw + magic + salt, then chunks of alt, then pw[0]/0x00 bits
  const data = [pw, Buffer.from('$apr1$', 'ascii'), sl];
  for (let i = pw.length; i > 0; i -= 16) data.push(i > 16 ? alt : alt.subarray(0, i));
  for (let j = pw.length; j > 0; j >>= 1) data.push((j & 1) ? Buffer.from([0]) : pw.subarray(0, 1));
  let final = md5(Buffer.concat(data));
  for (let k = 0; k < 1000; k++) {
    const parts = [];
    parts.push((k & 1) ? pw : final);
    if (k % 3) parts.push(sl);
    if (k % 7) parts.push(pw);
    parts.push((k & 1) ? final : pw);
    final = md5(Buffer.concat(parts));
  }
  const g = (i) => final[i];
  let out = '';
  out += to64(((g(0) << 16) | (g(6) << 8) | g(12)) & 0xffffff, 4);
  out += to64(((g(1) << 16) | (g(7) << 8) | g(13)) & 0xffffff, 4);
  out += to64(((g(2) << 16) | (g(8) << 8) | g(14)) & 0xffffff, 4);
  out += to64(((g(3) << 16) | (g(9) << 8) | g(15)) & 0xffffff, 4);
  out += to64(((g(4) << 16) | (g(10) << 8) | g(5)) & 0xffffff, 4);
  out += to64(g(11), 2);
  return `$apr1$${salt}$${out}`;
}

const scheme = String(get(o, 'scheme', 'apr1')).toLowerCase();
const costArg = Number(get(o, 'cost', scheme === 'pbkdf2' ? 100 : 14));

function hashFor(pass) {
  if (scheme === 'apr1') return apr1(pass, B64(randomBytes(6)).replace(/[^A-Za-z0-9./]/g, 'x').slice(0, 8));
  if (scheme === 'sha1') return '{SHA}' + createHash('sha1').update(pass, 'utf8').digest('base64');
  if (scheme === 'pbkdf2') {
    const salt = randomBytes(16);
    const key = pbkdf2Sync(pass, salt, Math.max(1000, costArg * 1000), 32, 'sha256');
    return `$pbkdf2-sha256$${Math.max(1000, costArg * 1000)}$${B64(salt)}$${B64(key)}`;
  }
  const N = Math.max(12, Math.min(costArg, 18));
  const salt = randomBytes(16);
  const key = scryptSync(pass, salt, 32, { N: Math.pow(2, N), r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
  return `$scrypt$${N}$${B64(salt)}$${B64(key)}`;
}

function verifyOne(stored, pass) {
  const hash = stored.includes(':') ? stored.split(':').slice(1).join(':') : stored;
  if (hash.startsWith('$apr1$')) {
    const salt = hash.split('$')[2] || '';
    const mine = apr1(pass, salt);
    return { ok: mine.length === hash.length && timingSafeEqual(Buffer.from(mine), Buffer.from(hash)), scheme: 'apr1' };
  }
  if (hash.startsWith('{SHA}')) return { ok: `{SHA}${createHash('sha1').update(pass, 'utf8').digest('base64')}` === hash, scheme: 'sha1' };
  if (hash.startsWith('$scrypt$')) {
    const [, , c, s, k] = hash.split('$');
    const salt = Buffer.from(s, 'base64'), want = Buffer.from(k, 'base64');
    const got = scryptSync(pass, salt, want.length, { N: Math.pow(2, Number(c)), r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
    return { ok: want.length === got.length && timingSafeEqual(want, got), scheme: 'scrypt' };
  }
  if (hash.startsWith('$pbkdf2-sha256$')) {
    const parts = hash.split('$');
    const rounds = Number(parts[3]);
    const salt = Buffer.from(parts[4], 'base64'), want = Buffer.from(parts[5], 'base64');
    const got = pbkdf2Sync(pass, salt, rounds, want.length, 'sha256');
    return { ok: want.length === got.length && timingSafeEqual(want, got), scheme: 'pbkdf2' };
  }
  if (/^\$2[aby]\$/.test(hash)) return { ok: null, scheme: 'bcrypt', note: 'cannot verify with node:crypto' };
  return { ok: null, scheme: 'unknown' };
}

const cmd = (o._[0] || '').toLowerCase();

if (cmd === 'verify' || o.f.verify) {
  const file = o.f.verify && o.f.verify !== true ? String(o.f.verify) : String(get(o, 'file', ''));
  if (!file || !existsSync(file)) die('--verify needs an existing .htpasswd path');
  const pairs = String(get(o, 'check', '')).split(',').map((s) => s.trim()).filter(Boolean).map((s) => { const i = s.indexOf('='); return { user: s.slice(0, i), pass: s.slice(i + 1) }; });
  if (!pairs.length) die('--verify needs --check user1=pass1,user2=pass2');
  const storedMap = new Map();
  for (const l of readFileSync(file, 'utf8').split(/\r?\n/)) {
    if (!l.trim() || l.startsWith('#')) continue;
    const i = l.indexOf(':');
    if (i === -1) continue;
    storedMap.set(l.slice(0, i), l.slice(i + 1));
  }
  const results = pairs.map((p) => {
    if (!storedMap.has(p.user)) return { user: p.user, result: 'NO-ENTRY', scheme: '-' };
    const v = verifyOne(storedMap.get(p.user), p.pass);
    return { user: p.user, result: v.ok === true ? 'MATCH' : v.ok === false ? 'MISMATCH' : 'UNVERIFIABLE', scheme: v.scheme, note: v.note || '' };
  });
  if (flag(o, 'json')) { emit({ file, results, entries: storedMap.size, pass: results.every((r) => r.result === 'MATCH') }); process.exit(0); }
  console.log(`htpasswdgen verify: ${file} (${storedMap.size} entries)`);
  console.log(table(results, ['user', 'result', 'scheme', 'note']));
  process.exit(results.every((r) => r.result === 'MATCH') ? 0 : 1);
}

const users = [];
const usersFile = o.f.users && o.f.users !== true ? String(o.f.users) : null;
if (usersFile) {
  const text = usersFile === '-' ? '' : readFileSync(usersFile, 'utf8');
  for (const line of (text || '').split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const [u, p] = t.split(',');
    if (!u) continue;
    users.push({ user: u.trim(), pass: (p ?? '').trim() });
  }
}
if (o.f.user && o.f.pass) users.push({ user: String(o.f.user), pass: String(o.f.pass) });
if (!users.length) die('nothing to do: pass --users <csv> or --user/--pass');

const seenUser = new Map();
const problems = [];
const entries = [];
for (const u of users) {
  const nm = u.user.trim();
  if (!nm) { problems.push({ user: '(blank)', severity: 'HIGH', message: 'blank username' }); continue; }
  if (/[:\r\n]/.test(nm)) { problems.push({ user: nm, severity: 'HIGH', message: 'username contains ":" or a newline — corrupts .htpasswd' }); continue; }
  if (!u.pass) problems.push({ user: nm, severity: 'HIGH', message: 'empty password — Apache rejects it at auth time' });
  if (/[\r\n]/.test(u.pass)) { problems.push({ user: nm, severity: 'HIGH', message: 'password contains a newline' }); continue; }
  if (seenUser.has(nm)) problems.push({ user: nm, severity: 'MEDIUM', message: `duplicate username (line group ${seenUser.get(nm)}); last entry wins in Apache` });
  seenUser.set(nm, entries.length + 1);
  if (u.pass.length < 10) problems.push({ user: nm, severity: 'MEDIUM', message: `password is only ${u.pass.length} chars` });
  if (u.pass && u.pass === nm) problems.push({ user: nm, severity: 'HIGH', message: 'password equals username' });
  entries.push(`${nm}:${hashFor(u.pass)}`);
}

let merged = 0;
const mergeFile = o.f.merge && o.f.merge !== true ? String(o.f.merge) : null;
let finalEntries = entries;
if (mergeFile && existsSync(mergeFile)) {
  const existing = readFileSync(mergeFile, 'utf8').split(/\r?\n/).filter((l) => l.trim() && !l.startsWith('#'));
  const newUsers = new Set(entries.map((e) => e.split(':')[0]));
  finalEntries = [...entries, ...existing.filter((l) => !newUsers.has(l.split(':')[0]))];
  merged = existing.length - (finalEntries.length - entries.length);
}
const body = finalEntries.join('\n') + '\n';
const out = o.f.out && o.f.out !== true ? String(o.f.out) : null;
if (out) writeFileSync(out, body, { mode: 0o640 });

if (flag(o, 'json')) {
  emit({ scheme, entries: finalEntries.length, generated: entries.length, merged, out: out || '(stdout)', users: finalEntries.map((e) => e.split(':')[0]), problems, body: out ? undefined : body });
  process.exit(problems.some((p) => p.severity === 'HIGH') ? 1 : 0);
}
if (!out) process.stdout.write(body);
console.log(`htpasswdgen: scheme=${scheme} generated=${entries.length} total=${finalEntries.length}${merged ? ` merged=${merged}` : ''}${out ? ` out=${out}` : ''}`);
if (problems.length) { console.log(''); console.log(table(problems, ['severity', 'user', 'message'])); }
process.exit(problems.some((p) => p.severity === 'HIGH') ? 1 : 0);
