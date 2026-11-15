// basicauth.js — issue and verify HTTP Basic credentials for htpasswd/bcrypt.
// Copyright (c) 2026 0xnothings
// @tool basicauth
// @desc Create and verify htpasswd-style credentials (bcrypt via scrypt/PBKDF2 documented) with an .htaccess snippet
// @usage node tools/basicauth.js issue --user admin --pass secret --json
// @tags devops,http,basic-auth,security
import { randomBytes, scryptSync, timingSafeEqual, createHash, pbkdf2Sync } from 'node:crypto';
import { args, get, flag, die, emit } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`basicauth — HTTP Basic credential tooling

  node tools/basicauth.js <issue|verify|snippet|check> [options]

  issue     --user <u> --pass <p> [--scheme scrypt|pbkdf2|apr1|sha1] [--cost N]
  verify    --user <u> --pass <p> --hash <stored>
  check     --pass <p> [--hash <stored>]     strength meter only
  snippet   --file <path> [--realm <r>]      emit the .htaccess block

  --json      machine-readable output
  -h, --help  this text

  Note: bcrypt cannot be produced by node:crypto (there is no blowfish primitive).
  This tool emits scrypt and PBKDF2 hashes with Apache-recognised prefixes where
  applicable, plus APR1-MD5 (htpasswd -m) implemented by hand, which Apache
  accepts natively.`);
  process.exit(0);
}

const cmd = (o._[0] || 'issue').toLowerCase();
const B64 = (buf) => Buffer.from(buf).toString('base64').replace(/=+$/, '');
const B64URL = (buf) => Buffer.from(buf).toString('base64').replace(/\+/g, '.');

// --- APR1-MD5, Apache's htpasswd -m format, hand-written (RFC-free, undocumented but stable) ---
const APR_MD5_ITOA64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
function to64(v, n) { let s = ''; while (--n >= 0) { s += APR_MD5_ITOA64[v & 0x3f]; v >>>= 6; } return s; }
function md5(buf) { return createHash('md5').update(buf).digest(); }
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

function sha1Hex(pw) { return createHash('sha1').update(pw, 'utf8').digest('base64').replace(/=+$/, ''); }

function issueScrypt(user, pass, cost) {
  const N = Math.max(2 ** 12, Math.min(2 ** cost, 2 ** 20));
  const salt = randomBytes(16);
  const key = scryptSync(pass, salt, 32, { N: Math.pow(2, cost), r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
  return `${user}:$scrypt$${cost}$${B64(salt)}$${B64(key)}`;
}
function issuePbkdf2(user, pass, rounds) {
  const salt = randomBytes(16);
  const key = pbkdf2Sync(pass, salt, rounds, 32, 'sha256');
  return `${user}:$pbkdf2-sha256$${rounds}$${B64(salt)}$${B64(key)}`;
}

function strength(p) {
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((r) => r.test(p)).length;
  let pool = 0;
  if (/[a-z]/.test(p)) pool += 26;
  if (/[A-Z]/.test(p)) pool += 26;
  if (/[0-9]/.test(p)) pool += 10;
  if (/[^A-Za-z0-9]/.test(p)) pool += 33;
  const bits = p.length ? Math.round(p.length * Math.log2(Math.max(pool, 1))) : 0;
  const common = /^(password|admin|letmein|qwerty|123456|welcome|changeme)/i.test(p);
  let verdict = 'weak';
  if (bits >= 80 && !common) verdict = 'strong';
  else if (bits >= 60 && !common) verdict = 'acceptable';
  else if (bits >= 45 && !common) verdict = 'marginal';
  const suggestions = [];
  if (p.length < 12) suggestions.push('use at least 12 characters');
  if (classes < 3) suggestions.push('mix upper, lower, digits and symbols');
  if (common) suggestions.push('starts with a well-known password pattern');
  if (/(.)\1{2,}/.test(p)) suggestions.push('repeated characters reduce entropy');
  return { length: p.length, classes, pool, bits, common, verdict, suggestions };
}

if (cmd === 'check') {
  const pass = String(get(o, 'pass', ''));
  if (!pass) die('--pass is required');
  const s = strength(pass);
  if (flag(o, 'json')) { emit(s); process.exit(0); }
  console.log(`length: ${s.length}  classes: ${s.classes}  pool: ${s.pool}  entropy: ~${s.bits} bits  verdict: ${s.verdict}`);
  for (const x of s.suggestions) console.log(`  - ${x}`);
  process.exit(s.verdict === 'weak' ? 1 : 0);
}

if (cmd === 'issue') {
  const user = String(get(o, 'user', ''));
  const pass = String(get(o, 'pass', ''));
  if (!user || !pass) die('--user and --pass are required');
  if (/[:\r\n]/.test(user)) die('username may not contain ":" or newlines');
  if (/[\r\n]/.test(pass)) die('password may not contain newlines');
  const scheme = String(get(o, 'scheme', 'scrypt')).toLowerCase();
  const cost = Number(get(o, 'cost', 14));
  let entry, note;
  if (scheme === 'apr1') {
    const salt = B64URL(randomBytes(6)).slice(0, 8);
    entry = `${user}:${apr1(pass, salt)}`;
    note = 'Apache htpasswd -m compatible (MD5, fast — brute-forceable, prefer scrypt where your server supports it)';
  } else if (scheme === 'sha1') {
    entry = `${user}:{SHA}${sha1Hex(pass)}`;
    note = 'htpasswd -s compatible; SHA1 is legacy, use only for compatibility';
  } else if (scheme === 'pbkdf2') {
    const rounds = 100000;
    entry = issuePbkdf2(user, pass, rounds);
    note = `PBKDF2-SHA256 ${rounds} rounds`;
  } else {
    entry = issueScrypt(user, pass, Math.max(12, Math.min(cost, 18)));
    note = `scrypt N=2^${Math.max(12, Math.min(cost, 18))} r=8 p=1`;
  }
  const s = strength(pass);
  const verifyCmd = `node tools/basicauth.js verify --user ${user} --pass <plaintext> --hash "${entry.split(':').slice(1).join(':')}"`;
  if (flag(o, 'json')) { emit({ user, scheme, entry, note, strength: s, verify: verifyCmd }); process.exit(0); }
  console.log(entry);
  console.log(`# scheme: ${scheme} — ${note}`);
  console.log(`# strength: ${s.verdict} (~${s.bits} bits)`);
  for (const x of s.suggestions) console.log(`#   - ${x}`);
  process.exit(0);
}

if (cmd === 'verify') {
  const user = String(get(o, 'user', ''));
  const pass = String(get(o, 'pass', ''));
  const stored = String(get(o, 'hash', ''));
  if (!pass || !stored) die('--pass and --hash are required');
  const hash = stored.includes(':') ? stored.split(':').slice(1).join(':') : stored;
  let ok = false, scheme = 'unknown';
  const hm = hash.match(/^\$(\w+)\$/);
  if (hash.startsWith('$apr1$')) {
    scheme = 'apr1';
    const salt = hash.split('$')[2] || '';
    const mine = apr1(pass, salt);
    ok = mine.length === hash.length && timingSafeEqual(Buffer.from(mine), Buffer.from(hash));
  } else if (hash.startsWith('{SHA}')) {
    scheme = 'sha1';
    const mine = `{SHA}${sha1Hex(pass)}`;
    ok = mine === hash;
  } else if (hash.startsWith('$scrypt$')) {
    scheme = 'scrypt';
    const [, , c, saltB64, keyB64] = hash.split('$');
    const salt = Buffer.from(saltB64, 'base64');
    const want = Buffer.from(keyB64, 'base64');
    const got = scryptSync(pass, salt, want.length, { N: Math.pow(2, Number(c)), r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
    ok = want.length === got.length && timingSafeEqual(want, got);
  } else if (/^\$2[aby]\$/.test(hash)) {
    die('bcrypt hashes cannot be verified by node:crypto; install bcrypt or verify server-side');
  } else if (/^[A-Za-z0-9./]{13}$/.test(hash)) {
    scheme = 'crypt-des';
    die('classic DES crypt is not implemented (and should not be used)');
  } else if (hm && /pbkdf2/i.test(hm[1])) {
    die('PBKDF2 verification requires the rounds and salt from the stored string; it is available on request');
  } else {
    die(`unrecognised hash format: ${hash.slice(0, 16)}...`);
  }
  if (flag(o, 'json')) { emit({ user, scheme, ok }); process.exit(ok ? 0 : 1); }
  console.log(ok ? `OK: password matches (${scheme})` : `FAIL: password does not match (${scheme})`);
  process.exit(ok ? 0 : 1);
}

if (cmd === 'snippet') {
  const file = String(get(o, 'file', '/etc/nginx/.htpasswd'));
  const realm = String(get(o, 'realm', 'Restricted'));
  const body = [
    `AuthType Basic`,
    `AuthName "${realm}"`,
    `AuthUserFile ${file}`,
    `Require valid-user`,
  ].join('\n');
  if (flag(o, 'json')) { emit({ file, realm, htaccess: body, apacheBlock: `<Directory /var/www/private>\n  ${body.replace(/\n/g, '\n  ')}\n</Directory>` }); process.exit(0); }
  console.log('# .htaccess');
  console.log(body);
  console.log('\n# Apache <Directory> block');
  console.log(`<Directory /var/www/private>\n  ${body.replace(/\n/g, '\n  ')}\n</Directory>`);
  console.log('\n# nginx equivalent');
  console.log(`location /private/ {\n  auth_basic "${realm}";\n  auth_basic_user_file ${file};\n}`);
  process.exit(0);
}

die(`unknown command "${cmd}" — try issue, verify, check or snippet`);
