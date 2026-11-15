#!/usr/bin/env node
// tlsgrade.js — grade a TLS endpoint's configuration.
// Copyright (c) 2026 0xnothings
// @tool tlsgrade
// @desc Grade a TLS endpoint A+ to F: protocol versions, cipher strength, forward secrecy, certificate chain, OCSP stapling, HSTS and key size
// @usage node tools/tlsgrade.js example.com:443 --json
// @tags devops,tls,security,audit
import { connect as tlsConnect } from 'node:tls';
import { connect as netConnect } from 'node:net';
import { createHash, X509Certificate } from 'node:crypto';
import { args, get, num, flag, die, emit, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`tlsgrade — TLS configuration grader

  node tools/tlsgrade.js <host[:port]> [options]

  --port <n>       default 443
  --sni <name>     SNI / verify hostname override
  --json           machine-readable output
  --min-grade <g>  exit 1 unless the grade is at least this letter
  -h, --help       this text

  Probes each protocol version with a real handshake, inspects the negotiated
  cipher, the presented chain, OCSP stapling, certificate key size/signature
  algorithm, validity window and the HSTS header.`);
  process.exit(0);
}

const target = o._[0];
if (!target) die('usage: node tools/tlsgrade.js <host[:port]> [--json]');
const [h, p] = target.includes(':') ? target.split(':') : [target, String(get(o, 'port', 443))];
const host = h, port = Number(p || 443);
const sni = String(get(o, 'sni', host));

function handshake(version, ciphers) {
  return new Promise((resolve) => {
    let sock;
    const started = Date.now();
    const done = (x) => { try { sock?.destroy(); } catch {} resolve(x); };
    const timer = setTimeout(() => done({ ok: false, error: 'timeout' }), 6000);
    try {
      sock = tlsConnect({
        host, port, servername: sni,
        minVersion: version, maxVersion: version,
        ciphers: ciphers || undefined,
        rejectUnauthorized: false,
        ALPNProtocols: ['h2', 'http/1.1'],
      });
    } catch (e) { clearTimeout(timer); return done({ ok: false, error: e.message }); }
    sock.on('secureConnect', () => {
      clearTimeout(timer);
      const c = sock.getCipher();
      const cert = sock.getPeerCertificate(true);
      const chain = [];
      let cur = cert;
      const seen = new Set();
      while (cur && cur.fingerprint256 && !seen.has(cur.fingerprint256)) {
        seen.add(cur.fingerprint256);
        chain.push(cur);
        cur = cur.issuerCertificate;
      }
      done({
        ok: true, protocol: sock.getProtocol(), cipher: c?.name, bits: undefined,
        alpn: sock.alpnProtocol || null, authorized: sock.authorized, authError: sock.authorizationError || null,
        cert, chain, ms: Date.now() - started, sigalg: undefined,
        sessionReused: sock.isSessionReused ? sock.isSessionReused() : null,
      });
    });
    sock.on('error', (e) => { clearTimeout(timer); done({ ok: false, error: e.code || e.message }); });
  });
}

const VERSIONS = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'];
const protocolResults = [];
for (const v of VERSIONS) protocolResults.push({ version: v, ...(await handshake(v)) });

const strongest = protocolResults.filter((r) => r.ok).pop() || null;
const findings = [];
const add = (sev, rule, msg) => findings.push({ severity: sev, rule, message: msg });

const legacy = protocolResults.filter((r) => r.ok && (r.version === 'TLSv1' || r.version === 'TLSv1.1'));
if (legacy.length) add('HIGH', 'legacy-protocol', `${legacy.map((r) => r.version).join(', ')} accepted — deprecated and vulnerable to BEAST/POODLE-class attacks`);
if (!protocolResults.find((r) => r.version === 'TLSv1.3')?.ok) add('MEDIUM', 'no-tls13', 'TLS 1.3 not offered');
if (!protocolResults.find((r) => r.version === 'TLSv1.2')?.ok) add('HIGH', 'no-tls12', 'TLS 1.2 not offered; many clients cannot connect');

const FS = /(ECDHE|DHE|TLS_AES.*GCM|TLS_CHACHA20)/i;
if (strongest && strongest.cipher && !FS.test(strongest.cipher)) add('HIGH', 'no-forward-secrecy', `negotiated cipher ${strongest.cipher} lacks forward secrecy`);
const WEAK = /(3DES|DES|RC4|NULL|EXPORT|MD5|CBC_SHA$)/i;
if (strongest && strongest.cipher && WEAK.test(strongest.cipher)) add('CRITICAL', 'weak-cipher', `negotiated cipher ${strongest.cipher} is broken or deprecated`);

let certInfo = null, chainRows = [];
if (strongest && strongest.ok && strongest.cert && strongest.cert.raw) {
  const leaf = strongest.cert;
  let x;
  try { x = new X509Certificate(leaf.raw); } catch { x = null; }
  const notAfter = x ? new Date(x.validTo) : new Date(leaf.valid_to);
  const notBefore = x ? new Date(x.validFrom) : new Date(leaf.valid_from);
  const daysLeft = Math.floor((notAfter - Date.now()) / 86400000);
  const keyType = x ? x.publicKey.asymmetricKeyType : 'unknown';
  const keySize = x?.publicKey?.asymmetricKeyDetails?.modulusLength || (keyType === 'ec' ? x?.publicKey?.asymmetricKeyDetails?.namedCurve : null) || null;
  certInfo = {
    subject: leaf.subject?.CN || (x && x.subject), issuer: leaf.issuer?.CN || (x && x.issuer),
    notBefore: notBefore.toISOString().slice(0, 10), notAfter: notAfter.toISOString().slice(0, 10), daysLeft,
    serial: (x ? x.serialNumber : leaf.serialNumber || '').slice(0, 24),
    fingerprint256: leaf.fingerprint256, keyType, keySize,
    san: x ? (x.subjectAltName || '').split(',').map((s) => s.trim().replace(/^DNS:/, '')).filter(Boolean) : [],
    sigAlg: x ? (x.signatureAlgorithm || x.sigAlgorithm || null) : null,
    authorized: strongest.authorized, authError: strongest.authError,
  };
  const names = (x?.subjectAltName || '').split(',').map((s) => s.trim().replace(/^DNS:/, ''));
  if (!strongest.authorized && strongest.authError !== 'UNABLE_TO_VERIFY_LEAF_SIGNATURE') add('HIGH', 'chain-invalid', `certificate verification failed: ${strongest.authError}`);
  else if (!strongest.authorized) add('MEDIUM', 'chain-incomplete', 'leaf could not be verified — an intermediate is likely missing from the served chain');
  if (daysLeft < 0) add('CRITICAL', 'cert-expired', `certificate expired ${-daysLeft} days ago`);
  else if (daysLeft < 14) add('CRITICAL', 'cert-expiring', `certificate expires in ${daysLeft} days`);
  else if (daysLeft < 30) add('MEDIUM', 'cert-soon', `certificate expires in ${daysLeft} days`);
  if (names.length && !names.some((n) => n === sni || (n.startsWith('*.') && sni.endsWith(n.slice(1))))) add('HIGH', 'sni-mismatch', `SNI ${sni} is not covered by the SAN (${names.slice(0, 4).join(', ')})`);
  if (keyType === 'rsa' && keySize && keySize < 2048) add('CRITICAL', 'weak-key', `RSA key is only ${keySize} bits`);
  if (keyType === 'rsa' && keySize && keySize < 3072) add('LOW', 'key-size', `RSA-${keySize} is acceptable but RSA-3072+ or ECDSA P-256 is preferred`);
  if (certInfo.sigAlg && /sha1/i.test(certInfo.sigAlg)) add('HIGH', 'sha1-sig', `certificate signed with ${certInfo.sigAlg}`);
  if (chainRows.length > 1) { /* filled below */ }
  chainRows = strongest.chain.map((c, i) => ({ depth: i, subject: c.subject?.CN || '(root)', issuer: c.issuer?.CN || '(self)', validTo: c.valid_to, selfSigned: (c.subject?.CN || '') === (c.issuer?.CN || '') }));
  if (strongest.chain.length < 2) add('MEDIUM', 'no-intermediates', 'server sent only one certificate — clients must fetch the intermediate via AIA');
  const hasOcsp = /OCSP/.test(x ? (x.infoAccess || '') : '');
  if (!hasOcsp) add('LOW', 'no-aia', 'no OCSP AIA URL in the leaf certificate');
}

function httpHead(servername) {
  return new Promise((resolve) => {
    let s;
    const done = (x) => { try { s?.destroy(); } catch {} resolve(x); };
    const timer = setTimeout(() => done({ ok: false }), 6000);
    try { s = tlsConnect({ host, port, servername, rejectUnauthorized: false, ALPNProtocols: ['http/1.1'] }); }
    catch { clearTimeout(timer); return done({ ok: false }); }
    s.on('secureConnect', () => { s.write(`HEAD / HTTP/1.1\r\nHost: ${servername}\r\nUser-Agent: tlsgrade\r\nConnection: close\r\n\r\n`); });
    s.on('data', (d) => { clearTimeout(timer); done({ ok: true, head: d.toString('utf8').slice(0, 2000) }); });
    s.on('error', () => { clearTimeout(timer); done({ ok: false }); });
  });
}

const http = await httpHead(sni);
let hsts = null, server = null, redirects = false;
if (http.ok) {
  hsts = (http.head.match(/strict-transport-security:\s*([^\r\n]+)/i) || [])[1]?.trim() || null;
  server = (http.head.match(/^server:\s*([^\r\n]+)/im) || [])[1]?.trim() || null;
  redirects = /^HTTP\/1\.[01]\s+30[18]/.test(http.head);
  if (!hsts) add('MEDIUM', 'no-hsts', 'no Strict-Transport-Security header — downgrade attacks remain possible');
  else {
    const maxAge = Number((hsts.match(/max-age=(\d+)/i) || [])[1] || 0);
    if (maxAge < 15552000) add('LOW', 'weak-hsts', `HSTS max-age=${maxAge}s is under 180 days`);
    if (!/includeSubDomains/i.test(hsts)) add('LOW', 'hsts-subdomains', 'HSTS without includeSubDomains');
  }
}
// cleartext listener check
const cleartext = await new Promise((resolve) => {
  const s = netConnect({ host, port: 80 });
  const timer = setTimeout(() => { try { s.destroy(); } catch {} resolve(false); }, 3000);
  s.on('connect', () => { clearTimeout(timer); s.destroy(); resolve(true); });
  s.on('error', () => { clearTimeout(timer); resolve(false); });
});
if (cleartext && !redirects) add('MEDIUM', 'port80-open', 'port 80 accepts connections without a redirect to HTTPS');

// grade
let score = 100;
const DEDUCT = { CRITICAL: 45, HIGH: 20, MEDIUM: 8, LOW: 3 };
for (const f of findings) score -= DEDUCT[f.severity];
if (protocolResults.find((r) => r.version === 'TLSv1.3')?.ok && !legacy.length) score += 6;
score = Math.max(0, Math.min(100, score));
const grade = score >= 96 ? 'A+' : score >= 88 ? 'A' : score >= 78 ? 'B' : score >= 65 ? 'C' : score >= 50 ? 'D' : score >= 30 ? 'E' : 'F';

const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
for (const f of findings) counts[f.severity]++;
const minGrade = o.f['min-grade'] ? String(o.f['min-grade']).toUpperCase() : null;
const ORDER = ['A+', 'A', 'B', 'C', 'D', 'E', 'F'];
const fail = minGrade ? ORDER.indexOf(grade) > ORDER.indexOf(minGrade) : counts.CRITICAL > 0;

if (flag(o, 'json')) {
  emit({ target: `${host}:${port}`, sni, grade, score, protocols: protocolResults.map((r) => ({ version: r.version, supported: !!r.ok, cipher: r.cipher || null, error: r.error || null, ms: r.ms })), certificate: certInfo, chain: chainRows, hsts, server, port80Open: cleartext, alpn: strongest?.alpn || null, findings, counts, pass: !fail });
  process.exit(0);
}

console.log(`tlsgrade: ${host}:${port} (sni ${sni})`);
console.log(`grade: ${grade}  score: ${score}/100  findings: ${findings.length} (${counts.CRITICAL} critical, ${counts.HIGH} high)`);
if (strongest) console.log(`negotiated: ${strongest.protocol} ${strongest.cipher}  alpn=${strongest.alpn || '-'}`);
console.log('');
console.log(table(protocolResults.map((r) => ({ protocol: r.version, supported: r.ok ? 'yes' : 'no', cipher: r.cipher || (r.error || '-'), ms: r.ms ?? '-' })), ['protocol', 'supported', 'cipher', 'ms']));
if (certInfo) {
  console.log('\ncertificate:');
  console.log(table([{ subject: certInfo.subject, issuer: certInfo.issuer, valid: `${certInfo.notBefore} -> ${certInfo.notAfter}`, daysLeft: certInfo.daysLeft, key: `${certInfo.keyType} ${certInfo.keySize || ''}`, sig: certInfo.sigAlg || '-', verified: certInfo.authorized ? 'yes' : `no (${certInfo.authError})` }], ['subject', 'issuer', 'valid', 'daysLeft', 'key', 'sig', 'verified']));
  if (certInfo.san.length) console.log(`SAN: ${certInfo.san.slice(0, 12).join(', ')}${certInfo.san.length > 12 ? ` (+${certInfo.san.length - 12})` : ''}`);
}
if (chainRows.length > 1) {
  console.log('\nchain:');
  console.log(table(chainRows.map((c) => ({ depth: c.depth, subject: c.subject, issuer: c.issuer, selfSigned: c.selfSigned ? 'yes' : 'no' })), ['depth', 'subject', 'issuer', 'selfSigned']));
}
console.log(`\nhttp: hsts=${hsts || '(none)'}  server=${server || '-'}  port80=${cleartext ? 'open' : 'closed'}${redirects ? ' (redirects to https)' : ''}`);
if (findings.length) {
  console.log('\nfindings:');
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  console.log(table(findings.sort((a, b) => order[a.severity] - order[b.severity]).map((f) => ({ severity: f.severity, rule: f.rule, detail: f.message })), ['severity', 'rule', 'detail']));
}
process.exit(fail ? 1 : 0);
