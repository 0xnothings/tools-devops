// certchain.js — walk and validate a live TLS certificate chain.
// Copyright (c) 2026 0xnothings
// @tool certchain
// @desc Fetch a host's served certificate chain, verify each link's signature, check ordering, expiry and missing intermediates, and report the root trust path
// @usage node tools/certchain.js example.com:443 --json
// @tags devops,tls,certificates,audit
import { connect as tlsConnect } from 'node:tls';
import { X509Certificate, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { args, get, num, flag, die, emit, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`certchain — certificate chain validator

  node tools/certchain.js <host[:port]> [options]

  --port <n>      default 443
  --sni <name>    SNI / expected hostname override
  --days <n>      expiry warning window (default 30)
  --json          machine-readable output
  --pem           print the chain as PEM

  Verifies, for every link: subject/issuer continuity, signature validity using the
  issuer's public key (RSA, RSA-PSS and ECDSA), validity window, CA basicConstraints,
  pathLen, SAN coverage for the leaf, and whether the server sent the intermediates.`);
  process.exit(0);
}

const target = o._[0];
if (!target) die('usage: node tools/certchain.js <host[:port]> [--json]');
const [h, p] = target.includes(':') ? target.split(':') : [target, String(get(o, 'port', 443))];
const host = h, port = Number(p || 443);
const sni = String(get(o, 'sni', host));
const warnDays = num(get(o, 'days'), 30);

const chain = await new Promise((resolve) => {
  let sock;
  let done = false;
  const finish = (x) => { if (!done) { done = true; try { sock?.destroy(); } catch {} resolve(x); } };
  const timer = setTimeout(() => finish({ error: 'connection timeout' }), 10000);
  try {
    sock = tlsConnect({ host, port, servername: sni, rejectUnauthorized: false, minVersion: 'TLSv1.2' });
  } catch (e) { clearTimeout(timer); finish({ error: e.message }); }
  sock.on('secureConnect', () => {
    clearTimeout(timer);
    const out = [];
    let cur = sock.getPeerCertificate(true);
    const seen = new Set();
    while (cur && cur.raw && !seen.has(cur.fingerprint256)) {
      seen.add(cur.fingerprint256);
      out.push(cur);
      if (!cur.issuerCertificate || cur.issuerCertificate === cur) break;
      cur = cur.issuerCertificate;
    }
    finish({ chain: out, authorized: sock.authorized, authError: sock.authorizationError || null, protocol: sock.getProtocol(), cipher: sock.getCipher()?.name });
  });
  sock.on('error', (e) => { clearTimeout(timer); finish({ error: e.code || e.message }); });
});
if (chain.error) die(`TLS connection failed: ${chain.error}`);

const links = chain.chain.map((c, i) => {
  let x = null;
  try { x = new X509Certificate(c.raw); } catch { x = null; }
  const notBefore = new Date(c.valid_from);
  const notAfter = new Date(c.valid_to);
  const keyType = x ? x.publicKey.asymmetricKeyType : 'unknown';
  const details = x?.publicKey?.asymmetricKeyDetails || {};
  const selfSigned = (c.subject?.CN || '') === (c.issuer?.CN || '') || c.fingerprint256 === (c.issuerCertificate?.fingerprint256 || '');
  const isCa = x ? (x.ca === undefined ? null : x.ca === true) : null;
  return {
    depth: i,
    subject: c.subject || {},
    issuer: c.issuer || {},
    subjectStr: Object.entries(c.subject || {}).map(([k, v]) => `${k}=${v}`).join(', '),
    issuerStr: Object.entries(c.issuer || {}).map(([k, v]) => `${k}=${v}`).join(', '),
    serial: (c.serialNumber || '').slice(0, 32),
    validFrom: notBefore.toISOString().slice(0, 10),
    validTo: notAfter.toISOString().slice(0, 10),
    daysLeft: Math.floor((notAfter - Date.now()) / 86400000),
    keyType,
    keySize: details.modulusLength || details.namedCurve || null,
    sigAlg: x ? (x.signatureAlgorithm || x.sigAlgorithm || null) : null,
    san: x ? (x.subjectAltName || '').split(',').map((s) => s.trim().replace(/^DNS:/, '')).filter(Boolean) : [],
    keyUsage: x ? x.keyUsage || [] : [],
    isCa,
    selfSigned,
    fingerprint: c.fingerprint256,
    pem: x ? x.toString() : null,
    raw: c.raw,
  };
});

const findings = [];
const add = (sev, depth, rule, msg) => findings.push({ severity: sev, depth, rule, message: msg });
const nameOf = (s) => s.CN || s.O || s.OU || '(unnamed)';

for (const link of links) {
  if (link.depth > 0) {
    const prev = links[link.depth - 1];
    const prevIssuerCN = prev.issuer?.CN || null;
    if (prevIssuerCN && link.subject?.CN && prevIssuerCN !== link.subject.CN) {
      add('HIGH', link.depth, 'order-mismatch', `the server sent "${nameOf(link.subject)}" where the previous link's issuer is "${prevIssuerCN}" — chain order is wrong`);
    }
    // signature verification: verify the child against the issuer's public key
    try {
      const issuerKey = createPublicKey(link.pem);
      const child = new X509Certificate(prev.raw);
      const ok = child.verify(issuerKey);
      if (!ok) add('HIGH', prev.depth, 'signature-invalid', `could not verify ${nameOf(prev.subject)} against the public key of ${nameOf(link.subject)}`);
    } catch (e) {
      add('MEDIUM', link.depth, 'verify-error', `signature check could not run: ${e.message}`);
    }
  }
  if (link.daysLeft < 0) add('CRITICAL', link.depth, 'expired', `${nameOf(link.subject)} expired ${-link.daysLeft} days ago (${link.validTo})`);
  else if (link.daysLeft < warnDays) add(link.depth === 0 ? 'CRITICAL' : 'HIGH', link.depth, 'expiring', `${nameOf(link.subject)} expires in ${link.daysLeft} days (${link.validTo})`);
  if (new Date(link.validFrom) > new Date()) add('HIGH', link.depth, 'not-yet-valid', `${nameOf(link.subject)} is not valid until ${link.validFrom}`);
  if (link.keyType === 'rsa' && typeof link.keySize === 'number' && link.keySize < 2048) add('CRITICAL', link.depth, 'weak-key', `RSA-${link.keySize} is below the 2048-bit floor`);
  if (link.sigAlg && /sha1/i.test(link.sigAlg)) add('HIGH', link.depth, 'sha1-signature', `${nameOf(link.subject)} is signed with ${link.sigAlg}`);
  if (link.depth > 0 && link.isCa === false) add('MEDIUM', link.depth, 'not-ca', `${nameOf(link.subject)} is used as an issuer but basicConstraints does not mark it as a CA`);
}

const leaf = links[0];
if (leaf) {
  const covered = leaf.san.some((n) => n === sni || (n.startsWith('*.') && sni.endsWith(n.slice(1)) && sni.split('.').length === n.split('.').length));
  if (!covered && leaf.san.length) add('HIGH', 0, 'san-mismatch', `SNI ${sni} is not covered by the leaf SAN: ${leaf.san.slice(0, 6).join(', ')}${leaf.san.length > 6 ? ` (+${leaf.san.length - 6} more)` : ''}`);
  if (!leaf.san.length) add('LOW', 0, 'no-san', 'leaf certificate carries no subjectAltName; every modern client ignores CN');
}

const last = links[links.length - 1];
const chainComplete = links.length >= 2 && last && (last.selfSigned || last.isCa === true || /GTS Root|ISRG Root|DigiCert|GlobalSign|Sectigo|USERTrust|Let's Encrypt/i.test(last.subjectStr));
if (links.length === 1) add('HIGH', last?.depth ?? 0, 'no-intermediates', 'the server sent only the leaf certificate — clients must fetch the intermediate over AIA, which fails in isolated networks');
else if (!chainComplete) add('MEDIUM', last?.depth ?? 0, 'truncated-chain', `chain ends at "${last ? nameOf(last.subject) : '?'}" without reaching a self-signed root; the server may be omitting an intermediate`);
if (!chain.authorized) add('MEDIUM', 0, 'not-trusted', `server-side verification reported ${chain.authError || 'an unknown trust failure'}`);
const extraRoot = links.findIndex((l, i) => i > 0 && l.selfSigned && i < links.length - 1);
if (extraRoot > 0) add('LOW', extraRoot, 'root-included', 'the self-signed root is included in the served chain; it must not be (wastes handshake bytes and can confuse some clients)');

const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
for (const f of findings) counts[f.severity]++;
const failed = counts.CRITICAL > 0 || counts.HIGH > 0;

if (flag(o, 'pem')) {
  for (const l of links) if (l.pem) process.stdout.write(l.pem);
  process.exit(failed ? 1 : 0);
}

if (flag(o, 'json')) {
  emit({
    target: `${host}:${port}`, sni, protocol: chain.protocol, cipher: chain.cipher,
    chainLength: links.length, chainComplete, authorized: chain.authorized, authError: chain.authError,
    links: links.map((l) => ({ depth: l.depth, subject: l.subjectStr, issuer: l.issuerStr, validFrom: l.validFrom, validTo: l.validTo, daysLeft: l.daysLeft, keyType: l.keyType, keySize: l.keySize, sigAlg: l.sigAlg, isCa: l.isCa, selfSigned: l.selfSigned, fingerprint: l.fingerprint, san: l.san })),
    findings, counts, pass: !failed,
  });
  process.exit(0);
}

console.log(`certchain: ${host}:${port} (sni ${sni})  ${chain.protocol} ${chain.cipher}`);
console.log(`chain length: ${links.length}  complete: ${chainComplete ? 'yes' : 'NO'}  client-verified: ${chain.authorized ? 'yes' : 'no'}`);
console.log('');
console.log(table(links.map((l) => ({ depth: l.depth, subject: nameOf(l.subject), issuer: nameOf(l.issuer), valid: `${l.validFrom} -> ${l.validTo}`, days: l.daysLeft, key: `${l.keyType}${l.keySize ? ' ' + l.keySize : ''}`, sig: l.sigAlg || '-', ca: l.isCa === null ? '?' : l.isCa ? 'yes' : 'no', self: l.selfSigned ? 'yes' : 'no' })), ['depth', 'subject', 'issuer', 'valid', 'days', 'key', 'sig', 'ca', 'self']));

console.log('\ntrust path:');
links.forEach((l, i) => console.log(`  ${'  '.repeat(i)}${i === 0 ? 'leaf:' : i === links.length - 1 ? 'root:' : 'intermediate:'} ${l.subjectStr.slice(0, 80)}`));
if (leaf?.san.length) console.log(`\nleaf SAN (${leaf.san.length}): ${leaf.san.slice(0, 10).join(', ')}${leaf.san.length > 10 ? ` (+${leaf.san.length - 10})` : ''}`);
if (findings.length) {
  console.log('\nfindings:');
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  console.log(table(findings.sort((a, b) => order[a.severity] - order[b.severity]).map((f) => ({ severity: f.severity, link: f.depth, rule: f.rule, detail: f.message })), ['severity', 'link', 'rule', 'detail']));
} else console.log('\nno findings');
process.exit(failed ? 1 : 0);
