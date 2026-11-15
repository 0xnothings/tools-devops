// certgen.js — self-signed and CSR certificate toolkit.
// Copyright (c) 2026 0xnothings
// @tool certgen
// @desc Generate RSA/EC keys, CSRs and self-signed certificates via openssl, plus base64 one-liners for CSR submission
// @usage node tools/certgen.js --cn example.com --san example.com,www.example.com --days 825 --out ./certs
// @tags devops,tls,certificates
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { args, get, num, flag, die } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`certgen — key / CSR / self-signed certificate generator

  node tools/certgen.js [options]

  --cn <name>        common name, e.g. example.com or 10.0.0.5
  --san <list>       subject alternative names (default: --cn)
  --type <t>         rsa | ec  (default: rsa)
  --bits <n>         RSA bits: 2048 | 4096 (default: 4096)
  --curve <c>        EC curve: prime256v1 | secp384r1 | secp521r1 (default: prime256v1)
  --days <n>         validity in days (default: 825)
  --out <dir>        output directory (default: ./certs)
  --csr-only         generate key + CSR, do not self-sign
  --ca <path>        sign the CSR with this CA (cert.pem + key.pem, dash separated via --ca-key)
  --ca-key <path>
  --pfx <pass>       also export a PKCS#12 bundle
  -h, --help         this text`);
  process.exit(0);
}

const cn = o.f.cn ? String(get(o, 'cn')) : die('--cn is required (e.g. example.com)');
const type = String(get(o, 'type', 'rsa'));
const bits = num(get(o, 'bits'), 4096);
const curve = String(get(o, 'curve', 'prime256v1'));
const days = num(get(o, 'days'), 825);
const outDir = String(get(o, 'out', './certs'));
const sans = String(get(o, 'san', cn)).split(',').map((s) => s.trim()).filter(Boolean);
mkdirSync(outDir, { recursive: true });

const run = (cmd, a) => {
  try { return execFileSync(cmd, a, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); }
  catch (e) { die(`${cmd} failed: ${(e.stderr || e.message).toString().split('\n')[0]}`); }
};

const keyPath = join(outDir, `${cn}.key`);
const csrPath = join(outDir, `${cn}.csr`);
const crtPath = join(outDir, `${cn}.crt`);
const extPath = join(outDir, `${cn}.ext`);

if (type === 'ec') run('openssl', ['ecparam', '-name', curve, '-genkey', '-noout', '-out', keyPath]);
else run('openssl', ['genrsa', '-out', keyPath, String(bits)]);

const sanLine = sans.map((s) => (/^\d+\.\d+\.\d+\.\d+$/.test(s) ? `IP:${s}` : `DNS:${s}`)).join(',');
writeFileSync(extPath, `basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=${sanLine}\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n`, 'utf8');

const subj = `/CN=${cn}${/\d+\.\d+\.\d+\.\d+/.test(cn) ? '' : `/O=0xnothings${/^[^.]+\.[^.]+$/.test(cn) ? `/C=XX` : ''}`}`;
run('openssl', ['req', '-new', '-key', keyPath, '-out', csrPath, '-subj', subj, '-addext', `subjectAltName=${sanLine}`]);

if (!flag(o, 'csr-only')) {
  if (o.f.ca && o.f['ca-key']) {
    run('openssl', ['x509', '-req', '-in', csrPath, '-CA', String(get(o, 'ca')), '-CAkey', String(get(o, 'ca-key')), '-CAcreateserial', '-out', crtPath, '-days', String(days), '-sha256', '-extfile', extPath]);
  } else {
    run('openssl', ['x509', '-req', '-in', csrPath, '-signkey', keyPath, '-out', crtPath, '-days', String(days), '-sha256', '-extfile', extPath]);
  }
}

if (o.f.pfx && !flag(o, 'csr-only')) {
  run('openssl', ['pkcs12', '-export', '-out', join(outDir, `${cn}.pfx`), '-inkey', keyPath, '-in', crtPath, '-passout', `pass:${get(o, 'pfx')}`]);
}

let info = null;
if (existsSync(crtPath)) {
  try {
    const t = execFileSync('openssl', ['x509', '-in', crtPath, '-noout', '-subject', '-issuer', '-dates', '-ext', 'subjectAltName'], { encoding: 'utf8' });
    info = t.trim();
  } catch {}
}
const csrB64 = existsSync(csrPath) ? readFileSync(csrPath, 'utf8').replace(/-----[^-]+-----/g, '').replace(/\s+/g, '') : '';

console.log(`wrote:`);
console.log(`  ${keyPath}   (private key — chmod 600)`);
console.log(`  ${csrPath}   (${sans.length} SAN${sans.length > 1 ? 's' : ''})`);
if (!flag(o, 'csr-only')) console.log(`  ${crtPath}   (${days} days)`);
if (o.f.pfx) console.log(`  ${join(outDir, `${cn}.pfx`)}   (PKCS#12)`);
try { execFileSync('chmod', ['600', keyPath]); } catch {}
if (info) console.log('\n' + info);
if (!flag(o, 'csr-only') && !o.f.ca) console.log('\nself-signed: browsers will warn. For a CA-issued cert, submit the CSR to your CA.');

if (flag(o, 'json')) console.log(JSON.stringify({ cn, sans, type, bits: type === 'rsa' ? bits : curve, days, files: { key: keyPath, csr: csrPath, crt: flag(o, 'csr-only') ? null : crtPath }, csr_der_base64_for_DV_api: csrB64.slice(0, 200) + '...' }, null, 2));
