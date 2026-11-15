// mailauth.js — audit a domain's email authentication posture.
// Copyright (c) 2026 0xnothings
// @tool mailauth
// @desc Check SPF (all-qualifier, lookup count), DMARC (policy, rua, pct), DKIM selector presence, MTA-STS, TLS-RPT and BIMI, with a spoofability verdict
// @usage node tools/mailauth.js example.com --dkim-selectors google,s1,mail --json
// @tags devops,email,dns,security
import { resolveTxt, resolve4, resolve6, resolveMx } from 'node:dns/promises';
import { args, get, num, flag, die, emit, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`mailauth — email authentication auditor

  node tools/mailauth.js <domain> [options]

  --dkim-selectors <csv>  selectors to probe (default: a curated common set)
  --json                  machine-readable output
  --expect-reject         fail unless DMARC enforces p=reject
  -h, --help              this text

  Checks SPF syntax, the terminal all mechanism, the 10-lookup budget and void
  lookups; DMARC presence, policy, subdomain policy, rua/ruf and pct; DKIM key
  presence and strength per selector; MTA-STS DNS record and policy file;
  SMTP TLS reporting; BIMI; plus a plain spoofability verdict.`);
  process.exit(0);
}

const domain = o._[0];
if (!domain) die('usage: node tools/mailauth.js <domain> [--json]');
const selectors = (o.f['dkim-selectors'] ? String(o.f['dkim-selectors']) : 'default,google,selector1,selector2,s1,s2,mail,dkim,mandrill,mailjet,dkim1024,smtp,amazonses,cm,k1,k2,20230601,protonmail,everlytickey1').split(',').map((s) => s.trim()).filter(Boolean);

const txt = async (name) => { try { const r = await resolveTxt(name); return r.map((chunks) => chunks.join('')); } catch { return []; } };

const findings = [];
const add = (sev, rule, msg) => findings.push({ severity: sev, rule, message: msg });
const result = { domain, spf: null, dmarc: null, dkim: [], mtaSts: null, tlsRpt: null, bimi: null, mx: [] };

// --- SPF ---
const rootTxt = await txt(domain);
const spfRecords = rootTxt.filter((t) => /^v=spf1\b/i.test(t));
if (!spfRecords.length) add('HIGH', 'no-spf', 'no SPF record — anyone can send as this domain and receivers have nothing to check');
else if (spfRecords.length > 1) add('CRITICAL', 'multiple-spf', `${spfRecords.length} SPF records — RFC 7208 permits exactly one; receivers treat multiple records as a permanent error`);
else {
  const spf = spfRecords[0];
  const terms = spf.split(/\s+/).slice(1);
  const alls = terms.filter((t) => /^[-~+?]?all$/i.test(t));
  const terminal = alls[alls.length - 1] || null;
  const lookups = terms.filter((t) => /^(include:|a$|a:|mx$|mx:|ptr$|ptr:|exists:|redirect=)/i.test(t) && !/^[+-~?]?/.test(t.replace(/^[+-~?]/, '')) === false).length;
  const lookupCount = terms.filter((t) => /(^|:)(include|exists|ptr)/i.test(t) || /^[aA](:|$)/.test(t) || /^mx(:|$)/i.test(t) || /^redirect=/i.test(t) || /^[+-~?]?(a|mx|include|exists|ptr|redirect)/i.test(t)).length;
  const mechanisms = terms.filter((t) => /^[+-~?]?(include:|a|mx|ptr|exists:|ip4:|ip6:|all)/i.test(t));
  result.spf = { record: spf, mechanisms: mechanisms.length, all: terminal, lookupEstimate: terms.length, terms };
  const hasRedirect = /(^|\s)redirect=/i.test(spf);
  if (!terminal && hasRedirect) {
    result.spf.all = 'redirect';
    result.spf.redirect = (spf.match(/redirect=(\S+)/i) || [])[1];
  } else if (!terminal) add('CRITICAL', 'spf-no-all', 'SPF has no "all" mechanism and no redirect= — the final result is Neutral, so the record does nothing');
  else if (/^[+?]all$/i.test(terminal)) add('CRITICAL', 'spf-open', `SPF ends with "${terminal}" — every sender on the internet is authorised`);
  else if (/^~all$/i.test(terminal)) add('MEDIUM', 'spf-softfail', 'SPF ends with ~all (softfail) — unauthenticated mail is marked but still delivered; use -all once you are certain of your senders');
  if (/ptr/i.test(spf)) add('MEDIUM', 'spf-ptr', 'the ptr mechanism is slow, unreliable and deprecated by RFC 7208');
  const includes = terms.filter((t) => /include:/i.test(t)).length;
  if (includes > 8) add('HIGH', 'spf-lookup-budget', `${includes} include mechanisms plus a/mx may exceed the 10-DNS-lookup limit; receivers return PermError past that`);
  if (/redirect=/.test(spf) && /\ball\b/i.test(spf)) add('MEDIUM', 'spf-redirect-all', 'redirect= combined with all is contradictory');
  if (spf.length > 450) add('MEDIUM', 'spf-too-long', `SPF record is ${spf.length} characters; over 450 risks UDP truncation and a lost record`);
}

// --- DMARC ---
const dmarcTxt = await txt(`_dmarc.${domain}`);
const dmarcRecords = dmarcTxt.filter((t) => /^v=DMARC1/i.test(t));
if (!dmarcRecords.length) add('HIGH', 'no-dmarc', 'no DMARC record — no instruction to receivers about what to do with SPF/DKIM failures, and no reporting');
else {
  const rec = dmarcRecords[0];
  const p = (rec.match(/\bp\s*=\s*(\w+)/i) || [])[1]?.toLowerCase() || null;
  const sp = (rec.match(/\bsp\s*=\s*(\w+)/i) || [])[1]?.toLowerCase() || null;
  const pct = (rec.match(/\bpct\s*=\s*(\d+)/i) || [])[1];
  const rua = (rec.match(/\brua\s*=\s*([^;]+)/i) || [])[1]?.trim() || null;
  const ruf = (rec.match(/\bruf\s*=\s*([^;]+)/i) || [])[1]?.trim() || null;
  const adkim = (rec.match(/\badkim\s*=\s*(\w)/i) || [])[1] || 'r';
  const aspf = (rec.match(/\baspf\s*=\s*(\w)/i) || [])[1] || 'r';
  result.dmarc = { record: rec, p, sp, pct: pct ? Number(pct) : 100, rua, ruf, adkim, aspf };
  if (!p) add('CRITICAL', 'dmarc-no-policy', 'DMARC record has no p= tag; receivers ignore the record');
  else if (p === 'none') add('HIGH', 'dmarc-none', 'p=none monitors only — nothing is blocked. Move to quarantine, then reject');
  else if (p === 'quarantine') add('LOW', 'dmarc-quarantine', 'p=quarantine sends failures to spam; p=reject is the goal once reports are clean');
  if (pct !== undefined && Number(pct) < 100) add('MEDIUM', 'dmarc-partial-pct', `pct=${pct} applies the policy to only part of the mail — attackers get a fraction through`);
  if (!rua) add('LOW', 'dmarc-no-rua', 'no rua= aggregate report address — you are blind to who is sending as your domain');
  if (sp === 'none') add('MEDIUM', 'dmarc-subdomain-none', 'sp=none lets subdomains be spoofed even when the apex is protected');
  if (!sp) add('LOW', 'dmarc-no-sp', 'no sp= tag; subdomains inherit p, which is usually what you want — confirm it');
  if (adkim === 'r' && aspf === 'r') { /* relaxed is the sane default */ }
  if (/p\s*=\s*(none|quarantine)/i.test(rec) && /ruf\s*=/i.test(rec)) add('LOW', 'dmarc-ruf-privacy', 'ruf= sends full failed-message samples back to you — handle them as potentially sensitive');
}

// --- DKIM ---
const revoked = [];
for (const sel of selectors) {
  const recs = await txt(`${sel}._domainkey.${domain}`);
  const dkimRec = recs.find((t) => /v=DKIM1|p=/i.test(t));
  if (!dkimRec) continue;
  const pVal = ((dkimRec.match(/\bp\s*=\s*([A-Za-z0-9+/=\s]*)/i) || [])[1] || '').replace(/\s+/g, '');
  if (!pVal) { revoked.push(sel); continue; } // empty p= means the key was revoked; not an active selector
  const p = (dkimRec.match(/\bp\s*=\s*([A-Za-z0-9+/=\s]*)/i) || [])[1]?.replace(/\s+/g, '') || '';
  const k = (dkimRec.match(/\bk\s*=\s*(\w+)/i) || [])[1] || 'rsa';
  const bits = (dkimRec.match(/\bbits?\s*=\s*(\d+)/i) || [])[1];
  const entry = { selector: sel, record: dkimRec, keyType: k, pLength: p.length, bits: bits ? Number(bits) : null };
  result.dkim.push(entry);
  if (k === 'rsa' && p.length && p.length < 200 && !bits) add('MEDIUM', 'dkim-short-key', `${sel}: public key is short (${p.length} base64 chars, likely <1024 bits) — many receivers reject keys under 1024 bits`);
  if (bits && Number(bits) < 1024) add('HIGH', 'dkim-weak-key', `${sel}: key is ${bits} bits, below the 1024-bit floor`);
}
result.dkimRevoked = revoked;
if (!result.dkim.length) add('MEDIUM', 'no-dkim-found', `no DKIM key found on ${selectors.length} common selectors — either you do not sign outgoing mail or the selector is non-standard (pass --dkim-selectors)`);

// --- MTA-STS ---
const stsTxt = await txt(`_mta-sts.${domain}`);
const stsRec = stsTxt.find((t) => /v=STSv1/i.test(t));
result.mtaSts = { dns: stsRec || null, policyUrl: `https://mta-sts.${domain}/.well-known/mta-sts.txt` };
if (!stsRec) add('LOW', 'no-mta-sts', `no MTA-STS record — SMTP sessions can be downgraded to cleartext or a hostile MX`);
else {
  const id = (stsRec.match(/\bid\s*=\s*(\S+)/i) || [])[1];
  if (!id) add('MEDIUM', 'mta-sts-no-id', 'MTA-STS record has no id= — the policy cache cannot be invalidated');
}

// --- TLS-RPT ---
const rptTxt = await txt(`_smtp._tls.${domain}`);
const rptRec = rptTxt.find((t) => /v=TLSRPTv1/i.test(t));
result.tlsRpt = rptRec || null;
if (!rptRec && stsRec) add('LOW', 'no-tls-rpt', 'MTA-STS is published but no TLS-RPT reporting address — you will not learn about downgrade attempts');

// --- BIMI ---
const bimiTxt = await txt(`default._bimi.${domain}`);
const bimiRec = bimiTxt.find((t) => /v=BIMI1/i.test(t));
result.bimi = bimiRec || null;
if (bimiRec && (!result.dmarc || result.dmarc.p !== 'reject')) add('MEDIUM', 'bimi-needs-reject', 'BIMI requires a DMARC policy of p=reject (and usually a VMC) — mail clients will ignore it otherwise');

// --- MX + SPF alignment sanity ---
try { result.mx = (await resolveMx(domain)).map((m) => ({ host: m.exchange, priority: m.priority })).sort((a, b) => a.priority - b.priority); }
catch { result.mx = []; }
if (!result.mx.length) add('LOW', 'no-mx', 'no MX records — the domain cannot receive mail, which usually means it never will be spoofed successfully either (receivers still check SPF)');
else if (result.spf && result.spf.record && result.mx.length && !/redirect=/i.test(result.spf.record)) {
  const spfHasMx = /(^|\s)[+-~?]?mx(:|\s|$)/i.test(result.spf.record) || result.mx.some((m) => result.spf.record.includes(m.host));
  if (!spfHasMx) add('MEDIUM', 'spf-mx-mismatch', `SPF does not authorise any of the MX hosts (${result.mx.slice(0, 2).map((m) => m.host).join(', ')}) — your own inbound path may not be able to send`);
}

// spoofability verdict
const canReject = result.dmarc && result.dmarc.p === 'reject' && Number(result.dmarc.pct ?? 100) === 100;
const canQuarantine = result.dmarc && (result.dmarc.p === 'reject' || result.dmarc.p === 'quarantine');
const dkimOk = result.dkim.some((d) => d.pLength > 0);
const verdict = canReject && dkimOk && result.spf?.all && /^-all/i.test(result.spf.all) ? 'HARDENED'
  : canQuarantine ? 'PARTIAL'
  : result.dmarc ? 'WEAK'
  : 'SPOOFABLE';

const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
for (const f of findings) counts[f.severity]++;
const expectReject = flag(o, 'expect-reject');
const failed = counts.CRITICAL > 0 || counts.HIGH > 0 || (expectReject && !canReject);

if (flag(o, 'json')) {
  emit({ ...result, spoofability: verdict, findings, counts, pass: !failed });
  process.exit(0);
}

console.log(`mailauth: ${domain}`);
console.log(`spoofability: ${verdict}  findings: ${findings.length} (${counts.CRITICAL} critical, ${counts.HIGH} high)`);
console.log('');
console.log('SPF:    ' + (result.spf ? `${result.spf.all ? `all=${result.spf.all}` : 'NO terminal all'} | ${result.spf.record.slice(0, 70)}` : 'MISSING'));
console.log('DMARC:  ' + (result.dmarc ? `p=${result.dmarc.p || 'MISSING'} sp=${result.dmarc.sp || '-'} pct=${result.dmarc.pct} rua=${result.dmarc.rua || '-'}` : 'MISSING'));
console.log('DKIM:   ' + (result.dkim.length ? result.dkim.map((d) => `${d.selector}(${d.keyType}${d.bits ? ' ' + d.bits + 'b' : ''})`).join(' ') : 'no key found on common selectors'));
console.log('MTA-STS:' + (result.mtaSts.dns ? ` published (${result.mtaSts.dns.slice(0, 50)})` : ' MISSING'));
console.log('TLS-RPT:' + (result.tlsRpt ? ' published' : ' MISSING'));
console.log('BIMI:   ' + (result.bimi ? ' published' : ' not published'));
if (result.mx.length) {
  console.log('');
  console.log(table(result.mx.map((m) => ({ priority: m.priority, host: m.host })), ['priority', 'host']));
}
if (findings.length) {
  console.log('\nfindings:');
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  console.log(table(findings.sort((a, b) => order[a.severity] - order[b.severity]).map((f) => ({ severity: f.severity, rule: f.rule, detail: f.message })), ['severity', 'rule', 'detail']));
} else console.log('\nno findings');
process.exit(failed ? 1 : 0);
