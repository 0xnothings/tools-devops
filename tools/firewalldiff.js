#!/usr/bin/env node
// firewalldiff.js — firewall rule review and drift detection.
// Copyright (c) 2026 0xnothings
// @tool firewalldiff
// @desc Dump iptables/nftables/ufw rules, flag dangerous accepts, and diff against a saved baseline
// @usage node tools/firewalldiff.js --save baseline.json  |  node tools/firewalldiff.js --diff baseline.json
// @tags devops,firewall,hardening
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { args, get, flag, die, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`firewalldiff — firewall rule audit + drift detection

  node tools/firewalldiff.js [options]

  --save <file>    write the current rule set as a baseline
  --diff <file>    compare current rules against a baseline
  --tool <name>    iptables | nft | ufw (default: auto-detect)
  --json           machine-readable output
  -h, --help       this text

  Flags risky rules: any-any accepts, public DB/admin ports,
  missing default DROP, unprotected SSH.`);
  process.exit(0);
}

const sh = (cmd, a) => { try { return execFileSync(cmd, a, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }); } catch { return null; } };

function detect() {
  if (o.f.tool) return String(get(o, 'tool'));
  if (sh('ufw', ['status']) !== null) return 'ufw';
  if (sh('nft', ['list', 'ruleset']) !== null) return 'nft';
  if (sh('iptables', ['-S']) !== null) return 'iptables';
  return null;
}

const tool = detect() || die('no firewall tool detected (iptables / nft / ufw)');
let raw = '';
if (tool === 'ufw') raw = sh('ufw', ['status', 'verbose']) || '';
else if (tool === 'nft') raw = sh('nft', ['list', 'ruleset']) || '';
else raw = sh('iptables', ['-S']) || '';

// iptables -S output is one rule per line; ufw/nft are multi-line — normalise to rule strings
const rules = raw.split('\n').map((l) => l.trim()).filter((l) => l && !/^#/.test(l));

const RISKY = [
  [/^-A\s+INPUT\s+-j\s+ACCEPT$/i, 'CRITICAL', 'unconditional ACCEPT on INPUT — the firewall accepts everything'],
  [/(?:0\.0\.0\.0\/0|any|Anywhere).*(?:dpt:|port)\s*(?:3306|5432|27017|6379|9200|11211|1433|1521|4444|5601)/i, 'CRITICAL', 'database/cache port open to the world'],
  [/(?:dpt:|port)\s*22.*(?:0\.0\.0\.0\/0|Anywhere)/i, 'MEDIUM', 'SSH open to the world — restrict to known IPs or use a bastion'],
  [/(?:dpt:|port)\s*(?:21|23|111|135|139|445|3389).*(?:\/0|Anywhere)/i, 'HIGH', 'legacy insecure service exposed'],
  [/(?:dpt:|port)\s*(?:8888|8080|8000|3000|5000).*(?:\/0|Anywhere)/i, 'HIGH', 'development/app server exposed publicly'],
  [/DROP|REJECT/i, 'INFO', ''],
];
const findings = [];
for (const r of rules) for (const [re, sev, why] of RISKY) if (why && re.test(r)) { findings.push({ severity: sev, rule: r.slice(0, 100), issue: why }); break; }

const hasDefaultDrop = rules.some((r) => /(?:policy DROP|:-INPUT DROP|default deny|Default: deny)/i.test(r)) || /INPUT DROP/i.test(raw);
if (!hasDefaultDrop && tool === 'iptables') findings.unshift({ severity: 'CRITICAL', rule: '(policy)', issue: 'no default DROP policy on INPUT — every unmatched packet is accepted' });
if (tool === 'ufw' && /Status: inactive/i.test(raw)) findings.unshift({ severity: 'CRITICAL', rule: '(status)', issue: 'ufw is inactive' });

const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
findings.forEach((f) => bySeverity[f.severity]++);

let drift = null;
if (o.f.diff) {
  const baseFile = String(get(o, 'diff'));
  if (!existsSync(baseFile)) die(`${baseFile} not found`);
  const base = JSON.parse(readFileSync(baseFile, 'utf8'));
  const oldSet = new Set(base.rules), newSet = new Set(rules);
  drift = {
    baseline: baseFile, taken_at: base.taken_at,
    added: rules.filter((r) => !oldSet.has(r)), removed: base.rules.filter((r) => !newSet.has(r)),
    unchanged: rules.filter((r) => oldSet.has(r)).length,
  };
}

if (o.f.save) {
  writeFileSync(String(get(o, 'save')), JSON.stringify({ tool, taken_at: new Date().toISOString(), host: process.env.HOSTNAME || 'unknown', rules }, null, 2), 'utf8');
  console.log(`baseline written: ${get(o, 'save')} (${rules.length} rules, tool=${tool})`);
  if (!flag(o, 'json')) process.exit(0);
}

if (flag(o, 'json')) { console.log(JSON.stringify({ tool, rule_count: rules.length, default_drop: hasDefaultDrop, by_severity: bySeverity, findings, drift }, null, 2)); process.exit(findings.some((f) => f.severity === 'CRITICAL') ? 1 : 0); }

console.log(`${tool}: ${rules.length} rule(s), default-drop ${hasDefaultDrop ? 'yes' : 'NO'}`);
if (drift) {
  console.log(`\n-- drift vs ${drift.baseline} (${drift.taken_at}) --`);
  console.log(`  ${drift.added.length} added, ${drift.removed.length} removed, ${drift.unchanged} unchanged`);
  drift.added.slice(0, 20).forEach((r) => console.log('  + ' + r.slice(0, 100)));
  drift.removed.slice(0, 20).forEach((r) => console.log('  - ' + r.slice(0, 100)));
}
if (findings.length) { console.log('\n-- findings --'); console.log(table(findings.map((f) => ({ severity: f.severity, issue: f.issue, rule: f.rule.slice(0, 56) })))); }
console.log(`\ncritical ${bySeverity.CRITICAL}, high ${bySeverity.HIGH}, medium ${bySeverity.MEDIUM}`);
process.exit(findings.some((f) => f.severity === 'CRITICAL') ? 1 : 0);
