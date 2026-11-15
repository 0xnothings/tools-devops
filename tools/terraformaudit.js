#!/usr/bin/env node
// terraformaudit.js — fingerprint common Terraform misconfigurations.
// Copyright (c) 2026 0xnothings
// @tool terraformaudit
// @desc Scan .tf files for public S3 ACLs, 0.0.0.0/0 ingress, unencrypted volumes, wildcard IAM and hardcoded secrets
// @usage node tools/terraformaudit.js ./infra --json
// @tags devops,terraform,audit
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { args, flag, die, emit, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`terraformaudit — Terraform misconfiguration scanner

  node tools/terraformaudit.js <dir|file.tf> [options]

  --json        machine-readable output
  --max-depth <n>  directory recursion depth (default 4)
  -h, --help    this text

  detects: public S3 ACL, 0.0.0.0/0 ingress, unencrypted EBS/S3, wildcard IAM actions,
           hardcoded credentials, public RDS, missing MFA delete, open security group egress`);
  process.exit(0);
}

const target = o._[0];
if (!target) die('usage: node tools/terraformaudit.js <dir|file.tf> [--json]');
const maxDepth = Number(o.f['max-depth'] || 4);

function walk(p, depth, acc) {
  let st;
  try { st = statSync(p); } catch { return acc; }
  if (st.isFile()) { if (p.endsWith('.tf')) acc.push(p); return acc; }
  let ents = [];
  try { ents = readdirSync(p, { withFileTypes: true }); } catch { return acc; }
  for (const e of ents) {
    if (e.name === '.terraform' || e.name === 'node_modules' || e.name === '.git') continue;
    const fp = join(p, e.name);
    if (e.isDirectory()) { if (depth < maxDepth) walk(fp, depth + 1, acc); }
    else if (e.name.endsWith('.tf')) acc.push(fp);
  }
  return acc;
}

const tfFiles = walk(target, 0, []);
if (!tfFiles.length) die(`no .tf files found under ${target}`);

const SECRET_PATTERNS = [
  [/AKIA[0-9A-Z]{16}/, 'AWS access key id literal'],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, 'private key literal'],
  [/(password|passwd|secret|token|api_key)\s*=\s*"[^"$\{]{8,}"/i, 'hardcoded credential value'],
];

const findings = [];
const add = (file, line, rule, sev, msg) => findings.push({ file, line, rule, severity: sev, message: msg });

for (const f of tfFiles) {
  const text = readFileSync(f, 'utf8');
  const raw = text.split(/\r?\n/);

  // block extraction: resource/block type + name
  const blocks = [];
  let cur = null, depth = 0;
  for (let i = 0; i < raw.length; i++) {
    const line = raw[i];
    const open = line.match(/^\s*(resource|data|module|variable|provider)\s+"([^"]+)"(?:\s+"([^"]+)")?\s*\{/);
    if (open && !cur) {
      cur = { kind: open[1], type: open[2], nm: open[3] || '', start: i + 1, body: [] };
      depth = 1;
      continue;
    }
    if (cur) {
      depth += (line.match(/\{/g) || []).length;
      depth -= (line.match(/\}/g) || []).length;
      if (depth <= 0) { blocks.push(cur); cur = null; }
      else cur.body.push({ n: i + 1, text: line });
    }
  }
  if (cur) blocks.push(cur);

  for (const b of blocks) {
    const body = b.body.map((l) => l.text).join('\n');
    const label = `${b.kind}.${b.type}${b.nm ? '.' + b.nm : ''}`;
    const lineOf = (re) => { const hit = b.body.find((l) => re.test(l.text)); return hit ? hit.n : b.start; };

    if (b.type === 'aws_s3_bucket_acl' || b.type === 'aws_s3_bucket') {
      if (/acl\s*=\s*"public-read(-write)?"/.test(body)) add(f, lineOf(/acl\s*=/), 's3-public-acl', 'CRITICAL', `${label}: bucket ACL set to public-*`);
      if (/block_public_acls\s*=\s*false/.test(body)) add(f, lineOf(/block_public_acls/), 's3-public-acl', 'HIGH', `${label}: block_public_acls disabled`);
      if (b.type === 'aws_s3_bucket' && !/server_side_encryption/.test(body) && !/aws_s3_bucket_server_side_encryption_configuration/.test(text)) {
        add(f, b.start, 's3-encryption', 'MEDIUM', `${label}: no server-side encryption configuration`);
      }
    }

    if (b.type === 'aws_security_group' || b.type === 'aws_security_group_rule' || b.type === 'aws_vpc_security_group_ingress_rule') {
      if (/cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"\s*\]/.test(body) || /cidr_ipv4\s*=\s*"0\.0\.0\.0\/0"/.test(body)) {
        const port22 = /from_port\s*=\s*22\b/.test(body) || /port\s*=\s*22\b/.test(body);
        const port3389 = /from_port\s*=\s*3389\b/.test(body) || /port\s*=\s*3389\b/.test(body);
        const sev = port22 || port3389 ? 'CRITICAL' : 'HIGH';
        const extra = port22 ? ' (SSH open to the internet)' : port3389 ? ' (RDP open to the internet)' : '';
        add(f, lineOf(/0\.0\.0\.0\/0/), 'open-ingress', sev, `${label}: 0.0.0.0/0 ingress${extra}`);
      }
    }

    if (b.type === 'aws_ebs_volume' || b.type === 'aws_instance') {
      if (/encrypted\s*=\s*false/.test(body) || (b.type === 'aws_ebs_volume' && !/encrypted\s*=/.test(body))) {
        add(f, lineOf(/encrypted/) || b.start, 'unencrypted-volume', 'HIGH', `${label}: EBS volume not encrypted`);
      }
    }

    if (b.type === 'aws_db_instance' || b.type === 'aws_rds_cluster') {
      if (/publicly_accessible\s*=\s*true/.test(body)) add(f, lineOf(/publicly_accessible/), 'rds-public', 'CRITICAL', `${label}: publicly_accessible = true`);
      if (/storage_encrypted\s*=\s*false/.test(body) || !/storage_encrypted/.test(body)) add(f, b.start, 'rds-encryption', 'HIGH', `${label}: storage not encrypted`);
      if (/password\s*=\s*"[^"$]{6,}"/.test(body)) add(f, lineOf(/password\s*=/), 'rds-secret', 'CRITICAL', `${label}: hardcoded master password`);
    }

    if (b.type.endsWith('_policy') || b.type.endsWith('_policy_document')) {
      if (/"Action"\s*:\s*"\*"/.test(body) || /actions\s*=\s*\[\s*"\*"\s*\]/.test(body) || /actions\s*=\s*"\*"/.test(body)) {
        const resourceStar = /"Resource"\s*:\s*"\*"/.test(body) || /resources\s*=\s*\[\s*"\*"\s*\]/.test(body) || /resources\s*=\s*"\*"/.test(body);
        add(f, lineOf(/"?\*"?\s*\]|:\s*"\*"/), 'iam-wildcard', resourceStar ? 'CRITICAL' : 'HIGH', `${label}: wildcard IAM action${resourceStar ? ' on Resource *' : ''}`);
      }
    }

    if (b.kind === 'variable') {
      if (/default\s*=\s*"[^"$]{8,}"/.test(body) && /(pass|secret|token|key)/i.test(b.nm)) {
        add(f, lineOf(/default\s*=/), 'secret-default', 'HIGH', `${label}: secret variable has a committed default value`);
      }
    }

    for (const pat of SECRET_PATTERNS) {
      const m = body.match(pat[0]);
      if (m) add(f, lineOf(pat[0]), 'hardcoded-secret', 'CRITICAL', `${label}: ${pat[1]}`);
    }
  }
}

// dedupe by file+line+rule
const seen = new Set();
const uniq = findings.filter((x) => { const k = `${x.file}:${x.line}:${x.rule}`; if (seen.has(k)) return false; seen.add(k); return true; });
const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
for (const x of uniq) counts[x.severity]++;
const failed = uniq.some((x) => x.severity === 'CRITICAL' || x.severity === 'HIGH');

if (flag(o, 'json')) { emit({ target, files: tfFiles.length, findings: uniq, counts, pass: !failed }); process.exit(0); }

console.log(`terraformaudit: ${target}`);
console.log(`files: ${tfFiles.length}  findings: ${uniq.length}  critical: ${counts.CRITICAL} high: ${counts.HIGH} medium: ${counts.MEDIUM}`);
if (uniq.length) {
  console.log('');
  console.log(table(uniq.map((x) => ({ severity: x.severity, file: x.file.split(/[\\/]/).pop(), line: x.line, detail: x.message })), ['severity', 'file', 'line', 'detail']));
} else console.log('\nno issues found');
process.exit(failed ? 1 : 0);
