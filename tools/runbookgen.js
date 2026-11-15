#!/usr/bin/env node
// runbookgen.js — generate an operational runbook from a service manifest.
// Copyright (c) 2026 0xnothings
// @tool runbookgen
// @desc Turn a service manifest (deps, healthcheck, contacts, escalation) into a markdown runbook with diagnosis, rollback and escalation steps
// @usage node tools/runbookgen.js service.json --out RUNBOOK.md --json
// @tags devops,runbook,oncall,docs
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { args, flag, die, emit } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`runbookgen — runbook generator

  node tools/runbookgen.js <service.json> [options]

  manifest:
  {
    "name": "billing-api",
    "owner": "payments-team",
    "tier": 1,
    "repos": ["github.com/acme/billing-api"],
    "deps": ["postgres-primary", "redis-sessions", "stripe-api"],
    "healthcheck": "https://billing.internal/healthz",
    "metrics": "https://grafana.internal/d/billing",
    "logs": "https://kibana.internal/app/logs?service=billing-api",
    "slo": "99.95% availability, p95 < 300ms",
    "contacts": [{"role":"primary","name":"Alice","slack":"@alice","phone":"+65..."}],
    "escalation": ["on-call engineer", "team lead", "eng manager after 30m"],
    "deploy": "Argo CD auto-sync from main",
    "rollback": "argocd app rollback billing-api",
    "common_issues": [{"symptom":"5xx spike","cause":"bad deploy","fix":"rollback"}]
  }

  --out <file>   write markdown to a file (default stdout)
  --json         emit the manifest analysis + the markdown as a JSON field
  -h, --help     this text`);
  process.exit(0);
}

const file = o._[0];
if (!file) die('usage: node tools/runbookgen.js <service.json> [--out RUNBOOK.md]');
if (!existsSync(file)) die(`no such file: ${file}`);
let m;
try { m = JSON.parse(readFileSync(file, 'utf8')); } catch (e) { die(`invalid JSON: ${e.message}`); }

const missing = [];
const need = ['name', 'owner', 'tier', 'healthcheck', 'contacts', 'escalation', 'rollback'];
for (const k of need) if (!m[k]) missing.push(k);
const deps = Array.isArray(m.deps) ? m.deps : [];
const contacts = Array.isArray(m.contacts) ? m.contacts : [];
const issues = Array.isArray(m.common_issues) ? m.common_issues : [];

const L = [];
L.push(`# Runbook — ${m.name || '(unnamed service)'}`);
L.push('');
L.push(`| | |`);
L.push(`|---|---|`);
L.push(`| Owner | ${m.owner || '**UNASSIGNED**'} |`);
L.push(`| Tier | ${m.tier ? `T${m.tier}` : '**unset**'} |`);
L.push(`| SLO | ${m.slo || 'not declared'} |`);
L.push(`| Deploy | ${m.deploy || 'not documented'} |`);
L.push(`| Rollback | ${m.rollback ? `\`${m.rollback}\`` : '**NOT DOCUMENTED**'} |`);
L.push(`| Generated | ${new Date().toISOString().slice(0, 16)}Z |`);
L.push('');

L.push('## 1. What this service is');
L.push('');
L.push(`${m.name || 'The service'}${m.description ? ` — ${m.description}` : ''}.`);
if (m.repos?.length) L.push(`\nRepositories: ${m.repos.map((r) => `\`${r}\``).join(', ')}`);
L.push('');

L.push('## 2. Dependencies');
L.push('');
if (deps.length) {
  L.push('If a dependency is degraded, the symptom appears here first:');
  L.push('');
  for (const d of deps) L.push(`- \`${d}\` — check its status page / health endpoint before investigating this service`);
} else L.push('_No dependencies declared. Add them to the manifest — most incidents start elsewhere._');
L.push('');

L.push('## 3. First five minutes');
L.push('');
L.push(`1. **Confirm the symptom** — is it one user, one region, or everyone? Check ${m.metrics || 'the dashboard'} and ${m.logs || 'the logs'}.`);
L.push(`2. **Check the last change** — \`${m.deploy || 'deploy pipeline'}\`. Anything shipped in the last hour is suspect.`);
L.push(`3. **Hit the health endpoint** — \`curl -sS ${m.healthcheck || '<healthcheck>'}\`. A 200 with a stale body is not healthy; read the body.`);
L.push(`4. **Check dependencies** — ${deps.length ? deps.map((d) => `\`${d}\``).join(', ') : 'none declared'}.`);
L.push(`5. **Decide: mitigate or investigate.** Tier ${m.tier || '?'} services mitigate first and ask questions after.`);
L.push('');

L.push('## 4. Diagnose');
L.push('');
L.push('```bash');
L.push(`# health and readiness`);
L.push(`curl -sS -o /dev/null -w '%{http_code} %{time_total}s\\n' ${m.healthcheck || 'https://<service>/healthz'}`);
L.push(`# recent errors`);
L.push(`journalctl -u ${m.name || '<service>'} --since '30 min ago' -p err --no-pager | tail -50`);
L.push(`# resource pressure`);
L.push(`ps -o pid,pcpu,pmem,rss,etime,cmd -C ${m.name || '<service>'} | head`);
L.push('```');
L.push('');
if (issues.length) {
  L.push('### Known failure modes');
  L.push('');
  L.push('| Symptom | Likely cause | First action |');
  L.push('|---|---|---|');
  for (const i of issues) L.push(`| ${i.symptom || '-'} | ${i.cause || '-'} | ${i.fix || '-'} |`);
  L.push('');
}

L.push('## 5. Mitigate');
L.push('');
L.push('Choose the smallest reversible action that restores service:');
L.push('');
L.push(`- **Roll back the deploy** — \`${m.rollback || '<rollback command NOT DOCUMENTED — fix this>'};\``);
L.push('- **Fail over** — shift traffic to the standby region via the load balancer; verify with the health endpoint before removing the old pool.');
L.push('- **Scale out** — if CPU/memory bound, add replicas; do not scale into a saturation-induced crash loop.');
L.push('- **Shed load** — enable rate limiting or disable the expensive non-critical endpoint before the whole service falls over.');
L.push('');
L.push('Record the timestamp of every action — the postmortem timeline is built from them.');
L.push('');

L.push('## 6. Escalate');
L.push('');
if (contacts.length) {
  L.push('| Role | Who | Slack | Phone |');
  L.push('|---|---|---|---|');
  for (const c of contacts) L.push(`| ${c.role || '-'} | ${c.name || '-'} | ${c.slack || '-'} | ${c.phone || '-'} |`);
} else L.push('_No contacts in the manifest — fill in `contacts` before this runbook is usable._');
L.push('');
if (m.escalation?.length) {
  L.push('Escalation path:');
  L.push('');
  m.escalation.forEach((e, i) => L.push(`${i + 1}. ${e}`));
} else L.push('Escalation path not declared.');
L.push('');

L.push('## 7. Verify recovery');
L.push('');
L.push(`- [ ] Health endpoint returns 200 with a fresh timestamp: \`${m.healthcheck || '<healthcheck>'}\``);
L.push('- [ ] Error rate back to the pre-incident baseline for 15 minutes (not just one scrape).');
L.push('- [ ] Latency p95 within SLO.');
L.push('- [ ] No new errors in the log stream for 10 minutes.');
L.push('- [ ] Synthetic check / user-facing smoke test passing.');
L.push('');

L.push('## 8. After the incident');
L.push('');
L.push('- Write the timeline from your action timestamps (detected → acked → mitigated → resolved).');
L.push('- Identify the contributing cause, not the blamed person.');
L.push('- File follow-up tickets with owners and dates; a runbook that never changes is a runbook nobody reads.');
L.push('- If a step above was wrong or missing, fix the manifest and regenerate.');
L.push('');

const md = L.join('\n');
const out = o.f.out && o.f.out !== true ? String(o.f.out) : null;
if (out) writeFileSync(out, md);

if (flag(o, 'json')) { emit({ manifest: file, name: m.name || null, missingFields: missing, dependencies: deps.length, contacts: contacts.length, knownIssues: issues.length, out: out || '(stdout)', markdown: out ? undefined : md, complete: missing.length === 0 }); process.exit(0); }
if (!out) process.stdout.write(md);
else console.log(`runbookgen: wrote ${out} (${md.split('\n').length} lines)${missing.length ? ` — manifest missing: ${missing.join(', ')}` : ''}`);
process.exit(0);
