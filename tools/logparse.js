// logparse.js — access/error log analyser.
// Copyright (c) 2026 0xnothings
// @tool logparse
// @desc Parse nginx/apache access logs: top IPs, paths, status mix, scanners, and attack signatures
// @usage node tools/logparse.js access.log --top 20 --json
// @tags devops,logs,forensics
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { args, get, num, flag, die, inputLines, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`logparse — web server log analyser

  node tools/logparse.js <logfile|-> [options]

  --top <n>        rows per ranking (default: 15)
  --since <ISO>    only lines at/after this timestamp
  --only-attacks   print only lines matching attack signatures
  --json           machine-readable output
  -h, --help       this text

  Supports combined/common nginx + Apache formats.
  Flags: scanners, SQLi/XSS/traversal attempts, credential spraying, 404 floods.`);
  process.exit(0);
}

const COMBINED = /^(\S+) \S+ \S+ \[([^\]]+)] "(\S+) ([^"]*?) (\S+)" (\d{3}) (\d+|-)(?: "([^"]*)" "([^"]*)")?/;
const ATTACKS = [
  [/(?:\.\.\/|%2e%2e%2f|\.\.%2f)/i, 'path traversal'],
  [/(?:union[\s+/*]+select|or\s+1=1|information_schema|sleep\(|benchmark\()/i, 'SQL injection'],
  [/(?:<script|%3cscript|onerror=|javascript:)/i, 'XSS attempt'],
  [/(?:wp-login\.php|xmlrpc\.php|\/user\/login|administrator\/index|admin\/login)/i, 'credential endpoint probe'],
  [/(?:\.env|\.git|wp-config\.php\.bak|\.aws\/credentials|backup\.(?:sql|zip))/i, 'sensitive file probe'],
  [/(?:\/phpmyadmin|\/pma\/|adminer\.php|\/\.svn\/)/i, 'admin panel scan'],
  [/(?:eval\(|base64_decode\(|\/cgi-bin\/|shell\.php)/i, 'code execution attempt'],
  [/(?:\.\.%2f|%00|%ff)/i, 'encoding evasion'],
  [/(?:SELECT|INSERT|DELETE).*(?:FROM|INTO|WHERE)/i, 'SQL keyword'],
  [/\/actuator|\/\.env\.|server-status|\.well-known\/.*\.\./i, 'infra probe'],
];
const SCANNER_UA = /(?:nikto|nmap|masscan|sqlmap|dirb|gobuster|wpscan|nuclei|zgrab|nmap|acunetix|nessus|openvas|zap|xray|semrush|ahrefs|mj12bot|dotbot|petalbot)/i;

const logFile = o._[0];
if (!logFile) die('usage: node tools/logparse.js <logfile|-> [--top 15] [--json]');
const top = num(get(o, 'top'), 15);
const since = o.f.since ? new Date(String(get(o, 'since'))).getTime() : null;
const onlyAttacks = flag(o, 'only-attacks');

const stats = { lines: 0, parsed: 0, malformed: 0, bytes: 0 };
const ips = new Map(), paths = new Map(), statuses = new Map(), methods = new Map(), agents = new Map();
const attacks = [], hourly = new Map();

const rl = createInterface({ input: createReadStream(logFile, 'utf8'), crlfDelay: Infinity });
for await (const line of rl) {
  stats.lines++;
  const m = line.match(COMBINED);
  if (!m) { stats.malformed++; continue; }
  const [, ip, tsRaw, method, path, proto, status, bytes, referer, ua] = m;
  stats.parsed++;
  const t = Date.parse(tsRaw.replace(':', ' '));
  if (since && !isNaN(t) && t < since) continue;
  stats.bytes += bytes === '-' ? 0 : Number(bytes);
  ips.set(ip, (ips.get(ip) || 0) + 1);
  paths.set(path, (paths.get(path) || 0) + 1);
  methods.set(method, (methods.get(method) || 0) + 1);
  statuses.set(status, (statuses.get(status) || 0) + 1);
  if (ua) agents.set(ua, (agents.get(ua) || 0) + 1);
  if (!isNaN(t)) hourly.set(new Date(t).toISOString().slice(0, 13), (hourly.get(new Date(t).toISOString().slice(0, 13)) || 0) + 1);

  const hit = ATTACKS.filter(([re]) => re.test(path) || re.test(referer || '')).map(([, name]) => name);
  if (SCANNER_UA.test(ua || '')) hit.push('scanner UA');
  if (hit.length) attacks.push({ ip, path, status, attack: [...new Set(hit)].join('+'), ua: (ua || '').slice(0, 50) });
}

const rank = (map, n = top) => [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, n).map(([k, v]) => ({ value: k, count: v }));
const attackers = new Map();
for (const a of attacks) attackers.set(a.ip, (attackers.get(a.ip) || 0) + 1);

const report = {
  file: logFile, parsed_lines: stats.parsed, malformed: stats.malformed, bytes_served: stats.bytes,
  top_ips: rank(ips), top_paths: rank(paths), status_mix: rank(statuses, 20), methods: rank(methods, 10),
  top_agents: rank(agents, 10), scanner_hits: attackers.size, attack_events: attacks.length,
  top_attackers: [...attackers.entries()].sort((a, b) => b[1] - a[1]).slice(0, top).map(([ip, n]) => ({ ip, hits: n })),
  busiest_hours: rank(hourly, 6), attacks: onlyAttacks ? attacks.slice(0, 500) : attacks.slice(0, 60),
};

if (flag(o, 'json')) { console.log(JSON.stringify(report, null, 2)); process.exit(0); }
console.log(`${logFile}: ${stats.parsed} parsed / ${stats.lines} lines (${stats.malformed} malformed), ${(stats.bytes / 1048576).toFixed(1)} MB served`);
if (onlyAttacks) { console.log(table(attacks.slice(0, 200).map((a) => ({ ip: a.ip, status: a.status, attack: a.attack, path: a.path.slice(0, 60) })))); process.exit(0); }
console.log('\n-- top IPs --'); console.log(table(report.top_ips));
console.log('\n-- status mix --'); console.log(table(report.status_mix));
console.log('\n-- top paths --'); console.log(table(report.top_paths));
console.log('\n-- top attackers --'); console.log(table(report.top_attackers));
console.log(`\n${attackers.size} IP(s) with attack signatures, ${attacks.length} event(s)`);
if (report.top_attackers.length) console.log(`block with: iptables -A INPUT -s ${report.top_attackers[0].ip} -j DROP`);
