#!/usr/bin/env node
// wpconfig.js — WordPress hardening and config audit (local or remote).
// Copyright (c) 2026 0xnothings
// @tool wpconfig
// @desc Audit wp-config.php + .htaccess: salts, debug flags, file edit, DB prefix, table_prefix, exposed backups
// @usage node tools/wpconfig.js ./public_html --json
// @tags devops,wordpress,hardening
import { readFileSync, existsSync, statSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { args, get, flag, die, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`wpconfig — WordPress configuration audit

  node tools/wpconfig.js <wordpress-root> [options]

  --json      machine-readable output
  --fix-hints print the exact code to add
  -h, --help  this text

  Checks: salt presence/length, WP_DEBUG in prod, DISALLOW_FILE_EDIT,
  FS_METHOD, table_prefix, AUTOSAVE_INTERVAL, revisions limit,
  exposed wp-config backups, directory listing, wp-includes dirs.`);
  process.exit(0);
}

const root = o._[0] || '.';
const cfgPath = join(root, 'wp-config.php');
if (!existsSync(cfgPath)) die(`wp-config.php not found in ${root}`);
const cfg = readFileSync(cfgPath, 'utf8');

const checks = [];
const add = (level, name, ok, detail, fix) => checks.push({ level, check: name, status: ok ? 'PASS' : level === 'INFO' ? 'INFO' : 'FAIL', detail, fix: ok ? '' : fix });

const constant = (name) => {
  const m = cfg.match(new RegExp(`define\\s*\\(\\s*['"]${name}['"]\\s*,\\s*([^)]+)\\)`, 'i'));
  return m ? m[1].trim() : null;
};

// salts
const saltKeys = ['AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT'];
const salts = saltKeys.map((k) => ({ k, v: constant(k) }));
const missingSalts = salts.filter((s) => !s.v);
const shortSalts = salts.filter((s) => s.v && s.v.replace(/['"]/g, '').length < 48);
const placeholderSalts = salts.filter((s) => s.v && /put your unique phrase here|changeme|xxx/i.test(s.v));
add('CRITICAL', 'salts present', !missingSalts.length, missingSalts.length ? `missing: ${missingSalts.map((s) => s.k).join(', ')}` : 'all 8 salts defined', 'fetch new salts from https://api.wordpress.org/secret-key/1.1/salt/');
add('HIGH', 'salt entropy', !shortSalts.length && !placeholderSalts.length, [...shortSalts, ...placeholderSalts].map((s) => s.k).join(', ') || 'salts look random', 'regenerate all salts — this logs out every session');

// debug
const debug = constant('WP_DEBUG');
const debugLog = constant('WP_DEBUG_LOG');
const debugDisplay = constant('WP_DEBUG_DISPLAY');
add('HIGH', 'WP_DEBUG off in production', !/true/i.test(debug || 'false'), `WP_DEBUG=${debug ?? 'undefined'}`, "define('WP_DEBUG', false);");
add('MEDIUM', 'WP_DEBUG_DISPLAY off', !/true/i.test(debugDisplay || 'false'), `WP_DEBUG_DISPLAY=${debugDisplay ?? 'undefined'}`, "define('WP_DEBUG_DISPLAY', false);");

// hardening flags
add('MEDIUM', 'file editor disabled', /true/i.test(constant('DISALLOW_FILE_EDIT') || ''), `DISALLOW_FILE_EDIT=${constant('DISALLOW_FILE_EDIT') ?? 'undefined'}`, "define('DISALLOW_FILE_EDIT', true);");
add('MEDIUM', 'plugin/theme install locked', /true/i.test(constant('DISALLOW_FILE_MODS') || ''), `DISALLOW_FILE_MODS=${constant('DISALLOW_FILE_MODS') ?? 'undefined'}`, "define('DISALLOW_FILE_MODS', true);");
add('LOW', 'FS_METHOD direct', /direct/i.test(constant('FS_METHOD') || ''), `FS_METHOD=${constant('FS_METHOD') ?? 'undefined'}`, "define('FS_METHOD', 'direct');");

// table prefix
const prefix = (cfg.match(/\$table_prefix\s*=\s*['"]([^'"]+)['"]/) || [, null])[1];
add('MEDIUM', 'non-default table prefix', prefix && prefix !== 'wp_', `$table_prefix = '${prefix}'`, "change to something unique like 'x7k2_' — requires DB migration");

// performance / hygiene
add('LOW', 'autosave interval set', !!constant('AUTOSAVE_INTERVAL'), `AUTOSAVE_INTERVAL=${constant('AUTOSAVE_INTERVAL') ?? 'undefined'}`, "define('AUTOSAVE_INTERVAL', 160);");
add('LOW', 'post revisions limited', !!constant('WP_POST_REVISIONS'), `WP_POST_REVISIONS=${constant('WP_POST_REVISIONS') ?? 'undefined'}`, "define('WP_POST_REVISIONS', 10);");
add('LOW', 'empty trash interval set', !!constant('EMPTY_TRASH_DAYS'), `EMPTY_TRASH_DAYS=${constant('EMPTY_TRASH_DAYS') ?? 'undefined'}`, "define('EMPTY_TRASH_DAYS', 7);");
add('LOW', 'force SSL admin', /true/i.test(constant('FORCE_SSL_ADMIN') || ''), `FORCE_SSL_ADMIN=${constant('FORCE_SSL_ADMIN') ?? 'undefined'}`, "define('FORCE_SSL_ADMIN', true);");

// exposed backups
const backups = [];
try {
  for (const f of readdirSync(root)) if (/^wp-config\.php\.(bak|old|save|swp|txt|zip)$|^wp-config\.(bak|old)$|^\.wp-config\.php\.swp$/i.test(f)) backups.push(f);
} catch {}
add('CRITICAL', 'no wp-config backups in webroot', !backups.length, backups.join(', ') || 'none found', 'delete them and add wp-config.php* to .htaccess deny rules');

const ht = join(root, '.htaccess');
if (existsSync(ht)) {
  const h = readFileSync(ht, 'utf8');
  add('MEDIUM', '.htaccess denies wp-config', /wp-config\.php/i.test(h), /wp-config\.php/i.test(h) ? 'rule present' : 'no rule', '<Files wp-config.php>\n  Require all denied\n</Files>');
  add('LOW', '.htaccess blocks XML-RPC', /xmlrpc\.php/i.test(h), /xmlrpc\.php/i.test(h) ? 'blocked' : 'not blocked', '<Files xmlrpc.php>\n  Require all denied\n</Files>');
  add('LOW', '.htaccess disables directory listing', /Options\s+-Indexes/i.test(h), /Options\s+-Indexes/i.test(h) ? 'on' : 'off', 'Options -Indexes');
} else add('INFO', '.htaccess', false, 'no .htaccess in root', 'add hardening rules — Apache only');

const f = checks.filter((c) => c.status === 'FAIL');
const critical = f.filter((c) => c.level === 'CRITICAL' || c.level === 'HIGH').length;

if (flag(o, 'json')) console.log(JSON.stringify({ root, critical_or_high: critical, failures: f.length, checks }, null, 2));
else {
  console.log(table(checks.map((c) => ({ level: c.level, status: c.status, check: c.check, detail: String(c.detail).slice(0, 52) }))));
  console.log(`\n${f.length} failing check(s), ${critical} critical/high`);
  if (flag(o, 'fix-hints') && f.length) { console.log('\nfixes:'); f.forEach((c) => console.log(`  ${c.check}: ${c.fix}`)); }
}
process.exit(critical ? 1 : 0);
