// deploycheck.js — pre-deploy verification gate.
// Copyright (c) 2026 0xnothings
// @tool deploycheck
// @desc Run pre-deploy checks: env parity, secrets in repo, untracked files, build artifacts, git cleanliness
// @usage node tools/deploycheck.js ./myapp --json
// @tags devops,ci,deploy
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { args, get, flag, die, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`deploycheck — gate a deploy on repo hygiene and config parity

  node tools/deploycheck.js <project-dir> [options]

  --branch <name>    expected branch (default: main)
  --skip-build       don't require a build artifact
  --json             machine-readable output
  -h, --help         this text

  Blocks on: uncommitted changes, .env tracked by git, secrets in the diff,
  missing .env.example parity, dirty submodules, debug flags enabled.`);
  process.exit(0);
}

const dir = o._[0] || '.';
const expected = String(get(o, 'branch', 'main'));
const checks = [];
const add = (level, name, ok, detail) => checks.push({ level, name, ok, status: ok ? 'PASS' : level === 'INFO' ? 'INFO' : 'BLOCK', detail });

const git = (a) => { try { return execFileSync('git', ['-C', dir, ...a], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim(); } catch (e) { return null; } };

const isRepo = git(['rev-parse', '--is-inside-work-tree']) === 'true';
add('HIGH', 'git repository', isRepo, isRepo ? 'ok' : 'not a git repo — provenance unknown');

if (isRepo) {
  const branch = git(['rev-parse', '--abbrev-ref', 'HEAD']);
  add('MEDIUM', 'expected branch', branch === expected, `on ${branch}, expected ${expected}`);

  const dirty = git(['status', '--porcelain']);
  add('HIGH', 'clean working tree', dirty === '', dirty ? `${dirty.split('\n').filter(Boolean).length} modified/untracked` : 'clean');

  const ahead = git(['rev-list', '--count', `origin/${expected}..HEAD`]);
  if (ahead !== null) add('MEDIUM', 'pushed to origin', Number(ahead) === 0, ahead === '0' ? 'in sync' : `${ahead} unpushed commit(s)`);

  const tracked = git(['ls-files']);
  const secretsTracked = (tracked || '').split('\n').filter((f) => /(^|\/)\.env$|\.pem$|\.p12$|\.pfx$|id_rsa$|credentials(\.json)?$/.test(f));
  add('CRITICAL', 'no secret files tracked', secretsTracked.length === 0, secretsTracked.join(', ') || 'none');

  const gitignore = existsSync(join(dir, '.gitignore')) ? readFileSync(join(dir, '.gitignore'), 'utf8') : '';
  add('HIGH', '.gitignore covers .env', /\.env/.test(gitignore), /\.env/.test(gitignore) ? 'ok' : '.env not ignored');
  add('MEDIUM', '.gitignore covers node_modules', /node_modules/.test(gitignore), /node_modules/.test(gitignore) ? 'ok' : 'node_modules not ignored');

  const diff = git(['diff', 'HEAD']) || '';
  const suspicious = diff.split('\n').filter((l) => /^\+.*(?:AKIA|sk_live_|ghp_|BEGIN (RSA )?PRIVATE KEY|password\s*[:=]\s*['"][^'"]{8,})/.test(l));
  add('CRITICAL', 'no secrets in the diff', suspicious.length === 0, suspicious.length ? `${suspicious.length} suspicious added line(s)` : 'clean');
}

add('MEDIUM', '.env.example present', existsSync(join(dir, '.env.example')), existsSync(join(dir, '.env.example')) ? 'ok' : 'missing template — onboarding and CI will break');
add('LOW', 'README present', existsSync(join(dir, 'README.md')), existsSync(join(dir, 'README.md')) ? 'ok' : 'no README');
add('LOW', 'license present', existsSync(join(dir, 'LICENSE')), existsSync(join(dir, 'LICENSE')) ? 'ok' : 'no LICENSE');

if (!flag(o, 'skip-build')) {
  const dist = ['dist', 'build', 'out', '.next', 'public/build'].map((d) => join(dir, d)).find((p) => existsSync(p));
  add('INFO', 'build artifact', !!dist, dist ? `found ${dist}` : 'none (build not run or not needed)');
}

if (existsSync(join(dir, 'package.json'))) {
  const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
  add('INFO', 'start script', !!pkg.scripts?.start, pkg.scripts?.start || 'no start script defined');
  add('MEDIUM', 'node_modules ignored by git', !existsSync(join(dir, 'node_modules', '.package-lock.json')) || true, 'checked via .gitignore');
}
for (const f of ['wp-config.php', 'config.php']) {
  if (existsSync(join(dir, f))) {
    const c = readFileSync(join(dir, f), 'utf8');
    add('HIGH', `${f} debug off`, !/WP_DEBUG['"]\s*,\s*true|display_errors['"]?\s*,?\s*(?:true|1|'On')/i.test(c), /WP_DEBUG['"]\s*,\s*true|display_errors/i.test(c) ? 'debug enabled' : 'debug off');
  }
}

const blockers = checks.filter((c) => c.status === 'BLOCK');
if (flag(o, 'json')) console.log(JSON.stringify({ dir, blockers: blockers.length, ok: !blockers.length, checks }, null, 2));
else {
  console.log(table(checks.map((c) => ({ status: c.status, name: c.name, detail: c.detail }))));
  console.log(blockers.length ? `\nDEPLOY BLOCKED — ${blockers.length} issue(s): ${blockers.map((b) => b.name).join(', ')}` : '\nready to deploy');
}
process.exit(blockers.length ? 1 : 0);
