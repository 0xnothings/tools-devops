// gitstats.js — repository contribution and churn statistics.
// Copyright (c) 2026 0xnothings
// @tool gitstats
// @desc Repo stats: commits per author, churn per file, busiest hours, stale branches, TODO debt count
// @usage node tools/gitstats.js . --months 12 --json
// @tags devops,git,metrics
import { execFileSync } from 'node:child_process';
import { args, get, num, flag, die, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`gitstats — repository statistics

  node tools/gitstats.js <repo-dir> [options]

  --months <n>     analysis window (default: 12)
  --top <n>        rows per ranking (default: 15)
  --json           machine-readable output
  -h, --help       this text`);
  process.exit(0);
}

const repo = o._[0] || '.';
const months = num(get(o, 'months'), 12);
const top = num(get(o, 'top'), 15);
const git = (a, big = false) => { try { return execFileSync('git', ['-C', repo, ...a], { encoding: 'utf8', maxBuffer: big ? 1024 * 1024 * 512 : 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] }); } catch { return null; } };

if (git(['rev-parse', '--is-inside-work-tree']) !== 'true\n' && git(['rev-parse', '--is-inside-work-tree']) !== 'true') die(`${repo} is not a git repository`);

const since = `--since=${months} months ago`;
const authorLines = (git(['shortlog', '-sn', '--all', since]) || '').split('\n').filter(Boolean)
  .map((l) => { const m = l.trim().match(/^(\d+)\s+(.+)$/); return m ? { commits: Number(m[1]), author: m[2] } : null; }).filter(Boolean);

const churn = (git(['log', '--numstat', '--pretty=format:', since], true) || '').split('\n').filter(Boolean)
  .map((l) => { const [a, d, f] = l.split('\t'); return { file: f, add: Number(a) || 0, del: Number(d) || 0 }; })
  .filter((x) => x.file);
const churnAgg = new Map();
for (const c of churn) {
  const cur = churnAgg.get(c.file) || { file: c.file, add: 0, del: 0, touches: 0 };
  cur.add += c.add; cur.del += c.del; cur.touches++;
  churnAgg.set(c.file, cur);
}
const hot = [...churnAgg.values()].map((c) => ({ ...c, churn: c.add + c.del })).sort((a, b) => b.churn - a.churn).slice(0, top);

const dates = (git(['log', '--pretty=format:%aI', since]) || '').split('\n').filter(Boolean);
const hourHist = {}, dowHist = {};
for (const d of dates) { const dt = new Date(d); hourHist[dt.getUTCHours()] = (hourHist[dt.getUTCHours()] || 0) + 1; dowHist[dt.getUTCDay()] = (dowHist[dt.getUTCDay()] || 0) + 1; }
const DOW = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

const branches = (git(['for-each-ref', '--sort=-committerdate', '--format=%(refname:short)\t%(committerdate:relative)\t%(authorname)', 'refs/heads/']) || '').split('\n').filter(Boolean).map((l) => { const [name, when, who] = l.split('\t'); return { name, when, who }; });
const merged = (git(['branch', '--merged', 'HEAD']) || '').split('\n').map((b) => b.replace(/^\*?\s*/, '').trim()).filter(Boolean);
const stale = branches.filter((b) => !merged.includes(b.name) && /months? ago|years? ago/.test(b.when));

const todoCount = (git(['grep', '-c', '-I', '-E', 'TODO|FIXME|HACK|XXX', 'HEAD']) || '').split('\n').filter(Boolean).length;
const repoSize = (git(['count-objects', '-vH']) || '').split('\n').find((l) => l.startsWith('size-pack')) || '';

const report = {
  repo, window_months: months, total_commits: dates.length,
  authors: authorLines.slice(0, top), hot_files: hot,
  busiest_hours_utc: Object.entries(hourHist).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([h, n]) => `${String(h).padStart(2, '0')}:00 (${n})`),
  busiest_days: Object.entries(dowHist).sort((a, b) => b[1] - a[1]).map(([d, n]) => `${DOW[d]} (${n})`),
  branches: branches.length, stale_branches: stale.map((s) => `${s.name} (${s.when})`),
  todo_files: todoCount, pack_size: repoSize.trim(),
};

if (flag(o, 'json')) { console.log(JSON.stringify(report, null, 2)); process.exit(0); }
console.log(`${repo}: ${report.total_commits} commits over ${months} months, ${branches.length} branches, ${report.pack_size}`);
console.log('\n-- authors --'); console.log(table(authorLines.slice(0, top)));
console.log('\n-- hottest files --'); console.log(table(hot.map((h) => ({ file: h.file.slice(0, 52), touches: h.touches, additions: h.add, deletions: h.del, churn: h.churn }))));
if (stale.length) { console.log('\n-- stale branches --'); stale.forEach((s) => console.log(`  ${s.name}  (${s.when}, ${s.who})`)); }
console.log(`\nbusiest hours (UTC): ${report.busiest_hours_utc.join(', ')}`);
console.log(`busiest days: ${report.busiest_days.slice(0, 3).join(', ')}`);
console.log(`TODO/FIXME in ${report.todo_files} tracked file(s)`);
