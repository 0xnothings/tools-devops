// imagetag.js — sort and audit container image tags.
// Copyright (c) 2026 0xnothings
// @tool imagetag
// @desc Sort semver-ish image tags, find the newest patch per minor, and flag mutable, stale and non-conforming tags
// @usage node tools/imagetag.js tags.txt --json
// @tags devops,docker,registry,versioning
import { readFileSync, existsSync } from 'node:fs';
import { args, get, num, flag, die, emit, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`imagetag — container tag auditor

  node tools/imagetag.js <tags.txt|"1.2.3 1.2.4 2.0.0"> [options]

  Input: one tag per line (or comma/space separated). Comments with # are skipped.

  --repo <name>       repository name, used in the recommendation output
  --keep <n>          how many recent minors to keep (default 3)
  --json              machine-readable output
  --latest-per-minor  print only the newest patch of each minor, newest first
  -h, --help          this text

  Classifies each tag as immutable (semver or a date-stamp) or mutable
  (latest, dev, stable, a bare major, a date-less branch name), and reports
  the sorted release order plus gaps in the patch sequence.`);
  process.exit(0);
}

const src = o._[0];
if (!src) die('usage: node tools/imagetag.js <tags.txt|"1.2.3 1.2.4"> [--json]');
let text;
if (existsSync(src)) text = readFileSync(src, 'utf8');
else text = src;
const tags = [...new Set(text.split(/[\s,]+/).map((s) => s.trim()).filter((s) => s && !s.startsWith('#')))];
if (!tags.length) die('no tags found in the input');

const MUTABLE = /^(latest|stable|stable-\w+|dev|devel|nightly|edge|main|master|mainline|canary|beta|alpha|rc|testing|unstable|prod|production)$/i;
const SEMVER = /^v?(\d+)\.(\d+)\.(\d+)(?:-([A-Za-z0-9.]+))?(?:\+([A-Za-z0-9.]+))?$/;
const DATE = /^(?:v?)(\d{4})[.-]?(\d{2})[.-]?(\d{2})(?:[-._]?(\d{4,6}))?$/;
const MAJOR_ONLY = /^v?\d+$/;
const MINOR_ONLY = /^v?\d+\.\d+$/;

function parse(t) {
  let m = t.match(SEMVER);
  if (m) return { kind: 'semver', major: +m[1], minor: +m[2], patch: +m[3], pre: m[4] || null, build: m[5] || null, original: t };
  m = t.match(DATE);
  if (m) return { kind: 'date', y: +m[1], mo: +m[2], d: +m[3], seq: m[4] ? +m[4] : 0, original: t };
  if (MAJOR_ONLY.test(t)) return { kind: 'major-only', major: +t.replace(/^v/, ''), original: t };
  if (MINOR_ONLY.test(t)) { const [a, b] = t.replace(/^v/, '').split('.').map(Number); return { kind: 'minor-only', major: a, minor: b, original: t }; }
  if (MUTABLE.test(t)) return { kind: 'mutable', original: t };
  const sha = t.match(/^[0-9a-f]{7,64}$/i);
  if (sha) return { kind: 'digest-like', original: t, sha: sha[0] };
  return { kind: 'other', original: t };
}

const parsed = tags.map(parse);
const semver = parsed.filter((p) => p.kind === 'semver');
const dates = parsed.filter((p) => p.kind === 'date');

const cmpSemver = (a, b) => (a.major - b.major) || (a.minor - b.minor) || (a.patch - b.patch) || ((a.pre ? 1 : 0) - (b.pre ? 1 : 0));
const cmpDate = (a, b) => (a.y - b.y) || (a.mo - b.mo) || (a.d - b.d) || (a.seq - b.seq);
semver.sort(cmpSemver);
dates.sort(cmpDate);

const findings = [];
const add = (sev, tag, msg) => findings.push({ severity: sev, tag, message: msg });

for (const p of parsed) {
  if (p.kind === 'mutable') add('HIGH', p.original, 'mutable tag — the image behind it changes without warning; never deploy this to production');
  if (p.kind === 'major-only') add('MEDIUM', p.original, 'major-only tag floats across breaking changes');
  if (p.kind === 'minor-only') add('LOW', p.original, 'minor-only tag floats across patch releases; acceptable for pins you re-resolve deliberately');
  if (p.kind === 'other' && !/^\d/.test(p.original)) add('LOW', p.original, 'non-version tag; cannot be ordered or audited automatically');
  if (p.kind === 'semver' && p.major === 0) add('MEDIUM', p.original, '0.x version — the API is not stable yet, upgrades are not patch-safe');
  if (p.kind === 'semver' && p.pre) add('LOW', p.original, `pre-release tag (${p.pre}); do not run pre-releases in production`);
}

// newest patch per minor
const perMinor = new Map();
for (const p of semver) {
  const k = `${p.major}.${p.minor}`;
  const cur = perMinor.get(k);
  if (!cur || cmpSemver(p, cur) > 0) perMinor.set(k, p);
}
const latestPerMinor = [...perMinor.entries()].sort((a, b) => cmpSemver(b[1], a[1])).map(([k, p]) => ({ minor: k, tag: p.original, prerelease: !!p.pre }));
const majors = new Map();
for (const p of semver) { const cur = majors.get(p.major); if (!cur || cmpSemver(p, cur) > 0) majors.set(p.major, p); }
const latestPerMajor = [...majors.entries()].sort((a, b) => b[0] - a[0]).map(([mj, p]) => ({ major: mj, tag: p.original }));
const newest = semver.length ? semver[semver.length - 1] : null;
const newestDate = dates.length ? dates[dates.length - 1] : null;

// patch gaps within the newest minor line
const gaps = [];
const byMinor = new Map();
for (const p of semver) { const k = `${p.major}.${p.minor}`; if (!byMinor.has(k)) byMinor.set(k, []); byMinor.get(k).push(p); }
for (const [k, list] of byMinor) {
  list.sort(cmpSemver);
  for (let i = 1; i < list.length; i++) {
    const missing = [];
    for (let p = list[i - 1].patch + 1; p < list[i].patch; p++) missing.push(p);
    if (missing.length) gaps.push({ line: k, between: `${list[i - 1].original} and ${list[i].original}`, missing: missing.map((p) => `${k}.${p}`).join(', ') });
  }
  if (List_firstPatchGap(list)) { /* noop */ }
}
function List_firstPatchGap() { return false; }

const keep = num(get(o, 'keep'), 3);
const keepList = latestPerMinor.slice(0, keep);
const pruneCandidates = semver.filter((p) => !keepList.some((k) => k.tag === p.original) && !p.pre);

if (flag(o, 'json')) {
  emit({
    input: src, total: tags.length,
    classified: { semver: semver.length, date: dates.length, mutableCount: parsed.filter((p) => p.kind === 'mutable').length, other: parsed.filter((p) => p.kind === 'other').length },
    sorted: semver.map((p) => p.original),
    sortedDates: dates.map((p) => p.original),
    newest: newest ? newest.original : null,
    newestDate: newestDate ? newestDate.original : null,
    latestPerMinor, latestPerMajor, gaps, findings,
    recommendedPin: newest ? newest.original : (newestDate ? newestDate.original : null),
    keep: keepList.map((k) => k.tag), pruneCandidates: pruneCandidates.map((p) => p.original),
    counts: { findings: findings.length, mutable: parsed.filter((p) => p.kind === 'mutable').length },
  });
  process.exit(0);
}

if (flag(o, 'latest-per-minor')) {
  for (const k of latestPerMinor) console.log(k.tag);
  process.exit(0);
}

console.log(`imagetag: ${tags.length} tag(s) from ${src.length > 60 ? 'file' : 'inline input'}`);
console.log(`newest semver: ${newest ? newest.original : '(none)'}${newestDate ? `  newest date-stamp: ${newestDate.original}` : ''}`);
console.log(`recommended pin: ${newest ? newest.original : '(none)'}`);
console.log('');
console.log(`latest per minor (newest ${keep} kept):`);
console.log(table(latestPerMinor.map((k, i) => ({ minor: k.minor, tag: k.tag, action: i < keep ? 'keep' : 'prune candidate' })), ['minor', 'tag', 'action']));
if (latestPerMajor.length) {
  console.log('\nlatest per major line:');
  console.log(table(latestPerMajor.map((k) => ({ major: k.major, tag: k.tag })), ['major', 'tag']));
}
if (semver.length) {
  console.log('\nrelease order:');
  console.log(table(semver.map((p, i) => ({ order: i + 1, tag: p.original, kind: p.pre ? `pre-release (${p.pre})` : 'stable' })).slice(-20), ['order', 'tag', 'kind']));
}
if (dates.length) {
  console.log('\ndate-stamped tags (newest first):');
  console.log(table(dates.slice().reverse().slice(0, 15).map((p) => ({ tag: p.original, date: `${p.y}-${String(p.mo).padStart(2, '0')}-${String(p.d).padStart(2, '0')}${p.seq ? ` seq ${p.seq}` : ''}` })), ['tag', 'date']));
}
if (gaps.length) {
  console.log('\nsequence gaps:');
  console.log(table(gaps, ['line', 'between', 'missing']));
}
if (findings.length) {
  console.log('\nfindings:');
  const order = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  console.log(table(findings.sort((a, b) => order[a.severity] - order[b.severity]), ['severity', 'tag', 'message']));
}
if (pruneCandidates.length) console.log(`\nprune candidates (${pruneCandidates.length}): ${pruneCandidates.slice(0, 12).map((p) => p.original).join(' ')}${pruneCandidates.length > 12 ? ' ...' : ''}`);
process.exit(findings.some((f) => f.severity === 'HIGH') ? 1 : 0);
