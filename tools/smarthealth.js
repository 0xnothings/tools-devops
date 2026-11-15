#!/usr/bin/env node
// smarthealth.js — parse smartctl output into a disk health verdict.
// Copyright (c) 2026 0xnothings
// @tool smarthealth
// @desc Parse smartctl -a output: reallocated/pending sectors, wear levelling, temperature, power-on hours and a failure-risk heuristic
// @usage node tools/smarthealth.js smartctl-all.txt --json
// @tags devops,disk,smart,health
import { readFileSync, existsSync } from 'node:fs';
import { args, flag, die, emit, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`smarthealth — SMART report analyser

  node tools/smarthealth.js <smartctl-output.txt> [more.txt ...] [options]

  Produce the input with:  smartctl -a /dev/sda > smartctl-sda.txt
  (or smartctl -x for the full table, -j for JSON)

  --json         machine-readable output
  --warn-temp <c>  temperature warning threshold (default 50)
  --fail-temp <c>  temperature failure threshold (default 60)
  --max-hours <n>  expected service life in power-on hours (default 35000)
  -h, --help     this text

  Heuristic risk model: reallocated/pending/uncorrectable sectors, growth in
  reallocation over time, NVMe percentage_used, SSD wear levelling, temperature,
  spin retries, and SMART overall health.`);
  process.exit(0);
}

const paths = o._.length ? o._ : [];
if (!paths.length) die('usage: node tools/smarthealth.js <smartctl-output.txt> [--json]');
const warnTemp = Number(o.f['warn-temp'] || 50);
const failTemp = Number(o.f['fail-temp'] || 60);
const maxHours = Number(o.f['max-hours'] || 35000);

const ID_MAP = {
  5: { key: 'reallocated_sectors', critical: true, label: 'Reallocated_Sector_Ct' },
  9: { key: 'power_on_hours', critical: false, label: 'Power_On_Hours' },
  12: { key: 'power_cycles', critical: false, label: 'Power_Cycle_Count' },
  177: { key: 'wear_leveling', critical: false, label: 'Wear_Leveling_Count' },
  187: { key: 'uncorrectable', critical: true, label: 'Reported_Uncorrect' },
  188: { key: 'command_timeouts', critical: false, label: 'Command_Timeout' },
  194: { key: 'temperature', critical: false, label: 'Temperature_Celsius' },
  196: { key: 'reallocated_events', critical: true, label: 'Reallocated_Event_Count' },
  197: { key: 'pending_sectors', critical: true, label: 'Current_Pending_Sector' },
  198: { key: 'offline_uncorrectable', critical: true, label: 'Offline_Uncorrectable' },
  199: { key: 'crc_errors', critical: false, label: 'UDMA_CRC_Error_Count' },
  231: { key: 'ssd_life_left', critical: false, label: 'SSD_Life_Left' },
  233: { key: 'media_wearout', critical: false, label: 'Media_Wearout_Indicator' },
  241: { key: 'total_lba_written', critical: false, label: 'Total_LBAs_Written' },
};

const disks = [];
for (const p of paths) {
  if (!existsSync(p)) die(`no such file: ${p}`);
  const text = readFileSync(p, 'utf8');
  const chunks = text.split(/(?=^=== START OF INFORMATION SECTION)/m).filter((c) => /Model|Device Model|Model Number|Vendor/i.test(c) || /SMART overall-health/i.test(c));
  for (const chunk of (chunks.length ? chunks : [text])) {
    const g = (re) => { const m = chunk.match(re); return m ? m[1].trim() : null; };
    const model = g(/^(?:Device Model|Model Number|Model Family|Product):\s*(.+)$/m) || '(unknown)';
    const serial = g(/^Serial Number:\s*(.+)$/m) || '-';
    const fw = g(/^Firmware Version:\s*(.+)$/m) || '-';
    const capacity = g(/^User Capacity:\s*(.+)$/m) || g(/^Total NVM Capacity:\s*(.+)$/m) || '-';
    const rotation = g(/^Rotation Rate:\s*(.+)$/m) || (/(Solid State Device|NVMe)/i.test(chunk) ? 'SSD' : 'unknown');
    const health = g(/SMART overall-health self-assessment test result:\s*(\S+)/i) || (/(PASSED|OK)/.test(chunk) ? 'PASSED' : 'UNKNOWN');
    const isNvme = /NVMe|smartctl .*NVMe/i.test(chunk) || /Percentage Used/i.test(chunk);

    const attrs = {};
    for (const line of chunk.split(/\r?\n/)) {
      const m = line.match(/^\s*(\d{1,3})\s+(\S+)\s+0x[0-9a-f]+\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)/);
      if (m) {
        const id = Number(m[1]);
        const meta = ID_MAP[id] || { key: `attr_${m[2]}`, critical: false, label: m[2] };
        const raw = m[9];
        const rawNum = /^\d+$/.test(raw) ? Number(raw) : (raw.match(/^(\d+)/) || [])[1];
        attrs[meta.key] = { value: Number(m[4]), worst: Number(m[5]), thresh: Number(m[6]), raw: rawNum !== undefined ? Number(rawNum) : null, type: m[7], updated: m[8], label: meta.label, critical: meta.critical };
      }
      const nv = line.match(/^(Percentage Used|Available Spare|Data Units Written|Power On Hours|Unsafe Shutdowns|Media and Data Integrity Errors|Available Spare Threshold):\s*([^\n]+)/);
      if (nv) attrs[nv[1].replace(/\s+/g, '_').toLowerCase()] = { value: nv[2].trim(), label: nv[1], nvme: true };
    }

    const realloc = attrs.reallocated_sectors?.raw ?? 0;
    const pending = attrs.pending_sectors?.raw ?? 0;
    const offline = attrs.offline_uncorrectable?.raw ?? 0;
    const uncorr = attrs.uncorrectable?.raw ?? 0;
    const crc = attrs.crc_errors?.raw ?? 0;
    const hours = attrs.power_on_hours?.raw ?? Number((attrs.power_on_hours?.value ?? 0));
    const temp = attrs.temperature?.raw ?? attrs.temperature?.value ?? (attrs.temperature_celsius?.raw ?? null);
    const pctUsed = attrs.percentage_used ? Number(String(attrs.percentage_used.value).replace('%', '')) : null;
    const spare = attrs.available_spare ? Number(String(attrs.available_spare.value).replace('%', '')) : null;
    const mediaErrors = attrs.media_and_data_integrity_errors ? Number(attrs.media_and_data_integrity_errors.value) : null;
    const wear = attrs.wear_leveling?.raw ?? attrs.media_wearout?.raw ?? attrs.ssd_life_left?.raw ?? null;

    let risk = 0;
    const reasons = [];
    const bump = (n, why) => { risk += n; reasons.push(why); };
    if (/FAILED/i.test(health)) bump(60, 'SMART overall-health reports FAILED');
    if (realloc > 0) bump(Math.min(25, 5 + realloc), `${realloc} reallocated sector(s)`);
    if (pending > 0) bump(Math.min(35, 15 + pending * 2), `${pending} pending (unstable) sector(s) — the drive cannot read them yet`);
    if (offline > 0) bump(Math.min(30, 10 + offline * 3), `${offline} offline-uncorrectable sector(s)`);
    if (uncorr > 0) bump(Math.min(15, 5 + uncorr), `${uncorr} reported uncorrectable error(s)`);
    if (mediaErrors) bump(Math.min(30, 10 + mediaErrors), `${mediaErrors} NVMe media/data integrity error(s)`);
    if (crc > 0) bump(Math.min(10, 2 + Math.floor(crc / 10)), `${crc} UDMA CRC error(s) — usually cabling, not the platter`);
    if (temp !== null && temp >= failTemp) bump(20, `temperature ${temp}C is above the ${failTemp}C failure threshold`);
    else if (temp !== null && temp >= warnTemp) bump(8, `temperature ${temp}C is above the ${warnTemp}C warning threshold`);
    if (pctUsed !== null && pctUsed >= 90) bump(25, `NVMe percentage used ${pctUsed}%`);
    else if (pctUsed !== null && pctUsed >= 75) bump(10, `NVMe percentage used ${pctUsed}%`);
    if (spare !== null && spare <= 10) bump(25, `available spare ${spare}%`);
    if (hours > maxHours) bump(10, `${hours} power-on hours exceeds the ${maxHours}h design life`);
    if (Object.values(attrs).some((a) => a.thresh && a.value <= a.thresh && a.thresh > 0)) bump(15, 'a SMART attribute has reached its failure threshold');

    const verdict = risk >= 60 ? 'FAILING' : risk >= 35 ? 'DEGRADED' : risk >= 15 ? 'WATCH' : 'HEALTHY';
    const action = verdict === 'FAILING' ? 'replace now — migrate data first, then RMA'
      : verdict === 'DEGRADED' ? 'schedule replacement, ensure backups are current, run a long self-test'
      : verdict === 'WATCH' ? 'monitor weekly, run smartctl -t long, verify backup integrity'
      : 'no action';
    disks.push({ file: p, model, serial, firmware: fw, capacity, media: rotation, nvme: isNvme, health, risk, verdict, action, reasons,
      key: { reallocated: realloc, pending, offline_uncorrectable: offline, uncorrectable: uncorr, crc_errors: crc, power_on_hours: hours, temperature: temp, percentage_used: pctUsed, available_spare: spare, wear } });
  }
}

if (flag(o, 'json')) { emit({ disks, worst: disks.map((d) => d.verdict).sort((a, b) => ['FAILING', 'DEGRADED', 'WATCH', 'HEALTHY'].indexOf(a) - ['FAILING', 'DEGRADED', 'WATCH', 'HEALTHY'].indexOf(b))[0] || 'HEALTHY' }); process.exit(0); }

console.log(`smarthealth: ${disks.length} device(s)`);
console.log('');
console.log(table(disks.map((d) => ({ model: d.model.slice(0, 28), media: d.media, hours: d.key.power_on_hours ?? '-', temp: d.key.temperature ?? '-', realloc: d.key.reallocated, pending: d.key.pending, used: d.key.percentage_used ?? '-', verdict: d.verdict })), ['model', 'media', 'hours', 'temp', 'realloc', 'pending', 'used', 'verdict']));
for (const d of disks) {
  console.log(`\n${d.model} [${d.serial}] ${d.capacity} ${d.nvme ? 'NVMe' : d.media}`);
  console.log(`  health=${d.health}  risk=${d.risk}/100  verdict=${d.verdict}`);
  console.log(`  action: ${d.action}`);
  if (d.reasons.length) for (const r of d.reasons) console.log(`  - ${r}`);
}
const worst = disks.some((d) => d.verdict === 'FAILING');
process.exit(worst ? 2 : disks.some((d) => d.verdict === 'DEGRADED') ? 1 : 0);
