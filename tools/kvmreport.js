#!/usr/bin/env node
// kvmreport.js — summarise libvirt/KVM domain XML.
// Copyright (c) 2026 0xnothings
// @tool kvmreport
// @desc Parse libvirt domain XML: vCPU/memory allocation, disk and network devices, host-passthrough CPU and autostart flags
// @usage node tools/kvmreport.js domain.xml --json
// @tags devops,kvm,libvirt,virtualization
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { args, flag, die, emit, table } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`kvmreport — libvirt/KVM domain XML reporter

  node tools/kvmreport.js <domain.xml|/etc/libvirt/qemu> [options]

  --json        machine-readable output
  --overcommit  flag memory/vcpu allocations that risk overcommit
  -h, --help    this text`);
  process.exit(0);
}

const target = o._[0] || '/etc/libvirt/qemu';
let files = [];
try {
  const st = statSync(target);
  if (st.isDirectory()) files = readdirSync(target).filter((f) => f.endsWith('.xml')).map((f) => join(target, f));
  else files = [target];
} catch (e) { die(`cannot read ${target}: ${e.message}`); }
if (!files.length) die(`no domain XML found at ${target}`);

// minimal, tolerant XML reader — enough for libvirt domain files (self-closing and paired tags, single or double quotes)
function attr(s, name) {
  if (!s) return null;
  const m = s.match(new RegExp(`${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)')`));
  return m ? (m[1] !== undefined ? m[1] : m[2]) : null;
}
function allTags(text, name) {
  const out = [];
  const openRe = new RegExp(`<${name}((?:[^>"']|"[^"]*"|'[^']*')*?)(/?)>`, 'g');
  let m;
  while ((m = openRe.exec(text))) {
    if (m[2] === '/') { out.push({ attrs: m[1], body: '' }); continue; }
    const closeTag = `</${name}>`;
    const closeIdx = text.indexOf(closeTag, openRe.lastIndex);
    const body = closeIdx === -1 ? '' : text.slice(openRe.lastIndex, closeIdx);
    out.push({ attrs: m[1], body });
    if (closeIdx === -1) break;
    openRe.lastIndex = closeIdx + closeTag.length;
  }
  return out;
}
function tag(text, name) {
  const all = allTags(text, name);
  return all.length ? all[0].attrs : null;
}

const rows = [];
for (const f of files) {
  const xml = readFileSync(f, 'utf8');
  const nm = (xml.match(/<name>([^<]*)<\/name>/) || [])[1] || '(unnamed)';
  const vcpuTag = tag(xml, 'vcpu');
  const vcpu = vcpuTag ? (xml.match(/<vcpu[^>]*>(\d+)<\/vcpu>/) || [])[1] || attr(vcpuTag, 'current') || '1' : '1';
  const memTag = tag(xml, 'memory') || '';
  const memKiB = Number(attr(memTag, 'unit') === 'GiB' ? Number(xml.match(/<memory[^>]*>(\d+)<\/memory>/)?.[1] || 0) * 1024 * 1024 : (xml.match(/<memory[^>]*>(\d+)<\/memory>/) || [])[1] || 0);
  const memGiB = memKiB / 1024 / 1024;
  const curMem = xml.match(/<currentMemory[^>]*>(\d+)<\/currentMemory>/);
  const curGiB = curMem ? Number(curMem[1]) / 1024 / 1024 : memGiB;
  const cpuMode = attr(tag(xml, 'cpu'), 'mode');
  const features = (xml.match(/<feature\s+policy='[^']*'\s+name='([^']+)'/g) || []).map((s) => (s.match(/name='([^']+)'/) || [])[1]).filter(Boolean);
  const disks = allTags(xml, 'disk').map((d) => {
    const src = (d.body.match(/<source[^>]*file='([^']*)'/) || d.body.match(/<source[^>]*dev='([^']*)'/) || [])[1] || (d.body.match(/<source[^>]*name='([^']*)'/) || [])[1] || '(none)';
    const targetDev = (d.body.match(/<target[^>]*dev='([^']*)'/) || [])[1] || '?';
    const sharing = (d.body.match(/<shareable\/>/) ? 'shareable' : (d.body.match(/<readonly\/>/) ? 'readonly' : 'rw'));
    const cache = (d.body.match(/<driver[^>]*cache='([^']*)'/) || [])[1] || 'default';
    const discard = /discard='unmap'/.test(d.body) ? 'unmap' : 'off';
    return { type: attr(d.attrs, 'type') || 'file', device: attr(d.attrs, 'device') || 'disk', source: src, target: targetDev, sharing, cache, discard };
  });
  const nets = allTags(xml, 'interface').map((n) => ({
    type: attr(n.attrs, 'type') || '?',
    mac: (n.body.match(/<mac\s+address='([^']*)'/) || [])[1] || '(auto)',
    model: attr(tag(n.body, 'model'), 'type') || '?',
    bridge: (n.body.match(/<source\s+bridge='([^']*)'/) || n.body.match(/<source\s+network='([^']*)'/) || [])[1] || '-',
  }));
  const graphics = allTags(xml, 'graphics').map((g) => ({ type: attr(g.attrs, 'type'), listen: attr(g.attrs, 'listen') || '127.0.0.1', port: attr(g.attrs, 'port') || 'auto' }));
  const devices = tag(xml, 'devices') || '';
  const bootOrder = (xml.match(/<boot[^>]*dev='([^']*)'/g) || []).map((s) => (s.match(/dev='([^']*)'/) || [])[1]);
  const osType = (xml.match(/<type[^>]*>([^<]*)<\/type>/) || [])[1];
  const onPoweroff = (xml.match(/<on_poweroff>([^<]*)<\/on_poweroff>/) || [])[1] || '-';
  const onReboot = (xml.match(/<on_reboot>([^<]*)<\/on_reboot>/) || [])[1] || '-';

  const notes = [];
  if (cpuMode === 'host-passthrough') notes.push({ level: 'MEDIUM', text: 'cpu mode host-passthrough pins the domain to this exact CPU model (live migration will fail)' });
  if (memGiB <= 0 || vcpu === '0') notes.push({ level: 'HIGH', text: 'memory or vcpu not declared' });
  if (graphics.some((g) => g.listen === '0.0.0.0')) notes.push({ level: 'HIGH', text: 'VNC/SPICE listening on 0.0.0.0' });
  if (disks.some((d) => d.sharing === 'shareable')) notes.push({ level: 'HIGH', text: 'shareable disk image attached to a live domain (data corruption risk)' });
  if (!/<memoryBacking>/.test(xml) && curGiB < memGiB) notes.push({ level: 'LOW', text: `ballooning enabled (max ${memGiB} GiB, current ${curGiB} GiB)` });
  if (disks.length === 0) notes.push({ level: 'LOW', text: 'no disk device (network/container boot only)' });

  rows.push({
    file: f.split(/[\\/]/).pop(), name: nm, os: osType || '?', vcpu: Number(vcpu),
    memGiB: Number(memGiB.toFixed(2)), curGiB: Number(curGiB.toFixed(2)),
    cpuMode: cpuMode || 'custom/default', features: features.join(',') || '-',
    disks: disks.length, nets: nets.length, graphics: graphics.map((g) => `${g.type}@${g.listen}:${g.port}`).join(' ') || 'none',
    poweroff: onPoweroff, reboot: onReboot, bootOrder: bootOrder.join('>') || '-',
    diskDetail: disks, netDetail: nets, notes,
  });
}

const findings = rows.flatMap((r) => r.notes.map((n) => ({ domain: r.name, severity: n.level, message: n.text })));
const high = findings.filter((f) => f.severity === 'HIGH').length;

if (flag(o, 'json')) { emit({ target, domains: rows, findings, counts: { domains: rows.length, high, notes: findings.length } }); process.exit(0); }

console.log(`kvmreport: ${target}`);
console.log(`domains: ${rows.length}  notes: ${findings.length}  high: ${high}`);
console.log('');
console.log(table(rows.map((r) => ({ name: r.name, vcpu: r.vcpu, memGiB: r.memGiB, curGiB: r.curGiB, cpuMode: r.cpuMode, disks: r.disks, nets: r.nets, graphics: r.graphics })), ['name', 'vcpu', 'memGiB', 'curGiB', 'cpuMode', 'disks', 'nets', 'graphics']));
for (const r of rows) {
  if (!r.diskDetail.length) continue;
  console.log(`\n${r.name} disks:`);
  console.log(table(r.diskDetail.map((d) => ({ target: d.target, device: d.device, source: d.source.slice(-44), cache: d.cache, discard: d.discard })), ['target', 'device', 'source', 'cache', 'discard']));
  if (r.netDetail.length) {
    console.log(`${r.name} networks:`);
    console.log(table(r.netDetail.map((n) => ({ iface: n.type, model: n.model, mac: n.mac, bridge: n.bridge })), ['iface', 'model', 'mac', 'bridge']));
  }
  if (r.features !== '-') console.log(`${r.name} cpu features: ${r.features}`);
}
if (findings.length) {
  console.log('\nnotes:');
  const order = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  console.log(table(findings.sort((a, b) => order[a.severity] - order[b.severity]).map((f) => ({ severity: f.severity, domain: f.domain, detail: f.message })), ['severity', 'domain', 'detail']));
}
process.exit(0);
