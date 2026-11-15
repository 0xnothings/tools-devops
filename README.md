# tools-devops

Zero-dependency Node.js operational tools. Config hygiene, deploy gates, log analysis, certificate lifecycle, host audits, and generators — all standard library only.

```bash
node tools/deploycheck.js ./myapp
node tools/logparse.js access.log --top 20
node tools/nginxgen.js proxy --domain api.example.com --upstream 127.0.0.1:3000
```

Requirements: Node.js 18+ (uses `fetch`, ESM). No `npm install`.

## How it works

```
_ lib.js        shared argv parser, table renderer, stdin/line helpers
tools/*.js      one file per tool, self-contained, --help on every one
index-tools.js  rescans tools/ and regenerates the catalogue below
smoke.js        runs every tool with --help and reports pass/fail
catalogue.json  machine-readable catalogue
```

Each tool carries its own metadata:

```js
// @tool envcheck
// @desc Diff a .env against .env.example: missing, extra, empty, duplicate keys
// @usage node tools/envcheck.js .env --template .env.example --json
// @tags devops,config,ci
```

`node index-tools.js` builds the README table from those blocks. Add a file, re-run the indexer, done.

Every tool supports `--json`. Exit codes: `0` clean, `1` problems found, `2` CI gate tripped.

## Discipline

- Nothing here mutates a remote host. Generators write files you name; auditors read.
- `dockerclean` prints commands, it does not run destructive prunes.
- `backup` writes plain `tar.gz` plus a manifest with checksums — verify before deleting anything upstream.
- Destructive-adjacent tools stop and tell you what to run instead.

## Catalogue

<!-- CATALOGUE:START -->

**48 tools**

| Tool | Description | Tags | Usage |
|---|---|---|---|
| [`backup`](tools/backup.js) | Create a tar.gz backup with a JSON manifest (hashes, sizes), verify archives, and prune by retention | devops, backup, archive | `node tools/backup.js ./public_html --out ./backups --keep 7 --json` |
| [`bandwidth`](tools/bandwidth.js) | Parse ifconfig / ip -s / vnstat / /proc/net/dev counters, compute throughput rates from two samples, and surface drops and errors | devops, network, metrics | `node tools/bandwidth.js sample1.txt sample2.txt --json` |
| [`basicauth`](tools/basicauth.js) | Create and verify htpasswd-style credentials (bcrypt via scrypt/PBKDF2 documented) with an .htaccess snippet | devops, http, basic-auth, security | `node tools/basicauth.js issue --user admin --pass secret --json` |
| [`certchain`](tools/certchain.js) | Fetch a host's served certificate chain, verify each link's signature, check ordering, expiry and missing intermediates, and report the root trust path | devops, tls, certificates, audit | `node tools/certchain.js example.com:443 --json` |
| [`certgen`](tools/certgen.js) | Generate RSA/EC keys, CSRs and self-signed certificates via openssl, plus base64 one-liners for CSR submission | devops, tls, certificates | `node tools/certgen.js --cn example.com --san example.com,www.example.com --days 825 --out ./certs` |
| [`composecheck`](tools/composecheck.js) | Lint docker-compose files for privileged mode, host-exposed ports, missing restart/healthcheck/resource limits and inline secrets | devops, docker, audit | `node tools/composecheck.js docker-compose.yml --json` |
| [`cronaudit`](tools/cronaudit.js) | Audit crontabs: duplicates, overlapping schedules, world-writable scripts, PATH hijack risk, missing redirection and shell metacharacters | devops, cron, audit | `node tools/cronaudit.js /etc/crontab /etc/cron.d --json` |
| [`cronconvert`](tools/cronconvert.js) | Convert schedules both ways: cron expression to systemd OnCalendar and English, OnCalendar to cron, and next-run previews | devops, cron, systemd, scheduler | `node tools/cronconvert.js "*/15 9-17 * * 1-5" --to systemd --json` |
| [`cronlab`](tools/cronlab.js) | Explain/validate cron expressions in English, compute next run times, and convert between formats | devops, cron, scheduler | `node tools/cronlab.js "*/15 9-17 * * 1-5" --next 5 --json` |
| [`deploycheck`](tools/deploycheck.js) | Run pre-deploy checks: env parity, secrets in repo, untracked files, build artifacts, git cleanliness | devops, ci, deploy | `node tools/deploycheck.js ./myapp --json` |
| [`diskusage`](tools/diskusage.js) | Walk directories for size and inode usage, report the biggest files and directories, and diff against a saved baseline snapshot | devops, disk, capacity | `node tools/diskusage.js /var --top 20 --save baseline.json --json` |
| [`dnspropagate`](tools/dnspropagate.js) | Query a record type across public resolvers over UDP, report answer disagreement, per-resolver latency and an overall propagation verdict | devops, dns, network | `node tools/dnspropagate.js example.com A --json` |
| [`dockerclean`](tools/dockerclean.js) | Report dangling images, stopped containers, orphan volumes and build cache; emit a safe/aggressive cleanup plan | devops, docker, cleanup | `node tools/dockerclean.js --mode plan --json` |
| [`dockerfilecheck`](tools/dockerfilecheck.js) | Dockerfile lint: latest tags, root user, ADD vs COPY, secrets in ARG/ENV, layer bloat, missing HEALTHCHECK and multi-stage opportunities | devops, docker, dockerfile, audit | `node tools/dockerfilecheck.js Dockerfile --json` |
| [`dotenvgen`](tools/dotenvgen.js) | Produce .env/.env.example/.env.docker from a single schema file with secret generation and validation | devops, config, generator | `node tools/dotenvgen.js schema.json --out .env --gen-secrets` |
| [`envcheck`](tools/envcheck.js) | Diff a .env against .env.example: find missing, extra, empty and duplicate keys (CI gate) | devops, config, ci | `node tools/envcheck.js .env --template .env.example --json` |
| [`envdiff`](tools/envdiff.js) | Diff two environments (dotenv files or KEY=value dumps): added, removed, changed keys with secret values masked | devops, config, drift | `node tools/envdiff.js .env.staging .env.prod --json` |
| [`envrc`](tools/envrc.js) | Parse .envrc: list exports and PATH changes, flag arbitrary shell execution, network fetches and missing `use` allow directives | devops, direnv, shell, audit | `node tools/envrc.js .envrc --json` |
| [`firewalldiff`](tools/firewalldiff.js) | Dump iptables/nftables/ufw rules, flag dangerous accepts, and diff against a saved baseline | devops, firewall, hardening | `node tools/firewalldiff.js --save baseline.json  |  node tools/firewalldiff.js --diff baseline.json` |
| [`gitstats`](tools/gitstats.js) | Repo stats: commits per author, churn per file, busiest hours, stale branches, TODO debt count | devops, git, metrics | `node tools/gitstats.js . --months 12 --json` |
| [`gru`](tools/gru.js) | Audit /etc/passwd and /etc/group: UID 0 accounts, empty passwords, sudo membership, shell inventory, staleness | devops, linux, hardening | `node tools/gru.js /etc/passwd /etc/group --shadow /etc/shadow --json` |
| [`healthcheck`](tools/healthcheck.js) | Poll a URL until it returns expected status/body, with interval, retries and total-time budget | devops, monitoring, ci | `node tools/healthcheck.js http://localhost:3000/healthz --expect 200 --retries 30 --json` |
| [`htpasswdgen`](tools/htpasswdgen.js) | Generate .htpasswd entries (apr1, sha1, scrypt, pbkdf2) as a batch from a CSV or prompts, with a verify mode and duplicate detection | devops, htpasswd, security | `node tools/htpasswdgen.js --users users.csv --scheme apr1 --out .htpasswd --json` |
| [`imagetag`](tools/imagetag.js) | Sort semver-ish image tags, find the newest patch per minor, and flag mutable, stale and non-conforming tags | devops, docker, registry, versioning | `node tools/imagetag.js tags.txt --json` |
| [`incidentlog`](tools/incidentlog.js) | Parse incident logs into a normalised timeline, compute MTTD/MTTA/MTTR, and detect recurrence patterns by service and cause | devops, incident, sre, postmortem | `node tools/incidentlog.js incidents.log --json` |
| [`k8scheck`](tools/k8scheck.js) | Audit Kubernetes YAML manifests for privileged containers, root users, latest tags, missing probes/limits and hostPath mounts | devops, kubernetes, audit | `node tools/k8scheck.js deploy.yaml --json` |
| [`kvmreport`](tools/kvmreport.js) | Parse libvirt domain XML: vCPU/memory allocation, disk and network devices, host-passthrough CPU and autostart flags | devops, kvm, libvirt, virtualization | `node tools/kvmreport.js domain.xml --json` |
| [`lbcheck`](tools/lbcheck.js) | Probe upstream backends over HTTP(S), report status/serving state, pairwise response consistency and retry-aware flapping detection | devops, loadbalancer, healthcheck | `node tools/lbcheck.js upstreams.txt --path /healthz --json` |
| [`logparse`](tools/logparse.js) | Parse nginx/apache access logs: top IPs, paths, status mix, scanners, and attack signatures | devops, logs, forensics | `node tools/logparse.js access.log --top 20 --json` |
| [`mailauth`](tools/mailauth.js) | Check SPF (all-qualifier, lookup count), DMARC (policy, rua, pct), DKIM selector presence, MTA-STS, TLS-RPT and BIMI, with a spoofability verdict | devops, email, dns, security | `node tools/mailauth.js example.com --dkim-selectors google,s1,mail --json` |
| [`makefile`](tools/makefile.js) | Parse a Makefile: list targets with doc comments, show variables, and flag .PHONY gaps plus dangerous targets | devops, make, build | `node tools/makefile.js Makefile --json` |
| [`nfsmount`](tools/nfsmount.js) | Parse /etc/exports and mount options, flag insecure settings (no_root_squash, insecure, no_subtree_check, wildcard hosts) and recommend safe defaults | devops, nfs, storage, audit | `node tools/nfsmount.js /etc/exports /proc/mounts --json` |
| [`nginxgen`](tools/nginxgen.js) | Generate production nginx server blocks: static, reverse proxy, websocket, PHP-FPM, redirect, TLS | devops, nginx, generator | `node tools/nginxgen.js proxy --domain api.example.com --upstream 127.0.0.1:3000 --out api.conf` |
| [`pathaudit`](tools/pathaudit.js) | Analyse PATH (or an explicit list) for world-writable directories, relative entries, duplicate binaries and shadowed system commands | devops, security, path, audit | `node tools/pathaudit.js --json` |
| [`pkgdiff`](tools/pkgdiff.js) | Diff dependencies between two package.json/composer.json/lockfiles: added, removed, bumped, risky majors | devops, dependencies, ci | `node tools/pkgdiff.js old/package.json new/package.json --json` |
| [`playbookaudit`](tools/playbookaudit.js) | Heuristic Ansible playbook audit: shell/command usage, become risks, plaintext vars, missing changed_when and ignore_errors | devops, ansible, audit | `node tools/playbookaudit.js site.yml --json` |
| [`portforward`](tools/portforward.js) | Build ssh -L/-R/-D tunnel commands plus jump-host chains from a declarative JSON spec, with ready-to-paste config blocks | devops, ssh, tunneling | `node tools/portforward.js tunnels.json --json` |
| [`portmap`](tools/portmap.js) | Map listening sockets to owning processes and flag unexpected public binds | devops, network, diagnostics | `node tools/portmap.js --json` |
| [`runbookgen`](tools/runbookgen.js) | Turn a service manifest (deps, healthcheck, contacts, escalation) into a markdown runbook with diagnosis, rollback and escalation steps | devops, runbook, oncall, docs | `node tools/runbookgen.js service.json --out RUNBOOK.md --json` |
| [`smarthealth`](tools/smarthealth.js) | Parse smartctl -a output: reallocated/pending sectors, wear levelling, temperature, power-on hours and a failure-risk heuristic | devops, disk, smart, health | `node tools/smarthealth.js smartctl-all.txt --json` |
| [`sshconfig`](tools/sshconfig.js) | Map jump-host topology and audit ssh_config security/keepalive options, reporting which Host entries are unreachable or unsafe | devops, ssh, audit | `node tools/sshconfig.js ~/.ssh/config --json` |
| [`sslrenew`](tools/sslrenew.js) | Check certificates for renewal, list the exact renewal commands, and land SNI hostname grouping | devops, tls, monitoring | `node tools/sslrenew.js hosts.txt --days 21 --json` |
| [`syssnap`](tools/syssnap.js) | Collect CPU, memory, disk, load, uptime, top processes into one snapshot with a health verdict | devops, monitoring, diagnostics | `node tools/syssnap.js --interval 1000 --json` |
| [`systemdunit`](tools/systemdunit.js) | Analyse .service units: sandboxing directives present/missing, restart policy, resource limits and capability scope | devops, systemd, hardening | `node tools/systemdunit.js /etc/systemd/system/app.service --json` |
| [`terraformaudit`](tools/terraformaudit.js) | Scan .tf files for public S3 ACLs, 0.0.0.0/0 ingress, unencrypted volumes, wildcard IAM and hardcoded secrets | devops, terraform, audit | `node tools/terraformaudit.js ./infra --json` |
| [`tlsgrade`](tools/tlsgrade.js) | Grade a TLS endpoint A+ to F: protocol versions, cipher strength, forward secrecy, certificate chain, OCSP stapling, HSTS and key size | devops, tls, security, audit | `node tools/tlsgrade.js example.com:443 --json` |
| [`uptimecalc`](tools/uptimecalc.js) | Compute availability, error budget, remaining budget and burn rate from a list of incident durations and an SLO target | devops, sre, slo, oncall | `node tools/uptimecalc.js incidents.csv --slo 99.9 --window 30d --json` |
| [`wpconfig`](tools/wpconfig.js) | Audit wp-config.php + .htaccess: salts, debug flags, file edit, DB prefix, table_prefix, exposed backups | devops, wordpress, hardening | `node tools/wpconfig.js ./public_html --json` |

<!-- CATALOGUE:END -->

## Adding a tool

1. Drop `tools/<name>.js` with the header block.
2. `import { args, get, num, flag, die, inputLines, table } from '../_lib.js';`
3. Help first, then parse, then work, then print.
4. `node smoke.js && node index-tools.js`.

## License

MIT — Copyright (c) 2026 0xnothings
