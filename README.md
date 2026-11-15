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

**18 tools**

| Tool | Description | Tags | Usage |
|---|---|---|---|
| [`backup`](tools/backup.js) | Create a tar.gz backup with a JSON manifest (hashes, sizes), verify archives, and prune by retention | devops, backup, archive | `node tools/backup.js ./public_html --out ./backups --keep 7 --json` |
| [`certgen`](tools/certgen.js) | Generate RSA/EC keys, CSRs and self-signed certificates via openssl, plus base64 one-liners for CSR submission | devops, tls, certificates | `node tools/certgen.js --cn example.com --san example.com,www.example.com --days 825 --out ./certs` |
| [`cronlab`](tools/cronlab.js) | Explain/validate cron expressions in English, compute next run times, and convert between formats | devops, cron, scheduler | `node tools/cronlab.js "*/15 9-17 * * 1-5" --next 5 --json` |
| [`deploycheck`](tools/deploycheck.js) | Run pre-deploy checks: env parity, secrets in repo, untracked files, build artifacts, git cleanliness | devops, ci, deploy | `node tools/deploycheck.js ./myapp --json` |
| [`dockerclean`](tools/dockerclean.js) | Report dangling images, stopped containers, orphan volumes and build cache; emit a safe/aggressive cleanup plan | devops, docker, cleanup | `node tools/dockerclean.js --mode plan --json` |
| [`dotenvgen`](tools/dotenvgen.js) | Produce .env/.env.example/.env.docker from a single schema file with secret generation and validation | devops, config, generator | `node tools/dotenvgen.js schema.json --out .env --gen-secrets` |
| [`envcheck`](tools/envcheck.js) | Diff a .env against .env.example: find missing, extra, empty and duplicate keys (CI gate) | devops, config, ci | `node tools/envcheck.js .env --template .env.example --json` |
| [`firewalldiff`](tools/firewalldiff.js) | Dump iptables/nftables/ufw rules, flag dangerous accepts, and diff against a saved baseline | devops, firewall, hardening | `node tools/firewalldiff.js --save baseline.json  |  node tools/firewalldiff.js --diff baseline.json` |
| [`gitstats`](tools/gitstats.js) | Repo stats: commits per author, churn per file, busiest hours, stale branches, TODO debt count | devops, git, metrics | `node tools/gitstats.js . --months 12 --json` |
| [`gru`](tools/gru.js) | Audit /etc/passwd and /etc/group: UID 0 accounts, empty passwords, sudo membership, shell inventory, staleness | devops, linux, hardening | `node tools/gru.js /etc/passwd /etc/group --shadow /etc/shadow --json` |
| [`healthcheck`](tools/healthcheck.js) | Poll a URL until it returns expected status/body, with interval, retries and total-time budget | devops, monitoring, ci | `node tools/healthcheck.js http://localhost:3000/healthz --expect 200 --retries 30 --json` |
| [`logparse`](tools/logparse.js) | Parse nginx/apache access logs: top IPs, paths, status mix, scanners, and attack signatures | devops, logs, forensics | `node tools/logparse.js access.log --top 20 --json` |
| [`nginxgen`](tools/nginxgen.js) | Generate production nginx server blocks: static, reverse proxy, websocket, PHP-FPM, redirect, TLS | devops, nginx, generator | `node tools/nginxgen.js proxy --domain api.example.com --upstream 127.0.0.1:3000 --out api.conf` |
| [`pkgdiff`](tools/pkgdiff.js) | Diff dependencies between two package.json/composer.json/lockfiles: added, removed, bumped, risky majors | devops, dependencies, ci | `node tools/pkgdiff.js old/package.json new/package.json --json` |
| [`portmap`](tools/portmap.js) | Map listening sockets to owning processes and flag unexpected public binds | devops, network, diagnostics | `node tools/portmap.js --json` |
| [`sslrenew`](tools/sslrenew.js) | Check certificates for renewal, list the exact renewal commands, and land SNI hostname grouping | devops, tls, monitoring | `node tools/sslrenew.js hosts.txt --days 21 --json` |
| [`syssnap`](tools/syssnap.js) | Collect CPU, memory, disk, load, uptime, top processes into one snapshot with a health verdict | devops, monitoring, diagnostics | `node tools/syssnap.js --interval 1000 --json` |
| [`wpconfig`](tools/wpconfig.js) | Audit wp-config.php + .htaccess: salts, debug flags, file edit, DB prefix, table_prefix, exposed backups | devops, wordpress, hardening | `node tools/wpconfig.js ./public_html --json` |

<!-- CATALOGUE:END -->

## Adding a tool

1. Drop `tools/<name>.js` with the header block.
2. `import { args, get, num, flag, die, inputLines, table } from '../_lib.js';`
3. Help first, then parse, then work, then print.
4. `node smoke.js && node index-tools.js`.

## License

MIT — Copyright (c) 2026 0xnothings
