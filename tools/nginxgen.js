#!/usr/bin/env node
// nginxgen.js — nginx vhost/block generator.
// Copyright (c) 2026 0xnothings
// @tool nginxgen
// @desc Generate production nginx server blocks: static, reverse proxy, websocket, PHP-FPM, redirect, TLS
// @usage node tools/nginxgen.js proxy --domain api.example.com --upstream 127.0.0.1:3000 --out api.conf
// @tags devops,nginx,generator
import { writeFileSync } from 'node:fs';
import { args, get, num, flag, die } from '../_lib.js';

const o = args(process.argv.slice(2));
if (o.f.help) {
  console.log(`nginxgen — nginx server block generator

  node tools/nginxgen.js <static|proxy|spa|php|redirect|websocket> [options]

  --domain <d>        server_name (required)
  --aliases <list>    extra server_name values
  --root <path>       document root for static/spa/php
  --upstream <host:port>  backend for proxy/websocket
  --socket <path>     php-fpm socket (default: unix:/run/php/php8.2-fpm.sock)
  --to <url>          redirect target for the redirect type
  --cert <path>       TLS certificate (default: /etc/letsencrypt/live/<domain>/fullchain.pem)
  --key <path>        TLS key
  --client-max <mb>   client_max_body_size (default: 32)
  --rate <r/s>        limit_req rate (default: 20r/s, burst 40)
  --no-tls            skip the 443 block
  --no-www            don't emit a www redirect block
  --security          add security headers block
  --out <file>        write to a file (default: stdout)
  -h, --help          this text`);
  process.exit(0);
}

const type = o._[0] || 'proxy';
const domain = o.f.domain ? String(get(o, 'domain')) : die('--domain is required');
const root = String(get(o, 'root', `/var/www/${domain}`));
const upstream = String(get(o, 'upstream', '127.0.0.1:3000'));
const socket = String(get(o, 'socket', 'unix:/run/php/php8.2-fpm.sock'));
const to = String(get(o, 'to', `https://${domain}`));
const cert = String(get(o, 'cert', `/etc/letsencrypt/live/${domain}/fullchain.pem`));
const key = String(get(o, 'key', `/etc/letsencrypt/live/${domain}/privkey.pem`));
const clientMax = num(get(o, 'client-max'), 32);
const rate = String(get(o, 'rate', '20r/s'));
const aliases = String(get(o, 'aliases', '')).split(',').map((s) => s.trim()).filter(Boolean);
const names = [domain, ...aliases].join(' ');

const security = `    # security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
`;

const limits = `    client_max_body_size ${clientMax}m;
    limit_req zone=${domain.replace(/\./g, '_')}_zone burst=40 nodelay;
    limit_conn addr 32;
`;

const proxyCommon = `        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
        proxy_read_timeout 90s;
        proxy_buffering off;`;

const blocks = {
  static: `    root ${root};
    index index.html;
    location / { try_files $uri $uri/ =404; }
    location ~* \\.(?:css|js|jpg|jpeg|png|gif|svg|webp|avif|woff2?|ttf|ico)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
        access_log off;
    }
    location ~ /\\.(?!well-known) { deny all; }`,
  spa: `    root ${root};
    index index.html;
    location / { try_files $uri $uri/ /index.html; }
    location ~* \\.(?:css|js|jpg|jpeg|png|gif|svg|webp|woff2?)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
    location = /index.html { add_header Cache-Control "no-store"; }`,
  proxy: `    location / {
${proxyCommon}
        proxy_pass http://${upstream};
    }
    location = /healthz { proxy_pass http://${upstream}/healthz; access_log off; }`,
  websocket: `    location / {
${proxyCommon}
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
        proxy_pass http://${upstream};
    }`,
  php: `    root ${root};
    index index.php index.html;
    location / { try_files $uri $uri/ /index.php?$query_string; }
    location ~ \\.php$ {
        include fastcgi_params;
        fastcgi_pass $socket;  →  __PHPSOCK__
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_read_timeout 120s;
    }
    location ~* \\.(?:css|js|jpg|jpeg|png|gif|svg|woff2?)$ { expires 30d; access_log off; }
    location ~ /\\.(?!well-known) { deny all; }
    location = /wp-config.php { deny all; }`,
  redirect: `    return 301 ${to}$request_uri;`,
};
if (type === 'php') blocks.php = blocks.php.replace('$socket;  →  __PHPSOCK__', socket + ';');
if (!blocks[type]) die(`unknown type "${type}" — use: ${Object.keys(blocks).join(', ')}`);

const listen = (ssl) => (ssl ? `    listen 443 ssl http2;\n    listen [::]:443 ssl http2;\n    ssl_certificate ${cert};\n    ssl_certificate_key ${key};\n    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_prefer_server_ciphers off;\n    ssl_session_cache shared:SSL:10m;\n    ssl_session_timeout 1d;\n    ssl_stapling on;\n    ssl_stapling_verify on;` : '    listen 80;\n    listen [::]:80;');

const header = (ssl, names_) => `server {\n${listen(ssl)}\n    server_name ${names_};\n\n    access_log /var/log/nginx/${domain}.access.log;\n    error_log  /var/log/nginx/${domain}.error.log warn;\n\n${limits}${flag(o, 'security') ? '\n' + security : ''}\n${blocks[type]}\n}\n`;

const parts = [];
if (!flag(o, 'no-tls')) {
  parts.push(`# rate limit zone — put this in the http{} block of /etc/nginx/nginx.conf\n# limit_req_zone $binary_remote_addr zone=${domain.replace(/\./g, '_')}_zone:10m rate=${rate};\n`);
  if (!flag(o, 'no-www')) parts.push(`server {\n    listen 80;\n    server_name www.${domain};\n    return 301 https://${domain}$request_uri;\n}\n`);
  parts.push(header(false, names));
  parts.push(header(true, names));
} else parts.push(header(false, names));

const out = parts.join('\n');
if (o.f.out) { writeFileSync(String(get(o, 'out')), out, 'utf8'); console.log(`wrote ${get(o, 'out')}\n  sudo cp ${get(o, 'out')} /etc/nginx/sites-available/${domain}.conf\n  sudo ln -sf /etc/nginx/sites-available/${domain}.conf /etc/nginx/sites-enabled/\n  sudo nginx -t && sudo systemctl reload nginx`); }
else process.stdout.write(out);
