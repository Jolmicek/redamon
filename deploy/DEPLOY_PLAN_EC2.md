# RedAmon — Cloud Deploy Plan (`deploy.sh`)

> **Goal.** Design a single, cloud-agnostic `deploy.sh` that provisions and operates a RedAmon
> instance on a remote Linux server (EC2 or any VPS) given only its **IP** and an **SSH credential**
> (`.pem` key or password). Two primary verbs: **`init`** (wipe the host clean and build from zero)
> and **`update`** (pull the latest `master` HEAD and apply it). The public attack surface is reduced
> to **exactly one thing: the webapp UI over HTTPS**. Everything else — agent API, MCP servers,
> databases, orchestrator, reverse-shell catcher — is bound to loopback and either hidden entirely or
> reverse-proxied and hardened by nginx.
>
> This document is the blueprint. It specifies the requirements, the architecture, every step the
> script must perform, the exact nginx/compose/firewall config, and the open decisions. Build
> `deploy.sh` from it.

---

## 0. TL;DR design decisions

1. **`deploy.sh` is a thin *remote driver*, not a reimplementation.** RedAmon already ships
   `redamon.sh`, a 1900-line control script that generates secrets, sizes memory to the host, builds
   every image in the right order, brings the stack up, runs `prisma db push`, and bootstraps the
   admin user. The deploy script's job is: **prepare a bare host → get the repo onto it → drive
   `redamon.sh` over SSH → wrap the whole thing in an internet-facing security layer (nginx + TLS +
   firewall + host hardening) that `redamon.sh` deliberately does *not* provide** (RedAmon is designed
   local-only). Do not duplicate secret generation, image build ordering, or resource sizing — call
   `redamon.sh`.

2. **Single public origin.** Only `443/tcp` (HTTPS → webapp) is exposed to the world (+ `80` for the
   ACME challenge and the HTTP→HTTPS redirect, + `22` locked to the operator IP). nginx terminates TLS
   and reverse-proxies the webapp **and** the agent WebSocket paths under the *same* origin, so the
   browser never needs to reach `:8090` directly. The agent, DBs, MCP servers and orchestrator ports
   are never published off-loopback.

3. **Cloud-agnostic.** No AWS SDK, no provider APIs. Input is `IP + SSH auth + domain`. Host firewall
   (`ufw`) is the portable control; a short appendix maps it to an EC2 Security Group for operators
   who prefer that.

4. **Reuse the example's proven mechanics** (`deploy/example/deploy.sh`): the arg parser, the
   pem-or-password `$SSH`/`$SCP` abstraction with SSH ControlMaster multiplexing, the `run_sudo` /
   `install_if_missing` helpers, the `ACTIVATE_X → setup_X/disable_X` flag-gated module pattern, the
   nginx-config-as-sourced-function dispatcher, and the fail2ban / file-hardening / SSL modules.
   Drop everything Django/Gunicorn/Celery/systemd-venv — RedAmon's runtime is docker-compose.

---

## 1. Minimum & recommended server requirements

RedAmon is heavy: a Kali metapackage image, a polyglot agent image with optional ML embedding models,
an optional GVM/OpenVAS feed stack, and on-demand scan + local-LLM containers. `redamon.sh` enforces a
**hard RAM gate of 8 GB** of Docker-visible memory at `up` time (`preflight_ram_gate`, baseline 6 GB +
2 GB headroom); below that it aborts unless `REDAMON_SKIP_RAM_GATE=1`.

| Profile | vCPU | RAM | Disk (gp3/SSD) | Example instance | Notes |
|---|---|---|---|---|---|
| **Bare minimum** (core only, `SKIP_KB`, no GVM) | 2 | **8 GB** | 50 GB | `t3.large` | Passes the gate; webapp + kali builds are slow/swappy. Add 8 GB swap. |
| **Recommended** (core + KB + occasional scans) | 4 | **16 GB** | 60–80 GB | `m5.xlarge` | The sane default for a real instance. |
| **Full** (GVM/OpenVAS + AI-attack-surface + Ollama judge + parallel scans) | 8 | **32 GB** | 100–120 GB | `m5.2xlarge` / `r5.xlarge` | Ollama `qwen2.5:7b` alone needs ~5–6 GB while scanning. |

**Why the disk numbers:** the two dominant images are **kali-sandbox (~12–15 GB)** and the
**agent-with-KB (~7–10 GB;** `~4.5 GB` with `SKIP_KB=true`). All built + pulled images: **~18–22 GB**
minimal, **~40–50 GB** full. Add GVM feeds (~4–6 GB), the Ollama model volume (~5 GB), Neo4j/Postgres
data (grows with engagements), and Docker build cache (5–15 GB). Budget **60 GB minimum, 100 GB for
the full profile.**

**OS:** Ubuntu 22.04 or 24.04 LTS (x86-64). ARM64 works but the `ai-attack-surface` image needs a Rust
toolchain build for `pyrit` (slower); prefer x86-64.

**Host prerequisites the deploy must install/verify** (a fresh box has none of these):
- **Docker Engine + Docker Compose v2 plugin** (`docker compose`, *not* legacy `docker-compose`). The
  only hard runtime dependency. Install from Docker's official apt repo (not `docker.io`, which ships
  an old engine + the v1 compose the example used — RedAmon requires `docker compose version` ≥ v2).
- **git**, **openssl**, **curl**, **jq**, **ca-certificates**. (git-lfs **not** needed — `.gitattributes`
  only sets `eol=lf`, no LFS objects.)
- **nginx**, **certbot** (+ `python3-certbot-nginx`) for TLS, **ufw**, **fail2ban**, **sshpass** is
  needed *on the local machine only* when using password auth.
- **Swap** (8 GB swapfile) on hosts < 16 GB; optionally RedAmon's `REDAMON_ENABLE_ZRAM=1`.
- **No kernel/sysctl tuning is required** by RedAmon. Neo4j 5 Community at heap 2g/pagecache 1g runs
  fine at the default `vm.max_map_count`. Optionally raise `fs.inotify.max_user_*` on small hosts
  (15+ containers). Add `{"dns":["8.8.8.8","8.8.4.4"]}` to `/etc/docker/daemon.json` if container DNS
  misbehaves on Ubuntu (documented in `readmes/TROUBLESHOOTING.md`).

---

## 2. What actually gets deployed (architecture recap)

**Always-on core (7 containers, `redamon.sh` `CORE_SERVICES`):** `postgres`, `neo4j`,
`docker-broker`, `recon-orchestrator`, `kali-sandbox`, `agent`, `webapp`.

**Build-only images (`--profile tools`, spawned on demand by the orchestrator):** `recon`,
`vuln-scanner`, `github-hunter`, `trufflehog`, `wcvs`, `codefix-sandbox`, `baddns`,
`ai-attack-surface`. Built at install; not long-running.

**Opt-in stacks:** GVM/OpenVAS (`--gvm`, ~8 feed images + gvmd/ospd/redis/pg, 10–20 min first feed
sync), KB embeddings (baked into the agent image unless `SKIP_KB=true`), `kb-refresh` sidecar
(`--profile kb-refresh`), on-demand Ollama judge (per AI-attack-surface scan).

**Networks:** `redamon-network` (app/db bridge), `redamon-orchestrator-net` (isolated privileged
orchestrator, 172.29/16), `pentest-net` (172.28/16), `redamon-codefix-net` (on-demand). None of these
are exposed; they are internal Docker bridges.

**Volumes:** `postgres_data`, `neo4j_data`, `report_data`, KB/tradecraft caches, the ~13 GVM feed
volumes, `redamon_llm_models`, `cypherfix-*`, `redamon_broker_socket`. These hold all engagement data
and **must survive `update`** and be excluded from any `git clean`.

**Port exposure model (from `docker-compose.yml`) — the crux of the hardening:**

| Port | Current bind | Deploy must |
|---|---|---|
| webapp `3000` | `0.0.0.0` (`${WEBAPP_PORT:-3000}:3000`) | **Re-bind `127.0.0.1:3000`**; nginx 443 proxies it |
| agent `8090` | `0.0.0.0` (`${AGENT_PORT:-8090}:8080`) | **Re-bind `127.0.0.1:8090`**; nginx proxies only `/ws/*` under 443 |
| reverse-shell `4444` | `0.0.0.0` (hardcoded) | Firewall to engagement target IPs only (see §11) |
| postgres 5432, neo4j 7474/7687, orchestrator 8010, MCP 8000-8016, ngrok 4040 | `127.0.0.1` already ✓ | Leave loopback; **never** expose. Firewall as belt-and-braces. |

Only `3000`, `8090`, `4444` bind `0.0.0.0` today. The datastore/MCP/orchestrator loopback binds were
fixed in the 2026-07-05 STRIDE wave — **do not regress them.**

---

## 3. The security posture change (why this is not a normal deploy)

RedAmon's own threat model (`internal/security/README.TM.SYSTEM_OVERVIEW.md`) states it is **local-only,
not intended for the public internet**, and every "medium likelihood" rating in the STRIDE doc
silently assumes *no anonymous internet attacker*. Putting it on a public IP invalidates that premise.
The deploy layer is what closes the gap. Non-negotiable facts the design is built around:

- **The agent REST API (`:8090`) has unauthenticated endpoints that take identity from the request
  body:** `POST /graph/exec` (reads any tenant's graph), `POST /emergency-stop-all` (kills all tasks),
  `POST /agent-session/stop`, and `WS /ws/kali-terminal` **proxies a root PTY (`bash --login`) with no
  agent-side ticket check** — i.e. a direct anonymous root shell in the Kali sandbox. **The agent REST
  surface must never be internet-reachable.** Only its four WebSocket paths may be proxied, and only
  behind the operator allowlist.
- **There is no login rate-limit or account lockout in the app.** nginx must supply it.
- **The auth cookie is set `secure: false`** (`webapp/src/app/api/auth/login/route.ts:48`). Works over
  HTTPS but is not marked Secure. Recommend a one-line production patch (see §8.6) + HSTS as the
  interim control.
- **`changeme`/empty secrets fail *open*** (JWT verify off, WS ticket unverified, MCP/tunnel bearer
  skipped). On a public host every secret MUST be strong-random and verified before boot (§8.5).
- **GVM ships `admin/admin`** (S13 residual) — rotate it out of band if GVM is enabled.

---

## 4. `deploy.sh` — interface & configuration

### 4.1 CLI (adapted from the example's positional parser)

```
Usage: ./deploy.sh <HOST_IP> <AUTH> <REMOTE_USER> <MODE> [ENV_NAME]

  HOST_IP    Public IP or DNS of the target server
  AUTH       path/to/key.pem  |  pass  |  pass:<password>
  REMOTE_USER  ssh user (ubuntu, admin, root-capable sudoer)
  MODE       init | update | status | harden | ssl-renew | down | logs
  ENV_NAME   optional config selector -> deploy/.env.<ENV_NAME> (default: deploy/.env)
```

- **AUTH detection** (verbatim-reusable from example lines 113–128): if the arg is a file → key auth
  (`-i $PEM`); `pass` → prompt with `read -rs`; `pass:<pw>` → inline; else treat as literal password.
  Password auth uses `sshpass -e` (password via `$SSHPASS` env, never argv).
- **MODE regex-validated**; unknown modes print usage and exit 1.

### 4.2 `deploy/.env` (the deploy-time config, **local to the operator, never committed**)

This is separate from the *application* `.env` that `redamon.sh` generates on the server. It holds
deploy inputs:

```bash
# --- Repo ---
REPO_URL=https://github.com/<org>/redamon.git      # or git@... with a deploy key
REPO_BRANCH=master
APP_DIR=redamon                                     # stable dir name -> stable COMPOSE_PROJECT_NAME

# --- Public identity / TLS ---
DOMAIN=redamon.example.com                          # required for TLS + WS origin
TLS_MODE=letsencrypt                                # letsencrypt | provided | self-signed
LETSENCRYPT_EMAIL=ops@example.com                   # for certbot (letsencrypt mode)
SSL_CERT_LOCAL=cert/fullchain.pem                   # provided mode only
SSL_KEY_LOCAL=cert/privkey.pem
SSL_KEY_PASSWORD=                                    # optional, if key is encrypted

# --- Access control (defense-in-depth) ---
OPERATOR_ALLOW_CIDRS=203.0.113.10/32                # comma list: nginx allow + ufw ssh/443 source
GATE_MODE=ip_allowlist                              # ip_allowlist | basic_auth | none
BASIC_AUTH_USER=                                     # basic_auth mode
BASIC_AUTH_PASS=

# --- Feature flags (map to redamon.sh install flags) ---
ENABLE_GVM=false                                     # --gvm  (heavy; 10-20min feed sync)
ENABLE_KB=false                                      # --kbase (bakes ML models; +4.4GB)
SKIP_KB=true                                          # smaller/faster agent build
ENABLE_ZRAM=true

# --- Engagement / offensive knobs ---
REVSHELL_TARGET_CIDRS=                                # ufw-allow 4444 from these only; empty = 4444 closed
TUNNELS_ENABLED=false

# --- Non-interactive admin bootstrap ---
ADMIN_NAME=
ADMIN_EMAIL=
ADMIN_PASSWORD=                                       # strong; used to pre-create admin headlessly

# --- Optional app config appended to the server .env (LLM keys are set in the UI, not here) ---
NVD_API_KEY=
KB_EMBEDDING_USE_API=
KB_EMBEDDING_API_BASE_URL=
KB_EMBEDDING_API_KEY=
```

### 4.3 Directory layout to build

```
deploy/
├── deploy.sh                         # the orchestrator (this plan)
├── DEPLOY_PLAN_EC2.md                # this file
├── .env(.example)                    # deploy-time config (4.2); .env is gitignored
├── cert/                             # provided-cert mode drop point (gitignored)
├── compose/
│   └── docker-compose.prod.yml       # override: loopback binds, 4444, build args, CORS (§5)
├── nginx/
│   ├── redamon.conf.tmpl             # single-443-origin template (§6)
│   └── snippets/ (ssl, security-headers, ws)
├── patches/
│   └── cypherfix-ws-origin.patch     # make the 2 hardcoded :8090 hooks honor the WS origin (§6.3)
└── modules/                          # sourced remotely, flag-gated setup_X/disable_X
    ├── _common.sh                    # run_sudo, install_if_missing, log/err helpers
    ├── host_bootstrap.sh             # docker engine+compose v2, base pkgs, swap
    ├── firewall.sh                   # ufw rules
    ├── ssh_hardening.sh              # PasswordAuth no, PermitRootLogin no
    ├── fail2ban.sh                   # sshd + nginx jails (repoint from example)
    ├── unattended_upgrades.sh
    ├── nginx.sh                      # render + install + nginx -t gate
    ├── tls.sh                        # certbot OR provided-cert install (md5 idempotent)
    └── secrets_gate.sh               # verify no changeme/default/short secrets
```

### 4.4 SSH/SCP abstraction (lift from example §2, verbatim)

Build `$SSH` / `$SCP` string vars with ControlMaster multiplexing so the dozens of remote calls reuse
one authenticated connection; `trap cleanup_ssh EXIT` closes the master socket.

```bash
SSH_CONTROL_PATH="/tmp/ssh-redamon-${HOST_IP}-$$"
SSH_COMMON_OPTS="-o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30 \
  -o ServerAliveCountMax=5 -o ControlMaster=auto -o ControlPath=${SSH_CONTROL_PATH} -o ControlPersist=60"
# key:  SSH="ssh $SSH_COMMON_OPTS -i $PEM $USER@$IP" ;  SCP="scp -q $SSH_COMMON_OPTS -i $PEM"
# pass: export SSHPASS=... ; SSH="sshpass -e ssh -o PubkeyAuthentication=no $SSH_COMMON_OPTS $USER@$IP"
```

Remote work is delivered as: `$SCP -r deploy/modules $USER@$IP:/tmp/redamon-deploy/` then
`$SSH VAR=val ... bash -s <<'EOF'` heredocs that `source` the modules and re-declare each `VAR="${VAR}"`
against the ssh-injected env (example §3 pattern). All privileged calls go through `run_sudo` (works
under both key and password sudo). Use `sg docker -c "docker compose ..."` right after adding the user
to the `docker` group so the membership applies without re-login.

---

## 5. Compose override — `deploy/compose/docker-compose.prod.yml`

Layered on with `docker compose -f docker-compose.yml -f deploy/compose/docker-compose.prod.yml ...`.
The deploy makes `redamon.sh` pick it up by exporting the standard compose env before calling it:
`export COMPOSE_FILE=docker-compose.yml:deploy/compose/docker-compose.prod.yml` (compose honors this
natively, so every `redamon.sh` compose invocation gets the overlay without editing `redamon.sh`).

```yaml
services:
  webapp:
    ports: !override ["127.0.0.1:3000:3000"]      # off 0.0.0.0
    build:
      args:
        # Same-origin WS so the browser never targets :8090. Baked at build time
        # (NEXT_PUBLIC_* is inlined by Next.js). Requires the cypherfix patch (§6.3)
        # AND a webapp/Dockerfile ARG addition (see note below).
        NEXT_PUBLIC_AGENT_WS_URL: "wss://${DOMAIN}/ws/agent"
        REDAMON_VERSION: "${REDAMON_VERSION:-0.0.0}"
    environment:
      NODE_ENV: production                          # enables the secure-cookie patch (§8.6)

  agent:
    ports: !override ["127.0.0.1:8090:8080"]      # off 0.0.0.0
    environment:
      AGENT_CORS_ORIGINS: "https://${DOMAIN}"     # never '*'

  kali-sandbox:
    # Re-list ALL kali publishes as loopback; the base file hardcodes 4444 on 0.0.0.0,
    # so we must override the whole ports list to close it.
    ports: !override
      - "127.0.0.1:8000:8000"
      - "127.0.0.1:8002:8002"
      - "127.0.0.1:8003:8003"
      - "127.0.0.1:8004:8004"
      - "127.0.0.1:8005:8005"
      - "127.0.0.1:8013:8013"
      - "127.0.0.1:8014:8014"
      - "127.0.0.1:4444:4444"                      # loopback by default; open via ufw per engagement (§11)
      - "127.0.0.1:4040:4040"
      - "127.0.0.1:8015:8015"
      - "127.0.0.1:8016:8016"
```

> **Required `webapp/Dockerfile` change:** it currently bakes only `NEXT_PUBLIC_REDAMON_VERSION`. Add
> `ARG NEXT_PUBLIC_AGENT_WS_URL` + `ENV NEXT_PUBLIC_AGENT_WS_URL=$NEXT_PUBLIC_AGENT_WS_URL` **before
> `RUN npm run build`**, or the build arg is silently ignored (Next.js inlines `NEXT_PUBLIC_*` at build
> time). Ship this as part of the deploy branch (§7.2 / §15).

> **`4444` policy:** closed by default (loopback). Opened per engagement via ufw to
> `REVSHELL_TARGET_CIDRS` only — never `0.0.0.0`. See §11.

---

## 6. nginx — single public origin (443)

**Design:** one TLS server on `443` for `${DOMAIN}`. It proxies the webapp (`127.0.0.1:3000`) for `/`
and `/api/*`, and the agent (`127.0.0.1:8090`) for the WebSocket paths under the **same origin**, so
port `8090` is **never published** off-loopback. A separate `80` server does the ACME challenge +
HTTP→HTTPS redirect. This satisfies the hard requirement: *from the public internet only the webapp UI
(443) is reachable; every other port/endpoint is closed or funneled + hardened by nginx.*

### 6.1 Routing map

| Public path (443) | Upstream | Notes |
|---|---|---|
| `/ws/agent`, `/ws/kali-terminal`, `/ws/cypherfix-triage`, `/ws/cypherfix-codefix` | `127.0.0.1:8090` (agent) | **Allowlisted exactly**; WS upgrade + 1h timeouts + `proxy_buffering off`. Everything else on the agent (`/graph/exec`, `/emergency-stop-all`, `/workspace/*`) is unreachable because it is never proxied. |
| `= /api/auth/login` | `127.0.0.1:3000` | `limit_req zone=login` (5r/m) — the app has no lockout. |
| `/api/` | `127.0.0.1:3000` | `limit_req zone=api`; `proxy_read_timeout 3600s` + `proxy_buffering off` for SSE report/agent streams. |
| `/` | `127.0.0.1:3000` | Next.js app; Upgrade headers for HMR/WS passthrough. |

### 6.2 Template (`redamon.conf.tmpl` — placeholders substituted by `sed`, example style)

```nginx
map $http_upgrade $connection_upgrade { default upgrade; '' close; }
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
limit_req_zone $binary_remote_addr zone=api:10m   rate=30r/s;
limit_conn_zone $binary_remote_addr zone=conn:10m;
server_tokens off;

# ---- 80: ACME + redirect ----
server {
    listen 80;
    server_name __DOMAIN__;
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 301 https://$host$request_uri; }
}

# ---- 443: the ONLY public app surface ----
server {
    listen 443 ssl http2;
    server_name __DOMAIN__;

    ssl_certificate     __SSL_CERT_REMOTE__;
    ssl_certificate_key __SSL_KEY_REMOTE__;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_stapling on; ssl_stapling_verify on;
    resolver 1.1.1.1 8.8.8.8 valid=300s; resolver_timeout 5s;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;
    add_header X-Robots-Tag "noindex, nofollow, noarchive, nosnippet" always;
    # CSP: ship Report-Only first, promote to Content-Security-Policy after verifying the
    # WebGL graph + xterm terminal render. A strict script-src WILL break them.
    add_header Content-Security-Policy-Report-Only "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' wss://__DOMAIN__; worker-src 'self' blob:; frame-ancestors 'none'" always;

    # DoS / slowloris protections
    limit_conn conn 20;
    client_body_timeout 15s; client_header_timeout 15s; send_timeout 15s; keepalive_timeout 20s;
    large_client_header_buffers 8 32k;
    client_max_body_size 60m;             # wordlist upload 50MB + RoE 20MB headroom
    autoindex off;

    # __GATE__  (rendered from GATE_MODE)
    #   ip_allowlist: allow <cidrs>; deny all;
    #   basic_auth:   auth_basic "RedAmon"; auth_basic_user_file /etc/nginx/.redamon_htpasswd;

    # Block hidden/sensitive files defensively
    location ~ /\. { deny all; return 404; }
    location ~ \.(env|pem|key|crt|sql|bak|old|swp)$ { deny all; return 404; }

    # ---- Agent WebSocket endpoints ONLY (nothing else on :8090 is proxied) ----
    location ~ ^/ws/(agent|kali-terminal|cypherfix-triage|cypherfix-codefix)$ {
        proxy_pass http://127.0.0.1:8090;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 3600s; proxy_send_timeout 3600s;
        proxy_buffering off;
    }

    location = /api/auth/login {
        limit_req zone=login burst=3 nodelay; limit_req_status 429;
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        add_header Cache-Control "no-store" always;
    }
    location /api/ {
        limit_req zone=api burst=60 nodelay; limit_req_status 429;
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 3600s; proxy_buffering off;   # SSE streams
    }
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

Install exactly like the example's `nginx.sh`: write to `/etc/nginx/sites-available/redamon`,
`rm -f /etc/nginx/sites-enabled/default`, symlink into `sites-enabled/`, **`nginx -t` gates the deploy
(hard `exit 1` on failure)**, then `systemctl reload nginx`.

### 6.3 Required code patch — cypherfix WS hooks

`useAgentWebSocket.ts` and `KaliTerminal.tsx` honor `NEXT_PUBLIC_AGENT_WS_URL`, so setting it to
`wss://${DOMAIN}/ws/agent` routes them same-origin. But `useCypherFixTriageWS.ts` and
`useCypherFixCodeFixWS.ts` **hardcode** `${wss}//${location.hostname}:8090/ws/...`. For a true
single-origin deployment (no public `:8090`), ship `patches/cypherfix-ws-origin.patch` that makes those
two hooks build their URL from `NEXT_PUBLIC_AGENT_WS_URL` (or `window.location.host`, dropping `:8090`)
exactly like the other two. Apply it after clone, before the webapp build.

> **Alternative if you refuse to patch app code:** expose a *second* TLS server block on a distinct
> public port `8090` that proxies `127.0.0.1:8090` and **allowlists only the four `/ws/*` paths,
> `return 403` for everything else**, plus open `8090/tcp` in ufw to the operator CIDR. This keeps the
> app code untouched but means "two public ports," which is weaker than the single-origin goal and
> contradicts the "only the webapp reachable" requirement. **The patch is the recommended path.**

---

## 7. `deploy.sh` command flows

### 7.1 `init` — wipe to zero and build fresh

> Destructive. This is the "erase everything from the host and start from zero" verb. Guard it behind a
> typed confirmation (`type INIT to wipe <IP>`), and refuse silently-destructive runs without it.

1. **Local preflight:** validate args, load `deploy/.env(.ENV_NAME)`, ensure `DOMAIN` + TLS inputs +
   `OPERATOR_ALLOW_CIDRS` present; if password auth, require local `sshpass`. Establish `$SSH` and
   fail-fast with `$SSH "echo ok"`.
2. **Ship deploy assets:** `$SCP -r deploy/modules deploy/compose deploy/nginx deploy/patches` (and
   `deploy/cert` in provided-TLS mode) to `/tmp/redamon-deploy/`.
3. **Host teardown (the "erase everything"):** over SSH, confirmation already taken locally —
   ```
   [ -x ~/<APP_DIR>/redamon.sh ] && (cd ~/<APP_DIR> && ./redamon.sh purge <<<"yes") || true  # graceful RedAmon teardown
   docker ps -aq | xargs -r docker rm -f
   docker system prune -af --volumes        # images, containers, networks, build cache, volumes
   docker network prune -f
   rm -rf ~/<APP_DIR>                        # nuke the checkout
   ```
   Warn loudly that this deletes ALL Docker state on the host, not just RedAmon.
4. **OS bootstrap** (`host_bootstrap.sh`): `install_if_missing` base pkgs; install Docker Engine +
   Compose v2 from Docker's apt repo; `usermod -aG docker $USER`; enable+start docker; create 8 GB
   swap if RAM < 16 GB; optional `/etc/docker/daemon.json` DNS.
5. **Host hardening** (`ssh_hardening.sh`, `firewall.sh`, `fail2ban.sh`, `unattended_upgrades.sh`):
   SSH key-only + no root login; ufw default-deny with the ruleset in §10; fail2ban sshd+nginx jails;
   unattended-upgrades. (nginx/TLS come after the app is up so the upstream exists.)
6. **Clone:** `git clone -b $REPO_BRANCH --depth 1 $REPO_URL ~/$APP_DIR`. Fixed `APP_DIR` → stable
   `COMPOSE_PROJECT_NAME` (critical for `redamon.sh`'s DB-volume detection).
7. **Apply prod overlay + patches:** copy `docker-compose.prod.yml` into place; apply
   `cypherfix-ws-origin.patch`; add the `NEXT_PUBLIC_AGENT_WS_URL` build arg to `webapp/Dockerfile`;
   apply the optional secure-cookie patch (§8.6). Export
   `COMPOSE_FILE=docker-compose.yml:deploy/compose/docker-compose.prod.yml`, `DOMAIN`, `REDAMON_VERSION`.
8. **Seed app `.env`:** append any operator app-config keys from `deploy/.env` (NVD/KB embedding, etc.)
   to `~/$APP_DIR/.env`. **Do not** set DB passwords (let `redamon.sh` generate). Pre-seed
   `TUNNELS_ENABLED`. `chmod 600 .env`.
9. **Drive `redamon.sh install`** over SSH (non-interactive): assemble flags from config —
   `./redamon.sh install $([ "$ENABLE_GVM" = true ] && echo --gvm) $([ "$ENABLE_KB" = true ] && echo --kbase)`;
   export `SKIP_KB`, `REDAMON_ENABLE_ZRAM`. This generates all secrets, builds every image (webapp
   isolated first, then capped parallelism), and `docker compose up -d`. **Budget 30–60 min** on first
   build; use a long SSH keepalive and stream logs.
10. **Secrets gate** (`secrets_gate.sh`): run the verifier from §8.5 against the generated `.env`; **fail
    the deploy** if any secret is unset/`changeme`/`redamon_secret`/`changeme123`/`admin`/too short.
11. **Non-interactive admin bootstrap** (§8.4): pre-create the admin with `create-admin.mjs` so
    `redamon.sh`'s interactive `ensure_admin` prompt is skipped.
12. **nginx + TLS** (`tls.sh`, `nginx.sh`): obtain the cert (certbot `--nginx` or install the provided
    cert with md5-idempotent replace), render `redamon.conf.tmpl` with `DOMAIN` + gate, `nginx -t`,
    reload.
13. **GVM note:** if `ENABLE_GVM=true`, print the "feeds sync 10–20 min before scans work" warning and
    rotate the `admin/admin` GVM password.
14. **Verify** (§12): loopback-bind assertions (`ss -tlnp`), HTTPS 200 on `/api/health` via the domain,
    WS handshake to `/ws/agent`, ufw status. Print the login URL + admin email.

### 7.2 `update` — pull latest HEAD and apply

Thin wrapper around **`redamon.sh update`**, which already does the smart part (git `pull --ff-only`,
diff `old..new`, rebuild only what changed, regenerate any newly-added secrets *before* recreate,
restart, preserve DB passwords via volume-exists detection).

1. Local preflight + `$SSH` as in init.
2. **Refresh deploy assets** on the host (modules/compose/nginx/patches) in case the deploy tooling
   changed.
3. **Pre-clean guard:** `redamon.sh update` requires a clean, fast-forwardable tree, so the app-code
   changes (webapp/Dockerfile build-arg, cypherfix patch, secure-cookie) must NOT sit as uncommitted
   working-tree edits or `git pull --ff-only` aborts. **Recommended: deploy from a dedicated branch
   that already contains those three changes**, so `update` is a clean fast-forward. (Fallback:
   `git stash` before update, re-apply after — brittle; avoid.)
4. **Run `./redamon.sh update`** over SSH with the same exported env (`COMPOSE_FILE`, `DOMAIN`,
   `SKIP_KB`, flags). It re-execs itself post-pull, rebuilds changed images, regenerates secrets,
   restarts.
5. **Re-run the secrets gate** (an update may introduce new secret keys).
6. **Re-render nginx** only if `deploy/nginx` changed; `nginx -t` + reload. TLS renewal is the separate
   `ssl-renew` verb / certbot timer.
7. **Admin bootstrap** is a no-op (admin exists) — `check-admin.mjs` returns non-zero and skips the
   prompt.
8. Verify + report.

### 7.3 Secondary verbs

- **`status`** — `redamon.sh status` + `docker compose ps` + `ufw status` + `nginx -t` + cert expiry.
- **`harden`** — re-apply only the host-hardening + nginx modules (idempotent), no rebuild.
- **`ssl-renew`** — certbot renew (or re-upload provided cert) + nginx reload.
- **`down`** — `redamon.sh down` (stops stack, keeps volumes/images). `deploy.sh` never auto-purges
  data outside `init`.
- **`logs`** — tail `docker compose logs -f` for a named service over SSH.

---

## 8. Secrets, admin, TLS specifics

### 8.1 Secret generation — **reuse, don't reinvent**
`redamon.sh ensure_auth_secrets` generates `AUTH_SECRET`, `INTERNAL_API_KEY`, `SCANNER_API_KEY`,
`ORCHESTRATOR_API_KEY`, `MCP_AUTH_TOKEN`, `AGENT_WS_TICKET_SECRET`, `TUNNEL_AUTH_TOKEN` (`openssl rand
-hex 32`, append-if-absent so never clobbered). `ensure_db_secrets` generates `POSTGRES_PASSWORD`/
`NEO4J_PASSWORD` (`openssl rand -hex 24`) **only when the data volume does not yet exist** — it warns
and refuses to rewrite once the DB is initialized (rewriting would lock out the running DB). The deploy
must **not** pre-set these; just ensure a stable `COMPOSE_PROJECT_NAME` so the volume-exists check is
correct.

### 8.4 Non-interactive admin bootstrap
`redamon.sh ensure_admin` prompts on `/dev/tty`, which blocks/fails over headless SSH. Pre-create the
admin so the prompt is skipped:
```bash
docker compose exec -T -e ADMIN_NAME="$ADMIN_NAME" -e ADMIN_EMAIL="$ADMIN_EMAIL" \
  -e ADMIN_PASSWORD="$ADMIN_PASSWORD" webapp node scripts/create-admin.mjs
```
Enforce a strong `ADMIN_PASSWORD` (there is no app-layer login lockout; nginx `limit_req` is the only
brake). Avoid the KB interactive prompt by installing **without** `--kbase` (default) or setting
`KB_EMBEDDING_USE_API=true` + an API key. There is **no** default admin / seed user — nothing to
disable, but the operator must complete this step or the UI has no login.

### 8.5 Secret verification gate (`secrets_gate.sh`) — fail the deploy on weak secrets
```bash
for v in AUTH_SECRET INTERNAL_API_KEY SCANNER_API_KEY ORCHESTRATOR_API_KEY \
         MCP_AUTH_TOKEN AGENT_WS_TICKET_SECRET TUNNEL_AUTH_TOKEN \
         POSTGRES_PASSWORD NEO4J_PASSWORD; do
  val=$(grep -E "^$v=" .env | cut -d= -f2-)
  case "$val" in ""|changeme|changeme123|redamon_secret|admin) echo "FATAL: $v default/unset"; exit 1;; esac
  [ ${#val} -ge 24 ] || { echo "FATAL: $v too short"; exit 1; }
done
```
`AGENT_WS_TICKET_SECRET` and `TUNNEL_AUTH_TOKEN` are load-bearing: unset → S6 ticket auth and tunnel
auth silently fail open.

### 8.2 TLS — three modes
- **`letsencrypt` (recommended):** requires `DOMAIN` DNS → the host and port 80 reachable. `certbot
  --nginx -d $DOMAIN -m $LETSENCRYPT_EMAIL --agree-tos -n`, then `certbot renew` via systemd timer with
  `--deploy-hook 'systemctl reload nginx'`. Cert path `/etc/letsencrypt/live/$DOMAIN/`.
- **`provided`:** SCP `SSL_CERT_LOCAL`/`SSL_KEY_LOCAL` to `/etc/ssl/certs|private/`, `chmod 644`/`600`,
  md5-idempotent replace (reuse example `ssl.sh`), decrypt with `openssl pkey` if `SSL_KEY_PASSWORD`
  set.
- **`self-signed`:** escape hatch for a bare IP without a domain (`openssl req -x509 ...`); browser
  warning accepted. Not for production.

### 8.6 Secure-cookie production patch (recommended)
`webapp/src/app/api/auth/login/route.ts:48` hardcodes `secure: false`. Ship a patch flipping it to
`secure: process.env.NODE_ENV === 'production'` so the session cookie is `Secure` behind TLS. HSTS +
the HTTP→HTTPS redirect are the interim controls if the patch is deferred.

---

## 9. Host / OS hardening modules

### 10. Firewall (`firewall.sh`, ufw — the portable control)
```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow from <OPERATOR_ALLOW_CIDRS> to any port 22 proto tcp    # SSH: operator only
ufw allow 80/tcp                                                   # ACME + redirect
ufw allow 443/tcp                                                  # the app
# 4444 stays CLOSED by default. Per engagement only:
#   ufw allow from <REVSHELL_TARGET_CIDRS> to any port 4444 proto tcp
ufw --force enable
```
> **Docker bypass caveat:** Docker publishes ports via its own iptables chains and can bypass ufw. The
> **loopback re-binds in §5 are the real control** for 3000/8090 — ufw is belt-and-braces. The deploy
> MUST verify post-boot with `ss -tlnp` that 3000 and 8090 show `127.0.0.1` only and that 5432/7474/
> 7687/8010 never show `0.0.0.0`. Optionally add `DOCKER-USER` iptables rules for 4444/8090.

### SSH hardening (`ssh_hardening.sh`, reuse example file_hardening OS half)
`PasswordAuthentication no`, `PermitRootLogin no`, key-only; validate with `sshd -t` before
`systemctl restart ssh`. `chmod 600 ~/.ssh/*`, `700 ~/.ssh`; `600 /etc/shadow`. (Beware locking
yourself out if you deployed via password auth — only disable password auth once a key is installed.)

### fail2ban (`fail2ban.sh`, repoint example)
Keep `[sshd]` (maxretry 3, bantime 2h) and the nginx jails (`nginx-http-auth`, `nginx-limit-req`,
`nginx-badbots`) reading `/var/log/nginx/*.log`. Drop the example's Django `[django-auth]` jail (no
such log here); optionally add a webapp-auth-log jail later.

### unattended-upgrades + swap/zram
Enable `unattended-upgrades` for security patches. Create an 8 GB swapfile on < 16 GB hosts; export
`REDAMON_ENABLE_ZRAM=1` for RedAmon's compressed-RAM cushion (Linux-native, non-fatal).

### GVM password rotation (if `--gvm`)
`docker compose exec -u gvmd gvmd gvmd --user=admin --new-password='<strong>'` — closes the S13 residual
`admin/admin`.

---

## 11. Reverse-shell (4444) & tunnel policy

- **Closed by default.** The prod overlay re-binds `4444` to loopback; ufw does not open it.
- **Per-engagement:** open `4444` via ufw to `REVSHELL_TARGET_CIDRS` (the RoE target scope) only, for
  the engagement's duration, then close it. A reverse shell only needs to reach it from the target, not
  from the whole internet.
- **Prefer tunnels** (ngrok/chisel) over a world-open `4444` when the target can't route back to a
  fixed IP — but keep `TUNNELS_ENABLED=false` by default (I19/S14: tunnels invert the LAN-only
  premise), set `TUNNEL_AUTH_TOKEN`, and **never run a world-open 4444 and a tunnel simultaneously.**
- Do not run tunnels on an already-internet-exposed host (redundant, doubles ingress).

---

## 12. Post-deploy verification (the deploy is not "done" until these pass)

```bash
# 1. Bindings: only loopback for internal services
$SSH "ss -tlnp | grep -E ':(3000|8090)\b'"      # must show 127.0.0.1 only
$SSH "ss -tlnp | grep -E ':(5432|7474|7687|8010|8000|8002|8003|8004|8005)\b'"  # 127.0.0.1 only
# 2. Public surface: ONLY 443 (+80 redirect) answers off-host
curl -sS -o /dev/null -w '%{http_code}\n' https://$DOMAIN/api/health   # 200
curl -sS -o /dev/null -w '%{http_code}\n' http://$DOMAIN/              # 301 -> https
# 3. Agent :8090 NOT reachable from the internet (should time out / refuse)
curl -m5 -sk https://$DOMAIN:8090/graph/exec ; echo "exit=$?"          # must fail
# 4. WS handshake through the single origin: open the app, confirm the AI drawer
#    connects and the Kali terminal opens (both now resolve to wss://$DOMAIN/ws/...)
# 5. Secrets gate passed; admin login works; `ufw status verbose`; cert expiry > 30d
```
Wire these as scripted assertions with hard `exit 1` on failure, mirroring the example's
`is-active --quiet` + `journalctl` + `exit 1` idiom (use
`docker inspect --format '{{.State.Health.Status}}'` for container health). RedAmon already ships
`tests/test_port_bindings.sh` asserting the loopback binds — run it as part of verification.

---

## 13. Idempotency, data preservation, rollback

- **Every module is `setup_X`/`disable_X`, flag-gated, and idempotent** (example patterns: `dpkg -s`
  guards, `command -v`, md5 config compare, grep-count crontab, `nginx -t`/`sshd -t` before reload).
- **`update` never touches Docker volumes** — all engagement data (Postgres, Neo4j, reports, GVM feeds,
  models) lives in named volumes that `redamon.sh update` preserves. Nothing runs `git clean` on the
  repo (unlike the example) because RedAmon keeps no in-repo runtime data.
- **Rollback:** no automatic snapshot. For safety, `update` may `docker image tag` the current
  webapp/agent images `:prev` before rebuild and snapshot Postgres
  (`docker compose exec -T postgres pg_dump ...`) + Neo4j before applying. Manual rollback:
  `git reset --hard <prev>` + `redamon.sh update`. (Optional P2.)

---

## 14. Cloud-agnostic notes

- The script only needs **IP + SSH auth + domain**; it works on EC2, DigitalOcean, Hetzner, bare metal.
- **EC2 Security Group** (if the operator prefers it over/with ufw): inbound `22` from operator IP,
  `80`+`443` from `0.0.0.0/0` (or operator CIDR for a private instance), `4444` only from target
  scope. Everything else denied. ufw inside the box is still recommended (Docker-bypass caveat).
- **Elastic IP / stable DNS** is needed for Let's Encrypt and for `NEXT_PUBLIC_AGENT_WS_URL` (baked at
  build time — if the domain changes you must rebuild the webapp image).

---

## 15. Open decisions / inputs required before writing `deploy.sh`

1. **Domain + TLS:** will every instance have a real DNS name (→ Let's Encrypt), or do some run on a
   bare IP (→ provided cert or self-signed)? The plan supports all three; confirm the default.
2. **Access gate:** `ip_allowlist` (needs a stable operator IP/VPN) vs `basic_auth` vs `none`. Given
   the unauthenticated agent WS + root-PTY terminal, **`ip_allowlist` is strongly recommended** as
   defense-in-depth even though the app has its own login.
3. **App-code patches (cypherfix WS origin, secure cookie, `webapp/Dockerfile` build arg):** commit
   them to a maintained deploy branch (recommended — makes `update` a clean fast-forward) or keep them
   as re-applied working-tree patches (brittle under `git pull --ff-only`).
4. **GVM / KB defaults:** off by default (lighter, faster). Turn on per instance via `deploy/.env`.
5. **4444 policy:** confirm "closed by default, opened per-engagement to target CIDRs" fits the
   intended workflow.

---

## 16. Appendix — consolidated port & exposure table

| Port | Service | Bind after deploy | Public? |
|---|---|---|---|
| 443 | nginx → webapp (+ agent `/ws/*`) | 0.0.0.0 | **Yes — the only app surface** |
| 80 | nginx (ACME + redirect) | 0.0.0.0 | Yes (redirect only) |
| 22 | SSH | 0.0.0.0 | Operator CIDR only (ufw/SG) |
| 3000 | webapp | 127.0.0.1 | No (nginx upstream) |
| 8090 | agent | 127.0.0.1 | No (nginx proxies `/ws/*` only) |
| 4444 | reverse-shell catcher | 127.0.0.1 | No by default; ufw-open to target CIDRs per engagement |
| 5432 / 7474 / 7687 | postgres / neo4j | 127.0.0.1 | Never |
| 8010 | recon-orchestrator | 127.0.0.1 | Never |
| 8000-8016 / 4040 | kali MCP / progress / tunnel / ngrok | 127.0.0.1 | Never |

---

## 17. Appendix — `redamon.sh` capabilities the deploy relies on (do not reimplement)

| Concern | `redamon.sh` provides | Deploy action |
|---|---|---|
| Secret generation | `ensure_auth_secrets` (7 tokens) + `ensure_db_secrets` (2 DB pw, volume-safe) | Call it; then verify with §8.5 gate |
| Memory sizing | `export_resource_caps` sizes NEO4J_HEAP/PAGECACHE + all `*_MEM` from host RAM | Nothing; ensure ≥8 GB or `REDAMON_SKIP_RAM_GATE=1` |
| RAM gate | `preflight_ram_gate` (8 GB floor) | Provision RAM; optionally override on tiny boxes |
| Build order | `compose_build` (webapp isolated first, capped parallelism) | Call `install`/`update`; don't run raw `docker compose build` |
| Image set | `--profile tools` build of 8 scanner images | Passed via `install` |
| Prisma schema | webapp entrypoint runs `prisma db push` automatically | Nothing |
| Admin bootstrap | `ensure_admin` (interactive) | Pre-create headlessly (§8.4) to skip the prompt |
| Update logic | `git pull --ff-only` + diff-driven selective rebuild + secret regen | Call `update`; keep tree fast-forwardable |
| Teardown | `down` / `clean` / `purge` (typed-confirm) | `init` uses `purge` then `docker system prune -af --volumes` |
| GVM/KB opt-in | `--gvm` / `--kbase` flag files | Map from `deploy/.env` |

---

*Plan version 1.0 — RedAmon 5.3.5. Built from a full pass over `docker-compose.yml`, `redamon.sh`,
the example `deploy/example/` scaffolding, `internal/security/README.TM.*`, the webapp auth/WS code,
and every service Dockerfile.*
