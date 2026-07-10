#!/usr/bin/env bash
# CSM Client - Production Nginx Configuration
# Dual-Access: Private VPN (HTTP full access) + Public (HTTPS only OAuth/API)
#
# Architecture:
# - HTTPS public (csm-api.beta80group.it):
#   Only /csm_api/, /signin-oidc, /auth/login/ routes
# - HTTP private (10.59.16.26 via VPN): Full application access
#
# SSL: Wildcard certificate *.beta80group.it

create_nginx_config() {
  local PROJECT_PATH="${1}"
  local ACTIVATE_WEBSOCKET="${2}"
  local DOMAIN="${3}"
  local SSL_CERT_REMOTE="${4}"
  local SSL_KEY_REMOTE="${5}"
  local NGINX_SERVER_NAMES="${6}"
  local GUNICORN_NGINX_KEEPALIVE="${7}"
  local SEO_INDEX="${8:-false}"  # Default to false (block indexing)
  
  echo "• Creating CSM Production Dual-Access Nginx configuration..."
  echo "  • HTTPS public domain: ${DOMAIN}"
  echo "  • HTTP private VPN: 10.59.16.26"
  
  cat > /tmp/nginx_config <<'NGINX_CONFIG'
# CSM Client - Production Dual-Access Configuration
# HTTPS (public): Only /csm_api/ and OAuth routes (/signin-oidc, /auth/login/)
# HTTP (private VPN 10.59.16.26): Full application access

# WebSocket upgrade header mapping (unified ASGI handles both HTTP and WebSocket)
map $http_upgrade $connection_upgrade {
    default upgrade;
    '' close;
}

# Hide nginx version to prevent targeted attacks
server_tokens off;

# Rate Limiting Zones - HTTP Flood Protection
limit_req_zone $binary_remote_addr zone=login_limit:10m rate=5r/m;
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/m;
limit_req_zone $binary_remote_addr zone=static_limit:20m rate=200r/m;
limit_req_zone $binary_remote_addr zone=global_limit:50m rate=60r/m;
limit_req_zone $binary_remote_addr zone=oauth_limit:10m rate=10r/m;

# Connection limits to prevent DoS attacks
limit_conn_zone $binary_remote_addr zone=conn_limit:10m;

# Upstream backend with connection pooling and failover
upstream gunicorn_backend {
    server unix:/run/gunicorn/gunicorn.sock max_fails=3 fail_timeout=30s;
    keepalive GUNICORN_NGINX_KEEPALIVE_PLACEHOLDER;
}

# ============================================================
# DEFAULT CATCH-ALL SERVERS - Block direct IP access
# These must be FIRST (default_server) to catch unmatched hosts
# ============================================================

# Default HTTPS - Block direct IP access (returns 444 = close connection)
server {
    listen 443 ssl http2 default_server;
    server_name _;
    
    # Minimal SSL config required for default server
    ssl_certificate SSL_CERT_REMOTE_PLACEHOLDER;
    ssl_certificate_key SSL_KEY_REMOTE_PLACEHOLDER;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Return 444 = close connection without response (more secure than 403)
    # This prevents information disclosure and drops the connection immediately
    access_log off;
    return 444;
}

# Default HTTP - Block direct IP access on port 80
server {
    listen 80 default_server;
    server_name _;
    
    # Return 444 = close connection without response
    access_log off;
    return 444;
}

# ============================================================
# HTTPS Server Block - PUBLIC (Only OAuth + API routes)
# Accessible from Internet, but restricted to specific routes
# ============================================================
server {
    listen 443 ssl http2;
    server_name NGINX_SERVER_NAMES_PLACEHOLDER;
    
    # SSL Configuration (Wildcard certificate *.beta80group.it)
    ssl_certificate SSL_CERT_REMOTE_PLACEHOLDER;
    ssl_certificate_key SSL_KEY_REMOTE_PLACEHOLDER;
    
    # Enhanced SSL Security - Modern cipher suite (GCM/ChaCha20 only, no CBC)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Limit concurrent connections per IP
    limit_conn conn_limit 10;
    
    # Timeout protections against Slowloris attacks
    client_body_timeout 12s;
    client_header_timeout 12s;
    send_timeout 10s;
    keepalive_timeout 15s;
    
    # Header size limits
    large_client_header_buffers 8 32k;
    client_header_buffer_size 16k;
    
    # Security headers for HTTPS
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header X-Robots-Tag "noindex, nofollow, noarchive, nosnippet" always;
    
    # Content-Security-Policy is set by Django middleware (core/middleware.py)
    # with per-request nonce tokens — do NOT duplicate it here in Nginx.

    # Permissions-Policy - Restrict browser API access
    # microphone=(self) allows mic access from same origin only (required for voice mode)
    add_header Permissions-Policy "camera=(), microphone=(self), geolocation=(), payment=(), usb=(), interest-cohort=()" always;
    
    # Allow only safe HTTP methods
    if ($request_method !~ ^(GET|POST|HEAD|OPTIONS)$) {
        return 405;
    }
    
    # Allow larger file uploads for API
    client_max_body_size 50M;
    
    # Global rate limiting (applies to all requests) - HTTP Flood protection
    limit_req zone=global_limit burst=50 nodelay;
    limit_req_status 429;
    
    # Disable directory listing globally
    autoindex off;
    
    # Block access to hidden files and directories (.env, .git, etc.)
    location ~ /\. {
        deny all;
        return 404;
    }
    
    # Block access to sensitive file extensions
    location ~ \.(sqlite3|sqlite3-shm|sqlite3-wal|db|sql|bak|backup|log)$ {
        deny all;
        return 404;
    }
    
    # Block access to certificate and key files
    location ~ \.(pem|key|crt|cer|p12|pfx)$ {
        deny all;
        return 404;
    }
    
    # Block access to Python bytecode and cache
    location ~ \.(pyc|pyo|pyd)$ {
        deny all;
        return 404;
    }
    
    # Block access to common backup file patterns
    location ~ (\.env|\.env\.local|\.env\.prod|~|\.swp|\.swo|\.bak|\.old|\.tmp)$ {
        deny all;
        return 404;
    }
    
    location = /favicon.ico { access_log off; log_not_found off; }
    
    # ============================================================
    # OAuth Routes - SSO Microsoft (HTTPS only)
    # ============================================================
    
    # OAuth callback from Microsoft
    location = /signin-oidc {
        limit_req zone=oauth_limit burst=10 nodelay;
        limit_req_status 429;
        
        proxy_pass http://gunicorn_backend;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        
        proxy_connect_timeout 10s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        proxy_next_upstream error timeout http_502 http_503;
        proxy_next_upstream_tries 2;
        proxy_next_upstream_timeout 1s;
        
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
        
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
    }
    
    # OAuth login initiation
    location = /auth/login/ {
        limit_req zone=oauth_limit burst=10 nodelay;
        limit_req_status 429;
        
        proxy_pass http://gunicorn_backend;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        
        proxy_connect_timeout 10s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        proxy_next_upstream error timeout http_502 http_503;
        proxy_next_upstream_tries 2;
        proxy_next_upstream_timeout 1s;
        
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
        
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
    }
    
    # ============================================================
    # /csm_api/ - SSL-Protected API Endpoint
    # ============================================================
    location /csm_api/ {
        limit_req zone=api_limit burst=20 nodelay;
        limit_req_status 429;
        
        proxy_pass http://gunicorn_backend;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        
        proxy_connect_timeout 10s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        proxy_next_upstream error timeout http_502 http_503;
        proxy_next_upstream_tries 2;
        proxy_next_upstream_timeout 1s;
        
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
        
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
    }
    
    # ============================================================
    # ALL OTHER PATHS: BLOCKED on public domain
    # Users must use VPN (10.59.16.26) for full app access
    # ============================================================
    location / {
        return 403 "Access denied. Use VPN to access the application.";
    }
}

# ============================================================
# HTTP Server Block - PUBLIC DOMAIN (Redirect to HTTPS or block)
# ============================================================
server {
    listen 80;
    server_name NGINX_SERVER_NAMES_PLACEHOLDER;
    
    # Security headers even during redirect phase
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Robots-Tag "noindex, nofollow, noarchive, nosnippet" always;
    
    # Redirect OAuth routes to HTTPS
    location = /signin-oidc {
        return 301 https://$host$request_uri;
    }
    
    location = /auth/login/ {
        return 301 https://$host$request_uri;
    }
    
    # Redirect API to HTTPS
    location /csm_api/ {
        return 301 https://$host$request_uri;
    }
    
    # Block all other routes on public domain
    location / {
        return 403 "Access denied. Use VPN to access the application.";
    }
}

# ============================================================
# HTTP Server Block - PRIVATE VPN (Full application access)
# Only accessible from VPN network (10.59.16.26)
# ============================================================
server {
    listen 10.59.16.26:80;
    server_name 10.59.16.26;

    # Limit concurrent connections per IP
    limit_conn conn_limit 20;
    
    # Timeout protections against Slowloris attacks
    client_body_timeout 12s;
    client_header_timeout 12s;
    send_timeout 10s;
    keepalive_timeout 15s;
    
    # Header size limits (maximum for WebSocket upgrade headers with CDN cookies/tokens)
    large_client_header_buffers 8 32k;
    client_header_buffer_size 16k;
    
    # Allow safe HTTP methods (more permissive for internal VPN)
    if ($request_method !~ ^(GET|POST|HEAD|OPTIONS|PUT|DELETE|PATCH)$) {
        return 405;
    }

    # Allow larger file uploads
    client_max_body_size 50M;
    
    # Global rate limiting (applies to all requests)
    limit_req zone=global_limit burst=50 nodelay;
    limit_req_status 429;
    
    # Disable directory listing globally
    autoindex off;
    
    # Block access to hidden files and directories (.env, .git, etc.)
    location ~ /\. {
        deny all;
        return 404;
    }
    
    # Block access to sensitive file extensions
    location ~ \.(sqlite3|sqlite3-shm|sqlite3-wal|db|sql|bak|backup|log)$ {
        deny all;
        return 404;
    }
    
    # Block access to certificate and key files
    location ~ \.(pem|key|crt|cer|p12|pfx)$ {
        deny all;
        return 404;
    }
    
    # Block access to Python bytecode and cache
    location ~ \.(pyc|pyo|pyd)$ {
        deny all;
        return 404;
    }
    
    # Block access to common backup file patterns
    location ~ (\.env|\.env\.local|\.env\.prod|~|\.swp|\.swo|\.bak|\.old|\.tmp)$ {
        deny all;
        return 404;
    }

    location = /favicon.ico { access_log off; log_not_found off; }
    
    # Serve static files directly (^~ prevents regex location evaluation)
    location ^~ /static/ {
        limit_req zone=static_limit burst=100 nodelay;
        limit_req_status 429;

        alias PROJECT_PATH_PLACEHOLDER/static_collected/;
        autoindex off;

        expires 1h;
        add_header Cache-Control "public, must-revalidate";
    }
    
    # Serve work files directly
    location ^~ /work/ {
        limit_req zone=static_limit burst=100 nodelay;
        limit_req_status 429;
        
        alias PROJECT_PATH_PLACEHOLDER/media/work/;
        autoindex off;
        expires 1h;
        add_header Cache-Control "public";
    }
    
    # Serve media files
    location ^~ /media/ {
        limit_req zone=static_limit burst=100 nodelay;
        limit_req_status 429;
        
        alias PROJECT_PATH_PLACEHOLDER/media/;
        autoindex off;
        expires 1d;
    }

    # Serve uploads directory
    location ^~ /uploads/ {
        client_max_body_size 50M;
        client_body_timeout 300s;
        
        proxy_pass http://gunicorn_backend;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;
        
        proxy_connect_timeout 10s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
        
        proxy_next_upstream error timeout http_502 http_503;
        proxy_next_upstream_tries 2;
        proxy_next_upstream_timeout 1s;
        
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
    }

    # WebSocket support - unified ASGI server (same as HTTP)
    location /ws/ {
        proxy_pass http://gunicorn_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        proxy_connect_timeout 7d;
        proxy_send_timeout 7d;
        proxy_read_timeout 7d;
        
        proxy_buffering off;
    }

    # Rate limited login endpoint - strict protection against credential stuffing
    location /login/ {
        limit_req zone=login_limit burst=5 nodelay;
        limit_req_status 429;
        
        proxy_pass http://gunicorn_backend;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;
        
        proxy_connect_timeout 10s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        proxy_next_upstream error timeout http_502 http_503;
        proxy_next_upstream_tries 2;
        proxy_next_upstream_timeout 1s;
        
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
        
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
        
        add_header Cache-Control "no-store, no-cache, must-revalidate, private" always;
    }
    
    # /csm_api/ on private IP - direct access (no redirect to HTTPS needed in VPN)
    location /csm_api/ {
        limit_req zone=api_limit burst=20 nodelay;
        limit_req_status 429;
        
        proxy_pass http://gunicorn_backend;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;
        
        proxy_connect_timeout 10s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        proxy_next_upstream error timeout http_502 http_503;
        proxy_next_upstream_tries 2;
        proxy_next_upstream_timeout 1s;
        
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
        
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
    }
    
    # Rate limited API endpoints
    location /api/ {
        limit_req zone=api_limit burst=20 nodelay;
        limit_req_status 429;
        
        proxy_pass http://gunicorn_backend;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;
        
        proxy_connect_timeout 10s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        proxy_next_upstream error timeout http_502 http_503;
        proxy_next_upstream_tries 2;
        proxy_next_upstream_timeout 1s;
        
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
        
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
    }
    
    # Keycloak reverse proxy (local container)
    location /kc/ {
        proxy_pass http://127.0.0.1:8080/kc/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
    }

    # Default location - proxy to Gunicorn (full app access)
    location / {
        proxy_pass http://gunicorn_backend;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;

        proxy_connect_timeout 10s;
        # Invio ordine SAP/RPA è sincrono nel ciclo request/response e può superare
        # i 60s (ShipTo resolve + CSRF + POST ordine grosso). Allineato a GUNICORN_TIMEOUT=300
        # per evitare 504 lato nginx mentre l'ordine viene comunque creato a valle.
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;

        # NB: 'timeout' rimosso da proxy_next_upstream — su una POST andata in timeout
        # un retry su un altro worker rischierebbe di creare l'ordine due volte.
        proxy_next_upstream error http_502 http_503;
        proxy_next_upstream_tries 2;
        proxy_next_upstream_timeout 1s;
        
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
        
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
    }
}
NGINX_CONFIG

  # Substitute variables in the config
  sed -i "s|NGINX_SERVER_NAMES_PLACEHOLDER|${NGINX_SERVER_NAMES}|g" /tmp/nginx_config
  sed -i "s|SSL_CERT_REMOTE_PLACEHOLDER|${SSL_CERT_REMOTE}|g" /tmp/nginx_config
  sed -i "s|SSL_KEY_REMOTE_PLACEHOLDER|${SSL_KEY_REMOTE}|g" /tmp/nginx_config
  sed -i "s|PROJECT_PATH_PLACEHOLDER|${PROJECT_PATH}|g" /tmp/nginx_config
  sed -i "s|GUNICORN_NGINX_KEEPALIVE_PLACEHOLDER|${GUNICORN_NGINX_KEEPALIVE}|g" /tmp/nginx_config
  
  # Remove X-Robots-Tag header if SEO_INDEX is true (allow indexing)
  if [[ "${SEO_INDEX}" == "true" ]]; then
    sed -i '/X-Robots-Tag/d' /tmp/nginx_config
    echo "  • SEO indexing ENABLED (X-Robots-Tag header removed)"
  else
    echo "  • SEO indexing BLOCKED (X-Robots-Tag: noindex, nofollow)"
  fi
  
  echo "  ✓ CSM Production Dual-Access Nginx configuration created"
  echo "    - HTTPS public (${DOMAIN}): /csm_api/, /signin-oidc, /auth/login/ only"
  echo "    - HTTP private (10.59.16.26): Full application access via VPN"
  echo "    - SSL: Wildcard certificate *.beta80group.it"
}
