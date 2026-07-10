#!/usr/bin/env bash
# Default HTTP Nginx Configuration
# HTTP only, no SSL

create_nginx_config() {
  local PROJECT_PATH="${1}"
  local ACTIVATE_WEBSOCKET="${2}"
  local DOMAIN="${3}"
  local SSL_CERT_REMOTE="${4}"
  local SSL_KEY_REMOTE="${5}"
  local NGINX_SERVER_NAMES="${6}"
  local GUNICORN_NGINX_KEEPALIVE="${7}"
  local SEO_INDEX="${8:-false}"  # Default to false (block indexing)
  
  echo "• Creating Nginx configuration without SSL (HTTP only)..."
  
  if [[ "${ACTIVATE_WEBSOCKET}" == "true" ]]; then
    echo "  • Including WebSocket header mapping (NOTE: WebSocket always available with ASGI)"
    cat > /tmp/nginx_config <<NGINX_CONFIG
# WebSocket upgrade header mapping (unified ASGI handles both HTTP and WebSocket)
map \$http_upgrade \$connection_upgrade {
    default upgrade;
    '' close;
}

# Hide nginx version to prevent targeted attacks
server_tokens off;

# Rate Limiting Zones - HTTP Flood Protection
limit_req_zone \$binary_remote_addr zone=login_limit:10m rate=5r/m;
limit_req_zone \$binary_remote_addr zone=api_limit:10m rate=10r/m;
limit_req_zone \$binary_remote_addr zone=static_limit:20m rate=200r/m;
limit_req_zone \$binary_remote_addr zone=global_limit:50m rate=60r/m;

# Connection limits to prevent DoS attacks
limit_conn_zone \$binary_remote_addr zone=conn_limit:10m;

# Upstream backend with connection pooling and failover
upstream gunicorn_backend {
    server unix:/run/gunicorn/gunicorn.sock max_fails=3 fail_timeout=30s;
    keepalive ${GUNICORN_NGINX_KEEPALIVE};
}

server {
    listen 80;
    server_name ${NGINX_SERVER_NAMES};

    # Limit concurrent connections per IP
    limit_conn conn_limit 10;
    
    # Timeout protections against Slowloris attacks
    client_body_timeout 12s;
    client_header_timeout 12s;
    send_timeout 10s;
    keepalive_timeout 15s;
    
    # Header size limits (maximum for WebSocket upgrade headers with CDN cookies/tokens)
    large_client_header_buffers 8 32k;
    client_header_buffer_size 16k;
    
    # Prevent search engine indexing - this is a private application
    add_header X-Robots-Tag "noindex, nofollow, noarchive, nosnippet" always;
    
    # Allow only safe HTTP methods
    if (\$request_method !~ ^(GET|POST|HEAD|OPTIONS)\$) {
        return 405;
    }

    # Allow larger file uploads (adjust size as needed)
    client_max_body_size 50M;
    
    # Global rate limiting (applies to all requests) - Strengthened for HTTP Flood protection
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
    location ~ \.(sqlite3|sqlite3-shm|sqlite3-wal|db|sql|bak|backup|log)\$ {
        deny all;
        return 404;
    }
    
    # Block access to certificate and key files
    location ~ \.(pem|key|crt|cer|p12|pfx)\$ {
        deny all;
        return 404;
    }
    
    # Block access to Python bytecode and cache
    location ~ \.(pyc|pyo|pyd)\$ {
        deny all;
        return 404;
    }
    
    # Block access to common backup file patterns
    location ~ (\.env|\.env\.local|\.env\.prod|~|\.swp|\.swo|\.bak|\.old|\.tmp)\$ {
        deny all;
        return 404;
    }

    location = /favicon.ico { access_log off; log_not_found off; }
    
    # Serve static files directly (^~ prevents regex location evaluation)
    # Rate limiting for static files - protects against HTTP Flood via static file requests
    location ^~ /static/ {
        limit_req zone=static_limit burst=100 nodelay;
        limit_req_status 429;

        alias ${PROJECT_PATH}/static_collected/;
        autoindex off;

        expires 1h;
        add_header Cache-Control "public, must-revalidate";
    }

    # Serve work files directly (^~ prevents regex location evaluation)
    # Rate limiting for work files - protects against HTTP Flood via work file requests
    location ^~ /work/ {
        limit_req zone=static_limit burst=100 nodelay;
        limit_req_status 429;
        
        alias ${PROJECT_PATH}/media/work/;
        autoindex off;
        expires 1h;
        add_header Cache-Control "public";
    }
    
    # Serve media files (^~ prevents regex location evaluation)
    # Rate limiting for media files - protects against HTTP Flood via media file requests
    location ^~ /media/ {
        limit_req zone=static_limit burst=100 nodelay;
        limit_req_status 429;
        
        alias ${PROJECT_PATH}/media/;
        autoindex off;
        expires 1d;
    }

    # Serve uploads directory (^~ prevents regex location evaluation)
    # Proxied to Django for authentication checks if needed
    location ^~ /uploads/ {
        # Allow larger uploads (matches params.py: max_file_size_mb = 50)
        client_max_body_size 50M;
        client_body_timeout 300s;
        
        proxy_pass http://gunicorn_backend;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_redirect off;
        
        # Upstream connection and timeout settings
        proxy_connect_timeout 10s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
        
        # Failover configuration
        proxy_next_upstream error timeout http_502 http_503;
        proxy_next_upstream_tries 2;
        proxy_next_upstream_timeout 1s;
        
        # Hide backend server information
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
    }

    # WebSocket support - unified ASGI server (same as HTTP)
    # NOTE: Gunicorn with UvicornWorker handles BOTH HTTP and WebSocket at same socket
    location /ws/ {
        proxy_pass http://gunicorn_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # WebSocket timeouts (longer for persistent connections)
        proxy_connect_timeout 7d;
        proxy_send_timeout 7d;
        proxy_read_timeout 7d;
        
        # Disable buffering for WebSocket
        proxy_buffering off;
    }

    # Rate limited login endpoint - strict protection against credential stuffing
    location /login/ {
        limit_req zone=login_limit burst=5 nodelay;
        limit_req_status 429;
        
        proxy_pass http://gunicorn_backend;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_redirect off;
        
        # Upstream connection and timeout settings
        proxy_connect_timeout 10s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Failover configuration
        proxy_next_upstream error timeout http_502 http_503;
        proxy_next_upstream_tries 2;
        proxy_next_upstream_timeout 1s;
        
        # Hide backend server information
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
        
        # Prevent caching of login pages
        add_header Cache-Control "no-store, no-cache, must-revalidate, private" always;
    }
    
    # Rate limited API endpoints
    location /api/ {
        limit_req zone=api_limit burst=20 nodelay;
        limit_req_status 429;
        
        proxy_pass http://gunicorn_backend;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_redirect off;
        
        # Upstream connection and timeout settings
        proxy_connect_timeout 10s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Failover configuration
        proxy_next_upstream error timeout http_502 http_503;
        proxy_next_upstream_tries 2;
        proxy_next_upstream_timeout 1s;
        
        # Hide backend server information
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
    }
    
    # Keycloak reverse proxy (local container)
    location /kc/ {
        proxy_pass http://127.0.0.1:8080/kc/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
    }

    # Proxy HTTP requests to Gunicorn (other endpoints)
    location / {
        proxy_pass http://gunicorn_backend;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_redirect off;

        # Upstream connection and timeout settings
        proxy_connect_timeout 10s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # Failover configuration
        proxy_next_upstream error timeout http_502 http_503;
        proxy_next_upstream_tries 2;
        proxy_next_upstream_timeout 1s;

        # Hide backend server information
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
    }
}
NGINX_CONFIG
  else
    echo "  • WebSocket support DISABLED in Nginx config"
    cat > /tmp/nginx_config <<NGINX_CONFIG
# Hide nginx version to prevent targeted attacks
server_tokens off;

# Rate Limiting Zones - HTTP Flood Protection
limit_req_zone \$binary_remote_addr zone=login_limit:10m rate=5r/m;
limit_req_zone \$binary_remote_addr zone=api_limit:10m rate=10r/m;
limit_req_zone \$binary_remote_addr zone=static_limit:20m rate=200r/m;
limit_req_zone \$binary_remote_addr zone=global_limit:50m rate=60r/m;

# Connection limits to prevent DoS attacks
limit_conn_zone \$binary_remote_addr zone=conn_limit:10m;

# Upstream backend with connection pooling and failover
upstream gunicorn_backend {
    server unix:/run/gunicorn/gunicorn.sock max_fails=3 fail_timeout=30s;
    keepalive ${GUNICORN_NGINX_KEEPALIVE};
}

server {
    listen 80;
    server_name ${NGINX_SERVER_NAMES};

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
    
    # Allow only safe HTTP methods
    if (\$request_method !~ ^(GET|POST|HEAD|OPTIONS)\$) {
        return 405;
    }

    # Allow larger file uploads (adjust size as needed)
    client_max_body_size 50M;
    
    # Global rate limiting (applies to all requests) - Strengthened for HTTP Flood protection
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
    location ~ \.(sqlite3|sqlite3-shm|sqlite3-wal|db|sql|bak|backup|log)\$ {
        deny all;
        return 404;
    }
    
    # Block access to certificate and key files
    location ~ \.(pem|key|crt|cer|p12|pfx)\$ {
        deny all;
        return 404;
    }
    
    # Block access to Python bytecode and cache
    location ~ \.(pyc|pyo|pyd)\$ {
        deny all;
        return 404;
    }
    
    # Block access to common backup file patterns
    location ~ (\.env|\.env\.local|\.env\.prod|~|\.swp|\.swo|\.bak|\.old|\.tmp)\$ {
        deny all;
        return 404;
    }

    location = /favicon.ico { access_log off; log_not_found off; }
    
    # Serve static files directly (^~ prevents regex location evaluation)
    # Rate limiting for static files - protects against HTTP Flood via static file requests
    location ^~ /static/ {
        limit_req zone=static_limit burst=100 nodelay;
        limit_req_status 429;

        alias ${PROJECT_PATH}/static_collected/;
        autoindex off;

        expires 1h;
        add_header Cache-Control "public, must-revalidate";
    }

    # Serve work files directly (^~ prevents regex location evaluation)
    # Rate limiting for work files - protects against HTTP Flood via work file requests
    location ^~ /work/ {
        limit_req zone=static_limit burst=100 nodelay;
        limit_req_status 429;
        
        alias ${PROJECT_PATH}/media/work/;
        autoindex off;
        expires 1h;
        add_header Cache-Control "public";
    }
    
    # Serve media files (^~ prevents regex location evaluation)
    # Rate limiting for media files - protects against HTTP Flood via media file requests
    location ^~ /media/ {
        limit_req zone=static_limit burst=100 nodelay;
        limit_req_status 429;
        
        alias ${PROJECT_PATH}/media/;
        autoindex off;
        expires 1d;
    }

    # Rate limited login endpoint - strict protection against credential stuffing
    location /login/ {
        limit_req zone=login_limit burst=5 nodelay;
        limit_req_status 429;
        
        proxy_pass http://gunicorn_backend;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_redirect off;
        
        # Upstream connection and timeout settings
        proxy_connect_timeout 10s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Failover configuration
        proxy_next_upstream error timeout http_502 http_503;
        proxy_next_upstream_tries 2;
        proxy_next_upstream_timeout 1s;
        
        # Hide backend server information
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
        
        # Prevent caching of login pages
        add_header Cache-Control "no-store, no-cache, must-revalidate, private" always;
    }
    
    # Rate limited API endpoints
    location /api/ {
        limit_req zone=api_limit burst=20 nodelay;
        limit_req_status 429;
        
        proxy_pass http://gunicorn_backend;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_redirect off;
        
        # Upstream connection and timeout settings
        proxy_connect_timeout 10s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Failover configuration
        proxy_next_upstream error timeout http_502 http_503;
        proxy_next_upstream_tries 2;
        proxy_next_upstream_timeout 1s;
        
        # Hide backend server information
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
    }

    # Keycloak reverse proxy (local container)
    location /kc/ {
        proxy_pass http://127.0.0.1:8080/kc/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
    }

    # Proxy HTTP requests to Gunicorn (NO WebSocket support - other endpoints)
    location / {
        proxy_pass http://gunicorn_backend;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_redirect off;

        # Upstream connection and timeout settings
        proxy_connect_timeout 10s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # Failover configuration
        proxy_next_upstream error timeout http_502 http_503;
        proxy_next_upstream_tries 2;
        proxy_next_upstream_timeout 1s;

        # Hide backend server information
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
    }
}
NGINX_CONFIG
  fi
  
  # Remove X-Robots-Tag header if SEO_INDEX is true (allow indexing)
  if [[ "${SEO_INDEX}" == "true" ]]; then
    sed -i '/X-Robots-Tag/d' /tmp/nginx_config
    echo "  • SEO indexing ENABLED (X-Robots-Tag header removed)"
  else
    echo "  • SEO indexing BLOCKED (X-Robots-Tag: noindex, nofollow)"
  fi
  
  echo "  ✓ HTTP-only Nginx configuration created"
}

