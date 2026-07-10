#!/usr/bin/env bash
# Gunicorn ASGI Server Module
# Manages Gunicorn systemd service for HTTP and WebSocket requests (unified ASGI)

# Create Gunicorn systemd service
setup_gunicorn_service() {
  local REMOTE_USER="${1}"
  local PROJECT_PATH="${2}"
  local VENV_DIR="${3}"
  local GUNICORN_NICE="${4}"
  local GUNICORN_CPU_WEIGHT="${5}"
  local GUNICORN_CPU_QUOTA="${6}"
  local GUNICORN_WORKERS="${7}"
  local GUNICORN_TIMEOUT="${8}"
  local GUNICORN_MAX_REQUESTS="${9}"
  local GUNICORN_MAX_REQUESTS_JITTER="${10}"
  local GUNICORN_BACKLOG="${11}"
  
  echo "• Creating Gunicorn systemd service (ASGI with UvicornWorker for HTTP + WebSocket)"

  cat > /tmp/gunicorn.service <<GUNICORN_SERVICE
[Unit]
Description=Gunicorn ASGI daemon (HTTP + WebSocket)
After=network.target

[Service]
Type=notify
User=${REMOTE_USER}
Group=${REMOTE_USER}
RuntimeDirectory=gunicorn
RuntimeDirectoryMode=0770
WorkingDirectory=${PROJECT_PATH}
Environment=ENABLE_SCHEDULER=true
EnvironmentFile=-${PROJECT_PATH}/.env

# CPU Priority: High priority for user-facing requests (configured from .env)
Nice=${GUNICORN_NICE}
CPUWeight=${GUNICORN_CPU_WEIGHT}
CPUQuota=${GUNICORN_CPU_QUOTA}

ExecStart=${PROJECT_PATH}/${VENV_DIR}/bin/gunicorn \\
          --access-logfile - \\
          --workers ${GUNICORN_WORKERS} \\
          --worker-class uvicorn.workers.UvicornWorker \\
          --timeout ${GUNICORN_TIMEOUT} \\
          --max-requests ${GUNICORN_MAX_REQUESTS} \\
          --max-requests-jitter ${GUNICORN_MAX_REQUESTS_JITTER} \\
          --backlog ${GUNICORN_BACKLOG} \\
          --bind unix:/run/gunicorn/gunicorn.sock \\
          core.asgi:application
ExecStartPost=/bin/sh -c 'setfacl -m u:www-data:rwx /run/gunicorn 2>/dev/null || usermod -a -G ${REMOTE_USER} www-data'
ExecReload=/bin/kill -s HUP \$MAINPID
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true
Restart=on-failure
RestartSec=10
StartLimitBurst=3

[Install]
WantedBy=multi-user.target
GUNICORN_SERVICE

  run_sudo cp /tmp/gunicorn.service /etc/systemd/system/gunicorn.service
  rm -f /tmp/gunicorn.service
  
  echo "✅ Gunicorn service created"
}


