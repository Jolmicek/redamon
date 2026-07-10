#!/usr/bin/env bash
# SECRET_KEY Rotation Module
# Manages automatic SECRET_KEY rotation (period configurable via SECRET_KEY_ROTATION_DAYS)

# Setup systemd timer for automatic SECRET_KEY rotation
setup_secret_key_rotation() {
  echo "🔐 ==================================================="
  echo "🔐 SETTING UP AUTOMATIC SECRET_KEY ROTATION"
  echo "🔐 ==================================================="
  
  local REMOTE_USER="${1}"
  local PROJECT_PATH="${2}"
  local VENV_DIR="${3}"
  
  # Validate parameters
  if [[ -z "${REMOTE_USER}" || -z "${PROJECT_PATH}" || -z "${VENV_DIR}" ]]; then
    echo "❌ Error: Missing required parameters for SECRET_KEY rotation setup"
    echo "   REMOTE_USER=${REMOTE_USER}, PROJECT_PATH=${PROJECT_PATH}, VENV_DIR=${VENV_DIR}"
    return 1
  fi
  
  # Get rotation days from .env file (default: 90 days)
  local ROTATION_DAYS="90"
  if [[ -f "${PROJECT_PATH}/.env" ]]; then
    ROTATION_DAYS=$(grep "^SECRET_KEY_ROTATION_DAYS=" "${PROJECT_PATH}/.env" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "90")
    # Validate rotation days
    if ! [[ "${ROTATION_DAYS}" =~ ^[0-9]+$ ]] || [[ "${ROTATION_DAYS}" -lt 1 ]]; then
      echo "  ⚠️ Invalid SECRET_KEY_ROTATION_DAYS value '${ROTATION_DAYS}', using default 90 days"
      ROTATION_DAYS="90"
    fi
  else
    echo "  ⚠️ .env file not found at ${PROJECT_PATH}/.env, using default rotation period"
  fi
  
  echo "  • Rotation period: ${ROTATION_DAYS} days"
  
  # Create systemd service for rotation
  cat > /tmp/secret-key-rotate.service <<SECRET_KEY_SERVICE
[Unit]
Description=Rotate Django SECRET_KEY
After=network.target

[Service]
Type=oneshot
User=${REMOTE_USER}
Group=${REMOTE_USER}
WorkingDirectory=${PROJECT_PATH}
Environment=PATH=${PROJECT_PATH}/${VENV_DIR}/bin
EnvironmentFile=-${PROJECT_PATH}/.env

# Rotate key (period configurable via SECRET_KEY_ROTATION_DAYS in .env)
# Exit code 0 = rotation occurred, Exit code 2 = not needed yet
ExecStart=${PROJECT_PATH}/${VENV_DIR}/bin/python ${PROJECT_PATH}/manage.py rotate_secret_key
SuccessExitStatus=0 2

# Log rotation events
StandardOutput=journal
StandardError=journal
SyslogIdentifier=secret-key-rotate
SECRET_KEY_SERVICE
  
  # Create systemd timer (checks daily, rotates if configured period has passed)
  cat > /tmp/secret-key-rotate.timer <<SECRET_KEY_TIMER
[Unit]
Description=Rotate Django SECRET_KEY (period configurable via SECRET_KEY_ROTATION_DAYS)
Requires=secret-key-rotate.service

[Timer]
# Check daily (rotation command checks if period from SECRET_KEY_ROTATION_DAYS has passed)
OnCalendar=daily
# Run on boot (after 5 minutes)
OnBootSec=5min
# Add randomization to avoid all servers rotating simultaneously
RandomizedDelaySec=1h
# Persistent: if missed, run as soon as timer is active
Persistent=true

[Install]
WantedBy=timers.target
SECRET_KEY_TIMER
  
  # Install service and timer (use run_sudo if available, otherwise sudo)
  # run_sudo is defined in _common.sh which should be sourced before this module
  echo "  • Installing systemd service and timer files..."
  local SUDO_CMD="sudo"
  if type run_sudo >/dev/null 2>&1; then
    SUDO_CMD="run_sudo"
    echo "  • Using run_sudo for elevated permissions"
  else
    echo "  • Using sudo for elevated permissions"
  fi
  
  ${SUDO_CMD} mv /tmp/secret-key-rotate.service /etc/systemd/system/ || {
    echo "❌ Error: Failed to move service file"
    return 1
  }
  ${SUDO_CMD} mv /tmp/secret-key-rotate.timer /etc/systemd/system/ || {
    echo "❌ Error: Failed to move timer file"
    return 1
  }
  
  # Set proper permissions
  echo "  • Setting file permissions..."
  ${SUDO_CMD} chmod 644 /etc/systemd/system/secret-key-rotate.service || true
  ${SUDO_CMD} chmod 644 /etc/systemd/system/secret-key-rotate.timer || true
  
  # Reload systemd and enable timer
  echo "  • Reloading systemd daemon..."
  ${SUDO_CMD} systemctl daemon-reload || {
    echo "❌ Error: Failed to reload systemd"
    return 1
  }
  
  echo "  • Enabling and starting timer..."
  ${SUDO_CMD} systemctl enable secret-key-rotate.timer || {
    echo "❌ Error: Failed to enable timer"
    return 1
  }
  ${SUDO_CMD} systemctl start secret-key-rotate.timer || {
    echo "❌ Error: Failed to start timer"
    ${SUDO_CMD} systemctl status secret-key-rotate.timer --no-pager || true
    return 1
  }
  
  # Check timer status
  sleep 2
  if ${SUDO_CMD} systemctl is-active --quiet secret-key-rotate.timer; then
    echo ""
    echo "✅ ==================================================="
    echo "✅ SECRET_KEY ROTATION TIMER ENABLED"
    echo "✅ ==================================================="
    echo ""
    echo "  • Timer checks: Daily (with 1-hour randomization)"
    echo "  • Rotation period: ${ROTATION_DAYS} days (rotation happens when period expires)"
    
    # Get next run time
    local NEXT_RUN=$(${SUDO_CMD} systemctl list-timers secret-key-rotate.timer --no-legend 2>/dev/null | awk '{print $1, $2}' || echo 'checking...')
    echo "  • Next scheduled check: ${NEXT_RUN}"
    echo ""
  else
    echo ""
    echo "❌ ==================================================="
    echo "❌ SECRET_KEY ROTATION TIMER FAILED TO START"
    echo "❌ ==================================================="
    echo ""
    ${SUDO_CMD} systemctl status secret-key-rotate.timer --no-pager || true
    return 1
  fi
}

# Disable SECRET_KEY rotation
disable_secret_key_rotation() {
  echo "🔐 Disabling SECRET_KEY rotation timer..."
  
  # Use run_sudo if available, otherwise sudo
  local SUDO_CMD="sudo"
  if type run_sudo >/dev/null 2>&1; then
    SUDO_CMD="run_sudo"
  fi
  
  ${SUDO_CMD} systemctl stop secret-key-rotate.timer 2>/dev/null || true
  ${SUDO_CMD} systemctl disable secret-key-rotate.timer 2>/dev/null || true
  
  # Remove service and timer files
  ${SUDO_CMD} rm -f /etc/systemd/system/secret-key-rotate.service
  ${SUDO_CMD} rm -f /etc/systemd/system/secret-key-rotate.timer
  
  ${SUDO_CMD} systemctl daemon-reload || true
  
  echo "✅ SECRET_KEY rotation disabled"
}

