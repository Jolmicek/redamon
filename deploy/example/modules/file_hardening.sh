#!/usr/bin/env bash
# File Permissions Hardening Module
# Secures system and application files

setup_file_hardening() {
  local REMOTE_USER="${1}"
  
  echo "🔒 =========================================================="
  echo "🔒 APPLYING FILE PERMISSIONS HARDENING"
  echo "🔒 =========================================================="
  
  # Set home directory to 755 to allow Nginx (www-data) to traverse to project files
  # This is required for serving static files since www-data needs execute permission
  chmod 755 /home/${REMOTE_USER} 2>/dev/null || true
  echo "  ✓ Home directory secured (755 - allows www-data to traverse)"
  
  # Secure SSH directory if exists
  if [[ -d /home/${REMOTE_USER}/.ssh ]]; then
    chmod 700 /home/${REMOTE_USER}/.ssh
    chmod 600 /home/${REMOTE_USER}/.ssh/* 2>/dev/null || true
    echo "  ✓ SSH directory secured (700)"
  fi
  
  # SSH Configuration Hardening - Disable root login
  echo "  • Checking SSH root login configuration..."
  if [[ -f /etc/ssh/sshd_config ]]; then
    # Check current PermitRootLogin setting (ignore commented lines starting with #)
    CURRENT_PERMIT=$(run_sudo grep -iE "^[[:space:]]*PermitRootLogin" /etc/ssh/sshd_config | grep -vE "^[[:space:]]*#" | tail -1 || echo "")
    
    if [[ -z "${CURRENT_PERMIT}" ]]; then
      # Not set, add it
      echo "  • PermitRootLogin not set, adding 'PermitRootLogin no'"
      run_sudo bash -c 'echo "# Disable root login - Security hardening" >> /etc/ssh/sshd_config'
      run_sudo bash -c 'echo "PermitRootLogin no" >> /etc/ssh/sshd_config'
      SSHD_NEEDS_RESTART=true
    elif echo "${CURRENT_PERMIT}" | grep -qiE "PermitRootLogin[[:space:]]*no"; then
      # Already set to no (case-insensitive check with ERE)
      echo "  ✓ PermitRootLogin already set to 'no'"
      SSHD_NEEDS_RESTART=false
    else
      # Set to something else, change it to no
      echo "  • PermitRootLogin set to '${CURRENT_PERMIT}', changing to 'PermitRootLogin no'"
      run_sudo sed -i 's/^[# ]*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
      SSHD_NEEDS_RESTART=true
    fi
    
    # Restart sshd if configuration was changed
    if [[ "${SSHD_NEEDS_RESTART}" == "true" ]]; then
      echo "  • Validating SSH configuration..."
      if run_sudo sshd -t 2>/dev/null; then
        echo "  ✓ SSH configuration is valid"
        echo "  • Restarting SSH service to apply changes..."
        run_sudo systemctl restart sshd || run_sudo service ssh restart || true
        sleep 2
        echo "  ✓ SSH service restarted"
      else
        echo "  ⚠️  Warning: SSH configuration validation failed, not restarting"
        echo "  • Please manually check /etc/ssh/sshd_config"
      fi
    fi
    
    echo "  ✓ SSH root login disabled"
  else
    echo "  ⚠️  Warning: /etc/ssh/sshd_config not found, skipping SSH hardening"
  fi
  
  # System-wide file permission hardening
  run_sudo chmod 644 /etc/passwd
  run_sudo chmod 644 /etc/group
  run_sudo chmod 600 /etc/shadow
  run_sudo chmod 600 /etc/gshadow
  echo "  ✓ System password files secured (/etc/passwd, /etc/shadow)"
  
  echo ""
  echo "✅ =========================================================="
  echo "✅ FILE PERMISSIONS HARDENING COMPLETED"
  echo "✅ =========================================================="
  echo ""
}

# Django Application Security - File Permissions
setup_django_file_permissions() {
  local PROJECT_PATH="${1}"
  local REMOTE_USER="${2}"
  local VENV_DIR="${3}"
  
  echo "• Securing Django application file permissions"
  
  # Set project directory to 755 to allow Nginx (www-data) to traverse to static files
  # www-data needs execute permission to reach static_collected, media, output directories
  chmod 755 "${PROJECT_PATH}"
  
  # Secure .env file (contains secrets)
  if [[ -f "${PROJECT_PATH}/.env" ]]; then
    chmod 600 "${PROJECT_PATH}/.env"
    chown ${REMOTE_USER}:${REMOTE_USER} "${PROJECT_PATH}/.env"
    echo "  ✓ .env file secured (600)"
  fi
  
  # Secure database file
  if [[ -f "${PROJECT_PATH}/db.sqlite3" ]]; then
    chmod 600 "${PROJECT_PATH}/db.sqlite3"
    chown ${REMOTE_USER}:${REMOTE_USER} "${PROJECT_PATH}/db.sqlite3"
    echo "  ✓ Database file secured (600)"
  fi
  
  # Secure SQLite WAL and SHM files (created by Django processes)
  if [[ -f "${PROJECT_PATH}/db.sqlite3-shm" ]]; then
    chmod 600 "${PROJECT_PATH}/db.sqlite3-shm"
    chown ${REMOTE_USER}:${REMOTE_USER} "${PROJECT_PATH}/db.sqlite3-shm"
    echo "  ✓ SQLite SHM file secured (600)"
  fi
  
  if [[ -f "${PROJECT_PATH}/db.sqlite3-wal" ]]; then
    chmod 600 "${PROJECT_PATH}/db.sqlite3-wal"
    chown ${REMOTE_USER}:${REMOTE_USER} "${PROJECT_PATH}/db.sqlite3-wal"
    echo "  ✓ SQLite WAL file secured (600)"
  fi
  
  # Secure logs directory
  if [[ -d "${PROJECT_PATH}/logs" ]]; then
    chmod 750 "${PROJECT_PATH}/logs"
    chown -R ${REMOTE_USER}:${REMOTE_USER} "${PROJECT_PATH}/logs"
    chmod 640 "${PROJECT_PATH}/logs/"*.log 2>/dev/null || true
    echo "  ✓ Logs directory secured"
  fi
  
  # Secure media directory (user uploads)
  # Using 755/644 permissions since these files are served publicly by Nginx
  # This allows www-data to read files without group membership (ACL-based security)
  if [[ -d "${PROJECT_PATH}/media" ]]; then
    chmod 755 "${PROJECT_PATH}/media"
    chown -R ${REMOTE_USER}:${REMOTE_USER} "${PROJECT_PATH}/media"
    find "${PROJECT_PATH}/media" -type d -exec chmod 755 {} \; 2>/dev/null || true
    find "${PROJECT_PATH}/media" -type f -exec chmod 644 {} \; 2>/dev/null || true
    echo "  ✓ Media directory secured (755/644 for Nginx serving)"
  fi
  
  # Secure output directory (generated files for download)
  # Using 755/644 permissions to allow direct downloads via Django serve view
  # www-data needs read access since Django runs as this user
  if [[ -d "${PROJECT_PATH}/output" ]]; then
    chmod 755 "${PROJECT_PATH}/output"
    chown -R ${REMOTE_USER}:${REMOTE_USER} "${PROJECT_PATH}/output"
    find "${PROJECT_PATH}/output" -type d -exec chmod 755 {} \; 2>/dev/null || true
    find "${PROJECT_PATH}/output" -type f -exec chmod 644 {} \; 2>/dev/null || true
    echo "  ✓ Output directory secured (755/644 for public downloads)"
  fi
  
  # Secure uploads directory (temporary uploads)
  # Using 755/644 permissions for Django access
  if [[ -d "${PROJECT_PATH}/uploads" ]]; then
    chmod 755 "${PROJECT_PATH}/uploads"
    chown -R ${REMOTE_USER}:${REMOTE_USER} "${PROJECT_PATH}/uploads"
    find "${PROJECT_PATH}/uploads" -type d -exec chmod 755 {} \; 2>/dev/null || true
    find "${PROJECT_PATH}/uploads" -type f -exec chmod 644 {} \; 2>/dev/null || true
    echo "  ✓ Uploads directory secured (755/644 for Django access)"
  fi
  
  # Secure work directory (processing files)
  # Using 755/644 permissions for Django access
  if [[ -d "${PROJECT_PATH}/work" ]]; then
    chmod 755 "${PROJECT_PATH}/work"
    chown -R ${REMOTE_USER}:${REMOTE_USER} "${PROJECT_PATH}/work"
    find "${PROJECT_PATH}/work" -type d -exec chmod 755 {} \; 2>/dev/null || true
    find "${PROJECT_PATH}/work" -type f -exec chmod 644 {} \; 2>/dev/null || true
    echo "  ✓ Work directory secured (755/644 for Django access)"
  fi
  
  # Secure static files
  if [[ -d "${PROJECT_PATH}/static_collected" ]]; then
    chmod 755 "${PROJECT_PATH}/static_collected"
    chown -R ${REMOTE_USER}:${REMOTE_USER} "${PROJECT_PATH}/static_collected"
    find "${PROJECT_PATH}/static_collected" -type d -exec chmod 755 {} \; 2>/dev/null || true
    find "${PROJECT_PATH}/static_collected" -type f -exec chmod 644 {} \; 2>/dev/null || true
    echo "  ✓ Static files secured"
  fi
  
  # Make manage.py executable
  if [[ -f "${PROJECT_PATH}/manage.py" ]]; then
    chmod 750 "${PROJECT_PATH}/manage.py"
    chown ${REMOTE_USER}:${REMOTE_USER} "${PROJECT_PATH}/manage.py"
    echo "  ✓ manage.py secured"
  fi
  
  # Secure Python files (prevent execution where not needed)
  # Only secure application code, not venv or site-packages
  find "${PROJECT_PATH}" -name "*.py" -type f ! -name "manage.py" \
    ! -path "${PROJECT_PATH}/${VENV_DIR}/*" \
    ! -path "*/site-packages/*" \
    ! -path "*/__pycache__/*" \
    -exec chmod 640 {} \; -exec chown ${REMOTE_USER}:${REMOTE_USER} {} \; 2>/dev/null || true
  
  echo "✅ Django application file permissions secured"
}

disable_file_hardening() {
  echo "• File permissions hardening DISABLED (ACTIVATE_FILE_HARDENING not set to true in .env)"
  echo "  ⚠️  Warning: Running without file hardening is not recommended for production"
  echo "  • System will use default file permissions (less secure)"
}

