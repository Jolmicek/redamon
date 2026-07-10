#!/usr/bin/env bash
# Nginx Web Server Module
# Manages Nginx configuration with modular config file support

# Setup ACL-based permissions for www-data (more secure than group membership)
setup_nginx_acl() {
  local REMOTE_USER="${1}"
  
  echo "• Setting up ACL-based permissions for www-data (socket access only)"

  # Check if ACL tools are installed, install if missing
  if ! command -v setfacl &>/dev/null || ! command -v getfacl &>/dev/null; then
    echo "  • ACL tools not found, installing acl package..."
    run_sudo apt-get update -qq
    run_sudo DEBIAN_FRONTEND=noninteractive apt-get install -y acl
    
    # Verify installation
    if command -v setfacl &>/dev/null && command -v getfacl &>/dev/null; then
      echo "  ✓ ACL tools installed successfully"
    else
      echo "  ⚠️  ACL installation failed, will use group-based fallback"
    fi
  else
    echo "  ✓ ACL tools already available"
  fi

  # Check if ACL is supported
  if command -v setfacl &>/dev/null && command -v getfacl &>/dev/null; then
    # Ensure www-data is NOT in ubuntu group (remove if exists)
    if id -nG www-data | grep -qw "${REMOTE_USER}"; then
      echo "  • Removing www-data from ${REMOTE_USER} group (using ACL instead)"
      run_sudo gpasswd -d www-data ${REMOTE_USER} 2>/dev/null || true
    fi
    
    # Test if filesystem supports ACLs
    echo "  • Testing filesystem ACL support..."
    run_sudo mkdir -p /run/gunicorn
    if run_sudo setfacl -m u:www-data:rwx /run/gunicorn 2>/dev/null; then
      echo "  ✓ Filesystem supports ACLs - will be applied via systemd ExecStartPost"
      # Clean up test ACL (systemd will apply it on service start)
      run_sudo setfacl -x u:www-data /run/gunicorn 2>/dev/null || true
    else
      echo "  ⚠️  Filesystem does not support ACLs"
      echo "  • Falling back to group-based permissions"
      run_sudo usermod -a -G ${REMOTE_USER} www-data
    fi
  else
    echo "  ⚠️  ACL tools not available, falling back to group-based permissions"
    echo "  • Adding www-data to ${REMOTE_USER} group (less secure fallback)"
    run_sudo usermod -a -G ${REMOTE_USER} www-data
  fi
}

# Create Nginx configuration using modular config files
# NGINX_CONFIG_FILE is REQUIRED and specifies which config to use:
#   - nginx_default_http.sh   : HTTP only (no SSL)
#   - nginx_default_https.sh  : Full HTTPS with HTTP->HTTPS redirect
#   - nginx_config_csm.sh     : CSM custom (HTTP + SSL only for /csm_api/)
#   - Or any custom config file
setup_nginx_config() {
  local APP_DIR="${1}"
  local PROJECT_PATH="${2}"
  local ACTIVATE_SSL="${3}"
  local ACTIVATE_WEBSOCKET="${4}"
  local DOMAIN="${5}"
  local SSL_CERT_REMOTE="${6}"
  local SSL_KEY_REMOTE="${7}"
  local NGINX_SERVER_NAMES="${8}"
  local GUNICORN_NGINX_KEEPALIVE="${9}"
  local NGINX_CONFIG_FILE="${10}"
  
  echo "• Configuring Nginx"
  
  # Disable default site
  run_sudo rm -f /etc/nginx/sites-enabled/default

  # NGINX_CONFIG_FILE is required
  if [[ -z "${NGINX_CONFIG_FILE}" ]]; then
    echo ""
    echo "❌ =========================================================="
    echo "❌ CRITICAL ERROR: NGINX_CONFIG_FILE is required"
    echo "❌ =========================================================="
    echo ""
    echo "Please set NGINX_CONFIG_FILE in your .env file."
    echo "Available options:"
    echo "  - nginx_default_http.sh   : HTTP only (no SSL)"
    echo "  - nginx_default_https.sh  : Full HTTPS with HTTP->HTTPS redirect"
    echo "  - nginx_config_csm.sh     : CSM custom (HTTP + SSL only for /csm_api/)"
    echo ""
    exit 1
  fi

  local CONFIG_PATH="/tmp/deploy_modules/nginx_config/${NGINX_CONFIG_FILE}"
  
  if [[ ! -f "${CONFIG_PATH}" ]]; then
    echo ""
    echo "❌ =========================================================="
    echo "❌ CRITICAL ERROR: Nginx config file not found"
    echo "❌ =========================================================="
    echo ""
    echo "File not found: ${CONFIG_PATH}"
    echo ""
    echo "Available config files:"
    ls -la /tmp/deploy_modules/nginx_config/ 2>/dev/null || echo "  (directory not found)"
    echo ""
    exit 1
  fi

  echo "• Using Nginx configuration: ${NGINX_CONFIG_FILE}"
  
  # Source the config file (defines create_nginx_config function)
  source "${CONFIG_PATH}"
  
  # Call the standardized create_nginx_config function
  # All config files must implement this function with the same signature
  create_nginx_config "${PROJECT_PATH}" "${ACTIVATE_WEBSOCKET}" "${DOMAIN}" "${SSL_CERT_REMOTE}" "${SSL_KEY_REMOTE}" "${NGINX_SERVER_NAMES}" "${GUNICORN_NGINX_KEEPALIVE}" "${SEO_INDEX}"

  # Move to final location with sudo
  run_sudo cp /tmp/nginx_config /etc/nginx/sites-available/${APP_DIR}
  rm -f /tmp/nginx_config

  # Enable our site
  run_sudo ln -sf /etc/nginx/sites-available/${APP_DIR} /etc/nginx/sites-enabled/
  
  echo "✅ Nginx configuration completed"
}
