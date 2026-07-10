#!/usr/bin/env bash
# SSL Certificate Management Module
# Handles SSL certificate installation and verification

# Validate and read SSL configuration from .env file
# Returns: Sets global variables or exits on error
validate_ssl_config() {
  local ENV_FILE="${1}"
  local SCRIPT_DIR="${2}"
  
  echo "• SSL mode enabled (ACTIVATE_SSL=true)"
  
  # Read all SSL configuration from .env (required fields)
  DOMAIN=$(grep "^DOMAIN=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" | xargs || echo "")
  SSL_KEY_PASSWORD=$(grep "^SSL_KEY_PASSWORD=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" | xargs || echo "")
  SSL_CERT_LOCAL=$(grep "^SSL_CERT_LOCAL=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" | xargs || echo "")
  SSL_KEY_LOCAL=$(grep "^SSL_KEY_LOCAL=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" | xargs || echo "")
  SSL_CERT_REMOTE=$(grep "^SSL_CERT_REMOTE=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" | xargs || echo "")
  SSL_KEY_REMOTE=$(grep "^SSL_KEY_REMOTE=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" | xargs || echo "")
  
  # Validate required settings
  if [[ -z "${DOMAIN}" ]]; then
    echo "✖ Error: DOMAIN is required in .env when ACTIVATE_SSL=true"
    exit 1
  fi
  
  if [[ -z "${SSL_CERT_LOCAL}" ]]; then
    echo "✖ Error: SSL_CERT_LOCAL is required in .env when ACTIVATE_SSL=true"
    exit 1
  fi
  
  if [[ -z "${SSL_KEY_LOCAL}" ]]; then
    echo "✖ Error: SSL_KEY_LOCAL is required in .env when ACTIVATE_SSL=true"
    exit 1
  fi
  
  if [[ -z "${SSL_CERT_REMOTE}" ]]; then
    echo "✖ Error: SSL_CERT_REMOTE is required in .env when ACTIVATE_SSL=true"
    exit 1
  fi
  
  if [[ -z "${SSL_KEY_REMOTE}" ]]; then
    echo "✖ Error: SSL_KEY_REMOTE is required in .env when ACTIVATE_SSL=true"
    exit 1
  fi
  
  # Check for SSL certificate files
  SSL_CERT_FULL_PATH="${SCRIPT_DIR}/${SSL_CERT_LOCAL}"
  SSL_KEY_FULL_PATH="${SCRIPT_DIR}/${SSL_KEY_LOCAL}"
  
  if [[ ! -f "${SSL_CERT_FULL_PATH}" ]]; then
    echo "✖ Error: SSL certificate not found at ${SSL_CERT_FULL_PATH}"
    exit 1
  fi
  
  if [[ ! -f "${SSL_KEY_FULL_PATH}" ]]; then
    echo "✖ Error: SSL private key not found at ${SSL_KEY_FULL_PATH}"
    exit 1
  fi
  
  # Display SSL configuration (with debug info)
  echo "  • Domain: '${DOMAIN}' (length: ${#DOMAIN})"
  echo "  • Local certificate: ${SSL_CERT_LOCAL}"
  echo "  • Local private key: ${SSL_KEY_LOCAL}"
  echo "  • Remote certificate: ${SSL_CERT_REMOTE}"
  echo "  • Remote private key: ${SSL_KEY_REMOTE}"
  if [[ -n "${SSL_KEY_PASSWORD}" ]]; then
    echo "  • Key encryption: Yes"
  else
    echo "  • Key encryption: No"
  fi
  
  # Export variables for caller
  export DOMAIN
  export SSL_KEY_PASSWORD
  export SSL_CERT_LOCAL
  export SSL_KEY_LOCAL
  export SSL_CERT_REMOTE
  export SSL_KEY_REMOTE
  export SSL_CERT_FULL_PATH
  export SSL_KEY_FULL_PATH
}

# Upload SSL certificates to remote server
upload_ssl_certificates() {
  local SCP_CMD="${1}"
  local REMOTE_USER="${2}"
  local EC2_IP="${3}"
  
  echo "• Uploading SSL certificates to server..."
  
  # Upload certificate
  ${SCP_CMD} "${SSL_CERT_FULL_PATH}" "${REMOTE_USER}@${EC2_IP}:/tmp/ssl_cert.pem"
  echo "  ✓ Certificate uploaded"
  
  # Upload private key
  ${SCP_CMD} "${SSL_KEY_FULL_PATH}" "${REMOTE_USER}@${EC2_IP}:/tmp/ssl_key.pem"
  echo "  ✓ Private key uploaded"
  
  echo "✅ SSL certificates uploaded successfully"
}

# Install SSL certificates on remote server
setup_ssl() {
  local SSL_KEY_PASSWORD="${1}"
  local SSL_CERT_REMOTE="${2}"
  local SSL_KEY_REMOTE="${3}"
  
  echo "• Checking SSL certificates..."
  
  # Create SSL directories
  run_sudo mkdir -p /etc/ssl/certs /etc/ssl/private
  
  # Check if certificates already exist and match
  CERT_NEEDS_UPDATE=false
  KEY_NEEDS_UPDATE=false
  
  # Check certificate
  if [[ -f /tmp/ssl_cert.pem ]]; then
    if [[ -f "${SSL_CERT_REMOTE}" ]]; then
      # Compare checksums
      LOCAL_CERT_HASH=$(md5sum /tmp/ssl_cert.pem | awk '{print $1}')
      REMOTE_CERT_HASH=$(run_sudo md5sum "${SSL_CERT_REMOTE}" 2>/dev/null | awk '{print $1}' || echo "")
      
      if [[ "${LOCAL_CERT_HASH}" != "${REMOTE_CERT_HASH}" ]]; then
        echo "  • Certificate changed, will update"
        CERT_NEEDS_UPDATE=true
      else
        echo "  ✓ Certificate already installed and up-to-date"
      fi
    else
      echo "  • Certificate not found on server, will install"
      CERT_NEEDS_UPDATE=true
    fi
  else
    echo "  ⚠️  Warning: Certificate file not found in /tmp/"
    CERT_NEEDS_UPDATE=false
  fi
  
  # Check private key (need to handle encrypted keys)
  if [[ -f /tmp/ssl_key.pem ]]; then
    # First, prepare the key (decrypt if needed)
    if [[ -n "${SSL_KEY_PASSWORD}" ]]; then
      if openssl pkey -in /tmp/ssl_key.pem -out /tmp/decrypted_key.pem -passin pass:"${SSL_KEY_PASSWORD}" 2>/dev/null; then
        KEY_FILE_TO_CHECK="/tmp/decrypted_key.pem"
      else
        echo "  ⚠️  Failed to decrypt key, using as-is"
        KEY_FILE_TO_CHECK="/tmp/ssl_key.pem"
      fi
    else
      KEY_FILE_TO_CHECK="/tmp/ssl_key.pem"
    fi
    
    if [[ -f "${SSL_KEY_REMOTE}" ]]; then
      # Compare checksums
      LOCAL_KEY_HASH=$(md5sum "${KEY_FILE_TO_CHECK}" | awk '{print $1}')
      REMOTE_KEY_HASH=$(run_sudo md5sum "${SSL_KEY_REMOTE}" 2>/dev/null | awk '{print $1}' || echo "")
      
      if [[ "${LOCAL_KEY_HASH}" != "${REMOTE_KEY_HASH}" ]]; then
        echo "  • Private key changed, will update"
        KEY_NEEDS_UPDATE=true
      else
        echo "  ✓ Private key already installed and up-to-date"
      fi
    else
      echo "  • Private key not found on server, will install"
      KEY_NEEDS_UPDATE=true
    fi
  else
    echo "  ⚠️  Warning: Private key file not found in /tmp/"
    KEY_NEEDS_UPDATE=false
  fi
  
  # Install certificate if needed
  if [[ "${CERT_NEEDS_UPDATE}" == "true" ]]; then
    echo "  • Installing certificate..."
    run_sudo mv /tmp/ssl_cert.pem "${SSL_CERT_REMOTE}"
    run_sudo chmod 644 "${SSL_CERT_REMOTE}"
    run_sudo chown root:root "${SSL_CERT_REMOTE}" 2>/dev/null || true
    echo "  ✓ Certificate installed at ${SSL_CERT_REMOTE}"
  else
    # Clean up uploaded file if not needed
    rm -f /tmp/ssl_cert.pem
  fi
  
  # Install private key if needed
  if [[ "${KEY_NEEDS_UPDATE}" == "true" ]]; then
    echo "  • Installing private key..."
    if [[ -f /tmp/decrypted_key.pem ]]; then
      run_sudo mv /tmp/decrypted_key.pem "${SSL_KEY_REMOTE}"
    elif [[ -f /tmp/ssl_key.pem ]]; then
      run_sudo mv /tmp/ssl_key.pem "${SSL_KEY_REMOTE}"
    fi
    run_sudo chmod 600 "${SSL_KEY_REMOTE}"
    run_sudo chown root:root "${SSL_KEY_REMOTE}" 2>/dev/null || true
    echo "  ✓ Private key installed at ${SSL_KEY_REMOTE}"
  else
    # Clean up uploaded files if not needed
    rm -f /tmp/ssl_key.pem /tmp/decrypted_key.pem
  fi
  
  # Summary
  if [[ "${CERT_NEEDS_UPDATE}" == "true" ]] || [[ "${KEY_NEEDS_UPDATE}" == "true" ]]; then
    echo "✅ SSL certificates updated successfully"
  else
    echo "✅ SSL certificates already up-to-date (no changes needed)"
  fi
}

disable_ssl() {
  echo "• SSL DISABLED (ACTIVATE_SSL not set to true in .env)"
  echo "  • Deployment will use HTTP only (no HTTPS)"
}
