#!/usr/bin/env bash
# Sensitive Files Transfer Module
# Handles upload of sensitive files that should NOT be committed to Git

#############################################################################
# Transfer Google Workspace credentials
# Arguments:
#   $1 - SCP command variable
#   $2 - SSH command variable  
#   $3 - PROJECT_ROOT path
#   $4 - REMOTE_USER
#   $5 - EC2_IP
#   $6 - APP_DIR
#############################################################################
transfer_google_workspace_credentials() {
  local SCP_CMD="$1"
  local SSH_CMD="$2"
  local PROJECT_ROOT="$3"
  local REMOTE_USER="$4"
  local EC2_IP="$5"
  local APP_DIR="$6"
  
  local GOOGLE_CREDENTIALS_LOCAL="${PROJECT_ROOT}/agent_app/tools/tools_partials/google_workspace/credentials"
  
  if [[ -d "${GOOGLE_CREDENTIALS_LOCAL}" ]]; then
    echo "🔐 Uploading Google Workspace credentials (sensitive files)..."
    
    # Upload credentials directory
    $SCP_CMD -r "${GOOGLE_CREDENTIALS_LOCAL}" "${REMOTE_USER}@${EC2_IP}:/tmp/google_credentials"
    
    # Copy to ~/.google/ directory where mcp-google-suite expects them
    $SSH_CMD "
      # Create .google directory in home
      mkdir -p ~/.google
      
      # Copy credentials to ~/.google/ (where MCP server looks)
      if [[ -f /tmp/google_credentials/oauth.keys.json ]]; then
        cp /tmp/google_credentials/oauth.keys.json ~/.google/oauth.keys.json
        chmod 600 ~/.google/oauth.keys.json
        echo '  ✓ Copied oauth.keys.json to ~/.google/'
      fi
      
      if [[ -f /tmp/google_credentials/tokens-backup.json ]]; then
        cp /tmp/google_credentials/tokens-backup.json ~/.google/server-creds.json
        chmod 600 ~/.google/server-creds.json
        echo '  ✓ Copied server-creds.json to ~/.google/'
      fi
      
      # Also keep a copy in project directory for reference
      mkdir -p /home/${REMOTE_USER}/${APP_DIR}/agent_app/tools/tools_partials/google_workspace
      rm -rf /home/${REMOTE_USER}/${APP_DIR}/agent_app/tools/tools_partials/google_workspace/credentials
      mv /tmp/google_credentials /home/${REMOTE_USER}/${APP_DIR}/agent_app/tools/tools_partials/google_workspace/credentials
      chmod 700 /home/${REMOTE_USER}/${APP_DIR}/agent_app/tools/tools_partials/google_workspace/credentials
      find /home/${REMOTE_USER}/${APP_DIR}/agent_app/tools/tools_partials/google_workspace/credentials -type f -exec chmod 600 {} \;
      
      echo '✅ Google Workspace credentials uploaded to ~/.google/ and project directory'
    "
  else
    echo "⚠️  Google Workspace credentials not found at: ${GOOGLE_CREDENTIALS_LOCAL}"
    echo "   This is normal if Google Workspace integration is not used"
  fi
}

#############################################################################
# Transfer all sensitive files (main entry point - parametric)
# Arguments:
#   $1 - SCP command variable
#   $2 - SSH command variable
#   $3 - PROJECT_ROOT path
#   $4 - REMOTE_USER
#   $5 - EC2_IP
#   $6 - APP_DIR
#   $7 - TRANSFER_SENSITIVE_FILES (comma-separated list of transfer functions)
#############################################################################
transfer_sensitive_files() {
  local SCP_CMD="$1"
  local SSH_CMD="$2"
  local PROJECT_ROOT="$3"
  local REMOTE_USER="$4"
  local EC2_IP="$5"
  local APP_DIR="$6"
  local TRANSFER_LIST="${7}"
  
  # If TRANSFER_LIST is empty, skip all transfers
  if [[ -z "${TRANSFER_LIST}" ]]; then
    echo "• No sensitive files to transfer (TRANSFER_SENSITIVE_FILES not set)"
    return 0
  fi
  
  echo ""
  echo "📦 Transferring sensitive files (not in Git): ${TRANSFER_LIST}"
  echo ""
  
  # Split comma-separated values and call each transfer function
  IFS=',' read -ra TRANSFERS <<< "${TRANSFER_LIST}"
  for transfer_name in "${TRANSFERS[@]}"; do
    # Trim whitespace
    transfer_name=$(echo "${transfer_name}" | xargs)
    
    case "${transfer_name}" in
      transfer_google_workspace_credentials)
        transfer_google_workspace_credentials "$SCP_CMD" "$SSH_CMD" "$PROJECT_ROOT" "$REMOTE_USER" "$EC2_IP" "$APP_DIR"
        ;;
      *)
        echo "⚠️  Unknown sensitive file transfer: ${transfer_name} (skipping)"
        ;;
    esac
  done
  
  echo ""
  echo "✅ Sensitive files transfer completed"
  return 0
}
