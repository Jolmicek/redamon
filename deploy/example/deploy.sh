#!/usr/bin/env bash
set -euo pipefail

########################################################################
# CONFIG  – adjust or export these variables before calling the script
########################################################################
# REPO_BRANCH will be read from .env file (see below)
# GIT_TOKEN will be read from .env file (see below)
APP_DIR="PMAG"                 # remote directory for the repo
PYTHON_EXEC="python3"          # interpreter to use for the venv (changed from python3.11)
VENV_DIR="venv"               # created inside ${APP_DIR}
GUNICORN_PORT="8000"          # port for Gunicorn

# Files to preserve during deployment updates (space-separated)
PRESERVE_FILES="db.sqlite3"
# Directories to preserve during deployment updates (space-separated)
PRESERVE_DIRS="static/output static/input logs media work" #agent_app/tools/tools_partials/analyze_pdf_contracts
########################################################################

usage() {
  echo "Usage: $0 <EC2_IP> <AUTH> <REMOTE_USER> <MODE> <CLIENT_NAME> [full]"
  echo "  AUTH: path/to/key.pem  |  pass  |  pass:<password>"
  echo "  MODE: update | init"
  echo "  CLIENT_NAME: pmag | mamoli | csm | <other_client> (REQUIRED)"
  echo "  full: optional flag for 'update' mode to recreate virtual environment"
  echo ""
  echo "Client Configuration:"
  echo "  CLIENT_NAME determines which .env file and client_variants to use:"
  echo "  - 'pmag': Uploads entire client_variants directory, uses .env.pmag"
  echo "  - 'mamoli': Uploads only client_variants/mamoli/, uses .env.mamoli"
  echo "  - 'csm': Uploads only client_variants/csm/, uses .env.csm"
  echo "  - '<other>': Uploads only client_variants/<other>/, uses .env.<other>"
  echo ""
  echo "Required .env.global Configuration:"
  echo "  GIT_TOKEN=your-azure-devops-token    # Required in .env.global - Azure DevOps Personal Access Token"
  echo ""
  echo "Required .env.<client> Configuration:"
  echo "  REPO_BRANCH=develop                              # Git branch to deploy (e.g., develop, prod/clientvar-mamoli)"
  echo ""
  echo "SSL Configuration (all in .env file):"
  echo "  ACTIVATE_SSL=true                               # Nginx: Enable HTTPS"
  echo "  ENFORCE_DJANGO_WITH_SSL=true                    # Django: Secure cookies (false for mixed HTTP/HTTPS)"
  echo "  DOMAIN=your-domain.com                          # Required"
  echo "  SSL_CERT_LOCAL=cert/your_cert.pem               # Required - local certificate path"
  echo "  SSL_KEY_LOCAL=cert/your_key.pem                 # Required - local key path"
  echo "  SSL_CERT_REMOTE=/etc/ssl/certs/cert.pem         # Required - remote certificate path"
  echo "  SSL_KEY_REMOTE=/etc/ssl/private/key.pem         # Required - remote key path"
  echo "  CSRF_TRUSTED_ORIGINS=https://your-domain.com    # Required - Django CSRF (use http:// for mixed SSL)"
  echo "  SSL_KEY_PASSWORD=password                       # Optional - if key encrypted"
  echo ""
  echo "Security Features (all in .env file):"
  echo "  ACTIVATE_FAIL2BAN=true                          # Enable Fail2ban intrusion prevention"
  echo "  ACTIVATE_ANTIVIRUS=true                         # Enable ClamAV antivirus scanning"
  echo "  ACTIVATE_FILE_HARDENING=true                    # Enable file permissions hardening (default: true)"
  echo "  SEO_INDEX=false                                 # Block search engine indexing (default: false)"
  echo ""
  echo "Django Admin Configuration (all in .env file):"
  echo "  ADMIN_INITIAL_PASSWORD=your-secure-password     # Initial admin password (default: 'admin' if not set)"
  echo ""
  echo "Advanced Deployment Options (all in .env file):"
  echo "  TRANSFER_SENSITIVE_FILES=transfer_google_workspace_credentials    # Comma-separated list of sensitive file transfers"
  echo "  PATCH_SCRIPTS=google_workspace                                    # Comma-separated list of post-install patches"
  echo ""
  echo "Examples (key-based):"
  echo "  $0 1.2.3.4 ~/.ssh/key.pem ubuntu update pmag      # Normal update for pmag"
  echo "  $0 1.2.3.4 ~/.ssh/key.pem ubuntu update pmag full # Update with venv recreation"
  echo "  $0 1.2.3.4 ~/.ssh/key.pem ubuntu init mamoli      # Full initialization for mamoli"
  echo ""
  echo "Examples (password-based, requires sshpass on local machine):"
  echo "  $0 1.2.3.4 pass ubuntu update csm                # Prompt for password, deploy csm"
  echo "  $0 1.2.3.4 pass:MySecret ubuntu update mamoli    # Password provided inline"
  exit 1
}

# Parse parameters (accept 5 or 6 parameters)
[[ $# -lt 5 || $# -gt 6 ]] && usage
EC2_IP="$1"
AUTH_ARG="$2"
REMOTE_USER="$3"
MODE="$4"
CLIENT_NAME="$5"
FULL_FLAG="${6:-}"

# Validate mode
[[ ! "$MODE" =~ ^(update|init)$ ]] && usage

# Validate CLIENT_NAME is not empty
if [[ -z "$CLIENT_NAME" ]]; then
  echo "✖ Error: CLIENT_NAME is required."
  echo "  Please specify the client name as the 5th parameter."
  echo "  Valid options: pmag, mamoli, csm, or other client name"
  usage
fi

# Validate full flag - only allowed with update mode
if [[ -n "$FULL_FLAG" ]]; then
  if [[ "$FULL_FLAG" != "full" ]]; then
    echo "✖ Invalid flag: $FULL_FLAG. Only 'full' is allowed as 6th parameter."
    exit 1
  fi
  if [[ "$MODE" != "update" ]]; then
    echo "✖ 'full' flag can only be used with 'update' mode."
    exit 1
  fi
fi

echo "• Client name: ${CLIENT_NAME}"

# Determine authentication mode (key or password)
AUTH_MODE=""
SSH_PASSWORD=""

if [[ -f "${AUTH_ARG}" ]]; then
  AUTH_MODE="key"
  PEM="${AUTH_ARG}"
elif [[ "${AUTH_ARG}" == "pass" || "${AUTH_ARG}" == "-" ]]; then
  AUTH_MODE="password"
  # Prompt securely for password
  read -r -s -p "SSH password for ${REMOTE_USER}@${EC2_IP}: " SSH_PASSWORD
  echo ""
elif [[ "${AUTH_ARG}" == pass:* ]]; then
  AUTH_MODE="password"
  SSH_PASSWORD="${AUTH_ARG#pass:}"
else
  # Treat as literal password if it's not a file
  AUTH_MODE="password"
  SSH_PASSWORD="${AUTH_ARG}"
fi

#############################################################################
# SSH Connection Multiplexing (reuse single connection to avoid rate limiting)
#############################################################################
SSH_CONTROL_PATH="/tmp/ssh-deploy-${EC2_IP}-$$"

cleanup_ssh() {
  # Close the SSH multiplexed connection on exit
  if [[ -S "${SSH_CONTROL_PATH}" ]]; then
    ssh -o ControlPath="${SSH_CONTROL_PATH}" -O exit "${REMOTE_USER}@${EC2_IP}" 2>/dev/null || true
  fi
}
trap cleanup_ssh EXIT

# SSH multiplexing options: reuse single persistent connection
SSH_MUX_OPTS="-o ControlMaster=auto -o ControlPath=${SSH_CONTROL_PATH} -o ControlPersist=60"
SSH_COMMON_OPTS="-o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30 -o ServerAliveCountMax=5 ${SSH_MUX_OPTS}"

if [[ "${AUTH_MODE}" == "key" ]]; then
  SSH="ssh ${SSH_COMMON_OPTS} -i ${PEM} ${REMOTE_USER}@${EC2_IP}"
  SCP="scp -q ${SSH_COMMON_OPTS} -i ${PEM}"
else
  # Require sshpass for password-based auth
  if ! command -v sshpass >/dev/null 2>&1; then
    echo "✖ 'sshpass' not found on local machine. Install it (e.g., 'sudo apt-get install -y sshpass') or use a PEM key."
    exit 1
  fi
  # Use env var mode to avoid quoting issues and force password/keyboard-interactive auth
  export SSHPASS="${SSH_PASSWORD}"
  SSH="sshpass -e ssh -o PreferredAuthentications=password,keyboard-interactive -o PubkeyAuthentication=no ${SSH_COMMON_OPTS} ${REMOTE_USER}@${EC2_IP}"
  SCP="sshpass -e scp -o PreferredAuthentications=password,keyboard-interactive -o PubkeyAuthentication=no -q ${SSH_COMMON_OPTS}"
fi

# Establish the master SSH connection upfront
echo "• Establishing SSH connection..."
$SSH "echo 'SSH connection established'" || { echo "✖ Failed to establish SSH connection"; exit 1; }

#############################################################################
# Locate .env file based on CLIENT_NAME
#############################################################################
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"

# Select .env file based on CLIENT_NAME
if [[ "${CLIENT_NAME}" == "pmag" ]]; then
  ENV_FILE="${SCRIPT_DIR}/.env.pmag"
elif [[ "${CLIENT_NAME}" == "mamoli" ]]; then
  ENV_FILE="${SCRIPT_DIR}/.env.mamoli"
else
  # For other clients, try client-specific file first, then fall back to generic
  CLIENT_ENV_FILE="${SCRIPT_DIR}/.env.${CLIENT_NAME}"
  if [[ -f "${CLIENT_ENV_FILE}" ]]; then
    ENV_FILE="${CLIENT_ENV_FILE}"
  else
    ENV_FILE="${SCRIPT_DIR}/.env"
  fi
fi

echo "• Using environment file: $(basename "${ENV_FILE}") for client: ${CLIENT_NAME}"

#############################################################################
# Read GIT_TOKEN from .env.global file (REQUIRED)
#############################################################################
ENV_GLOBAL_FILE="${SCRIPT_DIR}/.env.global"

if [[ -f "${ENV_GLOBAL_FILE}" ]]; then
  GIT_TOKEN=$(grep "^GIT_TOKEN=" "${ENV_GLOBAL_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" | xargs || echo "")
else
  GIT_TOKEN=""
fi

# Validate GIT_TOKEN is set
if [[ -z "${GIT_TOKEN}" ]]; then
  echo "✖ Error: GIT_TOKEN is required in .env.global file"
  echo "  Please add GIT_TOKEN=your-token to ${ENV_GLOBAL_FILE}"
  exit 1
fi

# Construct REPO_URL using GIT_TOKEN from .env
REPO_URL="https://beta80-rpalob7:${GIT_TOKEN}@dev.azure.com/beta80-rpalob7/PMAG/_git/PMAG"

echo "• Git token loaded from .env.global file (length: ${#GIT_TOKEN} characters)"

#############################################################################
# Read activation flags from LOCAL .env file (to pass to SSH sessions)
#############################################################################
LOCAL_ACTIVATE_FAIL2BAN="false"
LOCAL_ACTIVATE_ANTIVIRUS="false"
LOCAL_ACTIVATE_SSL="false"
LOCAL_ACTIVATE_FILE_HARDENING="true"  # Default to true for security
LOCAL_RUN_LOCAL_KNOWLEDGE_BASE_CONTAINER="false"
LOCAL_RUN_LOCAL_BROWSER_USE_CONTAINER="false"
LOCAL_BROWSER_USE_MAX_CONCURRENT_SESSIONS="2"
LOCAL_ACTIVATE_WEBSOCKET="false"
LOCAL_SEO_INDEX="false"  # Default to false for private applications
LOCAL_RUN_LOCAL_KEYCLOAK_CONTAINER="false"
LOCAL_KEYCLOAK_ENABLED="false"
LOCAL_KEYCLOAK_SERVER_URL=""
LOCAL_KEYCLOAK_REALM=""
LOCAL_KEYCLOAK_CLIENT_ID=""
LOCAL_KEYCLOAK_CLIENT_SECRET=""
LOCAL_KEYCLOAK_ROLE_MAPPING=""
LOCAL_KEYCLOAK_ADMIN_PASSWORD=""
LOCAL_KEYCLOAK_DB_STORAGE="internal"
LOCAL_KEYCLOAK_DB_USERNAME="keycloak"
LOCAL_KEYCLOAK_DB_PASSWORD=""
LOCAL_KEYCLOAK_DB_MASTER_USERNAME="postgres"
LOCAL_POSTGRES_PASSWORD=""
GUNICORN_NGINX_KEEPALIVE=""
GUNICORN_BACKLOG=""
TRANSFER_SENSITIVE_FILES=""
PATCH_SCRIPTS=""
NGINX_CONFIG_FILE=""

if [[ -f "${ENV_FILE}" ]]; then
  REPO_BRANCH=$(grep "^REPO_BRANCH=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
  LOCAL_ACTIVATE_FAIL2BAN=$(grep "^ACTIVATE_FAIL2BAN=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "false")
  LOCAL_ACTIVATE_ANTIVIRUS=$(grep "^ACTIVATE_ANTIVIRUS=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "false")
  LOCAL_ACTIVATE_SSL=$(grep "^ACTIVATE_SSL=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "false")
  LOCAL_ACTIVATE_FILE_HARDENING=$(grep "^ACTIVATE_FILE_HARDENING=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "true")
  LOCAL_RUN_LOCAL_KNOWLEDGE_BASE_CONTAINER=$(grep "^RUN_LOCAL_KNOWLEDGE_BASE_CONTAINER=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "false")
  LOCAL_RUN_LOCAL_BROWSER_USE_CONTAINER=$(grep "^RUN_LOCAL_BROWSER_USE_CONTAINER=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" | tr '[:upper:]' '[:lower:]' || echo "false")
  if [[ "${LOCAL_RUN_LOCAL_BROWSER_USE_CONTAINER}" == "true" ]]; then
    LOCAL_BROWSER_USE_MAX_CONCURRENT_SESSIONS=$(grep "^BROWSER_USE_MAX_CONCURRENT_SESSIONS=" "${ENV_FILE}" | cut -d'=' -f2 | sed 's/#.*//' | tr -d '"' | tr -d "'" | tr -d ' ')
    if [[ -z "${LOCAL_BROWSER_USE_MAX_CONCURRENT_SESSIONS}" ]]; then
      echo "✖ Error: BROWSER_USE_MAX_CONCURRENT_SESSIONS is required when RUN_LOCAL_BROWSER_USE_CONTAINER=true"
      echo "  Please add BROWSER_USE_MAX_CONCURRENT_SESSIONS=<number> to ${ENV_FILE}"
      exit 1
    fi
  fi
  LOCAL_RUN_LOCAL_KEYCLOAK_CONTAINER=$(grep "^RUN_LOCAL_KEYCLOAK_CONTAINER=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" | tr '[:upper:]' '[:lower:]' || echo "false")
  LOCAL_KEYCLOAK_ENABLED=$(grep "^KEYCLOAK_ENABLED=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" | tr '[:upper:]' '[:lower:]' || echo "false")
  LOCAL_KEYCLOAK_SERVER_URL=$(grep "^KEYCLOAK_SERVER_URL=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
  LOCAL_KEYCLOAK_REALM=$(grep "^KEYCLOAK_REALM=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
  LOCAL_KEYCLOAK_CLIENT_ID=$(grep "^KEYCLOAK_CLIENT_ID=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
  LOCAL_KEYCLOAK_CLIENT_SECRET=$(grep "^KEYCLOAK_CLIENT_SECRET=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
  LOCAL_KEYCLOAK_ROLE_MAPPING=$(grep "^KEYCLOAK_ROLE_MAPPING=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
  LOCAL_KEYCLOAK_ADMIN_PASSWORD=$(grep "^KEYCLOAK_ADMIN_PASSWORD=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
  LOCAL_KEYCLOAK_DB_STORAGE=$(grep "^KEYCLOAK_DB_STORAGE=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "internal")
  LOCAL_KEYCLOAK_DB_USERNAME=$(grep "^KEYCLOAK_DB_USERNAME=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "keycloak")
  LOCAL_KEYCLOAK_DB_PASSWORD=$(grep "^KEYCLOAK_DB_PASSWORD=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
  LOCAL_KEYCLOAK_DB_MASTER_USERNAME=$(grep "^KEYCLOAK_DB_MASTER_USERNAME=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "postgres")
  LOCAL_POSTGRES_PASSWORD=$(grep "^POSTGRES_PASSWORD=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
  LOCAL_ACTIVATE_WEBSOCKET=$(grep "^ACTIVATE_WEBSOCKET=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "false")
  LOCAL_SEO_INDEX=$(grep "^SEO_INDEX=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "false")
  GUNICORN_NGINX_KEEPALIVE=$(grep "^GUNICORN_NGINX_KEEPALIVE=" "${ENV_FILE}" | cut -d'=' -f2 | sed 's/#.*//' | tr -d '"' | tr -d "'" | xargs || echo "")
  GUNICORN_BACKLOG=$(grep "^GUNICORN_BACKLOG=" "${ENV_FILE}" | cut -d'=' -f2 | sed 's/#.*//' | tr -d '"' | tr -d "'" | xargs || echo "")
  TRANSFER_SENSITIVE_FILES=$(grep "^TRANSFER_SENSITIVE_FILES=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
  PATCH_SCRIPTS=$(grep "^PATCH_SCRIPTS=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
  NGINX_CONFIG_FILE=$(grep "^NGINX_CONFIG_FILE=" "${ENV_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
fi

# Validate REPO_BRANCH is set
if [[ -z "${REPO_BRANCH}" ]]; then
  echo "✖ Error: REPO_BRANCH is required in .env file"
  echo "  Please add REPO_BRANCH=<branch-name> to ${ENV_FILE}"
  exit 1
fi

echo "• Branch to deploy: ${REPO_BRANCH}"

echo "• Local .env activation flags:"
echo "  - ACTIVATE_FAIL2BAN: ${LOCAL_ACTIVATE_FAIL2BAN}"
echo "  - ACTIVATE_ANTIVIRUS: ${LOCAL_ACTIVATE_ANTIVIRUS}"
echo "  - ACTIVATE_SSL: ${LOCAL_ACTIVATE_SSL}"
echo "  - ACTIVATE_FILE_HARDENING: ${LOCAL_ACTIVATE_FILE_HARDENING}"
echo "  - RUN_LOCAL_KNOWLEDGE_BASE_CONTAINER: ${LOCAL_RUN_LOCAL_KNOWLEDGE_BASE_CONTAINER}"
echo "  - RUN_LOCAL_BROWSER_USE_CONTAINER: ${LOCAL_RUN_LOCAL_BROWSER_USE_CONTAINER}"
echo "  - BROWSER_USE_MAX_CONCURRENT_SESSIONS: ${LOCAL_BROWSER_USE_MAX_CONCURRENT_SESSIONS}"
echo "  - ACTIVATE_WEBSOCKET: ${LOCAL_ACTIVATE_WEBSOCKET}"
echo "  - SEO_INDEX: ${LOCAL_SEO_INDEX}"
echo "• Deployment customization:"
echo "  - TRANSFER_SENSITIVE_FILES: ${TRANSFER_SENSITIVE_FILES:-none}"
echo "  - PATCH_SCRIPTS: ${PATCH_SCRIPTS:-none}"
echo "  - NGINX_CONFIG_FILE: ${NGINX_CONFIG_FILE:-default}"

#############################################################################
# Read SSL configuration from .env file (using ssl.sh module)
#############################################################################
# Initialize SSL variables (required even when SSL is disabled)
ACTIVATE_SSL="${LOCAL_ACTIVATE_SSL}"
SSL_KEY_PASSWORD=""
SSL_CERT_REMOTE=""
SSL_KEY_REMOTE=""
DOMAIN=""

# Source SSL module for configuration validation
source "${SCRIPT_DIR}/modules/ssl.sh"

if [[ -f "${ENV_FILE}" ]]; then
  if [[ "${ACTIVATE_SSL}" == "true" ]]; then
    # Call module function to validate and read SSL config
    validate_ssl_config "${ENV_FILE}" "${SCRIPT_DIR}"
  else
    echo "• SSL mode disabled (ACTIVATE_SSL not set to true)"
  fi
fi

echo "➜ Connecting to ${EC2_IP} as ${REMOTE_USER} (mode=${MODE}${FULL_FLAG:+ $FULL_FLAG})…"

#############################################################################
# Upload deployment modules to server (BEFORE SSH sessions)
#############################################################################
MODULES_DIR="${SCRIPT_DIR}/modules"

if [[ -d "${MODULES_DIR}" ]]; then
  echo "• Uploading deployment modules..."
  
  # Remove old modules directory on server to avoid nesting issues
  $SSH "rm -rf /tmp/deploy_modules"
  
  # Upload fresh modules directory
  $SCP -r "${MODULES_DIR}" "${REMOTE_USER}@${EC2_IP}:/tmp/deploy_modules"
  
  echo "✅ Deployment modules uploaded"
else
  echo "⚠️  Warning: Modules directory not found at ${MODULES_DIR}"
  exit 1
fi

#############################################################################
# All remaining steps run on the EC2 instance - PART 1: System Setup
#############################################################################
# For password auth, use the same password for sudo (common setup)
if [[ "${AUTH_MODE}" == "password" ]]; then
  SUDO_PASS="${SSH_PASSWORD}"
else
  SUDO_PASS=""
fi
$SSH APP_DIR="${APP_DIR}" REPO_URL="${REPO_URL}" REPO_BRANCH="${REPO_BRANCH}" PYTHON_EXEC="${PYTHON_EXEC}" VENV_DIR="${VENV_DIR}" MODE="${MODE}" FULL_FLAG="${FULL_FLAG}" REMOTE_USER="${REMOTE_USER}" GUNICORN_PORT="${GUNICORN_PORT}" EC2_IP="${EC2_IP}" CLIENT_NAME="${CLIENT_NAME}" PRESERVE_FILES="\"${PRESERVE_FILES}\"" PRESERVE_DIRS="\"${PRESERVE_DIRS}\"" ACTIVATE_FAIL2BAN="${LOCAL_ACTIVATE_FAIL2BAN}" ACTIVATE_ANTIVIRUS="${LOCAL_ACTIVATE_ANTIVIRUS}" ACTIVATE_SSL="${LOCAL_ACTIVATE_SSL}" ACTIVATE_FILE_HARDENING="${LOCAL_ACTIVATE_FILE_HARDENING}" RUN_LOCAL_KNOWLEDGE_BASE_CONTAINER="${LOCAL_RUN_LOCAL_KNOWLEDGE_BASE_CONTAINER}" RUN_LOCAL_BROWSER_USE_CONTAINER="${LOCAL_RUN_LOCAL_BROWSER_USE_CONTAINER}" BROWSER_USE_MAX_CONCURRENT_SESSIONS="${LOCAL_BROWSER_USE_MAX_CONCURRENT_SESSIONS}" ACTIVATE_WEBSOCKET="${LOCAL_ACTIVATE_WEBSOCKET}" SEO_INDEX="${LOCAL_SEO_INDEX}" SUDO_PASSWORD="${SUDO_PASS}" bash -s <<'EOF'
set -euo pipefail

APP_DIR="${APP_DIR}"
REPO_URL="${REPO_URL}"
REPO_BRANCH="${REPO_BRANCH}"
PYTHON_EXEC="${PYTHON_EXEC}"
VENV_DIR="${VENV_DIR}"
MODE="${MODE}"
FULL_FLAG="${FULL_FLAG}"
REMOTE_USER="${REMOTE_USER}"
GUNICORN_PORT="${GUNICORN_PORT}"
EC2_IP="${EC2_IP}"
CLIENT_NAME="${CLIENT_NAME}"
PRESERVE_FILES="${PRESERVE_FILES}"
PRESERVE_DIRS="${PRESERVE_DIRS}"
ACTIVATE_FAIL2BAN="${ACTIVATE_FAIL2BAN}"
ACTIVATE_ANTIVIRUS="${ACTIVATE_ANTIVIRUS}"
ACTIVATE_SSL="${ACTIVATE_SSL}"
ACTIVATE_FILE_HARDENING="${ACTIVATE_FILE_HARDENING}"
RUN_LOCAL_KNOWLEDGE_BASE_CONTAINER="${RUN_LOCAL_KNOWLEDGE_BASE_CONTAINER}"
RUN_LOCAL_BROWSER_USE_CONTAINER="${RUN_LOCAL_BROWSER_USE_CONTAINER}"
BROWSER_USE_MAX_CONCURRENT_SESSIONS="${BROWSER_USE_MAX_CONCURRENT_SESSIONS}"
ACTIVATE_WEBSOCKET="${ACTIVATE_WEBSOCKET}"
SEO_INDEX="${SEO_INDEX}"

#############################################################################
# Helper functions
#############################################################################
# Helper to run sudo commands with password if needed
run_sudo() {
  if [[ -n "${SUDO_PASSWORD:-}" ]]; then
    echo "${SUDO_PASSWORD}" | sudo -S "$@"
  else
    sudo "$@"
  fi
}

# Helper — install packages via apt if missing
install_if_missing () {
  for pkg in "$@"; do
    dpkg -s "$pkg" &>/dev/null && continue
    echo "• Installing $pkg…"
    run_sudo apt-get update
    run_sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg"
  done
}

#############################################################################
# Essentials, Nginx and Docker (always install Docker for Redis + optional knowledge base)
#############################################################################
install_if_missing git curl jq nginx

# OpenCV/Docling dependencies (required for document processing with OCR)
install_if_missing libgl1 libglib2.0-0 libsm6 libxrender1 libxext6

# python-magic dependency (required for file type detection in security_utils)
install_if_missing libmagic1

# poppler binaries (pdftoppm/pdfinfo) — required by pdf2image for PDF→image rendering
# in the multimodal extraction engine (e.g. csm vision pipeline)
install_if_missing poppler-utils

# Fail2ban activation flag passed from local .env
echo "• Fail2ban intrusion prevention activation: ${ACTIVATE_FAIL2BAN}"

# Activation flags passed from local .env (no need to re-read from remote)
echo "• Knowledge container initialization: ${RUN_LOCAL_KNOWLEDGE_BASE_CONTAINER}"
echo "• Browser Use container initialization: ${RUN_LOCAL_BROWSER_USE_CONTAINER}"
echo "• WebSocket support activation: ${ACTIVATE_WEBSOCKET}"

# ClamAV activation flag passed from local .env
echo "• ClamAV antivirus activation: ${ACTIVATE_ANTIVIRUS}"

#############################################################################
# Load deployment modules (modular architecture)
#############################################################################
SCRIPT_DIR_REMOTE="/tmp/deploy_modules"
source "${SCRIPT_DIR_REMOTE}/_common.sh"
source "${SCRIPT_DIR_REMOTE}/fail2ban.sh"
source "${SCRIPT_DIR_REMOTE}/antivirus.sh"
source "${SCRIPT_DIR_REMOTE}/file_hardening.sh"

#############################################################################
# Fail2ban Intrusion Prevention System (conditional based on ACTIVATE_FAIL2BAN from .env)
#############################################################################
if [[ "${ACTIVATE_FAIL2BAN}" == "true" ]]; then
  setup_fail2ban "${REMOTE_USER}" "${APP_DIR}"
else
  disable_fail2ban
fi

# ================================================================
# ALWAYS INSTALL DOCKER - Required for Redis (and optional knowledge base)
# ================================================================
echo "• Installing Docker and Docker Compose (required for Redis + Celery)..."

if ! command -v docker &> /dev/null; then
  echo "• Installing Docker..."
  run_sudo apt-get update
  run_sudo apt-get install -y docker.io docker-compose
  
  # Add user to docker group
  run_sudo usermod -aG docker ${REMOTE_USER}
  
  # Start and enable Docker service
  run_sudo systemctl start docker
  run_sudo systemctl enable docker
  
  echo "✅ Docker installed and configured"
else
  echo "• Docker already installed"
  
  # Ensure user is in docker group and Docker is running
  run_sudo usermod -aG docker ${REMOTE_USER}
  run_sudo systemctl start docker || true
  run_sudo systemctl enable docker || true
fi

# Verify Docker installation
if command -v docker-compose &> /dev/null; then
  echo "✅ Docker and docker-compose ready for Redis and containers"
else
  echo "❌ Docker installation failed"
  exit 1
fi

#############################################################################
# FILE PERMISSIONS HARDENING (System Level) - Modular
#############################################################################
if [[ "${ACTIVATE_FILE_HARDENING}" == "true" ]]; then
  setup_file_hardening "${REMOTE_USER}"
else
  disable_file_hardening
fi

# Python 3 & venv support (simplified from previous working script)
if ! dpkg -s ${PYTHON_EXEC} &>/dev/null; then
  echo "• ${PYTHON_EXEC} not found, installing..."
  install_if_missing ${PYTHON_EXEC} ${PYTHON_EXEC}-venv ${PYTHON_EXEC}-dev
else
  echo "• ${PYTHON_EXEC} already installed"
  install_if_missing ${PYTHON_EXEC}-venv ${PYTHON_EXEC}-dev
fi

#############################################################################
# Setup project directory as ubuntu user
#############################################################################
echo "• Setting up project directory as ${REMOTE_USER} user"

# Handle init mode - completely remove project folder
if [[ "${MODE}" == "init" ]]; then
  echo "• INIT mode: Completely removing existing project directory"
  rm -rf "/home/${REMOTE_USER}/${APP_DIR}"
  # Also clean up any potential git cache or locks
  rm -rf "/home/${REMOTE_USER}/.cache/git/*" 2>/dev/null || true
fi

# Clone or update repo as ubuntu user
bash -c "
set -euo pipefail
cd /home/${REMOTE_USER}

if [[ -d \"${APP_DIR}/.git\" ]]; then
  echo \"• Repo exists ⇒ pulling latest ${REPO_BRANCH}\"
  cd \"${APP_DIR}\"
  
  # Update repository with preserved files/directories
  git remote set-url origin \"${REPO_URL}\"
  git fetch origin \"${REPO_BRANCH}\" --depth=1
  git reset --hard FETCH_HEAD
  
  # Build git clean exclusion patterns for preserved items
  CLEAN_EXCLUDES=\"\"
  
  if [[ \"${MODE}\" == \"update\" ]]; then
    echo \"• Preserving files and directories during git cleanup\"
    
    # Add file exclusions
    if [[ -n \"${PRESERVE_FILES}\" ]]; then
      read -ra PRESERVE_FILE_ITEMS <<< \"${PRESERVE_FILES}\"
      for item in \"\${PRESERVE_FILE_ITEMS[@]}\"; do
        CLEAN_EXCLUDES=\"\${CLEAN_EXCLUDES} -e \${item}\"
        echo \"  • Will preserve file: \$item\"
      done
    fi
    
    # Add directory exclusions
    if [[ -n \"${PRESERVE_DIRS}\" ]]; then
      read -ra PRESERVE_DIR_ITEMS <<< \"${PRESERVE_DIRS}\"
      for item in \"\${PRESERVE_DIR_ITEMS[@]}\"; do
        CLEAN_EXCLUDES=\"\${CLEAN_EXCLUDES} -e \${item}\"
        echo \"  • Will preserve directory: \$item\"
      done
    fi
  fi
  
  # Remove untracked files/directories, excluding preserved items
  if [[ -n \"\$CLEAN_EXCLUDES\" ]]; then
    eval \"git clean -fd \$CLEAN_EXCLUDES\"
    echo \"• Git cleanup completed with preserved items intact\"
  else
    git clean -fd
    echo \"• Git cleanup completed\"
  fi
  
elif [[ -d \"${APP_DIR}\" ]]; then
  echo \"• Directory ${APP_DIR} exists but is not a git repo, removing and cloning fresh\"
  rm -rf \"${APP_DIR}\"
  git clone -b \"${REPO_BRANCH}\" --depth=1 \"${REPO_URL}\" \"${APP_DIR}\"
  cd \"${APP_DIR}\"
else
  echo \"• Cloning ${REPO_BRANCH} into ${APP_DIR}\"
  git clone -b \"${REPO_BRANCH}\" --depth=1 \"${REPO_URL}\" \"${APP_DIR}\"
  cd \"${APP_DIR}\"
fi

# Ensure required directories exist after git operations
# (In update mode, preserved dirs should already exist; in init/clone mode, create them)
if [[ -n \"${PRESERVE_DIRS}\" ]]; then
  echo \"• Ensuring required directories exist\"
  read -ra REQUIRED_DIRS <<< \"${PRESERVE_DIRS}\"
  for dir in \"\${REQUIRED_DIRS[@]}\"; do
    if [[ ! -d \"\$dir\" ]]; then
      echo \"  • Creating directory: \$dir\"
      mkdir -p \"\$dir\"
    fi
  done
fi
"
EOF

#############################################################################
# Upload .env file AFTER repository setup
#############################################################################
if [[ -f "${ENV_FILE}" ]]; then
  echo "• Uploading .env → /home/${REMOTE_USER}/${APP_DIR}/.env"
  
  # For init mode, ensure we overwrite any existing .env
  if [[ "${MODE}" == "init" ]]; then
    echo "• INIT mode: Force uploading fresh .env file"
    $SCP "${ENV_FILE}" "${REMOTE_USER}@${EC2_IP}:/tmp/.env"
    $SSH "rm -f /home/${REMOTE_USER}/${APP_DIR}/.env && mv /tmp/.env /home/${REMOTE_USER}/${APP_DIR}/.env"
  else
    $SCP "${ENV_FILE}" "${REMOTE_USER}@${EC2_IP}:/tmp/.env"
    $SSH "mv /tmp/.env /home/${REMOTE_USER}/${APP_DIR}/.env"
  fi
else
  echo "• No .env to upload (file not found at ${ENV_FILE})"
fi

#############################################################################
# Upload SSL certificates if ACTIVATE_SSL is true
#############################################################################
if [[ "${ACTIVATE_SSL}" == "true" ]]; then
  upload_ssl_certificates "${SCP}" "${REMOTE_USER}" "${EC2_IP}"
fi

#############################################################################
# Manage client_variants from git repository (no local upload)
# The git pull already placed client_variants/ on the server from the repo.
# For non-pmag clients, we prune unwanted client folders for security/size.
#############################################################################
echo "• Processing client_variants for CLIENT_NAME: ${CLIENT_NAME}"

if [[ "${CLIENT_NAME}" == "pmag" ]]; then
  # For 'pmag' client, keep all client_variants from git — nothing to do
  echo "✅ All client_variants available from git repository (pmag client)"
else
  # For other clients, remove all client folders except the specific one
  echo "• Pruning client_variants to keep only: ${CLIENT_NAME}"
  $SSH "
    CV_DIR=/home/${REMOTE_USER}/${APP_DIR}/client_variants

    if [[ -d \"\${CV_DIR}\" ]]; then
      # Remove all client subdirectories except the target client and __init__.py
      for dir in \"\${CV_DIR}\"/*/; do
        dirname=\$(basename \"\${dir}\")
        if [[ \"\${dirname}\" != \"${CLIENT_NAME}\" && \"\${dirname}\" != \"__pycache__\" ]]; then
          rm -rf \"\${dir}\"
        fi
      done

      if [[ -d \"\${CV_DIR}/${CLIENT_NAME}\" ]]; then
        echo '✅ Client variant ${CLIENT_NAME} retained from git repository'
      else
        echo '⚠️  Client variant ${CLIENT_NAME} not found in git repository'
        mkdir -p \"\${CV_DIR}/${CLIENT_NAME}\"
        touch \"\${CV_DIR}/${CLIENT_NAME}/__init__.py\"
        echo '✅ Empty client variant structure created for ${CLIENT_NAME}'
      fi
    else
      echo '⚠️  No client_variants directory found after git pull'
      mkdir -p \"\${CV_DIR}\"
      echo '# Empty client_variants' > \"\${CV_DIR}/__init__.py\"
      mkdir -p \"\${CV_DIR}/${CLIENT_NAME}\"
      touch \"\${CV_DIR}/${CLIENT_NAME}/__init__.py\"
      echo '✅ Empty client_variants structure created'
    fi
  "
fi

#############################################################################
# Upload sensitive files (not in Git) - Using modular approach
#############################################################################
source "${SCRIPT_DIR}/modules/sensitive_files.sh"
transfer_sensitive_files "$SCP" "$SSH" "$PROJECT_ROOT" "$REMOTE_USER" "$EC2_IP" "$APP_DIR" "$TRANSFER_SENSITIVE_FILES"

#############################################################################
# All remaining steps run on the EC2 instance - PART 2: Python & Django Setup
#############################################################################
$SSH APP_DIR="${APP_DIR}" REPO_URL="${REPO_URL}" REPO_BRANCH="${REPO_BRANCH}" PYTHON_EXEC="${PYTHON_EXEC}" VENV_DIR="${VENV_DIR}" MODE="${MODE}" FULL_FLAG="${FULL_FLAG}" REMOTE_USER="${REMOTE_USER}" GUNICORN_PORT="${GUNICORN_PORT}" EC2_IP="${EC2_IP}" CLIENT_NAME="${CLIENT_NAME}" PRESERVE_FILES="\"${PRESERVE_FILES}\"" PRESERVE_DIRS="\"${PRESERVE_DIRS}\"" ACTIVATE_SSL="${ACTIVATE_SSL}" SSL_KEY_PASSWORD="${SSL_KEY_PASSWORD}" SSL_CERT_REMOTE="${SSL_CERT_REMOTE}" SSL_KEY_REMOTE="${SSL_KEY_REMOTE}" DOMAIN="${DOMAIN}" ACTIVATE_WEBSOCKET="${LOCAL_ACTIVATE_WEBSOCKET}" RUN_LOCAL_KNOWLEDGE_BASE_CONTAINER="${LOCAL_RUN_LOCAL_KNOWLEDGE_BASE_CONTAINER}" RUN_LOCAL_BROWSER_USE_CONTAINER="${LOCAL_RUN_LOCAL_BROWSER_USE_CONTAINER}" BROWSER_USE_MAX_CONCURRENT_SESSIONS="${LOCAL_BROWSER_USE_MAX_CONCURRENT_SESSIONS}" RUN_LOCAL_KEYCLOAK_CONTAINER="${LOCAL_RUN_LOCAL_KEYCLOAK_CONTAINER}" KEYCLOAK_ENABLED="${LOCAL_KEYCLOAK_ENABLED}" KEYCLOAK_SERVER_URL="${LOCAL_KEYCLOAK_SERVER_URL}" KEYCLOAK_REALM="${LOCAL_KEYCLOAK_REALM}" KEYCLOAK_CLIENT_ID="${LOCAL_KEYCLOAK_CLIENT_ID}" KEYCLOAK_CLIENT_SECRET="${LOCAL_KEYCLOAK_CLIENT_SECRET}" KEYCLOAK_ROLE_MAPPING="${LOCAL_KEYCLOAK_ROLE_MAPPING}" KEYCLOAK_ADMIN_PASSWORD="${LOCAL_KEYCLOAK_ADMIN_PASSWORD}" KEYCLOAK_DB_STORAGE="${LOCAL_KEYCLOAK_DB_STORAGE}" KEYCLOAK_DB_USERNAME="${LOCAL_KEYCLOAK_DB_USERNAME}" KEYCLOAK_DB_PASSWORD="${LOCAL_KEYCLOAK_DB_PASSWORD}" KEYCLOAK_DB_MASTER_USERNAME="${LOCAL_KEYCLOAK_DB_MASTER_USERNAME}" POSTGRES_PASSWORD="${LOCAL_POSTGRES_PASSWORD}" ACTIVATE_FILE_HARDENING="${LOCAL_ACTIVATE_FILE_HARDENING}" ACTIVATE_ANTIVIRUS="${LOCAL_ACTIVATE_ANTIVIRUS}" ACTIVATE_FAIL2BAN="${LOCAL_ACTIVATE_FAIL2BAN}" SEO_INDEX="${LOCAL_SEO_INDEX}" GUNICORN_NGINX_KEEPALIVE="${GUNICORN_NGINX_KEEPALIVE}" GUNICORN_BACKLOG="${GUNICORN_BACKLOG}" PATCH_SCRIPTS="${PATCH_SCRIPTS}" NGINX_CONFIG_FILE="${NGINX_CONFIG_FILE}" SUDO_PASSWORD="${SUDO_PASS}" bash -s <<'EOF'
set -euo pipefail

APP_DIR="${APP_DIR}"
PYTHON_EXEC="${PYTHON_EXEC}"
VENV_DIR="${VENV_DIR}"
MODE="${MODE}"
FULL_FLAG="${FULL_FLAG}"
REMOTE_USER="${REMOTE_USER}"
GUNICORN_PORT="${GUNICORN_PORT}"
EC2_IP="${EC2_IP}"
CLIENT_NAME="${CLIENT_NAME}"
PRESERVE_FILES="${PRESERVE_FILES}"
PRESERVE_DIRS="${PRESERVE_DIRS}"
ACTIVATE_SSL="${ACTIVATE_SSL}"
SSL_KEY_PASSWORD="${SSL_KEY_PASSWORD}"
SSL_CERT_REMOTE="${SSL_CERT_REMOTE}"
SSL_KEY_REMOTE="${SSL_KEY_REMOTE}"
DOMAIN="${DOMAIN}"
ACTIVATE_WEBSOCKET="${ACTIVATE_WEBSOCKET}"
RUN_LOCAL_KNOWLEDGE_BASE_CONTAINER="${RUN_LOCAL_KNOWLEDGE_BASE_CONTAINER}"
RUN_LOCAL_BROWSER_USE_CONTAINER="${RUN_LOCAL_BROWSER_USE_CONTAINER}"
BROWSER_USE_MAX_CONCURRENT_SESSIONS="${BROWSER_USE_MAX_CONCURRENT_SESSIONS}"
RUN_LOCAL_KEYCLOAK_CONTAINER="${RUN_LOCAL_KEYCLOAK_CONTAINER}"
KEYCLOAK_ENABLED="${KEYCLOAK_ENABLED}"
KEYCLOAK_SERVER_URL="${KEYCLOAK_SERVER_URL}"
KEYCLOAK_REALM="${KEYCLOAK_REALM}"
KEYCLOAK_CLIENT_ID="${KEYCLOAK_CLIENT_ID}"
KEYCLOAK_CLIENT_SECRET="${KEYCLOAK_CLIENT_SECRET}"
KEYCLOAK_ROLE_MAPPING="${KEYCLOAK_ROLE_MAPPING}"
KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD}"
KEYCLOAK_DB_STORAGE="${KEYCLOAK_DB_STORAGE}"
KEYCLOAK_DB_USERNAME="${KEYCLOAK_DB_USERNAME}"
KEYCLOAK_DB_PASSWORD="${KEYCLOAK_DB_PASSWORD}"
KEYCLOAK_DB_MASTER_USERNAME="${KEYCLOAK_DB_MASTER_USERNAME}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD}"
ACTIVATE_FILE_HARDENING="${ACTIVATE_FILE_HARDENING}"
ACTIVATE_ANTIVIRUS="${ACTIVATE_ANTIVIRUS}"
ACTIVATE_FAIL2BAN="${ACTIVATE_FAIL2BAN}"
SEO_INDEX="${SEO_INDEX}"
GUNICORN_NGINX_KEEPALIVE="${GUNICORN_NGINX_KEEPALIVE}"
GUNICORN_BACKLOG="${GUNICORN_BACKLOG}"
PATCH_SCRIPTS="${PATCH_SCRIPTS}"
NGINX_CONFIG_FILE="${NGINX_CONFIG_FILE}"

PROJECT_PATH="/home/${REMOTE_USER}/${APP_DIR}"

#############################################################################
# Load deployment modules (required for this SSH session)
#############################################################################
SCRIPT_DIR_REMOTE="/tmp/deploy_modules"
source "${SCRIPT_DIR_REMOTE}/_common.sh"
source "${SCRIPT_DIR_REMOTE}/antivirus.sh"
source "${SCRIPT_DIR_REMOTE}/ssl.sh"
source "${SCRIPT_DIR_REMOTE}/file_hardening.sh"
source "${SCRIPT_DIR_REMOTE}/knowledge_container.sh"
source "${SCRIPT_DIR_REMOTE}/browser_use.sh"
source "${SCRIPT_DIR_REMOTE}/keycloak.sh"
source "${SCRIPT_DIR_REMOTE}/nginx.sh"
source "${SCRIPT_DIR_REMOTE}/gunicorn.sh"
source "${SCRIPT_DIR_REMOTE}/celery.sh"
source "${SCRIPT_DIR_REMOTE}/secret_key_rotation.sh"
source "${SCRIPT_DIR_REMOTE}/patch_scripts.sh"

# Helper for sudo tee with heredoc (handles stdin properly)
run_sudo_tee() {
  local file_path="$1"
  if [[ -n "${SUDO_PASSWORD:-}" ]]; then
    echo "${SUDO_PASSWORD}" | sudo -S tee "$file_path" > /dev/null
  else
    sudo tee "$file_path" > /dev/null
  fi
}

#############################################################################
# Python virtual environment setup
#############################################################################
echo "• Setting up Python virtual environment as ${REMOTE_USER} user"

cd "${PROJECT_PATH}"

# For init mode, always recreate the virtual environment
if [[ "${MODE}" == "init" && -d "${VENV_DIR}" ]]; then
  echo "• INIT mode: Removing existing virtual environment"
  rm -rf "${VENV_DIR}"
fi

# For update mode with full flag, recreate the virtual environment
if [[ "${MODE}" == "update" && "${FULL_FLAG}" == "full" && -d "${VENV_DIR}" ]]; then
  echo "• UPDATE FULL mode: Removing existing virtual environment for complete reinstall"
  rm -rf "${VENV_DIR}"
fi

if [[ ! -d "${VENV_DIR}" ]]; then
  echo "• Creating venv (${PYTHON_EXEC})"
  ${PYTHON_EXEC} -m venv "${VENV_DIR}"
fi

source "${VENV_DIR}/bin/activate"
pip install --upgrade pip

# Install Gunicorn first
pip install gunicorn

# Install global + client-specific requirements via install_requirements.sh
# CLIENT_NAME is already set in environment from .env.{client} files
if [[ "${MODE}" == "update" && "${FULL_FLAG}" == "full" ]]; then
  echo "• UPDATE FULL mode: Force reinstalling all requirements"
  bash install_requirements.sh --force-reinstall
else
  bash install_requirements.sh
fi

#############################################################################
# Apply Patch Scripts (if configured via PATCH_SCRIPTS env variable)
#############################################################################
apply_patch_scripts "${PATCH_SCRIPTS}" "${VENV_DIR}" "${PROJECT_PATH}"

#############################################################################
# Django housekeeping 
#############################################################################
echo "• Running Django setup as ${REMOTE_USER} user"

cd "${PROJECT_PATH}"
source "${VENV_DIR}/bin/activate"

# Client variant migration system - handles core + client-specific migrations.
# Read-only client variants (every model managed=False, schema owned by another
# client on the same DB) opt out via SKIP_MIGRATIONS=true in their .env. When set,
# the deploy issues zero SQL against the database.
SKIP_MIGRATIONS_FLAG=$(grep "^SKIP_MIGRATIONS=" "${PROJECT_PATH}/.env" 2>/dev/null \
  | cut -d'=' -f2 | tr -d '"' | tr -d "'" | tr '[:upper:]' '[:lower:]' || echo "false")

if [[ "${SKIP_MIGRATIONS_FLAG}" == "true" ]]; then
  echo "• SKIP_MIGRATIONS=true — read-only client variant, skipping client_migrate"
else
  echo "• Running migrations for client variant"
  python manage.py client_migrate --fake-initial
fi

# DMN rules sync (opt-in, acque_venete only).
# Populates the DecisionTable DB with any rule declared in RULE_SCHEMAS that
# isn't there yet. Idempotent and non-destructive. Triggered by RUN_DMN_SYNC=true
# in the client's .env — see deploy/.env.acque_venete for docs.
# The management-command name is derived from DMN_SYNC_SCRIPT_PATH (basename
# without extension), so renaming/relocating the script only requires updating
# the .env variable, not this deploy script.
if [[ "${CLIENT_NAME}" == "acque_venete" || "${CLIENT_NAME}" == "pmag" ]]; then
  RUN_DMN_SYNC_FLAG=$(grep "^RUN_DMN_SYNC=" "${PROJECT_PATH}/.env" 2>/dev/null | cut -d'=' -f2 | tr -d '"' | tr -d "'" | tr '[:upper:]' '[:lower:]' || echo "false")
  if [[ "${RUN_DMN_SYNC_FLAG}" == "true" ]]; then
    DMN_SYNC_SCRIPT_PATH=$(grep "^DMN_SYNC_SCRIPT_PATH=" "${PROJECT_PATH}/.env" 2>/dev/null | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
    if [[ -z "${DMN_SYNC_SCRIPT_PATH}" ]]; then
      echo "⚠️  RUN_DMN_SYNC=true but DMN_SYNC_SCRIPT_PATH is unset — skipping"
    elif [[ ! -f "${PROJECT_PATH}/${DMN_SYNC_SCRIPT_PATH}" ]]; then
      echo "⚠️  DMN_SYNC_SCRIPT_PATH points to a missing file: ${DMN_SYNC_SCRIPT_PATH} — skipping"
    else
      DMN_SYNC_COMMAND=$(basename "${DMN_SYNC_SCRIPT_PATH}" .py)
      echo "• RUN_DMN_SYNC=true — running: python manage.py ${DMN_SYNC_COMMAND} (source: ${DMN_SYNC_SCRIPT_PATH})"
      python manage.py "${DMN_SYNC_COMMAND}" || {
        echo "⚠️  ${DMN_SYNC_COMMAND} failed, but continuing anyway..."
        echo "   (Use 'python manage.py ${DMN_SYNC_COMMAND} --list' on the server to diagnose)"
      }
    fi
  else
    echo "• RUN_DMN_SYNC=false (or unset) — skipping DMN rules sync"
  fi
fi

# Read admin password from .env (default to 'admin' if not set for backward compatibility)
ADMIN_INITIAL_PASSWORD=$(grep "^ADMIN_INITIAL_PASSWORD=" "${PROJECT_PATH}/.env" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "admin")
if [[ -z "${ADMIN_INITIAL_PASSWORD}" ]]; then
  ADMIN_INITIAL_PASSWORD="admin"
fi

# Export password as environment variable for Python to read (safer than string interpolation)
export ADMIN_INITIAL_PASSWORD

if [[ "${SKIP_MIGRATIONS_FLAG}" == "true" ]]; then
  echo "• SKIP_MIGRATIONS=true — skipping superuser bootstrap (read-only client variant)"
elif [[ "${MODE}" == "init" ]]; then
  echo "• INIT mode: Creating fresh superuser"
  python manage.py shell -c "
import os
from django.contrib.auth import get_user_model
User = get_user_model()
User.objects.filter(is_superuser=True).delete()
admin_password = os.environ.get('ADMIN_INITIAL_PASSWORD', 'admin')
User.objects.create_superuser('admin', 'admin@example.com', admin_password)
print('Fresh superuser created: admin/[password from ADMIN_INITIAL_PASSWORD]')
"
else
  echo "• Creating superuser if it doesn't exist"
  python manage.py shell -c "
import os
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(is_superuser=True).exists():
    admin_password = os.environ.get('ADMIN_INITIAL_PASSWORD', 'admin')
    User.objects.create_superuser('admin', 'admin@example.com', admin_password)
    print('Superuser created: admin/[password from ADMIN_INITIAL_PASSWORD]')
else:
    print('Superuser already exists')
"
fi

echo "• Collecting static files"
python manage.py collectstatic --noinput

#############################################################################
# Django Application Security - File Permissions (modular)
#############################################################################
if [[ "${ACTIVATE_FILE_HARDENING}" == "true" ]]; then
  setup_django_file_permissions "${PROJECT_PATH}" "${REMOTE_USER}" "${VENV_DIR}"
fi

#############################################################################
# SSL Certificate Installation (modular - conditional based on ACTIVATE_SSL)
#############################################################################
if [[ "${ACTIVATE_SSL}" == "true" ]]; then
  setup_ssl "${SSL_KEY_PASSWORD}" "${SSL_CERT_REMOTE}" "${SSL_KEY_REMOTE}"
else
  disable_ssl
fi

#############################################################################
# Redis Docker Container (ALWAYS - Required for Celery)
#############################################################################
echo "• Setting up Redis Docker container (required for Celery)..."

REDIS_DIR="${PROJECT_PATH}/redis"

if [[ -d "${REDIS_DIR}" && -f "${REDIS_DIR}/docker-compose.yml" ]]; then
  echo "• Found Redis configuration"
  
  # Ensure user can access Docker (new group membership requires re-login or newgrp)
  sg docker -c "
    cd '${REDIS_DIR}'
    
    # Stop any existing container
    docker-compose down 2>/dev/null || true
    
    # Start Redis container
    echo '• Starting Redis container...'
    docker-compose up -d redis
    
    # Wait for Redis to be ready
    echo '• Waiting for Redis to be ready...'
    for i in {1..30}; do
      if docker-compose exec -T redis redis-cli ping &>/dev/null; then
        echo '✅ Redis container is ready and healthy'
        docker-compose ps redis
        break
      fi
      if [[ \$i -eq 30 ]]; then
        echo '⚠️ Redis container readiness timeout (may still be starting)'
        docker-compose logs redis | tail -10
      else
        sleep 2
      fi
    done
  "
  
  echo "✅ Redis container setup completed"
else
  echo "❌ Redis directory or docker-compose.yml not found at ${REDIS_DIR}"
  echo "❌ Celery will not work without Redis!"
  exit 1
fi

#############################################################################
# Activation flags (passed from local .env)
#############################################################################
echo "• Activation flags from local .env:"
echo "  - ACTIVATE_WEBSOCKET: ${ACTIVATE_WEBSOCKET}"
echo "  - ACTIVATE_ANTIVIRUS: ${ACTIVATE_ANTIVIRUS}"
echo "  - ACTIVATE_FAIL2BAN: ${ACTIVATE_FAIL2BAN}"
echo "  - RUN_LOCAL_KNOWLEDGE_BASE_CONTAINER: ${RUN_LOCAL_KNOWLEDGE_BASE_CONTAINER}"
echo "  - RUN_LOCAL_BROWSER_USE_CONTAINER: ${RUN_LOCAL_BROWSER_USE_CONTAINER}"

#############################################################################
# ClamAV Antivirus Setup (modular - conditional based on ACTIVATE_ANTIVIRUS from .env)
#############################################################################
# Module already sourced above (antivirus.sh)
if [[ "${ACTIVATE_ANTIVIRUS}" == "true" ]]; then
  setup_clamav
else
  disable_clamav
fi

#############################################################################
# Knowledge Base Docker Container (modular - conditional based on RUN_LOCAL_KNOWLEDGE_BASE_CONTAINER from .env)
#############################################################################
if [[ "${RUN_LOCAL_KNOWLEDGE_BASE_CONTAINER}" == "true" ]]; then
  setup_knowledge_container "${PROJECT_PATH}"
else
  disable_knowledge_container "${PROJECT_PATH}"
fi

#############################################################################
# Browser Use Docker Container (modular - conditional based on RUN_LOCAL_BROWSER_USE_CONTAINER from .env)
#############################################################################
if [[ "${RUN_LOCAL_BROWSER_USE_CONTAINER}" == "true" ]]; then
  setup_browser_use_container "${PROJECT_PATH}"
else
  disable_browser_use_container "${PROJECT_PATH}"
fi

#############################################################################
# Keycloak Docker Container (modular - conditional based on RUN_LOCAL_KEYCLOAK_CONTAINER from .env)
#############################################################################
if [[ "${RUN_LOCAL_KEYCLOAK_CONTAINER}" == "true" ]]; then
  setup_keycloak_container "${PROJECT_PATH}"
else
  disable_keycloak_container "${PROJECT_PATH}"
fi

#############################################################################
# Read CPU Configuration from .env
#############################################################################
# Validate .env file exists
if [[ ! -f "${PROJECT_PATH}/.env" ]]; then
  echo "❌ Error: .env file not found at ${PROJECT_PATH}/.env"
  echo "CPU configuration parameters are required for deployment."
  echo "Please ensure .env file contains all required CPU settings:"
  echo "  GUNICORN_WORKERS, GUNICORN_CPU_QUOTA"
  echo "  CELERY_CPU_QUOTA, OMP_NUM_THREADS, etc."
  exit 1
fi

# Read CPU/resource configuration from .env file
GUNICORN_WORKERS=$(grep "^GUNICORN_WORKERS=" "${PROJECT_PATH}/.env" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
GUNICORN_NICE=$(grep "^GUNICORN_NICE=" "${PROJECT_PATH}/.env" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
GUNICORN_CPU_WEIGHT=$(grep "^GUNICORN_CPU_WEIGHT=" "${PROJECT_PATH}/.env" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
GUNICORN_CPU_QUOTA=$(grep "^GUNICORN_CPU_QUOTA=" "${PROJECT_PATH}/.env" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
GUNICORN_TIMEOUT=$(grep "^GUNICORN_TIMEOUT=" "${PROJECT_PATH}/.env" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
GUNICORN_MAX_REQUESTS=$(grep "^GUNICORN_MAX_REQUESTS=" "${PROJECT_PATH}/.env" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
GUNICORN_MAX_REQUESTS_JITTER=$(grep "^GUNICORN_MAX_REQUESTS_JITTER=" "${PROJECT_PATH}/.env" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
GUNICORN_NGINX_KEEPALIVE=$(grep "^GUNICORN_NGINX_KEEPALIVE=" "${PROJECT_PATH}/.env" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
GUNICORN_BACKLOG=$(grep "^GUNICORN_BACKLOG=" "${PROJECT_PATH}/.env" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")

CELERY_CONCURRENCY=$(grep "^CELERY_CONCURRENCY=" "${PROJECT_PATH}/.env" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
CELERY_NICE=$(grep "^CELERY_NICE=" "${PROJECT_PATH}/.env" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
CELERY_CPU_WEIGHT=$(grep "^CELERY_CPU_WEIGHT=" "${PROJECT_PATH}/.env" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
CELERY_CPU_QUOTA=$(grep "^CELERY_CPU_QUOTA=" "${PROJECT_PATH}/.env" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")

OMP_NUM_THREADS=$(grep "^OMP_NUM_THREADS=" "${PROJECT_PATH}/.env" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
OPENBLAS_NUM_THREADS=$(grep "^OPENBLAS_NUM_THREADS=" "${PROJECT_PATH}/.env" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
MKL_NUM_THREADS=$(grep "^MKL_NUM_THREADS=" "${PROJECT_PATH}/.env" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
TORCH_NUM_THREADS=$(grep "^TORCH_NUM_THREADS=" "${PROJECT_PATH}/.env" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
NUMEXPR_MAX_THREADS=$(grep "^NUMEXPR_MAX_THREADS=" "${PROJECT_PATH}/.env" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
TF_NUM_INTRAOP=$(grep "^TF_NUM_INTRAOP_PARALLELISM_THREADS=" "${PROJECT_PATH}/.env" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
TF_NUM_INTEROP=$(grep "^TF_NUM_INTEROP_PARALLELISM_THREADS=" "${PROJECT_PATH}/.env" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
TOKENIZERS_PARALLELISM=$(grep "^TOKENIZERS_PARALLELISM=" "${PROJECT_PATH}/.env" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")

# Read NGINX server names from .env (required)
NGINX_SERVER_NAMES=$(grep "^NGINX_SERVER_NAMES=" "${PROJECT_PATH}/.env" | cut -d'=' -f2 | tr -d '"' | tr -d "'")

# Validate required NGINX server names
if [[ -z "${NGINX_SERVER_NAMES}" ]]; then
  echo "❌ Error: NGINX_SERVER_NAMES is required in .env"
  echo "  Please add NGINX_SERVER_NAMES to ${PROJECT_PATH}/.env"
  echo "  Example: NGINX_SERVER_NAMES=63.179.49.122 10.59.11.26"
  exit 1
fi

# Validate required CPU parameters
if [[ -z "${GUNICORN_WORKERS}" || -z "${GUNICORN_CPU_QUOTA}" ]]; then
  echo "❌ Error: Missing required Gunicorn CPU parameters in .env"
  echo "  Required: GUNICORN_WORKERS, GUNICORN_CPU_QUOTA"
  exit 1
fi

if [[ -z "${CELERY_CPU_QUOTA}" ]]; then
  echo "❌ Error: Missing required CELERY_CPU_QUOTA in .env"
  exit 1
fi
if [[ -z "${OMP_NUM_THREADS}" ]]; then
  OMP_NUM_THREADS="2"
  echo "⚠ OMP_NUM_THREADS not set in .env, defaulting to ${OMP_NUM_THREADS}"
fi

echo "✓ CPU configuration loaded from .env:"
echo "  Gunicorn ASGI: ${GUNICORN_WORKERS} workers (async event loops), CPUQuota=${GUNICORN_CPU_QUOTA}"
echo "  Celery: gevent pool with ${CELERY_CONCURRENCY} greenlets, CPUQuota=${CELERY_CPU_QUOTA}, threads=${OMP_NUM_THREADS}"
echo "✓ Upstream configuration:"
echo "  Nginx keepalive: ${GUNICORN_NGINX_KEEPALIVE} (connection pooling)"
echo "  Gunicorn backlog: ${GUNICORN_BACKLOG} (request queue)"

#############################################################################
# Create Gunicorn systemd service (modular)
#############################################################################
# Module already sourced above (gunicorn.sh)

setup_gunicorn_service "${REMOTE_USER}" "${PROJECT_PATH}" "${VENV_DIR}" "${GUNICORN_NICE}" "${GUNICORN_CPU_WEIGHT}" "${GUNICORN_CPU_QUOTA}" "${GUNICORN_WORKERS}" "${GUNICORN_TIMEOUT}" "${GUNICORN_MAX_REQUESTS}" "${GUNICORN_MAX_REQUESTS_JITTER}" "${GUNICORN_BACKLOG}"

#############################################################################
# WebSocket Support - INTEGRATED into Gunicorn ASGI (UvicornWorker)
#############################################################################
# NOTE: WebSocket support is now built into the unified ASGI architecture.
# Gunicorn with UvicornWorker handles BOTH HTTP and WebSocket at the same socket.
# The ACTIVATE_WEBSOCKET flag is maintained for backward compatibility but has
# no functional impact - WebSocket is ALWAYS available with ASGI.

echo "• WebSocket support: INTEGRATED in Gunicorn ASGI (always available)"



#############################################################################
# Configure Nginx (modular)
#############################################################################
# Module already sourced above (nginx.sh)

# Setup ACL permissions for www-data
setup_nginx_acl "${REMOTE_USER}"

# Create Nginx configuration (NGINX_CONFIG_FILE is required in .env)
setup_nginx_config "${APP_DIR}" "${PROJECT_PATH}" "${ACTIVATE_SSL}" "${ACTIVATE_WEBSOCKET}" "${DOMAIN}" "${SSL_CERT_REMOTE}" "${SSL_KEY_REMOTE}" "${NGINX_SERVER_NAMES}" "${GUNICORN_NGINX_KEEPALIVE}" "${NGINX_CONFIG_FILE}"

# Test nginx configuration
if ! run_sudo nginx -t; then
  echo ""
  echo "❌ =========================================================="
  echo "❌ CRITICAL ERROR: NGINX CONFIGURATION TEST FAILED"
  echo "❌ =========================================================="
  echo ""
  echo "The Nginx configuration has syntax errors."
  echo "Deployment cannot continue with invalid Nginx configuration."
  echo ""
  exit 1
fi

#############################################################################
# Celery Worker systemd service (modular)
#############################################################################
# Module already sourced above (celery.sh)

setup_celery_service "${REMOTE_USER}" "${PROJECT_PATH}" "${VENV_DIR}" "${CELERY_NICE}" "${CELERY_CPU_WEIGHT}" "${CELERY_CPU_QUOTA}" "${CELERY_CONCURRENCY}" "${OMP_NUM_THREADS}" "${OPENBLAS_NUM_THREADS}" "${MKL_NUM_THREADS}" "${TORCH_NUM_THREADS}" "${NUMEXPR_MAX_THREADS}" "${TF_NUM_INTRAOP}" "${TF_NUM_INTEROP}" "${TOKENIZERS_PARALLELISM}"

#############################################################################
# Start/restart services
#############################################################################
echo "• Managing services"

# Reload systemd
run_sudo systemctl daemon-reload

if [[ "${MODE}" == "init" ]]; then
  echo "• INIT mode: Starting all services fresh"
  
  # Stop any existing services
  run_sudo systemctl stop gunicorn celery-worker nginx || true
  run_sudo systemctl stop gunicorn.socket || true
  run_sudo systemctl disable gunicorn.socket gunicorn celery-worker || true
  
  # Force kill any surviving celery processes (safety cleanup)
  echo "• Force-killing any remaining Celery processes"
  run_sudo pkill -9 -f "celery.*worker" || true
  sleep 2
  
  # Clean up socket directories
  run_sudo rm -rf /run/gunicorn
  
  # Enable and start services (Gunicorn now handles HTTP + WebSocket via ASGI)
  run_sudo systemctl enable gunicorn celery-worker nginx
  run_sudo systemctl start celery-worker nginx
  run_sudo systemctl start gunicorn
  
  # Verify Gunicorn socket creation
  echo "• Verifying Gunicorn socket creation"
  sleep 5
  
  if [[ -S /run/gunicorn/gunicorn.sock ]]; then
    echo "✅ Gunicorn socket created successfully"
    ls -la /run/gunicorn/gunicorn.sock
  else
    echo "⚠️  Socket not found, checking Gunicorn status"
    run_sudo systemctl status gunicorn --no-pager
    run_sudo journalctl -u gunicorn -n 20 --no-pager
  fi
  
elif [[ "${MODE}" == "update" ]]; then
  echo "• UPDATE mode: Restarting services"
  
  # Stop old socket service if it exists
  run_sudo systemctl stop gunicorn.socket || true
  run_sudo systemctl disable gunicorn.socket || true

  # Clean up socket files
  run_sudo rm -f /run/gunicorn/gunicorn.sock
  
  # Restart Gunicorn (now handles HTTP + WebSocket via ASGI)
  if run_sudo systemctl is-enabled gunicorn &>/dev/null; then
    echo "• Restarting Gunicorn service (unified ASGI for HTTP + WebSocket)"
    run_sudo systemctl restart gunicorn
  else
    echo "• Enabling and starting Gunicorn service (unified ASGI for HTTP + WebSocket)"
    run_sudo systemctl enable gunicorn
    run_sudo systemctl start gunicorn
  fi
  
  # Verify Gunicorn socket creation
  echo "• Verifying Gunicorn socket creation"
  sleep 5
  
  if [[ -S /run/gunicorn/gunicorn.sock ]]; then
    echo "✅ Gunicorn socket created successfully"
    ls -la /run/gunicorn/gunicorn.sock
  else
    echo "⚠️  Socket not found, checking Gunicorn status"
    run_sudo systemctl status gunicorn --no-pager
    run_sudo journalctl -u gunicorn -n 20 --no-pager
  fi
  
  # Restart Celery if enabled (with force-kill to prevent orphaned processes)
  if run_sudo systemctl is-enabled celery-worker &>/dev/null; then
    echo "• Stopping Celery worker service"
    run_sudo systemctl stop celery-worker
    
    # Force kill any surviving celery processes (safety cleanup)
    echo "• Force-killing any remaining Celery processes"
    run_sudo pkill -9 -f "celery.*worker" || true
    
    # Wait to ensure all processes are dead
    sleep 3
    
    # Verify cleanup
    if ps aux | grep -q "[c]elery.*worker"; then
      echo "⚠️  Warning: Some Celery processes still running"
      ps aux | grep "[c]elery.*worker" || true
    else
      echo "✅ All Celery processes terminated"
    fi
    
    # Start fresh
    echo "• Starting Celery worker service"
    run_sudo systemctl start celery-worker
  else
    echo "• Enabling and starting Celery worker service"
    run_sudo systemctl enable celery-worker
    run_sudo systemctl start celery-worker
  fi
  
  # Restart Nginx
  run_sudo systemctl restart nginx
fi

#############################################################################
# Service status check and socket verification
#############################################################################
echo "• Checking service status and socket connectivity"

# Check Gunicorn Service
if run_sudo systemctl is-active --quiet gunicorn; then
  echo "✅ Gunicorn service is running"
  
  # Verify socket file exists
  if [[ -S /run/gunicorn/gunicorn.sock ]]; then
    echo "✅ Gunicorn socket file exists"
    ls -la /run/gunicorn/gunicorn.sock
  else
    echo "❌ Gunicorn socket file missing despite active service"
    echo "• Attempting emergency restart..."
    run_sudo systemctl restart gunicorn
    sleep 5
    if [[ -S /run/gunicorn/gunicorn.sock ]]; then
      echo "✅ Emergency socket creation successful"
      ls -la /run/gunicorn/gunicorn.sock
    else
      echo ""
      echo "❌ =========================================================="
      echo "❌ CRITICAL ERROR: GUNICORN SOCKET CREATION FAILED"
      echo "❌ =========================================================="
      echo ""
      run_sudo journalctl -u gunicorn -n 30 --no-pager
      echo ""
      echo "Deployment cannot continue without Gunicorn running."
      echo ""
      exit 1
    fi
  fi
else
  echo ""
  echo "❌ =========================================================="
  echo "❌ CRITICAL ERROR: GUNICORN SERVICE FAILED TO START"
  echo "❌ =========================================================="
  echo ""
  run_sudo systemctl status gunicorn --no-pager
  echo ""
  echo "Deployment cannot continue without Gunicorn running."
  echo ""
  exit 1
fi

# Check Nginx
if run_sudo systemctl is-active --quiet nginx; then
  echo "✅ Nginx is running"
else
  echo ""
  echo "❌ =========================================================="
  echo "❌ CRITICAL ERROR: NGINX SERVICE FAILED TO START"
  echo "❌ =========================================================="
  echo ""
  run_sudo systemctl status nginx --no-pager
  echo ""
  echo "Deployment cannot continue without Nginx running."
  echo ""
  exit 1
fi

# Check Celery
if run_sudo systemctl is-active --quiet celery-worker; then
  echo "✅ Celery worker service is running"
else
  echo ""
  echo "❌ =========================================================="
  echo "❌ CRITICAL ERROR: CELERY WORKER SERVICE FAILED TO START"
  echo "❌ =========================================================="
  echo ""
  run_sudo systemctl status celery-worker --no-pager
  echo ""
  echo "Deployment cannot continue without Celery worker running."
  echo ""
  exit 1
fi

# Services already verified by systemd checks above

#############################################################################
# Setup Scheduled Tasks (Cron Jobs and Timers)
#############################################################################
echo ""
echo "🔄 Setting up scheduled tasks (cron jobs and timers)..."

# Allow cron job setup to fail without stopping deployment
set +e
setup_celery_cron || echo "⚠️  Celery cron job setup failed (continuing deployment)"

if [[ "${ACTIVATE_ANTIVIRUS}" == "true" ]]; then
  setup_clamav_cron || echo "⚠️  ClamAV cron job setup failed (continuing deployment)"
else
  disable_clamav_cron 2>/dev/null || true
fi
set -e

#############################################################################
# Setup Automatic SECRET_KEY Rotation (CRITICAL - deployment fails if this fails)
#############################################################################
# Module already sourced above (secret_key_rotation.sh)

if ! setup_secret_key_rotation "${REMOTE_USER}" "${PROJECT_PATH}" "${VENV_DIR}"; then
  echo ""
  echo "❌ =========================================================="
  echo "❌ CRITICAL ERROR: SECRET_KEY ROTATION SETUP FAILED"
  echo "❌ =========================================================="
  echo ""
  echo "The SECRET_KEY rotation timer is a critical security component."
  echo "Deployment cannot continue without it."
  echo ""
  echo "Check the error messages above for details."
  echo ""
  exit 1
fi

#############################################################################
# Check Knowledge Base Docker (if enabled) - MOVED AFTER CRITICAL SETUP
#############################################################################
# This check is non-critical and should not block timer/cron setup
if [[ "${RUN_LOCAL_KNOWLEDGE_BASE_CONTAINER}" == "true" ]]; then
  echo ""
  echo "• Checking knowledge base container status..."
  
  KNOWLEDGE_BASE_DIR="${PROJECT_PATH}/knowledge_base"
  if [[ -d "${KNOWLEDGE_BASE_DIR}" ]]; then
    CONTAINER_STATUS=$(sg docker -c "cd '${KNOWLEDGE_BASE_DIR}' && docker-compose ps -q knowbase" 2>/dev/null | wc -l || echo "0")
    
    if [[ "${CONTAINER_STATUS}" -gt 0 ]]; then
      echo "✅ Knowledge base container is running"
      
      # Test database connectivity using Django management command
      if cd "${PROJECT_PATH}" && source "${VENV_DIR}/bin/activate" && timeout 10s python manage.py shell -c "
import sys
from knowledge_base.db_connect import init_postgress_conn
try:
    conn = init_postgress_conn()
    with conn.cursor() as cursor:
        cursor.execute('SELECT 1')
        result = cursor.fetchone()
    conn.close()
    print('✅ Knowledge base database connection: OK')
    sys.exit(0)
except Exception as e:
    print(f'⚠️ Knowledge base database connection: {e}')
    sys.exit(1)
" 2>/dev/null; then
        echo "✅ Knowledge base database connectivity verified"
      else
        echo "⚠️ Knowledge base database connectivity issues"
      fi
    else
      echo "⚠️ Knowledge base container is not running"
    fi
  else
    echo "⚠️ Knowledge base directory not found at ${KNOWLEDGE_BASE_DIR}"
  fi
else
  echo "• Knowledge base container status check skipped (RUN_LOCAL_KNOWLEDGE_BASE_CONTAINER=false)"
fi

#############################################################################
# Check Browser Use Docker (if enabled) - Non-critical post-deploy check
#############################################################################
if [[ "${RUN_LOCAL_BROWSER_USE_CONTAINER}" == "true" ]]; then
  echo ""
  echo "• Checking Browser Use container status..."

  BROWSER_USE_DIR="${PROJECT_PATH}/shared_services/browser_use"
  if [[ -d "${BROWSER_USE_DIR}" ]]; then
    CONTAINER_STATUS=$(sg docker -c "cd '${BROWSER_USE_DIR}' && docker-compose ps -q browser-use-chrome" 2>/dev/null | wc -l || echo "0")

    if [[ "${CONTAINER_STATUS}" -gt 0 ]]; then
      echo "✅ Browser Use container is running"

      # Test CDP endpoint connectivity
      if curl -sf http://localhost:9222/json/version &>/dev/null; then
        echo "✅ Browser Use CDP endpoint connectivity verified"
      else
        echo "⚠️ Browser Use CDP endpoint not responding (container may still be starting)"
      fi
    else
      echo "⚠️ Browser Use container is not running"
    fi
  else
    echo "⚠️ Browser Use directory not found at ${BROWSER_USE_DIR}"
  fi
else
  echo "• Browser Use container status check skipped (RUN_LOCAL_BROWSER_USE_CONTAINER=false)"
fi

echo ""
echo "✅ Production deployment finished!"
echo ""
if [[ "${ACTIVATE_SSL}" == "true" ]]; then
  echo "🌐 Your Django app is available at:"
  echo "  • https://${DOMAIN} (primary)"
  echo "  • https://${EC2_IP} (redirects to domain)"
  echo "  • http://${DOMAIN} (redirects to HTTPS)"
  echo "  • http://${EC2_IP} (redirects to HTTPS)"
  echo ""
  echo "🔧 Admin interface: https://${DOMAIN}/admin (username: admin, password from ADMIN_INITIAL_PASSWORD in .env)"
  echo ""
  echo "🔒 SSL Configuration:"
  echo "  • Certificate: ${SSL_CERT_REMOTE}"
  echo "  • Private key: ${SSL_KEY_REMOTE}"
  echo "  • Protocols: TLSv1.2, TLSv1.3"
else
  echo "🌐 Your Django app is available at:"
  echo "  • http://${EC2_IP}"
  echo ""
  echo "🔧 Admin interface: http://${EC2_IP}/admin (username: admin, password from ADMIN_INITIAL_PASSWORD in .env)"
fi
echo ""
echo "📋 Service management commands:"
echo "  sudo systemctl status gunicorn     # HTTP + WebSocket (unified ASGI)"
echo "  sudo systemctl restart gunicorn"
echo "  sudo systemctl status nginx        # Reverse proxy"
echo "  sudo systemctl restart nginx"
echo "  sudo systemctl status celery-worker  # Background tasks"
echo "  sudo systemctl restart celery-worker"
echo ""
echo "📄 Log locations:"
echo "  sudo journalctl -u gunicorn -f     # HTTP + WebSocket (unified ASGI)"
echo "  sudo journalctl -u celery-worker -f"
echo "  sudo tail -f /var/log/nginx/access.log"
echo "  sudo tail -f /var/log/nginx/error.log"
echo ""
echo "🐳 Docker containers:"
echo "  • Redis (required): docker ps | grep pmag_redis"
echo "  • Check Redis: docker exec pmag_redis redis-cli ping"
echo "  • Redis logs: docker logs pmag_redis"
if [[ "${RUN_LOCAL_KNOWLEDGE_BASE_CONTAINER}" == "true" ]]; then
  echo "  • Knowledge base: docker ps | grep knowbase"
  echo "  • Knowledge base logs: docker logs knowbase-db"
fi
if [[ "${RUN_LOCAL_BROWSER_USE_CONTAINER}" == "true" ]]; then
  echo "  • Browser Use: docker ps | grep pmag_browser_use"
  echo "  • Browser Use logs: docker logs pmag_browser_use"
  echo "  • Browser Use health: curl http://localhost:9222/json/version"
fi
echo ""
echo "🔐 ACL Security Verification:"
echo "  • Check Gunicorn ACL: sudo getfacl /run/gunicorn"
echo "  • Verify www-data groups: id www-data"
echo "  • Test www-data access: sudo -u www-data ls /run/gunicorn"
echo ""
if [[ "${ACTIVATE_FILE_HARDENING}" == "true" ]]; then
  echo "🔒 Security Hardening Applied:"
  echo "  • File permissions: system-level and Django application secured"
  echo "  • System files: /etc/passwd, /etc/shadow hardened"
  echo "  • Django .env file: 600 (secrets protected)"
  echo "  • Database file: 600 (secured)"
  echo "  • User home directory: 750 (protected)"
  echo "  • ACL-based www-data access: socket directories only (no group membership)"
  echo "  • www-data isolated: can only access /run/gunicorn/ (HTTP+WebSocket), static/, media/"
  echo ""
fi
if [[ "${ACTIVATE_ANTIVIRUS}" == "true" ]]; then
  echo "🛡️ ClamAV Antivirus:"
  echo "  • Status: sudo systemctl status clamav-daemon"
  echo "  • Test scan: clamdscan /path/to/file"
  echo "  • Database update: sudo freshclam"
  echo "  • Daemon logs: sudo journalctl -u clamav-daemon -f"
  echo "  • Auto-update: Sundays at 2:00 AM"
  echo ""
fi
if [[ "${ACTIVATE_FAIL2BAN}" == "true" ]]; then
  echo "🛡️ Fail2ban Intrusion Prevention:"
  echo "  • Status: sudo systemctl status fail2ban"
  echo "  • Active jails: sudo fail2ban-client status"
  echo "  • Jail details: sudo fail2ban-client status <jail-name>"
  echo "  • Banned IPs: sudo fail2ban-client status <jail-name> | grep 'Banned IP'"
  echo "  • Unban IP: sudo fail2ban-client set <jail-name> unbanip <IP>"
  echo "  • View logs: sudo tail -f /var/log/fail2ban.log"
  echo "  • Protected services: SSH, Nginx (HTTP/HTTPS), Django authentication"
  echo ""
fi
echo "🧠 Resource Management (configured from .env):"
echo "  • Gunicorn (HTTP + WebSocket): ${GUNICORN_WORKERS} async workers (UvicornWorker) - handles thousands of concurrent connections"
echo "  • Gunicorn CPU priority: Nice=${GUNICORN_NICE}, CPUWeight=${GUNICORN_CPU_WEIGHT}, CPUQuota=${GUNICORN_CPU_QUOTA}"
echo "  • Architecture: Unified ASGI (no GIL bottleneck, native async/await support)"
echo "  • Celery: 1 worker with ${CELERY_CONCURRENCY} greenlet threads (gevent pool for parallel I/O-bound tasks)"
echo "  • Celery CPU priority: Nice=${CELERY_NICE}, CPUWeight=${CELERY_CPU_WEIGHT}, CPUQuota=${CELERY_CPU_QUOTA}"
echo "  • Docling thread limits: ${OMP_NUM_THREADS} threads per library (OMP/TORCH/OPENBLAS=${OMP_NUM_THREADS})"
echo "  • Dynamic CPU: Gunicorn gets 4× more CPU time when both services busy"
echo "  • Mode: Balanced (configurable in .env - see deploy/example.txt for options)"
echo "  • Nginx upstream keepalive: ${GUNICORN_NGINX_KEEPALIVE} (connection pooling, reduces overhead)"
echo "  • Gunicorn backlog: ${GUNICORN_BACKLOG} (request queue, handles bursts)"
echo "  • Gunicorn (HTTP) workers recycle every ${GUNICORN_MAX_REQUESTS} requests (±${GUNICORN_MAX_REQUESTS_JITTER})"
echo "  • Celery memory limit: 6GB (auto-restart if exceeded)"
echo "  • Redis memory limit: 512MB (auto-eviction with LRU)"
echo "  • Celery results auto-expire: 1 hour (via Redis TTL)"
echo "  • Weekly auto-restart: Sundays at 3:00 AM"
echo "  • View cron jobs: sudo crontab -l"

EOF
echo "✔ Production deployment completed successfully."

