#!/usr/bin/env bash
# Keycloak Docker Container Module (Mode 1 — Single Instance)
# Sets up Keycloak OIDC identity provider container
# Uses the same docker-compose.yml as local dev, but with production env vars

setup_keycloak_container() {
  local PROJECT_PATH="${1}"

  echo "• Setting up Keycloak Docker container..."

  KEYCLOAK_DIR="${PROJECT_PATH}/shared_services/keycloak"

  if [[ -d "${KEYCLOAK_DIR}" && -f "${KEYCLOAK_DIR}/docker-compose.yml" ]]; then
    echo "• Found Keycloak configuration"
    echo "• Keycloak realm: ${KEYCLOAK_REALM:-pmag}"
    echo "• Keycloak server URL: ${KEYCLOAK_SERVER_URL:-not set}"
    echo "• Keycloak DB storage: ${KEYCLOAK_DB_STORAGE:-internal}"

    local KC_DB_STORAGE="${KEYCLOAK_DB_STORAGE:-internal}"
    local KC_DB_USER="${KEYCLOAK_DB_USERNAME:-keycloak}"

    if [[ "${KC_DB_STORAGE}" == "external" ]]; then
      # ── External PostgreSQL mode ──
      echo "• Using external PostgreSQL database"

      # Auto-create keycloak database and user (idempotent)
      local MASTER_USER="${KEYCLOAK_DB_MASTER_USERNAME:-postgres}"
      local MASTER_PASS="${POSTGRES_PASSWORD:-}"
      local KC_DB_PASS="${KEYCLOAK_DB_PASSWORD:-}"

      if [[ -n "${MASTER_PASS}" && -n "${KC_DB_PASS}" ]]; then
        echo "• Checking if keycloak database and user exist..."

        # Check if user exists, create if not
        local USER_EXISTS
        USER_EXISTS=$(PGPASSWORD="${MASTER_PASS}" psql -h localhost -p 5432 -U "${MASTER_USER}" -d postgres -tAc \
          "SELECT 1 FROM pg_roles WHERE rolname = '${KC_DB_USER}';" 2>/dev/null || echo "")
        if [[ "${USER_EXISTS}" != "1" ]]; then
          echo "  Creating PostgreSQL user '${KC_DB_USER}'..."
          PGPASSWORD="${MASTER_PASS}" psql -h localhost -p 5432 -U "${MASTER_USER}" -d postgres -c \
            "CREATE USER ${KC_DB_USER} WITH PASSWORD '${KC_DB_PASS}';" 2>&1 || echo "  Warning: could not create user (may already exist)"
        else
          echo "  User '${KC_DB_USER}' already exists — skipping"
        fi

        # Check if database exists, create if not
        local DB_EXISTS
        DB_EXISTS=$(PGPASSWORD="${MASTER_PASS}" psql -h localhost -p 5432 -U "${MASTER_USER}" -d postgres -tAc \
          "SELECT 1 FROM pg_database WHERE datname = 'keycloak';" 2>/dev/null || echo "")
        if [[ "${DB_EXISTS}" != "1" ]]; then
          echo "  Creating database 'keycloak' owned by '${KC_DB_USER}'..."
          PGPASSWORD="${MASTER_PASS}" psql -h localhost -p 5432 -U "${MASTER_USER}" -d postgres -c \
            "CREATE DATABASE keycloak OWNER ${KC_DB_USER};" 2>&1 || echo "  Warning: could not create database (may already exist)"
        else
          echo "  Database 'keycloak' already exists — skipping"
        fi

        # Grant privileges (idempotent)
        PGPASSWORD="${MASTER_PASS}" psql -h localhost -p 5432 -U "${MASTER_USER}" -d postgres -c \
          "GRANT ALL PRIVILEGES ON DATABASE keycloak TO ${KC_DB_USER};" 2>/dev/null || true

        echo "  ✓ Keycloak database ready"
      else
        echo "  ⚠️ POSTGRES_PASSWORD or KEYCLOAK_DB_PASSWORD not set — skipping DB auto-creation"
        echo "    Ensure the keycloak database and user exist before starting"
      fi

      # Export KC_* env vars for external PostgreSQL
      export KC_COMMAND="start"
      export KC_DB="postgres"
      export KC_DB_URL="jdbc:postgresql://localhost:5432/keycloak"
      export KC_DB_USERNAME="${KC_DB_USER}"
      export KC_DB_PASSWORD="${KEYCLOAK_DB_PASSWORD}"
    else
      # ── Internal H2 mode ──
      echo "• Using internal H2 embedded database (dev-file)"
      export KC_COMMAND="start-dev"
      export KC_DB="dev-file"
      unset KC_DB_URL KC_DB_USERNAME KC_DB_PASSWORD
    fi

    export KC_PORT="8080"
    export KC_PROXY_HEADERS="xforwarded"
    export KC_HOSTNAME="https://${DOMAIN}/kc"
    export KC_HOSTNAME_ADMIN="https://${DOMAIN}/kc"

    sg docker -c "
      cd '${KEYCLOAK_DIR}'
      export KC_COMMAND='${KC_COMMAND}'
      export KC_DB='${KC_DB}'
      export KC_DB_URL='${KC_DB_URL:-}'
      export KC_DB_USERNAME='${KC_DB_USERNAME:-}'
      export KC_DB_PASSWORD='${KC_DB_PASSWORD:-}'
      export KC_PORT='${KC_PORT}'
      export KC_PROXY_HEADERS='${KC_PROXY_HEADERS}'
      export KC_HOSTNAME='${KC_HOSTNAME}'
      export KC_HOSTNAME_ADMIN='${KC_HOSTNAME_ADMIN}'
      export KC_BOOTSTRAP_ADMIN_PASSWORD='${KEYCLOAK_ADMIN_PASSWORD:-admin}'

      # Stop any existing container
      docker-compose down 2>/dev/null || true

      # Start container
      echo '• Starting Keycloak container...'
      docker-compose up -d keycloak

      # Wait for container to be ready (Keycloak is slow to start — Java bootstrap)
      echo '• Waiting for Keycloak to be ready (may take 60-120s)...'
      for i in {1..40}; do
        if bash -c 'echo > /dev/tcp/localhost/\${KC_PORT}' &>/dev/null; then
          echo '✅ Keycloak container is ready and healthy'
          docker-compose ps keycloak
          break
        fi
        if [[ \$i -eq 40 ]]; then
          echo '⚠️ Keycloak readiness timeout (may still be starting)'
          docker-compose logs keycloak | tail -15
        else
          sleep 3
        fi
      done
    "

    echo "✅ Keycloak container setup completed"
    echo "  • Admin console: https://${DOMAIN}/kc/admin/"
    echo "  • Realm import: auto-imported on first start from realm-pmag.json"
  else
    echo "❌ Keycloak directory or docker-compose.yml not found at ${KEYCLOAK_DIR}"
  fi
}

disable_keycloak_container() {
  echo "• Keycloak container DISABLED (RUN_LOCAL_KEYCLOAK_CONTAINER not set to true in .env)"
  echo "  • Keycloak authentication will not be available"

  local PROJECT_PATH="${1}"
  local KEYCLOAK_DIR="${PROJECT_PATH}/shared_services/keycloak"

  # Stop and remove existing container if present
  if [[ -d "${KEYCLOAK_DIR}" && -f "${KEYCLOAK_DIR}/docker-compose.yml" ]]; then
    echo "  • Stopping and removing existing Keycloak container..."
    sg docker -c "cd '${KEYCLOAK_DIR}' && docker-compose down 2>/dev/null || true"
    echo "  ✓ Keycloak container stopped and removed"
  fi
}
