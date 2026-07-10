#!/usr/bin/env bash
# Browser Use Docker Container Module
# Sets up browserless/chrome container for AI browser automation

setup_browser_use_container() {
  local PROJECT_PATH="${1}"

  echo "• Setting up Browser Use Docker container..."

  BROWSER_USE_DIR="${PROJECT_PATH}/shared_services/browser_use"

  if [[ -d "${BROWSER_USE_DIR}" && -f "${BROWSER_USE_DIR}/docker-compose.yml" ]]; then
    echo "• Found Browser Use configuration"
    echo "• Browser Use max concurrent sessions: ${BROWSER_USE_MAX_CONCURRENT_SESSIONS:-2}"

    # Ensure user can access Docker (new group membership requires re-login or newgrp)
    sg docker -c "
      cd '${BROWSER_USE_DIR}'
      export BROWSER_USE_MAX_CONCURRENT_SESSIONS='${BROWSER_USE_MAX_CONCURRENT_SESSIONS:-2}'

      # Stop any existing container
      docker-compose down 2>/dev/null || true

      # Start container (no --build needed, uses pre-built image)
      echo '• Starting Browser Use container (browserless/chrome)...'
      docker-compose up -d browser-use-chrome

      # Wait for container to be ready
      echo '• Waiting for Chrome CDP endpoint to be ready...'
      for i in {1..30}; do
        if curl -sf http://localhost:9222/json/version &>/dev/null; then
          echo '✅ Browser Use container is ready and healthy'
          docker-compose ps browser-use-chrome
          break
        fi
        if [[ \$i -eq 30 ]]; then
          echo '⚠️ Browser Use container readiness timeout (may still be starting)'
          docker-compose logs browser-use-chrome | tail -10
        else
          sleep 3
        fi
      done
    "

    echo "✅ Browser Use container setup completed"
  else
    echo "❌ Browser Use directory or docker-compose.yml not found at ${BROWSER_USE_DIR}"
  fi
}

disable_browser_use_container() {
  echo "• Browser Use container DISABLED (RUN_LOCAL_BROWSER_USE_CONTAINER not set to true in .env)"
  echo "  • Browser automation functionality will not be available"

  local PROJECT_PATH="${1}"
  local BROWSER_USE_DIR="${PROJECT_PATH}/shared_services/browser_use"

  # Stop and remove existing container if present
  if [[ -d "${BROWSER_USE_DIR}" && -f "${BROWSER_USE_DIR}/docker-compose.yml" ]]; then
    echo "  • Stopping and removing existing Browser Use container..."
    sg docker -c "cd '${BROWSER_USE_DIR}' && docker-compose down 2>/dev/null || true"
    echo "  ✓ Browser Use container stopped and removed"
  fi
}
