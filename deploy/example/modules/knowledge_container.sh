#!/usr/bin/env bash
# Knowledge Base Docker Container Module
# Sets up PostgreSQL container for knowledge base functionality

setup_knowledge_container() {
  local PROJECT_PATH="${1}"
  
  echo "• Setting up knowledge base Docker container..."
  
  KNOWLEDGE_BASE_DIR="${PROJECT_PATH}/knowledge_base"
  
  if [[ -d "${KNOWLEDGE_BASE_DIR}" && -f "${KNOWLEDGE_BASE_DIR}/docker-compose.yml" ]]; then
    echo "• Found knowledge base configuration"
    
    # Ensure user can access Docker (new group membership requires re-login or newgrp)
    sg docker -c "
      cd '${KNOWLEDGE_BASE_DIR}'
      
      # Stop any existing container
      docker-compose down 2>/dev/null || true
      
      # Build and start container
      echo '• Building and starting knowledge base container...'
      docker-compose up -d --build knowbase
      
      # Wait for container to be ready
      echo '• Waiting for PostgreSQL to be ready...'
      for i in {1..30}; do
        if docker-compose exec -T knowbase pg_isready -h localhost -p 5432 -U postgres &>/dev/null; then
          echo '✅ Knowledge base container is ready and healthy'
          docker-compose ps knowbase
          break
        fi
        if [[ \$i -eq 30 ]]; then
          echo '⚠️ Knowledge base container readiness timeout (may still be starting)'
          docker-compose logs knowbase | tail -10
        else
          sleep 3
        fi
      done
    "
    
    echo "✅ Knowledge base container setup completed"
  else
    echo "❌ Knowledge base directory or docker-compose.yml not found at ${KNOWLEDGE_BASE_DIR}"
  fi
}

disable_knowledge_container() {
  echo "• Knowledge base container DISABLED (RUN_LOCAL_KNOWLEDGE_BASE_CONTAINER not set to true in .env)"
  echo "  • Knowledge base functionality will not be available"
  
  local PROJECT_PATH="${1}"
  local KNOWLEDGE_BASE_DIR="${PROJECT_PATH}/knowledge_base"
  
  # Stop and remove existing container if present
  if [[ -d "${KNOWLEDGE_BASE_DIR}" && -f "${KNOWLEDGE_BASE_DIR}/docker-compose.yml" ]]; then
    echo "  • Stopping and removing existing knowledge base container..."
    sg docker -c "cd '${KNOWLEDGE_BASE_DIR}' && docker-compose down 2>/dev/null || true"
    echo "  ✓ Knowledge base container stopped and removed"
  fi
}

