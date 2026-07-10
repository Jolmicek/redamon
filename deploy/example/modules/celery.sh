#!/usr/bin/env bash
# Celery Worker Module
# Manages Celery systemd service for background tasks

# Create Celery Worker systemd service
setup_celery_service() {
  local REMOTE_USER="${1}"
  local PROJECT_PATH="${2}"
  local VENV_DIR="${3}"
  local CELERY_NICE="${4}"
  local CELERY_CPU_WEIGHT="${5}"
  local CELERY_CPU_QUOTA="${6}"
  local CELERY_CONCURRENCY="${7}"
  local OMP_NUM_THREADS="${8}"
  local OPENBLAS_NUM_THREADS="${9}"
  local MKL_NUM_THREADS="${10}"
  local TORCH_NUM_THREADS="${11}"
  local NUMEXPR_MAX_THREADS="${12}"
  local TF_NUM_INTRAOP="${13}"
  local TF_NUM_INTEROP="${14}"
  local TOKENIZERS_PARALLELISM="${15}"
  
  echo "• Setting up Celery worker as systemd service"

  cat > /tmp/celery-worker.service <<CELERY_SERVICE
[Unit]
Description=Celery Worker Service
After=network.target

[Service]
Type=simple
User=${REMOTE_USER}
Group=${REMOTE_USER}
WorkingDirectory=${PROJECT_PATH}
# venv first (python/celery precedence), then system paths so subprocess tools
# like poppler's pdftoppm/pdfinfo (used by pdf2image in the vision pipeline) are found
Environment=PATH=${PROJECT_PATH}/${VENV_DIR}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=C_FORCE_ROOT=1
Environment=FORCE_DISABLE_SCHEDULER=true

# Django async compatibility with gevent
Environment=DJANGO_ALLOW_ASYNC_UNSAFE=true

# Docling/AI Library Thread Limits (configured from .env)
Environment=OMP_NUM_THREADS=${OMP_NUM_THREADS}
Environment=OPENBLAS_NUM_THREADS=${OPENBLAS_NUM_THREADS}
Environment=MKL_NUM_THREADS=${MKL_NUM_THREADS}
Environment=TORCH_NUM_THREADS=${TORCH_NUM_THREADS}
Environment=NUMEXPR_MAX_THREADS=${NUMEXPR_MAX_THREADS}
Environment=TF_NUM_INTRAOP_PARALLELISM_THREADS=${TF_NUM_INTRAOP}
Environment=TF_NUM_INTEROP_PARALLELISM_THREADS=${TF_NUM_INTEROP}
Environment=TOKENIZERS_PARALLELISM=${TOKENIZERS_PARALLELISM}

EnvironmentFile=-${PROJECT_PATH}/.env

# CPU Priority: Background tasks priority (configured from .env)
Nice=${CELERY_NICE}
CPUWeight=${CELERY_CPU_WEIGHT}
CPUQuota=${CELERY_CPU_QUOTA}

ExecStart=${PROJECT_PATH}/${VENV_DIR}/bin/celery -A core worker --loglevel=info --pool=gevent --concurrency=${CELERY_CONCURRENCY}
ExecReload=/bin/kill -s HUP \$MAINPID
KillMode=mixed
TimeoutStopSec=10
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
CELERY_SERVICE

  run_sudo cp /tmp/celery-worker.service /etc/systemd/system/celery-worker.service
  rm -f /tmp/celery-worker.service
  
  echo "✅ Celery worker service created"
}

# Celery Worker Health Check and Diagnostics
verify_celery_health() {
  local PROJECT_PATH="${1}"
  local VENV_DIR="${2}"
  
  if run_sudo systemctl is-active --quiet celery-worker; then
    echo "• Testing Celery worker functionality..."
    
    # Test broker configuration
    echo "• Testing Django/Celery configuration..."
    DJANGO_TEST=$(cd ${PROJECT_PATH} && source ${VENV_DIR}/bin/activate && python manage.py shell -c "
import os
from django.conf import settings
from celery import current_app

broker_url = getattr(settings, 'CELERY_BROKER_URL', '')
result_backend = getattr(settings, 'CELERY_RESULT_BACKEND', '')
print('Broker URL:', broker_url)
print('Result backend:', result_backend)
print('Broker type:', 'Redis' if 'redis' in broker_url.lower() else 'Other')
print('Registered tasks:', len(current_app.tasks))

# Test Redis connection
if 'redis' in broker_url.lower():
    try:
        current_app.connection().ensure_connection(max_retries=3)
        print('Redis broker connection: OK')
    except Exception as e:
        print('Redis broker connection: ERROR -', str(e))
" 2>/dev/null)

    echo "$DJANGO_TEST"
    
    # Test Redis-based Celery with inspect commands
    echo "• Testing Celery worker connectivity..."
    
    # Check if workers are running via process list
    WORKER_PROCESSES=$(ps aux | grep -c "[c]elery -A core worker" || true)
    echo "• Celery worker processes: ${WORKER_PROCESSES}"
    
    # Try ping command (works well with Redis)
    if cd ${PROJECT_PATH} && source ${VENV_DIR}/bin/activate && timeout 10s ${VENV_DIR}/bin/celery -A core inspect ping &>/dev/null; then
      echo "✅ Celery workers are responding to ping"
      
      # Check active workers
      ACTIVE_WORKERS=$(cd ${PROJECT_PATH} && source ${VENV_DIR}/bin/activate && ${VENV_DIR}/bin/celery -A core inspect active 2>/dev/null | grep -c "celery@" || true)
      echo "• Active Celery workers: ${ACTIVE_WORKERS}"
      
      # Check registered tasks
      REGISTERED_TASKS=$(cd ${PROJECT_PATH} && source ${VENV_DIR}/bin/activate && ${VENV_DIR}/bin/celery -A core inspect registered 2>/dev/null | grep -c "'" || true)
      echo "• Registered tasks: ${REGISTERED_TASKS}"
      
      echo "✅ Redis-based Celery setup verified and healthy"
    else
      echo "❌ Celery workers are not responding"
      echo "• Check Redis container status: docker ps"
      echo "• Check Celery logs: sudo journalctl -u celery-worker -n 20"
      echo "• Check Redis connectivity: docker exec pmag_redis redis-cli ping"
    fi
  else
    echo "• Celery worker service not running, skipping health check"
  fi
}

# Setup weekly Celery restart cron job for memory management
setup_celery_cron() {
  echo "• Setting up weekly Celery restart cron job"

  # Create cron job for weekly restart (Sunday at 3 AM)
  CRON_JOB="0 3 * * 0 /usr/bin/systemctl restart celery-worker"
  CRON_COMMENT="# Auto-restart Celery worker weekly for memory management"

  # Check if cron job already exists (check actual cron content, not just command)
  CRON_EXISTS=$(run_sudo crontab -l 2>/dev/null | grep -c "systemctl restart celery-worker" || true)

  if [[ "$CRON_EXISTS" -gt 0 ]]; then
    echo "✅ Weekly Celery restart cron job already exists"
    run_sudo crontab -l 2>/dev/null | grep -A1 "celery-worker"
  else
    # Add cron job - use proper syntax with error handling
    echo "• Creating weekly Celery restart cron job..."
    
    # Get existing crontab or empty if none exists
    EXISTING_CRON=$(run_sudo crontab -l 2>/dev/null || echo "")
    
    # Add new cron job
    (echo "$EXISTING_CRON"; echo ""; echo "${CRON_COMMENT}"; echo "${CRON_JOB}") | run_sudo crontab -
    
    # Verify it was added
    if run_sudo crontab -l 2>/dev/null | grep -q "systemctl restart celery-worker"; then
      echo "✅ Weekly Celery restart scheduled for Sundays at 3:00 AM"
      run_sudo crontab -l | grep -A1 "celery-worker"
    else
      echo "⚠️  Warning: Could not verify cron job installation"
    fi
  fi
}

