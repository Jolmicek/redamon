#!/usr/bin/env bash
# ClamAV Antivirus Module
# Provides file scanning and malware detection

setup_clamav() {
  echo "• Setting up ClamAV antivirus protection (ACTIVATE_ANTIVIRUS=true)..."
  
  # Install ClamAV packages
  if ! dpkg -s clamav &>/dev/null; then
    echo "  • Installing ClamAV packages..."
    run_sudo apt-get update
    run_sudo DEBIAN_FRONTEND=noninteractive apt-get install -y clamav clamav-daemon clamav-freshclam
  else
    echo "  • ClamAV already installed"
  fi
  
  # Check if freshclam service is running (might cause lock issues)
  if systemctl is-active --quiet clamav-freshclam 2>/dev/null; then
    echo "  • ClamAV freshclam service detected, stopping temporarily for initial update"
    run_sudo systemctl stop clamav-freshclam
    sleep 2
  fi
  
  # Update virus database
  echo "  • Updating virus signature database..."
  if run_sudo freshclam 2>&1 | tee /tmp/freshclam_output.txt | grep -q "Database updated\|up-to-date"; then
    echo "  ✓ Virus database updated successfully"
  else
    # Check if database already exists
    if [[ -f /var/lib/clamav/main.cvd ]] || [[ -f /var/lib/clamav/main.cld ]]; then
      echo "  ✓ Virus database already exists (using existing)"
    else
      echo "  ⚠️  Warning: freshclam update had issues, but continuing..."
      cat /tmp/freshclam_output.txt || true
    fi
  fi
  rm -f /tmp/freshclam_output.txt
  
  # Start and enable ClamAV services
  echo "  • Starting ClamAV services..."
  run_sudo systemctl enable clamav-daemon clamav-freshclam
  run_sudo systemctl start clamav-freshclam
  run_sudo systemctl start clamav-daemon
  
  # Wait for daemon to be ready
  echo "  • Waiting for ClamAV daemon to be ready..."
  CLAMAV_READY=false
  for i in {1..30}; do
    if run_sudo clamdscan --version &>/dev/null; then
      CLAMAV_READY=true
      echo "  ✓ ClamAV daemon is ready after ${i} seconds"
      break
    fi
    sleep 2
  done
  
  if [[ "${CLAMAV_READY}" == "false" ]]; then
    echo "  ⚠️  ClamAV daemon took longer than expected to start"
    echo "  • Checking daemon status..."
    run_sudo systemctl status clamav-daemon --no-pager | head -20 || true
  fi
  
  # Verify ClamAV is working
  echo "  • Verifying ClamAV installation..."
  if run_sudo systemctl is-active --quiet clamav-daemon; then
    echo "  ✓ ClamAV daemon service is running"
    CLAMAV_VERSION=$(clamdscan --version 2>/dev/null | head -1 || echo "version check unavailable")
    echo "  ✓ ClamAV version: ${CLAMAV_VERSION}"
    echo "✅ ClamAV antivirus installed and configured successfully"
  else
    echo "❌ ClamAV daemon failed to start"
    run_sudo journalctl -u clamav-daemon -n 20 --no-pager || true
  fi
}

disable_clamav() {
  echo "• ClamAV antivirus DISABLED (ACTIVATE_ANTIVIRUS not set to true in .env)"
  
  # Stop and disable ClamAV services if they exist
  if systemctl list-unit-files | grep -q "clamav-daemon.service" 2>/dev/null; then
    echo "  • Disabling existing ClamAV services..."
    run_sudo systemctl stop clamav-daemon clamav-freshclam 2>/dev/null || true
    run_sudo systemctl disable clamav-daemon clamav-freshclam 2>/dev/null || true
    echo "  ✓ ClamAV services disabled"
  fi
}

# Setup weekly ClamAV database update cron job
setup_clamav_cron() {
  echo "• Setting up weekly ClamAV database update cron job"
  
  # Create cron job for weekly update (Sunday at 2 AM - before Celery restart)
  CLAMAV_CRON_JOB="0 2 * * 0 /usr/bin/systemctl stop clamav-freshclam && /usr/bin/freshclam && /usr/bin/systemctl start clamav-freshclam"
  CLAMAV_CRON_COMMENT="# Auto-update ClamAV virus database weekly"
  
  # Check if cron job already exists
  CLAMAV_CRON_EXISTS=$(run_sudo crontab -l 2>/dev/null | grep -c "freshclam" || true)
  
  if [[ "$CLAMAV_CRON_EXISTS" -gt 0 ]]; then
    echo "✅ Weekly ClamAV update cron job already exists"
    run_sudo crontab -l 2>/dev/null | grep -A1 "freshclam"
  else
    echo "• Creating weekly ClamAV database update cron job..."
    
    # Get existing crontab or empty if none exists
    EXISTING_CRON=$(run_sudo crontab -l 2>/dev/null || echo "")
    
    # Add new cron job
    (echo "$EXISTING_CRON"; echo ""; echo "${CLAMAV_CRON_COMMENT}"; echo "${CLAMAV_CRON_JOB}") | run_sudo crontab -
    
    # Verify it was added
    if run_sudo crontab -l 2>/dev/null | grep -q "freshclam"; then
      echo "✅ Weekly ClamAV database update scheduled for Sundays at 2:00 AM"
      run_sudo crontab -l | grep -A1 "freshclam"
    else
      echo "⚠️  Warning: Could not verify ClamAV cron job installation"
    fi
  fi
}

# Remove ClamAV cron job when disabled
disable_clamav_cron() {
  echo "• ClamAV database update cron job skipped (ACTIVATE_ANTIVIRUS=false)"
  
  # Remove ClamAV cron job if it exists and antivirus is disabled
  if run_sudo crontab -l 2>/dev/null | grep -q "freshclam"; then
    echo "  • Removing existing ClamAV cron job..."
    EXISTING_CRON=$(run_sudo crontab -l 2>/dev/null | grep -v "freshclam" | grep -v "Auto-update ClamAV")
    echo "$EXISTING_CRON" | run_sudo crontab -
    echo "  ✓ ClamAV cron job removed"
  fi
}

