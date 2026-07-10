#!/usr/bin/env bash
# Fail2ban Intrusion Prevention System Module
# Provides IP-level blocking for persistent attackers

setup_fail2ban() {
  local REMOTE_USER="${1}"
  local APP_DIR="${2}"
  
  echo "🛡️ =========================================================="
  echo "🛡️ INSTALLING FAIL2BAN INTRUSION PREVENTION SYSTEM"
  echo "🛡️ =========================================================="
  
  # Install Fail2ban packages
  if ! dpkg -s fail2ban &>/dev/null; then
    echo "  • Installing Fail2ban packages..."
    run_sudo apt-get update
    run_sudo DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban
  else
    echo "  • Fail2ban already installed"
  fi
  
  # Create Fail2ban configuration directory for custom jails
  run_sudo mkdir -p /etc/fail2ban/jail.d
  run_sudo mkdir -p /etc/fail2ban/filter.d
  
  # Create custom Django authentication filter for login attempts
  echo "  • Creating Django authentication filter..."
  cat > /tmp/django-auth.conf <<'F2B_DJANGO_FILTER'
# Fail2ban filter for Django authentication failures
[Definition]
failregex = ^.*WARNING.*Unauthorized:.*<HOST>.*$
            ^.*WARNING.*Invalid password.*<HOST>.*$
            ^.*WARNING.*Login failed.*<HOST>.*$
            ^.*ERROR.*Authentication failed.*<HOST>.*$
ignoreregex =
F2B_DJANGO_FILTER
  
  run_sudo cp /tmp/django-auth.conf /etc/fail2ban/filter.d/django-auth.conf
  rm -f /tmp/django-auth.conf
  echo "  ✓ Django authentication filter created"
  
  # Create custom Nginx aggressive request filter
  echo "  • Creating Nginx aggressive request filter..."
  cat > /tmp/nginx-limit-req.conf <<'F2B_NGINX_FILTER'
# Fail2ban filter for Nginx rate limiting violations
[Definition]
failregex = ^.*limiting requests, excess:.* by zone.*client: <HOST>.*$
            ^.*\[error\].*client: <HOST>.*$
ignoreregex =
F2B_NGINX_FILTER
  
  run_sudo cp /tmp/nginx-limit-req.conf /etc/fail2ban/filter.d/nginx-limit-req.conf
  rm -f /tmp/nginx-limit-req.conf
  echo "  ✓ Nginx aggressive request filter created"
  
  # Create comprehensive Fail2ban jail configuration
  echo "  • Creating Fail2ban jail configuration..."
  cat > /tmp/custom-jails.conf <<'F2B_JAILS'
# Custom Fail2ban jails for Django + Nginx deployment

[DEFAULT]
# Ban duration: 1 hour (3600 seconds)
bantime = 3600
# Time window to count failures: 10 minutes
findtime = 600
# Maximum failures before ban
maxretry = 5
# Backend for log monitoring
backend = systemd

# Email notifications (optional - requires postfix/sendmail)
# destemail = admin@yourdomain.com
# sendername = Fail2ban
# action = %(action_mwl)s

#############################################################################
# SSH Protection - Brute Force Prevention
#############################################################################
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 7200
findtime = 600

#############################################################################
# Nginx Protection - HTTP Attacks
#############################################################################
[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 5
bantime = 3600

[nginx-noscript]
enabled = true
port = http,https
filter = nginx-noscript
logpath = /var/log/nginx/access.log
maxretry = 6
bantime = 3600

[nginx-badbots]
enabled = true
port = http,https
filter = nginx-badbots
logpath = /var/log/nginx/access.log
maxretry = 2
bantime = 86400

[nginx-noproxy]
enabled = true
port = http,https
filter = nginx-noproxy
logpath = /var/log/nginx/access.log
maxretry = 2
bantime = 3600

[nginx-limit-req]
enabled = true
port = http,https
filter = nginx-limit-req
logpath = /var/log/nginx/error.log
maxretry = 10
findtime = 60
bantime = 600

#############################################################################
# Django Application Protection - Authentication Attacks
#############################################################################
[django-auth]
enabled = true
port = http,https
filter = django-auth
logpath = /home/REMOTE_USER_PLACEHOLDER/APP_DIR_PLACEHOLDER/logs/info.log
maxretry = 5
findtime = 300
bantime = 3600
backend = polling

#############################################################################
# Additional Security - DoS/DDoS Mitigation
#############################################################################
[nginx-req-limit]
enabled = false
port = http,https
filter = nginx-req-limit
logpath = /var/log/nginx/access.log
maxretry = 100
findtime = 60
bantime = 300
F2B_JAILS
  
  # Replace placeholders in jail configuration
  sed -i "s|REMOTE_USER_PLACEHOLDER|${REMOTE_USER}|g" /tmp/custom-jails.conf
  sed -i "s|APP_DIR_PLACEHOLDER|${APP_DIR}|g" /tmp/custom-jails.conf
  
  run_sudo cp /tmp/custom-jails.conf /etc/fail2ban/jail.d/custom-jails.conf
  rm -f /tmp/custom-jails.conf
  echo "  ✓ Fail2ban jail configuration created"
  
  # Ensure log files exist and have correct permissions for Fail2ban to monitor
  echo "  • Ensuring log files are accessible for Fail2ban..."
  run_sudo touch /var/log/auth.log
  run_sudo chmod 644 /var/log/auth.log
  
  # Create Django log directory if it doesn't exist
  mkdir -p /home/${REMOTE_USER}/${APP_DIR}/logs
  touch /home/${REMOTE_USER}/${APP_DIR}/logs/info.log
  chmod 644 /home/${REMOTE_USER}/${APP_DIR}/logs/info.log
  
  # Start and enable Fail2ban service
  echo "  • Starting Fail2ban service..."
  run_sudo systemctl enable fail2ban
  run_sudo systemctl restart fail2ban
  
  # Wait for Fail2ban to initialize
  echo "  • Waiting for Fail2ban to initialize..."
  sleep 3
  
  # Verify Fail2ban is running
  if run_sudo systemctl is-active --quiet fail2ban; then
    echo "  ✓ Fail2ban service is running"
    
    # Check active jails
    echo "  • Active Fail2ban jails:"
    run_sudo fail2ban-client status 2>/dev/null | grep "Jail list" || echo "    (jail list not available yet)"
    
    echo ""
    echo "✅ =========================================================="
    echo "✅ FAIL2BAN INTRUSION PREVENTION SYSTEM ACTIVATED"
    echo "✅ =========================================================="
    echo ""
    echo "  Protected services:"
    echo "    • SSH (max 3 attempts in 10 min → 2 hour ban)"
    echo "    • Nginx HTTP auth (max 5 attempts → 1 hour ban)"
    echo "    • Nginx bad bots (max 2 attempts → 24 hour ban)"
    echo "    • Nginx rate limiting (max 10 violations → 10 min ban)"
    echo "    • Django authentication (max 5 attempts in 5 min → 1 hour ban)"
    echo ""
  else
    echo "❌ Fail2ban failed to start"
    run_sudo journalctl -u fail2ban -n 20 --no-pager || true
  fi
}

disable_fail2ban() {
  echo "• Fail2ban DISABLED (ACTIVATE_FAIL2BAN not set to true in .env)"
  
  # Stop and disable Fail2ban service if it exists
  if systemctl list-unit-files | grep -q "fail2ban.service" 2>/dev/null; then
    echo "  • Disabling existing Fail2ban service..."
    run_sudo systemctl stop fail2ban 2>/dev/null || true
    run_sudo systemctl disable fail2ban 2>/dev/null || true
    echo "  ✓ Fail2ban service disabled"
  fi
}

