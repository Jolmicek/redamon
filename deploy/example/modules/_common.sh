#!/usr/bin/env bash
# Common helper functions used across all deployment modules

# Helper to run sudo commands with password if needed
run_sudo() {
  if [[ -n "${SUDO_PASSWORD:-}" ]]; then
    echo "${SUDO_PASSWORD}" | sudo -S "$@"
  else
    sudo "$@"
  fi
}

# Helper — install packages via apt if missing
install_if_missing() {
  for pkg in "$@"; do
    dpkg -s "$pkg" &>/dev/null && continue
    echo "• Installing $pkg…"
    run_sudo apt-get update
    run_sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg"
  done
}

