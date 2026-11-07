#!/usr/bin/env bash
# ProofBox AI - sandbox VM setup.
# Run once, as root, on a fresh Ubuntu LTS server.
#
# Usage (after copying runner.py to the VM):
#   sudo bash setup_sandbox_vm.sh /root/runner.py
#
# What it does:
#   * creates an unprivileged 'sandbox' user with no sudo and no docker group
#   * installs the runner at /opt/proofbox/runner.py
#   * blocks ALL outbound network traffic from the sandbox user (IPv4 and IPv6)
#   * self-tests that the sandbox user really cannot reach the internet

set -euo pipefail

RUNNER_SRC="${1:-}"
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must run as root (use sudo)." >&2
  exit 1
fi
if [ -z "$RUNNER_SRC" ] || [ ! -f "$RUNNER_SRC" ]; then
  echo "Usage: sudo bash setup_sandbox_vm.sh /path/to/runner.py" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y python3 iptables iptables-persistent

if ! id sandbox >/dev/null 2>&1; then
  useradd --create-home --home-dir /home/sandbox --shell /bin/bash sandbox
fi
passwd -l sandbox >/dev/null   # no password login; SSH keys only

install -d -m 0755 /opt/proofbox
install -m 0755 "$RUNNER_SRC" /opt/proofbox/runner.py

install -d -m 0700 -o sandbox -g sandbox /home/sandbox/.ssh

SANDBOX_UID="$(id -u sandbox)"

# Block all outbound traffic from processes owned by the sandbox user.
# SSH replies are sent by the root-owned sshd process, so admin access still works.
for ipt in iptables ip6tables; do
  if ! $ipt -C OUTPUT -m owner --uid-owner "$SANDBOX_UID" -j REJECT 2>/dev/null; then
    $ipt -I OUTPUT 1 -m owner --uid-owner "$SANDBOX_UID" -j REJECT
  fi
done
netfilter-persistent save

# Self-test: the sandbox user must NOT be able to reach the internet.
if runuser -u sandbox -- timeout 5 python3 -c \
    "import socket; socket.create_connection(('1.1.1.1', 53), 3)" 2>/dev/null; then
  echo "SELF-TEST FAILED: sandbox user can still reach the internet." >&2
  exit 1
fi
echo "Self-test passed: sandbox user has no outbound network access."

cat <<MSG

Setup complete.

Next steps:
  1. Add your PUBLIC key (never the private key) to:
       /home/sandbox/.ssh/authorized_keys
     then run:  chown sandbox:sandbox /home/sandbox/.ssh/authorized_keys && chmod 600 /home/sandbox/.ssh/authorized_keys
  2. Test from your computer:  ssh -i <your-private-key> sandbox@<VM_IP> "python3 /opt/proofbox/runner.py"
     and type {"code": "print(1)", "timeout": 5} then Enter, then Ctrl+Z (Windows) or Ctrl+D (Linux).
MSG
