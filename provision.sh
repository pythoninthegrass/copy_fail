#!/usr/bin/env bash

: <<'EOF'
provision.sh — run inside the Lima VM as root

What this does:
	1. Pins apt sources to snapshot.debian.org so we can install an exact kernel version regardless of what the mirror currently serves.
	2. Installs linux-image-6.1.0-43-cloud-amd64 (6.1.162-1) — the last version before the CVE-2026-31431 fix landed in 6.1.170-1.
	3. Configures GRUB to boot into that kernel by default.
	4. Installs python3 and build deps needed by the exploit.
	5. Reboots. After reboot, run verify.sh.

Idempotent: safe to re-run.
EOF

set -euo pipefail

VULN_KERNEL="6.1.0-43-cloud-amd64"
VULN_PKG_VER="6.1.162-1"
SNAPSHOT_DATE="20260221T204712Z"
SNAPSHOT_BASE="https://snapshot.debian.org/archive/debian/${SNAPSHOT_DATE}"
SNAPSHOT_SEC="https://snapshot.debian.org/archive/debian-security/${SNAPSHOT_DATE}"

echo "[provision] Pinning apt sources to snapshot ${SNAPSHOT_DATE}"

cat > /etc/apt/sources.list.d/debian.sources <<EOF
Types: deb
URIs: ${SNAPSHOT_BASE}
Suites: bookworm bookworm-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: ${SNAPSHOT_SEC}
Suites: bookworm-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOF

# snapshot.debian.org requires Valid-Until to be ignored
cat > /etc/apt/apt.conf.d/99snapshot <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Retries "3";
EOF

# Remove any mirror-list indirection that may exist in the base image
rm -f /etc/apt/mirrors/debian.list /etc/apt/mirrors/debian-security.list

apt-get update -qq

echo "[provision] Installing linux-image-${VULN_KERNEL} (${VULN_PKG_VER})"

DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades \
    "linux-image-${VULN_KERNEL}=${VULN_PKG_VER}" \
    python3 \
    python3-pip

echo "[provision] Configuring GRUB default kernel"

update-grub 2>/dev/null || true

# Debian nests kernel entries inside an "Advanced options" submenu.
# GRUB_DEFAULT with a bare display name only matches top-level entries;
# submenu entries require the "submenu_id>entry_id" --id format.
SUBMENU_ID=$(grep -oP "submenu '[^']+' \\\$menuentry_id_option '\K[^']+" \
    /boot/grub/grub.cfg | head -1 || true)
ENTRY_ID=$(grep -P "menuentry '[^']*${VULN_KERNEL}[^']*' " /boot/grub/grub.cfg \
    | grep -v "recovery mode" \
    | grep -oP "\\\$menuentry_id_option '\K[^']+" | head -1 || true)

if [[ -n "${SUBMENU_ID}" && -n "${ENTRY_ID}" ]]; then
    GRUB_ENTRY="${SUBMENU_ID}>${ENTRY_ID}"
    echo "[provision] Setting GRUB_DEFAULT to: ${GRUB_ENTRY}"
    sed -i "s|^GRUB_DEFAULT=.*|GRUB_DEFAULT='${GRUB_ENTRY}'|" /etc/default/grub
else
    echo "[provision] WARNING: could not find GRUB entry IDs for ${VULN_KERNEL}; falling back to 1>2"
    sed -i 's|^GRUB_DEFAULT=.*|GRUB_DEFAULT="1>2"|' /etc/default/grub
fi

sed -i 's|^GRUB_TIMEOUT=.*|GRUB_TIMEOUT=0|' /etc/default/grub
update-grub

echo "[provision] Staging exploit"
cp /tmp/lima/copy_fail.py /usr/local/bin/copy_fail.py 2>/dev/null || \
    cp "$(dirname "$0")/copy_fail.py" /usr/local/bin/copy_fail.py 2>/dev/null || true

echo "[provision] Rebooting into ${VULN_KERNEL} in 3 seconds..."
echo "            After reboot, run: limactl shell copyfail sudo bash /usr/local/bin/verify.sh"
sleep 3
reboot
