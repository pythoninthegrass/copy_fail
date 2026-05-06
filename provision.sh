#!/usr/bin/env bash
# provision.sh — run inside the Lima VM as root
#
# What this does:
#   1. Pins apt sources to snapshot.debian.org so we can install an exact
#      kernel version regardless of what the mirror currently serves.
#   2. Installs linux-image-6.1.0-43-cloud-amd64 (6.1.162-1) — the last
#      version before the CVE-2026-31431 fix landed in 6.1.170-1.
#   3. Configures GRUB to boot into that kernel by default.
#   4. Installs python3 and build deps needed by the exploit.
#   5. Reboots. After reboot, run verify.sh.
#
# Idempotent: safe to re-run.
set -euo pipefail

VULN_KERNEL="6.1.0-43-cloud-amd64"
VULN_PKG_VER="6.1.162-1"
SNAPSHOT_DATE="20260221T204712Z"
SNAPSHOT_BASE="https://snapshot.debian.org/archive/debian/${SNAPSHOT_DATE}"
SNAPSHOT_SEC="https://snapshot.debian.org/archive/debian-security/${SNAPSHOT_DATE}"

# ---------------------------------------------------------------------------
# 1. Pin apt sources to snapshot so the exact package version is available
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# 2. Install the vulnerable kernel
# ---------------------------------------------------------------------------
echo "[provision] Installing linux-image-${VULN_KERNEL} (${VULN_PKG_VER})"

DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades \
    "linux-image-${VULN_KERNEL}=${VULN_PKG_VER}" \
    python3 \
    python3-pip

# ---------------------------------------------------------------------------
# 3. Configure GRUB to boot the vulnerable kernel
# ---------------------------------------------------------------------------
echo "[provision] Configuring GRUB default kernel"

# Find the exact GRUB menu entry ID for the target kernel
GRUB_ENTRY=$(grep -oP "(?<=menuentry ')[^']+" /boot/grub/grub.cfg \
    | grep "${VULN_KERNEL}" | head -1 || true)

if [[ -z "${GRUB_ENTRY}" ]]; then
    # grub.cfg may not exist yet; update-grub first
    update-grub 2>/dev/null || true
    GRUB_ENTRY=$(grep -oP "(?<=menuentry ')[^']+" /boot/grub/grub.cfg \
        | grep "${VULN_KERNEL}" | head -1 || true)
fi

if [[ -n "${GRUB_ENTRY}" ]]; then
    echo "[provision] Setting GRUB_DEFAULT to: ${GRUB_ENTRY}"
    sed -i "s|^GRUB_DEFAULT=.*|GRUB_DEFAULT='${GRUB_ENTRY}'|" /etc/default/grub
else
    echo "[provision] WARNING: could not find GRUB entry for ${VULN_KERNEL}; using index 1"
    sed -i 's|^GRUB_DEFAULT=.*|GRUB_DEFAULT=1|' /etc/default/grub
fi

# Disable GRUB timeout so it boots immediately
sed -i 's|^GRUB_TIMEOUT=.*|GRUB_TIMEOUT=0|' /etc/default/grub

update-grub

# ---------------------------------------------------------------------------
# 4. Stage the exploit where verify.sh expects it
# ---------------------------------------------------------------------------
echo "[provision] Staging exploit"
cp /tmp/lima/copyfail.py /usr/local/bin/copyfail.py 2>/dev/null || \
    cp "$(dirname "$0")/copyfail.py" /usr/local/bin/copyfail.py 2>/dev/null || true

# ---------------------------------------------------------------------------
# 5. Reboot into the vulnerable kernel
# ---------------------------------------------------------------------------
echo "[provision] Rebooting into ${VULN_KERNEL} in 3 seconds..."
echo "            After reboot, run: limactl shell copyfail sudo bash /usr/local/bin/verify.sh"
sleep 3
reboot
