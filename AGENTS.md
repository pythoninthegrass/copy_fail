# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.

## Project Overview

CVE-2026-31431 ("copy.fail") reproduction kit — local privilege escalation via `crypto/algif_aead` in-place page cache write on Linux kernel < 6.1.170. An unprivileged user overwrites a SUID binary's page cache entry without triggering copy-on-write, then execs it to gain root.

## Common Commands

### Linting and Formatting

```bash
# Format
ruff format .

# Check formatting without applying
ruff format --check --diff .

# Lint (fix-only mode is set in ruff.toml)
ruff check .

# Fix markdown errors
markdownlint -f -c .markdownlint.jsonc .

# Check markdown without fixing
markdownlint -c .markdownlint.jsonc .
```

### Running the Exploit

```bash
# Start VM
limactl start --name=copyfail --mount-none ./copy_fail.yml

# Provision vulnerable kernel (reboots VM)
limactl shell --sync . copyfail sudo bash provision.sh

# After reboot: verify and run exploit
limactl shell --sync . copyfail sudo bash verify.sh

# Run exploit standalone inside VM (as unprivileged user)
limactl shell copyfail -- su -s /bin/bash nobody -c "python3 /usr/local/bin/copy_fail.py --target /usr/bin/su"

# Teardown
limactl stop copyfail && limactl delete copyfail
```

## Architecture

### Files

| File | Role |
| --- | --- |
| `copy_fail.py` | Python PoC — opens AF_ALG socket, mmaps target SUID binary, uses `splice()` to trigger in-place page cache write |
| `provision.sh` | Pins apt to `snapshot.debian.org`, installs `linux-image-6.1.0-43-cloud-amd64` (6.1.162-1), configures GRUB, reboots |
| `verify.sh` | Checks kernel version, confirms `algif_aead` loadability, runs exploit as `nobody`, checks ELF magic change, restores `su` |
| `copy_fail.yml` | Lima VM definition: x86_64 Debian 12 bookworm, 2 CPUs/2 GiB RAM, Rosetta enabled for Apple Silicon |

### Exploit Mechanism (`copy_fail.py`)

1. Opens target SUID binary (`/usr/bin/su`) read-only to populate page cache
2. `mmap`s first page of the target (`MAP_SHARED`)
3. Creates `AF_ALG` AEAD socket (`gcm(aes)`, 16-byte key, 16-byte auth tag)
4. Writes shellcode payload (`STUB_ELF`) into a pipe, feeds it to the ALG child socket with `MSG_MORE`
5. Calls `splice(pipe → /dev/null, SPLICE_F_MOVE)` — the kernel writes the "encrypted" result in-place into the page cache entry, bypassing copy-on-write (commit `72548b093ee3`)
6. Drops page cache and re-reads to confirm the ELF magic has changed

### Shellcode (`STUB_ELF`)

176-byte x86-64 ELF: calls `setuid(0)`, `setgid(0)`, then `execve("/bin/sh", ["/bin/sh", "-p"], NULL)`. Padded to `PAGE_SIZE` (4096 bytes) to cover a full page on splice.

### VM Details

- Guest: x86_64 Debian 12 bookworm (`genericcloud-amd64`)
- Vulnerable kernel: `6.1.0-43-cloud-amd64` (package `6.1.162-1`)
- Patched kernel: `6.1.170-1` or later
- Lima `vmType: vz` with Rosetta — works on Apple Silicon without manual cross-compilation
- `provision.sh` rewrites `/etc/apt/sources.list.d/debian.sources` to `snapshot.debian.org` (snapshot date `20260221T204712Z`) and sets `Acquire::Check-Valid-Until false`

## Mitigation Verification

Run on any Linux box to confirm whether `algif_aead` is blocked, either by a patched kernel or a modprobe rule.

```sh
ssh ubuntu@<host> "uname -r && python3 -c \"
import socket
AF_ALG = 38
s = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
try:
    s.bind(('aead', 'gcm(aes)', 0, 0))
    print('algif_aead: bind succeeded — NOT mitigated')
except Exception as e:
    print(f'algif_aead: blocked — {e}')
s.close()
\""
```

Expected output when mitigated (patched kernel or modprobe rule active):

```text
6.8.0-111-generic
algif_aead: blocked — [Errno 2] No such file or directory
```

### Wait-for-reboot variant

Use after issuing a reboot to poll until the box is back and confirm the new kernel is running:

```sh
sleep 30 && until ssh -o ConnectTimeout=5 ubuntu@<host> "uname -r && python3 -c \"
import socket
AF_ALG = 38
s = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
try:
    s.bind(('aead', 'gcm(aes)', 0, 0))
    print('algif_aead: bind succeeded — NOT mitigated')
except Exception as e:
    print(f'algif_aead: blocked — {e}')
s.close()
\"" 2>/dev/null; do sleep 5; done
```

### Interpreting results

| Output | Meaning |
| --- | --- |
| `blocked — [Errno 2] No such file or directory` | Mitigated — patched kernel or `install algif_aead /bin/false` active |
| `blocked — [Errno 1] Operation not permitted` | Module present but load blocked by modprobe rule |
| `bind succeeded` | **Vulnerable** — apply workaround or reboot into patched kernel |
