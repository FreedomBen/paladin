#!/usr/bin/env python3
"""Mint genuine AES Crypt fixtures for the paladin-core read-interop tests.

These are *real* AES Crypt Stream Format 2 files produced by the reference
`aescrypt` tool, so a round-trip test against them validates the whole v1/v2
read path (KDF, hmac1, key unwrap, CBC body, fsmod, hmac2) end to end.

Tool used to mint the committed fixtures:
    aescrypt version 3.16.1 (2023-07-12)   # writes Stream Format 2 only

Regenerate (from this directory):
    ./generate.py            # needs `aescrypt` on PATH

Plaintext for every fixture is the deterministic pattern byte[i] = i % 251, so
the tests reconstruct the expected plaintext without committing it separately.

The v1 fixture is mechanically derived from a v2 fixture by dropping the
(unauthenticated) extensions block and flipping the version byte 0x02 -> 0x01;
neither field is under a MAC, so the keys, body, and HMACs are unchanged. The
reference 3.x tool cannot emit v1 directly. Stream Format 3 needs AES Crypt 4.x
and is intentionally not covered here (see IMPLEMENTATION_PLAN_05 v3 deferral).
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# (filename, plaintext size, password). ASCII password unless noted.
ASCII_PW = "aescrypt test password"
# A non-ASCII password documents the UTF-16LE re-encoding path. It only round
# trips if the writer (here, aescrypt on Linux) also encoded UTF-8 -> UTF-16LE.
NONASCII_PW = "pÄsswörd"  # "pÄsswörd"

V2_CASES = [
    ("v2_size_0.aes", 0, ASCII_PW),
    ("v2_size_1.aes", 1, ASCII_PW),
    ("v2_size_15.aes", 15, ASCII_PW),
    ("v2_size_16.aes", 16, ASCII_PW),
    ("v2_size_17.aes", 17, ASCII_PW),
    ("v2_size_3000.aes", 3000, ASCII_PW),
    ("v2_nonascii_pw_size_17.aes", 17, NONASCII_PW),
]


def pattern(n: int) -> bytes:
    return bytes((i % 251) for i in range(n))


def encrypt(name: str, size: int, password: str) -> None:
    out = os.path.join(HERE, name)
    src = os.path.join(HERE, name + ".plain")
    with open(src, "wb") as f:
        f.write(pattern(size))
    if os.path.exists(out):
        os.remove(out)
    subprocess.run(
        ["aescrypt", "-e", "-p", password, "-o", out, src],
        check=True,
    )
    os.remove(src)
    print(f"  minted {name} ({size} byte plaintext)")


def derive_v1(v2_name: str, v1_name: str) -> None:
    """Strip the v2 extensions block and flip the version byte to make a v1 file."""
    with open(os.path.join(HERE, v2_name), "rb") as f:
        b = bytearray(f.read())
    assert b[0:3] == b"AES" and b[3] == 0x02, "expected a v2 fixture"
    # Layout: magic(3) version(1) reserved(1) then the extension block:
    # repeated (u16 len, len bytes) until a len == 0x0000 terminator.
    pos = 5
    while True:
        ln = (b[pos] << 8) | b[pos + 1]
        pos += 2 + ln
        if ln == 0:
            break
    v1 = bytearray(b[0:5]) + b[pos:]
    v1[3] = 0x01  # version 2 -> 1
    with open(os.path.join(HERE, v1_name), "wb") as f:
        f.write(v1)
    print(f"  derived {v1_name} from {v2_name}")


def main() -> int:
    print("minting AES Crypt fixtures...")
    for name, size, pw in V2_CASES:
        encrypt(name, size, pw)
    derive_v1("v2_size_17.aes", "v1_size_17.aes")
    print("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
