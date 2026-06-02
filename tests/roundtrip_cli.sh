#!/usr/bin/env bash
#
# roundtrip_cli.sh — drive the symcrypt CLI through a full encrypt/decrypt
# round-trip against a fixture and assert two properties:
#
#   1. the ciphertext is slightly larger than the plaintext
#      (self-describing header + per-chunk AEAD tags add a small overhead), and
#   2. the decrypted output is byte-for-byte identical to the original fixture.
#
# Usage:
#   tests/roundtrip_cli.sh [path/to/fixture]
#
# Environment:
#   SYMCRYPT_BIN   Path to a prebuilt CLI binary. When unset, the debug build
#                  is compiled with cargo and used.
#
set -euo pipefail

# --- locate the repo root and the fixture ----------------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
FIXTURE="${1:-${REPO_ROOT}/tests/fixtures/LOREM_IPSUM.txt}"

if [[ ! -f "${FIXTURE}" ]]; then
  echo "error: fixture not found: ${FIXTURE}" >&2
  exit 1
fi

# --- resolve the CLI binary -------------------------------------------------
if [[ -n "${SYMCRYPT_BIN:-}" ]]; then
  SYMCRYPT="${SYMCRYPT_BIN}"
else
  echo "Building symcrypt CLI (debug) ..."
  cargo build --quiet -p symcrypt-cli
  SYMCRYPT="${REPO_ROOT}/target/debug/symcrypt"
fi

if [[ ! -x "${SYMCRYPT}" ]]; then
  echo "error: symcrypt binary not found or not executable: ${SYMCRYPT}" >&2
  exit 1
fi

# --- scratch space (removed on exit) ---------------------------------------
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
CIPHERTEXT="${WORK}/cipher.symcrypt"
DECRYPTED="${WORK}/decrypted.txt"

# --- password supplied non-interactively ------------------------------------
# Pass the password by env-var NAME (--password-env) so the secret value never
# appears in the process argument list (visible via `ps`).
export SYMCRYPT_TEST_PASSWORD='correct horse battery staple'

# --- portable file size (bytes) --------------------------------------------
filesize() {
  local s
  if s=$(stat -c %s "$1" 2>/dev/null); then
    printf '%s\n' "${s}"   # GNU/Linux
  else
    stat -f %z "$1"        # BSD/macOS
  fi
}

# --- encrypt ----------------------------------------------------------------
echo "Encrypting: ${FIXTURE}"
"${SYMCRYPT}" --encrypt "${FIXTURE}" \
  --password-env SYMCRYPT_TEST_PASSWORD \
  --output "${CIPHERTEXT}"

if [[ ! -f "${CIPHERTEXT}" ]]; then
  echo "FAIL: ciphertext was not created: ${CIPHERTEXT}" >&2
  exit 1
fi

IN_SIZE="$(filesize "${FIXTURE}")"
OUT_SIZE="$(filesize "${CIPHERTEXT}")"
DELTA=$(( OUT_SIZE - IN_SIZE ))

printf 'plaintext : %8d bytes\n' "${IN_SIZE}"
printf 'ciphertext: %8d bytes (+%d bytes header/AEAD overhead)\n' "${OUT_SIZE}" "${DELTA}"

# --- check 1: ciphertext slightly larger than plaintext --------------------
if (( OUT_SIZE <= IN_SIZE )); then
  echo "FAIL: ciphertext (${OUT_SIZE} B) is not larger than plaintext (${IN_SIZE} B)" >&2
  exit 1
fi
echo "OK: ciphertext is larger than the plaintext by ${DELTA} bytes"

# --- decrypt ----------------------------------------------------------------
# Decrypt restores the original filename from the header by default, so pass an
# explicit --output to a fresh file and never risk clobbering the fixture.
echo "Decrypting -> ${DECRYPTED}"
"${SYMCRYPT}" --decrypt "${CIPHERTEXT}" \
  --password-env SYMCRYPT_TEST_PASSWORD \
  --output "${DECRYPTED}"

if [[ ! -f "${DECRYPTED}" ]]; then
  echo "FAIL: decrypted file was not created: ${DECRYPTED}" >&2
  exit 1
fi

# --- check 2: byte-for-byte identical to the original ----------------------
if cmp -s "${FIXTURE}" "${DECRYPTED}"; then
  echo "OK: decrypted output is byte-for-byte identical to the fixture"
else
  echo "FAIL: decrypted output differs from the fixture" >&2
  cmp "${FIXTURE}" "${DECRYPTED}" >&2 || true
  exit 1
fi

echo
echo "PASS: symcrypt encrypt/decrypt round-trip verified"
