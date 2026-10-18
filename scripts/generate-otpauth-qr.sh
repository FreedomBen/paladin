#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Render an otpauth:// URI as a QR code PNG for manually testing the
# add-account flows: `paladin add --qr`, `paladin import`, and the TUI /
# GTK "scan from clipboard image" path (see --copy).
#
# Builds a Google Authenticator key URI from the flags, prints it on
# stdout, and encodes it with qrencode at EC level M with 8 px modules
# (the `paladin qr` defaults). Values are percent-encoded the way
# paladin-core's emitter does it but never range-checked: Paladin's
# importer is the validator, so the flags also produce URIs for negative
# tests. Optional parameters are left out of the URI unless given.
#
# Test data only: the secret appears in argv and on stdout.
#
# Usage:
#   scripts/generate-otpauth-qr.sh [options]
#
# Options:
#   -o, --out PATH         PNG to write (default: <repo>/target/otpauth-qr.png)
#   -t, --type TYPE        totp (default) or hotp
#   -i, --issuer NAME      issuer; '' omits it (default: Paladin Test)
#   -l, --label NAME       account label (default: alice@example.com)
#   -s, --secret BASE32    secret (default: 20 random bytes)
#   -a, --algorithm ALG    SHA1, SHA256, or SHA512
#   -d, --digits N         code length
#   -p, --period SECONDS   TOTP time step
#   -c, --counter N        HOTP counter (default: 0)
#       --uri STRING       encode STRING verbatim instead of building a URI
#       --copy             also put the PNG on the clipboard (wl-copy / xclip)
#       --no-image         only print the URI; qrencode is not needed
#   -h, --help             show this help
#
# Examples:
#   scripts/generate-otpauth-qr.sh && paladin add --qr target/otpauth-qr.png
#   scripts/generate-otpauth-qr.sh --issuer GitHub --label me --copy
#   scripts/generate-otpauth-qr.sh --type hotp --counter 5 -o /tmp/hotp.png
#   paladin add --uri "$(scripts/generate-otpauth-qr.sh --no-image)"
#
#   # RFC 4226 test secret: HOTP codes 755224, 287082, 359152, ...
#   scripts/generate-otpauth-qr.sh --type hotp \
#       --secret GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
#
# Requires qrencode (Fedora: sudo dnf install qrencode) unless --no-image.

set -euo pipefail

TYPE="totp"
ISSUER="Paladin Test"
LABEL="alice@example.com"
SECRET=""
ALGORITHM=""
DIGITS=""
PERIOD=""
COUNTER=""
RAW_URI=""
HAVE_RAW_URI=0
HAVE_FIELDS=0
OUT=""
COPY=0
CLIPBOARD=""
NO_IMAGE=0

usage() {
    # The header comment, minus the shebang and SPDX lines.
    awk 'NR <= 3 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "${0}"
}

die() {
    echo "error: ${*}" >&2
    exit 1
}

usage_error() {
    echo "error: ${*}" >&2
    echo "Run '${0} --help' for usage." >&2
    exit 2
}

need_value() {
    [ "${#}" -ge 2 ] || usage_error "${1} needs a value"
}

# Percent-encode each byte outside the RFC 3986 unreserved set, the same
# set paladin-core's otpauth emitter leaves bare.
urlencode() {
    local LC_ALL=C
    local in="${1}" out="" ch i
    for ((i = 0; i < ${#in}; i++)); do
        ch="${in:i:1}"
        case "${ch}" in
            [A-Za-z0-9._~-]) out+="${ch}" ;;
            *) printf -v ch '%%%02X' "'${ch}"; out+="${ch}" ;;
        esac
    done
    printf '%s' "${out}"
}

# Print "&NAME=VALUE" with VALUE encoded, or nothing when VALUE is empty.
param() {
    [ -z "${2}" ] || printf '&%s=%s' "${1}" "$(urlencode "${2}")"
}

# Twenty random bytes as unpadded base32 (32 characters).
random_secret() {
    head -c 20 /dev/urandom | base32 | tr -d '=\n'
}

# Name the clipboard tool for this session, or fail.
clipboard_tool() {
    if [ -n "${WAYLAND_DISPLAY:-}" ] && command -v wl-copy >/dev/null 2>&1; then
        echo wl-copy
    elif [ -n "${DISPLAY:-}" ] && command -v xclip >/dev/null 2>&1; then
        echo xclip
    else
        return 1
    fi
}

# Put PNG ${2} on the clipboard with tool ${1}. Both tools fork to serve
# the selection, so stdout is detached to keep `$(...)` callers from
# waiting on it.
copy_png() {
    case "${1}" in
        wl-copy) wl-copy --type image/png <"${2}" >/dev/null ;;
        xclip) xclip -selection clipboard -target image/png -in "${2}" >/dev/null ;;
        *) return 1 ;;
    esac
}

while [ "${#}" -gt 0 ]; do
    case "${1}" in
        --*=*) set -- "${1%%=*}" "${1#*=}" "${@:2}"; continue ;;
        -h|--help) usage; exit 0 ;;
        -o|--out) need_value "${@}"; OUT="${2}"; shift ;;
        -t|--type) need_value "${@}"; TYPE="${2}"; HAVE_FIELDS=1; shift ;;
        -i|--issuer) need_value "${@}"; ISSUER="${2}"; HAVE_FIELDS=1; shift ;;
        -l|--label) need_value "${@}"; LABEL="${2}"; HAVE_FIELDS=1; shift ;;
        -s|--secret) need_value "${@}"; SECRET="${2}"; HAVE_FIELDS=1; shift ;;
        -a|--algorithm) need_value "${@}"; ALGORITHM="${2}"; HAVE_FIELDS=1; shift ;;
        -d|--digits) need_value "${@}"; DIGITS="${2}"; HAVE_FIELDS=1; shift ;;
        -p|--period) need_value "${@}"; PERIOD="${2}"; HAVE_FIELDS=1; shift ;;
        -c|--counter) need_value "${@}"; COUNTER="${2}"; HAVE_FIELDS=1; shift ;;
        --uri) need_value "${@}"; RAW_URI="${2}"; HAVE_RAW_URI=1; shift ;;
        --copy) COPY=1 ;;
        --no-image) NO_IMAGE=1 ;;
        *) usage_error "unknown argument: ${1}" ;;
    esac
    shift
done

if [ "${HAVE_RAW_URI}" -eq 1 ] && [ "${HAVE_FIELDS}" -eq 1 ]; then
    usage_error "--uri cannot be combined with flags that build the URI"
fi
if [ "${NO_IMAGE}" -eq 1 ] && { [ -n "${OUT}" ] || [ "${COPY}" -eq 1 ]; }; then
    usage_error "--out and --copy need an image; drop --no-image"
fi

if [ "${HAVE_RAW_URI}" -eq 1 ]; then
    URI="${RAW_URI}"
else
    case "${TYPE,,}" in
        totp) [ -z "${COUNTER}" ] || usage_error "--counter needs --type hotp" ;;
        hotp)
            [ -z "${PERIOD}" ] || usage_error "--period needs --type totp"
            COUNTER="${COUNTER:-0}"
            ;;
        *) usage_error "--type must be totp or hotp, not '${TYPE}'" ;;
    esac
    SECRET="${SECRET:-$(random_secret)}"
    path="$(urlencode "${LABEL}")"
    [ -z "${ISSUER}" ] || path="$(urlencode "${ISSUER}"):${path}"
    URI="otpauth://${TYPE}/${path}?secret=$(urlencode "${SECRET}")"
    URI+="$(param issuer "${ISSUER}")$(param algorithm "${ALGORITHM}")"
    URI+="$(param digits "${DIGITS}")$(param period "${PERIOD}")"
    URI+="$(param counter "${COUNTER}")"
fi

if [ "${NO_IMAGE}" -eq 1 ]; then
    printf '%s\n' "${URI}"
    exit 0
fi

if [ "${COPY}" -eq 1 ]; then
    CLIPBOARD="$(clipboard_tool)" ||
        die "--copy needs wl-copy (Wayland) or xclip (X11) in a graphical session"
fi
command -v qrencode >/dev/null 2>&1 ||
    die "qrencode not found; install it (Fedora: sudo dnf install qrencode," \
        "Debian/Ubuntu: sudo apt install qrencode) or use --no-image"

if [ -z "${OUT}" ]; then
    OUT="$(cd -- "$(dirname -- "${0}")/.." && pwd)/target/otpauth-qr.png"
fi
mkdir -p -- "$(dirname -- "${OUT}")"

# Owner-only, like `paladin qr --out`, since the PNG carries the secret.
# The URI goes in on stdin to keep the secret out of qrencode's argv.
umask 077
printf '%s' "${URI}" | qrencode --level=M --size=8 --output="${OUT}"

if [ "${COPY}" -eq 1 ]; then
    copy_png "${CLIPBOARD}" "${OUT}" || die "${CLIPBOARD} could not copy ${OUT}"
fi

printf '%s\n' "${URI}"
echo "Wrote ${OUT}" >&2
if [ "${COPY}" -eq 1 ]; then
    echo "Copied the QR image to the clipboard with ${CLIPBOARD}" >&2
fi
