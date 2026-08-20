#!/bin/sh
set -eu

# Download/verify a target IPSW supplied by the caller, then run the
# offline BuildManifest analysis. No device communication is performed.
#
# Usage:
#   IPSW_URL='https://...' ./research/a15-legacy-restore/fetch-target.sh
# or:
#   ./research/a15-legacy-restore/fetch-target.sh /path/to/target.ipsw

EXPECTED_SHA256="b75a78bb659277461189946838573eae5eee1a540737c4a681058603cdf3523b"
OUT="research/a15-legacy-restore/data/19E241"
IPSW="$OUT/iPhone14,6_15.4_19E241_Restore.ipsw"

mkdir -p "$OUT"

if [ "$#" -ge 1 ] && [ -f "$1" ]; then
    cp "$1" "$IPSW"
elif [ -n "${IPSW_URL:-}" ]; then
    curl -L --fail --retry 3 -o "$IPSW" "$IPSW_URL"
else
    echo "Provide a local IPSW path or set IPSW_URL to Apple's download URL." >&2
    exit 2
fi

echo "Verifying SHA-256..."
ACTUAL=$(shasum -a 256 "$IPSW" | awk '{print $1}')
if [ "$ACTUAL" != "$EXPECTED_SHA256" ]; then
    echo "ERROR: SHA-256 mismatch" >&2
    echo "Expected: $EXPECTED_SHA256" >&2
    echo "Actual:   $ACTUAL" >&2
    exit 1
fi

echo "Verified target IPSW."
./research/a15-legacy-restore/collect-manifest.sh "$IPSW" "$OUT"
