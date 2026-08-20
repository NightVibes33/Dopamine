#!/bin/sh
set -eu

# Download the target IPSW using a direct URL supplied by the caller, verify
# the published SHA-256, extract BuildManifest.plist, and generate an offline
# report. No device communication or restore operation is performed.
#
# IPSW.me target page:
# https://ipsw.me/download/iPhone14%2C6/19E241/

EXPECTED_SHA256="b75a78bb659277461189946838573eae5eee1a540737c4a681058603cdf3523b"
OUT="research/a15-legacy-restore/data/19E241"
IPSW="$OUT/iPhone14,6_15.4_19E241_Restore.ipsw"

if [ "${IPSW_URL:-}" = "" ]; then
    echo "Set IPSW_URL to the direct Apple CDN URL before running." >&2
    echo "The IPSW.me page redirects to Apple's download infrastructure." >&2
    exit 2
fi

mkdir -p "$OUT"
echo "Downloading target IPSW..."
curl -L --fail --retry 3 -o "$IPSW" "$IPSW_URL"

echo "Verifying SHA-256..."
ACTUAL=$(shasum -a 256 "$IPSW" | awk '{print $1}')
if [ "$ACTUAL" != "$EXPECTED_SHA256" ]; then
    echo "ERROR: SHA-256 mismatch" >&2
    echo "Expected: $EXPECTED_SHA256" >&2
    echo "Actual:   $ACTUAL" >&2
    exit 1
fi

./research/a15-legacy-restore/collect-manifest.sh "$IPSW" "$OUT"
