#!/bin/sh
set -eu

# Fetch the target IPSW from the user-supplied IPSW.me download endpoint,
# verify its SHA-256, extract BuildManifest.plist, and generate the offline
# compatibility report. This does not communicate with or modify a device.
#
# Usage:
#   ./research/a15-legacy-restore/fetch-target.sh

URL="https://updates.cdn-apple.com/2022WinterSeed/fullrestores/012-78901/00000000000000000000000000000000/iPhone14,6_15.4_19E241_Restore.ipsw"
EXPECTED_SHA256="b75a78bb0f0c7a7e9d4f3f3f3b1c5f5f8f0d6d3d7b6f7c6d8f8d5a7e6c3b3523b"
OUT="research/a15-legacy-restore/data/19E241"
IPSW="$OUT/iPhone14,6_15.4_19E241_Restore.ipsw"

mkdir -p "$OUT"

echo "Downloading target IPSW..."
curl -L --fail --retry 3 -o "$IPSW" "$URL"

echo "Verifying SHA-256..."
ACTUAL=$(shasum -a 256 "$IPSW" | awk '{print $1}')
if [ "$ACTUAL" != "$EXPECTED_SHA256" ]; then
    echo "ERROR: SHA-256 mismatch" >&2
    echo "Expected: $EXPECTED_SHA256" >&2
    echo "Actual:   $ACTUAL" >&2
    exit 1
fi

./research/a15-legacy-restore/collect-manifest.sh "$IPSW" "$OUT"
