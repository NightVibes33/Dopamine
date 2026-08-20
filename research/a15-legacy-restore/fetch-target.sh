#!/bin/sh
set -eu

# Analyze the verified iPhone14,6 / 19E241 target.
#
# With a local IPSW path, verify the full IPSW checksum then analyze it.
# With no argument, extract only BuildManifest.plist from the verified Apple CDN
# object using HTTP byte ranges, avoiding a 5.6 GiB download.

OUT="research/a15-legacy-restore/data/19E241"
PROFILE="research/a15-legacy-restore/target-profile.json"
mkdir -p "$OUT"

if [ "$#" -ge 1 ]; then
    IPSW="$1"
    [ -f "$IPSW" ] || { echo "IPSW not found: $IPSW" >&2; exit 2; }
    EXPECTED_SHA256=$(python3 -c 'import json; print(json.load(open("research/a15-legacy-restore/target-profile.json"))["ipsw_sha256"])')
    ACTUAL=$(python3 - "$IPSW" <<'PY'
import hashlib, sys
h=hashlib.sha256()
with open(sys.argv[1], 'rb') as f:
    for chunk in iter(lambda: f.read(1024*1024), b''):
        h.update(chunk)
print(h.hexdigest())
PY
)
    if [ "$ACTUAL" != "$EXPECTED_SHA256" ]; then
        echo "ERROR: SHA-256 mismatch" >&2
        echo "Expected: $EXPECTED_SHA256" >&2
        echo "Actual:   $ACTUAL" >&2
        exit 1
    fi
    echo "Verified target IPSW."
    exec ./research/a15-legacy-restore/collect-manifest.sh "$IPSW" "$OUT"
fi

URL=$(python3 -c 'import json; print(json.load(open("research/a15-legacy-restore/target-profile.json"))["apple_cdn_url"])')
python3 research/a15-legacy-restore/remote_manifest.py \
  "$URL" --output "$OUT/BuildManifest.plist"
python3 research/a15-legacy-restore/validate_manifest.py \
  "$OUT/BuildManifest.plist" | tee "$OUT/validation.txt"
python3 research/a15-legacy-restore/report.py \
  "$OUT/BuildManifest.plist" --json "$OUT/report.json" --text "$OUT/report.txt"
python3 research/a15-legacy-restore/component-matrix.py \
  "$OUT/BuildManifest.plist" --output "$OUT/component-matrix.json"
