#!/bin/sh
set -eu

# Offline helper: extract BuildManifest.plist from a locally supplied IPSW and
# generate all metadata-only reports. No device communication is performed.

IPSW=${1:?usage: $0 /path/to/iPhone14,6_15.4_19E241_Restore.ipsw [output-dir]}
OUT=${2:-research/a15-legacy-restore/data/19E241}

mkdir -p "$OUT"

python3 - "$IPSW" "$OUT/BuildManifest.plist" <<'PY'
import sys, zipfile
src, dst = sys.argv[1:]
with zipfile.ZipFile(src) as z:
    with z.open('BuildManifest.plist') as inp, open(dst, 'wb') as out:
        out.write(inp.read())
print(dst)
PY

python3 research/a15-legacy-restore/validate_manifest.py \
  "$OUT/BuildManifest.plist" | tee "$OUT/validation.txt"

python3 research/a15-legacy-restore/report.py \
  "$OUT/BuildManifest.plist" \
  --json "$OUT/report.json" \
  --text "$OUT/report.txt"

python3 research/a15-legacy-restore/component-matrix.py \
  "$OUT/BuildManifest.plist" \
  --output "$OUT/component-matrix.json"
