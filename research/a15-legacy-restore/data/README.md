# Target manifest data

Expected input for the iPhone14,6 / iOS 15.4 / 19E241 analysis:

`BuildManifest.plist` extracted from the target IPSW.

The IPSW itself is intentionally not committed because of its size and redistribution/licensing considerations.

Generate reports with:

```sh
python3 research/a15-legacy-restore/report.py \
  /path/to/BuildManifest.plist \
  --device iPhone14,6 \
  --json research/a15-legacy-restore/data/19E241-iPhone14,6.json \
  --text research/a15-legacy-restore/data/19E241-iPhone14,6.txt
```

The generated report is metadata-only and does not perform a restore or evaluate Apple's authorization service.
