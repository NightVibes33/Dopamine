from __future__ import annotations

import io
import json
import plistlib
import sys
import threading
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from manifest_utils import identity_matches, manifest_supports_product, matching_identities
from remote_manifest import extract_member
from report import build_report

PROFILE = json.loads((ROOT / "target-profile.json").read_text())


def synthetic_manifest():
    return {
        "ProductVersion": "15.4",
        "ProductBuildVersion": "19E241",
        "SupportedProductTypes": ["iPhone14,6"],
        "BuildIdentities": [
            {
                "ApChipID": 0x8110,
                "ApBoardID": 0x10,
                "Info": {"DeviceClass": "d49ap", "Variant": "Customer Erase Install (IPSW)"},
                "Manifest": {
                    "iBSS": {"Info": {"Path": "Firmware/dfu/iBSS.d49.RELEASE.im4p"}, "Digest": b"\x01\x02"},
                    "SEP": {"Info": {"Path": "Firmware/all_flash/sep-firmware.d49.RELEASE.im4p"}},
                },
            }
        ],
    }


class RangeHandler(BaseHTTPRequestHandler):
    payload = b""

    def log_message(self, *args):
        pass

    def do_GET(self):
        data = self.payload
        value = self.headers.get("Range")
        if not value or not value.startswith("bytes="):
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        spec = value[6:]
        if spec.startswith("-"):
            count = int(spec[1:])
            start = max(0, len(data) - count)
            end = len(data) - 1
        else:
            a, b = spec.split("-", 1)
            start = int(a)
            end = int(b) if b else len(data) - 1
            end = min(end, len(data) - 1)
        chunk = data[start:end + 1]
        self.send_response(206)
        self.send_header("Content-Length", str(len(chunk)))
        self.send_header("Content-Range", f"bytes {start}-{end}/{len(data)}")
        self.end_headers()
        self.wfile.write(chunk)


class ManifestTests(unittest.TestCase):
    def test_verified_hardware_match(self):
        manifest = synthetic_manifest()
        self.assertTrue(manifest_supports_product(manifest, "iPhone14,6"))
        matches = matching_identities(manifest, PROFILE)
        self.assertEqual(len(matches), 1)
        self.assertIn("Info.DeviceClass", matches[0][2])
        self.assertIn("ApChipID+ApBoardID", matches[0][2])

    def test_wrong_board_is_rejected(self):
        identity = synthetic_manifest()["BuildIdentities"][0]
        identity["ApBoardID"] = 0x99
        identity["Info"]["DeviceClass"] = "wrongap"
        ok, reasons = identity_matches(identity, PROFILE)
        self.assertFalse(ok)
        self.assertEqual(reasons, [])

    def test_report_contains_components(self):
        report = build_report(synthetic_manifest(), PROFILE)
        self.assertEqual(report["result"], "MANIFEST_HARDWARE_IDENTITY_FOUND")
        names = {x["name"] for x in report["matching_identities"][0]["components"]}
        self.assertEqual(names, {"iBSS", "SEP"})

    def test_remote_range_extractor(self):
        manifest_bytes = plistlib.dumps(synthetic_manifest())
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("BuildManifest.plist", manifest_bytes)
            zf.writestr("other.txt", b"not needed")
        RangeHandler.payload = buf.getvalue()
        server = ThreadingHTTPServer(("127.0.0.1", 0), RangeHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/firmware.ipsw"
            self.assertEqual(extract_member(url, "BuildManifest.plist"), manifest_bytes)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
