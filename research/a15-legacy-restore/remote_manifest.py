#!/usr/bin/env python3
"""Extract BuildManifest.plist from a remote IPSW using HTTP byte ranges.

This reads ZIP metadata and one member only. It does not download/modify boot
components, communicate with a device, request TSS tickets, or perform a restore.
"""
from __future__ import annotations

import argparse
import struct
import urllib.request
import zlib
from pathlib import Path

EOCD = b"PK\x05\x06"
ZIP64_LOCATOR = b"PK\x06\x07"
ZIP64_EOCD = b"PK\x06\x06"
CDH = b"PK\x01\x02"
LFH = b"PK\x03\x04"


def fetch_range(url: str, start: int | None = None, end: int | None = None, suffix: int | None = None):
    headers = {"User-Agent": "Dopamine-A15-Legacy-Restore-Research/1.0"}
    range_requested = suffix is not None or start is not None
    if suffix is not None:
        headers["Range"] = f"bytes=-{suffix}"
    elif start is not None:
        headers["Range"] = f"bytes={start}-{'' if end is None else end}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=60) as response:
        status = response.status
        if range_requested and status != 206:
            raise RuntimeError(f"server ignored HTTP Range request (status {status}); refusing full IPSW download")
        cr = response.headers.get("Content-Range")
        total = None
        if cr and "/" in cr:
            try:
                total = int(cr.rsplit("/", 1)[1])
            except ValueError:
                pass
        data = response.read()
        return data, total, status


def u64_extra(extra: bytes, need_uncomp: bool, need_comp: bool, need_offset: bool):
    pos = 0
    vals = {}
    while pos + 4 <= len(extra):
        header_id, size = struct.unpack_from("<HH", extra, pos)
        pos += 4
        payload = extra[pos:pos + size]
        pos += size
        if header_id != 0x0001:
            continue
        p = 0
        for key, needed in (("uncomp", need_uncomp), ("comp", need_comp), ("offset", need_offset)):
            if needed:
                if p + 8 > len(payload):
                    raise ValueError("truncated ZIP64 extra field")
                vals[key] = struct.unpack_from("<Q", payload, p)[0]
                p += 8
        return vals
    return vals


def central_directory_location(url: str):
    tail, total, _ = fetch_range(url, suffix=262144)
    if total is None:
        raise RuntimeError("server did not return Content-Range; byte ranges required")
    eocd_at = tail.rfind(EOCD)
    if eocd_at < 0:
        raise RuntimeError("ZIP EOCD not found")
    eocd = tail[eocd_at:eocd_at + 22]
    if len(eocd) < 22:
        raise RuntimeError("truncated EOCD")
    _, _, _, _, _, cd_size32, cd_offset32, _ = struct.unpack("<4s4H2IH", eocd)
    if cd_size32 != 0xFFFFFFFF and cd_offset32 != 0xFFFFFFFF:
        return total, cd_offset32, cd_size32

    locator_at = tail.rfind(ZIP64_LOCATOR, 0, eocd_at)
    if locator_at < 0 or locator_at + 20 > len(tail):
        raise RuntimeError("ZIP64 locator not found")
    _, _, zip64_offset, _ = struct.unpack_from("<4sIQI", tail, locator_at)
    record, _, _ = fetch_range(url, start=zip64_offset, end=zip64_offset + 55)
    if not record.startswith(ZIP64_EOCD) or len(record) < 56:
        raise RuntimeError("ZIP64 EOCD not found")
    cd_size = struct.unpack_from("<Q", record, 40)[0]
    cd_offset = struct.unpack_from("<Q", record, 48)[0]
    return total, cd_offset, cd_size


def find_member(url: str, wanted: str):
    _, cd_offset, cd_size = central_directory_location(url)
    cd, _, _ = fetch_range(url, start=cd_offset, end=cd_offset + cd_size - 1)
    pos = 0
    while pos + 46 <= len(cd):
        if cd[pos:pos + 4] != CDH:
            raise RuntimeError(f"invalid central-directory header at {pos}")
        fields = struct.unpack_from("<4s6H3I5H2I", cd, pos)
        method = fields[4]
        comp32 = fields[8]
        uncomp32 = fields[9]
        name_len, extra_len, comment_len = fields[10], fields[11], fields[12]
        offset32 = fields[16]
        name_start = pos + 46
        name = cd[name_start:name_start + name_len].decode("utf-8", "replace")
        extra = cd[name_start + name_len:name_start + name_len + extra_len]
        vals = u64_extra(extra, uncomp32 == 0xFFFFFFFF, comp32 == 0xFFFFFFFF, offset32 == 0xFFFFFFFF)
        comp = vals.get("comp", comp32)
        uncomp = vals.get("uncomp", uncomp32)
        offset = vals.get("offset", offset32)
        if name == wanted:
            return {"name": name, "method": method, "compressed": comp, "uncompressed": uncomp, "local_offset": offset}
        pos = name_start + name_len + extra_len + comment_len
    raise FileNotFoundError(wanted)


def extract_member(url: str, wanted: str) -> bytes:
    entry = find_member(url, wanted)
    header, _, _ = fetch_range(url, start=entry["local_offset"], end=entry["local_offset"] + 29)
    if len(header) < 30 or not header.startswith(LFH):
        raise RuntimeError("invalid local file header")
    fields = struct.unpack("<4s5H3I2H", header)
    method, name_len, extra_len = fields[3], fields[9], fields[10]
    data_offset = entry["local_offset"] + 30 + name_len + extra_len
    compressed, _, _ = fetch_range(url, start=data_offset, end=data_offset + entry["compressed"] - 1)
    if method == 0:
        result = compressed
    elif method == 8:
        result = zlib.decompress(compressed, -15)
    else:
        raise RuntimeError(f"unsupported ZIP compression method {method}")
    if len(result) != entry["uncompressed"]:
        raise RuntimeError(f"size mismatch: expected {entry['uncompressed']}, got {len(result)}")
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--member", default="BuildManifest.plist")
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    data = extract_member(args.url, args.member)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)
    print(f"extracted {args.member}: {len(data)} bytes -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
