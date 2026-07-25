# iPad 5 DarkSword adaptive low-memory profile v1

Target: iPad6,11 / iPad6,12 on iOS 16.7.x only.

Changes:
- Keeps the stock DarkSword path unchanged for all other devices.
- Frees the 0x400-byte userspace socket metadata buffer after every spray.
- Validates socket/fileport creation and short metadata responses.
- Calls `surface_munlock` for every scanned search mapping before deallocation.
- Uses bounded profiles: 512 MB + 16,384 sockets, 384 MB + 12,288 sockets, and 256 MB + 8,192 sockets.
- Runs two clean attempts per profile and exits with an error after six misses.
- Preserves stdout and writes sparse stage/memory telemetry to `DarkSword-iPad5-Adaptive.log`.

This branch must be validated from a stock boot. A successful build does not prove exploitation success.
