# `bad_query` on iPhone17,3 / iOS 27 beta 3

## Status

- Target: `iPhone17,3`, iOS 27.0 beta 3, build `24A5380h`
- Public PoC: <https://github.com/forcequitOS/bad_query>
- Reviewed upstream commit: `73ef6da`
- Upstream affected range: iOS 26.0–26.6.1 and iOS 27 through beta 4
- Upstream fixed claim: iOS 27 beta 5
- Target applicability: **public-PoC-applicable; not yet reproduced on this device**
- CVE identity: **unassigned / unconfirmed**

## Concrete chain

The published source uses `libsystem_containermanager.dylib` to construct a container query, supplies traversal components through `container_query_operation_set_part_domain`, requests a single result, copies its sandbox token, and consumes that token in the calling app.

Observed source-to-boundary chain:

1. `container_query_create`
2. `container_query_set_class` (`13` for a shared system container or `7` for a shared app-group container)
3. `container_query_set_group_identifiers`
4. `container_query_operation_set_part(3)`
5. `container_query_operation_set_part_domain` with traversal components and an absolute target path
6. `container_query_get_single_result`
7. `container_copy_sandbox_token`
8. `sandbox_extension_consume`

The claimed result is read/write access only to paths covered by the issued sandbox extension. This is a sandbox escape primitive, not a kernel exploit, PPL/SPTM bypass, code-signing bypass, persistence mechanism, or complete jailbreak.

## Validation disposition

`reportable-public-poc-applicable`

The target build precedes the upstream stated beta-5 fix and falls inside the explicitly stated beta-3/beta-4 affected range. Static source review confirms a complete API-level source/control/sink chain. Dynamic reproduction on `24A5380h` is still required to change the device-specific status to confirmed.

## Counterevidence and proof gaps

- No run from the target device has been captured.
- The exact server-side validation change between `24A5390f` and `24A5408d` has not yet been attributed.
- No Apple advisory currently connects the public PoC to one of the tracked CVE rows.
- `bad_query_list` is a separate inode enumeration helper and is reported by upstream to remain available on beta 5; it is not the sandbox-escape primitive.

## Safe next validation

Build the upstream sample without modifying the primitive, run it only on the owned test device, request a harmless test directory, and capture the returned handle plus a single create/read/delete result inside that directory. Do not target another user's container or credential-bearing paths.
