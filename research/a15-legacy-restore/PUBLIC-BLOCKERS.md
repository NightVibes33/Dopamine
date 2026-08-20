# Public blocker assessment — A15 / iPhone14,6

## Reference technique

The current public `surrealra1n` development branch describes tethered downgrade support for A7/A8(X), A11, and A12/A13 iPhones. Its recent A12/A13 work is based on the `usbliter8` SecureROM research path.

## A15 comparison

Public `usbliter8` device lists reviewed for this project enumerate A12/A13 targets, including iPhone SE (2nd generation, A13), but do not enumerate iPhone SE (3rd generation, A15). Independent public writeups likewise describe the underlying USB/SecureROM bug as an A12/A13 technique.

## Consequence for this project

`iPhone14,6` has the correct historical iOS 15.4 firmware, board identity, and target-specific boot components. Those facts solve the *firmware selection* question, not the *boot authority* question.

The unresolved dependency is therefore upstream of `futurerestore`, BuildManifest parsing, and component selection:

1. Obtain control at a sufficiently early A15 boot/restore stage.
2. Establish that the resulting A15 environment can use the target SEP/firmware combination.
3. Only then does a restore-engine adaptation become meaningful.

No public capability satisfying step 1 was identified in the reviewed sources as of 2026-08-20.

## Current disposition

**BLOCKED — missing public A15 early-boot primitive.**

This disposition should be revisited if new A15 SecureROM, DFU, or equivalent early-boot research becomes public.
