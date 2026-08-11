#!/usr/bin/env python3
"""Corrected entry point for the LFS cross-IPC validator.

Fixes MOVZ decoding precedence in v1 while preserving the original failed
validator as evidence. Static/offline only.
"""
import ave_lfs_cross_ipc_map as base


def movz_fixed(word):
    # MOVZ Wd,#imm or Xd,#imm. Parentheses are intentional: Python comparison
    # precedence made the v1 mask expression evaluate incorrectly.
    if (word & 0x7F800000) == 0x52800000 or (word & 0xFF800000) == 0xD2800000:
        return word & 31, ((word >> 5) & 0xFFFF) << (((word >> 21) & 3) * 16)
    return None


base.movz = movz_fixed

if __name__ == '__main__':
    base.main()
