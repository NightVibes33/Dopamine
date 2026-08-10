#!/usr/bin/env python3
import importlib.util
import pathlib
import unittest

MODULE_PATH = pathlib.Path(__file__).with_name('ave_arithmetic_guard_map.py')
spec = importlib.util.spec_from_file_location('ave_arithmetic_guard_map', MODULE_PATH)
ave = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ave)


def smull(rd, rn, rm):
    return 0x9B200000 | (rm << 16) | (31 << 10) | (rn << 5) | rd


def mul_w(rd, rn, rm):
    return 0x1B000000 | (rm << 16) | (31 << 10) | (rn << 5) | rd


def lsr_x_31(rd, rn):
    return 0xD340FC00 | (31 << 16) | (rn << 5) | rd


def cbnz_x(rt):
    return 0xB5000000 | rt


class ArithmeticGuardPatternTests(unittest.TestCase):
    def words(self, *instructions):
        return [(0x1000 + index * 4, instruction) for index, instruction in enumerate(instructions)]

    def test_accepts_register_linked_beta4_guard(self):
        words = self.words(
            smull(25, 4, 3),
            lsr_x_31(8, 25),
            cbnz_x(8),
        )
        guard = ave.find_wide_product_guard(words)
        self.assertIsNotNone(guard)
        self.assertEqual(guard['multiply_pc'], 0x1000)
        self.assertEqual(guard['shift_pc'], 0x1004)
        self.assertEqual(guard['branch_pc'], 0x1008)
        self.assertEqual(guard['product_reg'], 25)
        self.assertEqual(guard['range_reg'], 8)

    def test_rejects_unrelated_lsr_even_when_instructions_are_adjacent(self):
        words = self.words(
            smull(25, 4, 3),
            lsr_x_31(8, 24),
            cbnz_x(8),
        )
        self.assertIsNone(ave.find_wide_product_guard(words))

    def test_rejects_branch_on_different_register(self):
        words = self.words(
            smull(25, 4, 3),
            lsr_x_31(8, 25),
            cbnz_x(9),
        )
        self.assertIsNone(ave.find_wide_product_guard(words))

    def test_rejects_smull_of_unrelated_inputs(self):
        words = self.words(
            smull(25, 5, 6),
            lsr_x_31(8, 25),
            cbnz_x(8),
        )
        self.assertIsNone(ave.find_wide_product_guard(words))

    def test_finds_legacy_32_bit_multiply(self):
        words = self.words(0xD503201F, mul_w(9, 22, 21), 0xD503201F)
        self.assertEqual(ave.find_first_mul_w(words), 0x1004)

    def test_empty_evidence_is_inconclusive_not_positive(self):
        self.assertIsNone(ave.find_wide_product_guard([]))
        self.assertIsNone(ave.find_first_mul_w([]))


if __name__ == '__main__':
    unittest.main()
