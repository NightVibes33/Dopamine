import importlib.util
import sys
import unittest
from pathlib import Path

MODULE = Path(__file__).with_name("cloudattestation_policy_compare.py")
spec = importlib.util.spec_from_file_location("cloudcompare", MODULE)
cloudcompare = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = cloudcompare
spec.loader.exec_module(cloudcompare)


class AnalyzerTests(unittest.TestCase):
    def test_normalize_control_flow_and_memory_classes(self):
        self.assertEqual(cloudcompare.normalize("b.eq", "0x10"), "branch:b.eq")
        self.assertEqual(cloudcompare.normalize("bl", "_foo"), "call")
        self.assertEqual(cloudcompare.normalize("ldr", "x0, [x1]"), "load:ldr")
        self.assertEqual(cloudcompare.normalize("strb", "w0, [x1]"), "store:strb")

    def test_similarity_ignores_addresses_after_normalization(self):
        left = [cloudcompare.normalize("adrp", "x0, 0x1000"), cloudcompare.normalize("bl", "0x2000")]
        right = [cloudcompare.normalize("adrp", "x0, 0x9000"), cloudcompare.normalize("bl", "0xa000")]
        self.assertEqual(left, right)


if __name__ == "__main__":
    unittest.main()
