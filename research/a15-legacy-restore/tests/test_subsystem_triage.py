from __future__ import annotations
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("subsystem_triage",ROOT/"subsystem-triage.py")
MOD=importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MOD)


class SubsystemTriageTests(unittest.TestCase):
    def test_anonymized_report_omits_offsets(self):
        src={"ranked_candidates":[{
            "kind":"nearby_unmatched_pair",
            "priority_score":120,
            "a_start":0x1234,
            "b_start":0x5678,
            "a_features":{"decoded":20,"compare":6,"conditional_branches":5,"control_flow":8},
            "b_features":{"decoded":40,"compare":10,"conditional_branches":9,"control_flow":12},
            "delta":{"decoded":20,"compare":4,"conditional_branches":4,"control_flow":4},
        }]}
        report=MOD.build_report(src)
        self.assertEqual(report["candidate_count"],1)
        item=report["ranked_candidates"][0]
        self.assertEqual(item["candidate_id"],"CAND-001")
        self.assertEqual(item["vulnerability_status"],"NOT_ESTABLISHED")
        self.assertNotIn("a_start",item)
        self.assertNotIn("b_start",item)
        self.assertEqual(item["archetype"],"parser_state_machine_like")

    def test_small_helper_classification(self):
        row={"kind":"candidate_only","priority_score":7,"b_features":{"decoded":7,"direct_calls":0,"other":7}}
        archetype,_,strength,_=MOD.classify(row)
        self.assertEqual(archetype,"small_helper_or_layout_like")
        self.assertEqual(strength,"LOW")


if __name__=="__main__":
    unittest.main()
