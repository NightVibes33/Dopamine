#!/usr/bin/env python3
"""Classify changed SecureROM candidates into broad static archetypes.

Consumes function-feature-triage JSON and emits anonymized candidate IDs plus
aggregate structural signals. This intentionally omits ROM offsets and does not
produce patches, payloads, device I/O, or exploit instructions.
"""
from __future__ import annotations
import argparse, collections, json
from pathlib import Path

ARCHETYPES=(
    "parser_state_machine_like",
    "memory_transform_like",
    "call_orchestration_like",
    "system_control_like",
    "small_helper_or_layout_like",
)


def merged_features(row):
    a=row.get("a_features",{}) or {}; b=row.get("b_features",{}) or {}
    keys=set(a)|set(b)
    return {k:max(abs(a.get(k,0)),abs(b.get(k,0))) for k in keys}


def archetype_scores(row):
    f=merged_features(row)
    decoded=max(1,f.get("decoded",0))
    compare=f.get("compare",0); cond=f.get("conditional_branches",0)
    control=f.get("control_flow",0); loads=f.get("load",0); stores=f.get("store",0)
    arithmetic=f.get("arithmetic",0); logic=f.get("logic",0); system=f.get("system",0)
    calls=f.get("direct_calls",0)+f.get("indirect_calls",0)
    # Scores are descriptive densities, not vulnerability/exploit scores.
    raw={
        "parser_state_machine_like": (2*compare + 2*cond + control)/decoded,
        "memory_transform_like": (loads + stores + arithmetic + logic)/decoded,
        "call_orchestration_like": (2*calls + control)/decoded,
        "system_control_like": (3*system + f.get("indirect_branches",0))/decoded,
        "small_helper_or_layout_like": (1.0 if decoded <= 16 else 0.0) + (0.25 if calls <= 1 else 0.0),
    }
    return {k:round(v,4) for k,v in raw.items()}


def classify(row):
    scores=archetype_scores(row)
    archetype=max(scores,key=scores.get)
    structural=int(row.get("priority_score",0))
    kind=row.get("kind","unknown")
    similarity=row.get("similarity")
    if structural >= 75 and kind in ("similar_changed","nearby_unmatched_pair"):
        evidence="MEDIUM"
    elif structural >= 25:
        evidence="LOW_MEDIUM"
    else:
        evidence="LOW"
    return archetype,scores,evidence,similarity


def sanitized_delta(row):
    allowed={"decoded","control_flow","load","store","compare","arithmetic","logic","system","direct_calls","indirect_calls","indirect_branches","conditional_branches"}
    return {k:v for k,v in sorted((row.get("delta",{}) or {}).items()) if k in allowed and v}


def build_report(src):
    rows=src.get("ranked_candidates",[]) or []
    out=[]; counts=collections.Counter(); strengths=collections.Counter()
    for index,row in enumerate(rows,1):
        archetype,scores,evidence,similarity=classify(row)
        cid=f"CAND-{index:03d}"
        counts[archetype]+=1; strengths[evidence]+=1
        item={
            "candidate_id":cid,
            "source_kind":row.get("kind","unknown"),
            "structural_score":int(row.get("priority_score",0)),
            "archetype":archetype,
            "archetype_scores":scores,
            "evidence_strength":evidence,
            "feature_delta":sanitized_delta(row),
            "vulnerability_status":"NOT_ESTABLISHED",
        }
        if similarity is not None:
            item["mnemonic_similarity"]=similarity
        out.append(item)
    return {
        "candidate_count":len(out),
        "archetype_counts":dict(sorted(counts.items())),
        "evidence_strength_counts":dict(sorted(strengths.items())),
        "ranked_candidates":out,
        "method":"anonymized classification from aggregate ARM64 instruction-class/function-feature deltas",
        "limitations":[
            "archetypes are static heuristics, not recovered function names",
            "two T8110 revisions are available in the pinned corpus, limiting within-SoC persistence testing",
            "revision changes may represent stepping support, refactoring, diagnostics, hardening, or bug fixes",
            "no candidate is evidence of vulnerability or exploitability without independent validation",
        ],
    }


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("triage",type=Path)
    ap.add_argument("--output",type=Path)
    args=ap.parse_args()
    report=build_report(json.loads(args.triage.read_text()))
    text=json.dumps(report,indent=2,sort_keys=True)
    print(text)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(text+"\n",encoding="utf-8")

if __name__=="__main__": main()
