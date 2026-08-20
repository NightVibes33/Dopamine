#!/usr/bin/env python3
"""Merge independent static SecureROM triage signals by anonymized candidate ID.

Inputs are the anonymized subsystem report, neighboring-SoC context report, and
read-only string-reference labels. Output intentionally omits ROM addresses and
contains no payloads, patches, device interaction, or exploit instructions.
"""
from __future__ import annotations
import argparse, json
from pathlib import Path


def priority(item):
    tags=set(item.get("static_subsystem_tags",[]))
    score=int(item.get("structural_score",0))
    evidence=item.get("evidence_strength","LOW")
    if "usb_dfu" in tags and score >= 100 and evidence == "MEDIUM":
        return "HIGH_STATIC_REVIEW_PRIORITY"
    if score >= 75:
        return "ELEVATED_STATIC_REVIEW_PRIORITY"
    return "BASELINE_STATIC_REVIEW_PRIORITY"


def hypothesis(tags, archetype):
    tags=set(tags)
    if "usb_dfu" in tags:
        if archetype == "parser_state_machine_like":
            return "DFU-associated control/validation-state logic"
        return "DFU-associated boot-ROM logic"
    return f"unlabeled {archetype.replace('_',' ')}"


def build_report(subsystem,cross,strings):
    cross_by={x["candidate_id"]:x for x in cross.get("ranked_candidates",[])}
    labels_by={f"CAND-{int(x.get('rank',0)):03d}":x for x in strings.get("ranked_candidates",[]) if x.get("rank")}
    out=[]
    for base in subsystem.get("ranked_candidates",[]):
        cid=base["candidate_id"]
        ctx=cross_by.get(cid,{})
        lab=labels_by.get(cid,{})
        tags=lab.get("subsystem_tags",[]) or []
        labels=lab.get("unique_printable_labels",[]) or []
        item={
            "candidate_id":cid,
            "archetype":base.get("archetype"),
            "structural_score":base.get("structural_score",0),
            "evidence_strength":base.get("evidence_strength","LOW"),
            "source_kind":base.get("source_kind","unknown"),
            "static_subsystem_tags":tags,
            "static_labels":labels,
            "A14_similarity":(ctx.get("A14_t8103") or {}).get("best_similarity"),
            "A16_similarity":(ctx.get("A16_t8120") or {}).get("best_similarity"),
            "neighboring_generation_context":ctx.get("context_pattern","unknown"),
            "hypothesis_scope":hypothesis(tags,base.get("archetype","unknown")),
            "vulnerability_status":"NOT_ESTABLISHED",
        }
        item["research_priority"]=priority(item)
        out.append(item)
    counts={}
    for x in out:
        counts[x["research_priority"]]=counts.get(x["research_priority"],0)+1
    return {
        "candidate_count":len(out),
        "labeled_candidate_count":sum(bool(x["static_labels"]) for x in out),
        "tagged_candidate_count":sum(bool(x["static_subsystem_tags"]) for x in out),
        "priority_counts":dict(sorted(counts.items())),
        "ranked_candidates":out,
        "decision_rule":"priority reflects convergence of independent static signals; it is not an exploitability score",
        "limitations":[
            "string references are heuristic labels and do not prove full function identity",
            "cross-generation similarity supplies ancestry/context only",
            "structural deltas can reflect hardware stepping, refactoring, diagnostics, hardening, or bug fixes",
            "all candidates remain NOT_ESTABLISHED until independently validated",
        ],
    }


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("subsystem",type=Path)
    ap.add_argument("cross_soc",type=Path)
    ap.add_argument("strings",type=Path)
    ap.add_argument("--output",type=Path)
    args=ap.parse_args()
    report=build_report(json.loads(args.subsystem.read_text()),json.loads(args.cross_soc.read_text()),json.loads(args.strings.read_text()))
    text=json.dumps(report,indent=2,sort_keys=True)
    print(text)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(text+"\n",encoding="utf-8")

if __name__=="__main__": main()
