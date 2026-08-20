#!/usr/bin/env python3
"""Static lineage comparison for the SecureROM DFU descriptor-bearing routine.

Finds heuristic functions that resolve the printable label
"Apple Mobile Device (DFU Mode)" across supplied ROMs and compares normalized
mnemonic sequences. Output is metadata only; no binary patching or device I/O.
"""
from __future__ import annotations
import argparse, collections, difflib, hashlib, json, re
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64_const import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG

LABEL=b"Apple Mobile Device (DFU Mode)"
MAX_INSNS=2048
TARGET_RE=re.compile(r"#?(0x[0-9a-fA-F]+|[0-9]+)")


def load(p): return json.loads(Path(p).read_text())

def md():
    x=Cs(CS_ARCH_ARM64,CS_MODE_ARM); x.detail=True; return x

def decode_map(data, layout):
    text=layout['regions']['TEXT']; base=text['start']; off0=text['offset'] or 0; size=text['size']
    out={}; d=md()
    for off in range(off0,off0+size,4):
        one=list(d.disasm(data[off:off+4],base+(off-off0),count=1))
        if one: out[off]=one[0]
    return out

def file_to_vaddr(layout, off):
    for r in layout['regions'].values():
        ro=r.get('offset'); sz=r.get('size')
        if ro is not None and ro <= off < ro+sz:
            return r['start']+(off-ro)
    return None

def vaddr_to_file(layout, addr):
    for r in layout['regions'].values():
        if r['start'] <= addr < r['end'] and r.get('offset') is not None:
            return r['offset']+(addr-r['start'])
    return None

def branch_target(ins):
    if ins.mnemonic.lower()!='bl': return None
    m=TARGET_RE.search(ins.op_str)
    return int(m.group(1),0) if m else None

def is_prologue(win):
    if any(x is None for x in win): return False
    m=[x.mnemonic.lower() for x in win]; o=[x.op_str.lower() for x in win]
    if m[0] in ('paciasp','pacibsp'): return m[1]=='stp' or (m[1]=='sub' and 'sp' in o[1])
    if m[0]=='stp' and 'x29' in o[0] and 'x30' in o[0] and 'sp' in o[0]: return True
    if m[0]=='sub' and o[0].startswith('sp, sp'): return m[1] in ('stp','mov','add')
    return False

def discover(data,layout):
    by=decode_map(data,layout); starts=set()
    for off,ins in by.items():
        if is_prologue([by.get(off),by.get(off+4),by.get(off+8)]): starts.add(off)
        t=branch_target(ins)
        if t is not None:
            tf=vaddr_to_file(layout,t)
            if tf in by: starts.add(tf)
    funcs=[]
    for s in sorted(starts):
        body=[]; off=s
        for i in range(MAX_INSNS):
            cur=by.get(off)
            if cur is None: break
            if i>=3 and off in starts and off!=s: break
            body.append(cur); off+=4
            if cur.mnemonic.lower() in ('ret','retaa','retab'): break
        if len(body)>=3 and body[-1].mnemonic.lower() in ('ret','retaa','retab'):
            funcs.append((s,body))
    return funcs

def resolved_targets(body):
    regs={}; targets=[]
    for ins in body:
        ops=ins.operands; m=ins.mnemonic.lower()
        if m in ('adr','adrp') and len(ops)>=2 and ops[0].type==ARM64_OP_REG and ops[1].type==ARM64_OP_IMM:
            regs[ops[0].reg]=ops[1].imm
            if m=='adr': targets.append(ops[1].imm)
        elif m=='add' and len(ops)>=3 and ops[0].type==ARM64_OP_REG and ops[1].type==ARM64_OP_REG and ops[2].type==ARM64_OP_IMM:
            if ops[1].reg in regs:
                regs[ops[0].reg]=regs[ops[1].reg]+ops[2].imm; targets.append(regs[ops[0].reg])
            else: regs.pop(ops[0].reg,None)
        elif m.startswith('ldr') and len(ops)>=2:
            if ops[1].type==ARM64_OP_IMM: targets.append(ops[1].imm)
            elif ops[1].type==ARM64_OP_MEM and ops[1].mem.base in regs:
                targets.append(regs[ops[1].mem.base]+ops[1].mem.disp)
            if ops[0].type==ARM64_OP_REG: regs.pop(ops[0].reg,None)
    return targets

def features(body):
    c=collections.Counter(x.mnemonic.lower() for x in body)
    return {'insns':len(body),'direct_calls':c['bl'],'returns':c['ret']+c['retaa']+c['retab'],
            'conditional_branches':sum(v for k,v in c.items() if k in ('cbz','cbnz','tbz','tbnz') or k.startswith('b.')),
            'compares':c['cmp']+c['cmn']+c['tst']+c['ccmp']}

def find_label_functions(data,layout):
    label_offsets=[]; pos=0
    while True:
        i=data.find(LABEL,pos)
        if i<0: break
        label_offsets.append(i); pos=i+1
    label_v={file_to_vaddr(layout,x) for x in label_offsets}
    matches=[]
    for start,body in discover(data,layout):
        refs=set(resolved_targets(body))
        if refs & label_v:
            mn=[x.mnemonic.lower() for x in body]
            matches.append({'start':start,'insns':len(body),'features':features(body),'mnemonics':mn,
                            'fingerprint':hashlib.sha256(' '.join(mn).encode()).hexdigest()})
    return label_offsets,matches

def sim(a,b): return difflib.SequenceMatcher(None,a['mnemonics'],b['mnemonics'],autojunk=False).ratio()
def clean(x): return {k:v for k,v in x.items() if k!='mnemonics'}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--image',action='append',nargs=3,metavar=('LABEL','ROM','LAYOUT'),required=True)
    ap.add_argument('--output',type=Path)
    args=ap.parse_args()
    images=[]
    for label,rom,lay in args.image:
        data=Path(rom).read_bytes(); layout=load(lay); offs,funcs=find_label_functions(data,layout)
        images.append({'label':label,'layout':{'app':layout.get('app'),'version':layout.get('version'),'target':layout.get('target')},
                       'rom_sha256':hashlib.sha256(data).hexdigest(),'descriptor_offsets':offs,'functions':funcs})
    comparisons=[]
    for i in range(len(images)):
        for j in range(i+1,len(images)):
            a,b=images[i],images[j]; pairs=[]
            for fa in a['functions']:
                for fb in b['functions']:
                    pairs.append({'a_start':fa['start'],'b_start':fb['start'],'a_insns':fa['insns'],'b_insns':fb['insns'],
                                  'mnemonic_similarity':round(sim(fa,fb),4)})
            pairs.sort(key=lambda x:x['mnemonic_similarity'],reverse=True)
            comparisons.append({'a':a['label'],'b':b['label'],'best_pairs':pairs[:8]})
    out={'descriptor':LABEL.decode(),'images':[{**{k:v for k,v in x.items() if k!='functions'},'functions':[clean(f) for f in x['functions']]} for x in images],
         'comparisons':comparisons,
         'note':'Descriptor-bearing function lineage is static labeling only; similarity does not establish shared semantics or vulnerability.'}
    text=json.dumps(out,indent=2,sort_keys=True); print(text)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_text(text+'\n')
if __name__=='__main__': main()
