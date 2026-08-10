#!/usr/bin/env python3
"""Offline AppleAVE2 CodedData firmware-handoff validator. No IOKit calls."""
import bisect, collections, struct, sys
from pathlib import Path
LC_SEGMENT_64=0x19; LC_FUNCTION_STARTS=0x26

def sgn(v,b): return v-(1<<b) if v&(1<<(b-1)) else v

def uleb(d,o,e):
    v=0; sh=0
    while o<e:
        b=d[o]; o+=1; v|=(b&0x7f)<<sh
        if not b&0x80:return v,o
        sh+=7
    return 0,o

class M:
    def __init__(self,p):
        self.d=Path(p).read_bytes(); self.segs=[]; fs=None
        U32=lambda o:struct.unpack_from('<I',self.d,o)[0]; U64=lambda o:struct.unpack_from('<Q',self.d,o)[0]
        self.U32=U32; o=32
        for _ in range(U32(16)):
            c=U32(o); z=U32(o+4)
            if c==LC_SEGMENT_64:
                n=self.d[o+8:o+24].split(b'\0')[0].decode(errors='replace')
                self.segs.append(dict(n=n,v=U64(o+24),vs=U64(o+32),f=U64(o+40),fs=U64(o+48)))
            elif c==LC_FUNCTION_STARTS: fs=(U32(o+8),U32(o+12))
            o+=z
        self.text=next(s for s in self.segs if s['n']=='__TEXT'); self.x=next(s for s in self.segs if s['n']=='__TEXT_EXEC')
        o,z=fs; e=o+z; a=self.text['v']; self.fn=[]
        while o<e:
            q,o=uleb(self.d,o,e)
            if not q:break
            a+=q; self.fn.append(a)
    def f2v(self,o):
        for s in self.segs:
            if s['f']<=o<s['f']+s['fs']:return s['v']+o-s['f']
    def v2f(self,v):
        for s in self.segs:
            if s['v']<=v<s['v']+s['vs']:return s['f']+v-s['v']
    def func(self,v):
        i=bisect.bisect_right(self.fn,v)-1; return self.fn[i] if i>=0 else None
    def end(self,f):
        i=bisect.bisect_left(self.fn,f); return self.fn[i+1] if i+1<len(self.fn) else self.x['v']+self.x['vs']
    def words(self,f):
        a=self.v2f(f); b=self.v2f(self.end(f)); return [(self.f2v(o),self.U32(o)) for o in range(a,b,4)]
    def calls(self,f):
        out=[]
        for pc,w in self.words(f):
            if w&0xfc000000==0x94000000:
                t=(pc+sgn(w&0x03ffffff,26)*4)&0xffffffffffffffff
                if self.func(t)==t:out.append(t)
        return out
    def adrp(self,w,pc):
        imm=(((w>>5)&0x7ffff)<<2)|((w>>29)&3); return (pc&~0xfff)+(sgn(imm,21)<<12)
    def refs(self,s):
        o=self.d.find(s.encode()+b'\0')
        if o<0:return []
        v=self.f2v(o); pg=v&~0xfff; po=v&0xfff; out=[]
        for f in range(self.x['f'],self.x['f']+self.x['fs']-24,4):
            w=self.U32(f)
            if w&0x9f000000!=0x90000000:continue
            pc=self.f2v(f)
            if self.adrp(w,pc)!=pg:continue
            r=w&31
            for dd in range(4,24,4):
                n=self.U32(f+dd)
                if n&0x7f000000==0x11000000 and ((n>>5)&31)==r:
                    imm=(n>>10)&0xfff
                    if (n>>22)&1:imm<<=12
                    if imm==po:out.append(pc);break
        return out

def movx(w):
    if w&0xffe0ffe0==0xaa0003e0:return w&31,(w>>16)&31

def ldrw(w):
    if w&0xffc00000==0xb9400000:return w&31,(w>>5)&31,((w>>10)&0xfff)*4

def strw(w):
    if w&0xffc00000==0xb9000000:return w&31,(w>>5)&31,((w>>10)&0xfff)*4

def strx(w):
    if w&0xffc00000==0xf9000000:return w&31,(w>>5)&31,((w>>10)&0xfff)*8

def find_surface_export_helper(m,forwarder):
    counts=collections.Counter(m.calls(forwarder))
    for target,_ in counts.most_common():
        words=m.words(target)
        if not any(movx(w)==(19,0) for _,w in words[:20]):continue
        if not any(movx(w)==(20,3) for _,w in words[:20]):continue
        loadpc=storepc=None
        for i,(pc,w) in enumerate(words):
            ld=ldrw(w)
            if not ld or ld[1:]!=(19,0x100):continue
            for pc2,w2 in words[i+1:i+8]:
                if strw(w2)==(ld[0],20,8):loadpc=pc;storepc=pc2;break
            if storepc:break
        if not storepc:continue
        addrstore=next((pc for pc,w in words if (lambda x:x and x[1]==20 and x[2]==0)(strx(w))),None)
        if addrstore:return target,loadpc,storepc,addrstore,counts[target]
    raise RuntimeError('surface-to-firmware descriptor export helper not found')

def analyze(p3,p4):
    key='pBufSet->saCodedData[i].iAddr != 0 && pBufSet->saCodedData[i].iSize != 0'
    copykey='%lld %d AVE %s: %s:%d fail to copy bitstream %lld %p %p | %p %d %d'
    out={}
    for label,path in [('beta3',p3),('beta4',p4)]:
        m=M(path); rr=m.refs(key)
        if not rr:raise RuntimeError(label+' CodedData firmware-buffer assertion missing')
        f=m.func(rr[0]); idx=m.fn.index(f); size=m.end(f)-f
        helper,lp,sp,ap,count=find_surface_export_helper(m,f)
        cr=m.refs(copykey)
        if not cr:raise RuntimeError(label+' output-copy diagnostic missing')
        cf=m.func(cr[0])
        out[label]=dict(forwarder=f,index=idx,size=size,helper=helper,helper_index=m.fn.index(helper),helper_size=m.end(helper)-helper,size_load=lp,size_store=sp,addr_store=ap,helper_calls=count,copy=cf,copy_index=m.fn.index(cf),copy_size=m.end(cf)-cf)
    if out['beta3']['index']!=out['beta4']['index']:raise RuntimeError('CodedData handoff function identity changed')
    if out['beta3']['helper_index']!=out['beta4']['helper_index']:raise RuntimeError('surface export helper identity changed')
    if out['beta3']['copy_index']!=out['beta4']['copy_index']:raise RuntimeError('output copy function identity changed')
    return out

def main():
    if len(sys.argv)!=4:raise SystemExit('usage: ave_codeddata_consumer_map.py <b3> <b4> <out>')
    r=analyze(sys.argv[1],sys.argv[2]); a=r['beta3']; b=r['beta4']
    lines=['# AppleAVE2 CodedData firmware handoff','', 'Static/offline analysis only. No selector invocation or triggering values.','',
        f"- beta3 CodedData buffer-set function: `0x{a['forwarder']:x}` (function index `{a['index']}`, size `0x{a['size']:x}`)",
        f"- beta4 counterpart: `0x{b['forwarder']:x}` (same index, size `0x{b['size']:x}`)",
        f"- beta3 surface export helper: `0x{a['helper']:x}` (function index `{a['helper_index']}`)",
        f"- beta4 counterpart: `0x{b['helper']:x}` (same index)",
        f"- helper copies the backing surface size from surface-object `+0x100` into firmware descriptor `+0x8` (beta3 load `0x{a['size_load']:x}`, store `0x{a['size_store']:x}`)",
        f"- helper also writes the mapped/DART address into firmware descriptor `+0x0` (beta3 `0x{a['addr_store']:x}`)",
        f"- beta3 output bitstream-copy function: `0x{a['copy']:x}` (index `{a['copy_index']}`, size `0x{a['copy_size']:x}`)",
        f"- beta4 counterpart: `0x{b['copy']:x}` (same index, size `0x{b['copy_size']:x}`)",
        '', '## Interpretation','',
        'The CodedData surface is exported to the AVE firmware with the actual backing-surface size, not merely an unchecked request-side length. The firmware handoff function and the later CPU output-copy function remain structurally stable across beta3 and beta4. This localizes the security-relevant beta3→beta4 change upstream in validation/sizing rather than in these downstream handoff/copy functions.',
        '', 'The static evidence does not yet prove that AVE firmware writes beyond the supplied surface size. The CPU-side output copy is a separate path and should not be treated as the corruption sink without additional evidence.']
    Path(sys.argv[3]).write_text('\n'.join(lines)+'\n'); print('\n'.join(lines))
if __name__=='__main__':main()
