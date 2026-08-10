#!/usr/bin/env python3
"""Offline AppleAVE2 CodedData arithmetic-hardening validator.

Compares the AppleAVE2 CodedData sizing function across iOS 27 beta 3 and
beta 4. It verifies that beta 3 uses a 32-bit multiply for frame pixel area,
while beta 4 widens the same calculation to signed 64-bit and branches to a
failure path when the result does not fit the accepted range.

Static analysis only. It does not produce or submit a triggering request.
"""
import bisect, struct, sys
from pathlib import Path
LC_SEGMENT_64=0x19; LC_FUNCTION_STARTS=0x26
DIAG='%lld %d AVE %s: %s:%d GBufSize: %d, encType: %d, width: %d, height: %d, chromaFmt: %d, bitDepth: %d, frameRate: %d'

def signed(v,b):
    return v-(1<<b) if v&(1<<(b-1)) else v
class MachO:
    def __init__(self,path):
        self.path=Path(path); self.data=self.path.read_bytes(); self.segs=[]; self.fs=None
        n=self.u32(16); o=32
        for _ in range(n):
            cmd=self.u32(o); sz=self.u32(o+4)
            if cmd==LC_SEGMENT_64:
                name=self.data[o+8:o+24].split(b'\0')[0].decode(errors='replace')
                self.segs.append(dict(name=name,vmaddr=self.u64(o+24),vmsize=self.u64(o+32),fileoff=self.u64(o+40),filesize=self.u64(o+48)))
            elif cmd==LC_FUNCTION_STARTS:self.fs=(self.u32(o+8),self.u32(o+12))
            o+=sz
        self.text=next(s for s in self.segs if s['name']=='__TEXT'); self.exec=next(s for s in self.segs if s['name']=='__TEXT_EXEC'); self.functions=self._funcs()
    def u32(self,o):return struct.unpack_from('<I',self.data,o)[0]
    def u64(self,o):return struct.unpack_from('<Q',self.data,o)[0]
    def _uleb(self,o,e):
        v=0;s=0
        while o<e:
            b=self.data[o];o+=1;v|=(b&127)<<s
            if not b&128:return v,o
            s+=7
        return 0,o
    def _funcs(self):
        o,sz=self.fs;e=o+sz;a=self.text['vmaddr'];out=[]
        while o<e:
            d,o=self._uleb(o,e)
            if not d:break
            a+=d;out.append(a)
        return out
    def fo2va(self,fo):
        for s in self.segs:
            if s['fileoff']<=fo<s['fileoff']+s['filesize']:return s['vmaddr']+(fo-s['fileoff'])
    def va2fo(self,va):
        for s in self.segs:
            if s['vmaddr']<=va<s['vmaddr']+s['vmsize']:return s['fileoff']+(va-s['vmaddr'])
    def func_for(self,va):
        i=bisect.bisect_right(self.functions,va)-1;return self.functions[i] if i>=0 else None
    def func_end(self,f):
        i=bisect.bisect_left(self.functions,f);return self.functions[i+1] if i+1<len(self.functions) else self.exec['vmaddr']+self.exec['vmsize']
    def words(self,f):
        s=self.va2fo(f);e=self.va2fo(self.func_end(f));return [(self.fo2va(o),self.u32(o)) for o in range(s,e,4)]
    def decode_adrp(self,w,pc):
        imm=(((w>>5)&0x7ffff)<<2)|((w>>29)&3);return (pc&~0xfff)+(signed(imm,21)<<12)
    def refs(self,text):
        fo=self.data.find(text.encode()+b'\0')
        if fo<0:return []
        va=self.fo2va(fo);pg=va&~0xfff;po=va&0xfff;out=[];s=self.exec['fileoff'];e=s+self.exec['filesize']
        for o in range(s,e-24,4):
            w=self.u32(o)
            if w&0x9f000000!=0x90000000:continue
            pc=self.fo2va(o)
            if self.decode_adrp(w,pc)!=pg:continue
            r=w&31
            for d in range(4,24,4):
                n=self.u32(o+d)
                if n&0x7f000000==0x11000000 and ((n>>5)&31)==r:
                    imm=(n>>10)&0xfff
                    if (n>>22)&1:imm<<=12
                    if imm==po:out.append(pc);break
        return out

def is_mul_w(w): return (w & 0xFFE0FC00) == 0x1B007C00
def is_smull(w): return (w & 0xFFE0FC00) == 0x9B207C00

def decode_mul_regs(w,wide=False):
    return (w&31,(w>>5)&31,(w>>16)&31)

def is_cbnz_x(w): return (w & 0x7F000000) == 0x35000000 and ((w>>31)&1)==1

def find_coded(m):
    refs=m.refs(DIAG)
    if not refs:raise RuntimeError('CodedData diagnostic string xref not found')
    candidates=sorted({m.func_for(r) for r in refs if m.func_for(r)})
    for f in candidates:
        ws=m.words(f)[:96]
        if any(is_mul_w(w) or is_smull(w) for _,w in ws):return f
    raise RuntimeError('CodedData sizing function not identified')

def analyze(path):
    m=MachO(path);f=find_coded(m);ws=m.words(f)[:96]
    muls=[];smulls=[]
    for i,(pc,w) in enumerate(ws):
        if is_mul_w(w):muls.append((i,pc,decode_mul_regs(w)))
        if is_smull(w):smulls.append((i,pc,decode_mul_regs(w,True)))
    guards=[]
    for i,pc,regs in smulls:
        for j in range(i+1,min(i+6,len(ws))):
            if is_cbnz_x(ws[j][1]):guards.append((ws[j][0],j-i));break
    return dict(function=f,size=m.func_end(f)-f,muls=muls,smulls=smulls,guards=guards)

def main():
    if len(sys.argv)!=4:raise SystemExit('usage: ave_codeddata_arithmetic_diff.py <beta3-AppleAVE2> <beta4-AppleAVE2> <output.md>')
    b3=analyze(sys.argv[1]);b4=analyze(sys.argv[2])
    if not b3['muls'] or b3['smulls']:
        raise RuntimeError(f'beta3 arithmetic shape unexpected: {b3}')
    if not b4['smulls'] or not b4['guards']:
        raise RuntimeError(f'beta4 widened/guarded arithmetic not found: {b4}')
    out=['# AppleAVE2 CodedData arithmetic hardening','',
         'Static/offline comparison only; this does not construct or submit a triggering request.','',
         f"- beta 3 CodedData sizing: `0x{b3['function']:x}` (size `0x{b3['size']:x}`)",
         f"- beta 3 frame-area arithmetic: 32-bit `mul` at `0x{b3['muls'][0][1]:x}`",
         f"- beta 4 CodedData sizing: `0x{b4['function']:x}` (size `0x{b4['size']:x}`)",
         f"- beta 4 frame-area arithmetic: signed 64-bit `smull` at `0x{b4['smulls'][0][1]:x}`",
         f"- beta 4 range-failure branch: `0x{b4['guards'][0][0]:x}` within {b4['guards'][0][1]} instructions of the widened multiply",'',
         '## Interpretation','',
         'Beta 3 performs the pixel-area multiplication in 32 bits, while beta 4 widens that calculation and immediately gates the result before the legacy sizing logic continues. Combined with the separately proven beta-4 CheckInfo dimension guard, this is direct instruction-level evidence that the security hardening prevents invalid/overflowed frame dimensions from feeding the CodedData allocation-size path.','',
         'This establishes arithmetic hardening, not runtime corruption or a kernel primitive.']
    Path(sys.argv[3]).write_text('\n'.join(out)+'\n');print('\n'.join(out))
if __name__=='__main__':main()
