#!/usr/bin/env python3
"""Offline AppleAVE2 Prepare -> Build -> Send command-path validator.

Static analysis only. This tool does not open IOKit, invoke AppleAVE2, derive
triggering dimensions, or modify firmware.
"""
import bisect
import struct
import sys
from pathlib import Path

LC_SEGMENT_64 = 0x19
LC_FUNCTION_STARTS = 0x26


def u32(data, off): return struct.unpack_from('<I', data, off)[0]
def u64(data, off): return struct.unpack_from('<Q', data, off)[0]
def signed(value, bits):
    sign = 1 << (bits - 1)
    return value - (1 << bits) if value & sign else value


def decode_uleb(data, off, end):
    value = 0
    shift = 0
    while off < end:
        byte = data[off]
        off += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, off
        shift += 7
    return 0, off


def decode_adrp(word, pc):
    imm = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 3)
    return (pc & ~0xFFF) + (signed(imm, 21) << 12)


class MachO:
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        self.segments = []
        starts = None
        off = 32
        for _ in range(u32(self.data, 16)):
            cmd = u32(self.data, off)
            size = u32(self.data, off + 4)
            if cmd == LC_SEGMENT_64:
                name = self.data[off + 8:off + 24].split(b'\0')[0].decode(errors='replace')
                self.segments.append({
                    'name': name,
                    'vmaddr': u64(self.data, off + 24),
                    'vmsize': u64(self.data, off + 32),
                    'fileoff': u64(self.data, off + 40),
                    'filesize': u64(self.data, off + 48),
                })
            elif cmd == LC_FUNCTION_STARTS:
                starts = (u32(self.data, off + 8), u32(self.data, off + 12))
            off += size
        self.text = next(s for s in self.segments if s['name'] == '__TEXT')
        self.exec = next(s for s in self.segments if s['name'] == '__TEXT_EXEC')
        pos, size = starts
        end = pos + size
        address = self.text['vmaddr']
        self.functions = []
        while pos < end:
            delta, pos = decode_uleb(self.data, pos, end)
            if not delta: break
            address += delta
            self.functions.append(address)
        self.function_set = set(self.functions)

    def fileoff_to_va(self, off):
        for seg in self.segments:
            if seg['fileoff'] <= off < seg['fileoff'] + seg['filesize']:
                return seg['vmaddr'] + off - seg['fileoff']
        return None

    def va_to_fileoff(self, va):
        for seg in self.segments:
            if seg['vmaddr'] <= va < seg['vmaddr'] + seg['vmsize']:
                return seg['fileoff'] + va - seg['vmaddr']
        return None

    def function_for_va(self, va):
        index = bisect.bisect_right(self.functions, va) - 1
        return self.functions[index] if index >= 0 else None

    def function_end(self, start):
        index = bisect.bisect_left(self.functions, start)
        return self.functions[index + 1] if index + 1 < len(self.functions) else self.exec['vmaddr'] + self.exec['vmsize']

    def words(self, start):
        begin = self.va_to_fileoff(start)
        end = self.va_to_fileoff(self.function_end(start))
        return [(self.fileoff_to_va(off), u32(self.data, off)) for off in range(begin, end, 4)]

    def calls(self, start):
        result = []
        for pc, word in self.words(start):
            if word & 0xFC000000 != 0x94000000:
                continue
            target = (pc + signed(word & 0x03FFFFFF, 26) * 4) & 0xFFFFFFFFFFFFFFFF
            if target in self.function_set:
                result.append((pc, target))
        return result

    def refs_to_string(self, text):
        off = self.data.find(text.encode() + b'\0')
        if off < 0: return []
        va = self.fileoff_to_va(off)
        page = va & ~0xFFF
        page_off = va & 0xFFF
        refs = []
        start = self.exec['fileoff']
        end = start + self.exec['filesize']
        for fileoff in range(start, end - 24, 4):
            word = u32(self.data, fileoff)
            if word & 0x9F000000 != 0x90000000:
                continue
            pc = self.fileoff_to_va(fileoff)
            if decode_adrp(word, pc) != page:
                continue
            reg = word & 31
            for delta in range(4, 24, 4):
                nxt = u32(self.data, fileoff + delta)
                if nxt & 0x7F000000 != 0x11000000 or ((nxt >> 5) & 31) != reg:
                    continue
                imm = (nxt >> 10) & 0xFFF
                if (nxt >> 22) & 1: imm <<= 12
                if imm == page_off:
                    refs.append(pc)
                    break
        return refs

    def functions_for_string(self, text):
        return sorted({self.function_for_va(ref) for ref in self.refs_to_string(text)})

    def referenced_strings(self, start):
        result = []
        for pc, word in self.words(start):
            if word & 0x9F000000 != 0x90000000:
                continue
            page = decode_adrp(word, pc)
            reg = word & 31
            words = self.words(start)
            index = next((i for i, item in enumerate(words) if item[0] == pc), None)
            if index is None: continue
            for _, nxt in words[index + 1:index + 7]:
                if nxt & 0x7F000000 != 0x11000000 or ((nxt >> 5) & 31) != reg:
                    continue
                imm = (nxt >> 10) & 0xFFF
                if (nxt >> 22) & 1: imm <<= 12
                va = page + imm
                off = self.va_to_fileoff(va)
                if off is None: break
                raw = self.data[off:off + 400].split(b'\0')[0]
                if raw and all(32 <= b < 127 or b in (9, 10, 13) for b in raw):
                    value = raw.decode(errors='replace')
                    if value not in result: result.append(value)
                break
        return result


def unique_named_function(macho, name, predicate=None):
    funcs = macho.functions_for_string(name)
    if predicate:
        funcs = [f for f in funcs if predicate(f)]
    if len(funcs) != 1:
        raise RuntimeError(f'{name}: expected one function, got {funcs}')
    return funcs[0]


def direct_call_pc(macho, caller, target):
    matches = [pc for pc, dest in macho.calls(caller) if dest == target]
    if not matches: raise RuntimeError(f'0x{caller:x} does not call 0x{target:x}')
    return matches[0]


def analyze_one(path):
    m = MachO(path)
    prep = unique_named_function(m, 'AVE_CHM_PrepareDataInfo')
    builders = {
        codec: unique_named_function(m, f'AVE_CHM_MakeFwCmd_Process_{codec}')
        for codec in ('AVC', 'HEVC', 'AV1')
    }
    send_process = unique_named_function(m, 'SendFwCmd_Process')
    lower_candidates = m.functions_for_string('SendFwCmd')
    lower_send = None
    for f in lower_candidates:
        strings = m.referenced_strings(f)
        if 'pCHM != nullptr && pBuf != nullptr && size > 0' in strings:
            lower_send = f
            break
    if lower_send is None: raise RuntimeError('lower SendFwCmd not found')

    ready_candidates = m.functions_for_string('ProcessReadyCmd_Process')
    ready = None
    for f in ready_candidates:
        calls = [target for _, target in m.calls(f)]
        if prep in calls and send_process in calls:
            ready = f
            break
    if ready is None: raise RuntimeError('ProcessReadyCmd_Process state-machine function not found')

    prep_pc = direct_call_pc(m, ready, prep)
    send_process_pc = direct_call_pc(m, ready, send_process)
    if prep_pc >= send_process_pc:
        raise RuntimeError('PrepareDataInfo does not precede SendFwCmd_Process')

    send_calls = m.calls(send_process)
    builder_pcs = {codec: direct_call_pc(m, send_process, func) for codec, func in builders.items()}
    lower_pc = direct_call_pc(m, send_process, lower_send)
    if not all(pc < lower_pc for pc in builder_pcs.values()):
        raise RuntimeError('codec command builder does not precede lower SendFwCmd')

    return {
        'm': m,
        'ready': ready,
        'prep': prep,
        'builders': builders,
        'send_process': send_process,
        'lower_send': lower_send,
        'prep_pc': prep_pc,
        'send_process_pc': send_process_pc,
        'builder_pcs': builder_pcs,
        'lower_pc': lower_pc,
        'lower_strings': m.referenced_strings(lower_send),
    }


def descriptor(result, function):
    m = result['m']
    return (m.functions.index(function), m.function_end(function) - function)


def main():
    if len(sys.argv) != 4:
        raise SystemExit('usage: ave_command_submission_map.py <beta3-AppleAVE2> <beta4-AppleAVE2> <output.md>')
    b3 = analyze_one(sys.argv[1])
    b4 = analyze_one(sys.argv[2])

    stable = ['prep', 'send_process']
    for key in stable:
        if descriptor(b3, b3[key]) != descriptor(b4, b4[key]):
            raise RuntimeError(f'{key} function identity/size changed unexpectedly')
    for codec in ('AVC', 'HEVC', 'AV1'):
        if descriptor(b3, b3['builders'][codec]) != descriptor(b4, b4['builders'][codec]):
            raise RuntimeError(f'{codec} command builder identity/size changed unexpectedly')

    b3_lower = descriptor(b3, b3['lower_send'])
    b4_lower = descriptor(b4, b4['lower_send'])
    if b3_lower[0] != b4_lower[0]: raise RuntimeError('lower SendFwCmd function identity changed')
    if b4_lower[1] - b3_lower[1] != 0x100: raise RuntimeError('unexpected SendFwCmd size delta')

    slot_guard = '0 <= fwCmdSlot && fwCmdSlot < (AVE_Cmd_Max + (((3 + 2) + 2 + 5 + (2 + 1)) * ((2) < ((63 + 1)) ? (2) : ((63 + 1)))))'
    if slot_guard in b3['lower_strings']: raise RuntimeError('beta3 unexpectedly has command-slot guard')
    if slot_guard not in b4['lower_strings']: raise RuntimeError('beta4 command-slot guard missing')

    out = [
        '# AppleAVE2 firmware command submission map', '',
        'Static/offline validation only. No AppleAVE2 selector is invoked and no triggering input is generated.', '',
        '## Proven command path', '',
        '`ProcessReadyCmd_Process -> AVE_CHM_PrepareDataInfo -> SendFwCmd_Process -> AVE_CHM_MakeFwCmd_Process_{AVC|HEVC|AV1} -> SendFwCmd`', '',
        f"- beta3 ProcessReadyCmd_Process: `0x{b3['ready']:x}`",
        f"- beta3 PrepareDataInfo call: `0x{b3['prep_pc']:x}`",
        f"- beta3 SendFwCmd_Process call: `0x{b3['send_process_pc']:x}`",
        f"- beta3 lower SendFwCmd call: `0x{b3['lower_pc']:x}`", '',
        '## Beta3 -> beta4 structural comparison', '',
    ]
    for label, key in [('PrepareDataInfo', 'prep'), ('SendFwCmd_Process', 'send_process')]:
        i3, s3 = descriptor(b3, b3[key]); i4, s4 = descriptor(b4, b4[key])
        out.append(f'- `{label}`: same function index `{i3}` and same size `0x{s3:x}`')
    for codec in ('AVC', 'HEVC', 'AV1'):
        i3, s3 = descriptor(b3, b3['builders'][codec])
        out.append(f'- `MakeFwCmd_Process_{codec}`: same function index `{i3}` and same size `0x{s3:x}`')
    out += [
        f"- lower `SendFwCmd`: same function index `{b3_lower[0]}`, grows from `0x{b3_lower[1]:x}` to `0x{b4_lower[1]:x}` (+`0x100`)",
        '- beta4 adds a `fwCmdSlot` command-table bounds guard that is absent in beta3', '',
        '## Interpretation', '',
        'The normal frame path prepares firmware buffer/data information before building and sending the codec-specific IPC command. The codec command builders and SendFwCmd_Process remain structurally stable across beta3 and beta4. The distinct lower-level SendFwCmd growth is explained by a new firmware-command-slot bounds check, not by a newly introduced CodedData length assertion.', '',
        'Combined with the separate allocation and firmware-handoff validators, this keeps the current CodedData hypothesis centered on the upstream frame-dimension sizing hardening. It still does not prove a firmware out-of-bounds write or a useful kernel primitive.'
    ]
    Path(sys.argv[3]).write_text('\n'.join(out) + '\n')
    print('\n'.join(out))

if __name__ == '__main__':
    main()
