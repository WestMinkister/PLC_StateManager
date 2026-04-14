#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PLC Upload Response Decoder
PLC에서 읽어온 응답 데이터를 분석하여 프로그램 정보 추출

Usage:
    python plc_upload_decode.py docs/0414_upload_responses.json
"""
import json, struct, bz2, sys, os

def double_decode_ascii_hex(payload_hex, sub_cmd_byte=None):
    """Double-decode LGIS-GLOFA ASCII hex encoding.

    The response parser split byte[26] as 'sub_cmd', but it's actually
    the first ASCII hex character of the data. We must prepend it.

    payload_hex (from JSON) → wire bytes → ASCII string → prepend sub_cmd char → binary
    """
    try:
        wire_bytes = bytes.fromhex(payload_hex)
        ascii_str = wire_bytes.decode('ascii', errors='ignore')

        # Prepend the 'sub_cmd' byte — it's really the first data char
        if sub_cmd_byte is not None:
            first_char = chr(sub_cmd_byte)
            ascii_str = first_char + ascii_str

        # Filter only valid hex chars
        hex_chars = ''.join(c for c in ascii_str if c in '0123456789ABCDEFabcdef')
        if len(hex_chars) >= 2:
            # Ensure even length
            if len(hex_chars) % 2 != 0:
                hex_chars = hex_chars[:-1]
            return bytes.fromhex(hex_chars)
    except Exception:
        pass
    return None

def analyze_responses(filepath):
    with open(filepath) as f:
        responses = json.load(f)

    print(f"Total responses: {len(responses)}")
    print()

    # Group by command
    by_cmd = {}
    for r in responses:
        cmd = r.get('command_char', '?')
        by_cmd.setdefault(cmd, []).append(r)

    for cmd in sorted(by_cmd.keys()):
        print(f"  {cmd}: {len(by_cmd[cmd])} responses")
    print()

    # Process Z responses - these contain program data
    z_responses = by_cmd.get('Z', [])
    print(f"=== Z Responses ({len(z_responses)}) ===\n")

    all_decoded = []  # Collect all decoded binary chunks

    for i, r in enumerate(z_responses):
        payload_hex = r.get('payload_hex', '')
        if not payload_hex:
            continue

        sub_cmd = r.get('sub_cmd')
        binary = double_decode_ascii_hex(payload_hex, sub_cmd_byte=sub_cmd)
        if binary is None:
            continue

        all_decoded.append({'index': i, 'binary': binary, 'response': r})

        # Check for interesting patterns
        findings = []

        # bzip2 magic
        bz_idx = binary.find(b'BZh')
        if bz_idx >= 0:
            findings.append(f"bzip2 at offset {bz_idx}")
            try:
                decompressed = bz2.decompress(binary[bz_idx:])
                findings.append(f"decompressed {len(decompressed)} bytes")
                # Check for readable strings in decompressed data
                readable_parts = extract_strings(decompressed, min_len=4)
                if readable_parts:
                    findings.append(f"strings: {readable_parts[:5]}")
            except Exception as e:
                findings.append(f"bzip2 decompress failed: {e}")

        # ASCII strings in binary
        strings = extract_strings(binary, min_len=4)
        if strings:
            findings.append(f"strings: {strings[:5]}")

        # Known program names
        for name in [b'NewProgram', b'try_again', b'NewProgram2']:
            if name in binary:
                findings.append(f"*** FOUND: {name.decode()} ***")

        # IP addresses (4 consecutive bytes that look like 192.168.x.x)
        for j in range(len(binary) - 3):
            if binary[j] == 192 and binary[j+1] == 168:
                ip = f"{binary[j]}.{binary[j+1]}.{binary[j+2]}.{binary[j+3]}"
                findings.append(f"IP: {ip}")
                break

        # End-of-program marker
        if b'\xfd\xff\x07\x4a' in binary:
            findings.append("*** END-OF-PROGRAM MARKER ***")

        # Print if interesting
        if findings or len(binary) > 50:
            print(f"Z#{i:>2} binary={len(binary):>5}B | {' | '.join(findings)}")
            if len(binary) <= 64:
                print(f"      hex: {binary.hex()}")
            else:
                print(f"      hex: {binary[:32].hex()}...{binary[-16:].hex()}")

    # Also process X responses - bulk data
    x_responses = by_cmd.get('X', [])
    print(f"\n=== X Responses ({len(x_responses)}) ===\n")

    x_decoded_chunks = []
    for i, r in enumerate(x_responses):
        payload_hex = r.get('payload_hex', '')
        if not payload_hex:
            continue
        sub_cmd = r.get('sub_cmd')
        binary = double_decode_ascii_hex(payload_hex, sub_cmd_byte=sub_cmd)
        if binary and len(binary) > 0:
            x_decoded_chunks.append({'index': i, 'binary': binary})

    total_x_binary = sum(len(c['binary']) for c in x_decoded_chunks)
    print(f"Total X decoded binary: {total_x_binary} bytes across {len(x_decoded_chunks)} chunks")

    # Try to find bzip2 or program data in X chunks
    for chunk in x_decoded_chunks:
        binary = chunk['binary']
        bz_idx = binary.find(b'BZh')
        if bz_idx >= 0:
            print(f"  X#{chunk['index']}: bzip2 at offset {bz_idx}")
            try:
                decompressed = bz2.decompress(binary[bz_idx:])
                print(f"    decompressed: {len(decompressed)} bytes")
                strings = extract_strings(decompressed, min_len=4)
                if strings:
                    print(f"    strings: {strings[:10]}")
            except Exception as e:
                print(f"    decompress failed: {e}")

        for name in [b'NewProgram', b'try_again']:
            if name in binary:
                print(f"  X#{chunk['index']}: *** FOUND: {name.decode()} ***")

    # Summary
    print("\n=== SUMMARY ===\n")

    # Collect all bzip2 blocks and try to decompress
    bzip2_blocks = []
    for item in all_decoded:
        binary = item['binary']
        bz_idx = binary.find(b'BZh')
        if bz_idx >= 0:
            try:
                decompressed = bz2.decompress(binary[bz_idx:])
                bzip2_blocks.append({
                    'z_index': item['index'],
                    'compressed_size': len(binary) - bz_idx,
                    'decompressed_size': len(decompressed),
                    'data': decompressed
                })
            except:
                pass

    print(f"bzip2 blocks found and decompressed: {len(bzip2_blocks)}")
    for blk in bzip2_blocks:
        strings = extract_strings(blk['data'], min_len=4)
        print(f"  Z#{blk['z_index']}: {blk['compressed_size']}B → {blk['decompressed_size']}B | strings: {strings[:5]}")

    # Collect all program names found
    all_names = set()
    for item in all_decoded:
        for name in [b'NewProgram', b'NewProgram2', b'try_again']:
            if name in item['binary']:
                all_names.add(name.decode())
    for chunk in x_decoded_chunks:
        for name in [b'NewProgram', b'NewProgram2', b'try_again']:
            if name in chunk['binary']:
                all_names.add(name.decode())

    print(f"\nProgram names found: {all_names if all_names else 'None'}")

    # Try scatter-gather for Z 0xC0 data
    # Check if any Z responses with large data can be reassembled
    print(f"\nTotal Z decoded binary: {sum(len(d['binary']) for d in all_decoded)} bytes")
    print(f"Total X decoded binary: {total_x_binary} bytes")

def extract_strings(data, min_len=4):
    """Extract printable ASCII strings from binary data."""
    strings = []
    current = []
    for b in data:
        if 32 <= b < 127:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                strings.append(''.join(current))
            current = []
    if len(current) >= min_len:
        strings.append(''.join(current))
    return strings

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

class SymbolEntry:
    """래더 접점/디바이스"""
    def __init__(self, address, element_type=None, element_type_name=None):
        self.address = address            # "%MW3000.0"
        self.element_type = element_type  # 6, 7, 8, 14, 70, 102
        self.element_type_name = element_type_name  # "NO", "NC", "PULSE", "Coil", "FB_IO"

    def __repr__(self):
        name = self.element_type_name or str(self.element_type)
        return f"{self.address}({name})"

    def to_dict(self):
        return {'address': self.address, 'type': self.element_type, 'type_name': self.element_type_name}


class FunctionBlock:
    """함수 블록 (ADD, MOVE 등)"""
    def __init__(self, name, index, inputs=None, outputs=None):
        self.name = name
        self.index = index
        self.inputs = inputs or []
        self.outputs = outputs or []

    def __repr__(self):
        return f"{self.name}(in={self.inputs}, out={self.outputs})"

    def to_dict(self):
        return {'name': self.name, 'index': self.index, 'inputs': self.inputs, 'outputs': self.outputs}


class ProgramBlock:
    """프로그램 블록"""
    def __init__(self, name):
        self.name = name
        self.symbols = []       # [SymbolEntry, ...]
        self.functions = []     # [FunctionBlock, ...]
        self.instructions = b'' # raw bytecode
        self.instruction_size = 0

    def to_dict(self):
        return {
            'name': self.name,
            'symbols': [s.to_dict() for s in self.symbols],
            'functions': [f.to_dict() for f in self.functions],
            'instruction_size': self.instruction_size,
        }


class ProgramState:
    """PLC 프로그램 전체 상태"""
    def __init__(self):
        self.project_name = ''
        self.programs = {}      # {name: ProgramBlock}
        self.io_config = {}
        self.all_symbols = []   # all symbols across all programs
        self.all_functions = [] # all function blocks
        self.raw_blocks = []    # raw HEAD/FOOT blocks for debugging

    def to_dict(self):
        return {
            'project_name': self.project_name,
            'programs': {k: v.to_dict() for k, v in self.programs.items()},
            'symbol_count': len(self.all_symbols),
            'function_count': len(self.all_functions),
        }

    def summary(self):
        lines = [f"Project: {self.project_name}"]
        lines.append(f"Programs: {list(self.programs.keys())}")
        for name, prog in self.programs.items():
            lines.append(f"  {name}:")
            lines.append(f"    Symbols: {prog.symbols}")
            lines.append(f"    Functions: {prog.functions}")
            lines.append(f"    Instruction size: {prog.instruction_size} bytes")
        lines.append(f"Total symbols: {len(self.all_symbols)}")
        lines.append(f"Total functions: {len(self.all_functions)}")
        return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Element type / function name mappings
# ---------------------------------------------------------------------------

ELEMENT_TYPES = {
    0x06: 'NO',      # A접점 (상시개방)
    0x07: 'NC',      # B접점 (상시폐쇄)
    0x08: 'PULSE',   # 상승엣지
    0x14: 'Coil',    # 출력 코일 (0x14 = 20 decimal)
    0x46: 'FB_IO',   # 함수 블록 I/O (0x46 = 70 decimal)
    0x66: 'FB_Def',  # 함수 블록 정의 (0x66 = 102 decimal)
}

FUNCTION_NAMES = {
    0x47: 'ADD',    # INDEX 71
    0x76: 'MOVE',   # INDEX 118
}


# ---------------------------------------------------------------------------
# Symbol table parser
# ---------------------------------------------------------------------------

def parse_symbol_table(data):
    """Parse decompressed symbol table into symbols and function blocks.

    Strategy: scan for known patterns rather than strict sequential parsing.
    Unknown structures are preserved as raw bytes for future analysis.

    Args:
        data: bytes - decompressed bzip2 symbol table data

    Returns:
        tuple of (list[SymbolEntry], list[FunctionBlock])
    """
    symbols = []
    functions = []

    # Skip "LD VER 2.1" prefix if present — may wrap another bzip2 block
    ld_idx = data.find(b'LD VER')
    if ld_idx >= 0:
        bz_idx = data.find(b'BZh', ld_idx)
        if bz_idx >= 0:
            try:
                data = bz2.decompress(data[bz_idx:])
            except Exception:
                pass

    if len(data) < 7:
        return symbols, functions

    # Header: byte[0]=rung count, byte[1]=element count, byte[2:7]=flags
    # pos = 7  # skip 7-byte header (handled below via scan)

    # --- Pass 1: Scan for all function block regions (0x67 marker) ---
    fb_regions = []  # list of (start_offset, end_offset)
    pos = 7
    while pos < len(data) - 10:
        if data[pos] == 0x67:
            fb_start = pos
            func_index = data[pos + 6] if pos + 6 < len(data) else 0
            param_count = data[pos + 10] if pos + 10 < len(data) else 0
            func_name = FUNCTION_NAMES.get(func_index, f'FUNC_0x{func_index:02x}')

            fb = FunctionBlock(func_name, func_index)

            # Scan for IN (0x46 0x0d) / OUT (0x46 0x13) params and end (0x69)
            k = pos + 11
            fb_end = len(data)
            while k < len(data) - 5:
                if data[k] == 0x46 and k + 4 < len(data):
                    marker = data[k + 1]
                    param_len = data[k + 4]
                    if 1 <= param_len <= 30 and k + 5 + param_len <= len(data):
                        try:
                            param = data[k + 5:k + 5 + param_len].decode('ascii')
                            if param.startswith('%'):
                                if marker == 0x0d:    # IN parameter
                                    fb.inputs.append(param)
                                elif marker == 0x13:  # OUT parameter
                                    fb.outputs.append(param)
                                elif marker == 0x07:  # Constant
                                    fb.inputs.append(f'CONST:{param}')
                        except Exception:
                            pass
                        k += 5 + param_len
                        continue

                if data[k] == 0x69:  # FB end marker
                    fb_end = k + 6
                    break
                k += 1

            fb_end = min(fb_end, len(data))
            functions.append(fb)
            fb_regions.append((fb_start, fb_end))
            pos = fb_end
            continue
        pos += 1

    # --- Pass 2: Scan for all address strings (% prefix with length byte before) ---
    addresses = []  # list of {'address', 'offset', 'end'}
    pos = 7
    while pos < len(data) - 2:
        str_len = data[pos]
        if 1 <= str_len <= 30 and pos + 1 + str_len <= len(data):
            try:
                candidate = data[pos + 1:pos + 1 + str_len].decode('ascii')
                if candidate.startswith('%') and '\x00' not in candidate and candidate[1:2].isalpha():
                    addresses.append({
                        'address': candidate,
                        'offset': pos,
                        'end': pos + 1 + str_len,
                    })
                    pos += 1 + str_len
                    continue
            except Exception:
                pass
        pos += 1

    # --- Pass 3: Classify each address ---
    for addr_info in addresses:
        addr = addr_info['address']
        end = addr_info['end']
        offset = addr_info['offset']

        # If the address sits inside a function block region → FB_IO
        in_fb = any(fb_start <= offset < fb_end for fb_start, fb_end in fb_regions)
        if in_fb:
            symbols.append(SymbolEntry(addr, element_type=0x46, element_type_name='FB_IO'))
            continue

        # Scan up to 15 bytes after the address string for an element type
        scan_start = end
        scan_end = min(end + 15, len(data))
        found = False

        # Try 3-tuple pattern first: [prefix, etype, suffix] where suffix == prefix + 3
        for j in range(scan_start, scan_end - 2):
            prefix = data[j]
            etype = data[j + 1]
            suffix = data[j + 2]
            if suffix == prefix + 3 and etype in ELEMENT_TYPES:
                symbols.append(SymbolEntry(addr, etype, ELEMENT_TYPES[etype]))
                found = True
                break

        if not found:
            # Fallback: any ELEMENT_TYPES byte in the near window
            for j in range(scan_start, min(scan_start + 8, len(data))):
                if data[j] in ELEMENT_TYPES:
                    etype = data[j]
                    symbols.append(SymbolEntry(addr, etype, ELEMENT_TYPES[etype]))
                    found = True
                    break

        if not found:
            # Unknown type — preserve raw context for future analysis
            raw_ctx = data[scan_start:scan_end].hex() if scan_start < len(data) else ''
            symbols.append(SymbolEntry(
                addr,
                element_type=None,
                element_type_name=f'unknown({raw_ctx[:16]})',
            ))

    return symbols, functions


# ---------------------------------------------------------------------------
# ProgramState builder
# ---------------------------------------------------------------------------

def build_program_state(responses):
    """Build ProgramState from upload response data.

    Args:
        responses: list of response dicts from JSON file

    Returns:
        ProgramState object
    """
    state = ProgramState()

    # Decode all Z and X responses
    z_decoded = []
    x_decoded = []

    for r in responses:
        cmd = r.get('command_char', '?')
        payload_hex = r.get('payload_hex', '')
        if not payload_hex:
            continue
        sub_cmd = r.get('sub_cmd')
        binary = double_decode_ascii_hex(payload_hex, sub_cmd_byte=sub_cmd)
        if binary is None:
            continue

        if cmd == 'Z':
            z_decoded.append(binary)
        elif cmd == 'X':
            x_decoded.append(binary)

    # 1. Extract program names from HEAD/FOOT blocks
    for binary in z_decoded:
        # Check longer name first to avoid partial matches
        for name_bytes in [b'NewProgram2', b'NewProgram']:
            idx = binary.find(name_bytes)
            if idx >= 0:
                end = binary.find(b'\x00', idx)
                if end > idx:
                    name = binary[idx:end].decode('ascii', errors='replace')
                else:
                    name = name_bytes.decode()
                if name not in state.programs:
                    state.programs[name] = ProgramBlock(name)

    # 2. Extract symbol tables from bzip2 blocks
    all_symbols = []
    all_functions = []

    for binary in z_decoded + x_decoded:
        bz_idx = binary.find(b'BZh')
        if bz_idx >= 0:
            try:
                decompressed = bz2.decompress(binary[bz_idx:])
                syms, funcs = parse_symbol_table(decompressed)
                all_symbols.extend(syms)
                all_functions.extend(funcs)
            except Exception:
                pass

    # Also check for "LD VER" + bzip2 pattern (symbol table with version header)
    for binary in z_decoded:
        ld_idx = binary.find(b'LD VER')
        if ld_idx >= 0:
            bz_after = binary.find(b'BZh', ld_idx)
            if bz_after >= 0:
                try:
                    decompressed = bz2.decompress(binary[bz_after:])
                    syms, funcs = parse_symbol_table(decompressed)
                    # Avoid duplicates
                    existing = {s.address for s in all_symbols}
                    for s in syms:
                        if s.address not in existing:
                            all_symbols.append(s)
                            existing.add(s.address)
                    existing_funcs = {ff.name for ff in all_functions}
                    for fn in funcs:
                        if fn.name not in existing_funcs:
                            all_functions.append(fn)
                except Exception:
                    pass

    state.all_symbols = all_symbols
    state.all_functions = all_functions

    # Assign symbols to programs (best effort — assign all to first program)
    if state.programs:
        first_prog = list(state.programs.values())[0]
        first_prog.symbols = all_symbols
        first_prog.functions = all_functions

    # 3. Extract I/O config (IP addresses)
    for binary in z_decoded:
        for j in range(len(binary) - 3):
            if binary[j] == 192 and binary[j + 1] == 168:
                ip = f"{binary[j]}.{binary[j+1]}.{binary[j+2]}.{binary[j+3]}"
                state.io_config.setdefault('ip_addresses', set()).add(ip)
    if 'ip_addresses' in state.io_config:
        state.io_config['ip_addresses'] = sorted(state.io_config['ip_addresses'])

    # 4. Measure instruction data
    for binary in z_decoded:
        if b'\xfd\xff\x07\x4a' in binary:  # end-of-program marker
            for prog in state.programs.values():
                if prog.instruction_size == 0:
                    prog.instruction_size = len(binary)
                    prog.instructions = binary
                    break

    return state


# ---------------------------------------------------------------------------
# Diff utilities
# ---------------------------------------------------------------------------

def diff_program_state(before, after):
    """Compare two ProgramState objects and return differences.

    Args:
        before: ProgramState - baseline state
        after: ProgramState - new state after modification

    Returns:
        dict with change details
    """
    diff = {
        'programs_added': [],
        'programs_removed': [],
        'programs_changed': {},
        'symbols_added': [],
        'symbols_removed': [],
        'functions_added': [],
        'functions_removed': [],
        'functions_changed': [],
        'io_changes': {},
    }

    # Program list diff
    before_progs = set(before.programs.keys())
    after_progs = set(after.programs.keys())
    diff['programs_added'] = sorted(after_progs - before_progs)
    diff['programs_removed'] = sorted(before_progs - after_progs)

    # Symbol diff (across all programs)
    before_addrs = {s.address for s in before.all_symbols}
    after_addrs = {s.address for s in after.all_symbols}
    diff['symbols_added'] = sorted(after_addrs - before_addrs)
    diff['symbols_removed'] = sorted(before_addrs - after_addrs)

    # Function diff
    before_funcs = {(f.name, tuple(f.inputs), tuple(f.outputs)) for f in before.all_functions}
    after_funcs = {(f.name, tuple(f.inputs), tuple(f.outputs)) for f in after.all_functions}

    diff['functions_added'] = [
        {'name': f[0], 'inputs': list(f[1]), 'outputs': list(f[2])}
        for f in (after_funcs - before_funcs)
    ]
    diff['functions_removed'] = [
        {'name': f[0], 'inputs': list(f[1]), 'outputs': list(f[2])}
        for f in (before_funcs - after_funcs)
    ]

    # Per-program instruction size changes
    for prog_name in before_progs & after_progs:
        b_prog = before.programs[prog_name]
        a_prog = after.programs[prog_name]
        changes = {}

        if b_prog.instruction_size != a_prog.instruction_size:
            changes['instruction_size'] = {
                'before': b_prog.instruction_size,
                'after': a_prog.instruction_size,
                'delta': a_prog.instruction_size - b_prog.instruction_size,
            }

        if b_prog.instructions and a_prog.instructions:
            if b_prog.instructions != a_prog.instructions:
                min_len = min(len(b_prog.instructions), len(a_prog.instructions))
                diff_bytes = sum(
                    1 for i in range(min_len) if b_prog.instructions[i] != a_prog.instructions[i]
                )
                diff_bytes += abs(len(b_prog.instructions) - len(a_prog.instructions))
                changes['instruction_bytes_changed'] = diff_bytes

        if changes:
            diff['programs_changed'][prog_name] = changes

    # I/O config diff
    if before.io_config != after.io_config:
        diff['io_changes'] = {
            'before': before.io_config,
            'after': after.io_config,
        }

    return diff


def print_diff(diff):
    """Print human-readable diff summary."""
    has_changes = False

    if diff['programs_added']:
        print(f"  프로그램 추가: {diff['programs_added']}")
        has_changes = True
    if diff['programs_removed']:
        print(f"  프로그램 제거: {diff['programs_removed']}")
        has_changes = True
    if diff['symbols_added']:
        print(f"  접점 추가: {diff['symbols_added']}")
        has_changes = True
    if diff['symbols_removed']:
        print(f"  접점 제거: {diff['symbols_removed']}")
        has_changes = True
    if diff['functions_added']:
        for f in diff['functions_added']:
            print(f"  함수 추가: {f['name']}(in={f['inputs']}, out={f['outputs']})")
        has_changes = True
    if diff['functions_removed']:
        for f in diff['functions_removed']:
            print(f"  함수 제거: {f['name']}(in={f['inputs']}, out={f['outputs']})")
        has_changes = True
    for prog, changes in diff['programs_changed'].items():
        if 'instruction_bytes_changed' in changes:
            print(f"  {prog}: 인스트럭션 {changes['instruction_bytes_changed']}바이트 변경")
            has_changes = True
        if 'instruction_size' in changes:
            d = changes['instruction_size']
            print(f"  {prog}: 크기 {d['before']}→{d['after']} ({d['delta']:+d}바이트)")
            has_changes = True

    if not has_changes:
        print("  변경 없음")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) >= 2 and sys.argv[1] == '--diff' and len(sys.argv) >= 4:
        # Diff mode: compare two response files
        file1, file2 = sys.argv[2], sys.argv[3]
        print(f"Comparing:")
        print(f"  Before: {file1}")
        print(f"  After:  {file2}")
        print()

        with open(file1) as f:
            before_state = build_program_state(json.load(f))
        with open(file2) as f:
            after_state = build_program_state(json.load(f))

        print("=== Before ===")
        print(before_state.summary())
        print()
        print("=== After ===")
        print(after_state.summary())
        print()
        print("=== DIFF ===")
        d = diff_program_state(before_state, after_state)
        print_diff(d)
        return

    if len(sys.argv) >= 2 and sys.argv[1] == '--state':
        filepath = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'docs', '0414_upload_responses.json')

        if not os.path.exists(filepath):
            print(f"ERROR: File not found: {filepath}")
            sys.exit(1)

        with open(filepath) as f:
            responses = json.load(f)

        state = build_program_state(responses)
        print("=== ProgramState ===")
        print(state.summary())
        print()
        print("=== JSON ===")
        print(json.dumps(state.to_dict(), indent=2, ensure_ascii=False))
        return

    # Default: existing analyze mode
    if len(sys.argv) < 2:
        filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'docs', '0414_upload_responses.json')
    else:
        filepath = sys.argv[1]

    if not os.path.exists(filepath):
        print(f"ERROR: File not found: {filepath}")
        sys.exit(1)

    analyze_responses(filepath)

if __name__ == '__main__':
    main()
