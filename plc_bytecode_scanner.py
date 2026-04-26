#!/usr/bin/env python3
"""완전 업로드 pcapng → 바이트코드 토큰 위치 맵.

Phase B.1 Rosetta 정렬의 "오른쪽" (바이트코드 측) 입력.
각 PLC→PC 응답을 ASCII-hex 디코딩하고, 알려진 문법 토큰의
위치·빈도를 수집. bz2 블록은 해제 후 재스캔.

Usage:
    python plc_bytecode_scanner.py docs/0423_PLC로부터열기.pcapng \\
                                   --out docs/bytecode_scan_0423.json
"""
import sys
import os
import re
import bz2
import json
import argparse
from pathlib import Path
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from plc_upload_analyze import parse_pcapng_packets


# Grammar 토큰 패턴 (protocol_grammar.json과 정합)
TOKEN_PATTERNS = [
    # (name, regex_bytes, capture group meaning)
    ('FB_DEFINITION',  rb'\x67(.)\x00\x00\x00\x00(.)',  ('sub_type', 'func_id')),
    ('FB_BINDING',     rb'\x68(.)\x00(.)\x00\x00',      ('sub_type', 'offset')),
    ('FB_END',         rb'\x69(.)\x00(.)\x00\x00',      ('sub_type', 'offset')),
    ('FX_FLAG',        rb'\x58(.)\x00\x00\x00',         ('fx_id',)),
    ('VAR_IN_ANCHOR',  rb'\x46\x0d\x00\x00(.)',         ('len',)),
    ('VAR_OUT_ANCHOR', rb'\x46\x13\x00\x00(.)',         ('len',)),
    ('CONTACT_POS_C',  rb'\x04(.)\x07',                 ('element_type',)),
    ('CONTACT_POS_A',  rb'\x0a(.)\x0d',                 ('element_type',)),
    ('CONTACT_POS_B',  rb'\x10(.)\x13',                 ('element_type',)),
    ('RUNG_END_A',     rb'\x54\x98',                    ()),
    ('RUNG_END_B',     rb'\x54\xb0',                    ()),
    ('PROGRAM_END',    rb'\xfd\xff\x07\x4a',            ()),
    # S2: Ladder Expression 토큰 (INSTR_LOAD, INSTR_NC_MOD, INSTR_PULSE) 재활성화
    ('INSTR_LOAD',     rb'\x14(.)',                     ('operand_type',)),
    ('INSTR_NC_MOD',   rb'\x8d',                        ()),
    ('INSTR_PULSE',    rb'\x90\x00\xc0\x0f',            ()),
]

# 주소는 별도 regex (ASCII 텍스트)
ADDRESS_RE = re.compile(rb'%[A-Z]+\d+(?:\.\d+)?')


def extract_program_names_from_payload(decoded_binary: bytes) -> list:
    """Extract program names from a decoded program-section binary using grammar.

    Grammar (from protocol_grammar.json):
    - HEAD marker at offset 0 → first name at offset 8
    - size field at offset 4 (uint32_le) as termination guard
    - subsequent names: 1 byte after each 0x11 marker
    - names are ASCII null-terminated, max 32 bytes including padding

    Returns list of {name, offset, is_first} dicts.
    Empty list if no HEAD marker or binary too small.

    Phase B.8 Grammar Discriminator:
    Reject false positives (JSON status, nested HEAD section, binary garbage).
    Only genuine program sections pass all 5 conditions.
    """
    results = []
    HEAD = b"HEAD"
    FOOT = b"FOOT"

    # === PHASE B.8 GRAMMAR DISCRIMINATOR (5 conditions, all must match) ===
    # 직전 hotfix 가 JSON status / nested HEAD section / binary garbage 를 program 으로 잘못 인식했으므로
    # byte structure 만으로 판별. 사용자 원칙 "grammar over naming".

    # Condition 1: Early exit — no HEAD marker means no program section
    if not decoded_binary.startswith(HEAD):
        return results

    # Condition 2: Minimum length check
    if len(decoded_binary) < 30:
        return results

    # Condition 3: decoded[8] is printable ASCII (32-126)
    # Program name 의 첫 글자는 printable 이어야 함. JSON/binary 는 이 조건 실패
    if not (32 <= decoded_binary[8] < 127):
        return results

    # Condition 4 (revised): XGT 종결자 (FOOT) 또는 program-separator (0x11 marker)
    # (대부분 PROGRAM section 은 FOOT 가짐. 일부 캡처 variant 는 FOOT 없으나 0x11 marker 가 있음)
    # JSON status: 둘 다 없음 → 거부
    # nested HEAD: FOOT 는 있지만 condition 5 가 거부
    # binary garbage: condition 3 (printable[8]) 가 거부
    has_foot = FOOT in decoded_binary
    has_program_marker = b'\x11' in decoded_binary[8:]
    if not (has_foot or has_program_marker):
        return results

    # Condition 5: nested HEAD section 거부
    # Program section 안에 sub-section HEAD 는 사실상 없음
    # (program 이름이 'HEAD' 4글자만일 수 없음 — max 32 bytes 이지만 null-terminated 이므로 사실상 max 31)
    if decoded_binary[8:12] == HEAD:
        return results

    # Size field is at offset 4; use as termination guard
    if len(decoded_binary) < 8:
        return results

    size_field = int.from_bytes(decoded_binary[4:8], 'little')
    end = min(len(decoded_binary), 8 + size_field)

    def is_valid_program_name(name: str) -> bool:
        """사용자 임의 작명 허용. printable + 길이 1-32만 검증.

        사용자 핵심 원칙: 'grammar over naming'. 영문/숫자/특수문자/한글 등
        PLC가 허용하는 모든 형태의 이름을 받음. binary garbage/control char만 거부.

        Returns:
            True if name is printable and length 1-32, False otherwise.
        """
        if not name or len(name) > 32:
            return False
        # str.isprintable(): ASCII printable + unicode printable (한글 등) 모두 True
        # tab/newline/NUL 등 whitespace/control char는 False
        return name.isprintable()

    def read_program_name(buf: bytes, start: int, max_len: int = 32) -> str:
        """사용자 임의 인코딩 이름 읽기.

        ASCII 우선, UTF-8 fallback (한글/특수문자 대응).
        Null terminator 우선 사용. 없으면 max_len 또는 buf 끝까지 시도하고
        trailing non-printable byte 들 제거 (payload 끝 padding/checksum 대응).

        Return: 이름 문자열, 또는 None.
        """
        if start >= len(buf):
            return None

        window_end = min(len(buf), start + max_len)
        nul_pos = buf.find(b'\x00', start, window_end)
        end_pos = nul_pos if nul_pos > start else window_end

        if end_pos <= start:
            return None

        raw = buf[start:end_pos]
        # trailing non-printable byte 제거 (payload 끝의 padding/checksum 같은 trailing garbage)
        # Phase B.8: ASCII printable (32-126) 또는 UTF-8 continuation byte (0x80+) keep.
        # 0xeb 같은 invalid UTF-8 단일 byte (control char, 0x00-0x1f) 는 제거.
        # Rationale: UTF-8 한글은 multi-byte 인데 마지막 byte 가 0x80+ (continuation) 일 수 있으므로 보존.
        # Invalid single bytes (0x00-0x1f, 0x7f) 는 제거.
        while raw and not (32 <= raw[-1] < 127 or raw[-1] >= 0x80):
            raw = raw[:-1]
        if not raw:
            return None

        # ASCII 우선, UTF-8 fallback
        for encoding in ('ascii', 'utf-8'):
            try:
                candidate = raw.decode(encoding)
                if is_valid_program_name(candidate):
                    return candidate
            except UnicodeDecodeError:
                continue
        return None

    # First program at offset 8: scan null-terminated name
    first_name = read_program_name(decoded_binary, 8)
    if first_name:
        results.append({"name": first_name, "offset": 8, "is_first": True})

    # Subsequent programs: scan for 0x11 markers, name follows immediately
    pos = 8
    while pos < end:
        idx = decoded_binary.find(b'\x11', pos, end)
        if idx < 0:
            break

        name_start = idx + 1
        nm = read_program_name(decoded_binary, name_start)
        if nm:
            results.append({"name": nm, "offset": name_start, "is_first": False})

        pos = idx + 1  # Continue search past this marker

    return results


def extract_rung_markers_from_decoded(decoded_binary: bytes) -> list:
    """BZ2 압축 stream 해제 후 RUNG marker (46 01 00 00) 위치 추출.

    Phase B.8.3: RUNG marker는 IL의 XGRUNGSTART opcode signature.
    완전 program upload 캡처에서만 BZ2 압축 내부에 나타남.
    Partial capture는 RUNG marker 0개 → FB_DEFINITION fallback 유지 (확장성).

    Args:
        decoded_binary: PLC→PC 응답의 decoded binary

    Returns:
        [
            {'offset_in_decompressed': int, 'bz2_chunk_idx': int, 'rung_index': int},
            ...
        ]
        각 리스트 항목은 하나의 RUNG marker 위치.

        Empty list if no BZ2 stream or no RUNG marker.
    """
    RUNG = b'\x46\x01\x00\x00'
    BZ2_MAGIC = b'BZh'
    results = []

    pos = 0
    chunk_idx = 0
    while True:
        idx = decoded_binary.find(BZ2_MAGIC, pos)
        if idx < 0:
            break

        chunk = decoded_binary[idx:]

        # Try varying lengths (50~5000 bytes in 50-byte steps, descending)
        # Start high because typical program bytecode is 500-2000 bytes
        decompressed = None
        for end in range(min(len(chunk), 5000), 50, -50):
            try:
                decompressed = bz2.decompress(chunk[:end])
                break
            except (OSError, ValueError):
                continue

        if decompressed:
            # Find all RUNG markers in this decompressed chunk
            rpos = 0
            rung_count = 0
            while True:
                ridx = decompressed.find(RUNG, rpos)
                if ridx < 0:
                    break
                results.append({
                    'offset_in_decompressed': ridx,
                    'bz2_chunk_idx': chunk_idx,
                    'rung_index': rung_count,
                })
                rpos = ridx + 1
                rung_count += 1

        chunk_idx += 1
        pos = idx + 1

    return results


def decode_response_binary(payload):
    """PLC→PC 응답의 ASCII-hex 데이터를 바이너리로 복원.

    응답 레이아웃: LGIS-GLOFA(10B) + 헤더(14B) + 0x06(status) + ASCII hex data
    """
    sig = payload.find(b'LGIS-GLOFA')
    if sig < 0:
        return None
    if len(payload) < sig + 27:
        return None
    tail = payload[sig + 26:]
    try:
        s = tail.decode('ascii', errors='ignore')
    except UnicodeDecodeError:
        return None
    clean = ''.join(c for c in s if c in '0123456789abcdefABCDEF')
    if len(clean) % 2:
        clean = clean[:-1]
    try:
        return bytes.fromhex(clean) if clean else b''
    except ValueError:
        return None


def _is_inside_fb_block(pos: int, fb_defs: list, fb_ends: list) -> bool:
    """S2: pos가 FB_DEFINITION~FB_END 내부인지 확인 (false positive 필터 1)."""
    for fb_def in fb_defs:
        fb_start = fb_def['pos']
        # 가장 가까운 FB_END 찾기
        matching_ends = [e for e in fb_ends if e['pos'] > fb_start]
        if matching_ends:
            fb_end_pos = matching_ends[0]['pos'] + matching_ends[0].get('length', 7)
            if fb_start < pos < fb_end_pos:
                return True
    return False


def _has_nearby_address(pos: int, all_tokens: list, window_size: int = 100) -> bool:
    """S2: pos 근처 window_size 바이트 내에 ADDRESS 토큰이 있는지 (false positive 필터 2)."""
    for t in all_tokens:
        if t['type'] == 'ADDRESS':
            addr_pos = t.get('pos', 0)
            if pos <= addr_pos <= pos + window_size:
                return True
    return False


def _is_valid_element_type_context(element_type: int) -> bool:
    """S2: element_type이 알려진 값인지 확인 (false positive 필터 3)."""
    # S3에서 업데이트될 값들; 현재는 기본 + 확장 element_type
    known_types = {6, 7, 14, 16, 17, 103, 163}  # NO, NC, OUT, SET, RST, + S3 신규
    return element_type in known_types


def scan_tokens(binary):
    """주어진 바이너리에서 모든 알려진 문법 토큰을 위치와 함께 추출.

    S2: INSTR_LOAD, INSTR_NC_MOD, INSTR_PULSE 토큰 포함.
    False positive 필터 3종 적용:
    1. FB_DEFINITION 내부 스킵
    2. ADDRESS 토큰 근처만 인정
    3. element_type 맥락 필터 (CONTACT_POS_* only)
    B.5.3: DOTALL 플래그로 sub_type/func_id=0x0A variant 포착 (TOF func_id=10, MOVE_WORD variant).
    """
    tokens = []

    # S2: 1차 스캔 (기본 패턴)
    for name, pattern, group_meanings in TOKEN_PATTERNS:
        for m in re.finditer(pattern, binary, re.DOTALL):
            t = {'type': name, 'pos': m.start(), 'length': m.end() - m.start()}
            if group_meanings and m.groups():
                for i, meaning in enumerate(group_meanings):
                    val = m.group(i + 1)
                    if len(val) == 1:
                        t[meaning] = val[0]
                    else:
                        t[meaning] = val.hex()
            tokens.append(t)

    # 주소 (ASCII 인라인)
    for m in ADDRESS_RE.finditer(binary):
        tokens.append({
            'type': 'ADDRESS',
            'pos': m.start(),
            'addr': m.group().decode('ascii'),
        })

    # S2: 2차 검증 — false positive 필터 적용 (INSTR_LOAD, INSTR_NC_MOD, INSTR_PULSE)
    fb_defs = [t for t in tokens if t['type'] == 'FB_DEFINITION']
    fb_ends = [t for t in tokens if t['type'] == 'FB_END']

    instr_tokens = [t for t in tokens if t['type'].startswith('INSTR_')]
    filtered_instr = []

    for t in instr_tokens:
        pos = t.get('pos', 0)

        # 필터 1: FB_DEFINITION 내부 스킵
        if _is_inside_fb_block(pos, fb_defs, fb_ends):
            continue

        # CONTACT_POS_*에 대해서만 필터 3 적용
        if t['type'].startswith('CONTACT_POS_'):
            element_type = t.get('element_type')
            if element_type is not None and not _is_valid_element_type_context(element_type):
                continue

        # 필터 2 선택적: INSTR_LOAD는 nearby ADDRESS로 신뢰성 보강
        if t['type'] == 'INSTR_LOAD':
            if not _has_nearby_address(pos, tokens, window_size=100):
                # ADDRESS 없으면 false positive일 가능성 높음 → 스킵
                continue

        filtered_instr.append(t)

    # 필터링된 INSTR_* 토큰 추가
    tokens = [t for t in tokens if not t['type'].startswith('INSTR_')] + filtered_instr

    # bzip2 블록 (BZh 해제 후 재스캔 — 중첩)
    pos = 0
    while True:
        idx = binary.find(b'BZh', pos)
        if idx < 0:
            break
        try:
            decompressed = bz2.decompress(binary[idx:])
            # 해제 결과에서 재귀 스캔
            inner = scan_tokens(decompressed)
            for t in inner:
                t['pos'] += idx  # 부모 바이너리 기준 상대 위치 (여전히 추적)
                t['from_bzip2'] = True
            tokens.extend(inner)
        except Exception:
            pass
        pos = idx + 1

    return sorted(tokens, key=lambda x: x['pos'])


def scan_responses_bytes(response_bytes_list, include_binary=False):
    """Raw response bytes list → 각 응답의 token 추출 (Live PLC 통합용).

    PLCUploadClient.send_frame() 이 받은 raw response_data (bytes) list 받음.
    scan_pcapng() 이 pcapng 파일에서 하는 것과 동일한 token 추출
    (FB_DEFINITION, PROGRAM_NAME, RUNG_START 등) 을 메모리에서 수행.

    Args:
        response_bytes_list: raw response bytes list (예: PLCUploadClient.responses_raw)
        include_binary: True면 각 response에 binary_hex (hex string) 포함

    Returns:
        scan_pcapng() 와 동일 형식의 list of dicts
        각 dict: {binary_len, token_count, tokens, command_char, ...}
    """
    responses = []
    for payload in response_bytes_list:
        if not payload:
            continue

        # Parse command_char, command_byte, sub_cmd from payload header
        sig = payload.find(b'LGIS-GLOFA')
        command_char = None
        command_byte = None
        sub_cmd = None
        sub_cmd_hex = None
        payload_hex = None

        if sig >= 0 and len(payload) >= sig + 27:
            # sig+24 = 1 byte ASCII command char, sig+25 = 1 byte sub_cmd
            if sig + 25 < len(payload):
                try:
                    command_byte = payload[sig + 24]
                    command_char = chr(command_byte) if 32 <= command_byte < 127 else None
                    sub_cmd = payload[sig + 25]
                    sub_cmd_hex = f"0x{sub_cmd:02x}"
                except (IndexError, ValueError):
                    pass

            # Extract payload hex (starting from sig+26)
            tail = payload[sig + 26:]
            try:
                s = tail.decode('ascii', errors='ignore')
                clean = ''.join(c for c in s if c in '0123456789abcdefABCDEF')
                if len(clean) % 2:
                    clean = clean[:-1]
                payload_hex = clean if clean else None
            except (UnicodeDecodeError, Exception):
                pass

        binary = decode_response_binary(payload)
        if binary is None:
            continue

        tokens = scan_tokens(binary)

        # Extract PROGRAM_NAME tokens from binary using grammar
        program_names = extract_program_names_from_payload(binary)
        for pn in program_names:
            tokens.append({
                'type': 'PROGRAM_NAME',
                'value': pn['name'],
                'offset_in_payload': pn['offset'],
                'is_first': pn['is_first'],
            })

        # Phase B.8.3: Extract RUNG_START markers from BZ2-decompressed binary
        rung_markers = extract_rung_markers_from_decoded(binary)
        for rm in rung_markers:
            tokens.append({
                'type': 'RUNG_START',
                'offset_in_decompressed': rm['offset_in_decompressed'],
                'bz2_chunk_idx': rm['bz2_chunk_idx'],
                'rung_index': rm['rung_index'],
            })

        # Re-sort tokens by position
        tokens = sorted(tokens, key=lambda x: x.get('pos') or x.get('offset_in_payload') or 0)

        resp = {
            'binary_len': len(binary),
            'token_count': len(tokens),
            'tokens': tokens,
        }

        # Add command info
        if command_char:
            resp['command_char'] = command_char
        if command_byte is not None:
            resp['command_byte'] = command_byte
        if sub_cmd is not None:
            resp['sub_cmd'] = sub_cmd
        if sub_cmd_hex:
            resp['sub_cmd_hex'] = sub_cmd_hex
        if payload_hex:
            resp['payload_hex'] = payload_hex

        if include_binary:
            resp['binary_hex'] = binary.hex()

        responses.append(resp)
    return responses


def scan_pcapng(pcap_path, include_binary=False):
    """pcapng 파일 → PLC→PC 응답별 바이너리 + 토큰 맵.

    Args:
        pcap_path: pcapng 파일 경로
        include_binary: True면 각 response에 binary_hex (hex string) 포함

    Enhancements (Phase B.8):
    - Extracts command_char, command_byte, sub_cmd, sub_cmd_hex from payload
    - Decodes payload_hex from response
    - Generates PROGRAM_NAME tokens from decoded binary using grammar
    """
    packets = parse_pcapng_packets(pcap_path)

    # Extract PLC→PC responses (raw bytes)
    response_bytes_list = [payload for direction, payload in packets if direction == 'PLC→PC']

    # Use scan_responses_bytes for token extraction (DRY)
    responses = scan_responses_bytes(response_bytes_list, include_binary=include_binary)
    return responses


def summarize(responses):
    """전역 토큰 통계 요약."""
    total_tokens = 0
    type_counts = Counter()
    fb_func_ids = Counter()
    fx_ids = Counter()
    element_types = Counter()
    addresses = set()

    for r in responses:
        for t in r['tokens']:
            total_tokens += 1
            type_counts[t['type']] += 1
            if t['type'] == 'FB_DEFINITION' and 'func_id' in t:
                fb_func_ids[t['func_id']] += 1
            elif t['type'] == 'FX_FLAG' and 'fx_id' in t:
                fx_ids[t['fx_id']] += 1
            elif t['type'].startswith('CONTACT_POS') and 'element_type' in t:
                element_types[t['element_type']] += 1
            elif t['type'] == 'ADDRESS':
                addresses.add(t['addr'])

    return {
        'response_count': len(responses),
        'total_tokens': total_tokens,
        'token_type_counts': dict(type_counts.most_common()),
        'function_id_counts': dict(sorted(fb_func_ids.items())),
        'fx_id_counts': dict(sorted(fx_ids.items())),
        'element_type_counts': dict(sorted(element_types.items())),
        'unique_addresses': sorted(addresses),
        'unique_address_count': len(addresses),
    }


def main():
    parser = argparse.ArgumentParser(
        description='완전 업로드 pcapng → 바이트코드 토큰 스캔',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  python plc_bytecode_scanner.py docs/0423_PLC로부터열기.pcapng \\
                                 --out docs/bytecode_scan_0423.json
""")
    parser.add_argument('pcap_path', help='pcapng 파일 경로')
    parser.add_argument('--out', default='bytecode_scan.json', help='출력 JSON 경로')
    parser.add_argument('--verbose', '-v', action='store_true')
    args = parser.parse_args()

    if not Path(args.pcap_path).exists():
        print(f'Error: pcapng not found: {args.pcap_path}')
        sys.exit(1)

    print(f'Scanning: {args.pcap_path}')
    responses = scan_pcapng(args.pcap_path)
    summary = summarize(responses)

    print(f"\n=== 바이트코드 스캔 ===")
    print(f"PLC→PC 응답: {summary['response_count']}개")
    print(f"총 토큰: {summary['total_tokens']}")
    print(f"\n토큰 타입별 분포:")
    for tp, cnt in summary['token_type_counts'].items():
        print(f"  {tp:20s} {cnt:5d}")
    print(f"\nFB_DEFINITION func_id 분포: {len(summary['function_id_counts'])}종")
    for fid, cnt in summary['function_id_counts'].items():
        print(f"  INDEX={fid:3d} (0x{fid:02x}): {cnt}회")
    print(f"\nFX_FLAG fx_id 분포: {summary['fx_id_counts']}")
    print(f"ElementType 분포: {summary['element_type_counts']}")
    print(f"\n고유 주소 {summary['unique_address_count']}개:")
    for a in summary['unique_addresses']:
        print(f"  {a}")

    out_data = {
        'source': args.pcap_path,
        'summary': summary,
        'responses': responses,
    }
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(out_data, f, indent=2, ensure_ascii=False)
    print(f"\n✓ JSON 출력: {out_path.absolute()}")


if __name__ == '__main__':
    main()
