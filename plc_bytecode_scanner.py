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
    # INSTR_LOAD는 `14 XX`인데 14가 너무 자주 나와 false positive 많음 — 별도 처리
]

# 주소는 별도 regex (ASCII 텍스트)
ADDRESS_RE = re.compile(rb'%[A-Z]+\d+(?:\.\d+)?')


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


def scan_tokens(binary):
    """주어진 바이너리에서 모든 알려진 문법 토큰을 위치와 함께 추출."""
    tokens = []

    for name, pattern, group_meanings in TOKEN_PATTERNS:
        for m in re.finditer(pattern, binary):
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


def scan_pcapng(pcap_path, include_binary=False):
    """pcapng 파일 → PLC→PC 응답별 바이너리 + 토큰 맵.

    Args:
        pcap_path: pcapng 파일 경로
        include_binary: True면 각 response에 binary_hex (hex string) 포함
    """
    packets = parse_pcapng_packets(pcap_path)

    responses = []
    for direction, payload in packets:
        if direction != 'PLC→PC':
            continue
        binary = decode_response_binary(payload)
        if binary is None:
            continue
        tokens = scan_tokens(binary)
        resp = {
            'binary_len': len(binary),
            'token_count': len(tokens),
            'tokens': tokens,
        }
        if include_binary:
            resp['binary_hex'] = binary.hex()
        responses.append(resp)
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
