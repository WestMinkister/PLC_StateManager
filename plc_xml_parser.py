#!/usr/bin/env python3
"""
XG5000 프로젝트 XML → variables.json 변환기

PLC XML 프로젝트에서 모든 변수 주소를 추출하여 variables.json 생성합니다.
이 파일은 plc_value_backup.py --config로 사용할 수 있습니다.

Usage:
    python plc_xml_parser.py project.xml
    python plc_xml_parser.py project.xml --out my_variables.json
"""
import re
import json
import sys
import argparse
from collections import defaultdict
from pathlib import Path


def parse_xg5000_xml(xml_path):
    """Parse XG5000 project XML and extract all variable addresses.

    Scans the XML for all variable references in the form:
    - %MW<number>     (Memory Word)
    - %IW<number>     (Input Word)
    - %QW<number>     (Output Word)
    - %MB<number>     (Memory Byte - converted to Word address)
    - %IB<number>     (Input Byte)
    - %QB<number>     (Output Byte)
    - %MD<number>     (Memory Double-word)

    Bit references like %MW152.0 are deduplicated to word level.

    Returns:
        tuple: (variables_list, programs_list, stats_dict)
        where variables_list is a list of {'area': str, 'word': int, 'name': str}
    """
    with open(xml_path, encoding='utf-8') as f:
        xml_text = f.read()

    # Find program names for context
    programs = re.findall(r'<Program[^>]*>(\w+)<', xml_text)

    # Find ALL variable references: %<area><number> or %<area><number>.<bit>
    # Pattern matches: %MW, %IW, %QW, %MB, %IB, %QB, %MD, etc.
    vars_found = {}  # (area_letter, word_num) → info dict
    pattern = r'%([A-Z]+?)(\d+)(?:\.(\d+))?'

    stats = {
        'total_refs': 0,
        'mw_refs': 0,
        'iw_refs': 0,
        'qw_refs': 0,
        'mb_refs': 0,
        'ib_refs': 0,
        'qb_refs': 0,
        'other_refs': 0,
    }

    for m in re.finditer(pattern, xml_text):
        stats['total_refs'] += 1
        area_raw = m.group(1)  # "MW", "IW", "MB", "QW", etc.
        num = int(m.group(2))
        bit = m.group(3)
        full_addr = m.group(0)

        # Normalize area and word number
        if area_raw.endswith('W'):
            # Word addressing: MW152 → area='M', word=152
            area_letter = area_raw[:-1]  # Remove 'W'
            word_num = num
            if area_raw == 'MW':
                stats['mw_refs'] += 1
            elif area_raw == 'IW':
                stats['iw_refs'] += 1
            elif area_raw == 'QW':
                stats['qw_refs'] += 1
        elif area_raw.endswith('B'):
            # Byte addressing: MB2000 → area='M', word=2000//2=1000
            # Note: byte address is word-aligned (byte 2000 = word 1000)
            area_letter = area_raw[:-1]
            word_num = num // 2
            if area_raw == 'MB':
                stats['mb_refs'] += 1
            elif area_raw == 'IB':
                stats['ib_refs'] += 1
            elif area_raw == 'QB':
                stats['qb_refs'] += 1
        elif area_raw.endswith('D'):
            # Double word: MD... → area='M', word=num (32-bit)
            area_letter = area_raw[:-1]
            word_num = num
            stats['other_refs'] += 1
        else:
            # Unknown, try as-is (take first letter as area)
            area_letter = area_raw[0] if area_raw else 'M'
            word_num = num
            stats['other_refs'] += 1

        # Ensure single letter area
        if len(area_letter) > 1:
            area_letter = area_letter[0]

        key = (area_letter, word_num)
        if key not in vars_found:
            vars_found[key] = {
                'area': area_letter,
                'word': word_num,
                'name': f'{area_letter}W{word_num}',
                'addresses': set()
            }
        vars_found[key]['addresses'].add(full_addr)

    # Convert to sorted list
    result = []
    for key in sorted(vars_found.keys()):
        v = vars_found[key]
        entry = {
            'area': v['area'],
            'word': v['word'],
            'name': v['name'],
        }
        result.append(entry)

    return result, programs, stats


def parse_xg5000_xml_full(xml_path):
    """XG5000 XML에서 **완전한 프로젝트 구조**를 추출 — Phase B 정답지 생성기.

    기존 parse_xg5000_xml()의 확장판. 함수블록 INDEX, Rung 구조, 시스템 플래그,
    ElementType 분포까지 포함. PLC 프로토콜 추출 결과의 **검증 기준(ground truth)**.

    Returns dict with keys:
        - source: 파일 경로
        - addresses: {word: [...], bit: [...], by_area: {M: [...], I: [...]}, unique_count}
        - functions: [{name, xml_index, instance_count, var_in, var_out}, ...]
        - rungs: [{index, block_mask, elements: [{type, coord, addr}, ...]}, ...]
        - element_type_counts: {"6": 10, "7": 3, ...}
        - system_flags: sorted unique list
        - stats: {total_refs, rung_count, function_count, ...}
    """
    import collections

    with open(xml_path, encoding='utf-8') as f:
        text = f.read()

    # 1) 주소 — word / bit / 영역별
    word_addrs_raw = re.findall(r'%([A-Z]+)(\d+)(?![\d.])', text)  # 비트 주소 제외한 원본
    bit_addrs = sorted(set(re.findall(r'%[A-Z]+\d+\.\d+', text)))
    all_addrs_raw = re.findall(r'%([A-Z]+)(\d+)', text)

    by_area = collections.defaultdict(set)
    for area, num in all_addrs_raw:
        by_area[area].add(int(num))
    by_area_sorted = {k: sorted(v) for k, v in by_area.items()}

    unique_word = sorted({f'%{a}{n}' for a, n in all_addrs_raw})

    # 2) 함수블록 — FNAME + INDEX + VAR_IN/VAR_OUT
    funcs_found = []
    # FNAME과 INDEX가 같은 Param 값 안에 있음. VAR_IN/OUT도 동일 Param.
    # Param="..." 속성 값 전체를 찾고 그 안에서 파싱.
    for m in re.finditer(r'Param="([^"]+)"', text):
        param = m.group(1).replace('&#xA;', '\n').replace('&quot;', '"')
        fname_m = re.search(r'FNAME:\s*(\w+)', param)
        index_m = re.search(r'INDEX:\s*(\d+)', param)
        if fname_m and index_m:
            var_in = re.findall(r'VAR_IN:\s*([^,]+),\s*(0x[0-9a-fA-F]+)', param)
            var_out = re.findall(r'VAR_OUT:\s*([^,]+),\s*(0x[0-9a-fA-F]+)', param)
            funcs_found.append({
                'name': fname_m.group(1),
                'xml_index': int(index_m.group(1)),
                'var_in': [{'name': n.strip(), 'flags_hex': h} for n, h in var_in],
                'var_out': [{'name': n.strip(), 'flags_hex': h} for n, h in var_out],
            })

    # 인스턴스 집계
    inst_counter = collections.Counter(f['name'] for f in funcs_found)
    # 고유 함수 (중복 제거, 첫 등장의 VAR_IN/OUT 유지)
    seen = set()
    unique_funcs = []
    for f in funcs_found:
        if f['name'] not in seen:
            seen.add(f['name'])
            unique_funcs.append({**f, 'instance_count': inst_counter[f['name']]})

    # 3) Rung 구조 — 각 Rung 내부의 Element 리스트
    rungs = []
    # <Rung ...>...</Rung> 블록 추출. XML이 중첩되지 않는 구조 가정.
    rung_pattern = re.compile(r'<Rung([^>]*)>(.*?)</Rung>', re.DOTALL)
    for ri, m in enumerate(rung_pattern.finditer(text)):
        attr = m.group(1)
        body = m.group(2)
        block_mask_m = re.search(r'BlockMask="(\d+)"', attr)
        elements = []
        for em in re.finditer(r'<Element\s+([^>]*?)(?:/>|>([^<]*)</Element>)', body, re.DOTALL):
            el_attr = em.group(1)
            el_body = (em.group(2) or '').strip()
            et_m = re.search(r'ElementType="(\d+)"', el_attr)
            coord_m = re.search(r'Coordinate="(\d+)"', el_attr)
            elements.append({
                'type': int(et_m.group(1)) if et_m else None,
                'coord': int(coord_m.group(1)) if coord_m else None,
                'addr_or_name': el_body if el_body else None,
            })
        rungs.append({
            'index': ri,
            'block_mask': int(block_mask_m.group(1)) if block_mask_m else 0,
            'elements': elements,
            'element_count': len(elements),
        })

    # 4) ElementType 분포
    element_type_counts = dict(collections.Counter(
        re.findall(r'ElementType="(\d+)"', text)
    ).most_common())

    # 5) 시스템 플래그 (_로 시작하는 식별자)
    system_flags = sorted(set(re.findall(r'\b_[A-Z][A-Z0-9_]*\b', text)))

    # 6) 프로그램 블록
    progs = re.findall(r'<Program[^>]*Name="([^"]+)"', text)

    stats = {
        'xml_size_chars': len(text),
        'total_addr_refs': len(all_addrs_raw),
        'unique_addr_count': len(unique_word),
        'bit_addr_count': len(bit_addrs),
        'function_instance_count': len(funcs_found),
        'unique_function_count': len(unique_funcs),
        'rung_count': len(rungs),
        'system_flag_count': len(system_flags),
    }

    return {
        'source': str(xml_path),
        'programs': progs,
        'addresses': {
            'word_unique': unique_word,
            'bit_unique': bit_addrs,
            'by_area': by_area_sorted,
        },
        'functions': unique_funcs,
        'rungs': rungs,
        'element_type_counts': element_type_counts,
        'element_type_legend': {
            '0': 'blank', '1': 'vertical', '2': 'horizontal', '6': 'NO(A접점)',
            '7': 'NC(B접점)', '8': 'PULSE', '14': 'OUT coil',
            '16': 'unknown(SET?)', '17': 'unknown(RESET?)',
            '70': 'FB I/O var', '102': 'FB definition'
        },
        'system_flags': system_flags,
        'stats': stats,
    }


def main():
    parser = argparse.ArgumentParser(
        description='XG5000 XML → variables.json 변환기',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python plc_xml_parser.py project.xml
  python plc_xml_parser.py project.xml --out vars.json
  python plc_xml_parser.py project.xml --full --out ground_truth.json
        """
    )
    parser.add_argument('xml', help='XG5000 project XML file')
    parser.add_argument('--out', default='variables.json', help='Output file (default: variables.json)')
    parser.add_argument('--full', action='store_true',
                        help='Full structure extraction (functions/rungs/flags) — Phase B ground truth')
    args = parser.parse_args()

    xml_path = Path(args.xml)
    if not xml_path.exists():
        print(f"Error: file not found: {args.xml}")
        sys.exit(1)

    if args.full:
        # Phase B 정답지 생성 모드
        print(f"Parsing (full structure): {args.xml}")
        full = parse_xg5000_xml_full(str(xml_path))
        stats = full['stats']
        print(f"\n=== 정답지 (ground truth) ===")
        print(f"Programs: {full['programs']}")
        print(f"Addresses: unique={stats['unique_addr_count']} word, bit={stats['bit_addr_count']}")
        print(f"  By area: {dict((k, len(v)) for k, v in full['addresses']['by_area'].items())}")
        print(f"Functions: {stats['unique_function_count']} unique / {stats['function_instance_count']} instances")
        for fb in full['functions']:
            print(f"  {fb['name']}: INDEX={fb['xml_index']} × {fb['instance_count']} / in={len(fb['var_in'])} out={len(fb['var_out'])}")
        print(f"Rungs: {stats['rung_count']}")
        print(f"ElementType: {full['element_type_counts']}")
        print(f"System flags: {stats['system_flag_count']} unique")
        out_path = Path(args.out if args.out != 'variables.json' else 'xg5000_full.json')
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(full, f, indent=2, ensure_ascii=False)
        print(f"\n✓ Full ground truth → {out_path.absolute()}")
        return

    print(f"Parsing: {args.xml}")
    variables, programs, stats = parse_xg5000_xml(str(xml_path))

    print(f"\nPrograms found: {len(programs)}")
    for prog in programs[:5]:
        print(f"  - {prog}")
    if len(programs) > 5:
        print(f"  ... and {len(programs) - 5} more")

    print(f"\nVariable references (total: {stats['total_refs']})")
    print(f"  MW: {stats['mw_refs']}")
    print(f"  IW: {stats['iw_refs']}")
    print(f"  QW: {stats['qw_refs']}")
    print(f"  MB: {stats['mb_refs']}")
    print(f"  IB: {stats['ib_refs']}")
    print(f"  QB: {stats['qb_refs']}")
    print(f"  Other: {stats['other_refs']}")

    print(f"\nUnique variables found: {len(variables)}")

    # Group by area for display
    by_area = defaultdict(list)
    for v in variables:
        by_area[v['area']].append(v['word'])

    for area in sorted(by_area.keys()):
        words = sorted(by_area[area])
        print(f"  {area}W: {len(words)} variables")
        # Show first 5 and last 5
        if len(words) <= 10:
            print(f"       {words}")
        else:
            print(f"       {words[:5]} ... {words[-5:]}")

    # Save
    output = {
        'source': str(xml_path.absolute()),
        'programs': programs,
        'variables': variables
    }

    out_path = Path(args.out)
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\n✓ Saved to {out_path.absolute()} ({len(variables)} variables)")


if __name__ == '__main__':
    main()
