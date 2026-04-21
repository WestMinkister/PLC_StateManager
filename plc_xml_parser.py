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


def main():
    parser = argparse.ArgumentParser(
        description='XG5000 XML → variables.json 변환기',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python plc_xml_parser.py project.xml
  python plc_xml_parser.py project.xml --out vars.json
        """
    )
    parser.add_argument('xml', help='XG5000 project XML file')
    parser.add_argument('--out', default='variables.json', help='Output file (default: variables.json)')
    args = parser.parse_args()

    xml_path = Path(args.xml)
    if not xml_path.exists():
        print(f"Error: file not found: {args.xml}")
        sys.exit(1)

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
