#!/usr/bin/env python3
"""Phase B.0 — 프로토콜 추출 결과 vs XG5000 XML 정답지 대조 도구.

사용자 철학: XML은 검증용. PLC 프로토콜로 뽑은 결과가 XML과 얼마나 일치하는가를
측정하면 "프로토콜 완벽 이해"의 진척도를 정량화할 수 있다.

Usage:
    python validate_extraction.py --xml docs/0423_try_again_0422.xml \\
                                   --dump snapshots/dump_20260423_101530/
    python validate_extraction.py --xml docs/0423_try_again_0422.xml \\
                                   --snapshot snapshots/values.json
"""
import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from plc_xml_parser import parse_xg5000_xml_full


def load_extracted_from_dump(dump_dir):
    """Phase B.0 덤프 디렉토리에서 프로토콜 추출 결과를 읽어옴."""
    dump_dir = Path(dump_dir)
    meta_path = dump_dir / 'meta.json'
    if not meta_path.exists():
        raise FileNotFoundError(f"meta.json not found in {dump_dir}")
    with open(meta_path, encoding='utf-8') as f:
        meta = json.load(f)
    return {
        'source': 'dump',
        'symbols': meta.get('scatter_gather_symbols', []),
        'fragment_count': meta.get('scatter_gather_fragments', 0),
        'meta': meta,
    }


def load_extracted_from_snapshot(snapshot_path):
    """snapshots/values.json에서 읽기 결과만 꺼냄 (덤프 없을 때 축약 비교)."""
    with open(snapshot_path, encoding='utf-8') as f:
        snap = json.load(f)
    values_latest = snap.get('values_latest', {})
    # MW152, IW5000 같은 키를 %MW152 형태로 정규화
    symbols = [f'%{name[:2]}{name[2:]}' if re.match(r'^[A-Z]{2}\d', name) else name
               for name in values_latest]
    return {
        'source': 'snapshot',
        'symbols': symbols,
        'values': values_latest,
    }


def compare(xml_truth, extracted):
    """대조 리포트 생성."""
    xml_word = set(xml_truth['addresses']['word_unique'])
    ext_word = set(extracted['symbols'])

    common = xml_word & ext_word
    only_xml = xml_word - ext_word      # 추출 누락
    only_ext = ext_word - xml_word      # stale 또는 추출 오탐

    report = {
        'address_accuracy': {
            'xml_count': len(xml_word),
            'extracted_count': len(ext_word),
            'common': sorted(common),
            'missing_from_extraction': sorted(only_xml),
            'stale_or_extra': sorted(only_ext),
            'precision': round(len(common) / len(ext_word) * 100, 1) if ext_word else 0,
            'recall': round(len(common) / len(xml_word) * 100, 1) if xml_word else 0,
        },
        'function_status': {
            'xml_functions': [{'name': f['name'], 'xml_index': f['xml_index'],
                              'instances': f['instance_count']} for f in xml_truth['functions']],
            'extracted_functions': [],
            'note': 'Extracted function detection requires Phase B.2 (bytecode correlator)',
        },
        'system_flags_status': {
            'xml_count': len(xml_truth['system_flags']),
            'extracted_count': 0,
            'note': 'System flag detection requires regex extension (Phase B.0+)',
        },
        'rung_status': {
            'xml_count': xml_truth['stats']['rung_count'],
            'extracted_count': None,
            'note': 'Rung boundary detection requires Phase B.5',
        },
    }
    return report


def print_report(rep):
    acc = rep['address_accuracy']
    print("=== 주소 대조 ===")
    print(f"  XML 고유 주소: {acc['xml_count']}개")
    print(f"  추출 주소: {acc['extracted_count']}개")
    print(f"  일치: {len(acc['common'])}개")
    print(f"  Precision: {acc['precision']}% (추출 중 XML에 있는 비율)")
    print(f"  Recall:    {acc['recall']}% (XML 중 추출된 비율)")
    if acc['missing_from_extraction']:
        print(f"  누락 주소 (XML에만): {acc['missing_from_extraction']}")
    if acc['stale_or_extra']:
        print(f"  stale/오탐 (추출에만): {acc['stale_or_extra']}")

    print("\n=== 함수블록 ===")
    fs = rep['function_status']
    for fb in fs['xml_functions']:
        print(f"  XML: {fb['name']} INDEX={fb['xml_index']} × {fb['instances']}")
    print(f"  추출: {len(fs['extracted_functions'])} ({fs['note']})")

    print("\n=== 시스템 플래그 ===")
    print(f"  XML: {rep['system_flags_status']['xml_count']} / 추출: {rep['system_flags_status']['extracted_count']}")
    print(f"  ({rep['system_flags_status']['note']})")

    print("\n=== Rung ===")
    print(f"  XML: {rep['rung_status']['xml_count']}개")
    print(f"  추출: {rep['rung_status']['extracted_count']} ({rep['rung_status']['note']})")


def main():
    parser = argparse.ArgumentParser(description='Phase B.0 추출 결과 vs XML 정답지 대조')
    parser.add_argument('--xml', required=True, help='XG5000 XML 정답지 파일')
    parser.add_argument('--dump', help='Phase B.0 덤프 디렉토리 (snapshots/dump_<ts>/)')
    parser.add_argument('--snapshot', help='snapshots/values.json (덤프 없을 때)')
    parser.add_argument('--json-out', help='리포트를 JSON 파일로 저장')
    args = parser.parse_args()

    xml_path = Path(args.xml)
    if not xml_path.exists():
        print(f"Error: XML not found: {args.xml}")
        sys.exit(1)

    print(f"XML 정답지 분석 중: {args.xml}")
    xml_truth = parse_xg5000_xml_full(str(xml_path))
    print(f"  XML: {xml_truth['stats']['unique_addr_count']} 주소, "
          f"{xml_truth['stats']['unique_function_count']} 함수, "
          f"{xml_truth['stats']['rung_count']} rung\n")

    if args.dump:
        extracted = load_extracted_from_dump(args.dump)
        print(f"덤프 분석: {args.dump}")
    elif args.snapshot:
        extracted = load_extracted_from_snapshot(args.snapshot)
        print(f"스냅샷 분석: {args.snapshot}")
    else:
        print("Error: --dump 또는 --snapshot 중 하나 필요")
        sys.exit(1)

    report = compare(xml_truth, extracted)
    print_report(report)

    if args.json_out:
        with open(args.json_out, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n✓ JSON 리포트 → {args.json_out}")


if __name__ == '__main__':
    main()
