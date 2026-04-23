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


def compare_with_ast(xml_truth, ast):
    """AST vs XML 정답지 대조 (Phase B.3).

    Program count, rung count, instruction 분포, address set intersection을 검증.
    """
    # Program/Rung 개수 검증
    ast_program_count = ast['stats']['total_programs']
    ast_rung_count = ast['stats']['total_rungs']
    xml_rung_count = xml_truth['stats']['rung_count']

    # Instruction 종류별 분포
    by_kind = ast['stats'].get('by_kind', {})
    function_calls = by_kind.get('function_call', 0)
    contacts = by_kind.get('contact', 0)
    coils = by_kind.get('coil', 0)
    system_flags = by_kind.get('system_flag', 0)
    unknown = by_kind.get('unknown', 0)

    # Address set intersection
    # AST에서 params.in/out의 주소들 수집
    ast_addresses = set()
    for program in ast.get('programs', []):
        for rung in program.get('rungs', []):
            for instr in rung.get('instructions', []):
                if 'params' in instr:
                    ast_addresses.update(instr['params'].get('in', []))
                    ast_addresses.update(instr['params'].get('out', []))
                if 'address' in instr:
                    ast_addresses.add(instr['address'])

    # XML 주소
    xml_addresses = set(xml_truth['addresses']['word_unique'])

    # Intersection
    common_addresses = ast_addresses & xml_addresses
    only_ast = ast_addresses - xml_addresses
    only_xml = xml_addresses - ast_addresses

    # Function call recall
    recall_str = ast['stats'].get('function_call_recall', '0/18')

    report = {
        'pass': True,
        'program_count': {
            'ast': ast_program_count,
            'expected': 4,
            'match': ast_program_count == 4,
        },
        'rung_count': {
            'ast': ast_rung_count,
            'xml': xml_rung_count,
            'match': ast_rung_count == xml_rung_count,
        },
        'instruction_distribution': {
            'function_call': function_calls,
            'contact': contacts,
            'coil': coils,
            'system_flag': system_flags,
            'unknown': unknown,
            'total': function_calls + contacts + coils + system_flags + unknown,
        },
        'function_call_recall': recall_str,
        'address_intersection': {
            'ast_addresses': len(ast_addresses),
            'xml_addresses': len(xml_addresses),
            'common': len(common_addresses),
            'only_ast': sorted(only_ast)[:10],  # 첫 10개만
            'only_xml': sorted(only_xml)[:10],  # 첫 10개만
            'intersection_ratio': round(len(common_addresses) / max(len(xml_addresses), 1) * 100, 1),
        },
        'phase_b5_pending': ast['stats'].get('phase_b5_pending', []),
    }

    # 검증 결과
    if not (ast_program_count == 4 and ast_rung_count == 21):
        report['pass'] = False

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


def print_ast_report(rep):
    """AST vs XML 대조 리포트 출력."""
    status = "✓ PASS" if rep['pass'] else "✗ FAIL"
    print(f"\n{status} AST vs XML 대조\n")

    print("=== Program/Rung Count ===")
    pc = rep['program_count']
    print(f"  Program: {pc['ast']}/{pc['expected']} {'✓' if pc['match'] else '✗'}")

    rc = rep['rung_count']
    print(f"  Rung: {rc['ast']} (XML: {rc['xml']}) {'✓' if rc['match'] else '✗'}")

    print("\n=== Instruction 분포 (kind별) ===")
    dist = rep['instruction_distribution']
    print(f"  function_call: {dist['function_call']}")
    print(f"  contact: {dist['contact']}")
    print(f"  coil: {dist['coil']}")
    print(f"  system_flag: {dist['system_flag']}")
    print(f"  unknown: {dist['unknown']}")
    print(f"  총합: {dist['total']}")

    print("\n=== Function Call Recall ===")
    print(f"  {rep['function_call_recall']} (IL 18개 중 BC 매핑)")

    print("\n=== Address Intersection ===")
    addr = rep['address_intersection']
    print(f"  AST 주소: {addr['ast_addresses']}개")
    print(f"  XML 주소: {addr['xml_addresses']}개")
    print(f"  일치: {addr['common']}개 ({addr['intersection_ratio']}%)")
    if addr['only_ast']:
        print(f"  AST만: {addr['only_ast']}")
    if addr['only_xml']:
        print(f"  XML만: {addr['only_xml']}")

    print("\n=== Phase B.5 Pending ===")
    print(f"  {rep['phase_b5_pending']}")


def main():
    parser = argparse.ArgumentParser(
        description='프로토콜 추출 결과 vs XML/AST 정답지 대조',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python validate_extraction.py --xml docs/xg5000_full_manyfunction.json --dump snapshots/dump_20260423_101530/
  python validate_extraction.py --xml docs/xg5000_full_manyfunction.json --snapshot snapshots/values.json
  python validate_extraction.py --xml docs/xg5000_full_manyfunction.json --ast docs/program_ast_0423.json
""")
    parser.add_argument('--xml', required=True, help='XG5000 XML 정답지 파일')
    parser.add_argument('--dump', help='Phase B.0 덤프 디렉토리 (snapshots/dump_<ts>/)')
    parser.add_argument('--snapshot', help='snapshots/values.json (덤프 없을 때)')
    parser.add_argument('--ast', help='Phase B.3 Program AST JSON')
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

    # AST 비교 모드 (Phase B.3)
    if args.ast:
        ast_path = Path(args.ast)
        if not ast_path.exists():
            print(f"Error: AST not found: {args.ast}")
            sys.exit(1)

        print(f"AST 분석: {args.ast}")
        with open(ast_path, encoding='utf-8') as f:
            ast = json.load(f)

        report = compare_with_ast(xml_truth, ast)
        print_ast_report(report)

        if args.json_out:
            with open(args.json_out, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(f"\n✓ JSON 리포트 → {args.json_out}")
        sys.exit(0)

    # 기존 덤프/스냅샷 비교 모드
    if args.dump:
        extracted = load_extracted_from_dump(args.dump)
        print(f"덤프 분석: {args.dump}")
    elif args.snapshot:
        extracted = load_extracted_from_snapshot(args.snapshot)
        print(f"스냅샷 분석: {args.snapshot}")
    else:
        print("Error: --dump, --snapshot, --ast 중 하나 필요")
        sys.exit(1)

    report = compare(xml_truth, extracted)
    print_report(report)

    if args.json_out:
        with open(args.json_out, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n✓ JSON 리포트 → {args.json_out}")


if __name__ == '__main__':
    main()
