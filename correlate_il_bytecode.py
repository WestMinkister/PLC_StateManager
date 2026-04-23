#!/usr/bin/env python3
"""Phase B.1 Rosetta 정렬기 — IL 명령 순서 ↔ 바이트코드 FB_DEFINITION 순서.

사용자 지시의 중심 (2026-04-23): 이름 매핑이 아닌 Grammar 인식이 본질.
이 도구는 IL·바이트코드를 **구조적으로 정렬**하여 미지의 바이트 시퀀스에
이름을 "사후 주석"으로 붙일 뿐. 구조 인식은 이미 완료됨.

Usage:
    python correlate_il_bytecode.py \\
        --il docs/il_parsed_0423.json \\
        --bytecode docs/bytecode_scan_0423.json \\
        --out docs/rosetta_0423.json
"""
import sys
import json
import argparse
from pathlib import Path
from collections import Counter


def extract_il_function_sequence(il_data):
    """IL 파싱 결과에서 함수 호출 순서만 추출."""
    return il_data.get('function_call_sequence', [])


def extract_bc_fb_definitions(bytecode_data):
    """바이트코드 스캔 결과에서 FB_DEFINITION 토큰 순서 추출."""
    fb_defs = []
    for resp_idx, resp in enumerate(bytecode_data.get('responses', [])):
        for t in resp.get('tokens', []):
            if t.get('type') == 'FB_DEFINITION':
                fb_defs.append({
                    'resp_idx': resp_idx,
                    'pos': t['pos'],
                    'func_id': t.get('func_id'),
                    'sub_type': t.get('sub_type'),
                    'from_bzip2': t.get('from_bzip2', False),
                })
    return fb_defs


def correlate(il_sequence, bc_fb_defs, xml_truth=None):
    """IL 함수 호출 ↔ 바이트코드 FB_DEFINITION 상관관계 분석.

    IL 순서와 BC 순서는 다르다 (BC는 INDEX 오름차순으로 저장됨).
    따라서 **XML 정답지**를 신뢰할 수 있는 가교로 사용:
        IL OPCODE ↔ XML name ↔ XML INDEX ↔ BC func_id

    Args:
        il_sequence: IL 함수 호출 순서 리스트
        bc_fb_defs: BC FB_DEFINITION 토큰 리스트 (func_id 포함)
        xml_truth: (optional) XML 정답지 딕셔너리. functions 리스트에서 name↔index.

    Returns: dict — 대조 리포트 + 확정 매핑 + 누락 목록 + 이상 케이스
    """
    il_count = Counter(i['opcode'] for i in il_sequence)
    bc_count = Counter(d['func_id'] for d in bc_fb_defs)
    bc_ids_set = set(bc_count.keys())

    result = {
        'il_total_calls': len(il_sequence),
        'bc_total_fb_defs': len(bc_fb_defs),
        'il_opcode_counts': dict(il_count.most_common()),
        'bc_func_id_counts': dict(sorted(bc_count.items())),
    }

    # XML 정답지가 있으면 그걸로 교차검증 (가장 신뢰성 높은 방법)
    if xml_truth and 'functions' in xml_truth:
        xml_mapping = {f['name']: f['xml_index'] for f in xml_truth['functions']}
        result['xml_mapping'] = dict(sorted(xml_mapping.items()))

        # 각 IL OPCODE에 대해 XML 기반 추정 INDEX 시도
        # IL OPCODE 이름과 XML 함수명의 매칭 규칙:
        #   - 정확 일치: "ADD" ↔ "ADD" (거의 없음)
        #   - 접미사 매칭: "ADD2_INT" → base_name "ADD" or "ADD2"
        #   - 변형: "MOVE_WORD" → "MOVE"
        il_to_xml = {}
        unresolved_il = []
        for il_opcode in sorted(il_count.keys()):
            # XML에서 후보 찾기 (endswith 제거 후 매칭)
            candidates = []
            for xml_name in xml_mapping:
                if il_opcode == xml_name:
                    candidates.append(('exact', xml_name))
                elif il_opcode.startswith(xml_name) and len(xml_name) >= 2:
                    # "CTU_INT" ↔ "CTU_INT" 같은 경우 (이미 exact)
                    # "ADD2_INT" starts with "ADD2" which doesn't match "ADD"
                    # 단 정확한 이름이 우선. "MOVE_WORD".startswith("MOVE") 는 True.
                    candidates.append(('prefix', xml_name))
                elif xml_name.startswith(il_opcode):
                    candidates.append(('xml_starts_with_il', xml_name))
            # Fuzzy: base name 추출 시도 — 숫자·접미사 제거
            if not candidates:
                stripped = il_opcode.rstrip('0123456789')
                for sfx in ('_INT', '_WORD', '_DINT', '_UDINT', '_LINT', '_REAL', '_LREAL'):
                    if stripped.endswith(sfx):
                        stripped = stripped[:-len(sfx)]
                        break
                stripped = stripped.rstrip('0123456789')
                if stripped and stripped in xml_mapping:
                    candidates.append(('stripped', stripped))

            if candidates:
                # exact > stripped > prefix 우선순위
                for priority in ('exact', 'stripped', 'prefix', 'xml_starts_with_il'):
                    matched = [c for c in candidates if c[0] == priority]
                    if matched:
                        il_to_xml[il_opcode] = {
                            'xml_name': matched[0][1],
                            'xml_index': xml_mapping[matched[0][1]],
                            'match_type': priority,
                        }
                        break
            else:
                unresolved_il.append(il_opcode)

        result['il_to_xml_mapping'] = il_to_xml
        result['il_unresolved'] = unresolved_il

        # BC에서 발견/미발견 분류
        confirmed_in_bc = {}
        missing_in_bc = {}
        for il_op, info in il_to_xml.items():
            xml_idx = info['xml_index']
            if xml_idx in bc_ids_set:
                confirmed_in_bc[il_op] = {
                    'xml_index': xml_idx,
                    'bc_func_id': xml_idx,
                    'il_count': il_count[il_op],
                    'bc_count': bc_count[xml_idx],
                    'coverage': f"{bc_count[xml_idx]}/{il_count[il_op]}",
                }
            else:
                missing_in_bc[il_op] = {
                    'xml_index': xml_idx,
                    'il_count': il_count[il_op],
                    'reason_hypothesis': 'special encoding (likely Timer/Counter first-instance)',
                }

        result['confirmed_il_to_bc'] = confirmed_in_bc
        result['missing_from_bc'] = missing_in_bc

        # BC에는 있는데 IL 매핑 없는 func_id
        mapped_bc_ids = {info['bc_func_id'] for info in confirmed_in_bc.values()}
        orphan_bc_ids = bc_ids_set - mapped_bc_ids
        result['bc_orphan_func_ids'] = sorted(orphan_bc_ids)

        # 진척 지표
        total_unique_functions_in_il = len(il_count)
        confirmed = len(confirmed_in_bc)
        result['recall_il_to_bc'] = round(100 * confirmed / total_unique_functions_in_il, 1) if total_unique_functions_in_il else 0
    else:
        result['xml_mapping'] = None
        result['note'] = 'XML 정답지 없이는 순서 정렬만으로 신뢰할 수 없음'

    return result


def print_report(result):
    print(f"=== Rosetta 정렬 결과 ===")
    print(f"IL 함수 호출: {result['il_total_calls']}개")
    print(f"BC FB_DEFINITION: {result['bc_total_fb_defs']}개")
    print(f"\nIL OPCODE 분포:")
    for op, cnt in result['il_opcode_counts'].items():
        print(f"  {op:20s} {cnt}")
    print(f"\nBC func_id 분포:")
    for fid, cnt in result['bc_func_id_counts'].items():
        print(f"  {fid:3d} (0x{fid:02x})  {cnt}")

    if 'confirmed_il_to_bc' in result:
        confirmed = result['confirmed_il_to_bc']
        missing = result['missing_from_bc']
        orphan = result['bc_orphan_func_ids']
        print(f"\n=== XML 교차검증 Rosetta 매핑 (Recall {result['recall_il_to_bc']}%) ===")
        for op, info in sorted(confirmed.items(), key=lambda x: x[1]['xml_index']):
            print(f"  {op:15s} → XML INDEX {info['xml_index']:3d} (0x{info['xml_index']:02x})  "
                  f"IL:{info['il_count']} BC:{info['bc_count']}  coverage={info['coverage']}")
        if missing:
            print(f"\n⚠ BC FB_DEFINITION에서 미발견 ({len(missing)}개):")
            for op, info in sorted(missing.items(), key=lambda x: x[1]['xml_index']):
                print(f"  {op:15s} (XML INDEX {info['xml_index']})  IL:{info['il_count']}회  "
                      f"— {info['reason_hypothesis']}")
        if orphan:
            print(f"\n⚠ BC에만 있는 func_id (IL 매핑 없음): {orphan}")
        if result.get('il_unresolved'):
            print(f"\n⚠ IL → XML 매칭 실패 OPCODE: {result['il_unresolved']}")
    else:
        print(f"\n(XML 정답지 없이 실행 — 순서 정렬만 시도, 신뢰도 낮음)")


def main():
    parser = argparse.ArgumentParser(
        description='Phase B.1 Rosetta — IL 함수 호출 순서 ↔ 바이트코드 FB_DEFINITION',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--il', required=True, help='plc_il_parser 결과 JSON')
    parser.add_argument('--bytecode', required=True, help='plc_bytecode_scanner 결과 JSON')
    parser.add_argument('--xml-truth', help='XG5000 XML 정답지 JSON (plc_xml_parser --full 결과)')
    parser.add_argument('--out', default='rosetta.json', help='출력 JSON 경로')
    args = parser.parse_args()

    with open(args.il, encoding='utf-8') as f:
        il_data = json.load(f)
    with open(args.bytecode, encoding='utf-8') as f:
        bc_data = json.load(f)
    xml_truth = None
    if args.xml_truth:
        with open(args.xml_truth, encoding='utf-8') as f:
            xml_truth = json.load(f)

    il_seq = extract_il_function_sequence(il_data)
    bc_fb = extract_bc_fb_definitions(bc_data)

    result = correlate(il_seq, bc_fb, xml_truth=xml_truth)
    print_report(result)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f'\n✓ JSON 출력: {out_path.absolute()}')


if __name__ == '__main__':
    main()
