#!/usr/bin/env python3
"""XG5000 IL(Instruction List) 파일 파서.

Phase B.1 Rosetta 정렬의 입력측. IL 텍스트를 바이트코드 대조가 용이한
구조화 형태(프로그램→rung→instruction)로 변환.

Usage:
    python plc_il_parser.py docs/try_again_LSPLC --out il_parsed.json
"""
import re
import sys
import json
import argparse
from pathlib import Path
from collections import Counter


TYPE_SUFFIXES = ('_LINT', '_UDINT', '_DINT', '_INT', '_WORD', '_REAL', '_LREAL', '_UINT', '_ULINT')


def _extract_type_suffix(opcode):
    """ADD2_INT → _INT, MOVE_WORD → _WORD."""
    for sfx in TYPE_SUFFIXES:
        if opcode.endswith(sfx):
            return sfx
    return None


def _is_likely_function_opcode(opcode):
    """함수블록 호출 여부 판정 휴리스틱.

    LOAD/OR/OUT/SET/RST/XGRUNGSTART 같은 기본 명령은 제외.
    _INT/_WORD 접미사가 있거나 대문자 3자+인 경우 함수 호출로 간주.
    """
    if opcode in {'XGRUNGSTART', 'LOAD', 'OR', 'AND', 'OUT', 'SET', 'RST',
                  'ANDP', 'ORP', 'ANDN', 'ORN', 'LOADP', 'LOADN'}:
        return False
    if _extract_type_suffix(opcode):
        return True
    # 타이머·카운터
    if opcode in {'TON', 'TOF', 'TP', 'CTU', 'CTD', 'CTUD', 'RS', 'SR'}:
        return True
    if any(opcode.startswith(p) for p in ('CTU_', 'CTD_', 'CTUD_')):
        return True
    return False


def parse_il_file(il_path):
    """IL 파일 → 구조화 딕셔너리.

    Returns:
        dict with keys: source, programs, stats
        programs: [{name, rungs: [{instructions: [...]}], rung_count, instruction_count}]
    """
    path = Path(il_path)
    # XG5000 IL은 cp949/euc-kr 한글 포함 — 여러 인코딩 시도
    text = None
    for enc in ('cp949', 'euc-kr', 'utf-8'):
        try:
            text = path.read_text(encoding=enc)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        raise RuntimeError(f'인코딩 판별 실패: {il_path}')

    # [프로그램] 또는 [@VARIABLES] 단위 분리
    blocks = re.split(r'\n(?=\[)', text)

    programs = []
    opcode_counter = Counter()

    for block in blocks:
        header_match = re.match(r'^\[([^\]@]+)\]', block)
        if not header_match:
            continue  # [@VARIABLES] 같은 메타 섹션 스킵

        prog_name = header_match.group(1).strip()

        rungs = []
        current_rung = None

        for line in block.split('\n')[1:]:  # 헤더 라인 제외
            # 형식: "0\t<opcode>" 또는 "0\t<opcode>\t<operands>"
            match = re.match(r'^(\d+)\t(\S+)(?:\t(.*))?$', line)
            if not match:
                continue

            idx_str, opcode, operand_str = match.groups()
            operand_str = operand_str or ''
            opcode_counter[opcode] += 1

            if opcode == 'XGRUNGSTART':
                # 새 rung 시작 — 이전 rung 마감
                if current_rung is not None:
                    rungs.append(current_rung)
                current_rung = {'instructions': []}
                continue

            # 첫 인스트럭션 앞에 XGRUNGSTART 없는 경우 대비
            if current_rung is None:
                current_rung = {'instructions': []}

            # 파라미터 쪼개기 (콤마 분리, 공백 제거)
            operands = []
            if operand_str.strip():
                operands = [x.strip() for x in operand_str.split(',')]

            # 함수블록은 보통 첫 operand가 인스턴스 이름 (INST, INST1, ...)
            instance_name = None
            remaining_operands = operands
            if _is_likely_function_opcode(opcode) and operands:
                # 타이머·카운터·RS·SR 같이 명시적으로 INST 체계 쓰는 것만 추출
                if opcode in {'TON', 'TOF', 'TP', 'RS', 'SR'} or any(opcode.startswith(p) for p in ('CTU', 'CTD')):
                    first = operands[0]
                    # INST, INST1, INST2 같은 이름 (대문자+숫자)
                    if re.match(r'^INST\d*$', first, re.IGNORECASE):
                        instance_name = first
                        remaining_operands = operands[1:]

            current_rung['instructions'].append({
                'il_idx': int(idx_str),
                'opcode': opcode,
                'operand_str': operand_str,
                'operands': remaining_operands,
                'instance': instance_name,
                'type_suffix': _extract_type_suffix(opcode),
                'is_function_call': _is_likely_function_opcode(opcode),
            })

        if current_rung is not None:
            rungs.append(current_rung)

        programs.append({
            'name': prog_name,
            'rungs': rungs,
            'rung_count': len(rungs),
            'instruction_count': sum(len(r['instructions']) for r in rungs),
        })

    total_rungs = sum(p['rung_count'] for p in programs)
    total_instrs = sum(p['instruction_count'] for p in programs)

    # 함수 호출 순서 리스트 (Rosetta 정렬용)
    function_call_sequence = []
    for p in programs:
        for r in p['rungs']:
            for ins in r['instructions']:
                if ins['is_function_call']:
                    function_call_sequence.append({
                        'program': p['name'],
                        'opcode': ins['opcode'],
                        'instance': ins['instance'],
                        'type_suffix': ins['type_suffix'],
                    })

    return {
        'source': str(path),
        'programs': programs,
        'function_call_sequence': function_call_sequence,
        'stats': {
            'program_count': len(programs),
            'total_rungs': total_rungs,
            'total_instructions': total_instrs,
            'unique_opcodes': len(opcode_counter),
            'opcode_vocabulary': dict(opcode_counter.most_common()),
            'function_call_count': len(function_call_sequence),
        }
    }


def main():
    parser = argparse.ArgumentParser(
        description='XG5000 IL(Instruction List) 파일 파서 — Phase B.1 Rosetta 입력',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  python plc_il_parser.py docs/try_again_LSPLC --out il_parsed.json
""")
    parser.add_argument('il_path', help='IL 파일 경로 (XG5000 IL export)')
    parser.add_argument('--out', default='il_parsed.json',
                        help='출력 JSON 경로 (default: il_parsed.json)')
    parser.add_argument('--verbose', '-v', action='store_true')
    args = parser.parse_args()

    if not Path(args.il_path).exists():
        print(f'Error: IL file not found: {args.il_path}')
        sys.exit(1)

    print(f'Parsing IL: {args.il_path}')
    result = parse_il_file(args.il_path)

    print(f'\n=== IL 파싱 결과 ===')
    for p in result['programs']:
        print(f"  [{p['name']:<20}] — {p['rung_count']:3d} rungs, "
              f"{p['instruction_count']:4d} instructions")
    s = result['stats']
    print(f"\n총 {s['program_count']} programs / {s['total_rungs']} rungs / "
          f"{s['total_instructions']} instructions / {s['unique_opcodes']} OPCODE종")
    print(f'\n함수 호출 시퀀스: {s["function_call_count"]}개')

    if args.verbose:
        print(f'\nOPCODE 어휘 (전체 {s["unique_opcodes"]}종):')
        for op, cnt in s['opcode_vocabulary'].items():
            print(f'  {op:25s} {cnt:5d}')
        print(f'\n함수 호출 순서 (상위 10):')
        for fc in result['function_call_sequence'][:10]:
            inst = f' INST={fc["instance"]}' if fc['instance'] else ''
            print(f"  [{fc['program']}] {fc['opcode']}{inst}")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f'\n✓ JSON 출력: {out_path.absolute()}')


if __name__ == '__main__':
    main()
