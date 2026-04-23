#!/usr/bin/env python3
"""Phase B.7 — PLC_StateManager 통합 CLI.

6단계 공식 플로우 orchestrator:
  ① extract — pcapng → AST (plc_program_parser 래핑)
  ② compare — AST ↔ AST diff (plc_ast_diff 래핑)
  ③ (compare 와 동일 sub-command, rung·instruction 수준 판별)
  ④ backup — PLC 값 백업 (plc_value_backup subprocess 래핑, Commit 2)
  flow — ①②③④ 순차 실행 (Commit 2)

이 모듈은 각 단계의 단독 도구를 유지하면서 통합 UX 제공.
⑤ 쓰기 / ⑥ 실패 진단은 B.6 이후.
"""

from __future__ import annotations

import argparse
import json
import sys
import os
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from plc_program_parser import ProgramASTBuilder
from plc_ast_diff import (
    load_ast,
    diff_ast,
    DiffOptions,
    print_ast_diff,
    write_json_diff,
)


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='plc_state_manager.py',
        description='PLC_StateManager 통합 CLI — 6단계 플로우 orchestrator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  # ① pcapng 에서 AST 추출
  python plc_state_manager.py extract docs/0423.pcapng -o ast.json

  # ②③ 두 AST 비교 (rung·instruction 수준)
  python plc_state_manager.py compare ast_a.json ast_b.json --json-out diff.json

  # (Commit 2 예정) ④ 값 백업 / flow orchestrator
""",
    )
    subparsers = parser.add_subparsers(dest='command', help='sub-command')

    # ① extract
    p_extract = subparsers.add_parser(
        'extract',
        help='① pcapng 에서 프로그램 AST 추출',
    )
    p_extract.add_argument('input', help='입력 pcapng 또는 사전 처리된 JSON')
    p_extract.add_argument('-o', '--output', default='program_ast.json',
                           help='출력 AST JSON 경로 (기본: program_ast.json)')
    p_extract.add_argument('-v', '--verbose', action='store_true',
                           help='요약 통계 출력')
    p_extract.set_defaults(func=cmd_extract)

    # ②③ compare
    p_compare = subparsers.add_parser(
        'compare',
        help='②③ 두 AST 비교 (rung·instruction 수준)',
    )
    p_compare.add_argument('ast_a', help='이전 AST JSON')
    p_compare.add_argument('ast_b', help='이후 AST JSON')
    p_compare.add_argument('--json-out', metavar='FILE',
                           help='diff 결과를 JSON 으로 저장')
    p_compare.add_argument('--verbose', action='store_true')
    p_compare.add_argument('--summary-only', action='store_true')
    p_compare.add_argument('--strict-addr', action='store_true',
                           help='%MW1000.0 vs %MW1000 을 다른 주소로 간주')
    p_compare.add_argument('--strict-opcode', action='store_true',
                           help='opcode_label 정규화 없이 엄격 비교')
    p_compare.add_argument('--ignore-il-fallback', action='store_true',
                           help='source=il_fallback instruction 변경을 무시')
    p_compare.set_defaults(func=cmd_compare)

    return parser


def cmd_extract(args: argparse.Namespace) -> int:
    """① pcapng 또는 JSON 에서 AST 추출."""
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"오류: 입력 파일 없음: {input_path}", file=sys.stderr)
        return 1

    try:
        builder = ProgramASTBuilder()
        builder.load_bytecode(str(input_path))
        ast = builder.build()
    except Exception as e:
        print(f"AST 생성 실패: {e}", file=sys.stderr)
        return 1

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open('w', encoding='utf-8') as f:
        json.dump(ast, f, indent=2, ensure_ascii=False)

    print(f"✓ AST 추출: {output_path}")
    if args.verbose:
        stats = ast.get('stats', {})
        print(f"  Programs: {stats.get('total_programs', '?')}")
        print(f"  Rungs:    {stats.get('total_rungs', '?')}")
        print(f"  Recall:   {stats.get('function_call_recall', 'N/A')}")
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    """②③ 두 AST 를 rung·instruction 수준에서 비교."""
    try:
        ast_a = load_ast(args.ast_a)
        ast_b = load_ast(args.ast_b)
    except (FileNotFoundError, ValueError) as e:
        print(f"AST 로드 실패: {e}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"JSON 파싱 실패: {e}", file=sys.stderr)
        return 1

    opts = DiffOptions(
        ignore_addr_bit=not args.strict_addr,
        strict_opcode=args.strict_opcode,
        ignore_il_fallback=args.ignore_il_fallback,
    )

    diff = diff_ast(ast_a, ast_b, opts=opts)
    print_ast_diff(diff, verbose=args.verbose, summary_only=args.summary_only)

    if args.json_out:
        write_json_diff(diff, args.json_out)
        print(f"\n✓ JSON 저장: {args.json_out}")

    return 0


def main() -> int:
    parser = make_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
