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
import subprocess
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

  # ④ PLC 값 백업 (plc_value_backup 래핑)
  python plc_state_manager.py backup --read 192.168.1.100 --auto --out values.json

  # ①②③④ 한 번에 (flow orchestrator)
  python plc_state_manager.py flow \\
      --pcapng docs/0423.pcapng \\
      --xg5000-ast docs/program_ast_0423_b53.json \\
      --output-dir results/
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
    p_extract.add_argument('--no-il', action='store_true',
                           help='IL ground truth 없이 pcapng 자체에서만 파싱. '
                                'PLC 구조가 docs/il_parsed_0423.json 과 다를 때 권장.')
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

    # ④ backup
    p_backup = subparsers.add_parser(
        'backup',
        help='④ PLC 변수 값 백업 (plc_value_backup 래핑)',
    )
    p_backup.add_argument('--read', type=str, metavar='IP',
                          help='실기 PLC IP (live read)')
    p_backup.add_argument('--config', type=str, metavar='JSON',
                          help='변수 설정 JSON')
    p_backup.add_argument('--mw', nargs='+', type=int, metavar='ADDR',
                          help='MW 주소 목록')
    p_backup.add_argument('--auto', action='store_true',
                          help='자동 발견 모드')
    p_backup.add_argument('--out', type=str, default='snapshots/values.json',
                          help='출력 파일 (기본: snapshots/values.json)')
    # --port / --samples: default=None 으로 두어 사용자 명시 시에만 plc_value_backup 에
    # 전달. 미전달 시 plc_value_backup 자체 기본값 (port=2002 확장, samples=1) 사용.
    # 이전 버그: default=2004 를 명시 전달해 확장 frame 이 공식 port 2004 로 가 timeout.
    p_backup.add_argument('--port', type=int, default=None,
                          help='PLC 포트 (미지정 시 plc_value_backup 기본값 2002 사용)')
    p_backup.add_argument('--samples', type=int, default=None,
                          help='샘플 개수 (미지정 시 1)')
    p_backup.add_argument('--dry-run', action='store_true',
                          help='실제 연결 없이 frame 검증만')
    p_backup.set_defaults(func=cmd_backup)

    # flow orchestrator
    p_flow = subparsers.add_parser(
        'flow',
        help='①②③④ 순차 실행 (full workflow)',
    )
    p_flow.add_argument('--pcapng', required=True,
                        help='입력 pcapng (① 필수)')
    p_flow.add_argument('--xg5000-ast', dest='xg5000_ast',
                        help='참조 AST JSON (②③ 비교용, 없으면 skip)')
    p_flow.add_argument('--read', type=str, metavar='IP',
                        help='실기 PLC IP (④ 값 백업, 없으면 skip)')
    p_flow.add_argument('--output-dir', dest='output_dir', default='results',
                        help='결과 디렉토리 (기본: results)')
    p_flow.add_argument('--verbose', action='store_true')
    p_flow.set_defaults(func=cmd_flow)

    return parser


def cmd_extract(args: argparse.Namespace) -> int:
    """① pcapng 또는 JSON 에서 AST 추출."""
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"오류: 입력 파일 없음: {input_path}", file=sys.stderr)
        return 1

    try:
        use_il = not getattr(args, 'no_il', False)
        builder = ProgramASTBuilder(use_il=use_il)
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
    print(f"  모드: {ast.get('mode', '?')}")
    if args.verbose:
        stats = ast.get('stats', {})
        print(f"  Programs: {stats.get('total_programs', '?')}")
        print(f"  Rungs:    {stats.get('total_rungs', '?')}")
        print(f"  Recall:   {stats.get('function_call_recall', 'N/A')}")
    for w in ast.get('warnings', []):
        print(f"  [주의] {w}")
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


def _build_backup_argv(args: argparse.Namespace) -> list:
    """args → plc_value_backup.main() 이 기대하는 sys.argv 형태로 변환."""
    argv = []
    if args.read:     argv.extend(['--read', args.read])
    if args.config:   argv.extend(['--config', args.config])
    if args.mw:       argv.extend(['--mw'] + [str(x) for x in args.mw])
    if args.auto:     argv.append('--auto')
    if args.out:      argv.extend(['--out', args.out])
    if args.port:     argv.extend(['--port', str(args.port)])
    if args.samples:  argv.extend(['--samples', str(args.samples)])
    if args.dry_run:  argv.append('--dry-run')
    return argv


def _invoke_backup(argv: list) -> int:
    """plc_value_backup 실행. 3단계 전략:

    1) Frozen EXE + 인접 PLC_ValueBackup.exe 존재 → exe subprocess (단독 실행과 동일)
    2) Frozen EXE + 인접 exe 없음 → import fallback (timing/context 주의)
    3) 개발 환경 → plc_value_backup.py subprocess

    방식 1 이 가장 안정적. 사용자는 artifact 다운로드 시 두 EXE 를 같은 폴더에 두면 됨.
    """
    if getattr(sys, 'frozen', False):
        # Frozen 환경 — 우선 인접 EXE 찾기
        exe_dir = Path(sys.executable).parent
        backup_exe = exe_dir / 'PLC_ValueBackup.exe'
        if backup_exe.exists():
            # 방식 1: 인접 EXE subprocess — 단독 실행과 100% 동일 환경
            print(f"[진단] PLC_ValueBackup.exe 호출: {backup_exe}")
            print(f"[진단] 전달 인자: {argv}")
            result = subprocess.run([str(backup_exe)] + argv)
            return result.returncode

        # 방식 2: import fallback (PLC_ValueBackup.exe 가 없을 때)
        print("⚠ PLC_ValueBackup.exe 가 같은 폴더에 없음. import fallback 사용.", file=sys.stderr)
        print("  (권장: PLC_ValueBackup.exe 를 PLC_StateManager.exe 와 같은 폴더에 두세요)", file=sys.stderr)
        import plc_value_backup
        orig_argv = sys.argv
        sys.argv = [orig_argv[0]] + argv
        try:
            rc = plc_value_backup.main()
            return rc if isinstance(rc, int) else 0
        except SystemExit as e:
            return e.code if isinstance(e.code, int) else 0
        finally:
            sys.argv = orig_argv

    # 방식 3: 개발 환경 — plc_value_backup.py subprocess
    script_path = Path(__file__).parent / 'plc_value_backup.py'
    if not script_path.exists():
        print(f"오류: plc_value_backup.py 없음: {script_path}", file=sys.stderr)
        return 1
    cmd = [sys.executable, str(script_path)] + argv
    result = subprocess.run(cmd)
    return result.returncode


def cmd_backup(args: argparse.Namespace) -> int:
    """④ plc_value_backup 호출 (frozen: import, dev: subprocess)."""
    return _invoke_backup(_build_backup_argv(args))


def cmd_flow(args: argparse.Namespace) -> int:
    """①②③④ 순차 실행 orchestrator.

    동작:
      ① --pcapng 로부터 AST 추출 → output_dir/ast_protocol.json (필수)
      ②③ --xg5000-ast 제공 시 diff 수행 → output_dir/diff.json
      ④ --read IP 제공 시 값 백업 → output_dir/values.json

    각 단계는 실패해도 다음 단계 시도 (부분 성공 허용).
    """
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # ① Extract AST
    print("\n=== ① AST 추출 ===")
    pcapng_path = Path(args.pcapng)
    if not pcapng_path.exists():
        print(f"✗ pcapng 없음: {pcapng_path}", file=sys.stderr)
        return 1

    try:
        builder = ProgramASTBuilder()
        builder.load_bytecode(str(pcapng_path))
        ast_prot = builder.build()
    except Exception as e:
        print(f"✗ AST 생성 실패: {e}", file=sys.stderr)
        return 1

    ast_prot_path = out_dir / 'ast_protocol.json'
    with ast_prot_path.open('w', encoding='utf-8') as f:
        json.dump(ast_prot, f, indent=2, ensure_ascii=False)
    print(f"✓ {ast_prot_path}")
    if args.verbose:
        stats = ast_prot.get('stats', {})
        print(f"  Programs: {stats.get('total_programs', '?')}")
        print(f"  Rungs:    {stats.get('total_rungs', '?')}")

    # ②③ Compare (optional)
    if args.xg5000_ast:
        print("\n=== ②③ AST 비교 ===")
        try:
            ast_ref = load_ast(args.xg5000_ast)
            diff = diff_ast(ast_prot, ast_ref, opts=DiffOptions())
            print_ast_diff(diff, verbose=args.verbose, summary_only=not args.verbose)
            diff_path = out_dir / 'diff.json'
            write_json_diff(diff, str(diff_path))
            print(f"✓ {diff_path}")
        except Exception as e:
            print(f"⚠ 비교 실패 (다음 단계 진행): {e}", file=sys.stderr)
    else:
        print("\n=== ②③ Skipped (--xg5000-ast 없음) ===")

    # ④ Backup (optional)
    if args.read:
        print("\n=== ④ 값 백업 ===")
        backup_out = out_dir / 'values.json'
        rc = _invoke_backup(['--read', args.read, '--auto', '--out', str(backup_out)])
        if rc == 0:
            print(f"✓ {backup_out}")
        else:
            print(f"⚠ 백업 실패 (exit={rc})")
    else:
        print("\n=== ④ Skipped (--read 없음) ===")

    print(f"\n✓ Flow 완료: {out_dir}")
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
