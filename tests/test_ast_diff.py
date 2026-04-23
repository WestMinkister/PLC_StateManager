#!/usr/bin/env python3
"""Phase B.4: AST diff 단위 테스트 (Commit 1 — Normalizer + instruction_hash)."""

import sys
import os
import pytest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from plc_ast_diff import (
    normalize_address,
    normalize_time_literal,
    normalize_preset_value,
    normalize_params,
    instruction_hash,
    load_ast,
    DiffOptions,
    align_rungs_simple,
    align_programs_by_name,
    detect_instruction_changes,
    diff_instruction_list,
    diff_rung,
    diff_ast,
    classify_change,
    summarize_stats_diff,
    print_ast_diff,
    write_json_diff,
)


class TestNormalizer:
    """Commit 1 — Normalizer 함수 단위 테스트."""

    def test_normalize_address_bit_ignored(self):
        """기본 (ignore_bit=True) 에서 비트 오프셋 제거."""
        assert normalize_address('%MW1000.0') == '%MW1000'
        assert normalize_address('%MW1000.3') == '%MW1000'
        assert normalize_address('%MW1000') == '%MW1000'  # idempotent

    def test_normalize_address_strict(self):
        """ignore_bit=False (strict) 는 비트 오프셋 유지."""
        assert normalize_address('%MW1000.0', ignore_bit=False) == '%MW1000.0'
        assert normalize_address('%IW5000.12', ignore_bit=False) == '%IW5000.12'

    def test_normalize_address_no_prefix(self):
        """접두사 없는 주소는 그대로."""
        assert normalize_address('MW1000') == 'MW1000'
        assert normalize_address('') == ''
        assert normalize_address(None) == ''

    def test_normalize_time_literal_variants(self):
        """T# 리터럴 여러 단위 → 초 단위 float."""
        assert normalize_time_literal('T#3s') == 3.0
        assert normalize_time_literal('T#3000ms') == 3.0
        assert normalize_time_literal('T#0.05s') == pytest.approx(0.05)
        assert normalize_time_literal('T#1h') == 3600.0
        assert normalize_time_literal('T#1m') == 60.0
        assert normalize_time_literal('T#1d') == 86400.0

    def test_normalize_time_literal_invalid(self):
        """유효하지 않은 T# 리터럴은 None."""
        assert normalize_time_literal('') is None
        assert normalize_time_literal(None) is None
        assert normalize_time_literal('invalid') is None
        assert normalize_time_literal('T#xyz') is None

    def test_normalize_preset_value_int(self):
        """정수 계열 preset 정규화."""
        assert normalize_preset_value(3) == 3
        assert normalize_preset_value('3') == 3
        assert normalize_preset_value('3.0') == 3
        assert normalize_preset_value(3.0) == 3
        assert normalize_preset_value(3.9) == 3  # 반내림

    def test_normalize_preset_value_invalid(self):
        """유효하지 않은 preset은 None."""
        assert normalize_preset_value(None) is None
        assert normalize_preset_value('xyz') is None
        assert normalize_preset_value('') is None

    def test_normalize_params_all_fields(self):
        """params 전체 필드 정규화."""
        params_in = {
            'in': ['%MW1000.0', '%MW1002.5'],
            'out': ['%MW2000.0'],
            'preset_time': 'T#5s',
            'preset_value': '10',
            'instance': 'Timer_1',
        }
        result = normalize_params(params_in)
        assert result['in'] == ['%MW1000', '%MW1002']
        assert result['out'] == ['%MW2000']
        assert result['preset_time'] == 5.0
        assert result['preset_value'] == 10
        assert result['instance'] == 'Timer_1'

    def test_normalize_params_empty(self):
        """빈 params는 빈 dict."""
        assert normalize_params({}) == {}
        assert normalize_params(None) == {}


class TestInstructionHash:
    """Commit 1 — instruction_hash 단위 테스트."""

    def test_instruction_hash_stable_across_source_fields(self):
        """source/byte_offset/raw_hex/parse_quality 만 다른 instruction 은 동일 hash."""
        instr_a = {
            'kind': 'function_call',
            'opcode_label': 'ADD',
            'func_id': 71,
            'params': {'in': ['%MW1000', '%MW1002'], 'out': ['%MW1002']},
            'byte_offset': 519,
            'source': 'bytecode',
            'parse_quality': 'full',
            'raw_hex': 'deadbeef',
        }
        instr_b = dict(instr_a)
        instr_b['byte_offset'] = 99999
        instr_b['source'] = 'il_fallback'
        instr_b['parse_quality'] = 'il_fallback'
        instr_b['raw_hex'] = 'aabbccdd'
        assert instruction_hash(instr_a) == instruction_hash(instr_b)

    def test_instruction_hash_differs_on_opcode_change(self):
        """opcode_label 변경 시 hash 달라져야 함."""
        instr_a = {'kind': 'function_call', 'opcode_label': 'ADD', 'func_id': 71, 'params': {}}
        instr_b = {'kind': 'function_call', 'opcode_label': 'SUB', 'func_id': 127, 'params': {}}
        assert instruction_hash(instr_a) != instruction_hash(instr_b)

    def test_instruction_hash_timer_preset_change(self):
        """Timer preset 변경 시 hash 달라져야 함."""
        timer_a = {
            'kind': 'timer',
            'opcode_label': 'TOF',
            'func_id': 10,
            'params': {'preset_time': 'T#3s'},
        }
        timer_b = dict(timer_a)
        timer_b['params'] = {'preset_time': 'T#5s'}
        assert instruction_hash(timer_a) != instruction_hash(timer_b)

    def test_instruction_hash_address_normalize(self):
        """주소 정규화 후 hash는 동일해야 함."""
        instr_a = {
            'kind': 'contact',
            'element_type': 6,
            'contact_type': 'NO',
            'address': '%MW1000.0',
        }
        instr_b = dict(instr_a)
        instr_b['address'] = '%MW1000'
        assert instruction_hash(instr_a) == instruction_hash(instr_b)

    def test_instruction_hash_address_change(self):
        """다른 주소는 hash도 달라져야 함."""
        instr_a = {
            'kind': 'contact',
            'element_type': 6,
            'contact_type': 'NO',
            'address': '%MW1000',
        }
        instr_b = dict(instr_a)
        instr_b['address'] = '%MW2000'
        assert instruction_hash(instr_a) != instruction_hash(instr_b)

    def test_instruction_hash_non_dict(self):
        """비dict 입력은 graceful하게 처리."""
        h1 = instruction_hash(None)
        h2 = instruction_hash('string')
        h3 = instruction_hash(123)
        assert isinstance(h1, str)
        assert isinstance(h2, str)
        assert isinstance(h3, str)


class TestLoadAst:
    """AST 로더 단위 테스트."""

    def test_load_real_ast_json(self):
        """실제 B.5.3 AST 로드 성공."""
        ast_path = Path(__file__).parent.parent / 'docs' / 'program_ast_0423_b53.json'
        if not ast_path.exists():
            pytest.skip(f'AST 파일 없음: {ast_path}')
        ast = load_ast(ast_path)
        assert 'programs' in ast
        assert len(ast['programs']) == 4

    def test_load_ast_file_not_found(self):
        """존재하지 않는 파일 → FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            load_ast('/nonexistent/path.json')

    def test_load_ast_invalid_json(self, tmp_path):
        """유효하지 않은 JSON → JSONDecodeError."""
        bad_file = tmp_path / 'bad.json'
        bad_file.write_text('not json {')
        with pytest.raises(Exception):  # JSONDecodeError 또는 다른 파싱 에러
            load_ast(bad_file)

    def test_load_ast_missing_programs_key(self, tmp_path):
        """'programs' 키 없음 → ValueError."""
        bad_file = tmp_path / 'no_programs.json'
        bad_file.write_text('{"other": "data"}')
        with pytest.raises(ValueError, match="'programs'"):
            load_ast(bad_file)


# ============================================================================
# Commit 2 테스트: Aligner, Detector, diff 로직
# ============================================================================

def _make_instr(kind, **fields):
    """테스트용 instruction 생성 헬퍼."""
    base = {'kind': kind}
    base.update(fields)
    return base


def _make_rung(index, instrs, byte_range=None):
    """테스트용 rung 생성 헬퍼."""
    return {
        'index': index,
        'byte_range': byte_range or [0, 100],
        'boundary_marker': 'TEST',
        'instructions': instrs,
    }


def _make_program(index, name, rungs, fb_count=0):
    """테스트용 program 생성 헬퍼."""
    return {
        'index': index,
        'name': name,
        'rungs': rungs,
        'rung_count': len(rungs),
        'fb_count': fb_count,
        'byte_range': [0, 1000],
        'boundary_marker': 'TEST',
    }


def _make_ast(programs, by_kind=None):
    """테스트용 AST 생성 헬퍼."""
    return {
        'grammar_version': '2026-04-23',
        'programs': programs,
        'stats': {
            'total_programs': len(programs),
            'total_rungs': sum(p['rung_count'] for p in programs),
            'by_kind': by_kind or {},
        },
    }


class TestChangeDetection:
    """변경 유형 A~G 7개 테스트."""

    def test_diff_function_call_opcode_change(self):
        """A. ADD → SUB 감지."""
        ia = _make_instr('function_call', opcode_label='ADD', func_id=71, params={'in': ['%MW1'], 'out': ['%MW2']})
        ib = _make_instr('function_call', opcode_label='SUB', func_id=127, params={'in': ['%MW1'], 'out': ['%MW2']})
        changes = detect_instruction_changes(ia, ib, opts=DiffOptions())
        assert 'opcode_label' in changes
        assert changes['opcode_label'] == ('ADD', 'SUB')
        assert 'func_id' in changes

    def test_diff_timer_preset_change(self):
        """B. T#3s → T#5s 감지."""
        ia = _make_instr('timer', opcode_label='TOF', func_id=10, params={'in': [], 'out': [], 'preset_time': 'T#3s', 'preset_value': None})
        ib = _make_instr('timer', opcode_label='TOF', func_id=10, params={'in': [], 'out': [], 'preset_time': 'T#5s', 'preset_value': None})
        changes = detect_instruction_changes(ia, ib, opts=DiffOptions())
        assert 'params.preset_time' in changes
        # normalize_time_literal 이 float 로 변환
        assert changes['params.preset_time'] == (3.0, 5.0)

    def test_diff_counter_preset_change(self):
        """C. 3 → 5 감지."""
        ia = _make_instr('counter', opcode_label='CTU_INT', func_id=243, params={'in': [], 'out': [], 'preset_value': 3})
        ib = _make_instr('counter', opcode_label='CTU_INT', func_id=243, params={'in': [], 'out': [], 'preset_value': 5})
        changes = detect_instruction_changes(ia, ib, opts=DiffOptions())
        assert 'params.preset_value' in changes
        assert changes['params.preset_value'] == (3, 5)

    def test_diff_contact_address_change(self):
        """D. Contact address %MW1000 → %MW2000 감지."""
        ia = _make_instr('contact', element_type=6, contact_type='NO', address='%MW1000')
        ib = _make_instr('contact', element_type=6, contact_type='NO', address='%MW2000')
        changes = detect_instruction_changes(ia, ib, opts=DiffOptions())
        assert 'address' in changes
        assert changes['address'] == ('%MW1000', '%MW2000')

    def test_diff_rung_added(self):
        """E. rung 추가 감지."""
        ast_a = _make_ast([_make_program(0, 'P0', [_make_rung(0, [])])])
        ast_b = _make_ast([_make_program(0, 'P0', [_make_rung(0, []), _make_rung(1, [])])])
        diff = diff_ast(ast_a, ast_b)
        assert 'P0' in diff['programs_changed']
        assert len(diff['programs_changed']['P0']['rungs_added']) == 1

    def test_diff_contact_type_change(self):
        """F. Contact NO → NC (element_type 6 → 7) 감지."""
        ia = _make_instr('contact', element_type=6, contact_type='NO', address='%MW1000')
        ib = _make_instr('contact', element_type=7, contact_type='NC', address='%MW1000')
        changes = detect_instruction_changes(ia, ib, opts=DiffOptions())
        assert 'element_type' in changes
        assert 'contact_type' in changes

    def test_diff_fb_instance_change(self):
        """G. FB instance INST1 → INST2 감지."""
        ia = _make_instr('timer', opcode_label='TOF', func_id=10, params={'in': [], 'out': [], 'instance': 'INST1'})
        ib = _make_instr('timer', opcode_label='TOF', func_id=10, params={'in': [], 'out': [], 'instance': 'INST2'})
        changes = detect_instruction_changes(ia, ib, opts=DiffOptions())
        assert 'params.instance' in changes
        assert changes['params.instance'] == ('INST1', 'INST2')


class TestAligner:
    """Rung Aligner 단위 테스트."""

    def test_align_rungs_simple_equal_length(self):
        """같은 길이의 rung 리스트 정렬."""
        ra = [_make_rung(0, []), _make_rung(1, [])]
        rb = [_make_rung(0, []), _make_rung(1, [])]
        pairs = align_rungs_simple(ra, rb)
        assert len(pairs) == 2
        assert all(p[0] is not None and p[1] is not None for p in pairs)

    def test_align_rungs_simple_left_longer(self):
        """왼쪽이 더 긴 경우."""
        ra = [_make_rung(0, []), _make_rung(1, []), _make_rung(2, [])]
        rb = [_make_rung(0, [])]
        pairs = align_rungs_simple(ra, rb)
        assert len(pairs) == 3
        assert pairs[1][1] is None  # b 는 None
        assert pairs[2][1] is None

    def test_align_rungs_simple_right_longer(self):
        """오른쪽이 더 긴 경우."""
        ra = [_make_rung(0, [])]
        rb = [_make_rung(0, []), _make_rung(1, [])]
        pairs = align_rungs_simple(ra, rb)
        assert len(pairs) == 2
        assert pairs[1][0] is None  # a 는 None


class TestProgramAlignment:
    """프로그램 name 기반 alignment 단위 테스트."""

    def test_program_alignment_by_name(self):
        """이름 기반 프로그램 매칭."""
        progs_a = [_make_program(0, 'A', []), _make_program(1, 'B', [])]
        progs_b = [_make_program(0, 'A', []), _make_program(1, 'B', [])]
        result = align_programs_by_name(progs_a, progs_b)
        assert len(result['matched']) == 2
        assert result['added_names'] == []
        assert result['removed_names'] == []

    def test_program_added_removed(self):
        """프로그램 추가/삭제 감지."""
        progs_a = [_make_program(0, 'A', []), _make_program(1, 'B', [])]
        progs_b = [_make_program(0, 'A', []), _make_program(1, 'C', [])]
        result = align_programs_by_name(progs_a, progs_b)
        assert len(result['matched']) == 1  # A
        assert result['added_names'] == ['C']
        assert result['removed_names'] == ['B']


# ============================================================================
# Commit 3 테스트: Classifier + Reporter + CLI
# ============================================================================


class TestReporter:
    """Classifier + Reporter 단위 테스트."""

    def test_classify_change_opcode(self):
        """함수 변경 메시지 포맷."""
        changes = {'opcode_label': ('ADD', 'SUB')}
        msgs = classify_change(changes)
        assert len(msgs) == 1
        assert 'ADD' in msgs[0] and 'SUB' in msgs[0]
        assert '함수/opcode' in msgs[0]

    def test_classify_change_preset_time(self):
        """Timer preset 메시지 포맷."""
        changes = {'params.preset_time': (3.0, 5.0)}
        msgs = classify_change(changes)
        assert 'timer preset' in msgs[0]
        assert '3' in msgs[0] and '5' in msgs[0]

    def test_classify_change_address(self):
        """Contact address 메시지 포맷."""
        changes = {'address': ('%MW1000', '%MW2000')}
        msgs = classify_change(changes)
        assert '주소' in msgs[0]
        assert '%MW1000' in msgs[0] and '%MW2000' in msgs[0]

    def test_classify_change_params_in_list(self):
        """params.in 리스트 포맷."""
        changes = {'params.in': (['%MW1'], ['%MW2'])}
        msgs = classify_change(changes)
        assert 'params.in (입력)' in msgs[0]
        assert '%MW1' in msgs[0] and '%MW2' in msgs[0]

    def test_classify_change_multiple_fields(self):
        """여러 필드 동시 변경."""
        changes = {
            'opcode_label': ('ADD', 'SUB'),
            'func_id': (71, 127),
            'address': ('%MW1000', '%MW2000'),
        }
        msgs = classify_change(changes)
        assert len(msgs) == 3
        assert any('함수/opcode' in m for m in msgs)
        assert any('func_id' in m for m in msgs)
        assert any('주소' in m for m in msgs)

    def test_summarize_stats_diff(self):
        """stats_diff → 한국어 요약 리스트."""
        stats_diff = {
            'by_kind': {
                'function_call': {'before': 17, 'after': 16, 'delta': -1},
                'timer': {'before': 2, 'after': 3, 'delta': 1},
            },
            'function_call_recall': {'before': '16/18', 'after': '17/18'},
        }
        lines = summarize_stats_diff(stats_diff)
        assert any('function_call' in l and '-1' in l for l in lines)
        assert any('timer' in l and '+1' in l for l in lines)
        assert any('recall' in l for l in lines)

    def test_summarize_stats_diff_parse_quality(self):
        """parse_quality_distribution 요약."""
        stats_diff = {
            'parse_quality_distribution': {
                'full': {'before': 100, 'after': 102, 'delta': 2},
                'il_fallback': {'before': 5, 'after': 3, 'delta': -2},
            },
        }
        lines = summarize_stats_diff(stats_diff)
        assert any('parse_quality.full' in l and '+2' in l for l in lines)
        assert any('parse_quality.il_fallback' in l and '-2' in l for l in lines)

    def test_print_ast_diff_no_changes(self, capsys):
        """변경 없는 경우 출력."""
        diff = {
            'grammar_version_a': '2026-04-23',
            'grammar_version_b': '2026-04-23',
            'programs_added': [],
            'programs_removed': [],
            'programs_changed': {},
            'stats_diff': {},
            'warnings': [],
        }
        print_ast_diff(diff)
        captured = capsys.readouterr()
        assert '변경 없음' in captured.out
        assert '의미적으로 동일' in captured.out

    def test_print_ast_diff_with_changes(self, capsys):
        """변경 있는 경우 출력."""
        diff = {
            'grammar_version_a': '2026-04-23',
            'grammar_version_b': '2026-04-23',
            'programs_added': [],
            'programs_removed': [],
            'programs_changed': {
                'P0': {
                    'rungs_added': [],
                    'rungs_removed': [],
                    'rungs_changed': {
                        '0': {
                            'instructions_added': [],
                            'instructions_removed': [],
                            'instructions_changed': [{
                                'index': 0,
                                'before': {'kind': 'function_call', 'opcode_label': 'ADD'},
                                'after': {'kind': 'function_call', 'opcode_label': 'SUB'},
                                'changes': {'opcode_label': ('ADD', 'SUB')},
                            }],
                            'warnings': [],
                        }
                    },
                }
            },
            'stats_diff': {},
            'warnings': [],
        }
        print_ast_diff(diff)
        captured = capsys.readouterr()
        assert '변경 있음' in captured.out or 'Changes detected' in captured.out
        assert '[P0]' in captured.out
        assert 'rung[0]' in captured.out

    def test_print_ast_diff_summary_only(self, capsys):
        """--summary-only 플래그."""
        diff = {
            'grammar_version_a': '2026-04-23',
            'grammar_version_b': '2026-04-23',
            'programs_added': [],
            'programs_removed': [],
            'programs_changed': {
                'P0': {
                    'rungs_added': [],
                    'rungs_removed': [],
                    'rungs_changed': {'0': {'instructions_changed': []}},
                }
            },
            'stats_diff': {
                'by_kind': {'function_call': {'before': 10, 'after': 11, 'delta': 1}}
            },
            'warnings': [],
        }
        print_ast_diff(diff, summary_only=True)
        captured = capsys.readouterr()
        assert 'SUMMARY' in captured.out
        assert 'Stats Delta' in captured.out
        # rung 상세는 없어야 함
        assert 'rung[0]' not in captured.out


class TestCLI:
    """CLI + write_json_diff 통합 테스트."""

    def test_write_json_diff(self, tmp_path):
        """JSON 파일로 저장."""
        diff = {
            'grammar_version_a': '2026-04-23',
            'grammar_version_b': '2026-04-23',
            'programs_added': [],
            'programs_removed': [],
            'programs_changed': {},
            'stats_diff': {},
            'warnings': [],
        }
        out_path = tmp_path / 'diff.json'
        write_json_diff(diff, out_path)
        assert out_path.exists()
        import json as _json
        result = _json.loads(out_path.read_text(encoding='utf-8'))
        assert result['grammar_version_a'] == '2026-04-23'

    def test_cli_json_out(self, tmp_path):
        """tmp_path 에 두 AST 저장 후 CLI 실행, --json-out 으로 결과 저장 확인."""
        import json as _json
        import subprocess

        ast = {
            'grammar_version': '2026-04-23',
            'programs': [{
                'index': 0, 'name': 'P0', 'rung_count': 1, 'fb_count': 0,
                'byte_range': [0, 100], 'boundary_marker': 'TEST',
                'rungs': [{
                    'index': 0, 'byte_range': [0, 100], 'boundary_marker': 'TEST',
                    'instructions': [{
                        'kind': 'function_call', 'opcode_label': 'ADD',
                        'func_id': 71, 'params': {'in': [], 'out': []},
                    }],
                }],
            }],
            'stats': {'by_kind': {'function_call': 1}, 'total_programs': 1, 'total_rungs': 1},
        }

        a_path = tmp_path / 'a.json'
        b_path = tmp_path / 'b.json'
        out_path = tmp_path / 'diff.json'

        a_path.write_text(_json.dumps(ast), encoding='utf-8')
        # b 에서 ADD → SUB 로 변경
        ast_b = _json.loads(_json.dumps(ast))
        ast_b['programs'][0]['rungs'][0]['instructions'][0]['opcode_label'] = 'SUB'
        ast_b['programs'][0]['rungs'][0]['instructions'][0]['func_id'] = 127
        b_path.write_text(_json.dumps(ast_b), encoding='utf-8')

        # CLI 실행
        script_path = Path(__file__).parent.parent / 'plc_ast_diff.py'
        result = subprocess.run(
            ['python', str(script_path), str(a_path), str(b_path),
             '--json-out', str(out_path)],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0, f"CLI failed: {result.stderr}"
        assert out_path.exists(), f"--json-out 파일 없음"

        # JSON 내용 검증
        diff_result = _json.loads(out_path.read_text(encoding='utf-8'))
        assert 'P0' in diff_result['programs_changed']
        rung0 = diff_result['programs_changed']['P0']['rungs_changed']['0']
        assert len(rung0['instructions_changed']) == 1
        changes = rung0['instructions_changed'][0]['changes']
        assert 'opcode_label' in changes


class TestIntegration:
    """B.4 Integration — 실제 AST JSON 과 il_fallback 경고 시나리오."""

    def test_diff_self_is_empty(self):
        """실제 B.5.3 AST 를 자기 자신과 diff → 변경 없음."""
        ast_path = Path(__file__).parent.parent / 'docs' / 'program_ast_0423_b53.json'
        if not ast_path.exists():
            pytest.skip(f'AST 파일 없음: {ast_path}')

        ast = load_ast(ast_path)
        diff = diff_ast(ast, ast)

        # 프로그램 수준 변경 없음
        assert diff['programs_added'] == []
        assert diff['programs_removed'] == []
        assert diff['programs_renamed'] == []
        assert diff['programs_changed'] == {}
        # stats 수준 변경 없음
        assert diff['stats_diff'] == {}

    def test_il_fallback_warning_flag(self):
        """source=il_fallback instruction 의 변경 시 warnings 에 il_fallback 관련 기록."""
        ast_path = Path(__file__).parent.parent / 'docs' / 'program_ast_0423_b53.json'
        if not ast_path.exists():
            pytest.skip(f'AST 파일 없음: {ast_path}')

        import copy as _copy
        ast_a = load_ast(ast_path)
        ast_b = _copy.deepcopy(ast_a)

        # NewProgram3 의 il_fallback instruction 중 timer preset 변경 주입
        # NewProgram3 = boundary_marker='NO_BYTECODE_EVIDENCE', 모든 rung 이 il_fallback
        mutated = False
        for prog in ast_b['programs']:
            if prog.get('boundary_marker') != 'NO_BYTECODE_EVIDENCE':
                continue
            for rung in prog.get('rungs', []):
                for instr in rung.get('instructions', []):
                    if instr.get('source') == 'il_fallback' and instr.get('kind') == 'timer':
                        # preset_time 변경
                        params = instr.setdefault('params', {})
                        params['preset_time'] = 'T#99s'
                        mutated = True
                        break
                if mutated:
                    break
            if mutated:
                break

        if not mutated:
            pytest.skip('NewProgram3 에 il_fallback timer instruction 없음')

        diff = diff_ast(ast_a, ast_b, opts=DiffOptions(warn_il_fallback=True))

        # 변경 감지됨
        assert diff['programs_changed'], "il_fallback timer 변경이 감지되어야 함"
        # warnings 리스트에 il_fallback 관련 메시지 포함
        all_warn_text = '\n'.join(diff.get('warnings', []))
        assert 'il_fallback' in all_warn_text, \
            f"warnings 에 il_fallback 표시 필요. 실제: {diff.get('warnings')}"
