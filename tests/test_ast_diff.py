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
