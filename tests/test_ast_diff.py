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
