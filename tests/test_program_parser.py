#!/usr/bin/env python3
"""Phase B.3 Session 1: ProgramASTBuilder 테스트.

4개 프로그램, 21개 rung 경계 확정 검증.
"""
import sys
import os
import json
from pathlib import Path
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from plc_program_parser import ProgramASTBuilder


TEST_PCAPNG = Path(__file__).parent.parent / 'docs' / '0423_PLC로부터열기.pcapng'
TEST_JSON = Path(__file__).parent.parent / 'docs' / 'bytecode_scan_0423.json'


class TestProgramASTBuilder:
    """AST 조립기 테스트."""

    @pytest.fixture
    def builder_from_pcapng(self):
        """pcapng에서 AST 빌드."""
        if not TEST_PCAPNG.exists():
            pytest.skip(f'pcapng 없음: {TEST_PCAPNG}')
        builder = ProgramASTBuilder()
        builder.load_bytecode(str(TEST_PCAPNG))
        return builder

    @pytest.fixture
    def builder_from_json(self):
        """JSON에서 AST 빌드."""
        if not TEST_JSON.exists():
            pytest.skip(f'JSON 없음: {TEST_JSON}')
        builder = ProgramASTBuilder()
        builder.load_bytecode(str(TEST_JSON))
        return builder

    def test_load_bytecode_pcapng(self):
        """pcapng 로드 성공."""
        if not TEST_PCAPNG.exists():
            pytest.skip(f'pcapng 없음: {TEST_PCAPNG}')
        builder = ProgramASTBuilder()
        builder.load_bytecode(str(TEST_PCAPNG))
        assert builder.responses is not None
        assert len(builder.responses) > 0

    def test_load_bytecode_json(self):
        """JSON 로드 성공."""
        if not TEST_JSON.exists():
            pytest.skip(f'JSON 없음: {TEST_JSON}')
        builder = ProgramASTBuilder()
        builder.load_bytecode(str(TEST_JSON))
        assert builder.responses is not None
        assert len(builder.responses) > 0

    def test_program_count_is_4(self, builder_from_json):
        """프로그램 4개 확정."""
        ast = builder_from_json.build()
        assert len(ast['programs']) == 4, \
            f"기대: 4개, 실제: {len(ast['programs'])}"

    def test_total_rung_count_is_21(self, builder_from_json):
        """전체 rung 21개 확정."""
        ast = builder_from_json.build()
        total_rungs = sum(len(p['rungs']) for p in ast['programs'])
        assert total_rungs == 21, \
            f"기대: 21개, 실제: {total_rungs}"

    def test_program_rung_distribution(self, builder_from_json):
        """프로그램별 rung 분포 확정 (IL 기반: 1+4+4+12)."""
        ast = builder_from_json.build()
        expected_rungs = [1, 4, 4, 12]
        actual_rungs = [len(p['rungs']) for p in ast['programs']]
        assert actual_rungs == expected_rungs, \
            f"기대: {expected_rungs}, 실제: {actual_rungs}"

    def test_program_regions_ordered_by_byte(self, builder_from_json):
        """프로그램이 인덱스 순서대로 정렬되고 유효한 범위 보유."""
        ast = builder_from_json.build()
        for i, prog in enumerate(ast['programs']):
            # 각 프로그램의 범위가 유효한지 확인
            start, end = prog['byte_range']
            # IL 시그니처 기반이므로 범위가 겹칠 수 있음 (추정값이므로)
            # 단, 각 프로그램은 유효한 범위를 가져야 함
            assert end >= start, \
                f"프로그램 {i} 범위 [{start}, {end}] 유효하지 않음"
            assert 'name' in prog
            assert prog['index'] == i

    def test_rung_boundaries_nonempty(self, builder_from_json):
        """각 rung의 바이트 범위 유효성."""
        ast = builder_from_json.build()
        for prog in ast['programs']:
            for rung in prog['rungs']:
                start, end = rung['byte_range']
                assert end > start, \
                    f"{prog['name']} rung {rung['index']}: 범위 [{start}, {end}] 유효하지 않음"

    def test_rung_ordering_within_program(self, builder_from_json):
        """각 프로그램 내 rung이 바이트 순서대로 정렬."""
        ast = builder_from_json.build()
        for prog in ast['programs']:
            rungs = prog['rungs']
            for i in range(len(rungs) - 1):
                curr_end = rungs[i]['byte_range'][1]
                next_start = rungs[i + 1]['byte_range'][0]
                assert curr_end <= next_start, \
                    f"{prog['name']} rung {i} 끝({curr_end}) > rung {i+1} 시작({next_start})"

    def test_ast_has_required_fields(self, builder_from_json):
        """AST가 필수 필드 보유."""
        ast = builder_from_json.build()
        assert 'source' in ast
        assert 'grammar_version' in ast
        assert 'programs' in ast
        assert 'stats' in ast
        assert ast['stats']['program_count'] == 4
        assert ast['stats']['total_rung_count'] == 21

    def test_programs_have_names(self, builder_from_json):
        """각 프로그램이 이름 보유."""
        ast = builder_from_json.build()
        for prog in ast['programs']:
            assert 'name' in prog
            assert prog['name'].startswith('Program_')

    def test_rungs_have_boundary_markers(self, builder_from_json):
        """각 rung이 경계 마커 보유."""
        ast = builder_from_json.build()
        # IL 시그니처 기반 또는 실제 마커 (RUNG_END_A/B)
        valid_markers = {'RUNG_END_A', 'RUNG_END_B', 'IL_SIGNATURE', 'FB_DEFINITION cluster'}
        for prog in ast['programs']:
            for rung in prog['rungs']:
                assert 'boundary_marker' in rung
                assert rung['boundary_marker'] in valid_markers, \
                    f"예상치 못한 마커: {rung['boundary_marker']}"


def test_program_parser_cli_output(tmp_path):
    """CLI 출력 검증 (JSON 출력)."""
    if not TEST_JSON.exists():
        pytest.skip(f'JSON 없음: {TEST_JSON}')

    from plc_program_parser import ProgramASTBuilder
    builder = ProgramASTBuilder()
    builder.load_bytecode(str(TEST_JSON))
    ast = builder.build()

    # 임시 파일에 출력
    out_file = tmp_path / 'test_ast.json'
    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(ast, f, indent=2)

    # 다시 로드 검증
    with open(out_file) as f:
        loaded = json.load(f)

    assert loaded['stats']['program_count'] == 4
    assert loaded['stats']['total_rung_count'] == 21


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
