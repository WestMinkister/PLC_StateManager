"""Phase B.7 — 통합 CLI 테스트.

subprocess 기반 CLI end-to-end 테스트. docs/program_ast_0423_b53.json 재사용.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest


SCRIPT_PATH = Path(__file__).parent.parent / 'plc_state_manager.py'
DOCS_DIR = Path(__file__).parent.parent / 'docs'
AST_SAMPLE = DOCS_DIR / 'program_ast_0423_b53.json'
PCAPNG_SAMPLE = DOCS_DIR / '0423_PLC로부터열기.pcapng'


def _run(*args, timeout: int = 30):
    """plc_state_manager.py 를 subprocess 로 실행."""
    cmd = [sys.executable, str(SCRIPT_PATH), *args]
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout,
    )


class TestCLIStructure:
    """CLI 기본 구조 테스트."""

    def test_help_exit_code_zero(self):
        """--help 는 exit 0."""
        result = _run('--help')
        assert result.returncode == 0
        assert 'PLC_StateManager' in result.stdout or '6단계' in result.stdout

    def test_no_command_prints_help(self):
        """인자 없이 실행 시 help 출력 + exit 1."""
        result = _run()
        assert result.returncode == 1
        assert 'sub-command' in result.stdout or 'usage' in result.stdout.lower()


class TestExtractCommand:
    """① extract sub-command 테스트."""

    def test_extract_from_real_pcapng(self, tmp_path):
        """실제 pcapng 으로 AST 생성."""
        if not PCAPNG_SAMPLE.exists():
            pytest.skip(f'pcapng 없음: {PCAPNG_SAMPLE}')
        out_path = tmp_path / 'ast.json'
        result = _run('extract', str(PCAPNG_SAMPLE), '-o', str(out_path))
        assert result.returncode == 0, f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}"
        assert out_path.exists()
        # AST JSON 구조 확인
        ast = json.loads(out_path.read_text(encoding='utf-8'))
        assert 'programs' in ast
        assert len(ast['programs']) == 4

    def test_extract_nonexistent_file(self, tmp_path):
        """없는 파일 → exit 1."""
        out_path = tmp_path / 'ast.json'
        result = _run('extract', str(tmp_path / 'nonexistent.pcapng'),
                      '-o', str(out_path))
        assert result.returncode == 1
        assert '없음' in result.stderr or 'not found' in result.stderr.lower() \
               or 'Error' in result.stderr


class TestCompareCommand:
    """②③ compare sub-command 테스트."""

    def test_compare_self_is_empty(self):
        """AST 를 자기 자신과 비교 → 변경 없음."""
        if not AST_SAMPLE.exists():
            pytest.skip(f'AST 샘플 없음: {AST_SAMPLE}')
        result = _run('compare', str(AST_SAMPLE), str(AST_SAMPLE))
        assert result.returncode == 0
        assert '변경 없음' in result.stdout or 'Changes' not in result.stdout

    def test_compare_json_out(self, tmp_path):
        """--json-out 파일 생성 확인."""
        if not AST_SAMPLE.exists():
            pytest.skip(f'AST 샘플 없음: {AST_SAMPLE}')
        diff_path = tmp_path / 'diff.json'
        result = _run('compare', str(AST_SAMPLE), str(AST_SAMPLE),
                      '--json-out', str(diff_path))
        assert result.returncode == 0
        assert diff_path.exists()
        diff = json.loads(diff_path.read_text(encoding='utf-8'))
        assert 'programs_added' in diff
        assert 'programs_changed' in diff
        # self-diff 라 변경 없어야 함
        assert diff['programs_changed'] == {}

    def test_compare_invalid_ast(self, tmp_path):
        """잘못된 JSON → exit 1."""
        bad_path = tmp_path / 'bad.json'
        bad_path.write_text('this is not json', encoding='utf-8')
        result = _run('compare', str(bad_path), str(bad_path))
        assert result.returncode == 1
