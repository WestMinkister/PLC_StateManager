#!/usr/bin/env python3
"""Phase B.4 — AST 기반 의미적 diff.

PLC_StateManager 의 Program AST (plc_program_parser.py 산출물) 두 개를 입력받아
rung·instruction 수준까지 의미적 변경을 감지.

변경 유형:
  A. 함수 호출 변경 (ADD→SUB)
  B. Timer preset 변경 (T#3s→T#5s)
  C. Counter preset 변경 (3→5)
  D. Contact 주소 변경 (%MW1000→%MW2000)
  E. Rung 추가/삭제
  F. Contact 타입 변경 (NO→NC)
  G. FB instance 변경

Commit 1 범위: 로더 + 정규화 + instruction_hash.
"""

from __future__ import annotations

import json
import re
import hashlib
import functools
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, Tuple


SUPPORTED_GRAMMAR_VERSION = "2026-04-23"

_TIME_UNIT_TO_SECONDS = {
    'ms': 1e-3,
    's': 1.0,
    'm': 60.0,
    'h': 3600.0,
    'd': 86400.0,
}

_TIME_LITERAL_RE = re.compile(r'T#(\d+(?:\.\d+)?)(ms|s|m|h|d)$')

# kind 별 instruction_hash 비교 대상 필드
# 새 kind 추가 시 이 테이블에 1줄만 추가하면 확장 완료 (grammar_over_naming)
_INSTRUCTION_COMPARABLE_FIELDS: Dict[str, List[str]] = {
    'function_call': ['opcode_label', 'func_id', 'params'],
    'timer':         ['opcode_label', 'func_id', 'params'],
    'counter':       ['opcode_label', 'func_id', 'params'],
    'contact':       ['element_type', 'contact_type', 'address'],
    'coil':          ['coil_type', 'element_type', 'address'],
    'system_flag':   ['fx_index', 'symbol'],
    'logic_op':      ['opcode', 'operand_str'],
    'pulse_modifier':['opcode'],
    'unknown':       ['token_type', 'element_type', 'address'],
}

# 비교에서 제외하는 메타 필드 (source / quality / 위치 / raw)
_INSTRUCTION_IGNORED_FIELDS = {
    'byte_offset', 'raw_hex', 'stack_op', 'source', 'parse_quality',
    'fallback_id', 'phase_b5_3_awaiting_capture',
}

_GRAMMAR_JSON_PATH = Path(__file__).parent / 'protocol_grammar.json'


@dataclass
class DiffOptions:
    """AST diff 옵션 번들. CLI flag → DiffOptions 1회 변환 후 전파."""
    ignore_addr_bit: bool = True       # %MW1000.0 == %MW1000 (기본 True)
    strict_opcode: bool = False         # opcode_label 정규화 생략
    ignore_il_fallback: bool = False    # source=il_fallback 변경을 diff에서 제외
    warn_il_fallback: bool = True       # il_fallback 변경 감지 시 warnings 리스트 기록
    # aligner 는 Commit 2 에서 추가 예정 (미리 필드만 선언)
    aligner: Optional[Any] = None


def load_ast(path) -> Dict[str, Any]:
    """AST JSON 로드 + 스키마 버전/필수 키 검증.

    검증 실패 조건:
      - 파일 부재 → FileNotFoundError
      - JSON parse 실패 → json.JSONDecodeError
      - 'programs' 필드 없음 → ValueError

    grammar_version 이 SUPPORTED_GRAMMAR_VERSION 과 다르면 print 경고만 (raise 아님).
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"AST 파일 없음: {path}")
    with path.open(encoding='utf-8') as f:
        ast = json.load(f)
    if 'programs' not in ast:
        raise ValueError(f"유효한 AST 아님 ('programs' 키 없음): {path}")
    gv = ast.get('grammar_version')
    if gv and gv != SUPPORTED_GRAMMAR_VERSION:
        print(f"[경고] grammar_version 불일치: ast={gv}, supported={SUPPORTED_GRAMMAR_VERSION}")
    return ast


@functools.lru_cache(maxsize=1)
def _load_variants_map() -> Dict[int, Dict[str, Any]]:
    """protocol_grammar.json::FB_DEFINITION.variants → {func_id: {kind, opcode_label}}.

    파일 없거나 파싱 실패 시 빈 dict (lenient). 모듈 전역 1회 로드.
    """
    try:
        with _GRAMMAR_JSON_PATH.open(encoding='utf-8') as f:
            grammar = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    variants = grammar.get('grammar_tokens', {}).get('FB_DEFINITION', {}).get('variants', [])
    mapping = {}
    for v in variants:
        fid = v.get('func_id')
        if isinstance(fid, int):
            mapping[fid] = {
                'kind': v.get('kind'),
                'opcode_label': v.get('opcode_label'),
            }
    return mapping


def normalize_address(addr, *, ignore_bit: bool = True) -> str:
    """'%MW1000.3' → '%MW1000' (ignore_bit=True), else '%MW1000.3'.

    '%' 접두사 없으면 그대로 반환. None / 빈 문자열도 그대로.
    """
    if not addr or not isinstance(addr, str):
        return addr if isinstance(addr, str) else ''
    if not addr.startswith('%'):
        return addr
    if ignore_bit and '.' in addr:
        return addr.split('.', 1)[0]
    return addr


def normalize_time_literal(s) -> Optional[float]:
    """T# 리터럴 → 초 단위 float. 'T#3s' → 3.0, 'T#500ms' → 0.5.

    파싱 실패 / None 입력 → None.
    """
    if not s or not isinstance(s, str):
        return None
    m = _TIME_LITERAL_RE.fullmatch(s.strip())
    if not m:
        return None
    value, unit = m.groups()
    return float(value) * _TIME_UNIT_TO_SECONDS[unit]


def normalize_preset_value(v) -> Optional[int]:
    """'3' / 3 / '3.0' / 3.0 → 3. None → None. 실패 → None."""
    if v is None:
        return None
    try:
        return int(str(v).strip())
    except (ValueError, TypeError):
        try:
            return int(float(str(v).strip()))
        except (ValueError, TypeError):
            return None


def normalize_opcode_label(label, variants_map=None):
    """표준 opcode_label 로 정규화. AST 에 이미 opcode_label 이 있으면 그대로 (idempotent).

    variants_map 제공 시 func_id → opcode_label 매핑 활용 가능하지만,
    이 함수는 label 이 이미 정상일 때 그대로 반환하는 것이 기본.
    None → None.
    """
    if label is None:
        return None
    return str(label)


def normalize_params(params, *, ignore_bit: bool = True) -> Dict[str, Any]:
    """params dict 의 address 계열 필드 정규화. 원본 불변, 새 dict 반환.

    정규화 대상:
      - in / out 리스트 원소: normalize_address
      - preset_time: normalize_time_literal (float 초 단위)
      - preset_value: normalize_preset_value (int)
      - instance: 문자열 그대로 (정규화 없음)
    """
    if not isinstance(params, dict):
        return {}
    result = {}
    for key in ('in', 'out'):
        if key in params and isinstance(params[key], list):
            result[key] = [normalize_address(x, ignore_bit=ignore_bit) for x in params[key]]
    if 'preset_time' in params:
        result['preset_time'] = normalize_time_literal(params.get('preset_time'))
    if 'preset_value' in params:
        result['preset_value'] = normalize_preset_value(params.get('preset_value'))
    if 'instance' in params:
        result['instance'] = params.get('instance')
    return result


def instruction_hash(instr, *, ignore_bit: bool = True) -> str:
    """Instruction 정규화 키. source/byte_offset 등 메타 제외.

    kind 별 비교 필드는 _INSTRUCTION_COMPARABLE_FIELDS 테이블로 결정.
    알 수 없는 kind 는 instr dict 전체에서 _INSTRUCTION_IGNORED_FIELDS 제외 후 shallow 비교.

    반환: sha1 hex digest 앞 16자리 (str).
    """
    if not isinstance(instr, dict):
        return hashlib.sha1(repr(instr).encode()).hexdigest()[:16]
    kind = instr.get('kind', 'unknown')
    fields = _INSTRUCTION_COMPARABLE_FIELDS.get(kind)

    if fields is None:
        # unknown kind → shallow diff (확장성: crash 없이 보수적 비교)
        canonical = {
            k: v for k, v in instr.items()
            if k not in _INSTRUCTION_IGNORED_FIELDS
        }
    else:
        canonical = {'kind': kind}
        for fname in fields:
            if fname == 'params':
                canonical['params'] = normalize_params(
                    instr.get('params', {}), ignore_bit=ignore_bit
                )
            elif fname == 'address':
                canonical['address'] = normalize_address(
                    instr.get('address'), ignore_bit=ignore_bit
                )
            elif fname == 'operand_str':
                # logic_op 의 operand_str 은 주소 포함 가능. 간단히 그대로 비교
                canonical['operand_str'] = instr.get('operand_str')
            else:
                canonical[fname] = instr.get(fname)

    blob = json.dumps(canonical, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha1(blob.encode('utf-8')).hexdigest()[:16]
