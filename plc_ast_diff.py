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


SUPPORTED_GRAMMAR_VERSIONS = {
    "2026-04-23",
    "2026-04-26-il-free-with-program-names",
}
SUPPORTED_GRAMMAR_VERSION = "2026-04-26-il-free-with-program-names"

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
    if gv and gv not in SUPPORTED_GRAMMAR_VERSIONS:
        print(f"[경고] grammar_version 불일치: ast={gv}, supported={sorted(SUPPORTED_GRAMMAR_VERSIONS)}")
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


# ============================================================================
# Aligner Protocol + 구현체 (Commit 2)
# ============================================================================

class RungAligner(Protocol):
    """Rung 매칭 인터페이스. 향후 Hybrid aligner 교체 가능."""
    def __call__(
        self,
        rungs_a: List[Dict[str, Any]],
        rungs_b: List[Dict[str, Any]],
    ) -> List[Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]]:
        ...


def align_rungs_simple(
    rungs_a: List[Dict[str, Any]],
    rungs_b: List[Dict[str, Any]],
) -> List[Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]]:
    """rung index 기반 1:1 매칭. 길이 불일치 시 짧은 쪽을 None 으로 padding.

    예: len(a)=3, len(b)=5 → [(a0,b0), (a1,b1), (a2,b2), (None,b3), (None,b4)]
    """
    max_len = max(len(rungs_a), len(rungs_b))
    pairs = []
    for i in range(max_len):
        ra = rungs_a[i] if i < len(rungs_a) else None
        rb = rungs_b[i] if i < len(rungs_b) else None
        pairs.append((ra, rb))
    return pairs


def align_programs_by_name(
    progs_a: List[Dict[str, Any]],
    progs_b: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """프로그램 name 기반 1:1 매칭.

    반환:
      {
        'matched': [(prog_a, prog_b), ...],         # 양쪽 모두 있는 것
        'added_names': [name, ...],                  # b 에만 있음
        'removed_names': [name, ...],                # a 에만 있음
        'rename_hints': [(name_a, name_b, reason)],  # 구조 유사하지만 name 다름
      }

    rename_hints: a의 unmatched 중 b의 unmatched 와 (rung_count, fb_count) 둘 다 일치
    하는 쌍 발견 시. 경고 용도, 자동 rematch 하지 않음.
    """
    by_name_a = {p.get('name'): p for p in progs_a if p.get('name')}
    by_name_b = {p.get('name'): p for p in progs_b if p.get('name')}

    names_a = set(by_name_a.keys())
    names_b = set(by_name_b.keys())
    common = names_a & names_b
    added = sorted(names_b - names_a)
    removed = sorted(names_a - names_b)

    matched = []
    for name in sorted(common):
        matched.append((by_name_a[name], by_name_b[name]))

    # rename_hints: unmatched 쌍에서 구조 유사성 체크
    rename_hints = []
    for name_a in removed:
        pa = by_name_a[name_a]
        for name_b in added:
            pb = by_name_b[name_b]
            if (pa.get('rung_count') == pb.get('rung_count')
                    and pa.get('fb_count') == pb.get('fb_count')
                    and pa.get('rung_count') is not None):
                rename_hints.append((
                    name_a, name_b,
                    f"동일 구조 (rung={pa.get('rung_count')}, fb={pa.get('fb_count')})"
                ))

    return {
        'matched': matched,
        'added_names': added,
        'removed_names': removed,
        'rename_hints': rename_hints,
    }


# ============================================================================
# Detector 계층 (Commit 2)
# ============================================================================

def detect_instruction_changes(
    instr_a: Dict[str, Any],
    instr_b: Dict[str, Any],
    *, opts: DiffOptions,
) -> Dict[str, Tuple[Any, Any]]:
    """두 instruction 의 필드별 변경 탐지 (정규화 후).

    반환: {'opcode_label': (before, after), 'params.in': ([...],[...]), ...}
          변경 없으면 {}.

    기준: _INSTRUCTION_COMPARABLE_FIELDS[kind] 의 필드만 검사.
    params 는 normalize_params 적용 후 세부 서브키 비교 (params.in, params.out,
    params.preset_time, params.preset_value, params.instance).
    """
    kind_a = instr_a.get('kind', 'unknown')
    kind_b = instr_b.get('kind', 'unknown')
    changes: Dict[str, Tuple[Any, Any]] = {}

    if kind_a != kind_b:
        changes['kind'] = (kind_a, kind_b)

    # kind 가 달라도 공통 필드 비교는 진행 (유익한 정보)
    check_kind = kind_a if kind_a in _INSTRUCTION_COMPARABLE_FIELDS else kind_b
    fields = _INSTRUCTION_COMPARABLE_FIELDS.get(check_kind)
    if fields is None:
        # shallow fallback
        keys = (set(instr_a.keys()) | set(instr_b.keys())) - _INSTRUCTION_IGNORED_FIELDS
        for k in sorted(keys):
            if instr_a.get(k) != instr_b.get(k):
                changes[k] = (instr_a.get(k), instr_b.get(k))
        return changes

    for fname in fields:
        if fname == 'params':
            pa = normalize_params(instr_a.get('params', {}) or {}, ignore_bit=opts.ignore_addr_bit)
            pb = normalize_params(instr_b.get('params', {}) or {}, ignore_bit=opts.ignore_addr_bit)
            all_keys = set(pa.keys()) | set(pb.keys())
            for pkey in sorted(all_keys):
                if pa.get(pkey) != pb.get(pkey):
                    changes[f'params.{pkey}'] = (pa.get(pkey), pb.get(pkey))
        elif fname == 'address':
            va = normalize_address(instr_a.get('address'), ignore_bit=opts.ignore_addr_bit)
            vb = normalize_address(instr_b.get('address'), ignore_bit=opts.ignore_addr_bit)
            if va != vb:
                changes['address'] = (va, vb)
        else:
            va = instr_a.get(fname)
            vb = instr_b.get(fname)
            if va != vb:
                changes[fname] = (va, vb)

    return changes


def diff_instruction_list(
    list_a: List[Dict[str, Any]],
    list_b: List[Dict[str, Any]],
    *, opts: DiffOptions,
) -> Dict[str, Any]:
    """한 rung 내 instruction 리스트 비교.

    알고리즘:
      1. hash_a/hash_b 계산
      2. 양쪽 모두 사용 인덱스 플래그 관리
      3. hash 기반 매칭 우선 (순서 보존 목적으로 index 순회):
         - a[i] 와 b[i] hash 동일 → 변경 없음
         - 다름 → detect_instruction_changes
      4. 한쪽 길이 초과분 → added/removed

    반환:
      {
        'instructions_added': [instr_b_entries],
        'instructions_removed': [instr_a_entries],
        'instructions_changed': [{index, before, after, changes}],
      }
    """
    added: List[Dict[str, Any]] = []
    removed: List[Dict[str, Any]] = []
    changed: List[Dict[str, Any]] = []

    max_len = max(len(list_a), len(list_b))
    for i in range(max_len):
        ia = list_a[i] if i < len(list_a) else None
        ib = list_b[i] if i < len(list_b) else None
        if ia is None:
            added.append(ib)
            continue
        if ib is None:
            removed.append(ia)
            continue
        ha = instruction_hash(ia, ignore_bit=opts.ignore_addr_bit)
        hb = instruction_hash(ib, ignore_bit=opts.ignore_addr_bit)
        if ha == hb:
            continue  # 변경 없음
        cchanges = detect_instruction_changes(ia, ib, opts=opts)
        if cchanges:
            changed.append({
                'index': i,
                'before': ia,
                'after': ib,
                'changes': cchanges,
            })

    return {
        'instructions_added': added,
        'instructions_removed': removed,
        'instructions_changed': changed,
    }


def diff_rung(
    rung_a: Optional[Dict[str, Any]],
    rung_b: Optional[Dict[str, Any]],
    *, opts: DiffOptions,
) -> Dict[str, Any]:
    """단일 rung 쌍 비교. 한쪽이 None 이면 rung 전체 added/removed.

    반환:
      - rung_a 만 있음: {'rung_removed': True, 'rung': rung_a}
      - rung_b 만 있음: {'rung_added': True, 'rung': rung_b}
      - 둘 다 있음: diff_instruction_list 결과 + {'warnings': [...]}
    """
    if rung_a is None and rung_b is None:
        return {}
    if rung_a is None:
        return {'rung_added': True, 'rung': rung_b}
    if rung_b is None:
        return {'rung_removed': True, 'rung': rung_a}

    result = diff_instruction_list(
        rung_a.get('instructions', []),
        rung_b.get('instructions', []),
        opts=opts,
    )

    # byte_range 가 >50% 차이 시 warning
    warnings: List[str] = []
    br_a = rung_a.get('byte_range') or [0, 0]
    br_b = rung_b.get('byte_range') or [0, 0]
    len_a = max(br_a[1] - br_a[0], 1)
    len_b = max(br_b[1] - br_b[0], 1)
    ratio = abs(len_a - len_b) / max(len_a, len_b)
    if ratio > 0.5:
        warnings.append(
            f"byte_range 크기 차이 큼 ({len_a} vs {len_b} bytes, alignment 의심)"
        )

    # il_fallback 섞임 체크
    if opts.warn_il_fallback:
        for side, rung in (('a', rung_a), ('b', rung_b)):
            for instr in rung.get('instructions', []):
                if instr.get('source') == 'il_fallback':
                    # changed/added/removed 에 해당 instruction 이 있으면 경고
                    # (세부 매칭은 여기서 비용이 커서 간단히 "포함" 체크만)
                    if result['instructions_changed'] or result['instructions_added'] or result['instructions_removed']:
                        warnings.append(
                            f"il_fallback instruction 변경 (parse_quality={instr.get('parse_quality')})"
                        )
                    break

    result['warnings'] = warnings
    return result


def diff_ast(
    ast_a: Dict[str, Any],
    ast_b: Dict[str, Any],
    *, opts: Optional[DiffOptions] = None,
) -> Dict[str, Any]:
    """최상위 AST diff 진입점.

    Args:
        ast_a: baseline/before (예: XG5000 기준 AST)
        ast_b: target/after (예: pcapng 또는 Live PLC 에서 새로 추출한 AST)
    Result semantics:
        programs_added = ast_b - ast_a (after 에만 있음 = 새로 추가됨)
        programs_removed = ast_a - ast_b (before 에만 있음 = 제거됨)

    단계:
      1. align_programs_by_name
      2. 각 matched 프로그램 쌍에 대해 aligner (기본 align_rungs_simple) 로 rung 정렬
      3. 각 rung 쌍에 대해 diff_rung
      4. stats_diff 계산 (by_kind, parse_quality_distribution, function_call_recall)

    반환 구조:
      {
        'grammar_version_a': str,
        'grammar_version_b': str,
        'programs_added': [name, ...],
        'programs_removed': [name, ...],
        'programs_renamed': [(a, b, reason), ...],
        'programs_changed': {
          'NewProgram': {
            'rungs_added': [rung, ...],
            'rungs_removed': [rung, ...],
            'rungs_changed': {
              '0': {...diff_rung result...},
            },
          },
        },
        'stats_diff': {
          'by_kind': {kind: {'before': n, 'after': m, 'delta': m-n}, ...},
          'parse_quality_distribution': {...},
          'function_call_recall': {'before': '16/18', 'after': '16/18'},
        },
        'warnings': [global warnings],
      }
    """
    if opts is None:
        opts = DiffOptions()
    aligner: RungAligner = opts.aligner if opts.aligner else align_rungs_simple

    prog_align = align_programs_by_name(
        ast_a.get('programs', []), ast_b.get('programs', [])
    )

    programs_changed: Dict[str, Any] = {}
    all_warnings: List[str] = []

    for prog_a, prog_b in prog_align['matched']:
        rungs_a = prog_a.get('rungs', [])
        rungs_b = prog_b.get('rungs', [])
        rung_pairs = aligner(rungs_a, rungs_b)

        rungs_added = []
        rungs_removed = []
        rungs_changed: Dict[str, Any] = {}
        for idx, (ra, rb) in enumerate(rung_pairs):
            rd = diff_rung(ra, rb, opts=opts)
            if not rd:
                continue
            if rd.get('rung_added'):
                rungs_added.append(rd['rung'])
            elif rd.get('rung_removed'):
                rungs_removed.append(rd['rung'])
            else:
                has_change = (
                    rd.get('instructions_added')
                    or rd.get('instructions_removed')
                    or rd.get('instructions_changed')
                )
                if has_change:
                    rungs_changed[str(idx)] = rd
                    if rd.get('warnings'):
                        all_warnings.extend(
                            f"[{prog_a.get('name')}:rung{idx}] {w}"
                            for w in rd['warnings']
                        )

        if rungs_added or rungs_removed or rungs_changed:
            programs_changed[prog_a.get('name')] = {
                'rungs_added': rungs_added,
                'rungs_removed': rungs_removed,
                'rungs_changed': rungs_changed,
            }

    # stats_diff
    stats_a = ast_a.get('stats', {})
    stats_b = ast_b.get('stats', {})
    stats_diff: Dict[str, Any] = {}

    bka = stats_a.get('by_kind', {}) or {}
    bkb = stats_b.get('by_kind', {}) or {}
    by_kind_delta: Dict[str, Dict[str, int]] = {}
    for kind in sorted(set(bka.keys()) | set(bkb.keys())):
        before = bka.get(kind, 0)
        after = bkb.get(kind, 0)
        if before != after:
            by_kind_delta[kind] = {'before': before, 'after': after, 'delta': after - before}
    if by_kind_delta:
        stats_diff['by_kind'] = by_kind_delta

    pqa = stats_a.get('parse_quality_distribution', {}) or {}
    pqb = stats_b.get('parse_quality_distribution', {}) or {}
    pq_delta: Dict[str, Dict[str, int]] = {}
    for k in sorted(set(pqa.keys()) | set(pqb.keys())):
        before = pqa.get(k, 0)
        after = pqb.get(k, 0)
        if before != after:
            pq_delta[k] = {'before': before, 'after': after, 'delta': after - before}
    if pq_delta:
        stats_diff['parse_quality_distribution'] = pq_delta

    recall_a = stats_a.get('function_call_recall')
    recall_b = stats_b.get('function_call_recall')
    if recall_a != recall_b:
        stats_diff['function_call_recall'] = {'before': recall_a, 'after': recall_b}

    # rename_hints → warnings
    for (na, nb, reason) in prog_align['rename_hints']:
        all_warnings.append(f"rename 후보: {na} ↔ {nb} ({reason})")

    return {
        'grammar_version_a': ast_a.get('grammar_version'),
        'grammar_version_b': ast_b.get('grammar_version'),
        'programs_added': prog_align['added_names'],
        'programs_removed': prog_align['removed_names'],
        'programs_renamed': prog_align['rename_hints'],
        'programs_changed': programs_changed,
        'stats_diff': stats_diff,
        'warnings': all_warnings,
    }


# ============================================================================
# Classifier 계층 (Commit 3)
# ============================================================================

_CHANGE_LABELS: Dict[str, str] = {
    'kind':                '종류 (kind)',
    'opcode_label':        '함수/opcode',
    'func_id':             'func_id',
    'address':             '주소',
    'element_type':        'element_type',
    'contact_type':        'contact 타입',
    'coil_type':           'coil 타입',
    'fx_index':            'FX index',
    'symbol':              'symbol',
    'opcode':              'opcode',
    'operand_str':         'operand',
    'token_type':          'token_type',
    'params.in':           'params.in (입력)',
    'params.out':          'params.out (출력)',
    'params.preset_time':  'timer preset',
    'params.preset_value': 'counter preset',
    'params.instance':     'FB instance',
}


def classify_change(change_dict: Dict[str, Tuple[Any, Any]]) -> List[str]:
    """detect_instruction_changes() 결과 → 한국어 메시지 리스트.

    예:
      {'opcode_label': ('ADD','SUB')} → ['함수/opcode: ADD → SUB']
      {'params.preset_time': (3.0, 5.0)} → ['timer preset: 3.0 → 5.0']
      {'params.in': (['%MW1'],['%MW2'])} → ['params.in (입력): ["%MW1"] → ["%MW2"]']
    """
    messages: List[str] = []
    for field, (before, after) in change_dict.items():
        label = _CHANGE_LABELS.get(field, field)
        messages.append(f"{label}: {_format_value(before)} → {_format_value(after)}")
    return messages


def _format_value(v: Any) -> str:
    """값을 console 에 적합한 형태로 포맷."""
    if v is None:
        return 'None'
    if isinstance(v, list):
        return '[' + ', '.join(f'"{x}"' if isinstance(x, str) else str(x) for x in v) + ']'
    if isinstance(v, float):
        return f"{v:.6g}"
    return str(v)


def summarize_stats_diff(stats_diff: Dict[str, Any]) -> List[str]:
    """stats_diff dict → 한국어 요약 리스트.

    예: by_kind.function_call: 17 → 16 (-1)
    """
    lines: List[str] = []

    by_kind = stats_diff.get('by_kind', {})
    for kind, delta in sorted(by_kind.items()):
        before = delta['before']
        after = delta['after']
        diff = delta['delta']
        sign = '+' if diff > 0 else ''
        lines.append(f"by_kind.{kind}: {before} → {after} ({sign}{diff})")

    pq = stats_diff.get('parse_quality_distribution', {})
    for key, delta in sorted(pq.items()):
        before = delta['before']
        after = delta['after']
        diff = delta['delta']
        sign = '+' if diff > 0 else ''
        lines.append(f"parse_quality.{key}: {before} → {after} ({sign}{diff})")

    recall = stats_diff.get('function_call_recall')
    if recall:
        lines.append(f"recall: {recall['before']} → {recall['after']}")

    return lines


# ============================================================================
# Reporter 계층 (Commit 3)
# ============================================================================


def print_ast_diff(
    diff: Dict[str, Any],
    *,
    verbose: bool = False,
    summary_only: bool = False,
) -> None:
    """AST diff 결과를 console 에 한국어로 출력.

    형식 (plc_upload_decode.py::print_diff 스타일 계승):
      === AST SEMANTIC DIFF ===
      Grammar: 2026-04-23

      --- SUMMARY ---
      Programs 추가: 0
      Programs 제거: 0
      Programs 변경: 2 (NewProgram, NewProgram3)
      Rungs 변경: 3
      Instructions 변경: 5

      --- [NewProgram] ---
        rung[0]:
          [변경] 함수/opcode: ADD → SUB
          [변경] params.in (입력): [%MW1000] → [%MW2000]

      --- Stats Delta ---
      by_kind.function_call: 17 → 16 (-1)

      ✓ Changes detected
    """
    # 헤더
    print("=== AST SEMANTIC DIFF ===")
    gva = diff.get('grammar_version_a')
    gvb = diff.get('grammar_version_b')
    if gva or gvb:
        if gva == gvb:
            print(f"Grammar: {gva}")
        else:
            print(f"Grammar: {gva} ↔ {gvb} (불일치)")

    # 요약
    print()
    print("--- SUMMARY ---")
    programs_added = diff.get('programs_added', [])
    programs_removed = diff.get('programs_removed', [])
    programs_changed = diff.get('programs_changed', {})

    # 총계 계산
    total_rungs_added = 0
    total_rungs_removed = 0
    total_rungs_changed = 0
    total_instr_added = 0
    total_instr_removed = 0
    total_instr_changed = 0
    for pname, pdata in programs_changed.items():
        total_rungs_added += len(pdata.get('rungs_added', []))
        total_rungs_removed += len(pdata.get('rungs_removed', []))
        total_rungs_changed += len(pdata.get('rungs_changed', {}))
        for rkey, rdata in pdata.get('rungs_changed', {}).items():
            total_instr_added += len(rdata.get('instructions_added', []))
            total_instr_removed += len(rdata.get('instructions_removed', []))
            total_instr_changed += len(rdata.get('instructions_changed', []))

    print(f"Programs 추가: {len(programs_added)}")
    print(f"Programs 제거: {len(programs_removed)}")
    if programs_changed:
        print(f"Programs 변경: {len(programs_changed)} ({', '.join(programs_changed.keys())})")
    else:
        print(f"Programs 변경: 0")
    print(f"Rungs 추가: {total_rungs_added}")
    print(f"Rungs 제거: {total_rungs_removed}")
    print(f"Rungs 변경: {total_rungs_changed}")
    print(f"Instructions 추가: {total_instr_added}")
    print(f"Instructions 제거: {total_instr_removed}")
    print(f"Instructions 변경: {total_instr_changed}")

    if summary_only:
        stats_diff = diff.get('stats_diff', {})
        if stats_diff:
            print()
            print("--- Stats Delta ---")
            for line in summarize_stats_diff(stats_diff):
                print(line)
        warnings = diff.get('warnings', [])
        if warnings:
            print()
            print(f"⚠ Warnings: {len(warnings)}")
            if verbose:
                for w in warnings:
                    print(f"  - {w}")
        _print_final_status(diff)
        return

    # 프로그램 별 상세
    for pname, pdata in programs_changed.items():
        print()
        print(f"--- [{pname}] ---")

        # rungs_added
        for r in pdata.get('rungs_added', []):
            instr_count = len(r.get('instructions', []))
            print(f"  rung[{r.get('index', '?')}] 추가됨 ({instr_count} instructions)")

        # rungs_removed
        for r in pdata.get('rungs_removed', []):
            instr_count = len(r.get('instructions', []))
            print(f"  rung[{r.get('index', '?')}] 제거됨 ({instr_count} instructions)")

        # rungs_changed
        for rkey, rdata in pdata.get('rungs_changed', {}).items():
            print(f"  rung[{rkey}]:")
            for added in rdata.get('instructions_added', []):
                label = added.get('opcode_label') or added.get('kind', '?')
                print(f"    [추가] {label}")
            for removed in rdata.get('instructions_removed', []):
                label = removed.get('opcode_label') or removed.get('kind', '?')
                print(f"    [제거] {label}")
            for ch in rdata.get('instructions_changed', []):
                messages = classify_change(ch.get('changes', {}))
                for msg in messages:
                    warn = ''
                    if rdata.get('warnings'):
                        if any('il_fallback' in w for w in rdata.get('warnings', [])):
                            warn = '  ⚠ il_fallback comparison'
                    print(f"    [변경] {msg}{warn}")
            if verbose:
                for w in rdata.get('warnings', []):
                    print(f"    ⚠ {w}")

    # Stats Delta
    stats_diff = diff.get('stats_diff', {})
    if stats_diff:
        print()
        print("--- Stats Delta ---")
        for line in summarize_stats_diff(stats_diff):
            print(line)

    # Warnings
    warnings = diff.get('warnings', [])
    if warnings:
        print()
        print(f"⚠ Warnings: {len(warnings)}")
        for w in warnings:
            print(f"  - {w}")

    _print_final_status(diff)


def _print_final_status(diff: Dict[str, Any]) -> None:
    """diff 결과 요약 마지막 줄."""
    has_changes = (
        diff.get('programs_added')
        or diff.get('programs_removed')
        or diff.get('programs_changed')
        or diff.get('stats_diff')
    )
    print()
    if has_changes:
        print("✓ Changes detected")
    else:
        print("✓ 변경 없음 (두 AST 는 의미적으로 동일)")


def write_json_diff(diff: Dict[str, Any], path) -> None:
    """diff 결과를 JSON 파일로 저장.

    주의: programs_changed 내 'before'/'after' instruction dict 는 원본 그대로 포함
    (재현성 목적). 출력 크기 큼.
    """
    path = Path(path)
    with path.open('w', encoding='utf-8') as f:
        json.dump(diff, f, ensure_ascii=False, indent=2, default=str)


# ============================================================================
# CLI (Commit 3)
# ============================================================================


def main() -> int:
    """CLI 진입점. argparse 기반.

    반환: exit code (0=정상, 1=파일 오류, 2=인자 오류)
    """
    import argparse

    parser = argparse.ArgumentParser(
        description='AST 기반 의미적 diff (Phase B.4)',
        epilog="예: python plc_ast_diff.py docs/program_ast_A.json docs/program_ast_B.json",
    )
    parser.add_argument('ast_a', help='이전 AST JSON 경로')
    parser.add_argument('ast_b', help='이후 AST JSON 경로')
    parser.add_argument('--json-out', metavar='FILE', help='결과를 JSON 으로 저장')
    parser.add_argument('--verbose', action='store_true', help='경고 상세 출력')
    parser.add_argument('--summary-only', action='store_true', help='요약만 출력')
    parser.add_argument('--strict-addr', action='store_true',
                        help='주소 비트 오프셋 엄격 비교')
    parser.add_argument('--strict-opcode', action='store_true',
                        help='opcode_label 정규화 없이 엄격 비교')
    parser.add_argument('--ignore-il-fallback', action='store_true',
                        help='il_fallback instruction 변경 무시')

    args = parser.parse_args()

    try:
        ast_a = load_ast(args.ast_a)
        ast_b = load_ast(args.ast_b)
    except (FileNotFoundError, ValueError) as e:
        print(f"오류: {e}")
        return 1
    except json.JSONDecodeError as e:
        print(f"JSON 파싱 실패: {e}")
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
        print(f"\nJSON 저장: {args.json_out}")

    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
