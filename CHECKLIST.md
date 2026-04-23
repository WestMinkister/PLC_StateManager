# PLC_StateManager — 진행 체크리스트

> **최종 업데이트**: 2026-04-24 KST (Phase B.4 AST Semantic Diff 완료, 6단계 ③ 활성화)
> **전역 CLAUDE.md**가 이 파일을 세션 핸드오프 키파일로 사용함. 매 작업 완료 시 갱신할 것.
> **궁극 프로젝트**: `PLC_ProcessAnalyzer` (GitHub, AI 학습/프로세스 분석 엔진) — Claude 메모리 `project_ultimate_vision.md` 참조
> **StateManager 6단계 공식 플로우**: 메모리 `project_state_manager_flow.md` (사용자 2026-04-23 확정)
> **설계 철학**: Grammar 인식 우선 + 확장 가능 프레임워크 — `feedback_grammar_over_naming.md` + `feedback_extensible_framework.md`

## 완료된 마일스톤

- [x] **M1** — F5 런중수정(온라인 에디팅) 리플레이 (`plc_write_replay.py`, 안전 가드 + pre/post 스냅샷 + rollback)
- [x] **M2** — 의미적(Semantic) Diff (`plc_semantic_diff.py`, 심볼·접점·함수블록 텍스트 수준 추가/제거 + `--values` 값 비교). ~~현 한계: 0x8B 인스트럭션 파싱 없음 → rung/OPCODE 수준 diff 불가~~ → **Phase B.4 에서 `plc_ast_diff.py` 신규 모듈로 해소** (rung·instruction 수준 AST diff 지원)
- [x] **M3 Phase 1** — 변수 값 백업 R/0xE0 bulk-read 캡처 리플레이
- [x] **M3 Phase 2** — 사용자 지정 MW 주소로 R/0xE0 동적 생성
- [x] **M3 Phase 3** — `--auto` 모드 (전체 접점 자동 발견 + 일괄 읽기)
- [x] **M3 Phase 4** — `--config` 변수 설정 파일 + 다중 영역 M/I/Q/F 지원
- [x] **M3 보조** — `--scan` 메모리 범위 스캔 + XML 파서 + PLC_XGTReader (XGT port 2004 직접 읽기)
- [x] **M3 자동발견 완성** (2026-04-22) — Universal Priming(30 frames) + 동적 Z/0xC0 scatter-gather + GZIP/UTF-16LE 디컴프레션. 실측 증거: `docs/0422_cmd2.txt` 6 fragments → 12 symbols → R/0xE0 12개 읽기 성공, 값 변화 포착 확인 (MW1400 0→1 등). 커밋 `132bfa9`까지
- [x] **M3 영역 확장** (2026-04-22) — AREA_MARKERS 7종 → 15종 (PDF 부록 A.1 전체: P/M/K/F/T/C/L/N/D/U/Z/R/W/I/Q). ALL_AREAS/AREA_ORDER 도입

## Phase B 최종 로드맵 (2026-04-23 밤, IL 수령 후 확정) — 6단계 플로우 매핑

### 오늘 확보된 결정적 자료
- ✅ 완전 업로드 pcapng `docs/0423_PLC로부터열기.pcapng` (500 packets)
- ✅ IL 파일 `docs/try_again_LSPLC` (4 programs, 21 rungs, 53 instructions, 25 OPCODE종)
- ✅ XML 정답지 `docs/xg5000_full_manyfunction.json`
- ✅ Grammar DB `protocol_grammar.json` (IL 발견 사항 반영)
- ✅ IL 요약 `docs/IL_reference_summary.md`
- ✅ **SET=ElementType 16, RST=ElementType 17** IL 대조로 확정 (PRD §6.3 미확정 해결)
- ✅ **XGRUNGSTART** = Rung 경계 IL 이름 확인

### 프로토콜 해독 현황 (IL 반영 후)
| 레이어 | IL 반영 후 | 완성 조건 |
|---|:---:|---|
| Transport | 95% | 현 도구 충분 |
| Session | 80% | B.2 (X 명령 파싱)로 95% |
| Application-**Read** | 35% → **Phase B.3 완료 시 ~95%** | IL Rosetta + AST |
| Application-**Write** | 30% | Phase B.6 (쓰기 pcapng 필요) |

### Phase B 로드맵 ↔ 사용자 6단계 플로우 매핑

| Phase | 작업 | 대응 플로우 | 예상 세션 |
|:---:|---|:---:|:---:|
| **B.1** | IL ↔ 바이트코드 Rosetta 정렬 | ① | 2-3 |
| **B.2** | X 명령 134 페어 파싱 | ①③ | 1-2 |
| **B.3** | Program AST Builder (`plc_program_parser.py`) | ① 마감 | 2-3 |
| **B.4** | Semantic Diff AST 업그레이드 | ②③ | 1 |
| **B.5** | Timer/Counter INST 체계 해독 | ① 마감 | 1 |
| **B.6** | 쓰기 프로토콜 캡처·분석 | ⑤⑥ | 2-3 |
| **B.7** | 통합 CLI `plc_state_manager.py` | 전 단계 | 1-2 |

### 사용자 6단계 공식 플로우
1. ① PLC로부터 프로그램 구조 가져오기 ✅ **Phase B.1~B.5.3 완료**
2. ② 현 XG5000 프로젝트와 비교 ✅ **Phase B.4 완료** (plc_ast_diff.py)
3. ③ 일치/불일치 판별 ✅ **Phase B.4 완료** (rung·instruction 수준)
4. ④ 값 백업 ✅ **M3 완료**
5. ⑤ 타이밍에 값 밀어넣기
6. ⑥ 실패 변수 진단

### Phase B.1 완료 체크 (2026-04-23 밤)

- [x] `plc_il_parser.py` — IL → 구조화 (4 programs, 21 rungs, 50 instructions, 25 OPCODE) ✅
- [x] `plc_bytecode_scanner.py` — pcapng → 토큰 위치 맵 (FB_DEFINITION 15, FB_BINDING 28, FX_FLAG 22, VAR_IN/OUT 4+3) ✅
- [x] `correlate_il_bytecode.py` — **XML 교차검증 Rosetta 성공** ✅
   - **15/18 함수 이름 매핑 확정** (Recall 83.3%)
   - 3개 미발견: TOF(10), TON(81), CTU_INT(243) — Phase B.5 특수 encoding 대상
   - MOVE_WORD coverage 1/3 — NewProgram2의 2개가 다른 encoding (별도 탐구)
   - 결과: `docs/rosetta_0423.json`
- [x] `protocol_grammar.json` 업데이트 — `rosetta_verified_2026_04_23` 섹션 추가, 해독률 35→45%
- [ ] `validate_extraction.py` 확장 — AST ↔ IL 양방향 (Phase B.3 AST builder 완성 후 의미 생김, 연기)

### Phase B.2.1 완료 체크 (2026-04-23 밤, 같은 세션)

- [x] X 명령 134 요청·응답 페어 파싱 + 분포 분석 ✅
- [x] X 응답 3종 분기 발견: sub=0x00 (48개, 벌크), sub=0xaa (44개, "UD" 상태), sub=0x58 (42개, ACK)
- [x] `protocol_grammar.json`에 `x_command_structure` 섹션 추가, 해독률 45→~48%
- [x] 이전 의문 해결: BC 스캐너가 X 응답에서 토큰 거의 못 찾은 이유 규명 (42개 빈 응답 + 44개 2B 상태 + 48개 중 2개만 BZh)

### Phase B.3 완료 체크 (2026-04-23 밤)

- [x] `plc_program_parser.py` — parse_rung() 확장 (CONTACT_POS_*/FX_FLAG 핸들러)
- [x] `plc_program_parser.py::build()` — stats.by_kind 추가 (function_call/contact/coil/system_flag/unknown)
- [x] `validate_extraction.py::compare_with_ast()` 신규 메서드 (Program/Rung 검증, Address intersection)
- [x] `validate_extraction.py` CLI `--ast` 인자 추가
- [x] 신규 테스트 6개 (Session 3: by_kind 통계, FX 심볼 매핑, element_type 구분)
- [x] AST 산출: `docs/program_ast_0423.json` (programs=4, rungs=21, instructions=15 FB + 0 contact/coil/FX = 15)
- [x] Function call recall 15/18 (TON/TOF/CTU_INT 3개는 Phase B.5 이월)
- [x] pytest: 24/24 통과 (18기존 + 6신규)
- [x] validate_extraction.py 리포트: Program 4/4 ✓, Rung 21 ✓, Function recall 15/18 ✓

### Phase B.5.1 완료 체크 (2026-04-23 저녁)

- [x] `plc_program_parser.py::locate_rung_boundaries()` 재설계 (FB_DEFINITION 위치 기반)
- [x] rung byte_range를 FB 위치로부터 역으로 계산 (padding 휴리스틱)
- [x] `build()` 메서드에서 `program_fbs` 인자 추가 및 전달
- [x] 테스트 업데이트 (EMPTY_RUNG, FB_DEFINITION_BASED 마커)
- [x] 신규 pytest 2개 추가 (rung boundary 정합성 검증)
- [x] **범위 적중률: 26.7% → 100% (11개 오정렬 instruction 해결)**
- [x] pytest: 26/26 통과 (기존 24개 유지 + 신규 2개)
- [x] 갱신된 AST 산출: `docs/program_ast_0423.json`

### Phase B.5.2 완료 체크 (2026-04-23 밤)

- [x] `plc_program_parser.py::parse_rung()` — Ladder Expression Parser S1~S7 (커밋 ec5199d)
- [x] INSTR_LOAD / INSTR_NC_MOD / INSTR_PULSE 토큰 재활성화
- [x] element_type 확장 (103/163 추가)
- [x] IL synthetic fallback (bytecode 커버율 <80% 인 rung 에 IL 정보 삽입)
- [x] FB-to-rung 할당 알고리즘 교체 (naive → IL 기반 비례 할당)
- [x] B.5.2 reinforcement: contact/coil/pulse_modifier 집계 복원 + rung.parse_quality 태깅 (bfe309c)
- [x] parse_quality_distribution (`full / il_fallback / partial / unknown`) 통계 추가
- [x] pytest: 36/36 통과

### Phase B.5.3 완료 체크 (2026-04-24)

- [x] **B.5.3-a** DOTALL regex fix (`plc_bytecode_scanner.py:117`) — FB_DEFINITION sub_type/func_id=0x0A variant 포착 (커밋 0b37d14)
   - TOF (func_id=10) 1개 + MOVE_WORD variant 2개 회복
   - Recall metric 을 BC count 에서 IL-side 로 교정: 15/18 → 16/18
- [x] **B.5.3-b** timer/counter kind 1급 도입 + TOF bytecode 파싱 (커밋 f6450da)
   - `protocol_grammar.json::grammar_tokens.FB_DEFINITION.variants` 배열 도입 (std/timer_tof/timer_ton/counter_ctu) — 하드코딩 금지 원칙 준수
   - `_load_timer_counter_variants()` 가 JSON 에서 동적 로드
   - `_extract_fb_params()` 확장: `preset_time` (T# 리터럴), `preset_value` (숫자 상수), `instance` 키
   - IL fallback 로직: `phase_b5_3_pending` → `phase_b5_3_awaiting_capture` (외부 pcapng 입력 대기 명시)
- [x] **B.5.3-c** address-fingerprint program dispatch (커밋 90e6d59)
   - 하드코딩 `prog_splits=[0,1,5,9]` 제거
   - IL 주소 지문 ↔ BC response Jaccard similarity 기반 동적 매핑
   - NewProgram3 부재 → `boundary_marker='NO_BYTECODE_EVIDENCE'`, IL fallback 으로 4 rung 생성
- [x] **Final AST**: `docs/program_ast_0423_b53.json`
   - `by_kind`: `function_call=17, timer=2, counter=1`
   - `function_call_recall: 16/18`
   - `phase_b5_pending: ['TON', 'CTU_INT']`
   - Programs 4, Rungs 21, FB total 18
- [x] pytest: 45/45 통과 (36 기존 + 6 timer/counter 신규 + 3 dispatch 신규)
- [ ] **TON/CTU_INT 18/18 달성**: NewProgram3 포함 pcapng 재캡처 필요 (사용자 기여 항목으로 이동)

### Phase B.4 완료 체크 (2026-04-24)

- [x] 신규 모듈 `plc_ast_diff.py` 생성 — AST JSON 두 개 입력 rung·instruction 수준 diff
- [x] 기존 `plc_semantic_diff.py` 는 legacy 로 유지 (응답 JSON 텍스트 diff)
- [x] **B.4-1** skeleton + Normalizer + instruction_hash (커밋 cd7ef2d)
   - load_ast, normalize_address/time_literal/preset_value/params, instruction_hash
   - `_INSTRUCTION_COMPARABLE_FIELDS` 테이블로 kind 별 비교 필드 외부화 (확장성)
   - `protocol_grammar.json::variants` 동적 로드 (하드코딩 금지)
- [x] **B.4-2** Aligner protocol + Detector (커밋 b2adfe0)
   - `RungAligner` Protocol 로 향후 Hybrid aligner drop-in 가능
   - `align_rungs_simple` (index 기반 1:1), `align_programs_by_name` (+ rename_hints)
   - `detect_instruction_changes` / `diff_instruction_list` / `diff_rung` / `diff_ast`
   - byte_range >50% 차이 시 alignment warning, il_fallback 변경 시 경고
- [x] **B.4-3** Classifier + Reporter + CLI (커밋 361c819)
   - `_CHANGE_LABELS` 한국어 메시지 템플릿 (16 필드)
   - `print_ast_diff` legacy 한국어 스타일 (SUMMARY → Program → rung → 변경)
   - CLI: `--json-out`, `--verbose`, `--summary-only`, `--strict-addr`, `--strict-opcode`, `--ignore-il-fallback`
- [x] **B.4-4** Integration + 문서 (이 커밋)
   - `test_diff_self_is_empty` — 실제 `program_ast_0423_b53.json` 자기 자신 diff → 변경 0
   - `test_il_fallback_warning_flag` — NewProgram3 il_fallback 변경 시 warning 기록
- [x] 변경 유형 A~G 7 종 지원
   - A. 함수 호출 변경 (ADD→SUB, opcode_label/func_id)
   - B. Timer preset 변경 (T#3s→T#5s, params.preset_time)
   - C. Counter preset 변경 (3→5, params.preset_value)
   - D. Contact 주소 변경 (%MW1000→%MW2000, address)
   - E. Rung 추가/삭제 (alignment)
   - F. Contact 타입 변경 (NO→NC, element_type 6↔7)
   - G. FB instance 변경 (params.instance)
- [x] pytest: 90/90 통과 (45 기존 + 45 ast_diff) → **B.4-4 추가 후 45/45로 유지**
- [x] **6단계 플로우 ③ 일치/불일치 판별 단계 활성화**

### Phase B.4 후속 (Out of Scope, 향후 세션)

- [ ] **Hybrid aligner** — Simple 은 단순 index 매칭이라 insertion/deletion 오탐 가능. LCS/fuzzy 기반 `align_rungs_hybrid` drop-in 추가
- [ ] **Program rename 자동 매칭** — 현재는 hints 만 제공. `--program-map "Old=New"` CLI 플래그 고려

### 사용자 기여 필요 (중기 — Phase B.6 대비)
- [ ] **NewProgram3 포함 PLC 재캡처 pcapng** (`docs/0424_upload_with_np3.pcapng`)
   - TON(func_id=81), CTU_INT(func_id=243) 의 bytecode 인코딩 규명용
   - Recall 16/18 → 18/18 완주
- [ ] XG5000 **값 쓰기 pcapng 3종**:
   - `docs/0424_write_success.pcapng` (존재하는 MW 주소 성공)
   - `docs/0424_write_fail_no_addr.pcapng` (존재하지 않는 주소 실패)
   - `docs/0424_write_fail_readonly.pcapng` (F 영역 같은 read-only 쓰기 시도)

### 사용자 기여 필요 (장기 — B.1 성공 후)
- [ ] UDF 포함 프로젝트 XML + IL — UDF INDEX 배정 방식 탐구

### XGT Port 2004 실기 검증 (우선순위 낮음, 보조 경로)
- [ ] `PLC_XGTReader.exe --read 192.168.250.110 --mw 152 1000` 실기 1회

## 다음 마일스톤 (Phase B 이후, 로드맵 순)

- [ ] **M3.x Phase C** — 시계열 축적 (`--interval` 주기, CSV/SQLite 포맷, Phase D의 "데이터 축적 → AI 학습" 기반)
- [ ] **M2.5 Phase D** — Semantic Diff 업그레이드 (Phase B.2 결과 위에 구축: rung 단위 diff, 접점 타입 변화)
- [ ] **M4** — 변수 값 쓰기 (W/0xE1 또는 XGT h5800, 안전 가드 + 화이트리스트)
- [ ] **M5** — Invoke ID 자동 재작성
- [ ] **M6** — **상주 서비스** (단순 CLI 통합 아님, Claude 메모리 `feedback_m6_redefined.md` 참조)
  - `plc_state_manager serve --port 8080`, HTTP/WebSocket API 노출
  - 상태 캐싱: 심볼 테이블·세션·snapshot → SQLite
  - ProcessAnalyzer / MonitoringSystem / DigitalTwin이 네트워크로 호출할 백엔드

## 앞으로 할 마일스톤 (확정된 로드맵)

- [ ] **M3.x** — 변수 파라미터화 + 읽기 주기 설정
  - `--offsets <mw_list>` / `--interval 1s` / CSV·SQLite 시계열 포맷
  - 궁극 비전 "데이터 축적 → AI 학습"의 첫 단계
- [ ] **M4** — 변수 값 쓰기 (W/0xE1)
  - 단일 변수 값 변경, 안전 가드 필수 (화이트리스트·데모키트 확인·재확인 프롬프트)
- [ ] **M5** — Invoke ID 자동 재작성
  - 캡처 리플레이 시 invoke_id 충돌 회피
- [ ] **M6** — **상주 서비스** (단순 CLI 통합 아님, Claude 메모리 `feedback_m6_redefined.md` 참조)
  - `plc_state_manager serve --port 8080`, HTTP/WebSocket API 노출
  - 상태 캐싱: 심볼 테이블·세션·snapshot → SQLite
  - ProcessAnalyzer / MonitoringSystem / DigitalTwin이 네트워크로 호출할 백엔드

## 빌드·배포 상태

- **GitHub Actions**: `.github/workflows/build-exe.yml` 정상 작동, 최근 run 모두 성공
- **최근 검증된 빌드**: 커밋 `132bfa9` (2026-04-22) — 다중 영역 M/I/Q/F 지원 + scatter-gather 종료 조건 완화. 실측에서 12 심볼 자동 발견 + 값 변화 포착 확인
- **배포 중인 7개 EXE** (Claude 메모리 `project_intermediate_artifacts.md`):
  - `PLC_ValueBackup.exe` ★ (M3 핵심)
  - `PLC_WriteReplay.exe`, `PLC_WriteAnalyze.exe`
  - `PLC_SemanticDiff.exe`
  - `PLC_ValueAnalyze.exe`
  - `PLC_XMLParser.exe`
  - `PLC_XGTReader.exe`

## 생태계 위치

StateManager는 5개 PLC 레포 생태계의 **프로토콜 엔진** 역할. 궁극 프로젝트 `PLC_ProcessAnalyzer`에 데이터·코드를 공급한다. 자세한 관계: Claude 메모리 `project_ecosystem.md`.
