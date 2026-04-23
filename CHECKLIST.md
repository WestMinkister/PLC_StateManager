# PLC_StateManager — 진행 체크리스트

> **최종 업데이트**: 2026-04-23 밤 KST (IL 수령, Phase B 최종 로드맵 확정)
> **전역 CLAUDE.md**가 이 파일을 세션 핸드오프 키파일로 사용함. 매 작업 완료 시 갱신할 것.
> **궁극 프로젝트**: `PLC_ProcessAnalyzer` (GitHub, AI 학습/프로세스 분석 엔진) — Claude 메모리 `project_ultimate_vision.md` 참조
> **StateManager 6단계 공식 플로우**: 메모리 `project_state_manager_flow.md` (사용자 2026-04-23 확정)
> **설계 철학**: Grammar 인식 우선 + 확장 가능 프레임워크 — `feedback_grammar_over_naming.md` + `feedback_extensible_framework.md`

## 완료된 마일스톤

- [x] **M1** — F5 런중수정(온라인 에디팅) 리플레이 (`plc_write_replay.py`, 안전 가드 + pre/post 스냅샷 + rollback)
- [x] **M2** — 의미적(Semantic) Diff (`plc_semantic_diff.py`, 심볼·접점·함수블록 텍스트 수준 추가/제거 + `--values` 값 비교). **현 한계: 0x8B 인스트럭션 파싱 없음 → rung/OPCODE 수준 diff 불가 (PRD §12)**
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
1. ① PLC로부터 프로그램 구조 가져오기
2. ② 현 XG5000 프로젝트와 비교
3. ③ 일치/불일치 판별
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

### 사용자 기여 필요 (중기 — Phase B.6 대비)
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
