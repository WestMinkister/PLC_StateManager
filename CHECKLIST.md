# PLC_StateManager — 진행 체크리스트

> **최종 업데이트**: 2026-04-23 KST
> **전역 CLAUDE.md**가 이 파일을 세션 핸드오프 키파일로 사용함. 매 작업 완료 시 갱신할 것.
> **궁극 프로젝트**: `PLC_ProcessAnalyzer` (GitHub, AI 학습/프로세스 분석 엔진) — Claude 메모리 `project_ultimate_vision.md` 참조
> **설계 철학**: 확장 가능 프레임워크 우선, 미봉책 금지 — 메모리 `feedback_extensible_framework.md` 참조

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

## 현재 블로커 — Phase B.0 (정답지 인프라) 완료 대기, B.1 사용자 기여 필요

### Phase B 근본 재설계 (2026-04-23)
"단순 regex 확장"이 아니라 **함수블록 OPCODE 자동 매핑 프레임워크**로 전환. 사용자 기여(XML+pcapng) → 도구가 자동으로 `function_opcodes.json` DB 성장. 지금 모르는 함수도 미래 자동 수용.

- [x] **B.0** 정답지 인프라 (2026-04-23 커밋 대기):
  - `plc_xml_parser.py --full` — XG5000 XML → 함수 INDEX + Rung + 시스템플래그 + ElementType 완전 추출
  - `plc_value_backup.py --debug-dump` — 실기 때 fragment/GZIP/priming 응답 전체 저장
  - `validate_extraction.py` — 프로토콜 추출 vs XML 정답지 대조
  - `function_opcodes.json` — 매핑 DB 씨앗 (ADD·MOVE·TON·CTU_INT 4종)
- [ ] **B.0 사용자 액션 대기** — 최신 EXE + `--debug-dump --auto` 실기 1회 → `snapshots/dump_*` 디렉토리 공유
- [ ] **B.1** `plc_bytecode_scanner.py` — Z/0x82 응답에서 OPCODE 후보 자동 추출 (다음 세션)
- [ ] **B.2** `correlate_xml_bytecode.py` — XML 함수 리스트 ↔ 바이트코드 후보 상관관계 매퍼
- [ ] **B.3** 사용자 기여 파이프라인 — `contribute_function.py <project>.xml <capture>.pcapng`
- [ ] **B.4+** 함수 DB 순차 확장: SUB/MUL/DIV/OR/AND/NOT/RS/SR/TOF/TP/CTD/CTUD ...
- [ ] **B.5** Rung 경계 + 접점 타입 변화 감지 (Level 3-4)

### XGT Port 2004 실기 검증 (우선순위 낮음, 보조 경로)
- [ ] `PLC_XGTReader.exe --read 192.168.250.110 --mw 152 1000` 실기 1회
  - 성공 시 M4 쓰기를 XGT로 단순화 가능 (PDF §5.2 공개 스펙)
  - 실패 시 LGIS-GLOFA 유지 (영향 없음, 현 기능 그대로)

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
