# PLC_StateManager — 진행 체크리스트

> **최종 업데이트**: 2026-04-22 KST
> **전역 CLAUDE.md**가 이 파일을 세션 핸드오프 키파일로 사용함. 매 작업 완료 시 갱신할 것.
> **궁극 프로젝트**: `PLC_ProcessAnalyzer` (GitHub, AI 학습/프로세스 분석 엔진) — Claude 메모리 `project_ultimate_vision.md` 참조

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

## 현재 블로커 (다음 세션 — Phase B: Stale symbol 근본 해결)

- [ ] **Phase B: 로직 파싱 Level 1 — 실사용 변수 추출**
  - **문제**: 0422 실측에서 `%MW1400, %MW2400, %MW2401` 같은 심볼이 GZIP 워크스페이스 XML에서 발견됨. 일부는 실사용(MW1400 값 변화 포착됨), 일부는 과거 잔존 추정. 현 scatter-gather는 "프로젝트 history 전체"를 반영해 **실사용/stale 구분 불가** (PRD §8.3 "7 캡처 동일, 프로그램 변경 무관" 명시)
  - **해결 경로**: Z/0x82 또는 0x8B 인스트럭션 바이트코드에서 LE16 주소 스캔 → MW×2 역산으로 실사용 주소 집합 추출 → GZIP 심볼 셋과 교집합 → stale 제거 (PRD §7.2 기반, 🟢 확정)
  - **사용자 합의**: "예, XG5000에서 원하는 프로그램 만들고 캡처 가능" — Level 4(접점 타입)까지 추가 캡처 수집 가능
  - **수정 파일 예상**: `plc_upload_decode.py` (0x8B 파서 신규), `plc_value_backup.py` (scatter-gather 결과와 교집합 로직 추가)

## 다음 마일스톤 (확정된 로드맵, 우선순위 순)

- [ ] **Phase B** — Stale symbol 근본 해결 (Level 1 로직 파싱) ← **다음 세션 우선 타깃**
- [ ] **M3.x Phase C** — 시계열 축적 (`--interval` 주기, CSV/SQLite 포맷, Phase D의 "데이터 축적 → AI 학습" 기반)
- [ ] **M2.5 Phase D** — Semantic Diff 업그레이드 (Level 3 rung 경계 diff, Level 4 접점 타입 변화)
- [ ] **M4** — 변수 값 쓰기 (W/0xE1, 안전 가드 + 화이트리스트)
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
