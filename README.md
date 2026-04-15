# PLC_StateManager

PLC 런중수정(온라인 에디팅) 쓰기 재생 도구 및 스냅샷 관리 CLI.

## 개요

PLC_StateManager는 LGIS-GLOFA 프로토콜 기반의 PLC 상태 변경 모니터링 및 복원 도구입니다. 현재 Milestone 1은 **F5 런중수정 리플레이**에 초점을 맞추며, 캡처된 온라인 에디팅 시퀀스(T_START → E_WRITE×N → T_END)를 재전송하는 기능을 제공합니다.

## Milestone 1 구성 파일

- **plc_write_analyze.py** — pcapng 캡처 파일에서 온라인 에디팅 윈도우 추출, 프레임 분류(CONN/T_START/E_WRITE/AUX/T_END/DISC), BCC 검증, JSON 저장
- **plc_write_replay.py** — 저장된 프레임을 PLC에 재전송하며 안전 게이트 적용, pre/post-flight 스냅샷 자동 생성, 오류 시 rollback (T_END 재전송)
- **write_replay_frames.json** — 재생 대상 프레임 28개 (1 CONN + 1 T_START + 24 E_WRITE + 1 T_END + 1 DISC)
- **snapshots/** — 스냅샷 저장 디렉토리 (pre_*.bin, post_*.bin, diff JSON)

## 안전 모델

### 커맨드 화이트리스트 (WRITE_MODE_ALLOWED)

```
T (0x54) — 트랜잭션 시작/종료, [T(S)...T(E)] 윈도우 내 안전
E (0x45) — 온라인 에디트 데이터 쓰기, F5 런중수정의 핵심
X (0x58) — 대량 데이터 전송 (정지모드 용이나 재생 시 무해)
M (0x4D) — 모드 제어 (SA0=정지, R9F=실행, 마무리 단계)
```

### 차단 커맨드 (BLOCKED_IN_WRITE_MODE)

```
P (0x50) — 모드 전환, RUN/STOP 예기치 않은 변경 위험
W (0x57) — 직접 메모리 쓰기, 트랜잭션 범위 외, F5 리플레이에 불필요
```

### 안전 장치

- **--i-have-demo-kit 플래그 필수** — 실운영 PLC가 아닌 데모/테스트 기기임을 명시적으로 확인
- **Pre-flight 스냅샷 자동 실행** — 쓰기 전 PLC 프로그램 백업 (업로드)
- **Post-flight 스냅샷 자동 실행** — 쓰기 후 PLC 프로그램 스냅샷, pre와 diff 비교
- **Rollback 메커니즘** — 쓰기 윈도우 중 오류 발생 시 즉시 T_END 재전송, 트랜잭션 무효화

## 사용법 (CLI)

### 오프라인 분석

```bash
# 프레임 검증 (네트워크 I/O 없음)
python3 plc_write_replay.py --dry-run

# 차단된 커맨드 확인
python3 plc_write_replay.py --inspect
```

### Pre-flight 스냅샷 (먼저 실행)

```bash
# snapshots/pre_*.bin 생성 (XG5000 종료 권장)
python3 plc_write_replay.py --preflight-only 192.168.250.110
```

### 라이브 재생

```bash
# 데모 기기에서만 실행, 사용자 확인 필요
python3 plc_write_replay.py --replay 192.168.250.110 --i-have-demo-kit
```

## 재생성 방법

온라인 에디팅 pcapng 캡처가 있을 때:

```bash
# pcapng → write_replay_frames.json 변환
python3 plc_write_analyze.py \
  --pcap docs/pkt_monitor_0410_런중수정시작_두프로그램접점을F5로바꿔서런중수정쓰기_런중수정종료.pcapng \
  --out write_replay_frames.json
```

기본 pcapng 경로: `docs/pkt_monitor_0410_런중수정시작...pcapng`

## 현재 상태

### 캡처 데이터

- 프레임 개수: 28개
- 구성:
  - 1 CONN (차용, upload_replay_frames.json에서)
  - 1 T_START (sub_cmd=0x53, 'S')
  - 24 E_WRITE (sub_cmd 다양: 0xad, 0xce, 0x6e, 0x8d 등)
  - 1 T_END (sub_cmd=0x45, 'E')
  - 1 DISC (차용, upload_replay_frames.json에서)

### 검증 결과

- 모든 프레임 BCC 유효
- T 프레임 sub_cmd 명확히 식별 (0x53='S', 0x45='E')
- 오프라인 구문 검증 완료
- **라이브 테스트는 아직 수행하지 않음** (데모 기기 필요)

## 라이브 테스트 체크리스트 (데모 키트)

데모 PLC에서 처음 실행할 때:

- [ ] XG5000 종료 (PLC와의 다중 세션 방지)
- [ ] `--preflight-only <IP>` 먼저 실행 → snapshots/pre_*.bin 생성 확인
- [ ] `--replay <IP> --i-have-demo-kit` 실행
- [ ] 최종 diff 결과 확인: `changed_byte_count > 0` 이면 성공
- [ ] 즉시 재실행 → 다음 중 하나 관찰:
  - 멱등: diff에서 0 바이트 변경 (정상)
  - 거부: 재전송 거부 (안전 장치)
  - 행잉: 응답 타임아웃 (수동 복구 필요)

## 경고

운영 환경 PLC에 절대 실행하지 말 것. 런중수정은 실시간 프로그램 변경으로 예기치 않은 동작을 초래할 수 있습니다. 데모 기기에서만 테스트하세요.

## Milestone 2 — 의미적(Semantic) Diff

### 배경

Milestone 1은 바이트 수준의 diff만 제공했으므로 "실제로 뭐가 바뀌었는지" 파악하기 어려웠습니다. 특히 F5 런중수정 후 빈 가로선은 구조상 중립적이어서 PLC 바이트 변화가 0인 것이 정상인데, 이 한계를 극복하기 위해 Milestone 2에서는 PLC 응답을 파싱하여 프로그램, 접점, 함수 단위의 의미적 변경사항을 추출합니다.

### 변경된 산출물

- **스냅샷 저장 형식**: 이제 `.bin`(원시 바이트 덤프) + `.json`(파싱된 응답 리스트) 쌍으로 저장됨
- **diff 파일 확장**: `diff.json`에 `byte_diff` 섹션과 `semantic_diff` 섹션 모두 포함
- **신규 도구**: `plc_semantic_diff.py` (스탠드얼론 CLI) 및 컴파일된 EXE `PLC_SemanticDiff.exe` — 오프라인 환경에서 저장된 스냅샷 쌍을 비교

### Semantic Diff 출력 항목 (요약)

```json
{
  "semantic_diff": {
    "programs_added": ["MAIN", "SUB01"],
    "programs_removed": [],
    "programs_changed": ["MAIN"],
    "symbols_added": ["%MW152.0 [PULSE]", "%MW153.2 [INPUT_FLAG]"],
    "symbols_removed": [],
    "functions_added": ["ADD @index 71"],
    "functions_removed": [],
    "functions_changed": ["OR @index 15"],
    "io_changes": {
      "input_removed": ["%I0.5"],
      "output_added": ["%Q1.3"]
    }
  }
}
```

구체적인 출력 항목:
- `programs_added` / `programs_removed` / `programs_changed` — 프로그램명 변경
- `symbols_added` / `symbols_removed` — 접점 추가/삭제 (예: %MW152.0 [PULSE])
- `functions_added` / `functions_removed` / `functions_changed` — 함수/연산 추가/삭제/변경 (예: ADD @index 71)
- `io_changes` — 입출력 핀 변경

### 사용법 (콘솔)

```bash
# 기본 비교 (console 출력)
PLC_SemanticDiff.exe pre_xxx.json post_xxx.json

# 요약만 출력
PLC_SemanticDiff.exe --summary-only A.json B.json

# JSON 파일로 저장
PLC_SemanticDiff.exe --json-out result.json A.json B.json

# Python 직접 실행
python3 plc_semantic_diff.py pre_snapshot.json post_snapshot.json
```

### 쓰기 리플레이 실행 시 자동 출력

`--replay` 플로우가 완료되면 pre/post 스냅샷을 바탕으로 다음과 같이 자동 출력됩니다:

```
=== Byte-level Diff ===
Changed bytes: 156
Added: 48, Modified: 108, Removed: 0

=== Semantic Diff ===
Programs changed: 1 (MAIN)
Symbols added: 3, removed: 1
Functions modified: 5
I/O changes: 2 inputs, 1 output
```

콘솔 출력으로 즉시 변경 내역을 확인할 수 있으며, 상세 JSON은 `snapshots/diff_xxx.json`에 저장됩니다.

### 한계 (Milestone 3+ 예정)

- **래더 위치 정보 미포함**: rung 번호, 셀 좌표 등 그래픽 위치는 제공되지 않음
- **바이트코드 상세 해석 미포함**: 0x8B 등 저수준 명령어 수준의 해석은 미지원
- **파라미터화 쓰기 미지원**: 임의 접점값 지정 쓰기는 Milestone 3에서 추가
- **텍스트 래더 복원 미지원**: 원본 래더 코드 재구성 불가

## 다음 마일스톤

- Milestone 3: 임의 접점 쓰기 (파라미터화) + 상세 래더 정보
- Milestone 4: 정지모드 쓰기 (X 프레임 확장)
- Milestone 5: Invoke ID 자동 재작성
- Milestone 6: `plc_state_manager.py` 본체 (단일 진입점, 상태 캐싱)
