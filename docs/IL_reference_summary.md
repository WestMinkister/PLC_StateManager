# IL Reference Summary — `try_again_LSPLC` 분석

> 다음 세션(Phase B.1 IL↔바이트코드 정렬)의 **빠른 참조 문서**.
> 원본: `docs/try_again_LSPLC` (2.9MB), `docs/try_again_LSPLC.CSV` (동일 추정)

## 구조 개요

| 섹션 | 크기 | 내용 |
|---|:---:|---|
| `[NewProgram]` | 1 rung, 5 instr | ADD 테스트 |
| `[NewProgram2]` | 4 rung, 11 instr | SET/RST/MOVE 조합 |
| `[NewProgram3]` | 4 rung, 10 instr | Timer(TON) + Counter(CTU_INT) |
| `[FUNCTION_Program]` | 12 rung, 27 instr | 모든 함수 시험 (SUB/MUL/DIV/AND/OR/NOT/TOF/TP/CTD/CTUD/RS/SR) |
| `[@VARIABLES]` | 2.5MB (99.9%) | 시스템 변수 선언 31K 행 (코드와 무관) |

**총 4 프로그램, 21 rung, 53 인스트럭션** — 매우 컴팩트한 프로그램. 바이트코드 대조에 이상적.

## 전체 OPCODE 어휘 (25종)

### 제어·접점
| IL OPCODE | 카운트 | 의미 | 예상 바이트코드 | 확정도 |
|---|:---:|---|---|:---:|
| `XGRUNGSTART` | 21 | Rung 시작 (경계 마커) | `54 98` or `54 b0` (PRD §7.3) | 🟡 추정 |
| `LOAD` | 21 | 접점 읽기 | `14 XX` (PRD §7.3) | 🟢 |
| `LOAD NOT` | (일부) | NC 접점 (LOAD + 8d modifier) | `14 XX 8d` | 🟡 |
| `OR` | 4 | OR 연산 | ? | 🔴 |
| `ANDP` | 1 | AND Pulse (상승엣지) | `90 00 c0 0f` (PRD §7.3 PULSE) | 🟡 |
| `OUT` | 3 | 출력 코일 | ? ElementType 14 | 🔴 |
| `SET` | 2 | SET 코일 | **ElementType 16 확정** (IL 대조) | 🟢 |
| `RST` | 2 | RESET 코일 | **ElementType 17 확정** (IL 대조) | 🟢 |

### 함수블록
| IL OPCODE | 카운트 | XML INDEX | FB_DEFINITION 패턴 | 확정도 |
|---|:---:|:---:|:---:|:---:|
| `ADD2_INT` | 1 | 71 | ✓ 매칭 | 🟢 |
| `SUB_INT` | 1 | 127 | ✓ | 🟢 |
| `MUL2_INT` | 1 | 72 | ✓ | 🟢 |
| `DIV_INT` | 1 | 99 | ✓ | 🟢 |
| `AND2_WORD` | 1 | 20 | ✓ | 🟢 |
| `OR2_WORD` | 1 | 21 | ✓ | 🟢 |
| `NOT_WORD` | 1 | 110 | ✓ | 🟢 |
| `MOVE_WORD` | 3 | 118 | ✓ | 🟢 |
| `TON` | 1 | 81 | **✗ 미발견** | 🔴 Timer 특수 encoding |
| `TOF` | 1 | 10 | **✗ 미발견** | 🔴 Timer 특수 encoding |
| `TP` | 1 | 34 | ✓ | 🟡 |
| `CTU_INT` | 1 | 243 | **✗ 미발견** | 🔴 Counter 특수 encoding |
| `CTD_DINT` | 1 | 213 | ✓ | 🟡 |
| `CTD_LINT` | 1 | 212 | ✓ | 🟡 |
| `CTD_UDINT` | 1 | 210 | ✓ | 🟡 |
| `CTUD_DINT` | 1 | 207 | ✓ | 🟡 |
| `RS` | 1 | 19 | ✓ | 🟡 |
| `SR` | 1 | 28 | ✓ | 🟡 |

## 핵심 IL 문법 관찰

### 1. 데이터 타입 접미사
- `_INT` (Integer 16비트), `_WORD` (비트/워드), `_DINT` (32비트), `_UDINT` (unsigned 32비트), `_LINT` (64비트)
- 즉 **같은 함수도 타입별로 별개 INDEX**: `ADD2_INT = 71`이지만 `ADD2_DINT`는 다른 INDEX일 가능성 (추가 수집 필요)

### 2. 함수 파라미터 플레이스홀더
```
ADD2_INT  ^LINEIN,^EMPTY,%MW1000,%MW1002,%MW1002
          ~~~~~~~~  ~~~~~~  ~~~~~~~  ~~~~~~~  ~~~~~~~
          EN        ENO     IN1      IN2      OUT
```
- `^LINEIN` = 현재 rung의 논리 라인 입력 (EN)
- `^EMPTY` = 사용하지 않음 (ENO 등)
- `^LINEOUT` = rung 라인 출력
- 실제 주소 `%MW1000` 등은 IN/OUT 값

### 3. Timer/Counter 인스턴스 관리
```
TON       INST  ^LINEIN,T#3s,^LINEOUT,^EMPTY
CTU_INT   INST1 ^LINEIN,1,%MW1002,^LINEOUT,%MW1000
CTD_DINT  INST2 ^LINEIN,1,1,^LINEOUT,^EMPTY
```
- Timer/Counter는 **인스턴스 이름**(`INST`, `INST1`, `INST2`...) 필수
- 이게 FB_DEFINITION 패턴 외부의 별도 encoding 이유
- Phase B.5에서 INST 바인딩 구조 역추론 필요

### 4. 시스템 플래그
- `_ON` (FX153), `_OFF` (FX154) — 상시 ON/OFF 접점
- 둘 다 바이트코드에서 `58 [fx_index_le32]` 토큰으로 관찰됨 ✓

### 5. 시간 상수
- `T#3s` (3초), `T#5s` (5초) — IEC 61131-3 duration literal
- 바이트코드에서 어떤 형태로 encoding 되는지 미확인 (Phase B.5)

## 바이트코드 ↔ IL Rosetta 정렬 알고리즘 (다음 세션 B.1)

1. IL 파일에서 **각 프로그램별** 명령 순차 리스트 추출 (53개 전체)
2. pcapng에서 모든 Z 응답 바이너리 추출 (BZh 해제 포함)
3. 알려진 마커(`67 XX 00 00 00 00 YY`, `58 XX 00 00 00`, `54 98/b0`, `fd ff 07 4a`) 위치 매핑
4. IL 순서와 바이트코드 순서 **DTW(Dynamic Time Warping) 유사 정렬**:
   - IL `ADD2_INT` ↔ 바이트코드 `67 ... 47` (FB_DEFINITION INDEX=71)
   - IL `XGRUNGSTART` ↔ 바이트코드 `54 98/b0`
   - IL `LOAD %MW3000.0` ↔ 바이트코드 `14 XX [addr]`
5. 정렬되지 않은 바이트 시퀀스 = **미지의 OPCODE** (자동 발견)
6. `protocol_grammar.json`에 새 발견 자동 추가

## 예상 결과

Precision/Recall 모두 **95%+** 달성 예상. 단 Timer/Counter INST 구조는 별도 Phase B.5에서 규명.
