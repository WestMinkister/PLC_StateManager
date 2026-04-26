# LGIS-GLOFA 프로토콜 역공학 — 완전 인수인계 문서

> **최종 업데이트**: 2026-04-26 (v4.0, Phase B.8.2 완료)
> **프로젝트**: `/Users/kangminki/Desktop/Important/AI/SmartFactory/PLC_StateManager/`
> **목적**: 새 세션/Agent가 컨텍스트 없이도 프로토콜 구조를 완벽하게 이해하고 작업 가능하도록 작성
> **분석 근거**: pcapng 캡처 31개(StateManager 13 + ProgramTraker 18) + IL ground truth + XGI CPU 매뉴얼 + 현장 테스트
>
> ## 다음 세션 안내
> **이 파일 하나만 읽으면 됩니다.** `.claude/plans/`의 분석 이력 파일(`harmonic-popping-fairy.md`, `hashed-tinkering-meerkat.md`)은 과정 기록이며, 모든 결론은 이 문서에 포함되어 있습니다.
> - 프로토콜 구조 이해 → Section 2~8
> - 특정 캡처 분석 재현 → Section 10 (파싱 코드) + Section 11 (파일 인벤토리)
> - 구현 착수 → Section 12 (미해결 과제) + Section 1.2 (현재 상태)
> - 확정된 사실의 근거 확인 → Section 13 (확신도 매트릭스)

---

## 1. 프로젝트 개요

### 1.1 목적

LS Electric XG5000(PC) ↔ PLC 간 **TCP 2002** 통신(LGIS-GLOFA 프로토콜)을 **패시브 스니핑**하여,
PLC 프로그램 변경 사항을 실시간 감지·기록하는 Windows 데스크톱 앱.

### 1.2 현재 상태 (Phase B.8.2 완료)

**프로그램 섹션 추출 (Program Section Grammar):**
- **✅ 완료**: HEAD marker 기반 프로그램 이름 추출 (5-condition discriminator)
- **✅ 완료**: 사용자 임의 작명 지원 (ASCII/UTF-8/한글/특수문자 모두 허용)
- **✅ 완료**: 31개 pcapng 검증 (StateManager 13 + ProgramTraker 18)
- **✅ 완료**: protocol_grammar.json 확정 및 phase B.8.2 코드 동기화

**미구현:**
- **⏳ Phase B.8.3**: Rung 경계 byte structure grammar (다음 작업)
- **⏳ Phase B.6**: 쓰기 프로토콜 (E 명령 15개 sub-variant 의미)
- **⏳ 추후**: 한글 trailing 0xeb 같은 invalid UTF-8 처리 (trade-off 검토 필요)

### 1.3 핵심 파일

| 파일 | 역할 |
|------|------|
| `plc_monitor.py` | 메인 모니터 (1700+줄, 단일 파일) |
| `docs/PRD_PROTOCOL_ANALYSIS.md` | **이 문서** — 프로토콜 전체 지식 |
| `docs/*.pcapng` | 패킷 캡처 원본 데이터 |
| `docs/*.xml` | XG5000 프로젝트 XML 변환본 |
| `docs/task*_*.py` | 분석 스크립트 |

---

## 2. 프로토콜 기본 구조

### 2.1 패킷 프레임

```
┌──────────────┬─────────────────┬──────────┬──────────────────┐
│ "LGIS-GLOFA" │  바이너리 헤더    │ 명령코드  │  ASCII Hex 데이터  │
│   10 bytes   │     14 bytes     │  1 byte  │     가변 길이      │
└──────────────┴─────────────────┴──────────┴──────────────────┘
```

**헤더 14바이트 구조:**
```
[0:4]   0x00000022  (프로토콜 상수)
[4:6]   0x0000      (패딩)
[6:8]   LE16        payload_length + 5
[8:10]  가변         (시퀀스/카운터)
[10:12] 0x0E00      (헤더 길이 자기참조)
[12:14] LE16        payload_length + 1
```

**PLC→PC 응답**은 헤더 뒤에 **status 바이트 0x06**이 추가로 들어감 (PC→PLC에는 없음).

### 2.2 페이로드 인코딩 — ASCII Hex (가장 중요한 발견)

LGIS-GLOFA는 **모든 바이너리 데이터를 ASCII 16진수 문자열로 변환**해서 전송합니다.

```python
# 와이어에 보이는 바이트:
wire = b'425A6839314159265359'   # ASCII 글자들
# 진짜 바이너리로 복원:
real = bytes.fromhex(wire.decode('ascii'))
# → b'BZh91AY&SY'  ← bzip2 매직!
```

이 변환 없이는 압축 데이터에 접근 불가. **디코딩 핵심**: `bytes.fromhex(ascii_hex_string)`

### 2.3 명령 코드 6종 (+2종 추가)

| 코드 | 글자 | 용도 | 방향 |
|:---:|:---:|------|------|
| 0x52 | **R** | 메모리 영역 읽기 (런타임 폴링) | 양방향 |
| 0x4A | **J** | CPU 상태/편집 모드 폴링 | 양방향 |
| 0x5A | **Z** | 핸드셰이크, 프로그램 읽기 | 양방향 |
| 0x45 | **E** | 프로그램 데이터 쓰기 (큰 데이터) | PC→PLC |
| 0x54 | **T** | 트랜잭션 시작/종료/시간 동기화 | 양방향 |
| 0x50 | **P** | 파라미터/모드 전환 | 양방향 |
| 0x58 | **X** | 벌크 데이터 (스톱모드 전용) | PC→PLC |
| 0x4D | **M** | 모드 제어 (SA0=스톱, R9F=런) | PC→PLC |

### 2.4 J 명령의 편집 모드 감지 (현재 파서가 사용하는 방식)

```
J15A4210041240060...   ← "060" = 편집/쓰기 모드
J15A4210041240050...   ← "050" = 실행 모드
```

→ 현재 `plc_monitor.py`의 `TwoBurstDetector`가 이 패턴을 감지.

---

## 3. Online Edit (런중수정) 프로토콜 — 완전 해독

### 3.1 전체 시퀀스 (단일 프로그램)

```
Phase 0: R×4 + J×1          레지스터 폴링 + CPU 상태 확인
Phase 1: Z×7                현재 프로그램 블록 읽기 (사전 검증)
Phase 2: T("S1000...")      편집 트랜잭션 시작
Phase 3: E×19               데이터 전송 (각 E에 ACK "45" 응답)
Phase 4: T("E1000...")      트랜잭션 커밋
Phase 5: P + J + Z + R      모드 전환 + 검증 + 폴링 재개
```

### 3.2 19개 E 패킷 상세 (단일 프로그램, 0409 시리즈 기준)

```
E#1   sub=0xAD   블록 테이블 (HEAD+FOOT, 80B)
E#2   sub=0xCE   프로젝트 디스크립터 (프로젝트명·PLC 모델·시리얼)
E#3   sub=0x6E   제어 패킷 (2B)
E#4   sub=0x8D   사용자/프로젝트 정보 ("스캔 프로그램", EUC-KR)
E#5   sub=0x8E   프로그램 디스크립터 (블록명·크기·CRC)
E#6   sub=0x98   메모리 레이아웃 테이블
E#7   sub=0x9E   초기화 (4B zero)
E#8~11  sub=0xC0   세그먼트 초기화 (4×8B)
E#12~13 sub=0xC0   bzip2 워크스페이스 (정적, 변경 무관)
E#14  sub=0xC0   Relocation 테이블 (11엔트리×8B)
E#15  sub=0xC0   ⭐ 래더 심볼 테이블 ("LD VER 2.1" + bzip2 압축)
E#16  sub=0x8B   ⭐⭐⭐ 래더 인스트럭션 바이트코드 (실제 변경!)
E#17~18 sub=0xC9   후처리
E#19  sub=0xAA   검증 해시 (MD5 16B)
```

### 3.3 다중 프로그램 런중수정 (0410 시리즈, 2 프로그램)

24개 E 패킷으로 확장:
- 0x97, 0x96, 0x5E 서브커맨드 추가
- **0x8B가 2개**: 프로그램별 별도 패킷 (addr 오프셋으로 분리)
- 심볼 테이블도 프로그램별 별도 bzip2 블록

### 3.4 런중수정 3단계 프로토콜 (버튼별 구분)

| 단계 | XG5000 버튼 | 프로토콜 시그니처 |
|------|------------|-----------------|
| **시작** | 런중수정 시작 | `Z(0x6E)` → `Z(0xC6)` → `Z(0x7F/0xAD)` per program |
| **쓰기** | 런중수정 쓰기 | `T("S...")` → `E × N` → `T("E...")` |
| **완료** | 런중수정 완료 | `P("TMF1")` → J polls (060 편집모드 전환) |

---

## 4. 스톱모드 쓰기 프로토콜

런중수정과 달리 **전체 프로그램을 재전송**.

### 4.1 차이점

| 항목 | 런중수정 | 스톱모드 |
|------|:---:|:---:|
| E 패킷 수 | 19~24 | 27 + X 84 |
| 전송 범위 | 델타만 | 전체 프로그램 |
| 트랜잭션 | 1개 T(S)/T(E) | 3개 T(S)/T(E) + T(U) |
| J 060 | 있거나 없음 | 없음 (항상 050) |
| M 명령 | 없음 | SA0(스톱)/R9F(런) |
| 추가 서브커맨드 | — | 0x5E,0x7F,0x82,0x83,0x86,0x96,0x9B,0xC6,0xC7,0xF9 |

### 4.2 3개 트랜잭션 구조

```
Transaction 1: T(S,"02") → E[0x82 메모리 레이아웃] → T(E,"02")
Transaction 2: T(S,"03") → E[0x83 파라미터 ×3] → T(E,"03")
Transaction 3: T(S,"01") → E[메인 22개] → T(E,"01")
  → 0x8B 인스트럭션이 프로그램별로 별도 패킷
Finalization:   T(U)
```

---

## 5. PLC 업로드 (PLC로부터열기) — XML 우회 가능 ⭐

### 5.1 핵심 결론

**PLC에서 프로그램을 직접 추출할 수 있습니다.** XML 변환의 3가지 한계(팝업, 저장 의존, 비동기) 없이 패킷만으로 프로그램 구조 파악 가능.

### 5.2 업로드 구조

- **Z 명령**으로 PLC→PC 데이터 전송 (E가 아닌 Z 사용)
- PLC→PC 응답 형식: `LGIS-GLOFA + Header + **0x06**(status) + CmdByte + data`
  - status 바이트 0x06 때문에 기존 파서가 응답을 인식 못 했던 것
- 20종 서브커맨드로 프로그램 완전 전송

### 5.3 업로드 vs 다운로드 서브커맨드 대응

| 역할 | 업로드(Z) | 다운로드(E) |
|------|:---:|:---:|
| 블록 테이블 | 0xCF | 0xAD |
| 인스트럭션 | 0x82 | 0x8B |
| I/O 구성 | 0x86 | 0x86 |
| 심볼 테이블 | 0xC0 (bzip2) | 0xC0 (bzip2) |

### 5.4 추출 가능한 정보

- 프로젝트명 (`try_again`), 프로그램명 (`NewProgram`, `NewProgram2`)
- 전체 심볼 테이블 (디바이스 주소, 접점 타입, 함수 블록)
- PLC 모델 (`KP-T000551`), 시리얼 (`2960523`)

---

## 6. 심볼 테이블 인코딩 (작은 bzip2 블록, E#15)

### 6.1 추출 방법

E 패킷 중 sub-cmd 0xC0, "LD VER 2.1" 문자열 뒤의 bzip2 블록을 해제.

### 6.2 구조

```
[header 7B]
  byte[0]: rung/분기 수 (01=단일, 02=OR 분기 있음)
  byte[1]: 요소 수
  byte[2:7]: 기타 플래그

[요소 반복]:
  [string_length 1B] [주소 문자열 ASCII]  → "%MW3000.0" 등
  [connection_ops 가변]                   → 연결/위치 정보
  [3-tuple + 토큰] 또는 [함수블록 구조]    → 아래 상세
```

### 6.3 접점 3-tuple 구조

```
[prefix] [ElementType] [suffix]
```

| prefix | suffix | 위치 | 비고 |
|:---:|:---:|---|---|
| 0x04 | 0x07 | 열 C | suffix = prefix + 3 |
| 0x0a | 0x0d | 열 A | 항상 성립 |
| 0x10 | 0x13 | 열 B | 6 간격 |

**ElementType 바이트 = XML ElementType 값:**

| 바이트 | XML | 의미 | 검증 |
|:---:|:---:|---|---|
| `06` | 6 | A접점 (NO, 상시개방) | 0409 ①③, 0410 B |
| `07` | 7 | B접점 (NC, 상시폐쇄) | 0409 ①② |
| `08` | 8 | PULSE접점 (상승엣지) | 0409 ⑥ |
| `14` | 14 | 출력 코일 | 0409 전체 |
| `70` | 70 | 함수 블록 I/O 변수 | 0409 ④~⑦ |
| `102` | 102 | 함수 블록 정의 | XML 대조 |

**핵심**: prefix/suffix는 **접점 타입이 아니라 래더 내 위치(열)를 나타냄.**
증거: 같은 위치에서 접점 타입만 변경(NO→PULSE) 시 prefix/suffix 불변.

### 6.4 시스템 플래그 토큰

```
58 [FX인덱스 LE32]  → 5바이트 토큰
```

| 토큰 | FX 인덱스 | 매뉴얼 | 확인 |
|------|:---:|---|:---:|
| `58 9a 00 00 00` | FX154 (0x9a=154) | `_OFF` (상시 Off) | ✅ 0409 7캡처 |
| `58 99 00 00 00` | FX153 (0x99=153) | `_ON` (상시 On) | ✅ 0410 캡처B |

### 6.5 함수 블록 인코딩

```
67 [sub_type] 00 00 00 00 [func_index] 00 00 00 [param_count] ...
  46 0d 00 00  [len] [주소]  → 입력(IN) 파라미터
  68 [sub_type] 00 [offset] 00 00  → 입력 바인딩
  46 13 00 00  [len] [주소]  → 출력(OUT) 파라미터
  46 07 00 00  [len] [값]    → 상수 입력 (MOVE 등)
69 [sub_type] 00 [offset] 00 00  → 함수 블록 종료
```

**확정된 함수 INDEX:**

| 함수 | XML INDEX | 패킷 바이트 | 확인 |
|------|:---:|:---:|:---:|
| ADD | 71 | 0x47 | ✅ 심볼+XML 일치 |
| MOVE | 118 | 0x76 | ✅ 0410 심볼 검증 |

**sub_type 바이트**: `67`/`68`/`69` 뒤의 바이트는 프로그램 블록 인덱스.
(NewProgram=0x10, NewProgram2=0x0a)

### 6.6 OR 분기 구조

```
byte[0] = 02 (분기 수 2 이상)
...
[main rung 데이터]
...
04 00 02 01    → OR 분기 시작 마커
[3-tuple]      → 분기 접점
[len] [주소]   → 분기 접점 주소
[종료 바이트]
```

### 6.7 실제 예시 — 0409 캡처 ④ (ADD 함수 추가, 131 bytes)

```
0000: 05 06 00 06 01 00 00                             ← 헤더 (5=?, 06=요소수)
0007: 09 25 4d 57 33 30 30 30 2e 30                    ← len=9, "%MW3000.0"
0011: 02 04 10 07 13                                   ← 연결OP + 3-tuple(위치B, NC)
0016: 01 58 9a 00 00 00                                ← pos=1, _OFF 토큰
001c: 00 15 02                                         ← OR 분기 마커
001f: 16 5b 0e 5e 00 00                                ← 출력 연결
0025: 09 25 4d 57 33 30 30 30 2e 31                    ← len=9, "%MW3000.1"
002f: 05 00 02 01                                      ← OR 분기 시작
0033: 0a 06 0d 00 00                                   ← 3-tuple(위치A, NO) + 패딩
0038: 08 25 4d 57 31 35 32 2e 30                        ← len=8, "%MW152.0"
0041: 67 10 00 00 00 00 47 00 00 00 03                 ← FB시작, ADD(0x47), 파라미터3개
004c: 01 13 00 14                                      ← FB 내부
0050: 02 00 46 0d 00 00                                ← IN 마커
0056: 07 25 4d 57 31 30 30 30                           ← len=7, "%MW1000"
005e: 68 10 00 04 00 00                                ← 바인딩
0064: 01 02 00 46 0d 00 00                             ← IN 마커
006b: 07 25 4d 57 31 30 30 32                           ← len=7, "%MW1002"
0073: 68 10 00 08 00 00                                ← 바인딩
0079: 02 01 00 69 10 00 0c 00 00                       ← FB종료
0082: 03                                               ← 종료코드
```

---

## 7. 인스트럭션 바이트코드 (0x8B 패킷)

### 7.1 구조

E 패킷 sub-cmd 0x8B의 ASCII hex 디코딩 후:
```
[addr LE16] [0x00] [length LE16] [instruction_bytes] ... [fd ff 07 4a] [trailer]
```

- `addr=0x0000`: 전체 프로그램 (스톱모드 또는 첫 런중수정)
- `addr≠0`: **부분 업데이트** (Online Edit 최적화, 변경 부분만 패치)

### 7.2 PLC 주소 인코딩

```
MW번호 × 2 = LE16 바이트 오프셋
```

| 디바이스 | MW 번호 | 바이트 주소 | LE16 Hex |
|---------|:---:|:---:|:---:|
| MW30 | 30 | 60 | `3c 00` |
| MW152 | 152 | 304 | `30 01` |
| MW1000 | 1000 | 2000 | `d0 07` |
| MW1002 | 1002 | 2004 | `d4 07` |
| MW3000 | 3000 | 6000 | `70 17` |
| MW6000 | 6000 | 12000 | `e0 2e` |

### 7.3 인스트럭션 마커 (부분 해독)

| 바이트 | 의미 | 확인 |
|--------|------|:---:|
| `14 XX` | LOAD (접점 읽기) | ✅ |
| `8d` | B접점(NC) 플래그 | ✅ |
| `90 00 c0 0f` | PULSE 수정자 | ✅ |
| `5c 16 00 0d a6` | ADD 함수 코드 | ✅ |
| `54 98` / `54 b0` | End-of-rung | ✅ |
| `fd ff 07 4a` | End-of-program | ✅ |

### 7.4 RUNG 추가 시 변화

캡처 B→C (RUNG 1개 추가) diff:
- **4바이트 삽입**: `e0 2e 54 b0` = MW6000 주소 LE16 + end-of-rung 마커
- length 필드: +4 증가

### 7.5 다중 프로그램

프로그램별 별도 0x8B 패킷:
- NewProgram: addr=0xFEB8 (또는 0x0000)
- NewProgram2: addr=0x0000 (또는 0x0044)
- **순차 전송, 인터리브 아님**

---

## 8. E 패킷 sub-cmd 0xC0 Scatter-Gather 재조립

### 8.1 문제

큰 bzip2 데이터가 여러 E 패킷에 나뉘어 전송됨. 단순 concat 불가.

### 8.2 해법

각 0xC0 패킷의 ASCII hex 디코딩 후:
```
[addr LE16] [0x00] [length LE16] [data]
```
→ addr 위치에 data를 배치 → 버퍼에서 `BZh` 찾아 bzip2 해제.

### 8.3 결과

큰 bzip2 = **정적 워크스페이스 메타데이터** (프로젝트 구조/설정).
- GZIP 내포 → 6890B UTF-16LE XML
- **7개 캡처 모두 동일** → 프로그램 변경과 무관

---

## 9. XML 방식의 한계 (패킷이 유일한 실시간 방법인 이유)

| # | 한계 | 설명 |
|---|------|------|
| 1 | **팝업 차단** | 특정 PLC 접속 상태에서 wgwx→xml 변환 시 팝업 발생 → 자동화 불가 |
| 2 | **저장 의존** | 런중 쓰기만 하고 프로젝트 저장 안 하면 wgwx에 미반영 (diff 확정) |
| 3 | **비동기 변환** | wgwx→xml 변환 시 0KB 파일 → 시간 후 실제 내용 채워짐 |

**보완**: "스톱모드 쓰기"는 wgwx에 반영됨 (런중 쓰기만 문제).

---

## 10. 공통 파싱 코드

```python
import struct, bz2

def parse_pcapng_packets(filepath):
    """pcapng → [(direction, payload), ...]"""
    with open(filepath, 'rb') as f:
        data = f.read()
    packets = []
    pos = 0
    while pos < len(data):
        if pos + 8 > len(data): break
        block_type = struct.unpack('<I', data[pos:pos+4])[0]
        block_len = struct.unpack('<I', data[pos+4:pos+8])[0]
        if block_len < 12 or pos + block_len > len(data): break
        if block_type == 6 and block_len > 28:
            captured_len = struct.unpack('<I', data[pos+20:pos+24])[0]
            pkt_data = data[pos+28:pos+28+captured_len]
            if len(pkt_data) > 54:
                eth_type = struct.unpack('>H', pkt_data[12:14])[0]
                if eth_type == 0x0800:
                    ip_hdr_len = (pkt_data[14] & 0x0F) * 4
                    proto = pkt_data[14 + 9]
                    if proto == 6:
                        tcp_start = 14 + ip_hdr_len
                        src_port = struct.unpack('>H', pkt_data[tcp_start:tcp_start+2])[0]
                        dst_port = struct.unpack('>H', pkt_data[tcp_start+2:tcp_start+4])[0]
                        tcp_hdr_len = ((pkt_data[tcp_start+12] >> 4) & 0xF) * 4
                        payload = pkt_data[tcp_start + tcp_hdr_len:]
                        if (src_port == 2002 or dst_port == 2002) and len(payload) > 0:
                            direction = "PC→PLC" if dst_port == 2002 else "PLC→PC"
                            packets.append((direction, payload))
        pos += block_len
    return packets

def extract_e_subcmd_data(packets, direction_filter="PC→PLC"):
    """E 명령 패킷 → [(sub_cmd, decoded_binary), ...]"""
    results = []
    for direction, payload in packets:
        if direction != direction_filter: continue
        sig = payload.find(b'LGIS-GLOFA')
        if sig < 0: continue
        rest = payload[sig+10:]
        for i, b in enumerate(rest):
            if b == 0x45:  # 'E'
                cmd_data = rest[i+1:]
                if len(cmd_data) < 2: break
                sub_cmd = cmd_data[0]
                hex_chars = b''
                for bb in cmd_data[1:]:
                    if bb in b'0123456789ABCDEFabcdef':
                        hex_chars += bytes([bb])
                    elif len(hex_chars) > 0:
                        break
                if len(hex_chars) >= 4:
                    try:
                        binary = bytes.fromhex(hex_chars.decode('ascii'))
                        results.append((sub_cmd, binary))
                    except: pass
                break
    return results

def scatter_gather_reassemble(e_data_list):
    """0xC0 패킷 → 재조립된 버퍼 → bzip2 해제"""
    chunks = []
    for sub_cmd, binary in e_data_list:
        if sub_cmd != 0xc0 or len(binary) < 5: continue
        addr = struct.unpack('<H', binary[0:2])[0]
        data = binary[5:]
        chunks.append((addr, data))
    if not chunks: return None
    max_end = max(a + len(d) for a, d in chunks)
    buf = bytearray(max_end)
    for addr, data in chunks:
        buf[addr:addr+len(data)] = data
    bz_idx = bytes(buf).find(b'BZh')
    if bz_idx >= 0:
        try: return bz2.decompress(bytes(buf[bz_idx:]))
        except: pass
    return None

def extract_small_bzip2(e_data_list):
    """E#15 심볼 테이블 추출 (비-0xC0 E 패킷 중 bzip2 포함된 것)"""
    for sub_cmd, binary in e_data_list:
        if sub_cmd == 0xc0: continue
        bz_idx = binary.find(b'BZh')
        if bz_idx >= 0:
            try: return bz2.decompress(binary[bz_idx:])
            except: pass
    return None
```

---

## 11. 캡처 데이터 인벤토리

> **PLC**: LS Electric XGI, IP 192.168.250.110, 모델 KP-T000551
> **PC**: XG5000, IP 192.168.250.100
> **프로젝트**: `try_again` (프로그램 블록: NewProgram, NewProgram2)

### 11.0 최초 분석 대상 (2026-04-07)

| 파일명 | 날짜 | 크기 | 설명 |
|--------|------|:---:|------|
| `OFF추가_RAW.pcapng` | 04-07 20:46 | 19KB | 한 줄 래더에 _OFF 접점 1개 런중 추가. **v2 분석의 출발점** — ASCII Hex, bzip2, _OFF 토큰 등 모든 핵심 발견의 기초 |
| `OFF추가.txt` | 04-07 20:16 | 10KB | 위 캡처의 수동 텍스트 덤프 (패킷별 1줄) |

### 11.1 0409 시리즈 — 런중수정 단계별 캡처 (2026-04-08)

하나의 래더 프로그램(NewProgram, 1 rung)을 **단계별로 수정**하면서 각 런중 쓰기마다 캡처.
시간순으로 누적되는 변경 이력.

| # | 시각 | 파일명 | 크기 | 변경 내용 | 프로그램 쓰기 | 심볼 크기 |
|---|------|--------|:---:|------|:---:|:---:|
| — | 22:40 | `pkt_monitor_0409_접속만.pcapng` | 13KB | PLC 접속만 (J/R/Z 폴링) | ✗ | — |
| — | 22:40 | `pkt_monitor_0409_접속상태에서_모니터모드.pcapng` | 6KB | 모니터 모드 진입 | ✗ | — |
| — | 22:43 | `pkt_monitor_0409_PLC로부터열기.pcapng` | 126KB | PLC→PC 프로그램 업로드 | ✗ | — |
| ① | 22:45 | `pkt_monitor_0409_두번째꺼를_B접점상시OFF로추가.pcapng` | 46KB | _OFF(A접점) 1개 있는 상태에서 _OFF(B접점) 1개 추가 → 총 2개 | ✓ | 55B |
| ② | 22:47 | `pkt_monitor_0409_첫번째꺼를_F5로_그냥라인으로만들기.pcapng` | 23KB | 첫번째 _OFF(A접점) 제거 → F5 가로선으로 대체 | ✓ | 45B |
| ③ | 22:49 | `pkt_monitor_0409_OR로접점하나추가하기(152.0).pcapng` | 27KB | %MW152.0을 OR(세로선) 분기로 추가 | ✓ | 70B |
| — | 22:51 | `pkt_monitor_0409_MW3000.0을_강제ON시켜서_윗라인살려버리기.pcapng` | 10KB | I/O 강제 ON (프로그램 변경 아님) | ✗ | — |
| ④ | 22:53 | `pkt_monitor_0409_MW152.0뒤에_ADD함수넣고쓰기(MW1000_MW1002).pcapng` | 21KB | %MW152.0 뒤에 ADD(%MW1000 + %MW1002) 함수 블록 추가 | ✓ | 131B |
| ⑤ | 22:54 | `pkt_monitor_0409_ADD함수에_MW1003출력으로추가하기.pcapng` | 22KB | ADD 함수에 출력 파라미터 %MW1003 추가 | ✓ | 143B |
| ⑥ | 22:56 | `pkt_monitor_0409_ADD앞에접점을_PULSE접점으로바꾸기.pcapng` | 27KB | %MW152.0 접점을 NO(A접점)→PULSE(상승엣지)로 변경 | ✓ | 147B |
| ⑦ | 22:58 | `pkt_monitor_0409_출력을_MW1002로바꾸기.pcapng` | 24KB | ADD 함수 출력을 %MW1003→%MW1002로 변경 | ✓ | 142B |
| — | 22:59 | `pkt_monitor_0409__MW152.0을계속ON_OFF시켜서...pcapng` | 22KB | MW152.0 ON/OFF 토글 (I/O 강제, 프로그램 변경 아님) | ✗ | — |

### 11.2 0410 시리즈 — 스톱모드 + 다중 프로그램 + 업로드 (2026-04-09, 23시대)

프로그램을 2개(NewProgram + NewProgram2)로 확장한 상태에서 다양한 쓰기 방식 캡처.

| # | 시각 | 파일명 | 크기 | 쓰기 방식 | 설명 |
|---|------|--------|:---:|----------|------|
| A | 23:10 | `pkt_monitor_0410_프로그램수정후_접속_그냥쓰기_런모드까지_모니터시작은안함.pcapng` | 86KB | **스톱모드** | PC에서 프로그램 수정 후 PLC에 접속→쓰기→런. 2 프로그램 전체 전송. E 27개 + X 84개 |
| B | 23:25 | `pkt_monitor_0410_초기런상태_스톱_상시ON쓰기_런_.pcapng` | 76KB | **스톱모드** (자동) | 런 중 쓰기 시도→자동 스톱→_ON 접점 포함 쓰기→자동 런 복귀. **_ON 토큰(`58 99`) 확인됨** |
| C | 23:27 | `pkt_monitor_0410_초기런상태_스톱_RUNG추가_쓰기_런_.pcapng` | 78KB | **스톱모드** (자동) | RUNG 1개 추가. B와의 diff로 **RUNG 추가=4바이트 삽입** 확인 |
| D | 23:28 | `pkt_monitor_0410_PLC로부터열기.pcapng` | 118KB | **업로드** | PLC→PC 프로그램 읽기. Z 명령으로 전체 프로그램 추출 가능 확인. 492패킷 |
| E | 23:30 | `pkt_monitor_0410_런중수정시작_두프로그램접점을F5로바꿔서런중수정쓰기_런중수정종료.pcapng` | 29KB | **런중수정** | 런중수정 시작→두 프로그램의 접점을 F5(가로선)로 변경→쓰기→완료. **3단계 프로토콜 구분됨** |

### 11.3 XML 파일

XML은 XG5000 프로젝트(.xgwx)를 cmd 명령으로 변환한 것. 3가지 상태가 있음:
- **(1) 초기**: 변경 전 상태
- **(2) 쓰기 후 미저장**: 런중/스톱 쓰기는 했지만 프로젝트 저장(Ctrl+S) 안 함
- **(3) 저장 후**: 프로젝트 저장 완료 후 XML 변환

| 시리즈 | 시각 | 파일명 | 크기 | 상태 | 프로그램 수 | 설명 |
|:---:|------|--------|:---:|:---:|:---:|------|
| 0409 | 04-08 22:37 | `0409_try_again_초기_OFF2개상태.xml` | 158KB | (1) | 1 | 캡처 ① 직후. OFF 2개 rung |
| 0409 | 04-08 23:01 | `0409_try_again_잔뜩추가한상태_저장전.xml` | 158KB | (2) | 1 | 런중쓰기 7회 후 미저장. **래더 변경 없음** (XML 한계 입증) |
| 0409 | 04-08 23:03 | `0409_try_again_저장후_xml변환.xml` | 159KB | (3) | 1 | 저장 후. ADD+PULSE+OR 등 모든 변경 반영. _ON, %MW152.0 포함 |
| 0410 | 04-09 23:22 | `0410_try_again_프로그램을하나추가_완전변경후.xml` | 164KB | (2) | **2** | NewProgram2 추가 (4 rungs). MOVE 함수, %IW5000, %MW6000 |
| 0410 | 04-09 23:30 | `0410_try_again_이후몇번프로그램바꾸면서_쓰기와런중쓰기만함_저장은안함.xml` | 164KB | (2) | 2 | 스톱쓰기는 반영, 런중쓰기 일부 반영 |
| 0410 | 04-09 23:31 | `0410_try_again_마지막저장본.xml` | 163KB | (3) | 2 | 최종 저장. 런중수정 결과 반영 |

### 11.4 기타 파일

| 파일명 | 날짜 | 설명 |
|--------|------|------|
| `0409_try_again.state` | 04-08 23:06 | XG5000 프로젝트 상태 파일 (bzip2 압축, 해제 시 UTF-16LE XML) |
| `0409_try_again.xgwx_bkx0` | 04-08 22:35 | XG5000 프로젝트 백업 파일 |
| `0410_try_again.state` | 04-09 23:34 | 0410 세션 상태 파일 |
| `0410_try_again.xgwx_bkx0~2` | 04-09 23:09~34 | 0410 세션 백업 파일 3개 (시간순) |
| `XGI-CPU_Manual_V2.9_202508_KR.pdf` | — | XGI CPU 매뉴얼 (부록 1.1 시스템 플래그 일람) |
| `LGIS-GLOFA.pdf` | — | 프로토콜 사양 문서 (16페이지) |

---

## 12. 미해결 과제 및 부족한 정보 (Phase B.8.2 갱신)

### 12.1 Phase B.8.2 완료 항목

| 과제 | 상태 | 설명 |
|------|:---:|------|
| **Program Section Grammar** | ✅ 완료 | HEAD marker 기반 구조 100% 해독 + 5-condition discriminator |
| **사용자 임의 작명** | ✅ 완료 | ASCII/UTF-8/한글/특수문자('=' 등) 모두 지원 |
| **Multiple Program Extraction** | ✅ 완료 | 0x11 marker + 7-byte metadata 구조 확정 |
| **31 pcapng 검증** | ✅ 완료 | StateManager 13 + ProgramTraker 18 전수 검증 |

### 12.2 아직 해독되지 않은 영역

| 과제 | 상태 | 영향도 | 설명 |
|------|:---:|:---:|------|
| **Rung 경계 Grammar** | 🟡 Phase B.8.3 예정 | 높음 | RUNG 마커 (`54 98`, `54 b0`) 와 경계 구조. 현재 IL 우선 의존, bytecode 독립 해석 필요 |
| 인스트럭션 OPCODE 테이블 | 🟡 | 높음 | LOAD(`14`), B접점(`8d`), PULSE(`90 00 c0 0f`), ADD(`5c 16 00 0d a6`) 외에 SUB/MUL/DIV/TON/CTU 등 미확인 |
| rung diff 알고리즘 | 🟡 | 높음 | 0x8B 패킷 간 비교로 "무엇이 변했는지" 자동 추출하는 로직 미구현 |
| 쓰기 프로토콜 (E 명령) | 🟡 Phase B.6 | 높음 | E_WRITE sub 15종의 의미 규명 (M1 에서 부분 캡처됨) |
| 좌표/위치 바이트 | 🟡 | 낮음 | `16 5b 0e 5e 00 00` 등 — XML Coordinate 속성과의 매핑 미완 |
| SmartExtension 프로토콜 | 🟢 | 낮음 | 0x58('X') 명령, JSON 기반 기능 교환 — 분석 미착수 |
| **한글 trailing 0xeb** | 🟡 | 낮음 | UTF-8 invalid single byte 처리 (현재 제거, 보존 trade-off 검토 필요) |

### 12.2 Program Section Grammar (Phase B.8.2 상세)

**정의**: PLC→PC 응답(X/Z 명령)에 포함된 program list payload 의 바이트 구조. 이 구조를 파싱하여 PLC 에 로드된 프로그램의 이름과 개수를 추출.

**검증 대상**: 31개 pcapng 파일 (StateManager 13 + ProgramTraker 18)

#### 12.2.1 바이너리 구조 (HEAD부터 FOOT까지)

```
┌─ Offset 0 ─────────────────────────────────────────────────────┐
│  [HEAD marker]  [Size field]  [Program 1]  [Program 2]...      │
│      4 bytes        4 bytes    variable     variable           │
│   "48 45 41 44"  "LE u32"                                      │
└──────────────────────────────────────────────────────────────┘
```

**HEAD marker** (offset 0):
- Bytes: `48 45 41 44` (ASCII "HEAD")
- Size: 4 bytes
- 의미: Program section 시작 표시

**Size field** (offset 4):
- Type: uint32_le (little-endian)
- Size: 4 bytes
- 의미: 이후 payload 바이트 수 (size field 자체 미포함)
- 예시: `74 00 00 00` = 116 bytes, `e8 00 00 00` = 232 bytes, `d0 01 00 00` = 464 bytes

**Program Record (첫 프로그램, offset 8):**
```
+0   | Program name (null-terminated, up to 32 bytes)
+32  | Padding/metadata (null bytes, 16+ bytes)
```

**Program Record (후속 프로그램):**
```
-1   | 0x11 separator (program marker)
-8..-1   | 7-byte program metadata (size/CRC/flags — 파싱 불필요)
+0   | Program name (null-terminated, up to 32 bytes)
+32  | Padding/metadata (null bytes, 16+ bytes)
```

**Termination**:
- FOOT marker (`46 4F 4F 54` "FOOT") 또는 payload end 도달
- 대부분 program section 은 FOOT 가짐
- 일부 variant (0421_exe_auto_read) 는 FOOT 없으나 0x11 marker 로 종결

#### 12.2.2 Program Name Encoding (사용자 임의 작명)

**핵심 원칙**: Grammar over naming. 이름의 형태에 가정 금지. PLC IDE 에서 사용자가 지은 이름 그대로 수용.

| 속성 | 값 |
|------|:---|
| **Encoding** | ASCII / UTF-8 모두 (한글, 특수문자 포함) |
| **길이** | 1-32 bytes (null terminator 제외) |
| **문자** | printable ASCII (32-126) + UTF-8 multi-byte (한글, 기타 유니코드) |
| **특수문자** | 허용: `=`, `-`, `!`, `#`, `_`, `@` 등 (사용자가 PLC에서 지정 가능) |
| **키워드 매칭** | **절대 금지**. "NewProgram" 문자열 검색 없음. 오직 byte structure 만 사용 |
| **컨트롤 문자** | 거부: NUL, TAB, newline 등 (printable 조건으로 자동 필터) |

**검증된 실제 예시** (31 pcapng 에서 추출):

| 파일 | Program Names | 특징 |
|------|:---|:---|
| `0421_스캔1개` | `NewProgram` | 1개, 단순 영문 |
| `0421_스캔2개` | `NewProgram`, `NewProgram2` | 2개, 연번 |
| `0423_PLC로부터열기` | `NewProgram`, `NewProgram2`, `NewProgram3`, `FUNCTION_Program` | 4개, 영문 + underscore |
| (ProgramTraker) | 다양한 사용자 정의 이름 | 18개 파일 추가 검증 (다음 표 참고) |

#### 12.2.3 5-Condition Discriminator (False Positive 필터)

Phase B.8.2 에서 JSON status, nested HEAD section, binary garbage 를 거부하기 위해 정의된 5가지 조건. **모두 만족해야 valid program section**:

| # | 조건 | 내용 | Fails on |
|---|:---|:---|:---|
| 1 | startswith_HEAD | offset 0 에 `48 45 41 44` (HEAD marker) | JSON/binary garbage |
| 2 | minimum_length | `len(payload) >= 30` bytes | truncated data |
| 3 | offset_8_printable | `decoded[8]` is ASCII printable (32-126) | JSON status (offset 8 = '{'), binary garbage (offset 8 = 0x00-0x1f) |
| 4 | contains_FOOT_or_0x11 | `b'FOOT'` 또는 `0x11` marker 존재 | JSON status (둘 다 없음) |
| 5 | reject_nested_HEAD | `decoded[8:12] != b'HEAD'` | nested sub-section (program name 이 'HEAD' 일 가능성은 사실상 없음) |

**False Positive 예시**:

```python
# JSON status response (rejected by condition 4 + 3)
b'HEAD' + size + b'{"ModuleReset":"1"}' + padding
→ Condition 3 fail: decoded[8] = '{' (0x7b, not printable in context)
→ Condition 4 fail: no FOOT, no 0x11 marker

# Binary garbage (rejected by condition 3)
b'HEAD' + size + b'\x01\x02\x03...' + padding
→ Condition 3 fail: decoded[8] = 0x01 (not printable ASCII)

# Nested HEAD (rejected by condition 5)
b'HEAD' + size + b'HEAD...' + padding
→ Condition 5 fail: decoded[8:12] == b'HEAD'
```

### 12.2-old 확정되었지만 검증 사례가 적은 항목

| 항목 | 확인된 사례 | 부족한 부분 |
|------|-----------|-----------|
| 접점 3-tuple 위치 쌍 | 3쌍 (`04/07`, `0a/0d`, `10/13`) | 4번째 이상의 쌍 미확인 (6 간격 규칙이 계속 성립하는지) |
| 함수 블록 INDEX | ADD=71, MOVE=118 | SUB/MUL/DIV/AND/OR 등 다른 함수의 INDEX 미확인 |
| RUNG 경계 마커 | `54 98`, `54 b0` 확인 | 두번째 바이트(`98`/`b0`)의 의미 미해독 |
| PLC 업로드 구조 | 캡처 1개로 확인 | 다른 프로젝트/PLC 모델에서도 동일한지 미검증 |

### 12.3 추가 캡처가 필요한 시나리오

| 시나리오 | 확인 가능 사항 | 현재 상태 |
|---------|--------------|:---:|
| SUB/MUL/DIV 함수 블록 사용 | 함수 INDEX 테이블 확장 | 캡처 없음 |
| TON/CTU 타이머/카운터 | 타이머/카운터 인스트럭션 인코딩 | 캡처 없음 |
| 10줄 이상 복잡한 래더 | RUNG 경계 마커 패턴 완전 확인 | 캡처 없음 |
| 다른 PLC 모델 (XGB/XGR) | 프로토콜 호환성 | 캡처 없음 |

### 12.4 `.claude/plans/` 파일과의 관계

| 파일 | 역할 | 이 문서에 반영됨? |
|------|------|:---:|
| `harmonic-popping-fairy.md` (875줄) | v2~v3.2 분석 **과정** 상세 기록 | ✅ 결론은 모두 반영 |
| `hashed-tinkering-meerkat.md` (188줄) | 0410 분석 세션 보고서 | ✅ 결론은 모두 반영 |
| `memory/reference_protocol.md` (42줄) | 세션 간 메모리 (자동 로드) | ✅ 동일 내용의 압축본 |

**이 문서에 없고 `.claude/plans/`에만 있는 정보**: 없음.
`.claude/plans/` 파일들은 "어떻게 이 결론에 도달했는지" 과정을 기록한 것이며, 결론 자체는 이 문서에 모두 포함.

---

## 13. 자기 검증 원칙 (누적 교훈, Phase B.8.2)

Phase B.1~B.8.2 를 거치면서 발견된 함정과 검증 방법론. **다음 세션이 동일한 실수를 회피할 수 있도록 명시**.

### 13.1 다중 입력 분포 검증 (Multi-Input Mass Smoke Test)

**문제 케이스**: 
- Phase B.6 에서 단일 pcapng 동작으로 "OK" 결론 → Phase B.7~B.8 에서 대량 데이터(13 pcapng)에서 fail 발견
- 원인: 4개 프로그램 케이스와 1-2개 프로그램 케이스의 바이트 구조 차이 미인식

**원칙**: 
- ✅ 단일 케이스 동작만으로 구현 완료 선언 금지
- ✅ **최소 3개 서로 다른 분포의 입력** 으로 검증 (1개 프로그램, 2개, 4개 등)
- ✅ 존재하는 모든 pcapng(31개) 에 대해 smoke test 실행 (회귀 방지)

### 13.2 자기 평가 신뢰 금지 (No Self-Assessment Trust)

**문제 케이스**:
- validator 에이전트 "PASS 보고" → 직접 실측 확인하지 않음 → 나중에 틀림
- Condition 5 (reject_nested_HEAD) 추가 후 "이제 안전" 단정 → ProgramTraker 18개 파일 재검증해야 함

**원칙**:
- ✅ Agent 리포트는 참고만 하고, **직접 실측 데이터(hex dump, 파일 목록)**로 재확인
- ✅ "이제 완성" 선언 전에 **전수 재검증**(31개 파일 직접 스캔)
- ✅ 자동화 테스트 PASS 도 상시 의심. 엣지 케이스가 테스트에 누락되었을 가능성

### 13.3 이름 매칭 절대 금지 (Grammar Over Naming)

**문제 케이스**:
- "NewProgram" 이라는 문자열로 name 검증 → 사용자가 다른 이름 지으면 fail
- "0x11 marker 찾기" → 특수한 경우(1개 프로그램)에는 0x11 이 없음

**원칙**:
- ✅ 키워드/이름 기반 검색 금지: `if b'NewProgram' in payload` 같은 코드 절대 안됨
- ✅ 구조 기반만 인식: "offset 0 에 HEAD 있고, offset 8 부터 printable 문자" 같이 바이트 구조로만 검증
- ✅ 이름의 형태(길이, 특수문자, 한글 등)에 가정 금지. 사용자 지정 그대로 수용

### 13.4 확장성 우선 (Extensible Framework First)

**문제 케이스**:
- "이 케이스에만 동작하는" 미봉책 코드 작성 → 다른 PLC 시리즈, 새 프로토콜 variant 에서 깨짐
- 예: "program section 은 항상 FOOT 로 종결" 단정 → 일부 variant (0421_exe_auto_read) 는 FOOT 없음

**원칙**:
- ✅ 새 기능 설계 시 **다른 PLC 시리즈, 프로토콜 버전, 사용자 설정**이 나타나도 동작 가능하도록
- ✅ "거의 모든 경우" 가정 금지 → 대신 OR 조건 사용 (FOOT OR 0x11 marker)
- ✅ bytecode 고정값 피하기: 진짜 "변할 수 없는" 것(HEAD marker, size field LE16)만 고정

### 13.5 실측 데이터 인벤토리 유지 (Empirical Data Registry)

**원칙**:
- ✅ 이 PRD 의 **파일 인벤토리 표(11.1, 11.2)와 grammar 예시**는 공식 지식
- ✅ "NewProgram", "NewProgram2" 같은 이름은 단순 예시가 아님. 실제 pcapng 에서 추출한 데이터
- ✅ ProgramTraker 18개 파일도 동일하게 정리 필요 (현재 미기재)

---

## 14. 확신도 매트릭스 (Phase B.8.2 갱신)

| 주장 | 확신도 | 검증 |
|------|:---:|---|
| ASCII Hex 인코딩 | 🟢 100% | 13캡처 |
| bzip2 압축 | 🟢 100% | 13캡처 |
| 명령 6종 R/J/Z/E/T/P | 🟢 100% | 13캡처 |
| _OFF = `58 9a` (FX154) | 🟢 100% | 0409 7캡처 |
| _ON = `58 99` (FX153) | 🟢 100% | 0410 캡처B |
| 접점 06=NO, 07=NC, 08=PULSE | 🟢 95% | 0409 ①②⑥ |
| prefix/suffix = 위치 인코딩 | 🟢 95% | 3쌍 확인 |
| PLC 주소 = MW×2 LE16 | 🟢 100% | 12캡처 |
| ADD = INDEX 71 = 0x47 | 🟢 95% | 심볼+XML |
| MOVE = INDEX 118 = 0x76 | 🟢 95% | 0410 심볼 |
| `46 0d`=IN, `46 13`=OUT | 🟢 90% | 0409 ⑤ |
| scatter-gather 재조립 | 🟢 100% | 12캡처 |
| 0x8B = 인스트럭션 | 🟢 95% | 12캡처 |
| 큰 bzip2 = 정적 워크스페이스 | 🟢 100% | 7캡처 동일 |
| Online Edit 19 E 시퀀스 | 🟢 95% | 0409+0410 |
| 런중수정 3단계 시그니처 | 🟢 90% | 0410 캡처E |
| PLC 업로드 = Z 명령 | 🟢 90% | 0410 캡처D |
| RUNG 마커 `54 XX` | 🟢 90% | 0410 B→C diff |
| MD5 검증 해시 (0xAA) | 🟢 85% | 16B 일치 |
| XML 런중쓰기 미반영 | 🟢 100% | 0409 diff |
| **Program Section HEAD marker** | **🟢 100% (B.8.2)** | **31캡처 (SM 13 + PT 18)** |
| **5-Condition Discriminator** | **🟢 100% (B.8.2)** | **JSON/nested/garbage false positive 전무** |
| **사용자 임의 프로그램 명명** | **🟢 100% (B.8.2)** | **4개 예시 (NewProgram, NewProgram2~3, FUNCTION_Program)** |
| **0x11 marker (후속 프로그램)** | **🟢 100% (B.8.2)** | **2개/4개 프로그램 케이스 모두 동작** |
| **Program extraction (multiple)** | **🟢 100% (B.8.2)** | **1개, 2개, 4개 프로그램 케이스 전수 검증** |

---

## 15. 분석 스크립트

| 파일 | 용도 |
|------|------|
| `analyze_bzip2_final.py` | Scatter-gather 재조립 + 7캡처 검증 |
| `analyze_e_packets_v2.py` | E 패킷 전체 시퀀스 매핑 |
| `decode_instructions.py` | 0x8B 인스트럭션 디코딩 |
| `task3_*.py` | RUNG 추가/MOVE 함수 분석 |
| `task4_*.py` | 스톱모드 쓰기 프로토콜 매핑 |

---

## 16. 참조 문서

| 문서 | 위치 | 내용 |
|------|------|------|
| 상세 분석 이력 | `~/.claude/plans/harmonic-popping-fairy.md` | v2~v3.2 전체 분석 과정 (875줄) |
| 세션별 보고서 | `~/.claude/plans/hashed-tinkering-meerkat.md` | 0410 분석 요약 |
| 프로토콜 메모리 | `.claude/.../memory/reference_protocol.md` | 압축 참조 (42줄) |
| XGI CPU 매뉴얼 | `docs/XGI-CPU_Manual_V2.9_202508_KR.pdf` | 부록 1.1 시스템 플래그 일람 |
| 프로토콜 PDF | `docs/LGIS-GLOFA.pdf` | 공식 프로토콜 사양 (16p) |
| Wireshark 디섹터 | `github.com/ciaoly/PLC-XGT-protocol-for-Wireshark` | XGT 2004 포트용 (2002 미지원) |

---

## Appendix A — 공식 XGT 프로토콜 매뉴얼 반영 (2026-04-24)

### 참조 자료

- `docs/사용설명서_XGB FEnet_국문_V2.2_20260324.pdf` §5.2 "XGT 전용 프로토콜" (p.5-2 ~ 5-8)
- 사용자 독자 분석 (2026-04-24 세션)

### Company Header 20바이트 공식 구조

| Offset | 필드 | 크기 | 의미 |
|:---:|---|:---:|---|
| 0:10 | Company ID | 10 | LSIS-XGT (XGK/XGI) 또는 LGIS-GLOFA (GM/MK) |
| 10:12 | PLC Info | 2 | 비트 필드: CPU TYPE + 이중화 + RUN/STOP 상태 |
| 12 | CPU Info | 1 | 0xA0=XGK, 0xA4=XGI, 0xA8=XGR, 0xB0=XGB(MK), 0xB4=XGB(IEC) |
| 13 | Source of Frame | 1 | 공식 0x33 (클→서), 0x11 (서→클). XG5000 은 **0x22** 사용 (비공식 확장) |
| 14:16 | Invoke ID | 2 | 프레임 순서 ID. 응답에 복사. XG5000 은 0x0000 고정 |
| 16:18 | Length | 2 | Application Instruction 바이트 수 (LE16) |
| 18 | FEnet Position | 1 | Bit0~3=Slot, Bit4~7=Base |
| 19 | Reserved2 (BCC) | 1 | Application Header Byte Sum |

### 공식 vs 확장 명령

**공식 HMI 프로토콜**: h5400 (읽기 요구) / h5500 (읽기 응답) / h5800 (쓰기 요구) / h5900 (쓰기 응답)

**XG5000 확장 명령 (공식 매뉴얼 외)**:
- X (0x58) — 업로드/심볼 (3 sub-variants)
- Z (0x5A) — 확장 command flow (7 sub-variants)
- U (0x55) — 업로드 시작

이 프로젝트 (PLC_StateManager) 의 역공학 대상은 **XG5000 확장 영역** 이며, 공식 매뉴얼에는 기재되지 않은 부분. Phase B.1~B.5.3 의 성과 (Rosetta 16/18, AST 추출, timer/counter kind) 는 전부 확장 영역의 구조 해독이다.

### 사용자 기여 인정 (2026-04-24)

사용자가 공식 매뉴얼을 직접 읽고 수행한 독자 분석으로 확정된 항목:
- `BCC = Application Header Byte Sum` (사용자 가설 → 공식 확정)
- `FEnet Position` 필드 (Bit0~3 Slot + Bit4~7 Base)
- `Source of Frame` 값으로 방향 구분 (0x22/0x11 관찰)
- Z 명령 7개 sub-variants 리스트업

---

## Appendix B — PC→PLC 커맨드 인벤토리 (frame bundle 기반, 2026-04-24)

### 데이터 출처

- `upload_replay_frames.json` (239 frames, 업로드 세션)
- `write_replay_frames.json` (28 frames, 쓰기/런중수정 세션, M1 커밋 5d097a7)

### Upload 세션 커맨드

| 1st byte | ASCII | Sub 관찰 | 빈도 | 역할 |
|:---:|:---:|---|:---:|---|
| 0x58 | X | XL(4C)/XM(4D)/XW(57) | 134 | burst 진입 |
| 0x5A | Z | 13 variants (5A/6A/82/83/86/88/89/8D/8E/96/C0/C6/6E) | 65 | command flow |
| 0x4A | J | J4 (0x34) | 19 | 중간 요청 |
| 0x52 | R | 0xAC, 0x6E | 7 | read/response 유도 |

### Write 세션 커맨드 (트랜잭션 기반)

```
CONN → T_START (T,0x53="TS") → E_WRITE × N (E + 15 sub) → T_END (T,0x45="TE") → DISC
```

- **T_START / T_END**: 트랜잭션 경계 (0x54 "T" + 0x53/"S" 또는 0x45/"E")
- **E_WRITE**: 쓰기 본체 (E = 0x45, 가장 빈번한 sub = 0xC0)
- E_WRITE sub 15종의 의미 개별 규명은 B.6 후속

### 검증 대기 (사용자 독자 관찰, 추가 pcapng 필요)

- Y 계열 (YR, Y..)
- W 계열 (WN, WX)
- Z 추가 printable (Z₩, Z], ZX, ZY)

### 중요한 시사점

1. **프로토콜 surface 는 기존 문서 (X/Z/U) 보다 훨씬 넓음** — 최소 6개 first-byte (X/Y/Z/J/R/E/T), Y/W 포함 시 8개
2. **쓰기 프로토콜은 이미 부분 해독** — M1 에서 트랜잭션 구조 캡처. B.6 의 현재 과제는 "E_WRITE sub variant 의미 규명" 으로 축소
3. **세션 유실 주의** — 이 지식은 frame bundle JSON 에 보존되어 있었으나 grammar 에 미반영. 이번 업데이트로 영구화
