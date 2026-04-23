import argparse
import csv
import json
import os
import re
import sys
import time
import datetime
import serial # pip install pyserial 필요
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Union

# 기존 TCP 통신 라이브러리
from PyXGT.LS import plc_ls

# -----------------------------
# Regex: bit address or word address
# -----------------------------
BIT_RE = re.compile(r"^%?(?P<area>[MIQW])W(?P<word>\d+)\.(?P<bit>\d+)$", re.IGNORECASE)
WORD_RE = re.compile(r"^%?(?P<area>[MIQW])W(?P<word>\d+)$", re.IGNORECASE)

TARGETS_FILE = "targets.json"
CONFIG_FILE = "config.json"


# -----------------------------
# Data models
# -----------------------------
@dataclass(frozen=True)
class WBit:
    area: str
    word: int
    bit: int
    name: str = ""

    @property
    def human(self) -> str:
        return f"%{self.area}W{self.word}.{self.bit}"

    @property
    def headdevice(self) -> str:
        return f"{self.area}{self.word * 16 + self.bit}"

    @property
    def label(self) -> str:
        return self.name.strip() or self.human


@dataclass(frozen=True)
class WWord:
    area: str
    word: int
    name: str = ""

    @property
    def human(self) -> str:
        return f"{self.area}{self.word}"

    @property
    def headdevice(self) -> str:
        return f"{self.area}{self.word}"

    @property
    def label(self) -> str:
        return self.name.strip() or self.human


Target = Union[WBit, WWord]


# -----------------------------
# Helpers
# -----------------------------
def today_ymd() -> str:
    return time.strftime("%Y-%m-%d", time.localtime())


def current_ts(decimals: int) -> str:
    now = datetime.datetime.now()
    base = now.strftime("%Y-%m-%d %H:%M:%S")
    if decimals > 0:
        frac = f"{now.microsecond:06d}"[:decimals]
        return f"{base}.{frac}"
    return base


def ensure_dir_for_file(path: str) -> None:
    d = os.path.dirname(os.path.abspath(path))
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)


def dated_path(base_path: str, ymd: str) -> str:
    base_path = base_path.strip()
    root, ext = os.path.splitext(base_path)
    if not ext:
        ext = ".txt"
    return f"{root}_{ymd}{ext}"


def append_text(log_path: str, line: str) -> None:
    ensure_dir_for_file(log_path)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(line + "\n")
        f.flush()


def ensure_csv_header(csv_path: str) -> None:
    ensure_dir_for_file(csv_path)
    if os.path.exists(csv_path) and os.path.getsize(csv_path) > 0:
        return
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "event", "target", "human_addr", "device_addr", "prev", "curr", "note"])


def append_csv(csv_path: str, row: List[str]) -> None:
    ensure_csv_header(csv_path)
    with open(csv_path, "a", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(row)


# -----------------------------
# Connection Wrappers (TCP & USB/Serial)
# -----------------------------
class SerialPLCWrapper:
    """USB-to-Serial (COM 포트) 통신을 위한 래퍼 클래스 (예시)"""
    def __init__(self, port: str, baudrate: int):
        self.port = port
        self.baudrate = baudrate
        # 실제 통신 시 아래 주석 해제 및 설정
        # self.conn = serial.Serial(port=port, baudrate=baudrate, timeout=1)

    def command(self, protocol_type: str, action: str, read_type: str, addr: str):
        """
        여기에 LS Cnet 프로토콜(혹은 Modbus RTU)의 시리얼 송수신 로직을 구현합니다.
        PyXGT가 시리얼을 지원하지 않으므로 직접 바이트를 구성해서 보내고 받아 파싱해야 합니다.
        """
        # 예시로 항상 0을 반환하도록 설정 (실제 Cnet 프로토콜 파싱 로직 필요)
        # request_bytes = self.build_cnet_read_frame(addr, read_type)
        # self.conn.write(request_bytes)
        # response_bytes = self.conn.read(1024)
        # return self.parse_cnet_response(response_bytes)
        return 0 


def safe_read_data(conn, addr: str, read_type: str, retry: int, retry_delay: float) -> int:
    last_err: Optional[Exception] = None
    for _ in range(retry + 1):
        try:
            r = conn.command("XGB", "read", read_type, addr)
            if isinstance(r, list) and len(r) > 0:
                return int(r[0])
            return int(r)
        except Exception as e:
            last_err = e
            time.sleep(retry_delay)
    raise last_err


# -----------------------------
# Parse / Save / Load targets
# -----------------------------
def parse_target(s: str) -> Target:
    s = s.strip()
    m = BIT_RE.match(s)
    if m:
        area = m.group("area").upper()
        w = int(m.group("word"))
        b = int(m.group("bit"))
        if not (0 <= b <= 15):
            raise ValueError("bit는 0~15만 가능합니다.")
        return WBit(area=area, word=w, bit=b)

    m2 = WORD_RE.match(s)
    if m2:
        area = m2.group("area").upper()
        w = int(m2.group("word"))
        return WWord(area=area, word=w)

    raise ValueError(f"주소 형식 오류: {s}")


def load_config() -> Dict[str, object]:
    if not os.path.exists(CONFIG_FILE):
        return {}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def save_config(cfg_data: Dict[str, object]) -> None:
    # 기존 설정 유지하며 업데이트
    current = load_config()
    current.update(cfg_data)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(current, f, indent=2, ensure_ascii=False)


def load_targets_from_file() -> List[Target]:
    if not os.path.exists(TARGETS_FILE):
        return []
    with open(TARGETS_FILE, "r", encoding="utf-8") as f:
        data = json.load(f) or {}
    out: List[Target] = []
    for t in data.get("targets", []):
        area = str(t.get("area", "M")).upper()
        name = str(t.get("name", "") or "")
        if "bit" in t and t["bit"] is not None:
            out.append(WBit(area=area, word=int(t["word"]), bit=int(t["bit"]), name=name))
        else:
            out.append(WWord(area=area, word=int(t["word"]), name=name))
    return out


def save_targets_to_file(targets: List[Target]) -> None:
    payload = []
    for t in targets:
        if isinstance(t, WBit):
            payload.append({"type": "bit", "area": t.area, "word": t.word, "bit": t.bit, "name": t.name})
        else:
            payload.append({"type": "word", "area": t.area, "word": t.word, "bit": None, "name": t.name})
    with open(TARGETS_FILE, "w", encoding="utf-8") as f:
        json.dump({"targets": payload}, f, indent=2, ensure_ascii=False)


# -----------------------------
# Interactive input
# -----------------------------
def interactive_input() -> Dict[str, object]:
    print("=== PLC Monitor (Interactive) ===")
    cfg = load_config()
    
    # 1. 연결 방식 선택 (TCP vs USB/Serial)
    conn_type = input("Connection Type [1: TCP/IP, 2: USB/Serial(COM)] [1]: ").strip()
    use_serial = conn_type == "2"

    ip, port, com_port, baudrate = "", 2004, "", 9600

    if not use_serial:
        default_ip = str(cfg.get("last_ip", "") or "")
        default_port = int(cfg.get("last_port", 2004))
        ip = input(f"PLC IP [{default_ip}]: ").strip() or default_ip
        while not ip:
            ip = input("PLC IP (required): ").strip()
        port_s = input(f"PLC Port [{default_port}]: ").strip()
        port = default_port if not port_s else int(port_s)
        save_config({"last_ip": ip, "last_port": port, "conn_type": "tcp"})
    else:
        default_com = str(cfg.get("last_com", "COM3"))
        default_baud = int(cfg.get("last_baud", 115200))
        com_port = input(f"USB/COM Port [{default_com}]: ").strip() or default_com
        baud_s = input(f"Baudrate [{default_baud}]: ").strip()
        baudrate = default_baud if not baud_s else int(baud_s)
        save_config({"last_com": com_port, "last_baud": baudrate, "conn_type": "serial"})

    saved = load_targets_from_file()
    if saved:
        print("Saved targets found:")
        print("  " + ", ".join([f"{t.human}({t.label})" for t in saved]))
        use_saved = input("Use saved targets? (Y/n) [Y]: ").strip().lower()
        targets = saved if use_saved in ("", "y", "yes") else []
    else:
        targets = []

    if not targets:
        addrs_s = input("Addresses (ex: MW10, IW30.2): ").strip()
        addrs = [x.strip() for x in addrs_s.split(",") if x.strip()]
        if not addrs:
            raise RuntimeError("No addresses provided.")
        targets_tmp: List[Target] = []
        for a in addrs:
            t = parse_target(a)
            alias = input(f"Alias for {t.human} (optional): ").strip()
            if isinstance(t, WBit):
                targets_tmp.append(WBit(area=t.area, word=t.word, bit=t.bit, name=alias))
            else:
                targets_tmp.append(WWord(area=t.area, word=t.word, name=alias))
        targets = targets_tmp
        save_targets_to_file(targets)

    poll_interval = float(input("Poll interval seconds [0.5]: ").strip() or 0.5)
    retry = int(input("Retry count [2]: ").strip() or 2)
    verbose = input("Verbose? (y/N) [N]: ").strip().lower() in ("y", "yes")
    log_base = input("Text log base file [monitor.txt]: ").strip() or "monitor.txt"
    csv_base = input("CSV log base file [monitor.csv]: ").strip() or "monitor.csv"

    return {
        "use_serial": use_serial,
        "ip": ip,
        "port": port,
        "com_port": com_port,
        "baudrate": baudrate,
        "targets": targets,
        "poll_interval": poll_interval,
        "retry": retry,
        "retry_delay": 0.05,
        "verbose": verbose,
        "log_base": log_base,
        "csv_base": csv_base,
    }


# -----------------------------
# CLI args
# -----------------------------
def build_argparser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="PLC contact monitor (TCP & USB/Serial)")
    ap.add_argument("--serial", action="store_true", help="Use USB/Serial (COM port) instead of TCP")
    ap.add_argument("--ip", help="PLC IP address (for TCP)")
    ap.add_argument("--port", type=int, default=2004, help="PLC port (default: 2004)")
    ap.add_argument("--com", help="COM port for USB/Serial (e.g. COM3 or /dev/ttyUSB0)")
    ap.add_argument("--baud", type=int, default=115200, help="Baudrate for USB/Serial")
    ap.add_argument("--addr", action="append", help="Repeatable address like MW10.")
    ap.add_argument("--poll-interval", type=float, default=0.5)
    ap.add_argument("--retry", type=int, default=2)
    ap.add_argument("--retry-delay", type=float, default=0.05)
    ap.add_argument("--log-base", default="monitor.txt")
    ap.add_argument("--csv-base", default="monitor.csv")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--interactive", action="store_true")
    return ap


# -----------------------------
# Monitor core
# -----------------------------
def describe_targets(targets: List[Target]) -> str:
    parts = []
    for t in targets:
        if isinstance(t, WBit):
            parts.append(f"{t.human}({t.label})->{t.headdevice}")
        else:
            parts.append(f"{t.human}({t.label})->{t.headdevice}[Word]")
    return ", ".join(parts)


def run_monitor(cfg: Dict[str, object]) -> None:
    use_serial = bool(cfg.get("use_serial"))
    ip, port = str(cfg.get("ip")), int(cfg.get("port", 2004))
    com_port, baudrate = str(cfg.get("com_port")), int(cfg.get("baudrate", 115200))
    targets = cfg["targets"]
    poll_interval, retry = float(cfg["poll_interval"]), int(cfg["retry"])
    retry_delay, verbose = float(cfg["retry_delay"]), bool(cfg["verbose"])
    log_base, csv_base = str(cfg["log_base"]), str(cfg["csv_base"])

    decimals = 0
    if 0 < poll_interval < 1:
        s_frac = f"{poll_interval:.6f}".split(".")[1].rstrip("0")
        decimals = len(s_frac) if s_frac else 0

    current_day = today_ymd()
    log_path = dated_path(log_base, current_day)
    csv_path = dated_path(csv_base, current_day)

    def rotate_if_needed() -> Tuple[str, str, str]:
        nonlocal current_day, log_path, csv_path
        day = today_ymd()
        if day != current_day:
            current_day = day
            log_path = dated_path(log_base, current_day)
            csv_path = dated_path(csv_base, current_day)
            line = f"[{current_ts(decimals)}] ROTATE logs -> {os.path.basename(log_path)}"
            print(line)
            append_text(log_path, line)
            ensure_csv_header(csv_path)
        return current_day, log_path, csv_path

    print(f"[{current_ts(decimals)}] Targets:")
    for t in targets:
        print(f"  - {t.human} [{t.label}] -> {t.headdevice}")

    # 연결 설정 (TCP vs Serial)
    if use_serial:
        append_text(log_path, f"[{current_ts(decimals)}] CONNECT USB/SERIAL {com_port} ({baudrate}bps)")
        print(f"[{current_ts(decimals)}] CONNECT USB/SERIAL {com_port} ({baudrate}bps)")
        conn = SerialPLCWrapper(com_port, baudrate)
    else:
        append_text(log_path, f"[{current_ts(decimals)}] CONNECT TCP {ip}:{port}")
        print(f"[{current_ts(decimals)}] CONNECT TCP {ip}:{port}")
        conn = plc_ls(ip, port)

    ensure_csv_header(csv_path)
    last_val: Dict[str, Optional[int]] = {t.human: None for t in targets}
    fail_count = 0

    while True:
        start_time = time.perf_counter()
        _, log_path, csv_path = rotate_if_needed()

        for t in targets:
            try:
                read_type = "bit" if isinstance(t, WBit) else "word"
                v = safe_read_data(conn, t.headdevice, read_type, retry=retry, retry_delay=retry_delay)
                prev = last_val[t.human]

                if isinstance(t, WBit):
                    if prev is None:
                        last_val[t.human] = v
                        line = f"[{current_ts(decimals)}] INIT  {t.label} {t.human}({t.headdevice})={v}"
                        print(line)
                        append_text(log_path, line)
                        append_csv(csv_path, [current_ts(decimals), "INIT", t.label, t.human, t.headdevice, "", str(v), ""])
                    elif prev != v:
                        last_val[t.human] = v
                        line = f"[{current_ts(decimals)}] CHANGE {t.label} {t.human}({t.headdevice}) {prev}->{v}"
                        print(line)
                        append_text(log_path, line)
                        append_csv(csv_path, [current_ts(decimals), "CHANGE", t.label, t.human, t.headdevice, str(prev), str(v), ""])
                else:
                    val_str = f"U16:{v} / HEX:0x{v:04X} / BCD:{v:04X}"
                    if prev is None:
                        last_val[t.human] = v
                        line = f"[{current_ts(decimals)}] INIT  {t.label} {t.human} -> {val_str}"
                        print(line)
                        append_text(log_path, line)
                    elif prev != v:
                        prev_str = f"U16:{prev} / HEX:0x{prev:04X} / BCD:{prev:04X}"
                        last_val[t.human] = v
                        line = f"[{current_ts(decimals)}] CHANGE {t.label} {t.human} | {prev_str}  --->  {val_str}"
                        print(line)
                        append_text(log_path, line)
            except Exception as e:
                fail_count += 1
                line = f"[{current_ts(decimals)}] WARN read_failed {t.human} {type(e).__name__}: {e}"
                print(line)

        elapsed = time.perf_counter() - start_time
        sleep_time = poll_interval - elapsed
        if sleep_time > 0:
            time.sleep(sleep_time)


# -----------------------------
# Main
# -----------------------------
def main():
    ap = build_argparser()
    argv = sys.argv[1:]
    args = ap.parse_args(argv)

    try:
        use_interactive = args.interactive or not argv

        if use_interactive:
            cfg = interactive_input()
        else:
            cfg = {
                "use_serial": args.serial,
                "ip": args.ip,
                "port": args.port,
                "com_port": args.com,
                "baudrate": args.baud,
                "poll_interval": args.poll_interval,
                "retry": args.retry,
                "retry_delay": args.retry_delay,
                "log_base": args.log_base,
                "csv_base": args.csv_base,
                "verbose": args.verbose,
            }
            if args.addr:
                cfg["targets"] = [parse_target(x) for x in args.addr]
                save_targets_to_file(cfg["targets"])
            else:
                cfg["targets"] = load_targets_from_file()

        run_monitor(cfg)

    except Exception as e:
        print(f"\n[FATAL] {type(e).__name__}: {e}")
        try:
            input("Press Enter to exit...")
        except Exception:
            pass
        raise

if __name__ == "__main__":
    main()