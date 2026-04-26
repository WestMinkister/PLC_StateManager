#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PLC Upload Test Client
캡처 D의 프레임을 리플레이하여 PLC에서 프로그램 읽기 테스트

Usage:
    python plc_upload_test.py --dry-run              # 프레임 분석만 (네트워크 접속 없음)
    python plc_upload_test.py --replay 192.168.250.110  # 실제 PLC에 리플레이
"""
import socket
import struct
import json
import sys
import os
import time
import argparse

# ============================================================
# Protocol Constants
# ============================================================
SIGNATURE = b'LGIS-GLOFA'
PLC_INFO_CLIENT = b'\x00\x00'
CPU_INFO_CLIENT = 0x00
SOURCE_CLIENT = 0x22
SOURCE_PLC = 0x11
FRAME_TYPE_CMD = b'\x0e\x00'
FRAME_TYPE_RSP = b'\x0f\x00'
FRAME_TYPE_CONN = b'\x0a\x00'
FRAME_TYPE_DISC = b'\x12\x00'
DEFAULT_PORT = 2002

# Safety whitelist - NEVER send write commands
SAFE_COMMANDS = {0x4A, 0x52, 0x5A, 0x45, 0x58, 0x59, 0x4D, 0x57}  # J,R,Z,E,X,Y,M,W
# Note: E here is for reading metadata, not for writing (E-write uses T(S)/T(E) transaction)
# T (0x54) and P (0x50) are excluded as they can change PLC state
DANGEROUS_COMMANDS = {0x54, 0x50}  # T, P - can start transactions or change modes


def build_frame(command_byte, payload=b'', frame_type=FRAME_TYPE_CMD):
    """Build a complete LGIS-GLOFA frame.

    Args:
        command_byte: single int (e.g., 0x4A for 'J')
        payload: bytes after the command byte
        frame_type: 2-byte frame type (default: command 0x0E00)

    Returns:
        bytes: complete frame ready to send
    """
    cmd_data = bytes([command_byte]) + payload
    cmd_data_len = len(cmd_data)

    # Length field = frame_type(2) + cmd_data_len_field(2) + cmd_data
    length = 2 + 2 + cmd_data_len

    # Build 20-byte header (BCC placeholder at byte 19)
    header = bytearray(20)
    header[0:10] = SIGNATURE
    header[10:12] = PLC_INFO_CLIENT
    header[12] = CPU_INFO_CLIENT
    header[13] = SOURCE_CLIENT
    header[14:16] = struct.pack('<H', 0)  # Invoke ID = 0
    header[16:18] = struct.pack('<H', length)
    header[18] = 0x00  # FEnet Position
    header[19] = sum(header[0:19]) % 256  # BCC

    # Build sub-header
    sub_header = frame_type + struct.pack('<H', cmd_data_len)

    return bytes(header) + sub_header + cmd_data


def parse_response(data):
    """Parse a PLC→PC LGIS-GLOFA response.

    Returns dict with parsed fields, or None if invalid.
    """
    sig_pos = data.find(SIGNATURE)
    if sig_pos < 0:
        return None

    frame = data[sig_pos:]
    if len(frame) < 24:
        return None

    result = {}

    # 20-byte header
    result['plc_info'] = struct.unpack('<H', frame[10:12])[0]
    result['cpu_info'] = frame[12]
    result['source'] = frame[13]
    result['invoke_id'] = struct.unpack('<H', frame[14:16])[0]
    result['length'] = struct.unpack('<H', frame[16:18])[0]
    result['fenet'] = frame[18]
    result['bcc'] = frame[19]
    result['bcc_valid'] = (frame[19] == sum(frame[0:19]) % 256)

    # Sub-header
    result['frame_type'] = frame[20:22]
    result['cmd_data_len'] = struct.unpack('<H', frame[22:24])[0]

    # Command data
    if len(frame) > 24:
        if frame[20:22] == FRAME_TYPE_RSP:
            # Response: status + command echo + sub_cmd + data
            if len(frame) > 24:
                result['status'] = frame[24]
            if len(frame) > 25:
                result['command'] = frame[25]
                result['command_char'] = chr(frame[25]) if 32 <= frame[25] < 127 else f'0x{frame[25]:02x}'
            if len(frame) > 26:
                result['sub_cmd'] = frame[26]
            if len(frame) > 27:
                result['payload'] = frame[27:]
                result['payload_hex'] = frame[27:].hex()
        else:
            result['command'] = frame[24]
            result['command_char'] = chr(frame[24]) if 32 <= frame[24] < 127 else f'0x{frame[24]:02x}'
            if len(frame) > 25:
                result['sub_cmd'] = frame[25]
            if len(frame) > 26:
                result['payload'] = frame[26:]

    result['raw'] = frame
    result['raw_hex'] = frame.hex()

    return result


class PLCUploadClient:
    """TCP client for PLC program upload (read) via LGIS-GLOFA protocol."""

    def __init__(self, plc_ip, plc_port=DEFAULT_PORT, timeout=5.0):
        self.plc_ip = plc_ip
        self.plc_port = plc_port
        self.timeout = timeout
        self._sock = None
        self._recv_buffer = b''
        self.responses = []        # parsed response dicts
        self.responses_raw = []    # raw response bytes (for scan_responses_bytes)

    def connect(self):
        """Establish TCP connection to PLC."""
        print(f"Connecting to PLC at {self.plc_ip}:{self.plc_port}...")
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(self.timeout)
        self._sock.connect((self.plc_ip, self.plc_port))
        print(f"Connected!")

    def disconnect(self):
        """Close TCP connection."""
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
            print("Disconnected.")

    def send_frame(self, frame_bytes):
        """Send raw frame bytes and receive response.

        Args:
            frame_bytes: complete frame to send

        Returns:
            parsed response dict, or None on error
        """
        if not self._sock:
            raise RuntimeError("Not connected")

        # Safety check - verify command is in whitelist (only for 0x0E command frames)
        if len(frame_bytes) >= 22:
            ft = struct.unpack('<H', frame_bytes[20:22])[0]
            if ft == 0x0E and len(frame_bytes) > 24:
                cmd_byte = frame_bytes[24]
                if cmd_byte in DANGEROUS_COMMANDS:
                    print(f"  ⚠ BLOCKED dangerous command 0x{cmd_byte:02x} ({chr(cmd_byte)})")
                    return None

        self._sock.sendall(frame_bytes)

        # Receive response
        try:
            response_data = b''
            while True:
                chunk = self._sock.recv(65536)
                if not chunk:
                    break
                response_data += chunk

                # Check if we have a complete frame
                sig_pos = response_data.find(SIGNATURE)
                if sig_pos >= 0 and len(response_data) >= sig_pos + 20:
                    # Read length field
                    length = struct.unpack('<H', response_data[sig_pos+16:sig_pos+18])[0]
                    total_expected = sig_pos + 20 + length
                    if len(response_data) >= total_expected:
                        break

            if response_data:
                # Store raw response bytes for scan_responses_bytes (Live AST extraction)
                self.responses_raw.append(response_data)
                parsed = parse_response(response_data)
                if parsed:
                    self.responses.append(parsed)
                return parsed
            return None

        except socket.timeout:
            print("  ⏱ Response timeout")
            return None

    @staticmethod
    def reorder_frames(frames_json):
        """Reorder frames: 1 CONN first, commands in order, 1 DISC last."""
        conn_frames = [f for f in frames_json if f.get('frame_type') == 0x0A]
        cmd_frames = [f for f in frames_json if f.get('frame_type') == 0x0E]
        disc_frames = [f for f in frames_json if f.get('frame_type') == 0x12]

        ordered = []
        if conn_frames:
            ordered.append(conn_frames[0])  # 첫 번째 CONN만
        ordered.extend(cmd_frames)          # 명령 프레임들 (원래 순서)
        if disc_frames:
            ordered.append(disc_frames[0])  # 첫 번째 DISC만

        return ordered

    def replay_frames(self, frames_json, delay=0.1, max_consecutive_errors=5):
        """Replay captured frames from JSON file.

        Args:
            frames_json: list of frame dicts from upload_replay_frames.json
            delay: seconds between frames (default 100ms)
            max_consecutive_errors: stop after N consecutive NO RESPONSEs
        """
        # Reorder: CONN → commands → DISC
        ordered = self.reorder_frames(frames_json)
        total = len(ordered)
        success = 0
        errors = 0
        consecutive_errors = 0

        print(f"\nReplaying {total} frames (reordered: CONN → commands → DISC)...")
        print(f"{'#':>3} {'Frame':<25} {'Send':>5}   {'Recv':>5} {'Rsp':>4} {'Status'}")
        print("-" * 65)

        for i, frame_data in enumerate(ordered):
            frame_hex = frame_data.get('frame_hex', '')
            if not frame_hex:
                continue

            frame_bytes = bytes.fromhex(frame_hex)
            frame_type = frame_data.get('frame_type')
            cmd = frame_data.get('command', '?')
            sub_hex = frame_data.get('sub_cmd_hex', '?')

            # Label for display
            if frame_type == 0x0A:
                label = f"CONN ({frame_data.get('plc_ip', '?')})"
            elif frame_type == 0x12:
                label = "DISC"
            else:
                label = f"{cmd:>4} {sub_hex}"

            # Send and receive
            response = self.send_frame(frame_bytes)

            if response:
                rsp_cmd = response.get('command_char', '?')
                rsp_len = len(response.get('raw', b''))
                status = f"0x{response.get('status', 0):02x}" if 'status' in response else '-'
                bcc_ok = "✓" if response.get('bcc_valid') else "✗"
                print(f"{i:>3} {label:<25} {len(frame_bytes):>5}B → {rsp_len:>5}B {rsp_cmd:>4} {status} {bcc_ok}")
                success += 1
                consecutive_errors = 0

                # CONN 후 추가 대기 (세션 안정화)
                if frame_type == 0x0A:
                    time.sleep(0.3)
            else:
                print(f"{i:>3} {label:<25} {len(frame_bytes):>5}B → NO RESPONSE")
                errors += 1
                consecutive_errors += 1

                if consecutive_errors >= max_consecutive_errors:
                    print(f"\n⚠ {max_consecutive_errors}회 연속 무응답 — 리플레이 중단")
                    break

            if delay > 0:
                time.sleep(delay)

        print(f"\nResults: {success} successful, {errors} errors out of {total} frames")
        return success, errors

    def extract_ast_live(self, frames_json_path, ast_output_path='program_ast.json'):
        """Live PLC 통신 → AST 추출 통합.

        1. frames_json으로 표준 "PLC로부터 열기" sequence 재전송
        2. raw response bytes 모음 (responses_raw)
        3. scan_responses_bytes()로 token 추출
        4. ProgramASTBuilder.load_responses()로 AST build
        5. ast_output_path에 dump

        Args:
            frames_json_path: 캡처된 frame sequence JSON 경로
            ast_output_path: 출력 AST JSON 경로

        Returns:
            AST dict
        """
        from plc_bytecode_scanner import scan_responses_bytes
        from plc_program_parser import ProgramASTBuilder

        # Load frames
        with open(frames_json_path, encoding='utf-8') as f:
            frames = json.load(f)

        # Replay frames and collect raw responses
        print(f"Replaying frames from {frames_json_path}...")
        self.connect()
        try:
            self.replay_frames(frames, delay=0.1)
        finally:
            self.disconnect()

        if not self.responses_raw:
            print("⚠ No responses received from PLC")
            return None

        print(f"\n✓ Collected {len(self.responses_raw)} raw response bytes")

        # Extract tokens from raw responses
        print("Extracting tokens from responses...")
        scanned = scan_responses_bytes(self.responses_raw)
        print(f"✓ Scanned {len(scanned)} responses, {sum(r.get('token_count', 0) for r in scanned)} total tokens")

        # Build AST
        print("Building AST from tokens...")
        builder = ProgramASTBuilder(use_il=False)  # No IL in live mode
        builder.load_responses(scanned, source_label=f'live:{self.plc_ip}:{self.plc_port}')
        ast = builder.build()

        # Dump to JSON
        with open(ast_output_path, 'w', encoding='utf-8') as f:
            json.dump(ast, f, ensure_ascii=False, indent=2)
        print(f"✓ AST written to {ast_output_path}")

        return ast


def dry_run(replay_path):
    """Analyze replay frames without connecting to PLC."""
    with open(replay_path) as f:
        frames = json.load(f)

    print(f"Loaded {len(frames)} replay frames from {replay_path}")
    print()

    # Command summary
    cmd_counts = {}
    sub_cmd_counts = {}
    for frame in frames:
        cmd = frame.get('command', '?')
        cmd_counts[cmd] = cmd_counts.get(cmd, 0) + 1
        if cmd == 'Z':
            sub = frame.get('sub_cmd_hex', '?')
            sub_cmd_counts[sub] = sub_cmd_counts.get(sub, 0) + 1

    print("Command summary:")
    for cmd in sorted(cmd_counts.keys()):
        print(f"  {cmd}: {cmd_counts[cmd]}")

    print(f"\nZ sub-command breakdown ({sum(sub_cmd_counts.values())} total):")
    for sub in sorted(sub_cmd_counts.keys()):
        print(f"  {sub}: {sub_cmd_counts[sub]}")

    # Safety check
    print("\nSafety check:")
    has_dangerous = False
    for frame in frames:
        cmd_byte = frame.get('command_byte')
        if cmd_byte and cmd_byte in [0x54, 0x50]:  # T, P
            print(f"  ⚠ WARNING: Frame #{frame.get('index')} contains dangerous command {chr(cmd_byte)} (0x{cmd_byte:02x})")
            has_dangerous = True
    if not has_dangerous:
        print("  ✓ No dangerous commands (T/P) found in replay data")

    # Frame size summary
    total_bytes = sum(len(bytes.fromhex(f.get('frame_hex', ''))) for f in frames)
    print(f"\nTotal data to send: {total_bytes:,} bytes")
    print(f"Average frame size: {total_bytes // len(frames)} bytes")

    # Validate BCC for all frames
    bcc_ok = 0
    for frame in frames:
        frame_bytes = bytes.fromhex(frame.get('frame_hex', ''))
        if len(frame_bytes) >= 20:
            expected = sum(frame_bytes[0:19]) % 256
            if frame_bytes[19] == expected:
                bcc_ok += 1
    print(f"BCC validation: {bcc_ok}/{len(frames)} valid")


def main():
    parser = argparse.ArgumentParser(description='PLC Upload Test Client')
    parser.add_argument('--dry-run', action='store_true',
                        help='Analyze replay frames only (no network)')
    parser.add_argument('--replay', metavar='PLC_IP',
                        help='Replay frames to PLC at given IP')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT,
                        help=f'PLC port (default: {DEFAULT_PORT})')
    parser.add_argument('--delay', type=float, default=0.05,
                        help='Delay between frames in seconds (default: 0.05)')
    parser.add_argument('--frames', default=None,
                        help='Path to replay frames JSON (default: upload_replay_frames.json)')
    parser.add_argument('--save-responses', metavar='PATH',
                        help='Save responses to JSON file')

    args = parser.parse_args()

    # Find replay frames file
    replay_path = args.frames
    if not replay_path:
        replay_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   'upload_replay_frames.json')

    if not os.path.exists(replay_path):
        print(f"ERROR: Replay frames not found: {replay_path}")
        print("Run plc_upload_analyze.py first to generate replay data.")
        sys.exit(1)

    if args.dry_run:
        dry_run(replay_path)
        return

    if args.replay:
        with open(replay_path) as f:
            frames = json.load(f)

        print(f"Loaded {len(frames)} replay frames")
        print(f"Target: {args.replay}:{args.port}")
        print()

        client = PLCUploadClient(args.replay, args.port)
        try:
            client.connect()
            success, errors = client.replay_frames(frames, delay=args.delay)

            # Save responses if requested
            if args.save_responses and client.responses:
                save_data = []
                for r in client.responses:
                    entry = {}
                    for k, v in r.items():
                        if isinstance(v, bytes):
                            entry[k + '_hex'] = v.hex()
                        else:
                            entry[k] = v
                    save_data.append(entry)
                with open(args.save_responses, 'w') as f:
                    json.dump(save_data, f, indent=2)
                print(f"\nResponses saved to: {args.save_responses}")

        except ConnectionRefusedError:
            print(f"ERROR: Connection refused by {args.replay}:{args.port}")
            print("Is the PLC powered on and network connected?")
        except socket.timeout:
            print(f"ERROR: Connection timeout to {args.replay}:{args.port}")
        except Exception as e:
            print(f"ERROR: {e}")
        finally:
            client.disconnect()
        return

    # No action specified
    parser.print_help()


if __name__ == '__main__':
    main()
