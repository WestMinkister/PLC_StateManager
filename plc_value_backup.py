#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PLC Variable Values Backup
캡처 파일의 R/0xE0 요청을 리플레이하여 변수 값 백업

Usage:
    python plc_value_backup.py --dry-run                   # value_read_frames.json 분석만
    python plc_value_backup.py --read IP                   # 한 번 읽기
    python plc_value_backup.py --read IP --samples N       # N회 반복 읽기
    python plc_value_backup.py --read IP --port PORT       # 커스텀 포트
    python plc_value_backup.py --read IP --out PATH        # 출력 경로 지정
"""
import json
import sys
import os
import time
import struct
import argparse
from pathlib import Path
from datetime import datetime

# Add src directory to path for imports
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)
if hasattr(sys, '_MEIPASS') and sys._MEIPASS not in sys.path:
    sys.path.insert(0, sys._MEIPASS)


def resource_path(relative_path: str) -> str:
    """Resolve a resource file path, handling PyInstaller --onefile bundles.

    PyInstaller extracts --add-data files to sys._MEIPASS. When running from
    source, fall back to the script's directory."""
    base = getattr(sys, '_MEIPASS', script_dir)
    return os.path.join(base, relative_path)

try:
    from plc_upload_test import PLCUploadClient, DEFAULT_PORT
except ImportError as e:
    print(f"Error: failed to import plc_upload_test: {e}")
    sys.exit(1)


def decode_response_payload(response_payload_hex_ascii):
    """
    Decode R/0xE0 response payload to extract values.

    The response is ASCII hex like request: "333030..." → bytes → hex string → bytes
    Each pair of bytes is a LE16 word.

    Returns:
        {
            'raw_hex': str,
            'values': [int, ...] - one per variable (LE16)
        }
    """
    if not response_payload_hex_ascii:
        return {'raw_hex': '', 'values': []}

    try:
        # Decode ASCII hex to bytes
        response_bytes_ascii = bytes.fromhex(response_payload_hex_ascii)
        # Decode bytes to hex string
        response_hex = response_bytes_ascii.decode('ascii', errors='replace')
        # Decode hex string to bytes
        response_bytes = bytes.fromhex(response_hex)
    except (ValueError, UnicodeDecodeError) as e:
        return {'error': str(e), 'raw_hex': response_payload_hex_ascii, 'values': []}

    # Parse as LE16 words
    values = []
    pos = 0
    while pos + 2 <= len(response_bytes):
        word = struct.unpack('<H', response_bytes[pos:pos+2])[0]
        values.append(word)
        pos += 2

    return {
        'raw_hex': response_hex,
        'values': values
    }


def main():
    parser = argparse.ArgumentParser(
        description='Backup PLC variable values by replaying R/0xE0 commands with monitor mode entry'
    )
    parser.add_argument('--dry-run', action='store_true',
                        help='Analyze frames only (no network)')
    parser.add_argument('--read', type=str, metavar='IP',
                        help='PLC IP address for live read')
    parser.add_argument('--samples', type=int, default=1,
                        help='Number of read passes (default: 1)')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT,
                        help=f'PLC port (default: {DEFAULT_PORT})')
    parser.add_argument('--out', type=str, default='snapshots/values.json',
                        help='Output snapshot file')

    args = parser.parse_args()

    # Load value_read_frames.json
    frames_file = Path(resource_path('value_read_frames.json'))
    if not frames_file.exists():
        print(f"Error: value_read_frames.json not found")
        print(f"  Tried: {frames_file}")
        print(f"  _MEIPASS: {getattr(sys, '_MEIPASS', 'not set')}")
        print(f"  CWD: {os.getcwd()}")
        sys.exit(1)

    try:
        with open(frames_file, encoding='utf-8') as f:
            frames_data = json.load(f)
    except Exception as e:
        print(f"Error loading frames: {e}")
        sys.exit(1)

    variables = frames_data.get('variables', [])
    monitor_entries = frames_data.get('monitor_entry_frames', [])
    conn_frame_hex = frames_data.get('conn_frame_hex')
    j_heartbeat_hex = frames_data.get('j_heartbeat_frame_hex')
    read_request_hex = frames_data.get('read_request_frame_hex')
    disc_frame_hex = frames_data.get('disc_frame_hex')

    if not all([conn_frame_hex, monitor_entries, read_request_hex, variables]):
        print("Error: value_read_frames.json missing required fields")
        print(f"  conn: {conn_frame_hex is not None}")
        print(f"  monitor_entries: {len(monitor_entries)} frames")
        print(f"  read_request: {read_request_hex is not None}")
        print(f"  variables: {len(variables)} vars")
        sys.exit(1)

    print(f"Loaded {len(variables)} variables, {len(monitor_entries)} monitor entry frames")
    var_str = ', '.join(f"0x{v['offset']:04x}" for v in variables[:5])
    var_str += "..." if len(variables) > 5 else ""
    print(f"Variables: {var_str}")

    # Dry-run mode
    if args.dry_run:
        print("\n=== Dry-run mode (no network) ===")
        print(f"CONN frame: {conn_frame_hex[:40]}...")
        print(f"Monitor entry frames:")
        for entry in monitor_entries:
            print(f"  {entry['cmd']}/{entry['sub_cmd']}: {entry['note']}")
        print(f"J heartbeat: {j_heartbeat_hex[:40] if j_heartbeat_hex else '(not set)'}...")
        print(f"R/0xE0 template: {read_request_hex[:40]}...")
        print(f"DISC frame: {disc_frame_hex[:40] if disc_frame_hex else '(not set)'}...")
        print(f"\nWould send:")
        print(f"  1. CONN frame")
        if j_heartbeat_hex:
            print(f"  2. J heartbeat (optional priming)")
        print(f"  3. Monitor entry frames (Z/0x8D + Z/0x8E)")
        print(f"  4. {args.samples} R/0xE0 read(s)")
        if disc_frame_hex:
            print(f"  5. DISC frame")
        return

    # Live read mode
    if not args.read:
        print("Error: Use --dry-run or --read IP")
        sys.exit(1)

    print(f"\n=== Connecting to PLC {args.read}:{args.port} ===")
    client = PLCUploadClient(args.read, args.port, timeout=5.0)

    try:
        client.connect()
    except Exception as e:
        print(f"✗ Connection failed: {e}")
        sys.exit(1)

    # Collect samples
    samples = []
    try:
        # 1. CONN frame
        print("  [SESSION] Sending CONN frame...")
        conn_bytes = bytes.fromhex(conn_frame_hex)
        resp = client.send_frame(conn_bytes)
        if not resp:
            print("  ✗ CONN response not received")
            sys.exit(1)
        resp_len = len(resp.get('raw', b''))
        print(f"  ✓ CONN OK ({resp_len}B response)")
        time.sleep(0.3)

        # 2. J heartbeat (optional priming)
        if j_heartbeat_hex:
            print("  [PRIMING] Sending J heartbeat...")
            j_bytes = bytes.fromhex(j_heartbeat_hex)
            resp = client.send_frame(j_bytes)
            if resp:
                print(f"  ✓ J/0x34 OK")
            else:
                print(f"  ⚠ J/0x34 NO RESPONSE (continuing anyway)")
            time.sleep(0.05)

        # 3. Monitor mode entry: Z/0x8D + Z/0x8E
        print("  [MONITOR] Entering monitor mode...")
        for entry in monitor_entries:
            frame_hex = entry.get('frame_hex')
            cmd = entry.get('cmd')
            sub_cmd = entry.get('sub_cmd')
            note = entry.get('note', '')

            if not frame_hex:
                print(f"  ⚠ {cmd}/{sub_cmd}: NO FRAME HEX")
                continue

            try:
                frame_bytes = bytes.fromhex(frame_hex)
                resp = client.send_frame(frame_bytes)
                status = "OK" if resp else "NO RESPONSE"
                print(f"  {cmd}/{sub_cmd}: {status} ({note})")
                time.sleep(0.05)
            except Exception as e:
                print(f"  ✗ {cmd}/{sub_cmd}: {e}")

        # 4. R/0xE0 polling
        print(f"  [READ] Starting R/0xE0 polls...")
        for sample_num in range(args.samples):
            if args.samples > 1:
                print(f"\n  Sample {sample_num + 1}/{args.samples}...")

            try:
                req_bytes = bytes.fromhex(read_request_hex)
                resp = client.send_frame(req_bytes)

                if resp and resp.get('raw'):
                    # R/0xE0 응답은 byte[26:]부터 payload (sub_cmd echo 없음).
                    # parse_response가 byte[26]을 sub_cmd로 잘못 소비하므로
                    # raw 바이트에서 직접 추출.
                    raw = resp['raw']
                    sig_pos = raw.find(b'LGIS-GLOFA')
                    if sig_pos >= 0 and len(raw) > sig_pos + 26:
                        payload_bytes = raw[sig_pos + 26:]
                        payload_hex = payload_bytes.hex()
                        decoded = decode_response_payload(payload_hex)
                        sample_values = decoded.get('values', [])
                        samples.append(sample_values)
                        vals_preview = sample_values[:5]
                        print(f"    ✓ READ OK: {len(sample_values)} values {vals_preview}")
                    else:
                        print(f"    ✗ READ: response too short ({len(raw)}B)")
                else:
                    print(f"    ✗ READ NO RESPONSE")

            except Exception as e:
                print(f"    ✗ READ ERROR: {e}")

            if args.samples > 1 and sample_num < args.samples - 1:
                time.sleep(0.5)  # polling interval between samples

        # 5. DISC frame
        if disc_frame_hex:
            print("  [SESSION] Sending DISC frame...")
            try:
                disc_bytes = bytes.fromhex(disc_frame_hex)
                client.send_frame(disc_bytes)
                print(f"  ✓ DISC OK")
            except Exception as e:
                print(f"  ⚠ DISC error: {e}")

    finally:
        client.disconnect()

    # Build output snapshot
    output = {
        'timestamp': datetime.now().isoformat(),
        'plc_ip': args.read,
        'sample_count': len(samples),
        'variable_count': len(variables),
        'variables': variables,
        'samples': samples,
        'values_latest': {}
    }

    # Build latest values dict (if we have samples)
    if samples and samples[-1]:
        for var_idx, var in enumerate(variables):
            if var_idx < len(samples[-1]):
                key = f"{var['marker_hex']}_0x{var['offset']:04x}"
                output['values_latest'][key] = samples[-1][var_idx]

    # Save output
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        print(f"\n✓ Saved snapshot to {out_path}")
        print(f"  Samples: {len(samples)}, Latest values: {len(output['values_latest'])}")
    except Exception as e:
        print(f"Error saving snapshot: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
