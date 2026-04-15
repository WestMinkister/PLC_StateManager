#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PLC Variable Values Backup
캡처 파일의 R/0xE0 요청을 리플레이하여 변수 값 백업

Usage:
    python plc_value_backup.py --dry-run                   # value_read_frames.json 분석만
    python plc_value_backup.py --read IP                   # 한 번 읽기
    python plc_value_backup.py --read IP --samples N       # N회 반복 읽기
    python plc_value_backup.py --read IP --frames PATH --out PATH
"""
import socket
import struct
import json
import sys
import os
import time
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
    from plc_upload_test import build_frame, parse_response
except ImportError as e:
    print(f"Error: failed to import plc_upload_test: {e}")
    sys.exit(1)


class PLCValueBackupClient:
    """Connect to PLC and replay value read commands."""

    DEFAULT_PORT = 2002

    def __init__(self, plc_ip, port=DEFAULT_PORT, timeout=5):
        self.plc_ip = plc_ip
        self.port = port
        self.timeout = timeout
        self.sock = None

    def connect(self):
        """Establish TCP connection to PLC."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        try:
            self.sock.connect((self.plc_ip, self.port))
        except socket.error as e:
            raise RuntimeError(f"Failed to connect to {self.plc_ip}:{self.port}: {e}")

    def close(self):
        """Close connection."""
        if self.sock:
            self.sock.close()
            self.sock = None

    def send_raw_frame(self, frame_bytes):
        """Send raw frame bytes and receive response."""
        if not self.sock:
            raise RuntimeError("Not connected")

        try:
            self.sock.sendall(frame_bytes)
            response = self.sock.recv(4096)
            return response
        except socket.error as e:
            raise RuntimeError(f"Socket error: {e}")

    def send_command(self, command_byte, payload):
        """Build and send a command frame."""
        frame = build_frame(command_byte, payload)
        return self.send_raw_frame(frame)


def load_value_read_frames(frames_file):
    """Load value_read_frames.json and extract R/0xE0 request payloads."""
    with open(frames_file) as f:
        data = json.load(f)

    variables = data['variables']
    requests = [p for p in data['pairs']]

    return {
        'variables': variables,
        'pairs': requests
    }


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
        description='Backup PLC variable values by replaying R/0xE0 commands'
    )
    parser.add_argument('--dry-run', action='store_true',
                        help='Analyze frames only (no network)')
    parser.add_argument('--read', type=str, metavar='IP',
                        help='PLC IP address for live read')
    parser.add_argument('--samples', type=int, default=1,
                        help='Number of read passes (default: 1)')
    parser.add_argument('--frames', type=str, default=None,
                        help='Input frames file (default: bundled value_read_frames.json)')
    parser.add_argument('--out', type=str, default='snapshots/values.json',
                        help='Output snapshot file')

    args = parser.parse_args()

    # Load frames — use resource_path for bundled default, explicit path as-is
    if args.frames:
        frames_file = Path(args.frames)
    else:
        frames_file = Path(resource_path('value_read_frames.json'))

    if not frames_file.exists():
        print(f"Error: value_read_frames.json not found")
        print(f"  Tried: {frames_file}")
        print(f"  _MEIPASS: {getattr(sys, '_MEIPASS', 'not set')}")
        print(f"  CWD: {os.getcwd()}")
        if args.frames:
            print(f"  (Custom path via --frames: {args.frames})")
        sys.exit(1)

    try:
        frames_data = load_value_read_frames(frames_file)
    except Exception as e:
        print(f"Error loading frames: {e}")
        sys.exit(1)

    variables = frames_data['variables']
    pairs = frames_data['pairs']

    if not pairs:
        print("Error: No R/0xE0 pairs in frames file")
        sys.exit(1)

    print(f"Loaded {len(variables)} variables from {len(pairs)} pairs")
    var_str = ', '.join(f"0x{v['offset']:04x}" for v in variables[:5])
    var_str += "..." if len(variables) > 5 else ""
    print(f"Variables: {var_str}")

    # Dry-run mode
    if args.dry_run:
        print("\n=== Dry-run mode (no network) ===")
        print(f"Would send {len(pairs)} R/0xE0 request(s)")
        print(f"Sample request payload: {pairs[0]['request_payload_hex'][:100]}...")
        return

    # Live read mode
    if not args.read:
        print("Error: Use --dry-run or --read IP")
        sys.exit(1)

    print(f"\n=== Connecting to PLC {args.read} ===")
    client = PLCValueBackupClient(args.read)

    try:
        client.connect()
        print(f"✓ Connected to {args.read}:{client.DEFAULT_PORT}")
    except RuntimeError as e:
        print(f"✗ Connection failed: {e}")
        sys.exit(1)

    # Collect samples
    samples = []
    try:
        for sample_num in range(args.samples):
            print(f"\nSample {sample_num + 1}/{args.samples}...")
            sample_values = []

            # Send each request
            for pair_idx, pair in enumerate(pairs):
                req_payload_hex = pair['request_payload_hex']

                try:
                    # Convert ASCII hex payload to bytes for sending
                    req_bytes_ascii = bytes.fromhex(req_payload_hex)
                    req_hex_str = req_bytes_ascii.decode('ascii')
                    req_bytes = bytes.fromhex(req_hex_str)

                    # Send R command (0x52) with sub 0xE0
                    response = client.send_command(0x52, bytes([0xE0]) + req_bytes)

                    # Parse response
                    rsp_analysis = parse_response(response)
                    if rsp_analysis and 'cmd_payload_hex' in rsp_analysis:
                        rsp_payload = rsp_analysis['cmd_payload_hex']
                        decoded = decode_response_payload(rsp_payload)
                        sample_values.extend(decoded['values'])
                        print(f"  Pair {pair_idx}: {len(decoded['values'])} values")
                    else:
                        print(f"  Pair {pair_idx}: No valid response")

                except Exception as e:
                    print(f"  Pair {pair_idx}: Error - {e}")

            if sample_values:
                samples.append(sample_values)

    finally:
        client.close()
        print(f"\n✓ Disconnected")

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
        with open(out_path, 'w') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        print(f"✓ Saved snapshot to {out_path}")
        print(f"  Samples: {len(samples)}, Latest values: {len(output['values_latest'])}")
    except Exception as e:
        print(f"Error saving snapshot: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
