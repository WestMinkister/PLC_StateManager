#!/usr/bin/env python3
"""PLC Variable Reader — XGT Protocol (Port 2004)

Official LS Electric XGB FEnet protocol (Chapter 5) implementation.
All fields use LITTLE ENDIAN unless otherwise specified.

No CONN frame, no priming, no monitor mode — just TCP connect and read.

Usage:
    python plc_xgt_reader.py --read IP --mw 0 152 3000 1002 6000
    python plc_xgt_reader.py --read IP --iw 5000
    python plc_xgt_reader.py --read IP --config variables.json
    python plc_xgt_reader.py --scan IP --range 0 10000
    python plc_xgt_reader.py --scan IP --range 0 10000 --export variables.json
"""
import socket
import struct
import json
import sys
import time
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Any

XGT_SIG = b'LSIS-XGT\x00\x00'
XGT_PORT = 2004
SRC_CLIENT = 0x33
TIMEOUT = 5.0

# Data type codes (LE16)
DTYPE_BIT = 0x0000
DTYPE_BYTE = 0x0001
DTYPE_WORD = 0x0002
DTYPE_DWORD = 0x0003
DTYPE_CONT = 0x0014  # Continuous byte block (0x1400 in LE)

# Command codes (LE16)
CMD_READ_REQ = 0x0054
CMD_READ_RESP = 0x0055


def _build_header(payload_len: int) -> bytes:
    """Build 20-byte XGT header with correct little-endian fields.

    Header structure (ALL little-endian):
        [0:10]   LSIS-XGT\x00\x00 (signature)
        [10:12]  PLC Info (LE16, 0x0000)
        [12]     CPU Info (0xA0 = client can ignore)
        [13]     Source (0x33 = client→PLC)
        [14:16]  Invoke ID (LE16, 0x0000)
        [16:18]  Payload length (LE16)
        [18]     FEnet Position (0x00)
        [19]     BCC checksum = sum(header[0:19]) % 256
    """
    h = bytearray(20)
    h[0:10] = XGT_SIG
    h[10:12] = struct.pack('<H', 0x0000)  # PLC Info
    h[12] = 0xA0                          # CPU Info
    h[13] = SRC_CLIENT                    # Source
    h[14:16] = struct.pack('<H', 0x0000) # Invoke ID
    h[16:18] = struct.pack('<H', payload_len)  # Payload length (LE16)
    h[18] = 0x00                          # FEnet Position
    h[19] = sum(h[0:19]) % 256            # BCC
    return bytes(h)


def build_read_request(address_str: str, data_type: int = DTYPE_WORD) -> bytes:
    """Build individual read request for one address (표 5-7).

    Args:
        address_str: Address like '%MW0', '%MW1002', '%IW5000', '%MX48000'
        data_type: DTYPE_WORD (0x0002), DTYPE_BIT (0x0000), etc.

    Returns:
        Complete XGT frame ready to send on port 2004
    """
    addr = address_str.encode('ascii')

    payload = bytearray()
    payload += struct.pack('<H', CMD_READ_REQ)      # Command: 0x0054 (LE)
    payload += struct.pack('<H', data_type)         # Data Type (LE)
    payload += struct.pack('<H', 0x0000)            # Reserved (LE)
    payload += struct.pack('<H', 1)                 # Block Count: 1 (LE)
    payload += struct.pack('<H', len(addr))         # Variable Length (LE)
    payload += addr                                  # Address ASCII

    return _build_header(len(payload)) + bytes(payload)


def build_continuous_read_request(start_mb_addr: int, byte_count: int) -> bytes:
    """Build continuous block read request (표 5-9).

    Reads a continuous block of bytes from %MB{start_mb_addr}.

    Args:
        start_mb_addr: Starting byte address (e.g., 0 for %MB0, 100 for %MB100)
        byte_count: Number of bytes to read

    Returns:
        Complete XGT frame
    """
    addr = f'%MB{start_mb_addr}'.encode('ascii')

    payload = bytearray()
    payload += struct.pack('<H', CMD_READ_REQ)      # Command: 0x0054
    payload += struct.pack('<H', DTYPE_CONT)        # Data Type: Continuous (0x0014)
    payload += struct.pack('<H', 0x0000)            # Reserved
    payload += struct.pack('<H', 1)                 # Block Count
    payload += struct.pack('<H', len(addr))         # Variable Length
    payload += addr                                  # Start address
    payload += struct.pack('<H', byte_count)        # Data Count (bytes)

    return _build_header(len(payload)) + bytes(payload)


def parse_response(data: bytes) -> Optional[Dict[str, Any]]:
    """Parse read response (표 5-8).

    Response structure after 20-byte header:
        [20:22]  Command: 0x0055 (LE16)
        [22:24]  Data Type echo (LE16)
        [24:26]  Reserved (LE16)
        [26:28]  Error State (LE16, 0=OK)
        [28:30]  Block Count (LE16)
        [30:32]  Data Size (LE16, in bytes for continuous)
        [32:]    Raw value data

    Returns:
        {'cmd': int, 'dtype': int, 'error': int, 'block_count': int, 'data_size': int, 'raw_data': bytes}
        or None if parse failed
    """
    if len(data) < 32:
        return None

    sig = data.find(XGT_SIG)
    if sig < 0:
        return None

    frame = data[sig:]
    if len(frame) < 32:
        return None

    cmd = struct.unpack('<H', frame[20:22])[0]
    dtype = struct.unpack('<H', frame[22:24])[0]
    error = struct.unpack('<H', frame[26:28])[0]
    block_count = struct.unpack('<H', frame[28:30])[0]
    data_size = struct.unpack('<H', frame[30:32])[0]

    value_data = frame[32:32+data_size] if data_size > 0 else b''

    return {
        'cmd': cmd,
        'dtype': dtype,
        'error': error,
        'block_count': block_count,
        'data_size': data_size,
        'raw_data': value_data
    }


class XGTClient:
    """XGT protocol client for reading PLC variables."""

    def __init__(self, ip: str, port: int = XGT_PORT, timeout: float = TIMEOUT):
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.sock = None

    def connect(self) -> None:
        """Establish TCP connection to PLC."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.ip, self.port))

    def disconnect(self) -> None:
        """Close TCP connection."""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None

    def send_receive(self, frame: bytes) -> bytes:
        """Send request frame and receive response."""
        self.sock.sendall(frame)
        data = b''
        while True:
            try:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                # Check if we have a complete frame
                sig = data.find(XGT_SIG)
                if sig >= 0 and len(data) >= sig + 20:
                    length = struct.unpack('<H', data[sig+16:sig+18])[0]
                    if len(data) >= sig + 20 + length:
                        break
            except socket.timeout:
                break
        return data


def read_single_word(client: XGTClient, address: str) -> Optional[int]:
    """Read a single WORD variable.

    Returns:
        Integer value (0-65535) or None on error
    """
    frame = build_read_request(address, DTYPE_WORD)
    resp = client.send_receive(frame)
    result = parse_response(resp)

    if not result or result['error'] != 0:
        return None

    raw = result['raw_data']
    if len(raw) >= 2:
        return struct.unpack('<H', raw[0:2])[0]
    return None


def read_single_bit(client: XGTClient, address: str) -> Optional[int]:
    """Read a single BIT variable.

    Returns:
        0 or 1, or None on error
    """
    frame = build_read_request(address, DTYPE_BIT)
    resp = client.send_receive(frame)
    result = parse_response(resp)

    if not result or result['error'] != 0:
        return None

    raw = result['raw_data']
    if len(raw) >= 1:
        return raw[0] & 0x01
    return None


def read_block(client: XGTClient, start_mb: int, byte_count: int) -> Optional[bytes]:
    """Read a continuous block of bytes from %MB{start_mb}.

    Returns:
        Raw bytes or None on error
    """
    frame = build_continuous_read_request(start_mb, byte_count)
    resp = client.send_receive(frame)
    result = parse_response(resp)

    if not result or result['error'] != 0:
        return None

    return result['raw_data']


def main():
    parser = argparse.ArgumentParser(
        description='PLC XGT Protocol Reader (Port 2004)',
        epilog='''
Examples:
  # Read specific MW addresses
  python plc_xgt_reader.py --read 192.168.1.100 --mw 0 152 3000 1002

  # Read IW addresses
  python plc_xgt_reader.py --read 192.168.1.100 --iw 5000

  # Read from config file
  python plc_xgt_reader.py --read 192.168.1.100 --config variables.json

  # Scan memory range for non-zero values
  python plc_xgt_reader.py --scan 192.168.1.100 --range 0 10000

  # Scan and export found variables
  python plc_xgt_reader.py --scan 192.168.1.100 --range 0 10000 --export found.json

  # Multiple samples with interval
  python plc_xgt_reader.py --read 192.168.1.100 --mw 152 --samples 5

  # Custom output path
  python plc_xgt_reader.py --read 192.168.1.100 --mw 1002 --out snapshot.json
        '''
    )

    parser.add_argument('--read', type=str, metavar='IP', help='Read mode: PLC IP address')
    parser.add_argument('--scan', type=str, metavar='IP', help='Scan mode: PLC IP address')
    parser.add_argument('--mw', nargs='+', type=int, help='MW word addresses to read')
    parser.add_argument('--iw', nargs='+', type=int, help='IW word addresses to read')
    parser.add_argument('--config', type=str, help='JSON config with variable list')
    parser.add_argument('--port', type=int, default=XGT_PORT, help='XGT port (default 2004)')
    parser.add_argument('--timeout', type=float, default=TIMEOUT, help='Socket timeout (seconds)')
    parser.add_argument('--range', nargs=2, type=int, default=[0, 10000],
                        help='Scan range: start end')
    parser.add_argument('--export', type=str, help='Export found variables to JSON')
    parser.add_argument('--out', type=str, help='Output file for snapshot')
    parser.add_argument('--samples', type=int, default=1, help='Number of repeated reads')
    parser.add_argument('--interval', type=float, default=0.1, help='Interval between samples (s)')

    args = parser.parse_args()

    if args.read:
        # READ MODE
        addresses = []

        if args.mw:
            addresses += [f'%MW{n}' for n in args.mw]
        if args.iw:
            addresses += [f'%IW{n}' for n in args.iw]

        if args.config:
            with open(args.config, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
            for v in cfg.get('variables', []):
                if isinstance(v, dict):
                    addresses.append(f'%{v["area"]}W{v["word"]}')
                elif isinstance(v, str):
                    addresses.append(v)

        if not addresses:
            print("Error: specify --mw, --iw, or --config")
            sys.exit(1)

        print(f"=== READ MODE ===")
        print(f"  PLC: {args.read}:{args.port}")
        print(f"  Addresses: {len(addresses)}")
        print(f"  Samples: {args.samples}")

        client = XGTClient(args.read, args.port, args.timeout)
        client.connect()
        print(f"  ✓ Connected")

        all_samples = []

        for sample_idx in range(args.samples):
            values = {}
            for addr in addresses:
                if 'X' in addr or 'M' in addr and addr.endswith('X'):
                    val = read_single_bit(client, addr)
                else:
                    val = read_single_word(client, addr)

                if val is not None:
                    values[addr.replace('%', '')] = val
                    print(f"    {addr} = {val}")
                else:
                    print(f"    {addr} = ERROR")

            all_samples.append({
                'timestamp': datetime.now().isoformat(),
                'values': values
            })

            if sample_idx < args.samples - 1:
                time.sleep(args.interval)

        client.disconnect()

        # Save snapshot
        if args.out:
            output = {
                'source': f'xgt_read {args.read}:{args.port}',
                'addresses': addresses,
                'samples': all_samples if len(all_samples) > 1 else all_samples[0]['values']
            }
            with open(args.out, 'w', encoding='utf-8') as f:
                json.dump(output, f, indent=2, ensure_ascii=False)
            print(f"\n✓ Saved to {args.out}")

    elif args.scan:
        # SCAN MODE
        start, end = args.range
        start_byte = start * 2
        end_byte = (end + 1) * 2
        total_bytes = end_byte - start_byte
        BLOCK_SIZE = 400  # 200 words per request

        print(f"=== SCAN MODE ===")
        print(f"  PLC: {args.scan}:{args.port}")
        print(f"  Range: MW{start} ~ MW{end} ({end - start + 1} words)")
        print(f"  Block size: {BLOCK_SIZE} bytes ({BLOCK_SIZE//2} words)")
        print(f"  Total requests: {(total_bytes + BLOCK_SIZE - 1) // BLOCK_SIZE}")

        client = XGTClient(args.scan, args.port, args.timeout)
        client.connect()
        print(f"  ✓ Connected")

        all_values = {}
        scanned = 0

        for block_start in range(start_byte, end_byte, BLOCK_SIZE):
            block_end = min(block_start + BLOCK_SIZE, end_byte)
            count = block_end - block_start

            raw = read_block(client, block_start, count)

            if raw:
                for i in range(0, len(raw) - 1, 2):
                    word_idx = (block_start + i) // 2
                    if word_idx > end:
                        break
                    val = struct.unpack('<H', raw[i:i+2])[0]
                    if val != 0:
                        all_values[f'MW{word_idx}'] = val

            scanned += count // 2
            pct = min(100, scanned * 100 // (end - start + 1))
            print(f"  [{pct:3d}%] MW{block_start//2}... ({len(all_values)} non-zero)", end='\r')
            time.sleep(0.02)

        client.disconnect()

        print(f"\n\n=== SCAN COMPLETE ===")
        print(f"  Range: MW{start} ~ MW{end}")
        print(f"  Non-zero: {len(all_values)}")

        for addr in sorted(all_values.keys(), key=lambda x: int(x[2:])):
            print(f"    {addr} = {all_values[addr]}")

        if args.export:
            export = {
                'source': f'xgt_scan MW{start}-MW{end}',
                'variables': [
                    {'area': 'M', 'word': int(k[2:]), 'name': k}
                    for k in sorted(all_values.keys(), key=lambda x: int(x[2:]))
                ]
            }
            with open(args.export, 'w', encoding='utf-8') as f:
                json.dump(export, f, indent=2, ensure_ascii=False)
            print(f"\n✓ Exported {len(all_values)} variables to {args.export}")

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
