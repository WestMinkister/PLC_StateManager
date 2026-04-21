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
import re
import bz2
from pathlib import Path
from datetime import datetime

# Add src directory to path for imports
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)
if hasattr(sys, '_MEIPASS') and sys._MEIPASS not in sys.path:
    sys.path.insert(0, sys._MEIPASS)

# Area markers for multi-area support (M/I/Q/F/K/D)
AREA_MARKERS = {
    'M': [0x4D, 0x42],  # MB — Memory
    'I': [0x49, 0x42],  # IB — Input
    'Q': [0x51, 0x42],  # QB — Output
    'F': [0x46, 0x42],  # FB — Function block
    'K': [0x4B, 0x42],  # KB — Keep/Constant
    'D': [0x44, 0x42],  # DB — Data
    'W': [0x57, 0x42],  # WB — Word? (tentative)
}


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


def extract_mw_addresses_from_state(state):
    """Extract unique MW/IW/QW word numbers from ProgramState symbols.

    Args:
        state: ProgramState object from plc_upload_decode.build_program_state()

    Returns:
        Sorted list of unique MW word numbers (e.g., [152, 200, 1000, 1002, 3000])
    """
    mw_set = set()
    for sym in state.all_symbols:
        # SymbolEntry has .address property like "%MW152.0" or "%MW3000.2"
        addr = sym.address if hasattr(sym, 'address') else sym.get('address', '')
        # Match %MW<number>, %IW<number>, or %QW<number>
        match = re.match(r'%([A-Z])W(\d+)', addr)
        if match:
            area = match.group(1)
            word = int(match.group(2))
            if area == 'M':
                mw_set.add(word)
    return sorted(mw_set)


def build_z_c0_request(offset):
    """Build a Z/0xC0 request frame for the given buffer offset.

    Used for dynamic symbol table reading without hardcoded offset lists.
    """
    # Z/0xC0 payload: 6 bytes = [LE16 offset][0x00][LE16 frag_size=680][1B checksum]
    FRAG_SIZE = 680
    payload_prefix = struct.pack('<H', offset) + b'\x00' + struct.pack('<H', FRAG_SIZE)
    checksum = sum(payload_prefix) % 256
    addr_bin = payload_prefix + bytes([checksum])
    ascii_hex = addr_bin.hex().upper().encode('ascii')

    # Build LGIS-GLOFA frame: Z command (0x5A) + sub_cmd (0xC0) + payload
    cmd_payload = bytes([0xC0]) + ascii_hex
    cmd_data = bytes([0x5A]) + cmd_payload
    cmd_data_len = len(cmd_data)
    length = 2 + 2 + cmd_data_len

    header = bytearray(20)
    header[0:10] = b'LGIS-GLOFA'
    header[13] = 0x22  # Source: PC→PLC
    header[16:18] = struct.pack('<H', length)
    header[19] = sum(header[0:19]) % 256

    sub_header = b'\x0e\x00' + struct.pack('<H', cmd_data_len)
    return bytes(header) + sub_header + cmd_data


def dynamic_scatter_gather(client):
    """Dynamically read symbol table from PLC using sequential Z/0xC0 requests.

    Sends Z/0xC0 at offsets 0, 680, 1360, ... until response < 680 bytes.
    No hardcoded offset list — works for any number of programs.

    Args:
        client: Connected PLCUploadClient (session already primed with upload replay)
    Returns:
        set of symbol addresses like {'%MW152', '%MW6000'}
    """
    STEP = 680
    MIN_RESPONSE = 680

    fragments = []
    offset = 0

    while True:
        frame = build_z_c0_request(offset)
        print(f"    [SG] Sending Z/0xC0 offset={offset}...", end=' ')
        resp = client.send_frame(frame)

        if not resp:
            print("NO RESPONSE (None)")
            break
        if not resp.get('raw'):
            print(f"NO RAW DATA (keys: {list(resp.keys())})")
            break

        raw = resp['raw']
        sig = raw.find(b'LGIS-GLOFA')
        if sig < 0:
            print(f"NO SIGNATURE in {len(raw)}B response")
            break

        # Check status byte
        status = raw[sig + 24] if len(raw) > sig + 24 else None
        print(f"response {len(raw)}B, status=0x{status:02x}" if status is not None else f"response {len(raw)}B")

        payload = raw[sig + 26:]
        try:
            clean = ''.join(c for c in payload.decode('ascii', errors='ignore')
                           if c in '0123456789abcdefABCDEF')
            if len(clean) % 2:
                clean = clean[:-1]
            decoded = bytes.fromhex(clean) if clean else b''
        except (ValueError, UnicodeDecodeError):
            print(f"    [SG] DECODE FAILED")
            break

        print(f"    [SG] Decoded: {len(decoded)}B, hex: {decoded[:30].hex()}")

        if len(decoded) < 10:
            if decoded:
                fragments.append({'offset': offset, 'data': decoded})
            print(f"    [SG] Small response ({len(decoded)}B < 10) — stopping")
            break

        fragments.append({'offset': offset, 'data': decoded})

        if len(decoded) < MIN_RESPONSE:
            break

        offset += STEP
        time.sleep(0.05)

    if not fragments:
        return set(), 0

    # Reassemble buffer
    max_end = max(f['offset'] + len(f['data']) for f in fragments)
    buffer = bytearray(max_end)
    for f in sorted(fragments, key=lambda x: x['offset']):
        buffer[f['offset']:f['offset'] + len(f['data'])] = f['data']

    # Extract symbols from all BZh blocks
    symbols = set()
    pos = 0
    while pos < len(buffer) - 3:
        idx = buffer.find(b'BZh', pos)
        if idx < 0:
            break
        try:
            d = bz2.decompress(buffer[idx:])
            symbols.update(re.findall(r'%[A-Z]+\d+', d.decode('ascii', errors='replace')))
            pos = idx + len(d) + 1
        except Exception:
            pos = idx + 1

    return symbols, len(fragments)


def scatter_gather_symbols(upload_frames, responses):
    """Extract ALL symbols via Z/0xC0 scatter-gather reassembly.

    Args:
        upload_frames: list of dicts from upload_replay_frames.json (PC→PLC)
        responses: list of response dicts from PLCUploadClient.responses (from PLCUploadClient.responses)

    Returns:
        set of symbol addresses like {'%MW152', '%MW6000', '%IW5000', '%QW10'}
    """
    # 1. Find Z/0xC0 requests and their offsets
    c0_offsets = []
    c0_request_indices = []  # Track which request index each offset is from
    for i, frame in enumerate(upload_frames):
        cmd = frame.get('command_char') or frame.get('command')
        # Check if this is a Z/0xC0 request (Z=0x5A)
        if (cmd == 'Z' or cmd == 0x5A or isinstance(cmd, int) and cmd == 0x5A) and frame.get('sub_cmd') == 0xC0:
            # Request payload is ASCII hex encoded
            payload_hex = frame.get('cmd_payload_hex', '')
            if payload_hex and len(payload_hex) >= 6:
                try:
                    # Double decode: hex(ASCII_hex(binary))
                    # Step 1: hex string → raw bytes (which are ASCII hex chars)
                    raw_ascii_bytes = bytes.fromhex(payload_hex)
                    # Step 2: ASCII hex chars → actual binary
                    ascii_str = raw_ascii_bytes.decode('ascii', errors='ignore')
                    actual_binary = bytes.fromhex(ascii_str)
                    # First 2 bytes of actual binary = LE16 buffer offset
                    if len(actual_binary) >= 2:
                        offset = struct.unpack('<H', actual_binary[0:2])[0]
                        c0_offsets.append(offset)
                        c0_request_indices.append(i)
                except Exception:
                    pass

    if not c0_offsets:
        return set()

    # 2. Extract Z response payloads
    # Since responses list is from PLCUploadClient (has ALL responses in order),
    # we need to match based on Z command order
    z_responses = []

    for r in responses:
        cmd = r.get('command_char') or r.get('command')
        # Check if this is a Z response (Z=0x5A)
        if cmd == 'Z' or (isinstance(cmd, int) and cmd == 0x5A):
            # Get response raw data
            raw = r.get('raw')
            if isinstance(raw, str):
                try:
                    raw = bytes.fromhex(raw)
                except Exception:
                    raw = None

            if not isinstance(raw, bytes):
                continue

            sig = raw.find(b'LGIS-GLOFA')
            if sig >= 0 and len(raw) > sig + 26:
                payload_bytes = raw[sig + 26:]
                try:
                    # Payload is ASCII-encoded hex
                    ascii_str = payload_bytes.decode('ascii', errors='ignore')
                    # Clean to valid hex characters
                    clean = ''.join(c for c in ascii_str if c in '0123456789abcdefABCDEF')
                    if len(clean) % 2:
                        clean = clean[:-1]
                    if clean:
                        decoded = bytes.fromhex(clean)
                        z_responses.append(decoded)
                except Exception:
                    pass

    if not z_responses:
        return set()

    # 3. Match Z/0xC0 requests with responses
    # Count how many Z requests exist before each 0xC0 request
    z_request_count = 0
    c0_resp_indices = []  # Index into z_responses for each C0 request

    for i, frame in enumerate(upload_frames):
        cmd = frame.get('command_char') or frame.get('command')
        if cmd == 'Z' or (isinstance(cmd, int) and cmd == 0x5A):
            # This is a Z request (any type)
            if frame.get('sub_cmd') == 0xC0:
                # This 0xC0 request is the z_request_count'th Z request
                c0_resp_indices.append(z_request_count)
            z_request_count += 1

    # Build pairs: match each C0 offset with the corresponding Z response
    c0_pairs = []
    for offset, resp_idx in zip(c0_offsets, c0_resp_indices):
        if resp_idx < len(z_responses):
            c0_pairs.append({
                'offset': offset,
                'data': z_responses[resp_idx]
            })

    if not c0_pairs:
        return set()

    # 4. Reassemble buffer
    max_end = max(p['offset'] + len(p['data']) for p in c0_pairs)
    buffer = bytearray(max_end)
    for p in sorted(c0_pairs, key=lambda x: x['offset']):
        start = p['offset']
        end = start + len(p['data'])
        buffer[start:end] = p['data']

    # 5. Find and decompress all BZh blocks
    symbols = set()
    pos = 0
    while pos < len(buffer) - 3:
        bz_idx = buffer.find(b'BZh', pos)
        if bz_idx < 0:
            break
        try:
            decompressed = bz2.decompress(buffer[bz_idx:])
            text = decompressed.decode('ascii', errors='replace')
            found = re.findall(r'%[A-Z]+\d+', text)
            symbols.update(found)
        except Exception:
            pass
        pos = bz_idx + 1

    return symbols


def extract_addresses_from_symbols(symbols):
    """Convert symbol addresses to (area, word) tuples.

    '%MW152' → ('M', 152)
    '%IW5000' → ('I', 5000)
    '%QW10' → ('Q', 10)

    Args:
        symbols: iterable of symbol strings like '%MW152'

    Returns:
        list of (area, word) tuples
    """
    result = []
    for sym in symbols:
        match = re.match(r'%([A-Z])W(\d+)', sym)
        if match:
            area = match.group(1)
            word = int(match.group(2))
            result.append((area, word))
    return result


def build_r_e0_request(variables):
    """Build R/0xE0 request frame for specified variables (multi-area support).

    Args:
        variables: List of dicts like {'area': 'M', 'word': 152} or list of ints for backwards compat
    Returns:
        Complete LGIS-GLOFA frame (bytes)
    """
    # Handle backwards compat: convert list of ints to list of dicts
    if variables and isinstance(variables[0], int):
        variables = [{'area': 'M', 'word': addr} for addr in variables]

    # Binary payload
    # 캡처 분석: 응답 decoded = [값 워드 × N] + [3바이트 trailer].
    # trailer = 마지막 엔트리 값(2B) + 프로토콜 메타(1B).
    # 해결: 실제 주소 뒤에 패딩 엔트리 추가 → 패딩 값이 trailer에 소비됨.
    total_entries = len(variables) + 1  # +1 trailing padding
    payload_bin = bytearray()
    payload_bin.extend(struct.pack('>I', total_entries * 2))

    # 실제 변수 엔트리들
    for idx, var in enumerate(variables):
        payload_bin.append(0x04 if idx == 0 else 0x00)
        area = var.get('area', 'M')
        marker = AREA_MARKERS.get(area, [0x4D, 0x42])
        payload_bin.extend(marker + [0x02, 0x00])
        payload_bin.extend(struct.pack('<H', var['word'] * 2))
        payload_bin.append(0x00)

    # 패딩 엔트리 (이 값이 trailer 3바이트에 소비됨)
    payload_bin.append(0x00)
    payload_bin.extend([0x4D, 0x42, 0x02, 0x00])
    payload_bin.extend(struct.pack('<H', 0))
    payload_bin.append(0x00)

    payload_bin.extend([0x00, 0xD4])

    # Double ASCII-hex encode
    ascii_hex_bytes = payload_bin.hex().upper().encode('ascii')

    # Build LGIS-GLOFA frame
    cmd_payload = bytes([0xE0]) + ascii_hex_bytes
    cmd_data = bytes([0x52]) + cmd_payload
    cmd_data_len = len(cmd_data)
    length = 2 + 2 + cmd_data_len

    header = bytearray(20)
    header[0:10] = b'LGIS-GLOFA'
    header[10:12] = b'\x00\x00'
    header[12] = 0x00
    header[13] = 0x22
    header[14:16] = struct.pack('<H', 0)
    header[16:18] = struct.pack('<H', length)
    header[18] = 0x00
    header[19] = sum(header[0:19]) % 256

    sub_header = b'\x0e\x00' + struct.pack('<H', cmd_data_len)
    return bytes(header) + sub_header + cmd_data


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

    # R/0xE0 응답 구조 (0420 캡처 분석 확정):
    #   decoded_bytes = [값 워드 × N] + [3바이트 프로토콜 메타데이터]
    #   메타데이터는 매 응답 변동 (카운터/체크섬) — 값이 아님
    #   0420 캡처 36개 응답 비교로 확인: 접점 토글 시 앞 워드만 변경, 뒤 3바이트는 항상 변동
    TRAILER_SIZE = 3
    value_bytes = response_bytes[:-TRAILER_SIZE] if len(response_bytes) > TRAILER_SIZE else response_bytes
    trailer_hex = response_bytes[-TRAILER_SIZE:].hex() if len(response_bytes) > TRAILER_SIZE else ''

    values = []
    pos = 0
    while pos + 2 <= len(value_bytes):
        word = struct.unpack('<H', value_bytes[pos:pos+2])[0]
        values.append(word)
        pos += 2

    return {
        'raw_hex': response_hex,
        'values': values,
        'trailer_hex': trailer_hex,
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
    parser.add_argument('--mw', nargs='+', type=int, metavar='ADDR',
                        help='MW addresses to read (e.g., --mw 152 3000 1002)')
    parser.add_argument('--config', type=str, metavar='JSON',
                        help='Variable config file (e.g., variables.json)')
    parser.add_argument('--auto', action='store_true',
                        help='Auto-discover all MW addresses from PLC program and read values')
    parser.add_argument('--export', type=str, metavar='JSON',
                        help='Export auto-discovered variables to config file')
    parser.add_argument('--snapshot', type=str, metavar='JSON',
                        help='Use existing program snapshot JSON for address discovery (skips session 1)')
    parser.add_argument('--scan', type=str, metavar='IP',
                        help='Scan MW address range for non-zero values (auto-discovery)')
    parser.add_argument('--range', nargs=2, type=int, metavar=('START', 'END'),
                        default=[0, 10000],
                        help='MW address range for --scan (default: 0 10000)')

    args = parser.parse_args()

    # Scan mode (early exit)
    if args.scan:
        start, end = args.range
        print(f"\n=== MEMORY SCAN: MW{start} ~ MW{end} ===")
        print(f"  Total addresses: {end - start + 1}")
        BATCH_SIZE = 3
        total_addrs = end - start + 1
        total_batches = (total_addrs + BATCH_SIZE - 1) // BATCH_SIZE
        print(f"  Batch size: {BATCH_SIZE}, estimated batches: {total_batches}")

        # Estimate time (0.02s per batch + ~0.05s RTT)
        est_time = total_batches * 0.07
        est_minutes = est_time / 60
        print(f"  Estimated time: {est_minutes:.1f} minutes")

        # Connect to PLC
        print(f"\nConnecting to PLC {args.scan}:{args.port}...")
        client = PLCUploadClient(args.scan, args.port, timeout=5.0)
        try:
            client.connect()
        except Exception as e:
            print(f"✗ Connection failed: {e}")
            sys.exit(1)

        # Load CONN and monitor entry frames
        frames_file = Path(resource_path('value_read_frames.json'))
        if not frames_file.exists():
            print(f"Error: value_read_frames.json not found")
            sys.exit(1)

        try:
            with open(frames_file, encoding='utf-8') as f:
                frames_data = json.load(f)
        except Exception as e:
            print(f"Error loading frames: {e}")
            sys.exit(1)

        conn_frame_hex = frames_data.get('conn_frame_hex')
        monitor_entries = frames_data.get('monitor_entry_frames', [])
        disc_frame_hex = frames_data.get('disc_frame_hex')
        j_heartbeat_hex = frames_data.get('j_heartbeat_frame_hex')

        try:
            # 1. CONN frame
            print("\n[SCAN] Sending CONN frame...")
            conn_bytes = bytes.fromhex(conn_frame_hex)
            resp = client.send_frame(conn_bytes)
            if not resp:
                print("✗ CONN response not received")
                sys.exit(1)
            print(f"✓ CONN OK")
            time.sleep(0.3)

            # 2. J heartbeat (optional priming)
            if j_heartbeat_hex:
                print("[PRIMING] Sending J heartbeat...")
                j_bytes = bytes.fromhex(j_heartbeat_hex)
                resp = client.send_frame(j_bytes)
                if resp:
                    print(f"✓ J/0x34 OK")
                else:
                    print(f"⚠ J/0x34 NO RESPONSE (continuing anyway)")
                time.sleep(0.05)

            # 3. Monitor mode entry: Z/0x8D + Z/0x8E
            print("[MONITOR] Entering monitor mode...")
            for entry in monitor_entries:
                frame_hex = entry.get('frame_hex')
                cmd = entry.get('cmd')
                sub_cmd = entry.get('sub_cmd')
                if not frame_hex:
                    continue
                try:
                    frame_bytes = bytes.fromhex(frame_hex)
                    resp = client.send_frame(frame_bytes)
                    status = "OK" if resp else "NO RESPONSE"
                    print(f"  {cmd}/{sub_cmd}: {status}")
                    time.sleep(0.05)
                except Exception as e:
                    print(f"  ✗ {cmd}/{sub_cmd}: {e}")

            # 4. Batch-scan the address range
            print(f"\n[SCAN] Starting batch scan...\n")
            found_vars = []
            all_scanned = 0

            for batch_start in range(start, end + 1, BATCH_SIZE):
                batch_end = min(batch_start + BATCH_SIZE, end + 1)
                batch_addrs = list(range(batch_start, batch_end))

                batch_vars = [{'area': 'M', 'word': mw} for mw in batch_addrs]
                req = build_r_e0_request(batch_vars)
                resp = client.send_frame(req)

                if resp and resp.get('raw'):
                    raw = resp['raw']
                    sig_pos = raw.find(b'LGIS-GLOFA')
                    if sig_pos >= 0 and len(raw) > sig_pos + 26:
                        payload_bytes = raw[sig_pos + 26:]
                        decoded = decode_response_payload(payload_bytes.hex())
                        values = decoded.get('values', [])

                        for i, mw in enumerate(batch_addrs):
                            if i < len(values) and values[i] != 0:
                                found_vars.append({'area': 'M', 'word': mw, 'value': values[i]})

                all_scanned += len(batch_addrs)

                # Progress indicator every ~100 addresses
                if all_scanned % 99 < BATCH_SIZE or all_scanned == total_addrs:
                    pct = all_scanned * 100 // total_addrs
                    found_count = len(found_vars)
                    print(f"  [{pct:3d}%] MW{batch_start}... ({found_count} non-zero found)", end='\r')

                time.sleep(0.02)

            # 5. DISC frame
            if disc_frame_hex:
                print("\n  [SCAN] Sending DISC frame...")
                try:
                    disc_bytes = bytes.fromhex(disc_frame_hex)
                    client.send_frame(disc_bytes)
                    print(f"  ✓ DISC OK")
                except Exception as e:
                    print(f"  ⚠ DISC error: {e}")

        finally:
            client.disconnect()

        # Report results
        print(f"\n\n=== SCAN COMPLETE ===")
        print(f"  Scanned: MW{start} ~ MW{end} ({all_scanned} addresses)")
        print(f"  Non-zero: {len(found_vars)} addresses")
        print()
        for v in sorted(found_vars, key=lambda x: x['word']):
            print(f"  MW{v['word']:>5} = {v['value']}")

        # Export if requested
        if args.export:
            export_data = {
                'source': f'memory_scan MW{start}-MW{end}',
                'variables': [{'area': v['area'], 'word': v['word'], 'name': f"MW{v['word']}"} for v in sorted(found_vars, key=lambda x: x['word'])]
            }
            export_path = Path(args.export)
            export_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                with open(export_path, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, indent=2, ensure_ascii=False)
                print(f"\n✓ Exported {len(found_vars)} variables to {args.export}")
            except Exception as e:
                print(f"\n✗ Failed to export: {e}")
                sys.exit(1)

        sys.exit(0)

    # Handle --config mode: load variables from config file
    config_vars = None
    if args.config:
        config_path = Path(args.config)
        if not config_path.exists():
            print(f"Error: config file not found: {args.config}")
            sys.exit(1)
        try:
            with open(config_path, encoding='utf-8') as f:
                config = json.load(f)
        except Exception as e:
            print(f"Error loading config file: {e}")
            sys.exit(1)
        config_vars = config.get('variables', [])
        if not config_vars:
            print("Error: no variables in config file")
            sys.exit(1)
        # Convert to internal format and store for later use
        args._config_vars = [{'area': v.get('area', 'M'), 'word': v['word']} for v in config_vars]
        args._config_names = [f"{v.get('area','M')}W{v['word']}" for v in config_vars]

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

        # Show config if provided
        if args.config:
            print(f"\nConfig file: {args.config}")
            print(f"Variables ({len(config_vars)}):")
            for v in config_vars:
                area = v.get('area', 'M')
                name = v.get('name', '')
                var_str = f"{area}W{v['word']}"
                if name:
                    var_str += f" ({name})"
                print(f"  {var_str}")

        print(f"\nCONN frame: {conn_frame_hex[:40]}...")
        print(f"Monitor entry frames:")
        for entry in monitor_entries:
            print(f"  {entry['cmd']}/{entry['sub_cmd']}: {entry['note']}")
        print(f"J heartbeat: {j_heartbeat_hex[:40] if j_heartbeat_hex else '(not set)'}...")

        # Handle --auto mode discovery in dry-run
        if args.auto:
            if args.snapshot:
                print(f"\n[AUTO] Would load snapshot: {args.snapshot}")
                # Try to resolve snapshot path
                snap_path = Path(args.snapshot)
                if not snap_path.exists():
                    for fallback_dir in [Path('snapshots'), Path('docs'), Path('.')]:
                        candidate = fallback_dir / snap_path.name
                        if candidate.exists():
                            snap_path = candidate
                            break
                if snap_path.exists():
                    try:
                        from plc_upload_decode import build_program_state
                        with open(snap_path, encoding='utf-8') as f:
                            snap = json.load(f)
                        state = build_program_state(snap)
                        addrs = extract_mw_addresses_from_state(state)
                        print(f"  Discovered MW addresses: {addrs}")
                        print(f"  Total: {len(addrs)} unique MW words")
                    except Exception as e:
                        print(f"  Error loading snapshot: {e}")
                else:
                    print(f"  Error: snapshot not found: {args.snapshot}")
                    print(f"    Also tried: snapshots/, docs/, CWD")
            else:
                print(f"\n[AUTO] Would run session 1 (program read) to discover addresses")
                print(f"  Frames: {len(frames_data.get('upload_frames', []))} (estimated)")
        elif args.mw:
            print(f"\nCustom MW addresses: {args.mw}")
            frame = build_r_e0_request(args.mw)  # backwards compat: accepts list of ints
            print(f"Built R/0xE0 frame: {len(frame)}B")
            print(f"Frame hex: {frame.hex()[:80]}...")
        else:
            print(f"\nR/0xE0 template: {read_request_hex[:40]}...")

        print(f"DISC frame: {disc_frame_hex[:40] if disc_frame_hex else '(not set)'}...")
        print(f"\nWould send:")
        if args.auto and not args.snapshot:
            print(f"  [SESSION 1] Program read:")
            print(f"  1. CONN frame")
            print(f"  2. Upload replay (discover addresses)")
            print(f"  3. DISC frame")
            print(f"  [WAIT 0.5s]")
            print(f"  [SESSION 2] Value read:")
            print(f"  4. CONN frame")
            if j_heartbeat_hex:
                print(f"  5. J heartbeat (optional priming)")
            print(f"  6. Monitor entry frames (Z/0x8D + Z/0x8E)")
            print(f"  7. {args.samples} R/0xE0 read(s) for discovered addresses")
            if disc_frame_hex:
                print(f"  8. DISC frame")
        else:
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

    # Auto-discover MW addresses if --auto is set
    if args.auto:
        from plc_upload_decode import build_program_state

        if args.snapshot:
            # Use existing snapshot
            print(f"\n=== AUTO MODE: Loading snapshot ===")
            print(f"  [AUTO] Loading snapshot: {args.snapshot}")

            # Try to resolve snapshot path
            snap_path = Path(args.snapshot)
            if not snap_path.exists():
                for fallback_dir in [Path('snapshots'), Path('docs'), Path('.')]:
                    candidate = fallback_dir / snap_path.name
                    if candidate.exists():
                        snap_path = candidate
                        break

            if not snap_path.exists():
                print(f"  ✗ Snapshot not found: {args.snapshot}")
                print(f"    Also tried: snapshots/, docs/, CWD")
                sys.exit(1)

            try:
                with open(snap_path, encoding='utf-8') as f:
                    snap_responses = json.load(f)
            except Exception as e:
                print(f"  ✗ Failed to load snapshot: {e}")
                sys.exit(1)
        else:
            # Session 1: Generic priming + dynamic Z/0xC0 scatter-gather
            # Uses 36 UNIVERSAL priming frames (identical across all programs)
            # Then dynamically reads symbol table via Z/0xC0 at sequential offsets
            print(f"\n=== AUTO MODE: Universal Priming + Dynamic Scatter-Gather ===")

            # Load generic priming frames (program-independent, verified identical across 1/2/4-prog captures)
            priming_path = resource_path('generic_priming.json')
            try:
                with open(priming_path, encoding='utf-8') as f:
                    priming_data = json.load(f)
                priming_frames = priming_data.get('priming_frames', [])
                disc_frame_entry = priming_data.get('disc_frame')
                print(f"  [AUTO] Loaded {len(priming_frames)} universal priming frames")
            except Exception as e:
                print(f"  ✗ Failed to load generic_priming.json: {e}")
                sys.exit(1)

            # Connect
            print(f"  Connecting to PLC {args.read}:{args.port}...")
            client1 = PLCUploadClient(args.read, args.port, timeout=5.0)
            try:
                client1.connect()
            except Exception as e:
                print(f"  ✗ Connection failed: {e}")
                sys.exit(1)

            # Send 36 universal priming frames IN ORDER (no reordering!)
            # replay_frames reorders CONN/DISC which breaks the 2-session pattern
            try:
                success = 0
                errors = 0
                for i, pf in enumerate(priming_frames):
                    fhex = pf.get('frame_hex', '')
                    if not fhex:
                        continue
                    fb = bytes.fromhex(fhex)
                    resp = client1.send_frame(fb)
                    if resp:
                        success += 1
                        # Store for build_program_state
                        client1.responses.append(resp)
                    else:
                        errors += 1
                    time.sleep(0.05)
                print(f"  ✓ Priming: {success}/{len(priming_frames)} frames OK, {errors} errors")

                snap_responses = []
                for r in client1.responses:
                    entry = {}
                    for k, v in r.items():
                        if isinstance(v, bytes):
                            entry[k + '_hex'] = v.hex()
                        else:
                            entry[k] = v
                    snap_responses.append(entry)
            except Exception as e:
                print(f"  ✗ Priming failed: {e}")
                client1.disconnect()
                sys.exit(1)

        # Extract symbols and discover MW addresses
        try:
            state = build_program_state(snap_responses)
            mw_addresses = extract_mw_addresses_from_state(state)
            print(f"  [AUTO] Discovered {len(mw_addresses)} MW addresses (parser): {mw_addresses}")

            # Dynamic scatter-gather: send Z/0xC0 at sequential offsets
            # client1 is still connected (DISC was excluded from replay)
            if not args.snapshot:
                try:
                    print(f"  [AUTO] Dynamic scatter-gather (sequential Z/0xC0)...")
                    sg_symbols, n_frags = dynamic_scatter_gather(client1)
                    sg_addresses = extract_addresses_from_symbols(sg_symbols)

                    mw_set = set(mw_addresses)
                    for area, word in sg_addresses:
                        if area == 'M':
                            mw_set.add(word)

                    mw_addresses = sorted(mw_set)
                    print(f"  [AUTO] Scatter-gather: {n_frags} fragments → {len(sg_symbols)} symbols")
                    if sg_symbols:
                        print(f"  [AUTO] Symbols: {sorted(sg_symbols)}")
                except Exception as e:
                    print(f"  [AUTO] Scatter-gather failed: {e} (using parser results only)")
                finally:
                    # Close session 1 (DISC + disconnect)
                    if disc_frame_entry and disc_frame_entry.get('frame_hex'):
                        try:
                            client1.send_frame(bytes.fromhex(disc_frame_entry['frame_hex']))
                        except: pass
                    client1.disconnect()

                time.sleep(0.5)  # Wait between sessions

            if not mw_addresses:
                print(f"  ✗ No MW addresses found in program")
                sys.exit(1)

            print(f"  [AUTO] Total discovered: {len(mw_addresses)} MW addresses: {mw_addresses}")

            # Override args.mw with discovered addresses
            args.mw = mw_addresses

            # Export to config file if --export is specified
            if args.export:
                export_data = {
                    "variables": [{"area": "M", "word": mw, "name": f"MW{mw}"} for mw in mw_addresses]
                }
                try:
                    export_path = Path(args.export)
                    export_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(export_path, 'w', encoding='utf-8') as f:
                        json.dump(export_data, f, indent=2, ensure_ascii=False)
                    print(f"  ✓ Exported {len(mw_addresses)} variables to {args.export}")
                except Exception as e:
                    print(f"  ✗ Failed to export: {e}")
                    sys.exit(1)

        except Exception as e:
            print(f"  ✗ Failed to extract symbols: {e}")
            sys.exit(1)

    print(f"\n=== AUTO MODE: Session 2 (Value Read) ===" if args.auto else f"\n=== Connecting to PLC {args.read}:{args.port} ===")
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

        # Determine variables to read and variable names
        if hasattr(args, '_config_vars') and args._config_vars:
            read_vars = args._config_vars
            var_names = args._config_names
        elif args.mw:
            read_vars = [{'area': 'M', 'word': addr} for addr in args.mw]
            var_names = [f'MW{addr}' for addr in args.mw]
        else:
            read_vars = None
            var_names = [f"{v['marker_hex']}_0x{v['offset']:04x}" for v in variables]

        # 4. R/0xE0 polling (배치 분할: 3주소/배치, PLC 응답 버퍼 한계 대응)
        BATCH_SIZE = 3  # 3 real + 1 padding = 4 entries (캡처에서 검증된 크기)
        print(f"  [READ] Starting R/0xE0 polls...")

        for sample_num in range(args.samples):
            if args.samples > 1:
                print(f"\n  Sample {sample_num + 1}/{args.samples}...")

            try:
                if read_vars:
                    # 배치 분할 읽기 (--config 또는 --mw 모드)
                    all_values = []
                    batches = [read_vars[i:i+BATCH_SIZE] for i in range(0, len(read_vars), BATCH_SIZE)]
                    for batch_idx, batch in enumerate(batches):
                        read_frame_bytes = build_r_e0_request(batch)
                        resp = client.send_frame(read_frame_bytes)
                        if resp and resp.get('raw'):
                            raw = resp['raw']
                            sig_pos = raw.find(b'LGIS-GLOFA')
                            if sig_pos >= 0 and len(raw) > sig_pos + 26:
                                payload_bytes = raw[sig_pos + 26:]
                                decoded = decode_response_payload(payload_bytes.hex())
                                batch_values = decoded.get('values', [])[:len(batch)]
                                all_values.extend(batch_values)
                                batch_names = [f"{v['area']}W{v['word']}" for v in batch]
                                print(f"    [batch {batch_idx+1}/{len(batches)}] {dict(zip(batch_names, batch_values))}")
                            else:
                                print(f"    [batch {batch_idx+1}] response too short")
                                all_values.extend([None] * len(batch))
                        else:
                            print(f"    [batch {batch_idx+1}] NO RESPONSE")
                            all_values.extend([None] * len(batch))
                        time.sleep(0.05)

                    samples.append(all_values)
                    print(f"    ✓ READ OK: {len(all_values)} values")
                else:
                    # 기존 템플릿 모드 (단일 요청)
                    read_frame_bytes = bytes.fromhex(read_request_hex)
                    resp = client.send_frame(read_frame_bytes)
                    if resp and resp.get('raw'):
                        raw = resp['raw']
                        sig_pos = raw.find(b'LGIS-GLOFA')
                        if sig_pos >= 0 and len(raw) > sig_pos + 26:
                            payload_bytes = raw[sig_pos + 26:]
                            decoded = decode_response_payload(payload_bytes.hex())
                            sample_values = decoded.get('values', [])
                            samples.append(sample_values)
                            print(f"    ✓ READ OK: {len(sample_values)} values {sample_values}")
                        else:
                            print(f"    ✗ READ: response too short")
                    else:
                        print(f"    ✗ READ NO RESPONSE")

            except Exception as e:
                print(f"    ✗ READ ERROR: {e}")

            if args.samples > 1 and sample_num < args.samples - 1:
                time.sleep(0.5)

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
        for i, name in enumerate(var_names):
            if i < len(samples[-1]):
                output['values_latest'][name] = samples[-1][i]

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
