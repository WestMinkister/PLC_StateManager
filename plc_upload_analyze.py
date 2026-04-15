#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PLC Upload Capture Analyzer
캡처 D (PLC로부터열기) 패킷 분석 및 헤더 구조 검증

Usage:
    python plc_upload_analyze.py [--verbose]

Features:
    - Extract all LGIS-GLOFA protocol frames from pcapng capture
    - Validate 20-byte header against research doc specification
    - Compare with 14-byte PRD reverse-engineering header interpretation
    - Output detailed packet inventory for replay client
    - Save replay data as JSON for Phase 3
"""
import struct
import sys
import os
import json


def parse_pcapng_packets(filepath):
    """Parse pcapng file and extract LGIS-GLOFA packets on port 2002.

    Args:
        filepath: Path to .pcapng capture file

    Returns:
        List of (direction, payload) tuples where:
        - direction: "PC→PLC" or "PLC→PC"
        - payload: Raw bytes of TCP payload containing LGIS-GLOFA frame
    """
    with open(filepath, 'rb') as f:
        data = f.read()

    packets = []
    pos = 0

    while pos < len(data):
        if pos + 8 > len(data):
            break

        # Parse pcapng block header
        block_type = struct.unpack('<I', data[pos:pos+4])[0]
        block_len = struct.unpack('<I', data[pos+4:pos+8])[0]

        # Validate block
        if block_len < 12 or pos + block_len > len(data):
            break

        # Enhanced Packet Block (type 6)
        if block_type == 6 and block_len > 28:
            # Parse fields at fixed offsets
            captured_len = struct.unpack('<I', data[pos+20:pos+24])[0]
            pkt_data = data[pos+28:pos+28+captured_len]

            # Validate Ethernet frame (minimum IPv4 TCP frame)
            if len(pkt_data) > 54:
                eth_type = struct.unpack('>H', pkt_data[12:14])[0]

                # IPv4
                if eth_type == 0x0800:
                    ip_hdr_len = (pkt_data[14] & 0x0F) * 4
                    proto = pkt_data[14 + 9]

                    # TCP
                    if proto == 6:
                        tcp_start = 14 + ip_hdr_len
                        src_port = struct.unpack('>H', pkt_data[tcp_start:tcp_start+2])[0]
                        dst_port = struct.unpack('>H', pkt_data[tcp_start+2:tcp_start+4])[0]
                        tcp_hdr_len = ((pkt_data[tcp_start+12] >> 4) & 0xF) * 4
                        payload = pkt_data[tcp_start + tcp_hdr_len:]

                        # Port 2002 (LGIS-GLOFA)
                        if (src_port == 2002 or dst_port == 2002) and len(payload) > 0:
                            direction = "PC→PLC" if dst_port == 2002 else "PLC→PC"
                            packets.append((direction, payload))

        # Move to next block
        pos += block_len

    return packets


def parse_lgis_header(frame_bytes):
    """Parse LGIS-GLOFA frame and extract header fields.

    Validates both interpretations:
    1. Research doc: 20-byte header with BCC checksum
    2. PRD reverse-engineering: 10 + 14 byte structure

    Args:
        frame_bytes: Raw bytes of LGIS-GLOFA frame starting with "LGIS-GLOFA"

    Returns:
        Dict with all parsed header fields and validation results
    """
    result = {}

    # === Company ID (bytes 0-9) ===
    result['company_id'] = frame_bytes[0:10]
    result['company_id_str'] = frame_bytes[0:10].decode('ascii', errors='replace')

    # Remaining bytes after signature
    rest = frame_bytes[10:]

    # === Research doc interpretation (20-byte total header) ===
    if len(rest) >= 10:
        result['plc_info'] = struct.unpack('<H', rest[0:2])[0]
        result['cpu_info'] = rest[2]
        result['source_of_frame'] = rest[3]
        result['invoke_id'] = struct.unpack('<H', rest[4:6])[0]
        result['length'] = struct.unpack('<H', rest[6:8])[0]
        result['fenet_position'] = rest[8]
        result['bcc_actual'] = rest[9]

        # Validate BCC (checksum)
        bcc_calc = sum(frame_bytes[0:19]) % 256
        result['bcc_calculated'] = bcc_calc
        result['bcc_valid'] = (result['bcc_actual'] == bcc_calc)

    # === PRD interpretation (14-byte header after signature) ===
    if len(rest) >= 14:
        result['prd_const'] = rest[0:4].hex()
        result['prd_padding'] = rest[4:6].hex()
        result['prd_len_plus5'] = struct.unpack('<H', rest[6:8])[0]
        result['prd_sequence'] = struct.unpack('<H', rest[8:10])[0]
        result['prd_self_ref'] = rest[10:12].hex()
        result['prd_len_plus1'] = struct.unpack('<H', rest[12:14])[0]

    # Raw header hex for manual inspection
    header_len = min(24, len(frame_bytes))
    result['header_hex'] = frame_bytes[0:header_len].hex()

    return result


def extract_frames(packets):
    """Extract LGIS-GLOFA frames from raw TCP payloads.

    Searches for "LGIS-GLOFA" signature and parses header/command structure.

    Frame structure:
    [0:10]   "LGIS-GLOFA" signature
    [10:20]  Application header (PLC Info, CPU Info, SoF, InvokeID, Length, FEnet, BCC)
    [20:22]  Frame type (0x0E=PC→PLC command, 0x0F=PLC→PC response, 0x0A=connection, 0x12=disconnect)
    [22:24]  LE16 command_data_length (for command/response frames)
    [24]     Command byte (J=0x4A, R=0x52, Z=0x5A, E=0x45, T=0x54, P=0x50, X=0x58, M=0x4D)
    [25]     Sub-command byte (varies by command)
    [26:]    Command payload (typically ASCII hex)

    Args:
        packets: List of (direction, payload) tuples from parse_pcapng_packets()

    Returns:
        List of frame dicts with parsed header and command info
    """
    frames = []

    for idx, (direction, payload) in enumerate(packets):
        # Find LGIS-GLOFA signature
        sig_pos = payload.find(b'LGIS-GLOFA')
        if sig_pos < 0:
            continue

        # Extract frame from signature onwards
        frame = payload[sig_pos:]
        if len(frame) < 22:
            continue

        # Parse header
        header = parse_lgis_header(frame)
        header['packet_index'] = idx
        header['direction'] = direction
        header['frame_raw'] = frame.hex()
        header['frame_length'] = len(frame)

        # === Extract command structure (after 20-byte header) ===

        if len(frame) >= 22:
            # Parse frame type at bytes [20:22]
            frame_type = struct.unpack('<H', frame[20:22])[0]
            header['frame_type'] = frame_type
            header['frame_type_hex'] = f'0x{frame_type:02x}'

            # Determine frame type name
            if frame_type == 0x0E:
                frame_type_name = "PC→PLC command"
            elif frame_type == 0x0F:
                frame_type_name = "PLC→PC response"
            elif frame_type == 0x0A:
                frame_type_name = "Connection"
            elif frame_type == 0x12:
                frame_type_name = "Disconnect"
            else:
                frame_type_name = f"Unknown(0x{frame_type:02x})"
            header['frame_type_name'] = frame_type_name

            # Parse command frames (0x0E command)
            if frame_type == 0x0E and len(frame) >= 26:
                # Read command_data_length at [22:24]
                cmd_data_len = struct.unpack('<H', frame[22:24])[0]
                header['cmd_data_length'] = cmd_data_len

                # Command byte at [24]
                header['command_byte'] = frame[24]
                header['command_char'] = (chr(frame[24])
                                        if 32 <= frame[24] < 127
                                        else f'0x{frame[24]:02x}')

                # Sub-command byte at [25]
                header['sub_cmd'] = frame[25]

                # Payload from [26:]
                payload_start = 26
                header['cmd_payload_hex'] = frame[payload_start:].hex() if len(frame) > payload_start else ''
                header['cmd_payload_len'] = len(frame) - payload_start

            # Parse response frames (0x0F response)
            # Response structure: [20:22]=0x0F, [22:24]=cmd_data_len, [24]=status_byte(0x06), [25]=command_echo, [26]=sub_cmd_echo, [27:]=response_payload
            elif frame_type == 0x0F and len(frame) >= 26:
                # Read command_data_length at [22:24]
                cmd_data_len = struct.unpack('<H', frame[22:24])[0]
                header['cmd_data_length'] = cmd_data_len

                # Status byte at [24]
                header['status_byte'] = frame[24]

                # Command echo byte at [25]
                header['command_byte'] = frame[25]
                header['command_char'] = (chr(frame[25])
                                        if 32 <= frame[25] < 127
                                        else f'0x{frame[25]:02x}')

                # Sub-command echo byte at [26] (if present)
                if len(frame) > 26:
                    header['sub_cmd'] = frame[26]
                    # Payload from [27:]
                    payload_start = 27
                    header['cmd_payload_hex'] = frame[payload_start:].hex() if len(frame) > payload_start else ''
                    header['cmd_payload_len'] = len(frame) - payload_start
                else:
                    header['cmd_payload_hex'] = ''
                    header['cmd_payload_len'] = 0

            # For connection frames (0x0A), extract PLC IP from payload at [22:26]
            elif frame_type == 0x0A and len(frame) >= 26:
                plc_ip_bytes = frame[22:26]
                plc_ip = '.'.join(str(b) for b in plc_ip_bytes)
                header['plc_ip'] = plc_ip
                header['connection_payload'] = frame[26:].hex() if len(frame) > 26 else ''

            # For disconnect frames (0x12), payload is typically empty
            elif frame_type == 0x12:
                header['disconnect_payload'] = frame[22:].hex() if len(frame) > 22 else ''

        frames.append(header)

    return frames


def print_summary(frames, verbose=False):
    """Print formatted analysis summary and save replay data.

    Args:
        frames: List of frame dicts from extract_frames()
        verbose: If True, print all frames
    """

    print("=" * 80)
    print("PLC Upload Capture D Analysis")
    print(f"Total frames: {len(frames)}")
    print("=" * 80)

    # Separate by direction
    pc_to_plc = [f for f in frames if f['direction'] == 'PC→PLC']
    plc_to_pc = [f for f in frames if f['direction'] == 'PLC→PC']

    print(f"\nPC→PLC: {len(pc_to_plc)} frames")
    print(f"PLC→PC: {len(plc_to_pc)} frames")

    # BCC validation
    bcc_valid = sum(1 for f in frames if f.get('bcc_valid'))
    bcc_invalid = sum(1 for f in frames if f.get('bcc_valid') is False)
    print(f"\nBCC validation: {bcc_valid} valid, {bcc_invalid} invalid")

    if bcc_invalid > 0:
        print("  ⚠ WARNING: Some frames failed BCC validation")
        print("    This may indicate the research doc header interpretation is incorrect")

    # Command distribution
    print("\n--- Command Distribution ---")
    cmd_counts = {}
    for f in frames:
        frame_type = f.get('frame_type_name', '?')
        cmd = f.get('command_char', '?')
        key = f"{frame_type} {cmd}"
        cmd_counts[key] = cmd_counts.get(key, 0) + 1

    for key in sorted(cmd_counts.keys()):
        print(f"  {key}: {cmd_counts[key]}")

    # Header field analysis (first 10 PC→PLC command frames)
    print("\n--- Header Structure Validation (first 10 PC→PLC command frames) ---")
    print(f"{'#':>3} {'InvID':>5} {'Len':>5} {'FType':>6} {'CmdDataLen':>10} "
          f"{'Cmd':>4} {'Sub':>4} {'CmdPayloadHex (first 20 bytes)'}")
    print("-" * 120)

    command_frames = [f for f in pc_to_plc if f.get('frame_type') == 0x0E]
    for i, f in enumerate(command_frames[:10]):
        inv_id = f.get('invoke_id', '?')
        length = f.get('length', '?')
        ftype = f'0x{f.get("frame_type", 0):02x}'
        cmd_len = f.get('cmd_data_length', '?')

        cmd = f.get('command_char', '?')
        sub = f'0x{f.get("sub_cmd", 0):02x}' if 'sub_cmd' in f else '  -'
        payload_hex = f.get('cmd_payload_hex', '')[:40]

        print(f"{i:>3} {inv_id:>5} {length:>5} {ftype:>6} {cmd_len:>10} "
              f"{cmd:>4} {sub:>4} {payload_hex}")

    # First 5 PLC→PC response frames
    response_frames = [f for f in plc_to_pc if f.get('frame_type') == 0x0F]
    print(f"\n--- First 5 PLC→PC Response Frames (0x0F) ---")
    print(f"{'#':>3} {'InvID':>5} {'Len':>5} {'FType':>6} {'CmdDataLen':>10} "
          f"{'Cmd':>4} {'Sub':>4} {'PayloadLen':>10}")
    print("-" * 100)

    for i, f in enumerate(response_frames[:5]):
        inv_id = f.get('invoke_id', '?')
        length = f.get('length', '?')
        ftype = f'0x{f.get("frame_type", 0):02x}'
        cmd_len = f.get('cmd_data_length', '?')
        cmd = f.get('command_char', '?')
        sub = f'0x{f.get("sub_cmd", 0):02x}' if 'sub_cmd' in f else '  -'
        pay_len = f.get('cmd_payload_len', '?')

        print(f"{i:>3} {inv_id:>5} {length:>5} {ftype:>6} {cmd_len:>10} "
              f"{cmd:>4} {sub:>4} {pay_len:>10}")

    # PC→PLC command sequence analysis
    print("\n--- PC→PLC Command Sequence ---")
    print("Full execution flow with Z command sub-commands:")
    print(f"{'#':>3} {'Cmd':>4} {'Sub':>4} {'CmdDataLen':>10} {'PayloadLen':>10} {'Payload (first 30 bytes)'}")
    print("-" * 120)

    for i, f in enumerate(command_frames):
        cmd = f.get('command_char', '?')
        sub = f'0x{f.get("sub_cmd", 0):02x}' if 'sub_cmd' in f else '  -'
        cmd_len = f.get('cmd_data_length', '?')
        pay_len = f.get('cmd_payload_len', '?')
        payload_hex = f.get('cmd_payload_hex', '')[:30]

        print(f"{i:>3} {cmd:>4} {sub:>4} {cmd_len:>10} {pay_len:>10} {payload_hex}")

    # PRD vs Research doc comparison
    print("\n--- PRD vs Research Doc Header Comparison (first 5 PC→PLC) ---")
    print("This helps determine which header interpretation is correct.")
    print()

    for i, f in enumerate(pc_to_plc[:5]):
        print(f"Frame {i}:")
        print(f"  Raw header hex: {f.get('header_hex', '?')}")

        research_info = (f"PLC_Info=0x{f.get('plc_info', 0):04x} "
                        f"CPU=0x{f.get('cpu_info', 0):02x} "
                        f"SoF=0x{f.get('source_of_frame', 0):02x} "
                        f"InvID={f.get('invoke_id', '?')} "
                        f"Len={f.get('length', '?')} "
                        f"FEnet=0x{f.get('fenet_position', 0):02x} "
                        f"BCC={'OK' if f.get('bcc_valid') else 'FAIL'}")
        print(f"  Research doc: {research_info}")

        prd_info = (f"const={f.get('prd_const', '?')} "
                   f"pad={f.get('prd_padding', '?')} "
                   f"len+5={f.get('prd_len_plus5', '?')} "
                   f"seq={f.get('prd_sequence', '?')} "
                   f"self={f.get('prd_self_ref', '?')} "
                   f"len+1={f.get('prd_len_plus1', '?')}")
        print(f"  PRD interp:   {prd_info}")
        print()

    if verbose:
        # Full frame listing by type
        print("\n--- ALL PC→PLC Command Frames (0x0E) ---")
        print(f"{'#':>3} {'InvID':>5} {'Cmd':>4} {'Sub':>4} {'CmdDataLen':>10} {'PayloadLen':>10}")
        print("-" * 70)

        for i, f in enumerate(command_frames):
            inv_id = f.get('invoke_id', '?')
            cmd = f.get('command_char', '?')
            sub = f'0x{f.get("sub_cmd", 0):02x}' if 'sub_cmd' in f else '  -'
            cmd_len = f.get('cmd_data_length', '?')
            pay_len = f.get('cmd_payload_len', '?')

            print(f"{i:>3} {inv_id:>5} {cmd:>4} {sub:>4} {cmd_len:>10} {pay_len:>10}")

        # Connection and disconnect frames
        other_frames = [f for f in frames if f.get('frame_type') not in (0x0E, 0x0F)]
        if other_frames:
            print(f"\n--- Other Frame Types ---")
            print(f"{'#':>3} {'FType':>10} {'Details':>40}")
            print("-" * 70)
            for i, f in enumerate(other_frames):
                ftype = f.get('frame_type_name', '?')
                if f.get('plc_ip'):
                    details = f"PLC IP: {f.get('plc_ip')}"
                else:
                    details = f"{len(f.get('disconnect_payload', ''))//2} bytes payload"
                print(f"{i:>3} {ftype:>10} {details:>40}")

    # Save replay data (ALL PC→PLC frames: connection + commands + disconnect)
    replay_data = []
    for f in pc_to_plc:
        entry = {
            'index': f['packet_index'],
            'frame_type': f.get('frame_type'),
            'frame_type_hex': f.get('frame_type_hex'),
            'frame_type_name': f.get('frame_type_name'),
            'command': f.get('command_char', '?'),
            'command_byte': f.get('command_byte'),
            'sub_cmd': f.get('sub_cmd'),
            'sub_cmd_hex': f'0x{f.get("sub_cmd", 0):02x}' if 'sub_cmd' in f else None,
            'cmd_data_length': f.get('cmd_data_length'),
            'invoke_id': f.get('invoke_id'),
            'cmd_payload_hex': f.get('cmd_payload_hex', ''),
            'cmd_payload_len': f.get('cmd_payload_len'),
            'frame_hex': f.get('frame_raw', ''),
        }
        # Connection frame extra info
        if f.get('frame_type') == 0x0A:
            entry['plc_ip'] = f.get('plc_ip')
            entry['connection_payload'] = f.get('connection_payload')
        replay_data.append(entry)

    replay_path = os.path.join(os.path.dirname(__file__), 'upload_replay_frames.json')
    with open(replay_path, 'w') as fp:
        json.dump(replay_data, fp, indent=2)

    conn_count = sum(1 for f in replay_data if f.get('frame_type') == 0x0A)
    cmd_count = sum(1 for f in replay_data if f.get('frame_type') == 0x0E)
    disc_count = sum(1 for f in replay_data if f.get('frame_type') == 0x12)
    print(f"\n→ Replay data saved to: {replay_path}")
    print(f"  {len(replay_data)} total PC→PLC frames: {conn_count} connection + {cmd_count} command + {disc_count} disconnect")


def main():
    """Main entry point."""
    verbose = '--verbose' in sys.argv or '-v' in sys.argv

    # Locate capture file
    capture_d = os.path.join(
        os.path.dirname(__file__),
        'docs',
        'pkt_monitor_0410_PLC로부터열기.pcapng'
    )

    if not os.path.exists(capture_d):
        print(f"ERROR: Capture file not found: {capture_d}")
        sys.exit(1)

    print(f"Parsing: {capture_d}")
    packets = parse_pcapng_packets(capture_d)
    print(f"Raw TCP packets on port 2002: {len(packets)}")

    frames = extract_frames(packets)
    print_summary(frames, verbose=verbose)


if __name__ == '__main__':
    main()
