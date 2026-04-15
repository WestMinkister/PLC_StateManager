#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PLC Variable Values Analyze
MW152 캡처 파일에서 변수 읽기(R/0xE0) 요청을 파싱하여 변수 주소 추출

Usage:
    python plc_value_analyze.py [--pcap PATH] [--out FILE] [--verbose]

Features:
    - Extract R/0xE0 command frames from pcapng
    - Decode request payload to extract variable offsets
    - Save variable metadata and frame pairs to JSON
    - Validate request/response pairs
"""
import struct
import json
import sys
import os
import argparse
from pathlib import Path

# Add src directory to path for imports
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

try:
    from plc_upload_analyze import parse_pcapng_packets, extract_frames
except ImportError as e:
    print(f"Error: failed to import plc_upload_analyze: {e}")
    sys.exit(1)


def decode_value_request_payload(payload_hex_ascii):
    """
    Decode R/0xE0 request payload to extract variable offsets.

    The payload_hex_ascii is ASCII encoding of hex characters (e.g., "3030..." = "00...").
    After decoding: Structure is count(BE32) + repeated entries
        [0:4]    count (BE32) - number of expected return bytes (2 bytes per variable)
        [4:]     repeated entries: type(1) + marker(4D 42 02 XX) + offset(LE16) + padding(1)
                 Stride: 8 bytes per entry
        [end]    trailer: 0x00 0x0A (may vary)

    Returns:
        {
            'count': int,
            'variables': [{'offset': int, 'offset_hex': str}, ...],
            'entry_count': int
        }
    """
    # Step 1: Convert ASCII hex string to bytes
    try:
        payload_bytes_ascii = bytes.fromhex(payload_hex_ascii)
    except ValueError as e:
        return {'error': f'Failed to decode ASCII hex: {e}', 'variables': []}

    # Step 2: Decode ASCII bytes to hex string, then to actual bytes
    try:
        payload_hex = payload_bytes_ascii.decode('ascii')
        payload_bytes = bytes.fromhex(payload_hex)
    except (ValueError, UnicodeDecodeError) as e:
        return {'error': f'Failed to decode double-hex: {e}', 'variables': []}

    if len(payload_bytes) < 4:
        return {'error': 'Payload too short', 'variables': []}

    # Parse count (BE32)
    count = struct.unpack('>I', payload_bytes[0:4])[0]

    # Parse entries with stride 8
    variables = []
    pos = 4
    while pos + 8 <= len(payload_bytes):
        chunk = payload_bytes[pos:pos+8]
        # type_byte = chunk[0]  # e.g., 0x05 or 0x00
        marker = chunk[1:5]  # Should be something like 4D 42 02 XX (MB...)
        offset_le = struct.unpack('<H', chunk[5:7])[0]

        variables.append({
            'marker_hex': marker.hex(),
            'offset': offset_le,
            'offset_hex': f'0x{offset_le:04x}'
        })
        pos += 8

    # Remaining bytes (trailer)
    trailer = payload_bytes[pos:].hex() if pos < len(payload_bytes) else ''

    return {
        'count': count,
        'payload_len': len(payload_bytes),
        'variables': variables,
        'entry_count': len(variables),
        'trailer_hex': trailer
    }


def find_r_request_response_pairs(frames):
    """
    Find matching R/0xE0 request-response pairs from frame list.

    Returns:
        List of {'index': int, 'request': frame, 'response': frame}
    """
    pairs = []
    requests = []
    responses = []

    for idx, frame in enumerate(frames):
        if frame.get('command_byte') == 0x52:  # 'R'
            if frame.get('frame_type') == 0x0E:  # Command
                requests.append((idx, frame))
            elif frame.get('frame_type') == 0x0F:  # Response
                responses.append((idx, frame))

    # Match by sequence
    for req_idx, (req_frame_idx, req_frame) in enumerate(requests):
        if req_idx < len(responses):
            rsp_frame_idx, rsp_frame = responses[req_idx]
            pairs.append({
                'index': req_idx,
                'request_frame_idx': req_frame_idx,
                'response_frame_idx': rsp_frame_idx,
                'request': req_frame,
                'response': rsp_frame
            })

    return pairs


def main():
    parser = argparse.ArgumentParser(
        description='Analyze R/0xE0 frames from MW152 capture'
    )
    parser.add_argument('--pcap', type=str, metavar='PATH',
                        help='Path to pcapng capture file')
    parser.add_argument('--out', type=str, metavar='FILE', default='value_read_frames.json',
                        help='Output JSON file (default: value_read_frames.json)')
    parser.add_argument('--verbose', action='store_true',
                        help='Print detailed analysis')

    args = parser.parse_args()

    # Determine pcap path
    if args.pcap:
        pcap_path = args.pcap
    else:
        # Default to MW152 file in PLC_ProgramTraker/docs
        base_dir = Path('/Users/kangminki/Desktop/Important/AI/SmartFactory/PLC_ProgramTraker/docs')
        candidates = sorted([f for f in base_dir.glob('*MW152*.pcapng')])
        if candidates:
            pcap_path = str(candidates[0])
        else:
            print("Error: No MW152 pcapng file found in docs directory")
            print(f"  Checked: {base_dir}")
            sys.exit(1)

    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        print(f"Error: {pcap_path} not found")
        sys.exit(1)

    if args.verbose:
        print(f"Analyzing: {pcap_path.name}")

    # Parse capture
    try:
        packets = parse_pcapng_packets(str(pcap_path))
        frames = extract_frames(packets)
    except Exception as e:
        print(f"Error parsing capture: {e}")
        sys.exit(1)

    # Find R/0xE0 pairs
    pairs = find_r_request_response_pairs(frames)

    if not pairs:
        print("Error: No R/0xE0 request-response pairs found in capture")
        sys.exit(1)

    if args.verbose:
        print(f"Found {len(pairs)} R/0xE0 pairs")

    # Analyze first request to extract variables
    first_req = pairs[0]['request']
    payload_hex = first_req.get('cmd_payload_hex', '')

    if not payload_hex:
        print("Error: First request has no payload")
        sys.exit(1)

    req_analysis = decode_value_request_payload(payload_hex)

    if 'error' in req_analysis:
        print(f"Error analyzing request payload: {req_analysis['error']}")
        sys.exit(1)

    # Build output
    output = {
        'source': pcap_path.name,
        'capture_path': str(pcap_path),
        'sample_count': len(pairs),
        'variables': req_analysis['variables'],
        'variable_count': len(req_analysis['variables']),
        'pairs': []
    }

    # Add pair details
    for pair in pairs:
        req = pair['request']
        rsp = pair['response']
        pair_info = {
            'index': pair['index'],
            'request_frame_idx': pair['request_frame_idx'],
            'response_frame_idx': pair['response_frame_idx'],
            'request_payload_hex': req.get('cmd_payload_hex', ''),
            'response_payload_hex': rsp.get('cmd_payload_hex', ''),
        }
        output['pairs'].append(pair_info)

    # Save output
    out_path = Path(args.out)
    try:
        with open(out_path, 'w') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        print(f"✓ Saved to {out_path}")
    except Exception as e:
        print(f"Error saving output: {e}")
        sys.exit(1)

    if args.verbose:
        print()
        print(f"Variables extracted ({len(output['variables'])}):")
        for var in output['variables']:
            print(f"  Marker: {var['marker_hex']}, Offset: {var['offset_hex']} ({var['offset']})")
        print()
        print(f"Request/Response pairs: {len(output['pairs'])}")


if __name__ == '__main__':
    main()
