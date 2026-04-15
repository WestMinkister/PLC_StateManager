#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PLC Write Capture Analyzer
온라인 에디팅(런중수정) 쓰기 윈도우 추출 — T(S) → E×N → T(E) 캡처 분석

Usage:
    python plc_write_analyze.py [--verbose] [--pcap PATH] [--out PATH]

Features:
    - Extract the online-edit write window from pcapng capture
    - Classify frames: T_START, E_WRITE, T_END, AUX (X/M/J/R), CONN/DISC
    - Validate BCC on all frames
    - Save replay data to write_replay_frames.json matching upload schema
    - Include response-pairing metadata for validation
"""
import struct
import sys
import os
import json
import argparse
from plc_upload_analyze import parse_pcapng_packets, parse_lgis_header, extract_frames


def resource_path(relative_path: str) -> str:
    """Resolve a resource file path, handling PyInstaller --onefile bundles.

    PyInstaller extracts --add-data files to sys._MEIPASS. When running from
    source, fall back to the script's directory."""
    base = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, relative_path)


DEFAULT_PCAPNG = os.path.join(os.path.dirname(__file__), 'docs',
    'pkt_monitor_0410_런중수정시작_두프로그램접점을F5로바꿔서런중수정쓰기_런중수정종료.pcapng')


def classify_write_frame(frame: dict) -> str:
    """Classify a frame by its role in the write sequence.

    Returns: 'T_START'|'T_END'|'E_WRITE'|'AUX'|'CONN'|'DISC'

    T_START vs T_END are distinguished by sub_cmd byte:
    - T(S, "S1000...") = 0x53 ('S') at byte 25
    - T(E, "E1000...") = 0x45 ('E') at byte 25

    If unsure, use positional rule (first T = START, last T = END).
    """
    direction = frame.get('direction', '')
    frame_type = frame.get('frame_type')
    command_byte = frame.get('command_byte')
    sub_cmd = frame.get('sub_cmd')

    # Only classify PC→PLC frames for write window
    if direction != 'PC→PLC':
        return 'UNKNOWN'

    # Connection/Disconnect
    if frame_type == 0x0A:
        return 'CONN'
    if frame_type == 0x12:
        return 'DISC'

    # Response or non-command frames skip
    if frame_type != 0x0E:
        return 'UNKNOWN'

    # Classify by command byte
    if command_byte == 0x54:  # T
        # Distinguish T(S) vs T(E) by sub_cmd
        if sub_cmd == 0x53:  # 'S'
            return 'T_START'
        elif sub_cmd == 0x45:  # 'E'
            return 'T_END'
        else:
            # Ambiguous: log and use positional rule later
            return 'T_UNKNOWN'

    elif command_byte == 0x45:  # E
        return 'E_WRITE'

    elif command_byte in [0x58, 0x4D, 0x4A, 0x52]:  # X, M, J, R
        return 'AUX'

    return 'OTHER'


def find_write_window(pc_to_plc_frames: list) -> tuple[int, int]:
    """Find the write window: (start_idx, end_idx) of PC→PLC frames.

    start_idx = index of first T frame (T_START)
    end_idx = index of last T frame (T_END)

    Raises ValueError if fewer than 2 T frames found.
    """
    t_indices = []

    for idx, frame in enumerate(pc_to_plc_frames):
        role = classify_write_frame(frame)
        if role in ['T_START', 'T_END', 'T_UNKNOWN']:
            t_indices.append(idx)

    if len(t_indices) < 2:
        raise ValueError(f"Expected ≥2 T frames, found {len(t_indices)}")

    start_idx = t_indices[0]
    end_idx = t_indices[-1]

    # Resolve T_UNKNOWN using positional rule
    if classify_write_frame(pc_to_plc_frames[start_idx]) == 'T_UNKNOWN':
        print(f"  ⓘ T frame at idx {start_idx} sub_cmd=0x{pc_to_plc_frames[start_idx]['sub_cmd']:02x}: "
              "assuming T_START (first T)")
    if classify_write_frame(pc_to_plc_frames[end_idx]) == 'T_UNKNOWN':
        print(f"  ⓘ T frame at idx {end_idx} sub_cmd=0x{pc_to_plc_frames[end_idx]['sub_cmd']:02x}: "
              "assuming T_END (last T)")

    return start_idx, end_idx


def _borrow_frame_from_upload(frame_role: str) -> dict | None:
    """Borrow a CONN or DISC frame from upload_replay_frames.json.

    Args:
        frame_role: 'CONN' (frame_type 0x0A) or 'DISC' (frame_type 0x12)

    Returns:
        Frame dict matching schema, or None if not found.

    Prints warning if borrowed.
    """
    upload_path = resource_path('upload_replay_frames.json')

    if not os.path.exists(upload_path):
        return None

    try:
        with open(upload_path, 'r', encoding='utf-8') as f:
            upload_frames = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None

    # Map role to frame_type
    frame_type_map = {'CONN': 10, 'DISC': 18}  # 0x0A = 10, 0x12 = 18
    target_type = frame_type_map.get(frame_role)

    if target_type is None:
        return None

    # Find first matching frame
    for frame in upload_frames:
        if frame.get('frame_type') == target_type:
            plc_ip = frame.get('plc_ip', 'unknown')
            print(f"  ⚠ {frame_role} frame not in capture, borrowing from upload_replay_frames.json "
                  f"(PLC IP: {plc_ip})")
            # Create a copy and add frame_raw alias (upload schema uses frame_hex)
            frame = dict(frame)
            frame['frame_raw'] = frame.get('frame_hex', '')
            return frame

    return None


def pair_responses(all_frames: list) -> dict:
    """Build mapping of PC→PLC cmd frames to PLC→PC response frames.

    Uses positional matching: next PLC→PC frame after each PC→PLC frame.
    Also attempts invoke_id matching.

    Returns dict: {(pc_frame_idx): (response_frame_idx, response_data_hex, invoke_id)}
    """
    pairing = {}
    pc_to_plc_indices = [i for i, f in enumerate(all_frames) if f['direction'] == 'PC→PLC']
    plc_to_pc_indices = [i for i, f in enumerate(all_frames) if f['direction'] == 'PLC→PC']

    for pc_idx in pc_to_plc_indices:
        # Find next PLC→PC response (positional match)
        next_plc_idx = None
        for plc_idx in plc_to_pc_indices:
            if plc_idx > pc_idx:
                next_plc_idx = plc_idx
                break

        if next_plc_idx is not None:
            response = all_frames[next_plc_idx]
            pairing[pc_idx] = {
                'response_idx': next_plc_idx,
                'response_hex': response.get('frame_raw', ''),
                'invoke_id': response.get('invoke_id', None),
            }

    return pairing


def extract_write_replay(all_frames: list) -> list[dict]:
    """Extract the write replay sequence.

    Layout: 1 CONN + [frames within T_START...T_END window] + 1 DISC

    Each entry includes:
    - Standard fields from upload_replay_frames.json schema
    - write_role: 'CONN'|'T_START'|'E_WRITE'|'AUX'|'T_END'|'DISC'
    - expected_response_hex: hex string (or '')
    - expected_invoke_id: int or None
    """
    pc_to_plc = [f for f in all_frames if f['direction'] == 'PC→PLC']

    # Find write window
    try:
        start_idx, end_idx = find_write_window(pc_to_plc)
    except ValueError as e:
        raise ValueError(f"Cannot find write window: {e}")

    # Build response pairing
    pairing = pair_responses(all_frames)

    replay = []

    # Find and add first CONN (first PC→PLC frame with frame_type == 0x0A)
    conn_frame = None
    for f in pc_to_plc:
        if f.get('frame_type') == 0x0A:
            conn_frame = f
            break

    if conn_frame:
        entry = _frame_to_replay_entry(conn_frame, 'CONN', pairing)
        replay.append(entry)
    else:
        # Fallback: borrow CONN from upload_replay_frames.json
        conn_frame = _borrow_frame_from_upload('CONN')
        if conn_frame:
            entry = _frame_to_replay_entry(conn_frame, 'CONN', {})
            entry['expected_response_hex'] = ''  # No paired response in write capture
            replay.append(entry)
        else:
            raise ValueError("CONN frame (0x0A) not found in capture and cannot borrow from upload_replay_frames.json")

    # Add all frames in window (T_START → ... → T_END)
    for idx in range(start_idx, end_idx + 1):
        frame = pc_to_plc[idx]
        role = classify_write_frame(frame)
        if role == 'T_UNKNOWN':
            # Resolve using position within window
            if idx == start_idx:
                role = 'T_START'
            elif idx == end_idx:
                role = 'T_END'

        entry = _frame_to_replay_entry(frame, role, pairing)
        replay.append(entry)

    # Find and add first DISC (first PC→PLC frame with frame_type == 0x12)
    disc_frame = None
    for f in pc_to_plc:
        if f.get('frame_type') == 0x12:
            disc_frame = f
            break

    if disc_frame:
        entry = _frame_to_replay_entry(disc_frame, 'DISC', pairing)
        replay.append(entry)
    else:
        # Fallback: borrow DISC from upload_replay_frames.json
        disc_frame = _borrow_frame_from_upload('DISC')
        if disc_frame:
            entry = _frame_to_replay_entry(disc_frame, 'DISC', {})
            entry['expected_response_hex'] = ''  # No paired response in write capture
            replay.append(entry)
        else:
            raise ValueError("DISC frame (0x12) not found in capture and cannot borrow from upload_replay_frames.json")

    return replay


def _frame_to_replay_entry(frame: dict, role: str, pairing: dict) -> dict:
    """Convert a frame dict to replay entry (matching upload_replay_frames.json schema)."""
    # Determine PC→PLC frame index for pairing lookup
    pc_idx = frame.get('packet_index')
    response_hex = ''
    invoke_id = None
    if pc_idx in pairing:
        response_hex = pairing[pc_idx].get('response_hex', '')
        invoke_id = pairing[pc_idx].get('invoke_id')

    # Build replay entry
    entry = {
        'index': frame.get('packet_index', -1),
        'frame_type': frame.get('frame_type'),
        'frame_type_hex': frame.get('frame_type_hex', f"0x{frame.get('frame_type', 0):02x}"),
        'frame_type_name': frame.get('frame_type_name', 'Unknown'),
        'command': frame.get('command_char', '?'),
        'command_byte': frame.get('command_byte'),
        'sub_cmd': frame.get('sub_cmd'),
        'sub_cmd_hex': frame.get('sub_cmd_hex', f"0x{frame.get('sub_cmd', 0):02x}"
                                                   if frame.get('sub_cmd') is not None else None),
        'cmd_data_length': frame.get('cmd_data_length'),
        'invoke_id': frame.get('invoke_id', 0),
        'cmd_payload_hex': frame.get('cmd_payload_hex', ''),
        'cmd_payload_len': frame.get('cmd_payload_len'),
        'frame_hex': frame.get('frame_raw', ''),
        # Write-specific fields
        'write_role': role,
        'expected_response_hex': response_hex,
        'expected_invoke_id': invoke_id,
    }

    return entry


def print_summary(replay, verbose=False):
    """Print role counts, BCC validity, T sub_cmd bytes, command distribution."""
    roles = {}
    for entry in replay:
        role = entry.get('write_role', 'UNKNOWN')
        roles[role] = roles.get(role, 0) + 1

    print("\n" + "=" * 60)
    print("WRITE WINDOW SUMMARY")
    print("=" * 60)
    print(f"Total frames: {len(replay)}")
    print("\nFrame roles:")
    for role in ['CONN', 'T_START', 'E_WRITE', 'AUX', 'T_END', 'DISC']:
        count = roles.get(role, 0)
        print(f"  {role:12} : {count:3}")

    # T sub_cmd values
    t_start = None
    t_end = None
    for entry in replay:
        if entry['write_role'] == 'T_START' and entry.get('sub_cmd') is not None:
            t_start = entry['sub_cmd']
        if entry['write_role'] == 'T_END' and entry.get('sub_cmd') is not None:
            t_end = entry['sub_cmd']

    print(f"\nT frame sub_cmd bytes:")
    if t_start is not None:
        print(f"  T_START: 0x{t_start:02x} ({chr(t_start) if 32 <= t_start < 127 else '?'})")
    if t_end is not None:
        print(f"  T_END:   0x{t_end:02x} ({chr(t_end) if 32 <= t_end < 127 else '?'})")

    # BCC validation
    bcc_valid = sum(1 for e in replay if e.get('frame_hex') and _validate_bcc(bytes.fromhex(e['frame_hex'])))
    bcc_total = sum(1 for e in replay if e.get('frame_hex'))
    print(f"\nBCC validation: {bcc_valid}/{bcc_total} valid")

    # Command distribution
    commands = {}
    for entry in replay:
        cmd = entry.get('command', '?')
        commands[cmd] = commands.get(cmd, 0) + 1

    print("\nCommand distribution:")
    for cmd in sorted(commands.keys()):
        print(f"  {cmd}: {commands[cmd]}")

    if verbose:
        print("\nDetailed frame table:")
        print(f"{'#':>3} {'Role':<10} {'Cmd':<4} {'Sub':>6} {'Len':<6} {'BCC':>4}")
        print("-" * 50)
        for i, entry in enumerate(replay):
            cmd = entry.get('command', '?')
            role = entry.get('write_role', '?')
            sub = f"0x{entry['sub_cmd']:02x}" if entry.get('sub_cmd') is not None else '-'
            length = entry.get('cmd_data_length', '?')
            frame_hex = entry.get('frame_hex', '')
            bcc_ok = '✓' if (frame_hex and _validate_bcc(bytes.fromhex(frame_hex))) else '✗'
            print(f"{i:>3} {role:<10} {cmd:<4} {sub:>6} {length!s:<6} {bcc_ok:>4}")


def _validate_bcc(frame_bytes: bytes) -> bool:
    """Check BCC validity of a frame."""
    if len(frame_bytes) < 20:
        return False
    bcc_actual = frame_bytes[19]
    bcc_calc = sum(frame_bytes[0:19]) % 256
    return bcc_actual == bcc_calc


def main():
    parser = argparse.ArgumentParser(
        description='Extract online-edit write window from pcapng capture'
    )
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Print detailed frame table')
    parser.add_argument('--pcap', type=str, default=DEFAULT_PCAPNG,
                        help=f'Input pcapng file (default: {DEFAULT_PCAPNG})')
    parser.add_argument('--out', type=str, default='write_replay_frames.json',
                        help='Output JSON file')

    args = parser.parse_args()

    # Verify input exists
    if not os.path.exists(args.pcap):
        print(f"Error: pcapng file not found: {args.pcap}")
        sys.exit(1)

    print(f"Reading pcapng: {args.pcap}")

    # Parse capture
    packets = parse_pcapng_packets(args.pcap)
    print(f"  → {len(packets)} packets found")

    # Extract frames
    all_frames = extract_frames(packets)
    print(f"  → {len(all_frames)} LGIS-GLOFA frames extracted")

    # Separate PC→PLC
    pc_to_plc = [f for f in all_frames if f['direction'] == 'PC→PLC']
    print(f"  → {len(pc_to_plc)} PC→PLC frames")

    # Extract write window
    try:
        replay = extract_write_replay(all_frames)
        print(f"  → {len(replay)} frames in write window")
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    # Validate
    invalid_bcc = [e for e in replay if e.get('frame_hex') and
                   not _validate_bcc(bytes.fromhex(e['frame_hex']))]
    if invalid_bcc:
        print(f"\nWarning: {len(invalid_bcc)} frames have invalid BCC")
        for e in invalid_bcc:
            print(f"  Frame {e['index']}: {e['write_role']}")

    # Save
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(replay, f, indent=2)
    print(f"\nSaved: {args.out}")

    # Summary
    print_summary(replay, args.verbose)


if __name__ == '__main__':
    main()
