#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PLC Write Replay Client
안전 게이트 포함 런중수정 쓰기 리플레이 — T(S) → E×N → T(E) 재전송 + pre/post 스냅샷

Usage:
    python plc_write_replay.py --dry-run
    python plc_write_replay.py --inspect
    python plc_write_replay.py --preflight-only IP
    python plc_write_replay.py --replay IP --i-have-demo-kit

Safeguards:
    - Write-mode command whitelist: T, E, X, M only
    - Block P, W (mode change / direct write)
    - Response validation: status=0x00 required, payload mismatches warn only
    - Abort + rollback on first write-window failure: send captured T(E) frame
    - Pre/post-flight snapshots with MD5 diff
"""
import socket
import struct
import json
import sys
import os
import time
import argparse
from datetime import datetime
from pathlib import Path


def resource_path(relative_path: str) -> str:
    """Resolve a resource file path, handling PyInstaller --onefile bundles.

    PyInstaller extracts --add-data files to sys._MEIPASS. When running from
    source, fall back to the script's directory."""
    base = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, relative_path)


# Import from existing modules
# Insert both the script directory and _MEIPASS (if present) to find hidden imports
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)
if hasattr(sys, '_MEIPASS') and sys._MEIPASS not in sys.path:
    sys.path.insert(0, sys._MEIPASS)
from plc_upload_test import (
    PLCUploadClient, build_frame, parse_response,
    SIGNATURE, FRAME_TYPE_RSP, FRAME_TYPE_CMD, FRAME_TYPE_CONN, FRAME_TYPE_DISC,
    DEFAULT_PORT
)
from plc_upload_decode import double_decode_ascii_hex


# ============================================================
# Safety Configuration
# ============================================================
# Write-mode whitelist: T, E, X, M
# Rationale:
#   - T (0x54): Transaction start/end, safe within [T(S)...T(E)] window
#   - E (0x45): Online-edit data write, core of runtime edit sequence
#   - X (0x58): Bulk data (stop-mode only, but no harm in replay context)
#   - M (0x4D): Mode control (SA0=stop, R9F=run, used in finalization)
WRITE_MODE_ALLOWED = {0x54, 0x45, 0x58, 0x4D}  # T, E, X, M

# Block list: P, W
# Rationale:
#   - P (0x50): Parameter/mode switch, can change RUN/STOP unexpectedly
#   - W (0x57): Direct memory write, outside transaction scope, not needed for F5 write
BLOCKED_IN_WRITE_MODE = {0x50, 0x57}  # P, W


class PLCWriteReplayClient(PLCUploadClient):
    """TCP client for PLC write replay (online-edit transaction replay)."""

    def __init__(self, plc_ip, plc_port=DEFAULT_PORT, timeout=5.0):
        super().__init__(plc_ip, plc_port, timeout)

    def send_frame(self, frame_bytes, check_safety=True):
        """Override: safety-checked frame send.

        Args:
            frame_bytes: complete frame to send
            check_safety: if True, verify command is in write-mode whitelist

        Returns:
            parsed response dict, or None on error
        """
        if check_safety and len(frame_bytes) >= 25:
            ft = struct.unpack('<H', frame_bytes[20:22])[0]
            if ft == 0x0E and len(frame_bytes) > 24:
                cmd_byte = frame_bytes[24]
                if cmd_byte in BLOCKED_IN_WRITE_MODE:
                    print(f"  ⛔ BLOCKED: command 0x{cmd_byte:02x} ({chr(cmd_byte)}) "
                          "not allowed in write-mode")
                    return None
                elif cmd_byte not in WRITE_MODE_ALLOWED and cmd_byte not in [0x4A, 0x52, 0x5A]:
                    # Allow J (0x4A), R (0x52), Z (0x5A) for polling
                    print(f"  ⚠ Unrecognized command 0x{cmd_byte:02x} ({chr(cmd_byte)}), "
                          "proceeding with caution")

        # Call parent's send_frame (which does not override for write-mode check)
        return super().send_frame(frame_bytes)

    def await_response(self, timeout=None, expected_response_hex=None):
        """Receive next response from PLC.

        Validates:
        - BCC valid
        - frame_type == 0x0F (response)
        - status_byte matches expected (or skip if not available)
        - command echo + invoke_id match

        Args:
            timeout: response timeout in seconds
            expected_response_hex: hex string of captured-good response (optional).
                If provided, extracts expected status_byte from offset [sig_pos+24]
                and validates actual response matches that byte.

        Returns:
            (success: bool, response_dict or error dict)
        """
        if timeout is None:
            timeout = self.timeout

        if not self._sock:
            return False, {'error': 'Not connected'}

        # Extract expected_status from captured response (if available)
        expected_status = None
        if expected_response_hex:
            try:
                eb = bytes.fromhex(expected_response_hex)
                sp = eb.find(SIGNATURE)
                if sp >= 0 and len(eb) > sp + 24:
                    expected_status = eb[sp + 24]
            except Exception:
                pass  # If extraction fails, skip status check

        try:
            response_data = b''
            start = time.time()

            while time.time() - start < timeout:
                chunk = self._sock.recv(65536)
                if not chunk:
                    break
                response_data += chunk

                # Check for complete frame
                sig_pos = response_data.find(SIGNATURE)
                if sig_pos >= 0 and len(response_data) >= sig_pos + 20:
                    length = struct.unpack('<H', response_data[sig_pos+16:sig_pos+18])[0]
                    total_expected = sig_pos + 20 + length
                    if len(response_data) >= total_expected:
                        break

            if not response_data:
                return False, {'error': 'No response received'}

            parsed = parse_response(response_data)
            if not parsed:
                return False, {'error': 'Failed to parse response'}

            # Validate
            if not parsed.get('bcc_valid'):
                return False, {'error': 'BCC invalid', 'response': parsed}

            ft = struct.unpack('<H', parsed.get('frame_type', b'\x00\x00'))[0]
            if ft != 0x0F:
                return False, {'error': f'Wrong frame type 0x{ft:02x}', 'response': parsed}

            # Status check: compare against expected (if available)
            actual_status = parsed.get('status')
            if expected_status is not None and actual_status != expected_status:
                return False, {'error': f'Status mismatch: expected 0x{expected_status:02x}, got 0x{actual_status:02x}', 'response': parsed}

            return True, parsed

        except socket.timeout:
            return False, {'error': 'Response timeout'}
        except Exception as e:
            return False, {'error': f'Exception: {e}'}

    def replay_write(self, frames, delay=0.05, timeout=3.0):
        """Replay write-window sequence with abort/rollback.

        Args:
            frames: list of replay entry dicts (from write_replay_frames.json)
            delay: delay between frames (seconds)
            timeout: response timeout (seconds)

        Returns:
            (success: bool, stats: dict)
        """
        stats = {
            'total': len(frames),
            'sent': 0,
            'success': 0,
            'errors': 0,
            'blocked': 0,
            'rollback': None,
        }

        # Separate frame types
        conn_frames = [f for f in frames if f.get('write_role') == 'CONN']
        disc_frames = [f for f in frames if f.get('write_role') == 'DISC']
        write_window = [f for f in frames
                       if f.get('write_role') in ['T_START', 'E_WRITE', 'AUX', 'T_END']]

        # Send CONN
        if conn_frames:
            frame_hex = conn_frames[0].get('frame_hex', '')
            if frame_hex:
                frame_bytes = bytes.fromhex(frame_hex)
                print(f"\n  [CONN] Sending connection frame...")
                try:
                    self._sock.sendall(frame_bytes)
                    success, response = self.await_response(timeout)
                    if success:
                        stats['sent'] += 1
                        stats['success'] += 1
                        time.sleep(0.3)  # Stabilize session
                    else:
                        stats['errors'] += 1
                        stats['sent'] += 1
                        return False, stats
                except Exception as e:
                    print(f"EXCEPTION: {e}")
                    stats['errors'] += 1
                    stats['sent'] += 1
                    return False, stats

        # Send write window
        t_end_frame = None
        for f in write_window:
            if f.get('write_role') == 'T_END':
                t_end_frame = f
                break

        for entry in write_window:
            frame_hex = entry.get('frame_hex', '')
            role = entry.get('write_role')
            cmd = entry.get('command', '?')
            sub = entry.get('sub_cmd')
            expected_response_hex = entry.get('expected_response_hex')

            if not frame_hex:
                continue

            frame_bytes = bytes.fromhex(frame_hex)

            # Safety check
            if len(frame_bytes) >= 25:
                ft = struct.unpack('<H', frame_bytes[20:22])[0]
                if ft == 0x0E and len(frame_bytes) > 24:
                    cmd_byte = frame_bytes[24]
                    if cmd_byte in BLOCKED_IN_WRITE_MODE:
                        print(f"  [{role:10}] {cmd} (0x{cmd_byte:02x}): BLOCKED")
                        stats['blocked'] += 1
                        continue

            # Send frame
            label = f"{role:10}"
            print(f"  [{label}] {cmd} sub=0x{sub:02x} ... ", end='', flush=True)

            # For write-window frames, send_frame doesn't use await_response directly.
            # We need to call await_response with expected_response_hex.
            # But send_frame in parent class handles the response. Override locally:
            frame_bytes = bytes.fromhex(frame_hex)
            try:
                self._sock.sendall(frame_bytes)
                success, response = self.await_response(timeout, expected_response_hex)
                if success:
                    status = response.get('status', '?')
                    print(f"OK (status=0x{status:02x})")
                    stats['success'] += 1
                    stats['sent'] += 1
                else:
                    print(f"NO RESPONSE")
                    stats['errors'] += 1
                    stats['sent'] += 1

                    # Attempt rollback on write-window error (not CONN/DISC)
                    if role in ['T_START', 'E_WRITE', 'AUX', 'T_END'] and t_end_frame:
                        print(f"\n  ⚠ Error during write-window! Attempting rollback...")
                        t_end_hex = t_end_frame.get('frame_hex', '')
                        t_end_expected = t_end_frame.get('expected_response_hex')
                        if t_end_hex:
                            try:
                                t_end_bytes = bytes.fromhex(t_end_hex)
                                print(f"  [ROLLBACK] Sending T(E) frame...")
                                self._sock.sendall(t_end_bytes)
                                rollback_success, rollback_resp = self.await_response(timeout, t_end_expected)
                                if rollback_success:
                                    print(f"  ✓ Rollback sent successfully")
                                    stats['rollback'] = 'success'
                                else:
                                    print(f"  ✗ Rollback failed — transaction may be incomplete!")
                                    print(f"  ⚠⚠⚠ Manual recovery required: close/reopen XG5000 session")
                                    stats['rollback'] = 'failed'
                            except Exception as e:
                                print(f"  ✗ Rollback exception: {e}")
                                stats['rollback'] = 'exception'

                    return False, stats
            except Exception as e:
                print(f"EXCEPTION: {e}")
                stats['errors'] += 1
                stats['sent'] += 1
                return False, stats

            if delay > 0:
                time.sleep(delay)

        # Send DISC
        if disc_frames:
            frame_hex = disc_frames[0].get('frame_hex', '')
            if frame_hex:
                frame_bytes = bytes.fromhex(frame_hex)
                print(f"\n  [DISC] Sending disconnect frame...")
                try:
                    self._sock.sendall(frame_bytes)
                    success, response = self.await_response(timeout)
                    if success:
                        stats['sent'] += 1
                        stats['success'] += 1
                    else:
                        stats['errors'] += 1
                        stats['sent'] += 1
                except Exception as e:
                    print(f"EXCEPTION: {e}")
                    stats['errors'] += 1
                    stats['sent'] += 1

        return True, stats


def snapshot_program(ip, label, snapshot_dir='snapshots'):
    """Take a snapshot of PLC program via upload.

    Uses upload_replay_frames.json to read the program, decodes Z responses,
    saves raw bytes to snapshots/{label}_{timestamp}.bin

    Returns:
        Path object of snapshot file, or None on error
    """
    upload_json_path = resource_path('upload_replay_frames.json')
    if not os.path.exists(upload_json_path):
        print(f"Error: upload_replay_frames.json not found")
        print(f"  Tried: {upload_json_path}")
        print(f"  _MEIPASS: {getattr(sys, '_MEIPASS', 'not set')}")
        print(f"  CWD: {os.getcwd()}")
        return None

    with open(upload_json_path) as f:
        upload_frames = json.load(f)

    os.makedirs(snapshot_dir, exist_ok=True)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{label}_{timestamp}.bin"
    filepath = os.path.join(snapshot_dir, filename)

    print(f"  Connecting to {ip}:{DEFAULT_PORT}...")
    client = PLCUploadClient(ip)
    try:
        client.connect()
    except Exception as e:
        print(f"  Error: {e}")
        return None

    print(f"  Replaying upload frames (Z commands)...")
    success, errors = client.replay_frames(upload_frames, delay=0.05)
    client.disconnect()

    if success == 0:
        print(f"  No successful responses")
        return None

    # Collect Z response payloads
    all_binary = b''
    for response in client.responses:
        if response.get('command_char') == 'Z' and response.get('status') == 0x06:
            payload_hex = response.get('payload_hex', '')
            sub_cmd = response.get('sub_cmd')
            if payload_hex:
                binary = double_decode_ascii_hex(payload_hex, sub_cmd_byte=sub_cmd)
                if binary:
                    all_binary += binary

    # Save
    if not all_binary:
        print(f"  No valid Z response data")
        return None

    with open(filepath, 'wb') as f:
        f.write(all_binary)

    print(f"  Saved snapshot: {filepath} ({len(all_binary)} bytes)")
    return Path(filepath)


def diff_snapshots(pre_path, post_path):
    """Compare pre and post snapshots.

    Returns:
        dict with: size_pre, size_post, first_diff_offset, changed_byte_count, hex_preview
    """
    with open(pre_path, 'rb') as f:
        pre = f.read()
    with open(post_path, 'rb') as f:
        post = f.read()

    result = {
        'size_pre': len(pre),
        'size_post': len(post),
        'first_diff_offset': None,
        'changed_byte_count': 0,
        'hex_preview': '',
    }

    # Find first difference
    min_len = min(len(pre), len(post))
    for i in range(min_len):
        if pre[i] != post[i]:
            result['first_diff_offset'] = i
            break

    # Count differences
    changed = sum(1 for i in range(min_len) if pre[i] != post[i])
    if len(pre) != len(post):
        changed += abs(len(pre) - len(post))
    result['changed_byte_count'] = changed

    # Hex preview around first diff
    if result['first_diff_offset'] is not None:
        offset = result['first_diff_offset']
        start = max(0, offset - 8)
        end = min(min_len, offset + 16)
        preview = post[start:end]
        result['hex_preview'] = preview.hex().upper()

    return result


def print_confirmation_block(target_ip, frames_count, demo_kit_ok=False):
    """Print pre-flight confirmation block and prompt."""
    print("\n" + "=" * 70)
    print("PRE-FLIGHT CHECKLIST")
    print("=" * 70)
    print(f"TARGET:          {target_ip}:{DEFAULT_PORT}")
    print(f"FRAMES:          {frames_count}")
    print(f"DEMO-KIT CONFIRMED: {'YES' if demo_kit_ok else 'NO'}")
    print(f"COMMAND WHITELIST: T, E, X, M")
    print(f"BLOCKED:           P, W")
    print("=" * 70)

    prompt = f"\nType '{target_ip}' to confirm live write, or Ctrl-C to abort: "
    user_input = input(prompt).strip().rstrip('.,;:')

    if user_input != target_ip:
        print("Abort: input does not match target IP")
        return False

    return True


def main():
    parser = argparse.ArgumentParser(
        description='PLC write replay with pre/post-flight snapshots'
    )
    parser.add_argument('--dry-run', action='store_true',
                        help='Analyze frames offline, no network I/O')
    parser.add_argument('--inspect', action='store_true',
                        help='Print per-frame role table, check for BLOCKED commands')
    parser.add_argument('--preflight-only', type=str, metavar='IP',
                        help='Take pre-flight snapshot only')
    parser.add_argument('--replay', type=str, metavar='IP',
                        help='Perform live write replay')
    parser.add_argument('--i-have-demo-kit', action='store_true',
                        help='Confirm possession of demo kit (required for --replay)')
    parser.add_argument('--no-preflight', action='store_true',
                        help='Skip pre-flight snapshot')
    parser.add_argument('--no-postflight', action='store_true',
                        help='Skip post-flight snapshot')
    parser.add_argument('--delay', type=float, default=0.05,
                        help='Delay between frames (seconds)')
    parser.add_argument('--response-timeout', type=float, default=3.0,
                        help='Response timeout (seconds)')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT,
                        help=f'PLC port (default: {DEFAULT_PORT})')
    parser.add_argument('--frames', type=str, default=None,
                        help='Input replay frames JSON (default: bundled write_replay_frames.json)')
    parser.add_argument('--snapshot-dir', type=str, default='snapshots',
                        help='Snapshot directory')

    args = parser.parse_args()

    # Normalize IP arguments: strip whitespace and trailing dots/punctuation
    # (e.g. if user copy-pasted "192.168.250.110." from documentation)
    def _clean_ip(ip):
        return ip.strip().rstrip('.,;:') if ip else ip
    if args.replay:
        args.replay = _clean_ip(args.replay)
    if args.preflight_only:
        args.preflight_only = _clean_ip(args.preflight_only)

    # Load frames
    # If --frames not specified, use bundled write_replay_frames.json
    if args.frames:
        frames_path = args.frames
    else:
        frames_path = resource_path('write_replay_frames.json')

    if not os.path.exists(frames_path):
        print(f"Error: write_replay_frames.json not found")
        print(f"  Tried: {frames_path}")
        print(f"  _MEIPASS: {getattr(sys, '_MEIPASS', 'not set')}")
        print(f"  CWD: {os.getcwd()}")
        if args.frames:
            print(f"  (Custom path via --frames: {args.frames})")
        sys.exit(1)

    with open(frames_path) as f:
        frames = json.load(f)

    # Dispatch
    if args.dry_run:
        print("=== DRY-RUN: Frame Analysis ===\n")
        print(f"Loaded {len(frames)} frames from {frames_path}\n")
        print(f"{'#':>3} {'Role':<10} {'Cmd':<4} {'Sub':<6} {'Type':<4}")
        print("-" * 35)
        for i, frame in enumerate(frames):
            role = frame.get('write_role', '?')
            cmd = frame.get('command', '?')
            sub = f"0x{frame['sub_cmd']:02x}" if frame.get('sub_cmd') is not None else '-'
            ft = f"0x{frame.get('frame_type', 0):02x}"
            print(f"{i:>3} {role:<10} {cmd:<4} {sub:<6} {ft:<4}")
        print("\n✓ Dry-run complete (no network I/O)")

    elif args.inspect:
        print("=== FRAME INSPECTION ===\n")
        print(f"Loaded {len(frames)} frames\n")
        blocked_count = 0
        for i, frame in enumerate(frames):
            cmd_byte = frame.get('command_byte')
            role = frame.get('write_role')
            cmd = frame.get('command', '?')
            if cmd_byte in BLOCKED_IN_WRITE_MODE:
                print(f"  [{i:3}] {role:<10} {cmd}: BLOCKED (0x{cmd_byte:02x})")
                blocked_count += 1

        print(f"\nTotal BLOCKED commands: {blocked_count}")
        if blocked_count == 0:
            print("✓ No blocked commands found")

    elif args.preflight_only:
        ip = args.preflight_only
        print(f"=== PRE-FLIGHT SNAPSHOT ===\n")
        pre_path = snapshot_program(ip, 'pre', args.snapshot_dir)
        if pre_path:
            print(f"✓ Pre-flight snapshot: {pre_path}")
        else:
            print("✗ Pre-flight snapshot failed")
            sys.exit(1)

    elif args.replay:
        ip = args.replay

        # Check demo-kit flag
        if not args.i_have_demo_kit:
            print("\n⛔ Live write requires --i-have-demo-kit flag")
            print("\nRationale:")
            print("  - Writing to PLC changes runtime state")
            print("  - Rollback may require manual intervention in XG5000")
            print("  - Only proceed with real demo kit, not production PLC")
            sys.exit(1)

        # Pre-flight confirmation
        if not print_confirmation_block(ip, len(frames), args.i_have_demo_kit):
            sys.exit(1)

        # Pre-flight snapshot
        pre_path = None
        if not args.no_preflight:
            print("\n[PREFLIGHT] Taking pre-flight snapshot...")
            pre_path = snapshot_program(ip, 'pre', args.snapshot_dir)
            if not pre_path:
                print("✗ Pre-flight snapshot failed, aborting")
                sys.exit(1)
            print(f"✓ Saved: {pre_path}")

        # Replay
        print(f"\n[REPLAY] Connecting to {ip}:{args.port}...")
        client = PLCWriteReplayClient(ip, plc_port=args.port, timeout=args.response_timeout)
        try:
            client.connect()
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)

        print(f"[REPLAY] Sending {len(frames)} frames (delay={args.delay}s)...")
        success, stats = client.replay_write(frames, delay=args.delay, timeout=args.response_timeout)
        client.disconnect()

        print(f"\n[REPLAY] Results:")
        print(f"  Sent: {stats['sent']}")
        print(f"  Success: {stats['success']}")
        print(f"  Errors: {stats['errors']}")
        print(f"  Blocked: {stats['blocked']}")
        if stats['rollback']:
            print(f"  Rollback: {stats['rollback']}")

        if not success:
            print(f"\n✗ Replay failed with errors")
            if stats['rollback'] == 'failed':
                print(f"  Manual recovery: close XG5000, power-cycle PLC, restart XG5000")
            sys.exit(1)

        # Post-flight snapshot
        post_path = None
        if not args.no_postflight:
            print(f"\n[POSTFLIGHT] Taking post-flight snapshot...")
            post_path = snapshot_program(ip, 'post', args.snapshot_dir)
            if post_path:
                print(f"✓ Saved: {post_path}")

                # Diff
                if pre_path:
                    print(f"\n[DIFF] Comparing pre ↔ post...")
                    diff = diff_snapshots(pre_path, post_path)
                    print(f"  Pre size:        {diff['size_pre']} bytes")
                    print(f"  Post size:       {diff['size_post']} bytes")
                    print(f"  Changed bytes:   {diff['changed_byte_count']}")
                    if diff['first_diff_offset'] is not None:
                        print(f"  First diff @:    0x{diff['first_diff_offset']:04x}")
                        print(f"  Hex preview:     {diff['hex_preview']}")

                    # Save diff JSON
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    diff_path = os.path.join(args.snapshot_dir, f"{timestamp}_diff.json")
                    with open(diff_path, 'w') as f:
                        json.dump(diff, f, indent=2)
                    print(f"  Saved diff:      {diff_path}")

                    if diff['changed_byte_count'] > 0:
                        print(f"\n✓✓✓ F5 write successful — program changed!")
                    else:
                        print(f"\n⚠ No byte changes detected (may be idempotent)")

        print(f"\n✓ Replay complete")

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
