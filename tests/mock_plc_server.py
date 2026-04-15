#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mock PLC TCP server for offline replay testing.

Accepts LGIS-GLOFA frames, returns captured expected_response_hex from
write_replay_frames.json. NOT a real PLC simulator — only echoes recorded responses.

Usage:
    python3 mock_plc_server.py --port 12002
    python3 mock_plc_server.py --port 12002 --frames ../write_replay_frames.json

Test with:
    python3 ../plc_write_replay.py --replay 127.0.0.1 --port 12002 \\
      --i-have-demo-kit --no-preflight --no-postflight --delay 0.01 \\
      --response-timeout 2.0
"""
import socket
import struct
import json
import sys
import os
import argparse
import logging
from pathlib import Path

# LGIS-GLOFA frame signature and constants
SIGNATURE = b'LGIS-GLOFA'
FRAME_TYPE_CONN = 0x0A
FRAME_TYPE_CMD = 0x0E
FRAME_TYPE_DISC = 0x12
FRAME_TYPE_RSP = 0x0F

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


class MockPLCServer:
    """Single-threaded mock PLC TCP server that echoes captured responses."""

    def __init__(self, host='127.0.0.1', port=12002, frames_json=None):
        self.host = host
        self.port = port
        self.frames_json = frames_json or 'write_replay_frames.json'
        self.server_sock = None
        self.client_sock = None
        self.frames = []
        self.lookup = {}  # (frame_type, cmd_byte, sub_cmd) -> frame entry
        self.request_count = 0
        self.response_count = 0

        self._load_frames()
        self._build_lookup()

    def _load_frames(self):
        """Load write_replay_frames.json."""
        try:
            with open(self.frames_json, 'r') as f:
                self.frames = json.load(f)
            logger.info(f"Loaded {len(self.frames)} frames from {self.frames_json}")
        except FileNotFoundError:
            logger.error(f"Frames file not found: {self.frames_json}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse frames JSON: {e}")
            sys.exit(1)

    def _build_lookup(self):
        """Build lookup table: (frame_type, cmd_byte, sub_cmd) -> response_hex."""
        for frame in self.frames:
            ft = frame.get('frame_type')
            cmd = frame.get('command_byte')
            sub = frame.get('sub_cmd')
            role = frame.get('write_role', '')
            resp = frame.get('expected_response_hex', '')

            if ft == FRAME_TYPE_CONN:
                # CONN: no cmd_byte, key by frame_type alone
                key = ('CONN', None, None)
                self.lookup[key] = (role, resp)
            elif ft == FRAME_TYPE_DISC:
                # DISC: no cmd_byte, key by frame_type alone
                key = ('DISC', None, None)
                self.lookup[key] = (role, resp)
            elif cmd is not None:
                # CMD frame: key by (cmd_byte, sub_cmd)
                # For disambiguation, also store with invoke_id if needed later
                key = (cmd, sub)
                self.lookup[key] = (role, resp)

        logger.info(f"Built lookup table with {len(self.lookup)} entries")

    def start(self):
        """Start the mock PLC server."""
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_sock.bind((self.host, self.port))
            self.server_sock.listen(1)
            logger.info(f"Mock PLC server listening on {self.host}:{self.port}")
            print(f"Mock PLC server listening on {self.host}:{self.port}")

            self.accept_connection()
            self.handle_client()

        except Exception as e:
            logger.error(f"Server error: {e}")
            sys.exit(1)
        finally:
            self.cleanup()

    def accept_connection(self):
        """Accept a single client connection."""
        logger.info("Waiting for client connection...")
        self.client_sock, client_addr = self.server_sock.accept()
        logger.info(f"Client connected from {client_addr}")
        print(f"Client connected from {client_addr}")

    def handle_client(self):
        """Handle client requests until disconnect."""
        buffer = b''

        while True:
            try:
                chunk = self.client_sock.recv(65536)
                if not chunk:
                    logger.info("Client disconnected (empty read)")
                    break

                buffer += chunk
                logger.debug(f"Received {len(chunk)} bytes, buffer size: {len(buffer)}")

                # Process all complete frames in buffer
                while len(buffer) > 0:
                    frame_consumed = self.process_one_frame(buffer)
                    if frame_consumed < 0:
                        # DISC frame signal
                        if self.client_sock:
                            self.client_sock.close()
                            self.client_sock = None
                        return
                    if frame_consumed == 0:
                        break
                    buffer = buffer[frame_consumed:]

            except socket.timeout:
                logger.warning("Socket timeout, continuing")
                continue
            except ConnectionResetError:
                logger.info("Client connection reset")
                break
            except Exception as e:
                logger.error(f"Error handling client: {e}")
                break

        logger.info(f"Session complete: {self.request_count} requests, "
                    f"{self.response_count} responses sent")

    def process_one_frame(self, buffer):
        """
        Process one LGIS-GLOFA frame from buffer.
        Returns: number of bytes consumed, or 0 if incomplete frame.
        """
        # Find signature
        sig_pos = buffer.find(SIGNATURE)
        if sig_pos < 0:
            logger.warning("No LGIS-GLOFA signature found, discarding buffer")
            return len(buffer)  # Discard junk

        if sig_pos > 0:
            logger.warning(f"Discarding {sig_pos} bytes before signature")
            return sig_pos  # Skip junk before signature

        # Check minimal frame length
        if len(buffer) < 20:
            return 0  # Incomplete

        # Extract frame length
        try:
            length = struct.unpack('<H', buffer[16:18])[0]
        except struct.error:
            return 0

        total_len = 20 + length
        if len(buffer) < total_len:
            return 0  # Incomplete

        frame_bytes = buffer[:total_len]
        self.request_count += 1

        # Parse frame
        ft = struct.unpack('<H', frame_bytes[20:22])[0]
        logger.info(f"Request {self.request_count}: frame_type=0x{ft:02x}")

        # Handle frame type
        if ft == FRAME_TYPE_CONN:
            self.handle_conn_frame()
        elif ft == FRAME_TYPE_DISC:
            if self.handle_disc_frame():
                return -total_len  # Signal to close
        elif ft == FRAME_TYPE_CMD:
            self.handle_cmd_frame(frame_bytes)
        else:
            logger.warning(f"Unknown frame type 0x{ft:02x}")

        return total_len

    def handle_conn_frame(self):
        """Handle CONN frame (frame_type 0x0A)."""
        role, resp_hex = self.lookup.get(('CONN', None, None), ('CONN', ''))

        if resp_hex:
            logger.info(f"Sending CONN response: {len(resp_hex)//2} bytes")
            self.send_response(resp_hex)
            self.response_count += 1
        else:
            # Generate synthetic CONN response with valid BCC
            # Copied from captured response structure: 4c4749532d474c4f46411501a4110000080000980f00040006543534
            # But with status=0x06 and invoke_id=0x0000
            conn_resp_hex = '4c4749532d474c4f46411501a4110000080000980f00040000060000'
            logger.info(f"CONN: sending synthetic response ({len(conn_resp_hex)//2} bytes)")
            self.send_response(conn_resp_hex)
            self.response_count += 1

    def handle_disc_frame(self):
        """Handle DISC frame (frame_type 0x12)."""
        logger.info("Received DISC frame, closing connection")
        # Return a sentinel to break the recv loop
        return True  # Signal to close

    def handle_cmd_frame(self, frame_bytes):
        """Handle CMD frame (frame_type 0x0E)."""
        # Extract cmd_byte and sub_cmd
        if len(frame_bytes) < 26:
            logger.warning("CMD frame too short")
            return

        cmd_byte = frame_bytes[24]
        sub_cmd = frame_bytes[25] if len(frame_bytes) > 25 else None

        logger.info(f"  cmd=0x{cmd_byte:02x} ({chr(cmd_byte) if 32 <= cmd_byte < 127 else '?'}), "
                    f"sub_cmd=0x{sub_cmd:02x}" if sub_cmd is not None else "")

        # Lookup response
        key = (cmd_byte, sub_cmd)
        if key in self.lookup:
            role, resp_hex = self.lookup[key]
            if resp_hex:
                logger.info(f"  Sending {role} response: {len(resp_hex)//2} bytes")
                self.send_response(resp_hex)
                self.response_count += 1
            else:
                logger.warning(f"  {role}: no response captured")
        else:
            logger.warning(f"  No lookup match for (0x{cmd_byte:02x}, 0x{sub_cmd:02x}), "
                           f"sending empty response")

    def send_response(self, resp_hex):
        """Send response bytes."""
        try:
            resp_bytes = bytes.fromhex(resp_hex)
            self.client_sock.sendall(resp_bytes)
            logger.debug(f"Sent {len(resp_bytes)} bytes")
        except Exception as e:
            logger.error(f"Failed to send response: {e}")

    def cleanup(self):
        """Clean up sockets."""
        if self.client_sock:
            try:
                self.client_sock.close()
            except Exception:
                pass
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
        logger.info("Server shutdown complete")


def main():
    parser = argparse.ArgumentParser(
        description='Mock PLC TCP server for write replay testing'
    )
    parser.add_argument('--host', type=str, default='127.0.0.1',
                        help='Listen address (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=12002,
                        help='Listen port (default: 12002)')
    parser.add_argument('--frames', type=str, default='write_replay_frames.json',
                        help='Path to write_replay_frames.json')

    args = parser.parse_args()

    # Resolve frames path relative to script location
    if not os.path.isabs(args.frames):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        args.frames = os.path.join(script_dir, '..', args.frames)

    server = MockPLCServer(
        host=args.host,
        port=args.port,
        frames_json=args.frames
    )

    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("Server interrupted by user")
        server.cleanup()


if __name__ == '__main__':
    main()
