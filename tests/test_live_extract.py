#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Live PLC ↔ AST 통합 테스트.

scan_responses_bytes() 와 scan_pcapng() 의 token 추출 일치성 검증 + mock test.
"""
import sys
import os
import json
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from plc_bytecode_scanner import scan_pcapng, scan_responses_bytes
from plc_upload_analyze import parse_pcapng_packets


def test_scan_responses_bytes_vs_scan_pcapng():
    """scan_responses_bytes 가 scan_pcapng 과 같은 token 을 추출하는지 검증."""
    print("\n" + "=" * 70)
    print("TEST: scan_responses_bytes vs scan_pcapng")
    print("=" * 70)

    # 테스트용 pcapng 파일 찾기
    pcapng_paths = [
        Path("docs/0423_PLC로부터열기.pcapng"),
        Path("docs") / "0423_PLC로부터열기.pcapng",
    ]

    pcapng_path = None
    for p in pcapng_paths:
        if p.exists():
            pcapng_path = p
            break

    if not pcapng_path:
        print("⚠ pcapng 파일 없음 — 테스트 스킵")
        return True

    print(f"pcapng 파일: {pcapng_path}")

    # Step 1: scan_pcapng 로 직접 스캔
    print("\n[Step 1] scan_pcapng() 직접 호출...")
    direct = scan_pcapng(str(pcapng_path))
    print(f"  ✓ {len(direct)} responses 스캔됨")

    direct_token_count = sum(r.get('token_count', 0) for r in direct)
    direct_binary_len = sum(r.get('binary_len', 0) for r in direct)
    print(f"  ✓ Total tokens: {direct_token_count}")
    print(f"  ✓ Total binary length: {direct_binary_len} bytes")

    # Step 2: pcapng 에서 raw response bytes 추출
    print("\n[Step 2] pcapng 에서 raw response bytes 추출...")
    packets = parse_pcapng_packets(str(pcapng_path))
    response_bytes_list = [payload for direction, payload in packets if direction == 'PLC→PC']
    print(f"  ✓ {len(response_bytes_list)} raw response bytes 추출됨")

    # Step 3: scan_responses_bytes 호출
    print("\n[Step 3] scan_responses_bytes() 호출...")
    via_memory = scan_responses_bytes(response_bytes_list)
    print(f"  ✓ {len(via_memory)} responses 스캔됨")

    via_memory_token_count = sum(r.get('token_count', 0) for r in via_memory)
    via_memory_binary_len = sum(r.get('binary_len', 0) for r in via_memory)
    print(f"  ✓ Total tokens: {via_memory_token_count}")
    print(f"  ✓ Total binary length: {via_memory_binary_len} bytes")

    # Step 4: 비교
    print("\n[Step 4] 결과 비교...")
    responses_match = len(direct) == len(via_memory)
    tokens_match = direct_token_count == via_memory_token_count
    binary_match = direct_binary_len == via_memory_binary_len

    print(f"  Response count:   {len(direct)} vs {len(via_memory)} → {responses_match}")
    print(f"  Token count:      {direct_token_count} vs {via_memory_token_count} → {tokens_match}")
    print(f"  Binary length:    {direct_binary_len} vs {via_memory_binary_len} → {binary_match}")

    if responses_match and tokens_match and binary_match:
        print("\n✓ PASS: scan_responses_bytes 와 scan_pcapng 일치!")
        return True
    else:
        print("\n✗ FAIL: 불일치 발견")
        # 상세 분석
        if not responses_match:
            print(f"  - Response 개수 차이: {len(direct)} vs {len(via_memory)}")
        if not tokens_match:
            print(f"  - Token 개수 차이: {direct_token_count} vs {via_memory_token_count}")
            # response별 상세 분석
            for i, (d, m) in enumerate(zip(direct, via_memory)):
                d_tokens = d.get('token_count', 0)
                m_tokens = m.get('token_count', 0)
                if d_tokens != m_tokens:
                    print(f"    - Response {i}: {d_tokens} vs {m_tokens}")
        return False


def test_program_ast_builder_load_responses():
    """ProgramASTBuilder.load_responses() 가 응답 list 를 제대로 로드하는지 검증."""
    print("\n" + "=" * 70)
    print("TEST: ProgramASTBuilder.load_responses()")
    print("=" * 70)

    from plc_program_parser import ProgramASTBuilder

    # pcapng 파일 찾기
    pcapng_paths = [
        Path("docs/0423_PLC로부터열기.pcapng"),
        Path("docs") / "0423_PLC로부터열기.pcapng",
    ]

    pcapng_path = None
    for p in pcapng_paths:
        if p.exists():
            pcapng_path = p
            break

    if not pcapng_path:
        print("⚠ pcapng 파일 없음 — 테스트 스킵")
        return True

    print(f"pcapng 파일: {pcapng_path}")

    # Step 1: pcapng 로부터 responses 추출
    print("\n[Step 1] pcapng 로부터 responses 추출...")
    direct = scan_pcapng(str(pcapng_path))
    print(f"  ✓ {len(direct)} responses 로드됨")

    # Step 2: load_responses 사용
    print("\n[Step 2] ProgramASTBuilder.load_responses() 호출...")
    builder = ProgramASTBuilder(use_il=False)
    builder.load_responses(direct, source_label='test:live')

    print(f"  ✓ source_path: {builder.source_path}")
    print(f"  ✓ responses count: {len(builder.responses)}")

    # Step 3: AST 빌드
    print("\n[Step 3] AST 빌드...")
    try:
        ast = builder.build()
        print(f"  ✓ AST 빌드 성공")
        print(f"  ✓ Programs: {ast.get('stats', {}).get('total_programs', '?')}")
        print(f"  ✓ Rungs: {ast.get('stats', {}).get('total_rungs', '?')}")
        print(f"  ✓ Source: {ast.get('source', '?')}")
        return True
    except Exception as e:
        print(f"  ✗ AST 빌드 실패: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_plc_upload_client_responses_raw():
    """PLCUploadClient 가 responses_raw 를 제대로 채우는지 (mock 으로) 검증."""
    print("\n" + "=" * 70)
    print("TEST: PLCUploadClient.responses_raw (mock)")
    print("=" * 70)

    # Mock PLCUploadClient 만들기 (실제 socket 연결 없음)
    from plc_upload_test import PLCUploadClient
    from unittest.mock import MagicMock, patch

    client = PLCUploadClient("127.0.0.1", 2002)

    # Mock socket 응답 (간단한 LGIS-GLOFA 응답)
    mock_response = (
        b'LGIS-GLOFA' +  # signature
        b'\x00\x00' +    # plc_info
        b'\x00' +        # cpu_info
        b'\x11' +        # source (PLC)
        b'\x00\x00' +    # invoke_id
        b'\x08\x00' +    # length = 8
        b'\x00' +        # fenet
        b'\x00' +        # bcc
        b'\x0f\x00' +    # frame_type (RSP)
        b'\x04\x00' +    # cmd_data_len = 4
        b'\x06' +        # status
        b'Z' +           # command echo
        b'\x02' +        # sub_cmd
        b'0001'          # mock data
    )

    print("\n[Step 1] Mock socket setup...")
    with patch('plc_upload_test.socket.socket') as mock_socket_class:
        # Mock socket instance
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.recv.return_value = mock_response

        # connect 후 send_frame 호출
        client.connect()
        print("  ✓ Connected (mocked)")

        # send_frame 호출 (mock socket 이 응답 반환)
        print("\n[Step 2] send_frame() 호출...")
        frame_bytes = b'test_frame_data'  # 간단한 test frame
        result = client.send_frame(frame_bytes)

        print(f"  ✓ Parsed response: {result is not None}")
        print(f"  ✓ responses count: {len(client.responses)}")
        print(f"  ✓ responses_raw count: {len(client.responses_raw)}")

        if len(client.responses_raw) > 0:
            print(f"  ✓ First raw response length: {len(client.responses_raw[0])} bytes")
            return True
        else:
            print("  ✗ responses_raw 비어있음")
            return False


def run_all_tests():
    """모든 테스트 실행."""
    print("\n\n" + "=" * 70)
    print("LIVE PLC ↔ AST 통합 테스트 시작")
    print("=" * 70)

    results = []

    # Test 1
    try:
        result = test_scan_responses_bytes_vs_scan_pcapng()
        results.append(("scan_responses_bytes vs scan_pcapng", result))
    except Exception as e:
        print(f"\n✗ Exception: {e}")
        import traceback
        traceback.print_exc()
        results.append(("scan_responses_bytes vs scan_pcapng", False))

    # Test 2
    try:
        result = test_program_ast_builder_load_responses()
        results.append(("ProgramASTBuilder.load_responses()", result))
    except Exception as e:
        print(f"\n✗ Exception: {e}")
        import traceback
        traceback.print_exc()
        results.append(("ProgramASTBuilder.load_responses()", False))

    # Test 3
    try:
        result = test_plc_upload_client_responses_raw()
        results.append(("PLCUploadClient.responses_raw (mock)", result))
    except Exception as e:
        print(f"\n✗ Exception: {e}")
        import traceback
        traceback.print_exc()
        results.append(("PLCUploadClient.responses_raw (mock)", False))

    # 요약
    print("\n\n" + "=" * 70)
    print("테스트 결과 요약")
    print("=" * 70)
    passed = sum(1 for _, result in results if result)
    total = len(results)
    print(f"\n{passed}/{total} passed")
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status}: {name}")

    return passed == total


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
