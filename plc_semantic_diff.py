#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PLC Semantic Diff CLI
오프라인에서 두 스냅샷의 의미적(semantic) 차이를 비교하는 CLI 도구

Usage:
    python plc_semantic_diff.py <A.json> <B.json>
    python plc_semantic_diff.py --json-out result.json <A.json> <B.json>
    python plc_semantic_diff.py --summary-only <A.json> <B.json>
    python plc_semantic_diff.py --help
"""
import json
import sys
import os
import argparse
from pathlib import Path

# PyInstaller bootstrap: add both source and bundled paths to sys.path
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)
if hasattr(sys, '_MEIPASS') and sys._MEIPASS not in sys.path:
    sys.path.insert(0, sys._MEIPASS)

try:
    from plc_upload_decode import build_program_state, diff_program_state, print_diff
except ImportError as e:
    print(f"Error: failed to import plc_upload_decode: {e}")
    print(f"  script_dir: {script_dir}")
    print(f"  _MEIPASS: {getattr(sys, '_MEIPASS', 'not set')}")
    sys.exit(1)


def diff_value_snapshots(snap_a, snap_b):
    """
    Compare two value snapshot JSONs.

    Returns:
        {
            'values_added': count,
            'values_removed': count,
            'values_changed': [{'key': str, 'before': int, 'after': int}, ...],
            'details': str
        }
    """
    vals_a = snap_a.get('values_latest', {})
    vals_b = snap_b.get('values_latest', {})

    added = set(vals_b.keys()) - set(vals_a.keys())
    removed = set(vals_a.keys()) - set(vals_b.keys())
    common = set(vals_a.keys()) & set(vals_b.keys())

    changed = []
    for key in sorted(common):
        if vals_a[key] != vals_b[key]:
            changed.append({
                'key': key,
                'before': vals_a[key],
                'after': vals_b[key]
            })

    return {
        'values_added': len(added),
        'values_removed': len(removed),
        'values_changed': changed,
        'details_count': f'{len(added)} added / {len(removed)} removed / {len(changed)} changed'
    }


def main():
    parser = argparse.ArgumentParser(
        description='Compare two PLC snapshot JSON files semantically'
    )
    parser.add_argument('snapshot_a', metavar='A.json',
                        help='First snapshot (before state)')
    parser.add_argument('snapshot_b', metavar='B.json',
                        help='Second snapshot (after state)')
    parser.add_argument('--json-out', type=str, metavar='FILE',
                        help='Save structured diff to JSON file')
    parser.add_argument('--summary-only', action='store_true',
                        help='Print only change counts, not details')
    parser.add_argument('--values', action='store_true',
                        help='Compare value snapshots instead of program snapshots')

    args = parser.parse_args()

    # Load snapshots
    path_a = Path(args.snapshot_a)
    path_b = Path(args.snapshot_b)

    if not path_a.exists():
        print(f"Error: {path_a} not found")
        sys.exit(1)
    if not path_b.exists():
        print(f"Error: {path_b} not found")
        sys.exit(1)

    try:
        with open(path_a, encoding='utf-8') as f:
            snapshot_a = json.load(f)
        with open(path_b, encoding='utf-8') as f:
            snapshot_b = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading files: {e}")
        sys.exit(1)

    # Choose comparison mode
    if args.values:
        # Value snapshot mode
        print(f"Comparing value snapshots...")
        diff = diff_value_snapshots(snapshot_a, snapshot_b)
    else:
        # Program snapshot mode (original behavior)
        print(f"Building program states...")
        try:
            state_a = build_program_state(snapshot_a)
            state_b = build_program_state(snapshot_b)
        except Exception as e:
            print(f"Error building program state: {e}")
            sys.exit(1)

        # Compute diff
        print(f"Computing semantic diff...")
        diff = diff_program_state(state_a, state_b)

    # Output
    if args.json_out:
        output_path = Path(args.json_out)
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(diff, f, indent=2, ensure_ascii=False)
            print(f"✓ Saved structured diff to {output_path}")
        except Exception as e:
            print(f"Error writing JSON: {e}")
            sys.exit(1)

    # Print summary
    if args.values:
        # Value snapshot output
        print("\n=== VALUE CHANGES ===")
        print(f"값 추가: {diff['values_added']}개")
        print(f"값 제거: {diff['values_removed']}개")
        print(f"값 변경: {len(diff['values_changed'])}개")

        if not args.summary_only and diff['values_changed']:
            print("\n값 변경 목록:")
            for change in diff['values_changed']:
                print(f"  [{change['key']}] {change['before']} → {change['after']}")
    else:
        # Program snapshot output (original)
        if args.summary_only:
            print("\n=== SUMMARY ===")
            print(f"Programs added: {len(diff['programs_added'])}")
            print(f"Programs removed: {len(diff['programs_removed'])}")
            print(f"Symbols added: {len(diff['symbols_added'])}")
            print(f"Symbols removed: {len(diff['symbols_removed'])}")
            print(f"Functions added: {len(diff['functions_added'])}")
            print(f"Functions removed: {len(diff['functions_removed'])}")
            print(f"Programs changed: {len(diff['programs_changed'])}")
        else:
            print("\n=== DIFF ===")
            print_diff(diff)

    # Exit with code based on changes
    if args.values:
        has_changes = diff['values_added'] > 0 or diff['values_removed'] > 0 or len(diff['values_changed']) > 0
    else:
        has_changes = (
            len(diff['programs_added']) > 0 or
            len(diff['programs_removed']) > 0 or
            len(diff['symbols_added']) > 0 or
            len(diff['symbols_removed']) > 0 or
            len(diff['functions_added']) > 0 or
            len(diff['functions_removed']) > 0 or
            len(diff['programs_changed']) > 0 or
            len(diff.get('io_changes', [])) > 0
        )

    if has_changes:
        print("\n✓ Changes detected")
    else:
        print("\n✓ No changes")

    sys.exit(0)


if __name__ == '__main__':
    main()
