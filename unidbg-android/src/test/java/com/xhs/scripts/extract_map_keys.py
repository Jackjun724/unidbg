#!/usr/bin/env python3
"""
Extract key strings from map_insert calls in a qtrace file.

map_insert is at offset 0x28c7e8.
Inside map_insert, the key string pointer is saved to x20 (mov x20, x1 at 0x28c804),
then a strlen loop at 0x28c814 reads bytes: ldrb w8, [x20, x25] until w8==0.

We extract the bytes read in this loop to reconstruct each key string.

Strategy: simple state machine
  State 0: scanning for [0x28c7e8] (map_insert entry)
  State 1: inside map_insert, collecting ldrb bytes from [0x28c814]
           When we see a 0x00 byte, key is done -> save and go to state 0
           If we see another [0x28c7e8] before finishing, save partial and restart
"""

import re
import sys
from collections import OrderedDict

TRACE_FILE = "/Users/jackjun/Desktop/unidbg/unidbg-android/src/test/java/com/xhs/trace/trace_sig_real.txt"

def extract_keys():
    keys = []
    current_bytes = []
    in_map_insert = False
    call_count = 0

    # We only need two patterns:
    # 1. map_insert entry
    entry_re = re.compile(r'^\[0x28c7e8\]')
    # 2. ldrb in strlen loop - extract the byte value from x8=0xHH
    #    Format: [0x28c814] ... | x8=0xHH ...
    ldrb_re = re.compile(r'^\[0x28c814\].*\| x8=0x([0-9a-fA-F]+)')

    with open(TRACE_FILE, 'r') as f:
        for line in f:
            # Check for map_insert entry
            if entry_re.match(line):
                # Save previous key if any
                if current_bytes:
                    key_str = bytes(current_bytes).decode('utf-8', errors='replace')
                    keys.append((call_count, key_str))
                call_count += 1
                current_bytes = []
                in_map_insert = True
                continue

            if not in_map_insert:
                continue

            # Inside map_insert - look for ldrb bytes
            m = ldrb_re.match(line)
            if m:
                byte_val = int(m.group(1), 16)
                if byte_val == 0:
                    # Null terminator - key complete
                    key_str = bytes(current_bytes).decode('utf-8', errors='replace')
                    keys.append((call_count, key_str))
                    current_bytes = []
                    in_map_insert = False
                else:
                    current_bytes.append(byte_val)

    # Handle last entry
    if current_bytes:
        key_str = bytes(current_bytes).decode('utf-8', errors='replace')
        keys.append((call_count, key_str))

    return keys


def main():
    print(f"Parsing trace file: {TRACE_FILE}")
    print(f"Looking for map_insert calls at offset 0x28c7e8...\n")

    keys = extract_keys()

    print(f"Found {len(keys)} map_insert calls with extracted keys:\n")
    print(f"{'#':>4}  {'Key':<30}")
    print(f"{'─'*4}  {'─'*30}")

    unique_keys = OrderedDict()
    for idx, (call_num, key) in enumerate(keys, 1):
        print(f"{idx:>4}  {key}")
        if key not in unique_keys:
            unique_keys[key] = 0
        unique_keys[key] += 1

    print(f"\n{'='*60}")
    print(f"Total map_insert calls with keys: {len(keys)}")
    print(f"Unique keys: {len(unique_keys)}")
    print(f"\nUnique key list (sorted, with count):")
    print(f"{'─'*40}")
    for key, count in sorted(unique_keys.items()):
        print(f"  {key:<30}  x{count}")

    print(f"\nKeys in insertion order:")
    print(f"{'─'*40}")
    seen = set()
    for _, key in keys:
        if key not in seen:
            seen.add(key)
            print(f"  {key}")


if __name__ == "__main__":
    main()
