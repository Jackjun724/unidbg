#!/usr/bin/env python3
"""
Parse qtrace to extract map_insert key-value pairs.
Reads the real device trace and finds all map_insert (0x28c7e8) calls.
For each call, extracts the key string from memory reads within the function.
"""
import re
import sys

TRACE_FILE = sys.argv[1] if len(sys.argv) > 1 else "trace/trace_sig_real.txt"
MAP_INSERT_OFFSET = "0x28c7e8"

def extract_mem_ops(line):
    """Extract R[addr]=val/size and W[addr]=val/size from trace line."""
    reads = re.findall(r'R\[(0x[0-9a-f]+)\]=([0-9a-f]+)/(\d+)', line)
    writes = re.findall(r'W\[(0x[0-9a-f]+)\]=([0-9a-f]+)/(\d+)', line)
    return reads, writes

def extract_regs(line):
    """Extract register values from trace line."""
    regs = {}
    for m in re.finditer(r'\b(x\d+|fp|lr|sp)=(0x[0-9a-f]+)', line):
        regs[m.group(1)] = int(m.group(2), 16)
    return regs

def bytes_to_str(byte_list):
    """Convert byte list to printable string."""
    try:
        return bytes(byte_list).decode('utf-8', errors='replace').rstrip('\x00')
    except:
        return repr(bytes(byte_list))

def main():
    # Pass 1: Find all map_insert call boundaries
    print(f"[*] Scanning {TRACE_FILE} for map_insert calls...")

    calls = []  # [(start_line, end_line, caller_line)]
    in_map_insert = False
    call_start = 0
    call_depth = 0
    caller_line = ""

    with open(TRACE_FILE) as f:
        for line_no, line in enumerate(f, 1):
            m = re.match(r'^\[(0x[0-9a-f]+)\]', line)
            if not m:
                continue
            offset = m.group(1)

            if offset == MAP_INSERT_OFFSET and not in_map_insert:
                in_map_insert = True
                call_start = line_no
                call_depth = 0
                # Save the previous line as caller context
                continue

            if in_map_insert:
                # Detect return from map_insert (offset jumps back to caller range)
                # map_insert is at 0x28c7e8-0x28cb??, handlers are 0x15xxxx-0x1xxxxx
                off_int = int(offset, 16)
                if off_int < 0x28c000 or off_int > 0x2a0000:
                    # Returned from map_insert
                    calls.append((call_start, line_no - 1))
                    in_map_insert = False

    print(f"[*] Found {len(calls)} map_insert calls")

    # Pass 2: For each call, extract key from memory reads
    # The key is an SSO string at x1. Inside map_insert, the key chars are read
    # via ldrb instructions from the SSO string buffer.
    # SSO format: first byte bit0=0 means short string, length=byte>>1, data at +1

    print(f"\n[*] Extracting keys from map_insert calls...")

    with open(TRACE_FILE) as f:
        lines = {}
        # Read lines around each call
        targets = set()
        for start, end in calls:
            for i in range(max(1, start-2), min(end+1, start+200)):
                targets.add(i)

    # Re-read targeted lines
    results = []
    for idx, (start, end) in enumerate(calls):
        key_bytes = []
        x1_val = None
        caller_offset = None

        # Read the caller line (2 before start) and the map_insert body
        read_start = max(1, start - 3)
        read_end = min(start + 300, end + 1)

        with open(TRACE_FILE) as f:
            for i, line in enumerate(f, 1):
                if i < read_start:
                    continue
                if i > read_end:
                    break

                if i == start - 1 or i == start - 2:
                    # Caller context - try to get x1
                    regs = extract_regs(line)
                    if 'x1' in regs:
                        x1_val = regs['x1']
                    # Get caller offset
                    m = re.match(r'^\[(0x[0-9a-f]+)\]', line)
                    if m:
                        caller_offset = m.group(1)

                if i >= start and i <= read_end:
                    reads, _ = extract_mem_ops(line)
                    for addr_s, val_s, size_s in reads:
                        addr = int(addr_s, 16)
                        val = int(val_s, 16)
                        size = int(size_s)
                        # Look for 1-byte reads (character reads from key string)
                        if size == 1 and 0x20 <= val <= 0x7e:
                            key_bytes.append((addr, val))

        # Try to reconstruct key from sequential byte reads
        if key_bytes:
            # Group consecutive address reads
            groups = []
            current_group = [key_bytes[0]]
            for ab in key_bytes[1:]:
                if ab[0] == current_group[-1][0] + 1:
                    current_group.append(ab)
                else:
                    groups.append(current_group)
                    current_group = [ab]
            groups.append(current_group)

            # The key is typically one of the shorter groups (2-4 chars like "x29")
            # Look for groups starting with 'x' (0x78)
            key_str = None
            for g in groups:
                chars = [b[1] for b in g]
                s = bytes(chars).decode('ascii', errors='replace')
                if s.startswith('x') and len(s) <= 5:
                    key_str = s
                    break

            if not key_str and groups:
                # Take shortest group that looks like a key
                for g in sorted(groups, key=len):
                    chars = [b[1] for b in g]
                    s = bytes(chars).decode('ascii', errors='replace')
                    if len(s) >= 2 and len(s) <= 5:
                        key_str = s
                        break

            results.append({
                'idx': idx,
                'line': start,
                'caller': caller_offset,
                'key': key_str,
                'x1': hex(x1_val) if x1_val else None,
                'groups': [(bytes([b[1] for b in g]).decode('ascii', errors='replace'), len(g)) for g in groups[:5]]
            })
        else:
            results.append({
                'idx': idx,
                'line': start,
                'caller': caller_offset,
                'key': None,
                'x1': hex(x1_val) if x1_val else None,
                'groups': []
            })

    # Output results
    print(f"\n{'='*80}")
    print(f"{'#':>3} {'Line':>10} {'Caller':>12} {'Key':>8} {'Byte Groups'}")
    print(f"{'='*80}")
    for r in results:
        key = r['key'] or '???'
        groups_str = str(r['groups'][:3]) if r['groups'] else ''
        print(f"{r['idx']:>3} {r['line']:>10} {r['caller'] or '':>12} {key:>8} {groups_str}")

    # Summary: list missing fields
    found_keys = set(r['key'] for r in results if r['key'])
    print(f"\n[*] Found keys: {sorted(found_keys)}")

    missing = {'x6', 'x29', 'x97', 'x99', 'x269'}
    for m in sorted(missing):
        matches = [r for r in results if r['key'] == m]
        if matches:
            print(f"  {m}: found at line {matches[0]['line']}, caller={matches[0]['caller']}")
        else:
            print(f"  {m}: NOT FOUND in map_insert calls")

if __name__ == "__main__":
    main()
