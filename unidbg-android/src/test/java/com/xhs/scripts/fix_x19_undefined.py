"""
IDA Script: Batch fix "v0 VALUE MAYBE UNDEFINED" for VM handlers
Usage: In IDA -> File -> Script file -> select this file

Finds all sub_ functions that read X19 as base register in the first 4 instructions
without saving it first (VM handler pattern), then sets __usercall type with X19 as param.
"""
import idautils
import ida_funcs
import ida_ua
import idaapi
import idc

X19 = idaapi.str2reg("X19")

def find_x19_handlers():
    """Find functions that implicitly receive VM state via X19."""
    candidates = []
    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue
        name = ida_funcs.get_func_name(func_ea)
        # Skip library/external functions
        if name.startswith(".") or name.startswith("_") or name.startswith("j_"):
            continue
        # Skip already fixed functions
        cur_type = idc.get_type(func_ea)
        if cur_type and "__usercall" in cur_type:
            continue

        ea = func_ea
        reads_x19 = False
        writes_x19 = False
        for _ in range(16):
            insn = ida_ua.insn_t()
            length = ida_ua.decode_insn(insn, ea)
            if length == 0:
                break
            mnem = insn.get_canon_mnem()
            # X19 saved in prologue -> not a VM handler
            if mnem in ('STP', 'STR') and (insn.ops[0].reg == X19 or insn.ops[1].reg == X19):
                writes_x19 = True
                break
            # X19 used as base register in memory access -> implicit param
            for op in insn.ops:
                if op.type in (ida_ua.o_displ, ida_ua.o_phrase) and op.reg == X19:
                    reads_x19 = True
                    break
            if reads_x19:
                break
            ea += length

        if reads_x19 and not writes_x19:
            candidates.append((func_ea, name))
    return candidates


def main():
    candidates = find_x19_handlers()
    print(f"[fix_x19] Found {len(candidates)} VM handler candidates")

    fixed = 0
    failed = 0
    fail_samples = []

    for func_ea, name in candidates:
        new_type = f"__int64 __usercall {name}@<X0>(__int64 vm_state@<X19>)"
        ok = idc.SetType(func_ea, new_type)
        if ok:
            fixed += 1
        else:
            failed += 1
            if len(fail_samples) < 10:
                fail_samples.append(f"0x{func_ea:X} {name}")

    print(f"[fix_x19] Done! Fixed: {fixed}, Failed: {failed}")
    if fail_samples:
        print(f"[fix_x19] Sample failures: {fail_samples}")


if __name__ == "__main__":
    main()
else:
    main()
