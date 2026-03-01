package com.github.unidbg.arm.backend.hypervisor;

import capstone.Arm64_const;
import capstone.api.Disassembler;
import capstone.api.Instruction;
import capstone.api.arm64.OpInfo;
import capstone.api.arm64.Operand;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.ReadHook;
import com.github.unidbg.arm.backend.WriteHook;
import com.github.unidbg.arm.backend.hypervisor.arm64.MemorySizeDetector;
import com.github.unidbg.arm.backend.hypervisor.arm64.SimpleMemorySizeDetector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class HypervisorWatchpoint implements BreakRestorer {

    private static final Logger log = LoggerFactory.getLogger(HypervisorWatchpoint.class);
    private static final MemorySizeDetector MEMORY_SIZE_DETECTOR = new SimpleMemorySizeDetector();

    private final Object callback;
    private final long begin;
    private final long end;
    private final Object user_data;
    final int n;
    private final boolean isWrite;

    private final long dbgwcr, dbgwvr, bytes;

    HypervisorWatchpoint(Object callback, long begin, long end, Object user_data, int n, boolean isWrite) {
        if (begin >= end) {
            throw new IllegalArgumentException("begin=0x" + Long.toHexString(begin) + ", end=" + Long.toHexString(end));
        }

        long size = end - begin;
        if ((size >>> 31) != 0) {
            throw new IllegalArgumentException("too large size=0x" + Long.toHexString(size));
        }

        this.callback = callback;
        this.begin = begin;
        this.end = end;
        this.user_data = user_data;
        this.n = n;
        this.isWrite = isWrite;

        long dbgwcr = 0x5;
        if (isWrite) {
            dbgwcr |= 0b10 << 3;
        } else {
            dbgwcr |= 0b01 << 3;
        }
        for (int i = 2; i <= 31; i++) {
            int bytes = 1 << i;
            int mask = bytes - 1;
            long dbgwvr = begin & ~mask;
            long offset = begin - dbgwvr;
            if(offset + size <= bytes) {
                long bas;
                int maskBits;
                if (i <= 3) {
                    maskBits = 0;
                    bas = 0;
                    for (long m = 0; m < size; m++) {
                        bas |= (1L << (offset + m));
                    }
                } else {
                    maskBits = i;
                    bas = 0xff;
                }
                dbgwcr |= (bas << 5);
                dbgwcr |= (maskBits << 24);

                if (log.isDebugEnabled()) {
                    log.debug("begin=0x{}, end=0x{}, dbgwvr=0x{}, dbgwcr=0x{}, offset={}, size={}, i={}", Long.toHexString(begin), Long.toHexString(end), Long.toHexString(dbgwvr), Long.toHexString(dbgwcr), offset, size, i);
                }

                this.bytes = bytes;
                this.dbgwvr = dbgwvr;
                this.dbgwcr = dbgwcr;
                return;
            }
        }

        throw new UnsupportedOperationException("begin=0x" + Long.toHexString(begin) + ", end=0x" + Long.toHexString(end));
    }

    final boolean contains(long address, boolean isWrite) {
        if (isWrite ^ this.isWrite) {
            return false;
        }
        return address >= dbgwvr && address < (dbgwvr + bytes);
    }

    final void onHit(Backend backend, long address, boolean isWrite, Disassembler disassembler, byte[] code, long pc) {
        if (address >= begin && address < end) {
            Instruction insn = disassembler.disasm(code, pc, 1)[0];
            if (isWrite) {
                int size = MEMORY_SIZE_DETECTOR.detectWriteSize(insn);
                long value = extractWriteValue(insn, backend, size);
                ((WriteHook) callback).hook(backend, address, size, value, user_data);
            } else {
                int size = MEMORY_SIZE_DETECTOR.detectReadSize(insn);
                ((ReadHook) callback).hook(backend, address, size, user_data);
            }
        }
    }

    private static long extractWriteValue(Instruction insn, Backend backend, int size) {
        int valueOpIndex;
        switch (insn.getMnemonic()) {
            case "stxr":
            case "stlxr":
            case "stxp":
            case "stlxp":
                valueOpIndex = 1;
                break;
            default:
                valueOpIndex = 0;
                break;
        }
        OpInfo opInfo = (OpInfo) insn.getOperands();
        Operand[] ops = opInfo.getOperands();
        if (ops.length > valueOpIndex && ops[valueOpIndex].getType() == Arm64_const.ARM64_OP_REG) {
            int unicornReg = insn.mapToUnicornReg(ops[valueOpIndex].getValue().getReg());
            long value = backend.reg_read(unicornReg).longValue();
            switch (size) {
                case 1: return value & 0xFFL;
                case 2: return value & 0xFFFFL;
                case 4: return value & 0xFFFFFFFFL;
                default: return value;
            }
        }
        return 0;
    }

    @Override
    public final void install(Hypervisor hypervisor) {
        hypervisor.install_watchpoint(n, dbgwcr, dbgwvr);
    }
}
