package com.github.unidbg.arm.backend.hypervisor.arm64;

import capstone.api.Instruction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SimpleMemorySizeDetector implements MemorySizeDetector {

    private static final Logger log = LoggerFactory.getLogger(SimpleMemorySizeDetector.class);

    @Override
    public int detectReadSize(Instruction insn) {
        switch (insn.getMnemonic()) {
            case "ldrb":
            case "ldursb":
                return 1;
            case "ldursh":
            case "ldrh":
                return 2;
            case "ldr":
            case "ldxr":
            case "ldaxr":
            case "ldur":
                if (insn.getOpStr().startsWith("w")) {
                    return 4;
                }
                if (insn.getOpStr().startsWith("x")) {
                    return 8;
                }
                break;
            case "ldp":
            case "ldxp":
            case "ldaxp":
                if (insn.getOpStr().startsWith("w")) {
                    return 8;
                }
                if (insn.getOpStr().startsWith("x")) {
                    return 16;
                }
                break;
            default:
                log.info("detectReadSize: insn={}", insn);
                break;
        }
        return 0;
    }

    @Override
    public int detectWriteSize(Instruction insn) {
        String opStr = insn.getOpStr();
        switch (insn.getMnemonic()) {
            case "strb":
            case "sturb":
                return 1;
            case "strh":
            case "sturh":
                return 2;
            case "str":
            case "stur":
                if (opStr.startsWith("w")) {
                    return 4;
                }
                if (opStr.startsWith("x")) {
                    return 8;
                }
                break;
            case "stxr":
            case "stlxr": {
                String valueReg = extractAfterFirstComma(opStr);
                if (valueReg.startsWith("w")) {
                    return 4;
                }
                if (valueReg.startsWith("x")) {
                    return 8;
                }
                break;
            }
            case "stp":
                if (opStr.startsWith("w")) {
                    return 8;
                }
                if (opStr.startsWith("x")) {
                    return 16;
                }
                break;
            case "stxp":
            case "stlxp": {
                String valueReg = extractAfterFirstComma(opStr);
                if (valueReg.startsWith("w")) {
                    return 8;
                }
                if (valueReg.startsWith("x")) {
                    return 16;
                }
                break;
            }
            default:
                log.info("detectWriteSize: insn={}", insn);
                break;
        }
        return 0;
    }

    private static String extractAfterFirstComma(String opStr) {
        int commaIdx = opStr.indexOf(',');
        return commaIdx >= 0 ? opStr.substring(commaIdx + 1).trim() : opStr;
    }

}
