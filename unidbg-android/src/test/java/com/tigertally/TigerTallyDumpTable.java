package com.tigertally;

import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.pointer.UnidbgPointer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import unicorn.Arm64Const;

/**
 * 在 vmpHash 执行期，dump trace 中发现的 256 字节运行期置换表（建表循环出口 0x0b27bc, x19=表基址）。
 * 这张表 = “每个字节的变换”候选。
 */
public class TigerTallyDumpTable {
    static String hex(byte[] b){StringBuilder s=new StringBuilder();for(byte x:b)s.append(String.format("%02x",x&0xff));return s.toString();}

    public static void main(String[] args) throws IOException {
        TigerTallyTrace tt = new TigerTallyTrace();
        tt.setSharedPreferencesValue("TT_COOKIEID_NEW","");
        tt.setSharedPreferencesValue("switch","1");
        tt.setSharedPreferencesValue("package_sign_cert","");
        tt.setSharedPreferencesValue("acw_sc__v3","");
        tt.init();

        Module module = tt.moduleForHook();
        long base = module.base;
        Debugger dbg = tt.emulatorForHook().attach();

        final int[] hitCount = {0};
        // 建表循环出口：x19 = 256 字节表基址
        dbg.addBreakPoint(base + 0x0b27bc, (emu, addr) -> {
            Backend be = emu.getBackend();
            long x19 = be.reg_read(Arm64Const.UC_ARM64_REG_X19).longValue();
            long lr  = be.reg_read(Arm64Const.UC_ARM64_REG_LR).longValue();
            try {
                UnidbgPointer p = UnidbgPointer.pointer(emu, x19);
                byte[] table = p.getByteArray(0, 256);
                hitCount[0]++;
                System.out.println("[TABLE#" + hitCount[0] + "] x19=0x" + Long.toHexString(x19)
                        + " caller=0x" + Long.toHexString(lr - base));
                System.out.println("TABLE_HEX=" + hex(table));
            } catch (Exception e) {
                System.out.println("dump err: " + e);
            }
            return true; // 继续执行
        });

        System.out.println("=== 输入1 触发建表 ===");
        String h1 = tt.vmpHash(1, "{\"pageNumber\":2,\"pageSize\":10,\"priceExp\":true,\"sceneId\":100,\"tabId\":\"10000\"}".getBytes(StandardCharsets.UTF_8));
        System.out.println("=== 输入2 (完全不同) 触发建表 ===");
        String h2 = tt.vmpHash(1, "hello_world_different_input_abcdefg".getBytes(StandardCharsets.UTF_8));
        System.out.println("vmpHash1=" + h1);
        System.out.println("vmpHash2=" + h2 + "  命中次数=" + hitCount[0]);
        tt.close();
    }
}
