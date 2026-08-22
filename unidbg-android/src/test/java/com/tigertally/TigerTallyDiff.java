package com.tigertally;

import java.io.IOException;
import java.io.PrintStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * 位翻转差分采集：把 vmpHash 当 oracle，输出 base 及大量单/双位翻转输入的哈希，
 * 供 Python 判定线性/仿射性，进而逐位还原变换。
 */
public class TigerTallyDiff {
    public static void main(String[] args) throws IOException {
        TigerTallyTrace tt = new TigerTallyTrace();
        tt.setSharedPreferencesValue("TT_COOKIEID_NEW", "");
        tt.setSharedPreferencesValue("switch", "1");
        tt.setSharedPreferencesValue("package_sign_cert", "");
        tt.setSharedPreferencesValue("acw_sc__v3", "");
        int init = tt.init();

        PrintStream out = new PrintStream(new FileOutputStream(
                "/Users/jackjun/Desktop/wtoken_analysis/trace/diff_data.txt"), true);
        out.println("INIT=" + init);

        int L = 8;                       // base 输入 8 字节 = 64 bit
        byte[] base = new byte[L];
        for (int i = 0; i < L; i++) base[i] = (byte) (0x30 + i);   // "01234567"

        String hb = tt.vmpHash(1, base);
        out.println("BASE_IN=" + hex(base));
        out.println("BASE_OUT=" + hb);

        // 单比特翻转
        for (int bit = 0; bit < L * 8; bit++) {
            byte[] x = base.clone();
            x[bit >> 3] ^= (1 << (bit & 7));
            out.println("FLIP1 " + bit + " " + tt.vmpHash(1, x));
        }
        // 双比特翻转（用于线性性验证）：固定一组 (i,j)
        int[][] pairs = {
            {0,1},{0,8},{3,17},{5,40},{7,63},{10,33},{12,55},{20,44},
            {1,2},{2,4},{9,18},{15,31},{22,47},{30,61},{4,36},{11,52}
        };
        for (int[] p : pairs) {
            byte[] x = base.clone();
            x[p[0] >> 3] ^= (1 << (p[0] & 7));
            x[p[1] >> 3] ^= (1 << (p[1] & 7));
            out.println("FLIP2 " + p[0] + " " + p[1] + " " + tt.vmpHash(1, x));
        }
        out.close();
        System.out.println("DONE -> diff_data.txt");
        tt.close();
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }
}
