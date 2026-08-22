package com.tigertally;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * 差分探测：在不逐指令还原 VMP 的前提下，通过受控输入确定 vmpHash / vmpSign 的性质。
 */
public class TigerTallyProbe {

    private static String hx(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }

    public static void main(String[] args) throws IOException {
        TigerTallyTrace tt = new TigerTallyTrace();
        tt.setSharedPreferencesValue("TT_COOKIEID_NEW", "");
        tt.setSharedPreferencesValue("switch", "1");
        tt.setSharedPreferencesValue("package_sign_cert", "");
        tt.setSharedPreferencesValue("acw_sc__v3", "");
        int init = tt.init();
        System.out.println("INIT=" + init);

        String body = "{\"pageNumber\":2,\"pageSize\":10,\"priceExp\":true,\"sceneId\":100,\"tabId\":\"10000\"}";

        // 1) 确定性：同输入两次
        String h1 = tt.vmpHash(1, body.getBytes(StandardCharsets.UTF_8));
        String h2 = tt.vmpHash(1, body.getBytes(StandardCharsets.UTF_8));
        System.out.println("HASH_DET_1=" + h1);
        System.out.println("HASH_DET_2=" + h2);
        System.out.println("HASH_DETERMINISTIC=" + h1.equals(h2));

        // 2) 受控输入探测（长度/块边界）
        String[] probes = new String[] { "", "a", "aa", "abc",
                repeat("A", 55), repeat("A", 56), repeat("A", 63),
                repeat("A", 64), repeat("A", 65), repeat("A", 119), repeat("A", 120) };
        for (String p : probes) {
            String h = tt.vmpHash(1, p.getBytes(StandardCharsets.UTF_8));
            System.out.println("HASH[len=" + p.length() + "]=" + h + "  IN=" + hx(p.getBytes(StandardCharsets.UTF_8)));
        }

        // 3) requestType 是否影响 hash
        System.out.println("HASH_rt0=" + tt.vmpHash(0, body.getBytes(StandardCharsets.UTF_8)));
        System.out.println("HASH_rt1=" + tt.vmpHash(1, body.getBytes(StandardCharsets.UTF_8)));
        System.out.println("HASH_rt2=" + tt.vmpHash(2, body.getBytes(StandardCharsets.UTF_8)));

        // 4) vmpSign 确定性（是否含随机 IV / 时间戳）
        byte[] hashBytes = h1.getBytes(StandardCharsets.UTF_8);
        String s1 = tt.vmpSign(1, hashBytes);
        String s2 = tt.vmpSign(1, hashBytes);
        System.out.println("SIGN_DET_1=" + s1);
        System.out.println("SIGN_DET_2=" + s2);
        System.out.println("SIGN_DETERMINISTIC=" + s1.equals(s2));

        // 5) sign 对不同输入
        String s3 = tt.vmpSign(1, "0000000000000000000000000000000000000000000000000000000000000000".getBytes(StandardCharsets.UTF_8));
        System.out.println("SIGN_zeros=" + s3);

        tt.close();
    }

    private static String repeat(String s, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append(s);
        return sb.toString();
    }
}
