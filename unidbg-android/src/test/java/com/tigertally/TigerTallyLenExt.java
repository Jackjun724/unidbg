package com.tigertally;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * 读取长度扩展候选查询，对每个 query 跑 vmpHash，输出 (L, actual_hash)。
 */
public class TigerTallyLenExt {
    static byte[] unhex(String s) {
        byte[] b = new byte[s.length()/2];
        for (int i=0;i<b.length;i++) b[i]=(byte)Integer.parseInt(s.substring(i*2,i*2+2),16);
        return b;
    }
    public static void main(String[] args) throws IOException {
        TigerTallyTrace tt = new TigerTallyTrace();
        tt.setSharedPreferencesValue("TT_COOKIEID_NEW","");
        tt.setSharedPreferencesValue("switch","1");
        tt.setSharedPreferencesValue("package_sign_cert","");
        tt.setSharedPreferencesValue("acw_sc__v3","");
        tt.init();

        List<String[]> q = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(
                "/Users/jackjun/Desktop/wtoken_analysis/trace/lenext_queries.txt"))) {
            String line;
            while ((line=br.readLine())!=null) {
                String[] p = line.trim().split(" ");
                if (p.length>=3) q.add(new String[]{p[0],p[1],p[2]});
            }
        }
        PrintStream out = new PrintStream(new FileOutputStream(
                "/Users/jackjun/Desktop/wtoken_analysis/trace/lenext_result.txt"), true);
        for (String[] p : q) {
            String actual = tt.vmpHash(1, unhex(p[1]));
            boolean hit = actual.equalsIgnoreCase(p[2]);
            out.println("L=" + p[0] + " predicted=" + p[2] + " actual=" + actual + (hit ? "  <==== MATCH" : ""));
            if (hit) System.out.println(">>> MATCH at L=" + p[0]);
        }
        out.close();
        System.out.println("DONE -> lenext_result.txt");
        tt.close();
    }
}
