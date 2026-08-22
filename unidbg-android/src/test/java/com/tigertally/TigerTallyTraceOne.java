package com.tigertally;

/**
 * 对指定输入生成 vmpHash 的指令级 trace 到指定文件。
 * 用法: args[0]=输入(hex)  args[1]=输出trace路径
 */
public class TigerTallyTraceOne {
    public static void main(String[] args) throws Exception {
        byte[] data = unhex(args[0]);
        String path = args[1];

        TigerTallyTrace tt = new TigerTallyTrace();
        tt.setSharedPreferencesValue("TT_COOKIEID_NEW", "");
        tt.setSharedPreferencesValue("switch", "1");
        tt.setSharedPreferencesValue("package_sign_cert", "");
        tt.setSharedPreferencesValue("acw_sc__v3", "");
        tt.init();

        String h = tt.vmpHashTracedTo(1, data, path);
        System.out.println("INPUT=" + args[0] + " HASH=" + h + " -> " + path);
        tt.close();
    }

    static byte[] unhex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return b;
    }
}
