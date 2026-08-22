package com.tigertally;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/** 为若干新输入算真实 vmpHash + md5hex, 供重放器泛化交叉验证 */
public class TigerTallyGen {
    static String hx(byte[] b){StringBuilder s=new StringBuilder();for(byte x:b)s.append(String.format("%02x",x&0xff));return s.toString();}
    public static void main(String[] args) throws Exception {
        TigerTallyTrace tt = new TigerTallyTrace();
        tt.setSharedPreferencesValue("TT_COOKIEID_NEW","");
        tt.setSharedPreferencesValue("switch","1");
        tt.setSharedPreferencesValue("package_sign_cert","");
        tt.setSharedPreferencesValue("acw_sc__v3","");
        tt.init();
        String[] inputs = {"C", "Z", "hello", "world!!", "abcdefg"};
        for (String s : inputs) {
            byte[] data = s.getBytes(StandardCharsets.UTF_8);
            String md5hex = hx(MessageDigest.getInstance("MD5").digest(data));
            String vh = tt.vmpHash(1, data);
            System.out.println("IN=" + s + " len=" + data.length + " md5hex=" + md5hex + " vmpHash=" + vh);
        }
        tt.close();
    }
}
