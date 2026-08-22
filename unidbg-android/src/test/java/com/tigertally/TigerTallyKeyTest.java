package com.tigertally;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * 判定 vmpHash 是否依赖 init 期密钥（GAID / 设备指纹）。
 * 两个独立实例用不同 GAID 初始化，哈希同一 body 后比较。
 */
public class TigerTallyKeyTest {
    static final String APPKEY = "USx3BOoesCb8-k8JydZslOWXA7O5sDxvDXidf-gxFRK7a5TVqj5Nz8-JUE85IECYN8Cm1TfvNmTbEIE3Izyzgvx5sqsi6voZbEaB-SzUb-F0_K0kfTJCXT_zb1l3jT5ZRMEyGQJs558W2i_79TaB4LSlK67dPkB7wUzW-ee8sJ0=";
    static final String BODY = "{\"pageNumber\":2,\"pageSize\":10,\"priceExp\":true,\"sceneId\":100,\"tabId\":\"10000\"}";

    static String run(String gaid) throws IOException {
        TigerTallyTrace tt = new TigerTallyTrace();
        tt.setSharedPreferencesValue("TT_COOKIEID_NEW", "");
        tt.setSharedPreferencesValue("switch", "1");
        tt.setSharedPreferencesValue("package_sign_cert", "");
        tt.setSharedPreferencesValue("acw_sc__v3", "");
        int init = tt.init(gaid, APPKEY);
        String h = tt.vmpHash(1, BODY.getBytes(StandardCharsets.UTF_8));
        tt.close();
        return "init=" + init + " hash=" + h;
    }

    public static void main(String[] args) throws IOException {
        System.out.println("GAID_A: " + run("d25a7a2b-6d82-4c55-a5e4-38f1f6e466cf"));
        System.out.println("GAID_B: " + run("ffffffff-ffff-ffff-ffff-ffffffffffff"));
        System.out.println("GAID_C: " + run(""));
    }
}
