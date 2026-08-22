package com.tigertally;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.TraceHook;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.BaseVM;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.StringObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.VaList;
import com.github.unidbg.linux.android.dvm.jni.ProxyDvmObject;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.virtualmodule.android.AndroidModule;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * 复现 tiger-tally-server.jar 中的 unidbg 调用（阿里云虎符 TigerTally SDK）。
 * 基于 JADX 反编译的 TigerTallyTest 驱动逻辑，增加指令级 Trace 输出用于算法分析。
 *
 * 算法链: init(genericNt2 + genericNt1) -> vmpHash(genericNt4) -> vmpSign(genericNt3) -> wToken
 */
public class TigerTallyTrace extends AbstractJni {

    private static final String BASE = "/Users/jackjun/Desktop/wtoken_analysis/";
    private static final String TRACE_DIR = BASE + "trace/";

    private final VM vm;
    private DalvikModule dm;
    private DvmClass nativeClass;
    private DvmClass securityUtilClass;
    private DvmClass securityIDClass;
    private DvmClass securityNativeClass;
    private final Map<String, String> sharedPreferences = new HashMap<>();
    private final AndroidEmulator emulator = AndroidEmulatorBuilder
            .for64Bit()
            .setProcessName("com.cdfsunrise.cdflehu.LeHuApplication")
            .build();

    public TigerTallyTrace() {
        Memory memory = this.emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        this.vm = this.emulator.createDalvikVM(new File(BASE + "bin/com.cdfsunrise.cdflehu.apk"));
        new AndroidModule(this.emulator, this.vm).register(memory);
        this.vm.setJni(this);
        this.vm.setVerbose(false); // 关闭 JNI 逐条打印，避免干扰 trace 分析
    }

    // ==================== JNI 环境 mock（保持与 TigerTallyTest 一致）====================

    @Override
    public DvmObject<?> newObjectV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if (signature.contains("com/aliyun/TigerTally/s/A$")) {
            return dvmClass.newObject(null);
        }
        if (signature.contains("com/aliyun/TigerTally/s/B$")) {
            return dvmClass.newObject(null);
        }
        if (signature.contains("com/aliyun/TigerTally/TTSessionId")) {
            return dvmClass.newObject(null);
        }
        if (signature.contains("java/util/HashMap") && signature.contains("<init>")) {
            return ProxyDvmObject.createObject(vm, new HashMap<>());
        }
        return super.newObjectV(vm, dvmClass, signature, vaList);
    }

    @Override
    public void callVoidMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if ((signature.contains("com/aliyun/TigerTally/s/") && signature.contains("<init>"))
                || signature.contains("com/aliyun/TigerTally/common/id/SecurityID->setOAIDRaw")
                || signature.contains("com/aliyun/TigerTally/common/id/SecurityID->setGAIDRaw")) {
            return;
        }
        super.callVoidMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public int getStaticIntField(BaseVM vm, DvmClass dvmClass, String signature) {
        if ("android/os/Build$VERSION->SDK_INT:I".equals(signature)) {
            return 23;
        }
        return super.getStaticIntField(vm, dvmClass, signature);
    }

    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {
        switch (signature) {
            case "android/os/Build->BRAND:Ljava/lang/String;":
                return new StringObject(vm, "Android");
            case "android/os/Build->MANUFACTURER:Ljava/lang/String;":
                return new StringObject(vm, "unknown");
            case "android/os/Build->MODEL:Ljava/lang/String;":
                return new StringObject(vm, "sdk_gphone64_arm64");
            case "android/os/Build->DEVICE:Ljava/lang/String;":
                return new StringObject(vm, "emu64a64");
            case "android/os/Build->PRODUCT:Ljava/lang/String;":
                return new StringObject(vm, "emu64a64");
            case "android/os/Build->HARDWARE:Ljava/lang/String;":
                return new StringObject(vm, "ranchu");
            case "android/os/Build->FINGERPRINT:Ljava/lang/String;":
                return new StringObject(vm, "Android/sdk_gphone64_arm64/emu64a64:6.0/MASTER/12345:user/release-keys");
            case "android/os/Build$VERSION->RELEASE:Ljava/lang/String;":
                return new StringObject(vm, "6.0");
            default:
                return super.getStaticObjectField(vm, dvmClass, signature);
        }
    }

    @Override
    public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        if ("android/content/res/Configuration->locale:Ljava/util/Locale;".equals(signature)) {
            return vm.resolveClass("java/util/Locale").newObject(Locale.getDefault());
        }
        return super.getObjectField(vm, dvmObject, signature);
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "com/aliyun/TigerTally/common/utils/SecurityUtil->getCtx()Landroid/content/Context;":
                return vm.resolveClass("android/content/Context").newObject(null);
            case "android/os/Environment->getExternalStorageState()Ljava/lang/String;":
                return new StringObject(vm, "mounted");
            case "android/os/Environment->getExternalStorageDirectory()Ljava/io/File;":
                return vm.resolveClass("java/io/File").newObject(new File("/sdcard"));
            default:
                return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
        }
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "java/util/HashMap->entrySet()Ljava/util/Set;": {
                Map<String, String> map = (Map<String, String>) dvmObject.getValue();
                return ProxyDvmObject.createObject(vm, map.entrySet());
            }
            case "java/util/HashMap$EntrySet->iterator()Ljava/util/Iterator;": {
                Iterable<?> iterable = (Iterable<?>) dvmObject.getValue();
                return ProxyDvmObject.createObject(vm, iterable.iterator());
            }
            case "java/util/Iterator->next()Ljava/lang/Object;":
            case "java/util/HashMap$EntryIterator->next()Ljava/lang/Object;": {
                Iterator<?> iter = (Iterator<?>) dvmObject.getValue();
                Map.Entry<?, ?> entry = (Map.Entry<?, ?>) iter.next();
                return ProxyDvmObject.createObject(vm, entry);
            }
            case "java/util/HashMap$Entry->getKey()Ljava/lang/Object;":
            case "java/util/HashMap$Node->getKey()Ljava/lang/Object;": {
                Map.Entry<?, ?> entry = (Map.Entry<?, ?>) dvmObject.getValue();
                return new StringObject(vm, (String) entry.getKey());
            }
            case "java/util/HashMap$Entry->getValue()Ljava/lang/Object;":
            case "java/util/HashMap$Node->getValue()Ljava/lang/Object;": {
                Map.Entry<?, ?> entry = (Map.Entry<?, ?>) dvmObject.getValue();
                return new StringObject(vm, (String) entry.getValue());
            }
            case "java/io/File->toString()Ljava/lang/String;":
            case "java/io/File->getPath()Ljava/lang/String;": {
                File file = (File) dvmObject.getValue();
                return new StringObject(vm, file.getPath());
            }
            case "android/content/Context->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;":
                return vm.resolveClass("android/content/SharedPreferences").newObject(null);
            case "android/content/SharedPreferences->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;": {
                DvmObject<?> keyObj = vaList.getObjectArg(0);
                String key = keyObj != null ? (String) keyObj.getValue() : null;
                StringObject defaultObj = vaList.getObjectArg(1);
                String defaultValue = defaultObj != null ? (String) defaultObj.getValue() : "";
                String value = this.sharedPreferences.getOrDefault(key, defaultValue);
                return new StringObject(vm, value);
            }
            case "android/content/Context->getFilesDir()Ljava/io/File;":
                return vm.resolveClass("java/io/File").newObject(new File("/data/data/com.cdfsunrise.cdflehu/files"));
            case "android/content/Context->getExternalFilesDir(Ljava/lang/String;)Ljava/io/File;":
                return vm.resolveClass("java/io/File").newObject(new File("/sdcard/Android/data/com.cdfsunrise.cdflehu/files"));
            case "android/content/pm/PackageManager->getApplicationLabel(Landroid/content/pm/ApplicationInfo;)Ljava/lang/CharSequence;":
                return new StringObject(vm, "cdflehu");
            case "android/content/Context->getPackageCodePath()Ljava/lang/String;":
                return new StringObject(vm, "/data/app/com.cdfsunrise.cdflehu-1/base.apk");
            case "android/content/Context->getResources()Landroid/content/res/Resources;":
                return vm.resolveClass("android/content/res/Resources").newObject(null);
            case "android/content/res/Resources->getConfiguration()Landroid/content/res/Configuration;":
                return vm.resolveClass("android/content/res/Configuration").newObject(null);
            case "android/content/Context->getPackageName()Ljava/lang/String;":
                return new StringObject(vm, "com.cdfsunrise.cdflehu");
            case "android/content/Context->getSystemService(Ljava/lang/String;)Ljava/lang/Object;":
                return vm.resolveClass("android/os/TelephonyManager").newObject(null);
            case "android/os/TelephonyManager->getDeviceId()Ljava/lang/String;":
                return new StringObject(vm, "000000000000000");
            case "android/os/TelephonyManager->getSubscriberId()Ljava/lang/String;":
                return new StringObject(vm, "");
            case "android/os/TelephonyManager->getSimSerialNumber()Ljava/lang/String;":
                return new StringObject(vm, "");
            case "android/os/TelephonyManager->getNetworkOperatorName()Ljava/lang/String;":
                return new StringObject(vm, "Android");
            case "com/aliyun/TigerTally/s/A$AA->en(Ljava/lang/String;)Ljava/lang/String;":
            case "com/aliyun/TigerTally/s/A$BB->en(Ljava/lang/String;)Ljava/lang/String;": {
                DvmObject<?> inputStr = vaList.getObjectArg(0);
                if (inputStr instanceof StringObject) {
                    return inputStr;
                }
                return new StringObject(vm, "");
            }
            case "java/util/Locale->getLanguage()Ljava/lang/String;":
                return new StringObject(vm, "zh");
            case "java/lang/String->toString()Ljava/lang/String;":
                return dvmObject;
            default:
                return super.callObjectMethodV(vm, dvmObject, signature, vaList);
        }
    }

    @Override
    public boolean callBooleanMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "java/util/Iterator->hasNext()Z":
            case "java/util/HashMap$EntryIterator->hasNext()Z": {
                Iterator<?> iter = (Iterator<?>) dvmObject.getValue();
                return iter.hasNext();
            }
            case "com/aliyun/TigerTally/common/id/SecurityID->getGAID()Z":
                return true;
            case "com/aliyun/TigerTally/common/id/SecurityID->getOAID()Z":
                return false;
            default:
                return super.callBooleanMethodV(vm, dvmObject, signature, vaList);
        }
    }

    @Override
    public int getIntField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        if (signature.contains("TTSessionId->code:I")) {
            return 0;
        }
        return super.getIntField(vm, dvmObject, signature);
    }

    @Override
    public void setIntField(BaseVM vm, DvmObject<?> dvmObject, String signature, int value) {
        if (signature.contains("TTSessionId->")) {
            return;
        }
        super.setIntField(vm, dvmObject, signature, value);
    }

    @Override
    public void setObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature, DvmObject<?> value) {
        if (signature.contains("TTSessionId->")) {
            return;
        }
        super.setObjectField(vm, dvmObject, signature, value);
    }

    @Override
    public int callIntMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if ("android/content/Context->checkCallingOrSelfPermission(Ljava/lang/String;)I".equals(signature)) {
            return 0;
        }
        return super.callIntMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public int callStaticIntMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if ("java/util/Objects->hash([Ljava/lang/Object;)I".equals(signature)) {
            DvmObject<?> array = vaList.getObjectArg(0);
            if (array != null) {
                Object[] objects = (Object[]) array.getValue();
                return Objects.hash(objects);
            }
            return 0;
        }
        return super.callStaticIntMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public boolean callStaticBooleanMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "com/aliyun/TigerTally/common/id/SecurityID->getGAID()Z":
                return true;
            case "com/aliyun/TigerTally/common/id/SecurityID->getOAID()Z":
                return false;
            default:
                return super.callStaticBooleanMethodV(vm, dvmClass, signature, vaList);
        }
    }

    // ==================== SO 加载与算法调用 ====================

    public void loadSO() {
        if (this.dm != null) {
            return;
        }
        this.dm = this.vm.loadLibrary(new File(BASE + "bin/libtiger_tally.so"), true);
        this.dm.callJNI_OnLoad(this.emulator);
        System.out.println("SO loaded! base=0x" + Long.toHexString(this.dm.getModule().base)
                + " size=0x" + Long.toHexString(this.dm.getModule().size));
        this.nativeClass = this.vm.resolveClass("com/aliyun/TigerTally/t/B");
        this.securityUtilClass = this.vm.resolveClass("com/aliyun/TigerTally/common/utils/SecurityUtil");
        this.securityIDClass = this.vm.resolveClass("com/aliyun/TigerTally/common/id/SecurityID");
        this.securityNativeClass = this.vm.resolveClass("com/aliyun/TigerTally/common/utils/SecurityNative");
    }

    public int init() {
        return init("d25a7a2b-6d82-4c55-a5e4-38f1f6e466cf",
                "USx3BOoesCb8-k8JydZslOWXA7O5sDxvDXidf-gxFRK7a5TVqj5Nz8-JUE85IECYN8Cm1TfvNmTbEIE3Izyzgvx5sqsi6voZbEaB-SzUb-F0_K0kfTJCXT_zb1l3jT5ZRMEyGQJs558W2i_79TaB4LSlK67dPkB7wUzW-ee8sJ0=");
    }

    public int init(String gaid, String appKey) {
        loadSO();
        setOAID("");
        setGAID(gaid);
        int nt2Result = genericNt2(1, "null");
        System.out.println("genericNt2 result: " + nt2Result);
        Map<String, String> map = new HashMap<>();
        map.put("AppKey", appKey);
        map.put("CollectType", "0");
        DvmObject<?> dvmMap = ProxyDvmObject.createObject(this.vm, map);
        int result = this.nativeClass.callStaticJniMethodInt(this.emulator, "genericNt1(Ljava/util/Map;)I", new Object[]{dvmMap});
        System.out.println("genericNt1 result: " + result);
        return result;
    }

    public void setGAID(String gaid) {
        loadSO();
        this.securityIDClass.callStaticJniMethod(this.emulator, "setGAIDRaw(Ljava/lang/String;)V", new Object[]{new StringObject(this.vm, gaid)});
    }

    public void setOAID(String oaid) {
        loadSO();
        this.securityIDClass.callStaticJniMethod(this.emulator, "setOAIDRaw(Ljava/lang/String;)V", new Object[]{new StringObject(this.vm, oaid)});
    }

    public void setSharedPreferencesValue(String key, String value) {
        this.sharedPreferences.put(key, value);
    }

    public int genericNt2(int i, String str) {
        loadSO();
        return this.nativeClass.callStaticJniMethodInt(this.emulator, "genericNt2(ILjava/lang/String;)I", new Object[]{i, new StringObject(this.vm, str)});
    }

    /** vmpHash = genericNt4(I[B)Ljava/lang/String; 对请求体做哈希 */
    public String vmpHash(int requestType, byte[] data) {
        loadSO();
        DvmObject<?> byteArray = ProxyDvmObject.createObject(this.vm, data);
        DvmObject<?> result = this.nativeClass.callStaticJniMethodObject(this.emulator, "genericNt4(I[B)Ljava/lang/String;", new Object[]{requestType, byteArray});
        return result.getValue().toString();
    }

    /** vmpSign = genericNt3(I[B)Ljava/lang/String; 对哈希做签名 */
    public String vmpSign(int requestType, byte[] data) {
        loadSO();
        DvmObject<?> byteArray = ProxyDvmObject.createObject(this.vm, data);
        DvmObject<?> result = this.nativeClass.callStaticJniMethodObject(this.emulator, "genericNt3(I[B)Ljava/lang/String;", new Object[]{requestType, byteArray});
        return result.getValue().toString();
    }

    /** 带指令级 trace 的调用：为单次 JNI 调用生成独立 trace 文件 */
    private String callWithTrace(String jniSignature, int requestType, byte[] data, String traceFileName) throws IOException {
        loadSO();
        Module module = this.dm.getModule();
        PrintStream traceStream = new PrintStream(new FileOutputStream(TRACE_DIR + traceFileName), true);
        TraceHook hook = this.emulator.traceCode(module.base, module.base + module.size);
        hook.setRedirect(traceStream);
        try {
            DvmObject<?> byteArray = ProxyDvmObject.createObject(this.vm, data);
            DvmObject<?> result = this.nativeClass.callStaticJniMethodObject(this.emulator, jniSignature, new Object[]{requestType, byteArray});
            return result.getValue().toString();
        } finally {
            hook.stopTrace();
            traceStream.close();
        }
    }

    public String vmpHashTraced(int requestType, byte[] data) throws IOException {
        return callWithTrace("genericNt4(I[B)Ljava/lang/String;", requestType, data, "trace_vmphash.txt");
    }

    /** 追踪 vmpHash 到绝对路径 */
    public String vmpHashTracedTo(int requestType, byte[] data, String absPath) throws IOException {
        loadSO();
        Module module = this.dm.getModule();
        PrintStream traceStream = new PrintStream(new FileOutputStream(absPath), true);
        TraceHook hook = this.emulator.traceCode(module.base, module.base + module.size);
        hook.setRedirect(traceStream);
        try {
            DvmObject<?> byteArray = ProxyDvmObject.createObject(this.vm, data);
            DvmObject<?> result = this.nativeClass.callStaticJniMethodObject(this.emulator, "genericNt4(I[B)Ljava/lang/String;", new Object[]{requestType, byteArray});
            return result.getValue().toString();
        } finally {
            hook.stopTrace();
            traceStream.close();
        }
    }

    public String vmpSignTraced(int requestType, byte[] data) throws IOException {
        return callWithTrace("genericNt3(I[B)Ljava/lang/String;", requestType, data, "trace_vmpsign.txt");
    }

    /** 与服务端 SignHandler.convertToWToken 一致的后处理 */
    public static String convertToWToken(String sign) {
        String result = sign;
        if (result.startsWith("0005_")) {
            result = "0004_" + result.substring(5);
        }
        if (result.endsWith("_fHw=_")) {
            result = result.substring(0, result.length() - 6);
        } else if (result.contains("_fHx0ZXN0")) {
            int idx = result.lastIndexOf("_fHx0ZXN0");
            if (idx > 0) {
                result = result.substring(0, idx);
            }
        }
        return result;
    }

    public Module moduleForHook() {
        return this.dm.getModule();
    }

    public AndroidEmulator emulatorForHook() {
        return this.emulator;
    }

    public void close() throws IOException {
        this.emulator.close();
    }

    public static void main(String[] args) throws IOException {
        TigerTallyTrace test = new TigerTallyTrace();
        test.setSharedPreferencesValue("TT_COOKIEID_NEW", "");
        test.setSharedPreferencesValue("switch", "1");
        test.setSharedPreferencesValue("package_sign_cert", "");
        test.setSharedPreferencesValue("acw_sc__v3", "");

        System.out.println("======== TigerTally 初始化 ========");
        int initResult = test.init();
        System.out.println("======== Init result: " + initResult + " ========");

        if (initResult != 0) {
            System.err.println("初始化失败，退出。");
            test.close();
            return;
        }

        String bodyStr = "{\"pageNumber\":2,\"pageSize\":10,\"priceExp\":true,\"sceneId\":100,\"tabId\":\"10000\"}";
        byte[] inputData = bodyStr.getBytes("UTF-8");
        System.out.println("\n请求体: " + bodyStr);

        System.out.println("\n======== 调用 vmpHash (genericNt4) [带 Trace] ========");
        String hashResult = test.vmpHashTraced(1, inputData);
        System.out.println("vmpHash 结果: " + hashResult);

        System.out.println("\n======== 调用 vmpSign (genericNt3) [带 Trace] ========");
        byte[] signData = hashResult.getBytes("UTF-8");
        String signResult = test.vmpSignTraced(1, signData);
        System.out.println("vmpSign 结果: " + signResult);

        String wToken = convertToWToken(signResult);
        System.out.println("\n======== 最终 wToken ========");
        System.out.println(wToken);

        System.out.println("\nTrace 文件已输出到: " + TRACE_DIR);
        test.close();
    }
}
