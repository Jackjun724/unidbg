package com.xhs;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.android.dvm.jni.ProxyDvmObject;
import com.github.unidbg.linux.android.dvm.wrapper.DvmBoolean;
import com.github.unidbg.linux.android.dvm.wrapper.DvmInteger;
import com.github.unidbg.linux.android.dvm.wrapper.DvmLong;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.utils.Inspector;
import com.github.unidbg.virtualmodule.android.AndroidModule;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.util.*;

public class demo1 extends AbstractJni {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;


    demo1() {
        emulator = AndroidEmulatorBuilder.for64Bit()
                .addBackendFactory(new Unicorn2Factory(false))
                .setProcessName("com.xingin.xhs").build();
//        emulator.getSyscallHandler().addIOResolver(this);
//        emulator.traceWrite(0x404d8228,0x404d8228+16);
//        emulator.attach().addBreakPoint(0x400309dc);
//        emulator.attach().addBreakPoint(0x400309cc);
//        emulator.traceWrite(0x404de094,0x404de094+4);
//        mapResult:{x-mini-mua=eyJhIjoiRUNGQUFGMDEiLCJjIjoxLCJrIjoiMjllM2Q4ZWQ3MGFkM2JhMTE2MmQwZDFmMTYyODQxZTAyODMwY2M0ZGRhZGFhOTdlNGQ0MTg3ZjMyNDA4Yzg3ZiIsInAiOiJhIiwicyI6ImFiZWZiZGU0ZWQzMTNhODRjNjk4ODhiYmIyYjFhNGI2NDQ3M2RkYTZhZWQ2ZWU2MTIwN2FhOTNhYzk1NzRjOTE0ZGFkZGYwOWJjYzBiMmZhOTdkZTgxMGU2YzEwYjFlY2IzNTY1M2ZmMTRiYzhkMGVhNTA2YTc5N2ZmOTdkMzRlIiwidiI6IjIuOS42MSJ9.TBV2xC7KeTWpV41fLQgLqlFROwnmrgjHs5wk0U2yxrH4kdujMP-mQzp8s67TU2WUaszTKk6kZThRhmuBJQuwmpTgjaUVgvDizPQvXaE3YYeCZB18h5Fi6A2DFVuU57QkWomhZxYXoQjAPzK1OtPOoXGqGu-4SCBwKgdotdi7QMYlYAU_Na0t3VhGn7T2ENaewRCUqWRvTyKwPrw-FPRdET4LbWtd9oepkE2S4wqYG2L6Si_u5i__ZIiAbjypqd0actntEMZrJFsbIwumUd58BGN2-zjOa0HDOS-ZXAhLJ9Twzm7dRz8NBLBPYrHHO7M4CW4aYtx28ifD644tqy4DxQ807iXUZoXn7h9O1exwr6jOkdrbJxG9P880GajzQb0x8T0uvS_ATF4THaBFYUV0qClBSUwEEOG87I6sibzfmVsGw-frJSwAeB3yQXPPvUG6OTZ61_pycRTVDUYh5llShhjCksUC2nClUnvPtmt-wE3RuJdioD-uBnEwzlBX6HCUnhRYesqFdiMOUTSYVc0LWk_ngzymNsdr7cjUnNfCq6RaJVpb9kUUiIyPfng6kmrQtdR78oB4JJRjccmgfW9BXZqF6jf0WgHr-Xrj-hAz390_5pPDvXPFWhK_kpyL3UUFImavAlsu-SfL0RY24hP9ZGQ74WvUzNyx4e42JDFftJaWd-qJNSXkLAFX_BAqhYFQrsPZE9SoT5D3cEVXL0Zn_mlTKBjMLOGnq9yNpScebpFnTV2LxnmSzy3zBvjlm0s2S82HcD6rPnAyTV-w0cBRq1eG1M3mKc0-2qqbjPUZxuJWUMvn5xKgoKFE9vnI7t_xBPM2Td49JpxzsOtGO49r-vuqyqH9QvxgPEDU8lIAoy38OLmztDRLKvSGBATjXgCp., x-mini-s1=AAEAAAABLrlq10+XP8LvwDnOO+rAgKxqWIF2zsMh+1hb75Y/3LPMDd17TS8BSiG45ypotcIzngvK4ymENyc=, x-mini-sig=8d76abca40fc918913088bebcc0de60834070ee4bcd3c8e7fdf6341469c4ef77}
//        mapResult:{x-mini-mua=eyJhIjoiRUNGQUFGMDEiLCJjIjoxLCJrIjoiYzRmYmQyMjliMmVhNjhhODU4ZTY4Mjc2MzRjMzY3ZGEwNzI2YmYzZWZjYzIyZjY3MjVjY2MwYmU3MzQ4ZGQwMCIsInAiOiJhIiwicyI6ImViYmE1ZTVlZWQ4ZjFiY2NhYTFmYTFhZjk5NTUyOTAyZTI5MzVhNDJhNGM2NGY0ZWM2ZWExMjkzOWU2YTBkNzFlYTJiZDQxNTE2YzY3NWUyZGRjYTRlMDM3OTE4YWNmMDhiZmZjNDM2OGNkZDQ4Njk0OGI2NDQ4YmY4ZjA1OTAwIiwidiI6IjIuOS42MSJ9.zkRx7w9YDMh1YQAXgGvRWGeDRP2hDDkaGXePm48ZMYElNnaWap6NCnB8Yf3vMX9EUfD7Wu3ymx46uTFLL8ghiaVISUxAVZWtIzpRoxt1MG2PhVg_pSb4v1BcLZi0-J5IBRIc2wqCGAdU0y3W39lP0ELxWOV33mAAz8lqjdXryQR5M3jGqQgsNaHi1zGAsJ0eyPw1P-D5cWyUozlORf9LjJgFwuzSagIeC3zV9JXE8Ao3WahTHEqMuyllPsIwK6x1D1eArjy3SHvr5fV6s2jrI7YRzeh7Dzer8n0-vQBToGqPy0a2vbXOhUshkclh_L3YfIY11219ReO5v9v5-NFPbMmdkGzR016S-ZJkrak8l0sUocVuE9WFBADzzwrizpMlTk3tIqFD5J80rpUzHcyH2tI0r2r3q_cgVpbsKRG9lP3_yX75_tcGcrq3WYF8K3Bp7WTFfU6qO3jaxQd-aOqLGZspvlPaiXrPL3xv6Y6PweCDftc8iVBnXH9i4WSrpi3vvf7A6uj4maB6RN-fsZN9uBbxoisr3b2p1sTKI4CRyvKooqcsai8T9oJMH2ucBSonv--z3ad0SeQV-3NjTVul1uOsSsQsPCml1YQ_Y3pT0ezK9SWv64u068ux-LYHCFVCLE6j_aeCpxFDjpwV59vCBGr4InAGOB3NGyoFJjuIyoR6Vkn0qvJPw43S2poNP1ydH_75yWNHzrCLefsA85COWjiIObdJq19j0sWyfmC5kXq_GjQEkOH9hJ2e7o-p1ns0MZGqJz7YR6sRXeAQnKZr4T8rsfn5jlh-M9xNyZcVpp4unJlhMNlfaTzm008XJmigF58ORLGVx7-_HrO8RD9h81vWLh8Se5ypafu1cJLdaqNDk4D59qUKCeA4hXrNi4FG., x-mini-s1=AAEAAAAB+3aTIs4RpI+eZMtvQD+NF0bzKOJhPdEVgBanNCnxXzwJbSjQgRpXwoPAcG6hGD6HOOL3K+3d1LU=, x-mini-sig=59b40d388ac73e4b4ff33d7bc229fdcfa60254a50dfef491306fffeaf5581d07}
        // 获取模拟器的内存操作接口
        final Memory memory = emulator.getMemory();
        // 设置系统类库解析
        memory.setLibraryResolver(new AndroidResolver(23));
//        memory.addModuleListener(new SearchData("9b332a80a8edcc723e9dbf64c13e24c2975451929dc2085c3a8249dd01820eaefe4d8c7b7861bf24b98819c5f46e0878", "libkwsgmain.so", 1000));
        // 创建Android虚拟机,传入APK，Unidbg可以替我们做部分签名校验的工作
        vm = emulator.createDalvikVM(new File("unidbg-android/src/test/resources/xiaohongshu.apk"));
        // 设置JNI
        vm.setJni(this);
        // 打印日志
        vm.setVerbose(true);
//        new MediaNdkModule(emulator, vm).register(memory);
        new AndroidModule(emulator, vm).register(memory);
//        new JniGraphics(emulator, vm).register(memory);
        // 加载目标SO
        DalvikModule dm = vm.loadLibrary("tiny", true);
//        DalvikModule dm = vm.loadLibrary(new File("unidbg-android/src/test/java/com/demo/demo1/files/libkwsgmain.so"), true);
        //获取本SO模块的句柄,后续需要用它
        module = dm.getModule();
        // 调用JNI OnLoad
        dm.callJNI_OnLoad(emulator);
    }

    public static void main(String[] args) throws FileNotFoundException {
        demo1 xhs = new demo1();
//        ks.init();
//        ks.trace();
//        xhs.trace();
        xhs.init1();
//        xhs.init2();
        xhs.init3();
//        xhs.trace();
        xhs.hook();

        xhs.sig();

    }


    public void hook() {
        Debugger debugger = emulator.attach();
        // S1 -> BASE64
//        debugger.addBreakPoint(module.base + 0x7329F4);
        // S1 -> SHA
//        debugger.addBreakPoint(module.base + 0x72436C);

        // jni hash -> put
//        debugger.addBreakPoint(module.base + 0x17EC24);

// 方法2: 如果是 JNI 方法，可以直接 hook 方法返回
//        debugger.addBreakPoint(module.base + 0x22c40);
//        debugger.addBreakPoint(module.base + 0x219fc);
//        emulator.traceWrite(0xbfffef50L, 0xbfffef50 + 32);


//        // 修改入参
//        debugger.addBreakPoint(module.base + 0x26A14, new BreakPointCallback() {
//            @Override
//            public boolean onHit(Emulator<?> emulator, long address) {
//                emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_X2, 0x4);
//
//                String hexString = "12345678"; // 十六进制字符串
//                int length = hexString.length()/2;
//                MemoryBlock fakeInputBlock = emulator.getMemory().malloc(length, true);
//                byte[] byteArray = DatatypeConverter.parseHexBinary(hexString);
//                fakeInputBlock.getPointer().write(byteArray);
//                // 修改X1为指向新字符串的新指针
//                emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_X1,fakeInputBlock.getPointer().peer);
//
//                return true;
//            }
//        });
//
//        // 保持结果
//        debugger.addBreakPoint(module.base + 0x26cb8, new BreakPointCallback() {
//            RegisterContext context = emulator.getContext();
//            @Override
//            public boolean onHit(Emulator<?> emulator, long address) {
//                byte[] bytes = emulator.getBackend().mem_read(0x404e30a0,0x10);
//                StringBuilder hexString = new StringBuilder();
//                for (byte b : bytes) {
//                    hexString.append(String.format("%02X", b & 0xFF));
//                }
//                System.out.println("aesResult:"+hexString);
//                String filename = "unidbg-android/src/test/java/com/demo/demo1/files/dfaAes.txt"; // 文件名
//                try {
//                    FileWriter writer = new FileWriter(filename,true);
//                    writer.write(hexString.toString()+"\n"); // 写入字符串
//                    writer.close();
//                } catch (IOException e) {
//                    System.err.println("写入文件时出现错误：" + e.getMessage());
//                }
//
//                return true;
//            }
//        });
//
//
//        // dfa 攻击循环左移位置
//        debugger.addBreakPoint(module.base + 0x25938, new BreakPointCallback() {
//            UnidbgPointer pointer;
//            RegisterContext context = emulator.getContext();
//            int num = 0;
//            @Override
//            public boolean onHit(Emulator<?> emulator, long address) {
//                pointer = context.getPointerArg(0);
//                num+=1;
//                if(num%9==0){
//                    pointer.setByte(randint(0,15),(byte) randint(0,0xff));
//                }
//                return true;
//            }
//        });

//        debugger.addBreakPoint(module.base + 0x2636C);
        emulator.traceWrite(0x12b284b0, 0x12b284b0 + 64);

        debugger.addBreakPoint(module.findSymbolByName("memcpy").getAddress(), new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                RegisterContext context = emulator.getContext();
                int len = context.getIntArg(2);
                UnidbgPointer pointer1 = context.getPointerArg(0);
                UnidbgPointer pointer2 = context.getPointerArg(1);
                Inspector.inspect(pointer2.getByteArray(0, len), "memcpy dest " + Long.toHexString(pointer1.peer) + " src " + Long.toHexString(pointer2.peer));
                return true;
            }
        });

        debugger.addBreakPoint(module.base + 0x547210, (emulator, address) -> {
            RegisterContext context = emulator.getContext();
            UnidbgPointer dest = context.getPointerArg(0);   // x0 = dest
            UnidbgPointer src = context.getPointerArg(1);    // x1 = src
            int len = context.getIntArg(2);                  // x2 = length

            if (len > 0 && len < 0x10000 && src != null) {
                Inspector.inspect(src.getByteArray(0, len),
                        "custom memcpy dest=0x" + Long.toHexString(dest.peer) +
                                " src=0x" + Long.toHexString(src.peer) +
                                " len=" + len);
            } else {
                System.out.println("custom memcpy dest=0x" + Long.toHexString(dest.peer) +
                        " src=0x" + (src != null ? Long.toHexString(src.peer) : "null") +
                        " len=" + len);
            }
            return false; // true = continue execution, false = pause at breakpoint
        });
    }

    public void trace() {
        String traceFile = "unidbg-android/src/test/java/com/xhs/trace.txt";
        PrintStream traceStream = null;
        try {
            traceStream = new PrintStream(new FileOutputStream(traceFile), true);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        //核心 trace 开启代码，也可以自己指定函数地址和偏移量
        emulator.traceCode(module.base, module.base + module.size).setRedirect(traceStream);
    }


    @Override
    public long callLongMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "java/lang/Long->longValue()J":
                return (Long) dvmObject.getValue();
            case "android/os/BatteryManager->getLongProperty(Lint;)Ljava/lang/Object;":
                return 100L;
        }
        throw new UnsupportedOperationException(signature);
    }


    @Override
    public float callFloatMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "java/lang/Float->floatValue()F":
                return (Float) dvmObject.getValue();
        }
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public int callIntMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "android/content/Intent->getIntExtra(Ljava/lang/String;I)I":
                return 0;
            case "android/telephony/TelephonyManager->getSimState()Ljava/lang/Object;":
                return 1;
            case "android/media/AudioManager->getStreamVolume(LI;)Ljava/lang/Object;":
                return 10;
            case "android/media/AudioManager->getStreamMaxVolume(LI;)Ljava/lang/Object;":
                return 100;
            case "android/telephony/TelephonyManager->getPhoneType()Ljava/lang/Object;":
                return 1;
        }
        return super.callIntMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public DvmObject<?> newObjectV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "java/util/HashMap-><init>()V": {
                HashMap<String, String> map = new LinkedHashMap<>();
                return ProxyDvmObject.createObject(vm, map);
            }
        }
        return super.newObjectV(vm, dvmClass, signature, vaList);
    }

    public boolean callBooleanMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "java/lang/Boolean->booleanValue()Z":
                return (Boolean) dvmObject.getValue();
            case "android/content/Intent->getBooleanExtra(Ljava/lang/String;Z)Z":
            case "android/net/wifi/WifiManager->isWifiEnabled()Ljava/lang/Object;":
                return true;
            default:
                return super.callBooleanMethodV(vm, dvmObject, signature, vaList);
        }
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "android/content/Context->getSystemService(Ljava/lang/String;)Ljava/lang/Object;": {
                String arg = (String) vaList.getObjectArg(0).getValue();
                System.out.println("Context.getSystemService arg=" + arg);
                switch (arg) {
                    case "phone":
                        return vm.resolveClass("android/telephony/TelephonyManager").newObject(null);
                    case "wifi":
                        return vm.resolveClass("android/net/wifi/WifiManager").newObject(null);
                    case "audio":
                        return vm.resolveClass("android/media/AudioManager").newObject(null);
                    case "batterymanager":
                        return vm.resolveClass("android/os/BatteryManager").newObject(null);
                    default:
                        return null;
                }
            }
            case "android/telephony/TelephonyManager->getSimOperator()Ljava/lang/Object;": {
                return new StringObject(vm, "06");
            }
            case "android/telephony/TelephonyManager->getSimOperatorName()Ljava/lang/Object;": {
                return new StringObject(vm, "中国联通");
            }
            case "android/telephony/TelephonyManager->getNetworkCountryIso()Ljava/lang/Object;":
                return new StringObject(vm, "CN");
            case "android/content/Context->getContentResolver()Landroid/content/ContentResolver;": {
                return vm.resolveClass("android/content/ContentResolver").newObject(vm);
            }
            case "java/util/Map->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;": {
                DvmObject<?> key = vaList.getObjectArg(0);
                DvmObject<?> value = vaList.getObjectArg(1);
                System.out.println("Map.put key=" + key + " value=" + value);
                HashMap<String, String> map = (HashMap<String, String>) dvmObject.getValue();
                map.put((String) key.getValue(), (String) value.getValue());
                return value;
            }
            default:
                return super.callObjectMethodV(vm, dvmObject, signature, vaList);
        }
    }

    @Override
    public long getLongField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        switch (signature) {
            case "android/content/pm/PackageInfo->firstInstallTime:J":
                return 1742976047391L;
            case "android/content/pm/PackageInfo->lastUpdateTime:J":
//                return System.currentTimeMillis();
                return 1773776674023L;
        }
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public boolean callStaticBooleanMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "android/app/ActivityManager->isUserAMonkey()Z":
                return false;
        }
        return super.callStaticBooleanMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public int getIntField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        switch (signature) {
            case "android/content/pm/ApplicationInfo->targetSdkVersion:I":
                return 23;
            case "android/content/pm/ApplicationInfo->flags:I":
                return 0;
            default:
                return super.getIntField(vm, dvmObject, signature);
        }
    }

    @Override
    public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        switch (signature) {
            case "android/content/pm/PackageInfo->packageName:Ljava/lang/String;":
                return new StringObject(vm, "com.xingin.xhs");
            case "android/content/pm/PackageInfo->versionName:Ljava/lang/String;":
                return new StringObject(vm, "9210803");
            case "android/content/pm/PackageInfo->applicationInfo:Landroid/content/pm/ApplicationInfo;":
                return vm.resolveClass("android/content/pm/ApplicationInfo").newObject(vm);
            case "android/content/pm/ApplicationInfo->publicSourceDir:Ljava/lang/String;":
                return new StringObject(vm, "/data/user/0/com.xingin.xhs");
            case "android/content/pm/ApplicationInfo->dataDir:Ljava/lang/String;":
                return new StringObject(vm, "/data/data/com.xingin.xhs");
            case "android/content/pm/ApplicationInfo->nativeLibraryDir:Ljava/lang/String;":
                return new StringObject(vm, "/data/app/~~SIH8_S_phQLm2etlRFaJgw==/com.xingin.xhs-YqL1zdzYkIykiQ7RagLamw==/lib/arm64");
            default:
                return super.getObjectField(vm, dvmObject, signature);
        }
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "com/xingin/tiny/internal/t->b(I[Ljava/lang/Object;)Ljava/lang/Object;": {
                System.out.println("call self: " + vaList.getIntArg(0));
                switch (vaList.getIntArg(0)) {
                    case 1428086509:
//////                        return new ArrayObject(
//////                                DvmLong.valueOf(vm,0x7DB1F6BEB4L),
//////                                DvmLong.valueOf(vm,0x7DB1F6C34CL),
//////                                DvmLong.valueOf(vm,0x7DB1F6C4E0L),
//////                                DvmLong.valueOf(vm,0x7DB1F6C61CL),
//////                                DvmLong.valueOf(vm,0x7DB1F6C7BCL),
//////                                DvmLong.valueOf(vm,0x7DB1F6C8CCL)
//////                        );
                        return null;
                    case -1645221235:
                        return new StringObject(vm, "/data/user/0/com.xingin.xhs");
                    case -1036195886:
                        return vm.resolveClass("android/content/pm/PackageInfo").newObject(null);
                    case -138105942: {
                        ArrayObject arrayObject = vaList.getObjectArg(1);
                        DvmClass clazz = (DvmClass) arrayObject.getValue()[0];
                        String name = (String) arrayObject.getValue()[1].getValue();
                        DvmObject<?> signatureObj = arrayObject.getValue()[2];

                        if (signatureObj == null || signatureObj.getValue() == null) {
                            // 获取 Field
                            System.out.println("getField: " + name);
                            DvmField dvmField = new DvmField(clazz, name, null, false);
                            DvmObject<?> result = vm.resolveClass("java/lang/reflect/Field").newObject(dvmField);
                            clazz.setFieldId(result.hashCode(), dvmField);
                            System.out.println("setFieldId " + Integer.toHexString(result.hashCode()));
                            return result;
                        } else {
                            // 获取 Method
                            DvmObject<?>[] signatureArgs = (DvmObject<?>[]) signatureObj.getValue();
                            System.out.println("sign:" + signatureArgs);
                            StringBuilder methodSignature = new StringBuilder("(");
                            for (DvmObject<?> signatureArg : signatureArgs) {
                                if (signatureArg.getValue().getClass() == String.class) {
                                    System.out.println(signatureArg.getValue().getClass().getName());
                                    methodSignature.append("L")
                                            .append(signatureArg.getValue().getClass().getName().replaceAll("\\.", "/"))
                                            .append(";");
                                } else {
                                    methodSignature.append(signatureArg.getValue().getClass().getName());
                                }
                            }
                            methodSignature.append(")Ljava/lang/Object;");
                            System.out.println(name + " " + methodSignature);
                            DvmMethod dvmMethod = new DvmMethod(clazz, name, methodSignature.toString(), true);
                            DvmObject<?> result = vm.resolveClass("java/lang/reflect/Method").newObject(dvmMethod);
                            clazz.setMethodID(result.hashCode(), dvmMethod);
                            System.out.println("setMethodId " + Integer.toHexString(result.hashCode()));
                            return result;
                        }
                    }
                    case 1275860725:
                        return vm.resolveClass("android/content/Context").newObject(vm);
                    case -1383960524: {
                        // l4.a(String) -> Class<T>, 通过类名加载类
                        ArrayObject arrayObject = vaList.getObjectArg(1);
                        String name = (String) arrayObject.getValue()[0].getValue();
                        if (name.equals("WifiManager")) {
                            name = "android/net/wifi/WifiManager";
                        }
                        return vm.resolveClass(name.replaceAll("\\.", "/"));
                    }
                    case 710371441: {
                        // l4.a(Class, String, Object[]) 或 l4.a(Class, String, byte[], Object[]) -> Method
                        // objArr[0]=实例/类, objArr[1]=方法名, objArr[2]=参数类型数组, objArr[3]=byte[]或null
                        // 两个分支都返回 Method，没有 Field 分支
                        ArrayObject arrayObject = vaList.getObjectArg(1);
                        DvmObject<?> instance = arrayObject.getValue()[0];
                        String name = (String) arrayObject.getValue()[1].getValue();
                        DvmObject<?> paramTypesObj = arrayObject.getValue()[2];

                        DvmClass clazz = instance instanceof DvmClass ? (DvmClass) instance : instance.getObjectType();

                        // 从参数类型构建方法签名
                        StringBuilder methodSignature = new StringBuilder("(");
                        if (paramTypesObj != null && paramTypesObj.getValue() != null) {
                            DvmObject<?>[] paramTypes = (DvmObject<?>[]) paramTypesObj.getValue();
                            for (DvmObject<?> paramType : paramTypes) {
                                if (paramType instanceof DvmClass) {
                                    methodSignature.append("L")
                                            .append(((DvmClass) paramType).getClassName())
                                            .append(";");
                                } else if (paramType.getValue() instanceof String) {
                                    methodSignature.append("L")
                                            .append(((String) paramType.getValue()).replaceAll("\\.", "/"))
                                            .append(";");
                                }
                            }
                        }
                        methodSignature.append(")Ljava/lang/Object;");
                        System.out.println("getMethod: " + clazz.getClassName() + "." + name + " " + methodSignature);

                        DvmMethod dvmMethod = new DvmMethod(clazz, name, methodSignature.toString(), true);
                        DvmObject<?> result = vm.resolveClass("java/lang/reflect/Method").newObject(dvmMethod);
                        clazz.setMethodID(result.hashCode(), dvmMethod);
                        System.out.println("setMethodId " + Integer.toHexString(result.hashCode()));
                        return result;
                    }
                    case -2126679615:
                        return new StringObject(vm, "1080,2280,440");
                    case -1268893863:
                        return vm.resolveClass("android/content/Intent").newObject(vm);
                    case -1120247918:
                        return new StringObject(vm, "wifi");
                    default:
                        throw new IllegalStateException("unknown call self: " + vaList.getIntArg(0));
                }
            }
            case "java/lang/Long->valueOf(J)Ljava/lang/Long;":
                return DvmLong.valueOf(vm, vaList.getLongArg(0));
            case "android/app/ActivityThread->currentProcessName()Ljava/lang/Object;":
                return new StringObject(vm, "com.xingin.xhs");
            default:
                return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
        }
    }

    @Override
    public int callStaticIntMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "android/provider/Settings$System->getInt(Landroid/content/ContentResolver;Ljava/lang/String;)I": {
                String arg1 = (String) vaList.getObjectArg(1).getValue();
                System.out.println("Settings$System arg1=" + arg1);
                if (arg1.equals("screen_brightness")) {
                    return 85;
                } else if (arg1.equals("screen_brightness_mode")) {
                    return 0;
                }
            }
            case "android/provider/Settings$Secure->getInt(Landroid/content/ContentResolver;Ljava/lang/String;)I": {
                String arg1 = (String) vaList.getObjectArg(1).getValue();
                System.out.println("Settings$Secure arg1=" + arg1);
                if (arg1.equals("accessibility_enabled")) {
                    return 1;
                } else if (arg1.equals("location_mode")) {
                    return 1;
                }
            }
            case "android/provider/Settings$Global->getInt(Landroid/content/ContentResolver;Ljava/lang/String;)I": {
                String arg1 = (String) vaList.getObjectArg(1).getValue();
                System.out.println("Settings$Global arg1=" + arg1);
                if (arg1.equals("adb_enabled")) {
                    return 0;
                }
            }
        }
        return super.callStaticIntMethodV(vm, dvmClass, signature, vaList);
    }

    /**
     * 模拟原始 public static native Object a(int i5, Object... objArr);
     * native 内部会递归回调 callStaticObjectMethodV，所以返回 DvmObject 以支持递归
     */
    public DvmObject<?> a(int i5, Object... objArr) {
        DvmObject<?>[] dvmArgs = new DvmObject<?>[objArr.length];
        for (int i = 0; i < objArr.length; i++) {
            Object obj = objArr[i];
            if (obj instanceof DvmObject) {
                dvmArgs[i] = (DvmObject<?>) obj;
            } else if (obj instanceof String) {
                dvmArgs[i] = new StringObject(vm, (String) obj);
            } else if (obj instanceof Long) {
                dvmArgs[i] = DvmLong.valueOf(vm, (Long) obj);
            } else if (obj instanceof Integer) {
                dvmArgs[i] = DvmInteger.valueOf(vm, (Integer) obj);
            } else if (obj instanceof Boolean) {
                dvmArgs[i] = DvmBoolean.valueOf(vm, (Boolean) obj);
            } else if (obj instanceof Float) {
                dvmArgs[i] = ProxyDvmObject.createObject(vm, obj);
            } else if (obj instanceof byte[]) {
                dvmArgs[i] = new ByteArray(vm, (byte[]) obj);
            } else {
                dvmArgs[i] = ProxyDvmObject.createObject(vm, obj);
            }
        }
        List<Object> list = new ArrayList<>();
        list.add(vm.getJNIEnv());
        list.add(0);
        list.add(i5);
        list.add(vm.addLocalObject(new ArrayObject(dvmArgs)));
        Number numbers = module.callFunction(emulator, 0x175118, list.toArray());
        return vm.getObject(numbers.intValue());
    }

    public void sig() {
        DvmObject<?> result = a(-1754486979,
                "GET",
                "edith.xiaohongshu.com",
                "/api/sns/v1/tag/reobpage",
                "ug_role=-1",
                null
        );
        Map mapResult = (Map) result.getValue();
        System.out.println("mapResult:" + mapResult);
    }

    public void init1() {
        DvmObject<?> result = a(-934400877, 10000L);
        System.out.println("result:" + result);
    }

    public void init2() {
        DvmObject<?> result = a(-117791318);
        System.out.println("result:" + result);
    }

    public void init3() {
        DvmObject<?> result = a(1039552848,
                "ECFAAF01",
                "JTdCJTdE",
                0,
                true, false, false,
                1.0f,
                false, false, false,
                true, false, true,
                2.0f,
                true,
                3000.0f
        );
        System.out.println("result:" + result);
    }

}