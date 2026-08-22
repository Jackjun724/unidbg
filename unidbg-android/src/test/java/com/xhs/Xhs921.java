package com.xhs;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.hook.hookzz.HookEntryInfo;
import com.github.unidbg.hook.hookzz.HookZz;
import com.github.unidbg.hook.hookzz.IHookZz;
import com.github.unidbg.hook.hookzz.WrapCallback;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.linux.android.SystemPropertyHook;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.android.dvm.array.LongArray;
import com.github.unidbg.linux.android.dvm.jni.ProxyDvmObject;
import com.github.unidbg.linux.android.dvm.wrapper.DvmBoolean;
import com.github.unidbg.linux.android.dvm.wrapper.DvmInteger;
import com.github.unidbg.linux.android.dvm.wrapper.DvmLong;
import com.github.unidbg.linux.file.DirectoryFileIO;
import com.github.unidbg.linux.file.SimpleFileIO;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.utils.Inspector;
import com.github.unidbg.virtualmodule.android.AndroidModule;
import com.github.unidbg.virtualmodule.android.MediaNdkModule;
import unicorn.Arm64Const;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class Xhs921 extends AbstractJni implements IOResolver<AndroidFileIO> {
    private static final String BISTORE_DIR = "/data/user/0/com.xingin.xhs/.bistore/";
    private static final String BISTORE_NAME = "a6de269810198701a152619ebd19abc1";
    private static final String LOCAL_BISTORE_DIR = "unidbg-android/src/test/java/com/xhs/";
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;
    private final Map<String, Set<String>> bAddrResults = new LinkedHashMap<>();
    // MMKV mock storage: instance_id -> (key -> value)
    private final Map<Long, Map<String, byte[]>> mmkvStore = new HashMap<>();
    public List<String> dataStorage = new ArrayList<>();
    public PrintStream traceStream = null;
    private String bAddrOutputPath;
    private long mmkvInstanceCounter = 0x100000L;
    private long[] mmkvFuncPtrs; // 6 MMKV function pointers

    Xhs921() {
        String traceFile = "unidbg-android/src/test/java/com/xhs/trace.txt";
        try {
            traceStream = new PrintStream(new FileOutputStream(traceFile), true);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        emulator = AndroidEmulatorBuilder.for64Bit()
                .addBackendFactory(new Unicorn2Factory(false))
                .setProcessName("com.xingin.xhs").build();
        // 获取模拟器的内存操作接口
        final Memory memory = emulator.getMemory();
        SystemPropertyHook systemPropertyHook = new SystemPropertyHook(emulator);
        systemPropertyHook.setPropertyProvider(key -> {
            switch (key) {
                case "gsm.version.baseband":
                    return "M8994F-2.6.22.0.56";
                default:
                    return "";
            }
        });
        memory.addHookListener(systemPropertyHook);

        // 设置系统类库解析
        memory.setLibraryResolver(new AndroidResolver(23));
        vm = emulator.createDalvikVM(new File("unidbg-android/src/test/resources/xiaohongshu.apk"));
        vm.setJni(this);
        vm.setVerbose(false);
        emulator.getSyscallHandler().addIOResolver(this);
//        emulator.getSyscallHandler().setVerbose(true);
        new AndroidModule(emulator, vm).register(memory);
        new MediaNdkModule(emulator, vm).register(memory);
//        new JniGraphics(emulator, vm).register(memory);
//        new SystemProperties(emulator, null).register(memory);
        // 加载目标SO
        DalvikModule dm = vm.loadLibrary("tiny", true);
        //获取本SO模块的句柄,后续需要用它
        module = dm.getModule();
        // 调用JNI OnLoad
        dm.callJNI_OnLoad(emulator);
        // 注册 MMKV mock 函数
        registerMmkvSvc();
    }

    public static void main(String[] args) throws Exception {
        Xhs921 xhs = new Xhs921();
        System.out.println("xhs.init1()");
        xhs.init1();
//        xhs.trace();
        System.out.println("xhs.init3()");
        xhs.init3();
        System.out.println("xhs.sig()");
        xhs.sig("");
    }

    private static int regNameToArm64Const(String reg) {
        switch (reg) {
            case "x0":
                return Arm64Const.UC_ARM64_REG_X0;
            case "x1":
                return Arm64Const.UC_ARM64_REG_X1;
            case "x2":
                return Arm64Const.UC_ARM64_REG_X2;
            case "x3":
                return Arm64Const.UC_ARM64_REG_X3;
            case "x4":
                return Arm64Const.UC_ARM64_REG_X4;
            case "x5":
                return Arm64Const.UC_ARM64_REG_X5;
            case "x6":
                return Arm64Const.UC_ARM64_REG_X6;
            case "x7":
                return Arm64Const.UC_ARM64_REG_X7;
            case "x8":
                return Arm64Const.UC_ARM64_REG_X8;
            case "x9":
                return Arm64Const.UC_ARM64_REG_X9;
            case "x10":
                return Arm64Const.UC_ARM64_REG_X10;
            case "x11":
                return Arm64Const.UC_ARM64_REG_X11;
            case "x12":
                return Arm64Const.UC_ARM64_REG_X12;
            case "x13":
                return Arm64Const.UC_ARM64_REG_X13;
            case "x14":
                return Arm64Const.UC_ARM64_REG_X14;
            case "x15":
                return Arm64Const.UC_ARM64_REG_X15;
            case "x16":
                return Arm64Const.UC_ARM64_REG_X16;
            case "x17":
                return Arm64Const.UC_ARM64_REG_X17;
            case "x18":
                return Arm64Const.UC_ARM64_REG_X18;
            case "x19":
                return Arm64Const.UC_ARM64_REG_X19;
            case "x20":
                return Arm64Const.UC_ARM64_REG_X20;
            case "x21":
                return Arm64Const.UC_ARM64_REG_X21;
            case "x22":
                return Arm64Const.UC_ARM64_REG_X22;
            case "x23":
                return Arm64Const.UC_ARM64_REG_X23;
            case "x24":
                return Arm64Const.UC_ARM64_REG_X24;
            case "x25":
                return Arm64Const.UC_ARM64_REG_X25;
            case "x26":
                return Arm64Const.UC_ARM64_REG_X26;
            case "x27":
                return Arm64Const.UC_ARM64_REG_X27;
            case "x28":
                return Arm64Const.UC_ARM64_REG_X28;
            default:
                return -1;
        }
    }

    /**
     * 注册6个MMKV native回调函数，模拟libmmkv2.so的API
     * [0] mmkv_open(name, mode_str, crypto_key, root_path) → instance ptr
     * [1] mmkv_set(instance, key, data_ptr, data_size) → bool
     * [2] mmkv_getValueSize(instance, key) → int (-1 if not found)
     * [3] mmkv_getBytes(instance, key, out_buf, buf_size) → bool
     * [4] mmkv_removeKey(instance, key) → void
     * [5] mmkv_lock(instance, flag) → void
     */
    /**
     * 从 bistore_kv.bin 加载预解密的 MMKV KV 数据到指定 store
     * 文件格式: uint32(count) + repeated { uint16(key_len) + key + uint32(val_len) + val }
     */
    private void loadBistoreKV(Map<String, byte[]> store) {
        File kvFile = new File(LOCAL_BISTORE_DIR + "bistore_kv.bin");
        if (!kvFile.exists()) {
            System.out.println("[MMKV] bistore_kv.bin not found, store empty");
            return;
        }
        try (java.io.DataInputStream dis = new java.io.DataInputStream(
                new java.io.BufferedInputStream(new java.io.FileInputStream(kvFile)))) {
            byte[] all = java.nio.file.Files.readAllBytes(kvFile.toPath());
            java.nio.ByteBuffer buf = java.nio.ByteBuffer.wrap(all).order(java.nio.ByteOrder.LITTLE_ENDIAN);
            int count = buf.getInt();
            for (int i = 0; i < count; i++) {
                int keyLen = buf.getShort() & 0xFFFF;
                byte[] keyBytes = new byte[keyLen];
                buf.get(keyBytes);
                int valLen = buf.getInt();
                byte[] valBytes = new byte[valLen];
                buf.get(valBytes);
                String key = new String(keyBytes, StandardCharsets.UTF_8);
                store.put(key, valBytes);
            }
            System.out.printf("[MMKV] Loaded %d KV pairs from bistore_kv.bin%n", count);
        } catch (Exception e) {
            System.out.println("[MMKV] Failed to load bistore_kv.bin: " + e.getMessage());
        }
    }

    private void registerMmkvSvc() {
        com.github.unidbg.memory.SvcMemory svcMemory = emulator.getSvcMemory();
        mmkvFuncPtrs = new long[6];

        // [0] mmkv_open(name, mode_str, crypto_key, root_path) → instance ptr
        mmkvFuncPtrs[0] = svcMemory.registerSvc(new Arm64Svc("mmkv_open") {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext ctx = emulator.getContext();
                UnidbgPointer namePtr = ctx.getPointerArg(0);
                String name = namePtr != null ? namePtr.getString(0) : "default";
                long instanceId = ++mmkvInstanceCounter;
                Map<String, byte[]> store = new LinkedHashMap<>();
                mmkvStore.put(instanceId, store);
                // 为 aa.aab 实例预加载 bistore 数据
                if ("aa.aab".equals(name)) {
                    loadBistoreKV(store);
                }
                System.out.printf("[MMKV] open(\"%s\") => 0x%x%n", name, instanceId);
                return instanceId;
            }
        }).peer;

        // [1] mmkv_set(instance, key, data_ptr, data_size) → bool
        mmkvFuncPtrs[1] = svcMemory.registerSvc(new Arm64Svc("mmkv_set") {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext ctx = emulator.getContext();
                long instance = ctx.getLongArg(0);
                UnidbgPointer keyPtr = ctx.getPointerArg(1);
                UnidbgPointer dataPtr = ctx.getPointerArg(2);
                long dataSize = ctx.getLongArg(3);
                String key = keyPtr != null ? keyPtr.getString(0) : "";
                Map<String, byte[]> store = mmkvStore.get(instance);
                if (store != null) {
                    if (dataPtr != null && dataSize > 0) {
                        byte[] data = dataPtr.getByteArray(0, (int) dataSize);
                        store.put(key, data);
                        System.out.printf("[MMKV] set(0x%x, \"%s\", %d bytes)%n", instance, key, dataSize);
                    } else {
                        // data_ptr == null means remove
                        store.remove(key);
                        System.out.printf("[MMKV] set(0x%x, \"%s\", remove)%n", instance, key);
                    }
                }
                return 1; // true
            }
        }).peer;

        // [2] mmkv_getValueSize(instance, key) → int (-1 if not found)
        mmkvFuncPtrs[2] = svcMemory.registerSvc(new Arm64Svc("mmkv_getValueSize") {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext ctx = emulator.getContext();
                long instance = ctx.getLongArg(0);
                UnidbgPointer keyPtr = ctx.getPointerArg(1);
                String key = keyPtr != null ? keyPtr.getString(0) : "";
                Map<String, byte[]> store = mmkvStore.get(instance);
                if (store != null && store.containsKey(key)) {
                    int size = store.get(key).length;
                    System.out.printf("[MMKV] getValueSize(0x%x, \"%s\") => %d%n", instance, key, size);
                    return size;
                }
                System.out.printf("[MMKV] getValueSize(0x%x, \"%s\") => -1%n", instance, key);
                return -1;
            }
        }).peer;

        // [3] mmkv_getBytes(instance, key, out_buf, buf_size) → bool
        mmkvFuncPtrs[3] = svcMemory.registerSvc(new Arm64Svc("mmkv_getBytes") {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext ctx = emulator.getContext();
                long instance = ctx.getLongArg(0);
                UnidbgPointer keyPtr = ctx.getPointerArg(1);
                UnidbgPointer outBuf = ctx.getPointerArg(2);
                long bufSize = ctx.getLongArg(3);
                String key = keyPtr != null ? keyPtr.getString(0) : "";
                Map<String, byte[]> store = mmkvStore.get(instance);
                if (store != null && store.containsKey(key)) {
                    byte[] data = store.get(key);
                    if (data.length <= bufSize && outBuf != null) {
                        outBuf.write(0, data, 0, data.length);
                        System.out.printf("[MMKV] getBytes(0x%x, \"%s\", %d) => true%n", instance, key, data.length);
                        return 1;
                    }
                }
                System.out.printf("[MMKV] getBytes(0x%x, \"%s\") => false%n", instance, key);
                return 0;
            }
        }).peer;

        // [4] mmkv_removeKey(instance, key) → void
        mmkvFuncPtrs[4] = svcMemory.registerSvc(new Arm64Svc("mmkv_removeKey") {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext ctx = emulator.getContext();
                long instance = ctx.getLongArg(0);
                UnidbgPointer keyPtr = ctx.getPointerArg(1);
                String key = keyPtr != null ? keyPtr.getString(0) : "";
                Map<String, byte[]> store = mmkvStore.get(instance);
                if (store != null) {
                    store.remove(key);
                }
                System.out.printf("[MMKV] removeKey(0x%x, \"%s\")%n", instance, key);
                return 0;
            }
        }).peer;

        // [5] mmkv_lock(instance, flag) → void
        mmkvFuncPtrs[5] = svcMemory.registerSvc(new Arm64Svc("mmkv_lock") {
            @Override
            public long handle(Emulator<?> emulator) {
                RegisterContext ctx = emulator.getContext();
                long instance = ctx.getLongArg(0);
                int flag = ctx.getIntArg(1);
                System.out.printf("[MMKV] lock(0x%x, %d)%n", instance, flag);
                return 0;
            }
        }).peer;

        System.out.println("[MMKV] Registered 6 mock MMKV functions:");
        String[] names = {"mmkv_open", "mmkv_set", "mmkv_getValueSize", "mmkv_getBytes", "mmkv_removeKey", "mmkv_lock"};
        for (int i = 0; i < 6; i++) {
            System.out.printf("  [%d] %s => 0x%x%n", i, names[i], mmkvFuncPtrs[i]);
        }
    }

    @Override
    public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String pathname, int oflags) {
        // .bistore 文件服务
        if (pathname.equals(BISTORE_DIR + BISTORE_NAME)) {
            File file = new File(LOCAL_BISTORE_DIR + "bistore_main.bin");
            if (file.exists()) {
                return FileResult.success(new SimpleFileIO(oflags, file, pathname));
            }
        }
        if (pathname.equals(BISTORE_DIR + BISTORE_NAME + ".crc")) {
            File file = new File(LOCAL_BISTORE_DIR + "bistore_crc.bin");
            if (file.exists()) {
                return FileResult.success(new SimpleFileIO(oflags, file, pathname));
            }
        }

        // /sdcard statfs64 - 模拟真机存在的外部存储
        if (pathname.equals("/sdcard")) {
            System.out.println("[resolve] /sdcard hit, returning DirectoryFileIO");
            return FileResult.success(new DirectoryFileIO(oflags, pathname));
        }

        return null;
    }

    /**
     * Hook svc #0 捕获 fstatat64 (syscall 79) 的路径参数
     */
    public void hookFstatat() {
        // hook地址 0x27da98 是 svc #0 指令
        emulator.attach().addBreakPoint(module.base + 0x27da98, (emu, addr) -> {
            Backend backend = emu.getBackend();
            long x8 = backend.reg_read(Arm64Const.UC_ARM64_REG_X8).longValue();
            if (x8 == 79) { // newfstatat
                long x0 = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                long x1 = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).longValue();
                UnidbgPointer pathPtr = UnidbgPointer.pointer(emulator, x1);
                String path = pathPtr != null ? pathPtr.getString(0) : "<null>";
                System.out.println("[SVC fstatat64] dirfd=" + x0 + " path=" + path);
            }
            return true;
        });
    }

    /**
     * Hook JSON 值处理函数。
     * 通过 trace 分析确认的数据流：
     * jstringToStdString (0x1c9da8)
     * → SIMD copy (0x1ca038)
     * → dispatcher 0x170b70 分发每个 JSON 元素
     * → 0x172278 接收 std::string(x1)，逐字节写入 JSON
     * <p>
     * Hook 0x172278 入口：x1 = std::string*，读取即为当前 value。
     */
    public void hookJsonPut() {
        long base = module.base;
        Debugger debugger = emulator.attach();

        // Hook 0x172278: 字节处理函数入口
        // trace 确认: x1 = std::string 指针 (SSO)，包含当前要写入 JSON 的 value
        // 从 dispatcher 0x170b70 经 0x170d94 调用
        final int[] callCount = {0};
        final String[] lastHeaderKey = {""};
        final boolean[] inHeaderJson = {false};
        debugger.addBreakPoint(base + 0x172278, (emu, addr) -> {
            Backend backend = emu.getBackend();
            long x0 = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
            long x1 = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).longValue();
            long lr = backend.reg_read(Arm64Const.UC_ARM64_REG_LR).longValue();

            String val = "";
            try {
                UnidbgPointer ptr = UnidbgPointer.pointer(emulator, x1);
                if (ptr != null) {
                    val = readSSOString(emulator, ptr);
                }
            } catch (Exception e) {
                val = "<err>";
            }

            callCount[0]++;

            // Detect header JSON context: starts with key "a" value "ECFAAF01"
            if (val.equals("a") && callCount[0] < 5) inHeaderJson[0] = true;
            // Ends when we see "x0" (fingerprint payload starts)
            if (val.equals("x0")) inHeaderJson[0] = false;

            if (inHeaderJson[0]) {
                System.out.printf("[HeaderJson #%d] caller=0x%x value=\"%s\"%n",
                        callCount[0], lr - base, val);

                // When we see key "s" or "k", dump the SSO string source address
                if (val.equals("s") || val.equals("k") || val.equals("t") || val.equals("u")) {
                    lastHeaderKey[0] = val;
                }
                // When next value is the hex data for s/k
                if (!lastHeaderKey[0].isEmpty() && val.length() >= 40) {
                    System.out.printf("  >>> HEADER field '%s' value src=0x%x len=%d%n",
                            lastHeaderKey[0], x1, val.length());
                    // Dump call stack by reading LR chain
                    long x19 = backend.reg_read(Arm64Const.UC_ARM64_REG_X19).longValue();
                    long x20 = backend.reg_read(Arm64Const.UC_ARM64_REG_X20).longValue();
                    long x21 = backend.reg_read(Arm64Const.UC_ARM64_REG_X21).longValue();
                    System.out.printf("  >>> X19=0x%x X20=0x%x X21=0x%x%n", x19, x20, x21);
                    lastHeaderKey[0] = "";
                }
            } else {
                System.out.printf("[JsonValue #%d] caller=0x%x x0=0x%x x1=0x%x value=\"%s\"%n",
                        callCount[0], lr - base, x0, x1, val);
            }
            return true;
        });

        // Hook dispatcher 入口 0x170b70: 每个 JSON 元素都经过这里
        debugger.addBreakPoint(base + 0x170b70, (emu, addr) -> {
            Backend backend = emu.getBackend();
            long x0 = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
            long x1 = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).longValue();
            long x2 = backend.reg_read(Arm64Const.UC_ARM64_REG_X2).longValue();
            long lr = backend.reg_read(Arm64Const.UC_ARM64_REG_LR).longValue();

            System.out.printf("[Dispatcher] caller=0x%x x0=0x%x x1=0x%x x2=0x%x%n",
                    lr - base, x0, x1, x2);
            return true;
        });
    }

    private String readSSOString(Emulator<?> emulator, UnidbgPointer ptr) {
        byte firstByte = ptr.getByte(0);
        if ((firstByte & 1) == 0) {
            // 短字符串模式，长度 = firstByte >> 1
            int len = (firstByte & 0xFF) >> 1;
            if (len == 0) return "";
            byte[] data = ptr.getByteArray(1, len);
            return new String(data, StandardCharsets.UTF_8);
        } else {
            // 长字符串模式，+8 是长度，+16 是数据指针
            long len = ptr.getLong(8);
            long dataPtr = ptr.getLong(16);
            UnidbgPointer dataP = UnidbgPointer.pointer(emulator, dataPtr);
            byte[] data = dataP.getByteArray(0, (int) len);
            return new String(data, StandardCharsets.UTF_8);
        }
    }

    // 辅助方法
    private String bytesToHexDump(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            if (i > 0 && i % 16 == 0) sb.append('\n');
            sb.append(String.format("%02X ", data[i] & 0xFF));
        }
        return sb.toString();
    }

    private String bytesToHex(byte[] bytes) {
        return bytesToHex(bytes, 0, bytes.length);
    }

    private String bytesToHex(byte[] bytes, int offset, int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = offset; i < offset + length && i < bytes.length; i++) {
            sb.append(String.format("%02x", bytes[i] & 0xFF));
        }
        return sb.toString();
    }

    public void hookGF_mul() {
        List<int[]> roundStates = new ArrayList<>();
        List<Integer> currentColumn = new ArrayList<>();

        emulator.attach().addBreakPoint(module.base + 0x66cefc, (emu, addr) -> {
            Backend backend = emu.getBackend();
            int w1 = backend.reg_read(Arm64Const.UC_ARM64_REG_W1).intValue() & 0xff;
            currentColumn.add(w1);

            if (currentColumn.size() == 16) { // 一组完成(4列×4行)
                int[] state = currentColumn.stream().mapToInt(Integer::intValue).toArray();
                roundStates.add(state);
                System.out.printf("MixColumns input state #%d: %s%n",
                        roundStates.size(),
                        Arrays.stream(state).mapToObj(b -> String.format("%02x", b))
                                .collect(Collectors.joining(" ")));
                currentColumn.clear();
            }

            return true;
        });
    }

    public void hookWhiteBoxAes() {
        // ====== Hook 1: AES入口 - 内层白盒AES函数 ======
        emulator.attach().addBreakPoint(module.base + 0x66041c, (emu, addr) -> {
            System.out.println("[White-Box AES] === White-Box AES Entry ===");
            // 打印参数寄存器
            Backend backend = emu.getBackend();
            System.out.printf("[White-Box AES] x0=0x%x x1=0x%x x2=0x%x x3=0x%x%n",
                    backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue(),
                    backend.reg_read(Arm64Const.UC_ARM64_REG_X1).longValue(),
                    backend.reg_read(Arm64Const.UC_ARM64_REG_X2).longValue(),
                    backend.reg_read(Arm64Const.UC_ARM64_REG_X3).longValue());
            return true;
        });

        // ====== Hook 2: AES外层包装 - 观察被调用7次 ======
        emulator.attach().addBreakPoint(module.base + 0x70c56c, (emu, addr) -> {
            System.out.println("[White-Box AES] === AES Wrapper Entry (called 7x) ===");
            Backend backend = emu.getBackend();
            int w6 = backend.reg_read(Arm64Const.UC_ARM64_REG_W6).intValue();
            System.out.printf("[White-Box AES] w6=0x%x (mode flag)%n", w6);
            return true;
        });

        // ====== Hook 3: AddRoundKey XOR - 每轮16次 ======
        emulator.attach().addBreakPoint(module.base + 0x7110b8, (emu, addr) -> {
            Backend backend = emu.getBackend();
            int w9 = backend.reg_read(Arm64Const.UC_ARM64_REG_W9).intValue();
            int w8 = backend.reg_read(Arm64Const.UC_ARM64_REG_W8).intValue();
            System.out.printf("[White-Box AES] AddRoundKey: 0x%02x ^ 0x%02x = 0x%02x%n",
                    w9 & 0xff, w8 & 0xff, (w9 ^ w8) & 0xff);
            return true;
        });

        // ====== Hook 4: GF(2^8)乘法 - MixColumns核心 ======
        emulator.attach().addBreakPoint(module.base + 0x66cefc, (emu, addr) -> {
            Backend backend = emu.getBackend();
            System.out.printf("[White-Box AES] GF_mul entry: w0=0x%x w1=0x%x%n",
                    backend.reg_read(Arm64Const.UC_ARM64_REG_W0).intValue(),
                    backend.reg_read(Arm64Const.UC_ARM64_REG_W1).intValue());
            return true;
        });

        // ====== Hook 5: 32字节输入数据的memcpy ======
        emulator.attach().addBreakPoint(module.base + 0x66ae8c, (emu, addr) -> {
            Backend backend = emu.getBackend();
            long x1 = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).longValue(); // dst
            long x2 = backend.reg_read(Arm64Const.UC_ARM64_REG_X2).longValue(); // src
            long x3 = backend.reg_read(Arm64Const.UC_ARM64_REG_X3).longValue(); // len
            if (x3 == 0x20) {
                System.out.printf("[White-Box AES] memcpy 32 bytes: dst=0x%x src=0x%x%n", x1, x2);
                byte[] data = emu.getBackend().mem_read(x2, 32);
                System.out.println("[White-Box AES] data: " + bytesToHex(data));
            }
            return true;
        });
    }

    public void hookS1Sha256() {

        Debugger debugger = emulator.attach();

        debugger.addBreakPoint(module.base + 0x72436C, (emulator, address) -> {
            RegisterContext ctx = emulator.getContext();

            long dataPtr = ctx.getLongArg(0);
            long dataLen = ctx.getLongArg(1);
            final long outPtr = ctx.getLongArg(2);

            // 正确读 LR
            long lr = emulator.getContext().getLR();

            System.out.println("===== SHA-256 ENTER =====");
            System.out.printf("  LR=0x%x input ptr=0x%x len=%d%n", lr, dataPtr, dataLen);
            if (dataLen > 0 && dataLen <= 4096) {
                byte[] input = emulator.getMemory().pointer(dataPtr).getByteArray(0, (int) dataLen);
                // hex
                System.out.println("  [HEX ] " + bytesToHex(input));
                // 可读文本
                System.out.println("  [TEXT] " + new String(input, StandardCharsets.UTF_8));
            }

            // 在 LR 打一次性断点，函数返回时触发
            debugger.addBreakPoint(lr, (emulator1, address1) -> {
                byte[] hash = emulator1.getMemory().pointer(outPtr).getByteArray(0, 32);
                System.out.println("===== SHA-256 RETURN =====");
                System.out.println("  [HASH] " + bytesToHex(hash));

                // 移除自身，避免下次经过 LR 地址时重复触发
                debugger.removeBreakPoint(address1);
                return true;
            });

            return true;
        });

        // ---- 每个压缩块（sub_723980）----
        debugger.addBreakPoint(module.base + 0x723980, new BreakPointCallback() {
            private int blockCount = 0;

            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                RegisterContext ctx = emulator.getContext();

                long ctxPtr = ctx.getLongArg(0);  // X0 - SHA256 context
                long blockPtr = ctx.getLongArg(1);  // X1 - 当前512bit块

                byte[] block = emulator.getMemory().pointer(blockPtr).getByteArray(0, 64);
                System.out.printf("  [COMPRESS #%d] block(64B): %s%n", blockCount++, bytesToHex(block));

                return true;
            }
        });

        // ---- padding后最终块（sub_547670 = memcpy tail block）----
        debugger.addBreakPoint(module.base + 0x547670, (emulator, address) -> {
            RegisterContext ctx = emulator.getContext();

            long dst = ctx.getLongArg(0);
            long src = ctx.getLongArg(1);
            long len = ctx.getLongArg(2);

            System.out.println("  [TAIL BLOCK memcpy]");
            System.out.printf("    dst=0x%x src=0x%x len=%d%n", dst, src, len);

            if (len > 0 && len <= 64) {
                byte[] tail = emulator.getMemory().pointer(src).getByteArray(0, (int) len);
                System.out.println("    tail data: " + bytesToHex(tail));
            }

            return true;
        });

    }

    /* x-mini-mua server椭圆 public key */
    public void hookPublicKey() {
        // 这个点要通过hook urandom read_chk 的随机来xref向上找到
        Debugger debugger = emulator.attach();
        long base = module.base;

        AtomicInteger callCount = new AtomicInteger();

        debugger.addBreakPoint(base + 0x53973C, (emulator, address) -> {
            RegisterContext ctx = emulator.getContext();
            UnidbgPointer x0 = ctx.getPointerArg(0);
            UnidbgPointer x1 = ctx.getPointerArg(1);
            UnidbgPointer x2 = ctx.getPointerArg(2);

            byte[] scalar = x0.getByteArray(0, 32);
            byte[] point = x1.getByteArray(0, 32);

            int idx = callCount.getAndIncrement();
            if (idx % 2 == 0) {
                System.out.println("  ECDH本地私钥  (X0): " + bytesToHex(scalar));
            } else {
                System.out.println("  ECDH对端公钥  (X1): " + bytesToHex(point));
            }

            // 保存参数，供返回点读取输出
            emulator.set("sm_x0", x0);
            emulator.set("sm_x1", x1);
            emulator.set("sm_x2", x2);
            emulator.set("sm_idx", idx);
            return true;
        });

    }

    public void hookReadChk() {
        Debugger debugger = emulator.attach();
        debugger.addBreakPoint(module.base + 0x4755F8L);
    }

    /**
     * Hook base64 encode (0x7329F4) to capture raw input data
     * Signature: int base64_encode(char* out, uint64_t out_size, uint64_t* out_len, uint8_t* input, uint64_t input_len)
     */
    public void hookBase64Encode() {
        long base = module.base;
        Debugger debugger = emulator.attach();
        final int[] b64Count = {0};

        debugger.addBreakPoint(base + 0x7329F4, (emu, addr) -> {
            Backend backend = emu.getBackend();
            long x3 = backend.reg_read(Arm64Const.UC_ARM64_REG_X3).longValue(); // input data
            long x4 = backend.reg_read(Arm64Const.UC_ARM64_REG_X4).longValue(); // input length
            long lr = backend.reg_read(Arm64Const.UC_ARM64_REG_LR).longValue();

            b64Count[0]++;
            UnidbgPointer inputPtr = UnidbgPointer.pointer(emulator, x3);
            if (inputPtr != null && x4 > 0 && x4 < 65536) {
                byte[] data = inputPtr.getByteArray(0, (int) x4);
                String hex = bytesToHex(data);
                String ascii = "";
                try {
                    ascii = new String(data, StandardCharsets.UTF_8);
                    // Only show if printable
                    if (!ascii.chars().allMatch(c -> c >= 0x20 && c < 0x7f)) {
                        ascii = "<binary>";
                    }
                } catch (Exception e) {
                    ascii = "<binary>";
                }
                System.out.printf("[Base64Encode #%d] caller=0x%x len=%d%n  hex=%s%n  ascii=%s%n",
                        b64Count[0], lr - base, x4, hex, ascii);
            }
            return true;
        });
    }

    /**
     * Hook string_assign (0x1418F0) to catch when 128-char hex string for 's' field is created.
     * Also hook bytes-to-hex conversion to trace how random bytes become hex strings.
     */
    public void hookStringAssignForHeader() {
        long base = module.base;
        Debugger debugger = emulator.attach();
        final int[] saCount = {0};

        // Hook string_assign: void string_assign(std::string* dst, const char* src, size_t len)
        debugger.addBreakPoint(base + 0x1418F0, (emu, addr) -> {
            Backend backend = emu.getBackend();
            long x0 = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
            long x1 = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).longValue();
            long x2 = backend.reg_read(Arm64Const.UC_ARM64_REG_X2).longValue();
            long lr = backend.reg_read(Arm64Const.UC_ARM64_REG_LR).longValue();

            // Only log hex-like strings of key lengths
            if (x2 == 128 || x2 == 64 || x2 == 40 || x2 == 32) {
                saCount[0]++;
                UnidbgPointer srcPtr = UnidbgPointer.pointer(emulator, x1);
                String val = "";
                if (srcPtr != null) {
                    byte[] data = srcPtr.getByteArray(0, (int) x2);
                    val = new String(data, StandardCharsets.UTF_8);
                }
                System.out.printf("[StringAssign #%d] caller=0x%x dst=0x%x len=%d value=\"%s\"%n",
                        saCount[0], lr - base, x0, x2, val);
                // Print backtrace via register chain
                long x19 = backend.reg_read(Arm64Const.UC_ARM64_REG_X19).longValue();
                long x20 = backend.reg_read(Arm64Const.UC_ARM64_REG_X20).longValue();
                System.out.printf("  X19=0x%x X20=0x%x%n", x19, x20);
            }
            return true;
        });
    }

    /**
     * Hook u 字段相关函数，追踪 u 值的计算和插入
     */
    public void hookUFieldTrace() {
        Debugger debugger = emulator.attach();
        long base = module.base;

        // Hook map_insert (0x28C7E8) 捕获所有 key 插入
        debugger.addBreakPoint(base + 0x28C7E8, (emu, addr) -> {
            Backend backend = emu.getBackend();
            long x1 = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).longValue();
            long lr = backend.reg_read(Arm64Const.UC_ARM64_REG_LR).longValue();
            UnidbgPointer keyPtr = UnidbgPointer.pointer(emu, x1);
            if (keyPtr != null) {
                String key = readSSOStringAt(keyPtr);
                if (key != null && key.length() <= 5) {
                    System.out.println("[MAP_INSERT] key=\"" + key + "\" caller=0x" + Long.toHexString(lr - base));
                }
            }
            return true;
        });

        // Hook sub_1F95D4 (t builder) 入口
        debugger.addBreakPoint(base + 0x1F95D4, (emu, addr) -> {
            Backend backend = emu.getBackend();
            long x27 = backend.reg_read(Arm64Const.UC_ARM64_REG_X27).longValue();
            System.out.println("[U_TRACE] sub_1F95D4 enter: X27(v3)=0x" + Long.toHexString(x27));
            return true;
        });

        // Hook sub_51F9E4 (security detection)
        debugger.addBreakPoint(base + 0x51F9E4, (emu, addr) -> {
            System.out.println("[U_TRACE] sub_51F9E4 security detection called");
            return true;
        });

        // Hook vm_load_1F655C (0x1F6564) — u 值拷贝点
        debugger.addBreakPoint(base + 0x1F6564, (emu, addr) -> {
            Backend backend = emu.getBackend();
            long x19 = backend.reg_read(Arm64Const.UC_ARM64_REG_X19).longValue();
            UnidbgPointer vmState = UnidbgPointer.pointer(emu, x19);
            if (vmState != null) {
                long srcPtrAddr = vmState.getLong(1248);
                UnidbgPointer src = UnidbgPointer.pointer(emu, srcPtrAddr);
                if (src != null) {
                    String val = readCStringAt(src);
                    System.out.println("[U_TRACE] vm_load_1F655C: u_value_src=\"" + val + "\"");
                }
            }
            return true;
        });

        // Hook vm_dispatch_15BF1C 出口 — key名解密结果
        debugger.addBreakPoint(base + 0x15BF1C, (emu, addr) -> {
            // 在入口记录参数，出口读取结果 (这里简化只在入口打印)
            return true;
        });

        // Hook 0x1B5F10 — byte_7B77C8 读取点 (atomic_load)
        debugger.addBreakPoint(base + 0x1B5F10, (emu, addr) -> {
            Backend backend = emu.getBackend();
            long x8 = backend.reg_read(Arm64Const.UC_ARM64_REG_X8).longValue();
            UnidbgPointer c8Ptr = UnidbgPointer.pointer(emu, module.base + 0x7B77C8);
            UnidbgPointer e8Ptr = UnidbgPointer.pointer(emu, module.base + 0x7B77E8);
            System.out.println("[U_TRACE] @0x1B5F10 byte_7B77C8=" + (c8Ptr != null ? c8Ptr.getByte(0) : "null")
                    + " byte_7B77E8=" + (e8Ptr != null ? e8Ptr.getByte(0) : "null"));
            return true;
        });

        // Hook 0x1B5F34 — byte_7B77E8 check & dispatch
        debugger.addBreakPoint(base + 0x1B5F34, (emu, addr) -> {
            Backend backend = emu.getBackend();
            UnidbgPointer e8Ptr = UnidbgPointer.pointer(emu, module.base + 0x7B77E8);
            byte val = e8Ptr != null ? e8Ptr.getByte(0) : 0;
            System.out.println("[U_TRACE] @0x1B5F34 byte_7B77E8=" + val + " → path=" + (val != 0 ? "376(t/u)" : "3720(no t/u)"));
            return true;
        });

        System.out.println("[U_TRACE] hooks installed");
    }

    /**
     * Hook decryption functions to capture "t" field key names and "u" field class/method names.
     * Also hooks FindClass wrapper (sub_4FD5A8) and method resolver (sub_4FE1A0).
     */
    public void hookHeaderDecrypt() {
        long base = module.base;
        Debugger debugger = emulator.attach();

        // Hook sub_29A6F0 return (3-byte key decryptor #1)
        debugger.addBreakPoint(base + 0x29A758, (emu, addr) -> {
            long x0 = emu.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
            UnidbgPointer ptr = UnidbgPointer.pointer(emulator, x0);
            if (ptr != null) {
                String s = readCStringAt(ptr);
                System.out.println("[DECRYPT sub_29A6F0] key=\"" + s + "\"");
            }
            return true;
        });

        // Hook sub_29A680 return (3-byte key decryptor #2)
        debugger.addBreakPoint(base + 0x29A6E8, (emu, addr) -> {
            long x0 = emu.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
            UnidbgPointer ptr = UnidbgPointer.pointer(emulator, x0);
            if (ptr != null) {
                String s = readCStringAt(ptr);
                System.out.println("[DECRYPT sub_29A680] key=\"" + s + "\"");
            }
            return true;
        });

        // Hook sub_29A610 return (3-byte key decryptor #3)
        debugger.addBreakPoint(base + 0x29A678, (emu, addr) -> {
            long x0 = emu.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
            UnidbgPointer ptr = UnidbgPointer.pointer(emulator, x0);
            if (ptr != null) {
                String s = readCStringAt(ptr);
                System.out.println("[DECRYPT sub_29A610] key=\"" + s + "\"");
            }
            return true;
        });

        // Hook sub_29A524 return (4-byte key decryptor #1)
        debugger.addBreakPoint(base + 0x29A58C, (emu, addr) -> {
            long x0 = emu.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
            UnidbgPointer ptr = UnidbgPointer.pointer(emulator, x0);
            if (ptr != null) {
                String s = readCStringAt(ptr);
                System.out.println("[DECRYPT sub_29A524] key=\"" + s + "\"");
            }
            return true;
        });

        // Hook sub_29A4B4 return (4-byte key decryptor #2)
        debugger.addBreakPoint(base + 0x29A51C, (emu, addr) -> {
            long x0 = emu.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
            UnidbgPointer ptr = UnidbgPointer.pointer(emulator, x0);
            if (ptr != null) {
                String s = readCStringAt(ptr);
                System.out.println("[DECRYPT sub_29A4B4] key=\"" + s + "\"");
            }
            return true;
        });

        // Hook at 0x2E2574: STR X22, [X23, #qword_7C1530] — X22 = decrypted class name buffer
        debugger.addBreakPoint(base + 0x2E2574, (emu, addr) -> {
            long x22 = emu.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X22).longValue();
            UnidbgPointer ptr = UnidbgPointer.pointer(emulator, x22);
            if (ptr != null) {
                String s = readCStringAt(ptr);
                System.out.println("[U_CLASS] decrypted class name = \"" + s + "\" (X22=0x" + Long.toHexString(x22) + ")");
            }
            return true;
        });

        // Hook at 0x2E25D4: STR X22, [X23, #qword_7C1520] — X22 = decrypted method name buffer
        debugger.addBreakPoint(base + 0x2E25D4, (emu, addr) -> {
            long x22 = emu.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X22).longValue();
            UnidbgPointer ptr = UnidbgPointer.pointer(emulator, x22);
            if (ptr != null) {
                String s = readCStringAt(ptr);
                System.out.println("[U_METHOD] decrypted method name = \"" + s + "\" (X22=0x" + Long.toHexString(x22) + ")");
            }
            return true;
        });

        // Hook FindClass wrapper sub_4FD5A8 to see what class is being loaded
        debugger.addBreakPoint(base + 0x4FD5A8, (emu, addr) -> {
            long x2 = emu.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X2).longValue();
            UnidbgPointer ptr = UnidbgPointer.pointer(emulator, x2);
            if (ptr != null) {
                String s = readCStringAt(ptr);
                System.out.println("[FindClass] class=\"" + s + "\"");
            }
            return true;
        });

        // Hook sub_2DAFA0 return to capture decoded string
        debugger.addBreakPoint(base + 0x2DAFA0, (emu, addr) -> {
            // We'll hook at the call sites instead
            return true;
        });

        System.out.println("[*] Header decrypt hooks installed");
    }

    private String readSSOStringAt(UnidbgPointer ptr) {
        try {
            byte firstByte = ptr.getByte(0);
            if ((firstByte & 1) == 0) {
                // Short SSO: length = firstByte >>> 1, data starts at offset 1
                int len = (firstByte & 0xFF) >>> 1;
                if (len == 0) return "";
                byte[] buf = new byte[len];
                for (int i = 0; i < len; i++) buf[i] = ptr.getByte(i + 1);
                return new String(buf, StandardCharsets.UTF_8);
            } else {
                // Long SSO: size at offset 8, pointer at offset 16
                long size = ptr.getLong(8);
                long dataAddr = ptr.getLong(16);
                UnidbgPointer dataPtr = UnidbgPointer.pointer(emulator, dataAddr);
                if (dataPtr == null || size <= 0 || size > 1024) return "<long-sso-err>";
                byte[] buf = new byte[(int) size];
                for (int i = 0; i < (int) size; i++) buf[i] = dataPtr.getByte(i);
                return new String(buf, StandardCharsets.UTF_8);
            }
        } catch (Exception e) {
            return "<sso-err:" + e.getMessage() + ">";
        }
    }

    private String readCStringAt(UnidbgPointer ptr) {
        try {
            byte[] buf = new byte[128];
            for (int i = 0; i < buf.length; i++) {
                buf[i] = ptr.getByte(i);
                if (buf[i] == 0) {
                    return new String(buf, 0, i, StandardCharsets.UTF_8);
                }
            }
            return new String(buf, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "<err:" + e.getMessage() + ">";
        }
    }

    /**
     * Unused - kept for reference
     */
    public void hookRandomAndECDH() {
        long base = module.base;
        Debugger debugger = emulator.attach();

        // Track which header JSON key is being written (from byte_reader at 0x172278)
        final String[] lastKey = {""};

        // Hook 0x17105c caller — this writes JSON keys (single chars like "a","c","k","p","s","v")
        // When we see key "s", the next value write will be the s hex string
        debugger.addBreakPoint(base + 0x172278, (emu, addr) -> {
            Backend backend = emu.getBackend();
            long x1 = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).longValue();
            long lr = backend.reg_read(Arm64Const.UC_ARM64_REG_LR).longValue();
            long x19 = backend.reg_read(Arm64Const.UC_ARM64_REG_X19).longValue();

            String val = "";
            try {
                UnidbgPointer ptr = UnidbgPointer.pointer(emulator, x1);
                if (ptr != null) val = readSSOString(emulator, ptr);
            } catch (Exception e) {
                val = "<err>";
            }

            // When writing header key "s", dump VM state (X19 context)
            if (val.equals("s") || val.equals("t") || val.equals("u")) {
                System.out.printf("[HEADER_KEY] key=\"%s\" caller=0x%x X19=0x%x%n", val, lr - base, x19);
                lastKey[0] = val;
            }
            // When writing the s/t/u value (128-char or 40-char hex string after key)
            if (lastKey[0].equals("s") && val.length() == 128) {
                System.out.printf("[HEADER_S_VALUE] value=\"%s\"%n", val);
                // Dump X19 context to understand VM state
                UnidbgPointer p19 = UnidbgPointer.pointer(emulator, x19);
                if (p19 != null) {
                    try {
                        // Dump relevant offsets around the VM state
                        for (int off = 0; off <= 1200; off += 8) {
                            long qword = p19.getLong(off);
                            if (qword != 0) {
                                System.out.printf("  X19+0x%x = 0x%x%n", off, qword);
                            }
                        }
                    } catch (Exception e) { /* ignore */ }
                }
                lastKey[0] = "";
            }
            return true;
        });
    }

    public void hookSigHashAndTransform() {
        // 通过从后向前推一点点找到这个位置
        long base = module.base;

        // ----------------------------------------------------------
        // Hook A: 变换开始前 (offset 0x278630) - 读取原始数据
        // ----------------------------------------------------------
        emulator.attach().addBreakPoint(base + 0x278630, (emulator, address) -> {
            RegisterContext ctx = emulator.getContext();
            // x19+0xc0 存储 buffer 指针
            UnidbgPointer x19 = ctx.getPointerArg(19);  // 不标准, 用下面方式
            long x19val = ((Number) emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X19)).longValue();
            UnidbgPointer bufferPtrPtr = UnidbgPointer.pointer(emulator, x19val + 0xc0);
            if (bufferPtrPtr != null) {
                long bufferAddr = bufferPtrPtr.getLong(0);
                UnidbgPointer bufferPtr = UnidbgPointer.pointer(emulator, bufferAddr);
                if (bufferPtr != null) {
                    byte[] data = bufferPtr.getByteArray(0, 32);
                    System.out.println("===== 变换前 (offset 0x278630) =====");
                    System.out.println("  buffer 地址: 0x" + Long.toHexString(bufferAddr));
                    System.out.println("  原始数据 (32 bytes): " + bytesToHex(data));

                    final String prefix = bytesToHex(data, 0, 16);
                    dataStorage.add(prefix);
                    System.out.println("  前16字节: " + prefix);
                    System.out.println("  后16字节: " + bytesToHex(data, 16, 16));
                }
            }
            return true;
        });

        // ----------------------------------------------------------
        // Hook B: bl SHA256 之前 (offset 0x273fb8) - 读取变换后数据
        // ----------------------------------------------------------
        emulator.attach().addBreakPoint(base + 0x273fb8, (emulator, address) -> {
            RegisterContext ctx = emulator.getContext();
            // 此时 x0 已经被设置为 buffer 指针, x1 = 0x20
            UnidbgPointer x0 = ctx.getPointerArg(0);
            int x1 = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X1).intValue();

            System.out.println("===== 变换后 / ByteToHex 调用前 (offset 0x273fb8) =====");
            System.out.println("  x0 (buffer) = " + x0);
            System.out.println("  x1 (length) = 0x" + Integer.toHexString(x1));

            if (x0 != null) {
                byte[] data = x0.getByteArray(0, Math.min(x1, 64));
                System.out.println("  变换后数据 (" + data.length + " bytes): " + bytesToHex(data));
                final String dataPrefix = bytesToHex(data, 0, 16);
                dataStorage.add(dataPrefix);
                System.out.println("  前16字节 (已变换): " + dataPrefix);
                if (data.length >= 32) {
                    System.out.println("  后16字节 (未变换): " + bytesToHex(data, 16, 16));
                }
            }
            return true;
        });
    }

    /*
     * x-mini-sig hash content
     * */
    public void hookSigHashContentUpdate() {
        Debugger debugger = emulator.attach();
        debugger.addBreakPoint(module.base + 0x535B48, (emulator, address) -> {
            RegisterContext context = emulator.getContext();
            UnidbgPointer data = context.getPointerArg(1);  // x1 = data
            long lr = context.getLongArg(30);
            int len = context.getIntArg(2);                 // x2 = len
            if (data != null && len > 0 && len < 0x10000) {
                Inspector.inspect(data.getByteArray(0, len),
                        "SHA256_update len=" + len + " lr=0x" + Long.toHexString(lr));
            }
            return true;
        });
    }

    public void hookMemcpy() {

        // 1. 获取 HookZz 实例
        IHookZz hookZz = HookZz.getInstance(emulator);

        long[] address = new long[]{
                module.base + 0x547210,
                module.base + 0x66D200,
        };

        for (long hookAddress : address) {
            // 3. 使用 wrap 方法进行 Hook
            hookZz.wrap(hookAddress, new WrapCallback<RegisterContext>() {
                // 函数执行前拦截 (获取传入的参数)
                @Override
                public void preCall(Emulator<?> emulator, RegisterContext ctx, HookEntryInfo info) {

                    // 在 ARM64 中，参数依次放入 X0, X1, X2...
                    // getPointerArg / getLongArg 会自动处理不同架构(32/64位)的寄存器映射
                    UnidbgPointer destPtr = ctx.getPointerArg(0); // 参数 1: result (dest)
                    UnidbgPointer srcPtr = ctx.getPointerArg(1); // 参数 2: a2 (src)
                    long lr = ctx.getLR();
                    long size = ctx.getLongArg(2);    // 参数 3: a3 (size)

                    System.out.printf("\n--- [HookZz] (memcpy) ---\n");
                    System.out.printf("dest : %s\n", destPtr);
                    System.out.printf("src  : %s\n", srcPtr);
                    System.out.printf("size : %d bytes\n", size);
                    System.out.printf("LR   : 0x%s\n", Long.toHexString(lr));

                    // 如果想查看准备拷贝的具体数据内容：
                    if (size > 0 && srcPtr != null) {
                        try {
                            // 防止 size 过大，最多打印 1024 字节看看长什么样
                            int printSize = (int) Math.min(size, 1024);
                            byte[] srcData = srcPtr.getByteArray(0, (int) printSize);
                            // 打印漂亮的 Hex Dump
                            Inspector.inspect(srcData, "Source Data (Ready to copy)");
                        } catch (Exception e) {
                            System.out.println("Failed to read memory at src pointer.");
                        }
                    }
                }
            });
        }
    }

    public void hook() {
        Debugger debugger = emulator.attach();
        // S1 -> BASE64
        debugger.addBreakPoint(module.base + 0x7329F4);
        // S1 -> SHA
//        debugger.addBreakPoint(module.base + 0x72436C);
    }

    /**
     * Hook S-Box 变换: 捕获 hex字符 → output nibble 的映射
     * <p>
     * 关键地址:
     * 0x712640: ldrb w8, [x11, x10] — 从hex缓冲区读取ASCII字符 (x10=offset, x11=0x130c0000)
     * 0x70df3c: strb w8, [x10, x9] — 写入output nibble (x9=offset, x10=0x130c0000)
     * <p>
     * hex缓冲区区间: offset 0x16ec0-0x16ecf (hex编码的SHA字符串)
     * output区间:     offset 0x16fb0-0x16fbf (S-Box替换后的nibble)
     * <p>
     * 注意: 同一条strb指令用于多个阶段(hex编码写入 + output写入)，靠offset区分
     */
    public void hookSBox() {
        Debugger debugger = emulator.attach();

        // S-Box 映射表: hex_digit_value (0-15) → output_nibble
        final int[] sbox = new int[16];
        Arrays.fill(sbox, -1); // -1 = 未知

        // 跟踪状态
        final List<Integer> hexCharsRead = new ArrayList<>();   // 从hex缓冲区读取的字符
        final List<Integer> outputNibbles = new ArrayList<>();  // 写入的output nibbles

        // Hook 1: ldrb w8, [x11, x10] at 0x712640 — 读取hex缓冲区
        debugger.addBreakPoint(module.base + 0x712640, (emulator, address) -> {
            Backend backend = emulator.getBackend();
            long x10 = backend.reg_read(Arm64Const.UC_ARM64_REG_X10).longValue();
            long x11 = backend.reg_read(Arm64Const.UC_ARM64_REG_X11).longValue();

            // 只关注从hex缓冲区读取 (offset 0x16ec0-0x16ecf)
            if (x11 == 0x130c0000L && x10 >= 0x16ec0L && x10 <= 0x16ecfL) {
                // 读取内存中的hex字符
                UnidbgPointer ptr = UnidbgPointer.pointer(emulator, x11 + x10);
                int hexChar = ptr.getByte(0) & 0xFF;
                int position = (int) (x10 - 0x16ec0L);

                hexCharsRead.add(hexChar);
                System.out.printf("[S-Box] READ  hex_buf[%d] = 0x%02x '%c'\n",
                        position, hexChar, (char) hexChar);
            }
            return true; // 继续执行
        });

        // Hook 2: strb w8, [x10, x9] at 0x70df3c — 写入output nibble
        debugger.addBreakPoint(module.base + 0x70df3c, (emulator, address) -> {
            Backend backend = emulator.getBackend();
            long w8 = backend.reg_read(Arm64Const.UC_ARM64_REG_W8).longValue() & 0xFFL;
            long x9 = backend.reg_read(Arm64Const.UC_ARM64_REG_X9).longValue();
            long x10 = backend.reg_read(Arm64Const.UC_ARM64_REG_X10).longValue();

            // 只关注output区间 (offset 0x16fb0-0x16fbf)
            if (x10 == 0x130c0000L && x9 >= 0x16fb0L && x9 <= 0x16fbfL) {
                int position = (int) (x9 - 0x16fb0L);
                int nibble = (int) w8;
                outputNibbles.add(nibble);

                // 对应的hex字符 (按顺序匹配)
                int idx = outputNibbles.size() - 1;
                if (idx < hexCharsRead.size()) {
                    int hexChar = hexCharsRead.get(idx);
                    int hexValue = Character.digit((char) hexChar, 16);

                    System.out.printf("[S-Box] WRITE output[%d] = 0x%x  ←  '%c' (0x%x)\n",
                            position, nibble, (char) hexChar, hexValue);

                    // 记录到S-Box
                    if (hexValue >= 0 && hexValue <= 15) {
                        sbox[hexValue] = nibble;
                    }
                } else {
                    System.out.printf("[S-Box] WRITE output[%d] = 0x%x\n", position, nibble);
                }

                // 每处理完16个nibble，打印当前S-Box状态
                if (outputNibbles.size() % 16 == 0) {
                    printSBox(sbox);
                    hexCharsRead.clear();
                    outputNibbles.clear();
                }
            }
            return true;
        });
    }

    private void printSBox(int[] sbox) {
        System.out.println("\n========== S-Box 当前状态 ==========");
        System.out.print("输入:  ");
        for (int i = 0; i < 16; i++) System.out.printf("%2x ", i);
        System.out.print("\n输出:  ");
        for (int i = 0; i < 16; i++) {
            if (sbox[i] == -1) System.out.print(" ? ");
            else System.out.printf("%2x ", sbox[i]);
        }

        // 检查完整性
        int known = 0;
        for (int v : sbox) if (v != -1) known++;
        System.out.printf("\n已确认: %d/16", known);

        if (known == 16) {
            System.out.print("\n\n完整S-Box (Python): SBOX = [");
            for (int i = 0; i < 16; i++) {
                System.out.printf("0x%x", sbox[i]);
                if (i < 15) System.out.print(", ");
            }
            System.out.println("]");
        }
        System.out.println("\n====================================");
    }

    /**
     * Dump srand/rand values for multiple seeds via PLT stubs in libtiny.so
     */
    public void dumpRand() {
        // Use PLT stubs in libtiny.so (properly resolved to libc)
        long srandPlt = module.base + 0x7337c0;  // srand PLT
        long randPlt = module.base + 0x733090;    // rand PLT

        for (int seed = 0; seed <= 5; seed++) {
            module.callFunction(emulator, srandPlt, seed);
            StringBuilder sb = new StringBuilder();
            sb.append(String.format("srand(%d):", seed));
            for (int i = 0; i < 10; i++) {
                Number result = module.callFunction(emulator, randPlt);
                sb.append(String.format(" 0x%08x", result.longValue() & 0xFFFFFFFFL));
            }
            System.out.println(sb);
        }
    }

    /**
     * Determine exact Fisher-Yates variant by fixing seed and capturing swap details
     */
    public void hookPRNG() {
        Debugger debugger = emulator.attach();
        AtomicInteger srandCount = new AtomicInteger(0);
        AtomicInteger randPerRound = new AtomicInteger(0);

        // Hook srand - override seed to 0
        debugger.addBreakPoint(module.base + 0x7337c0, (emulator, address) -> {
            Backend backend = emulator.getBackend();
            long x0 = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue() & 0xFFFFFFFFL;
            int round = srandCount.getAndIncrement();
            randPerRound.set(0);
            System.out.printf("[S] R%d srand(%d)%n", round, x0);
            backend.reg_write(Arm64Const.UC_ARM64_REG_X0, 0);
            return true;
        });

        // Hook rand return
        debugger.addBreakPoint(module.base + 0x66cc5c, (emulator, address) -> {
            long w0 = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W0).longValue() & 0xFFFFFFFFL;
            int r = srandCount.get() - 1;
            int i = randPerRound.getAndIncrement();
            System.out.printf("[S] R%d rand#%d=0x%08x%n", r, i, w0);
            return true;
        });

        // Hook sdiv at 0x713120: sdiv w11, w10, w9 — capture dividend AND divisor
        debugger.addBreakPoint(module.base + 0x713120, (emulator, address) -> {
            Backend backend = emulator.getBackend();
            long w10 = backend.reg_read(Arm64Const.UC_ARM64_REG_W10).longValue() & 0xFFFFFFFFL;
            long w9 = backend.reg_read(Arm64Const.UC_ARM64_REG_W9).longValue() & 0xFFFFFFFFL;
            long rem = w10 % w9;
            System.out.printf("[S] sdiv 0x%x / %d = rem %d%n", w10, w9, rem);
            return true;
        });

        // Hook VM_REG writes R8-R15 — only print 1-digit values (the final digits)
        debugger.addBreakPoint(module.base + 0x7105f8, (emulator, address) -> {
            int regIdx = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W8).intValue();
            int value = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W9).intValue();
            if (regIdx >= 8 && regIdx <= 15 && value >= 1 && value <= 9) {
                System.out.printf("[S] REG[%d]=%d%n", regIdx, value);
            }
            return true;
        });

        // Hook swap stores at 0x70dd90 and 0x70ddbc — the actual Fisher-Yates swaps
        debugger.addBreakPoint(module.base + 0x70dd90, (emulator, address) -> {
            Backend backend = emulator.getBackend();
            int w11 = backend.reg_read(Arm64Const.UC_ARM64_REG_W11).intValue();
            long x9 = backend.reg_read(Arm64Const.UC_ARM64_REG_X9).longValue();
            // Only print single-digit values (1-9) — the digit swaps
            if (w11 >= 1 && w11 <= 9) {
                System.out.printf("[S] SWAP_A [0x%x]=%d%n", x9, w11);
            }
            return true;
        });
        debugger.addBreakPoint(module.base + 0x70ddbc, (emulator, address) -> {
            Backend backend = emulator.getBackend();
            int w11 = backend.reg_read(Arm64Const.UC_ARM64_REG_W11).intValue();
            long x10 = backend.reg_read(Arm64Const.UC_ARM64_REG_X10).longValue();
            if (w11 >= 1 && w11 <= 9) {
                System.out.printf("[S] SWAP_B [0x%x]=%d%n", x10, w11);
            }
            return true;
        });

        // Hook target stores
        debugger.addBreakPoint(module.base + 0x70df3c, (emulator, address) -> {
            long w8 = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W8).longValue() & 0xFFL;
            long x9 = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_X9).longValue();
            if (x9 >= 0x16ebcL && x9 <= 0x16ebfL) {
                System.out.printf("[S] STORE [0x%x]=0x%02x(%d)%n", x9, w8, w8);
            }
            return true;
        });
    }

    public void hookCrc32() {
        Debugger debugger = emulator.attach();

        // Track CRC32 state
        final long[] crcState = {0};           // current CRC value
        final boolean[] inCrc = {false};       // whether we're inside a CRC32 computation
        final List<Integer> inputBytes = new ArrayList<>();
        final AtomicInteger eorCount = new AtomicInteger(0);

        // Hook: CRC init value load — ldr w8, [x22, w8, uxtw #2] at 0x711498
        // When this loads 0xFFFFFFFF, a new CRC32 computation starts
        debugger.addBreakPoint(module.base + 0x711498, (emulator, address) -> {
            // Read result after instruction executes — check at next instruction
            return true;
        });

        // Hook: eor w8, w9, w8 at 0x7110b8 — the core CRC32 XOR operation
        debugger.addBreakPoint(module.base + 0x7110b8, (emulator, address) -> {
            Backend backend = emulator.getBackend();
            long w9 = backend.reg_read(Arm64Const.UC_ARM64_REG_W9).longValue() & 0xFFFFFFFFL;
            long w8 = backend.reg_read(Arm64Const.UC_ARM64_REG_W8).longValue() & 0xFFFFFFFFL;
            long pc = backend.reg_read(Arm64Const.UC_ARM64_REG_PC).longValue() & 0xFFFFFFFFL;

            // Detect CRC32 init: byte ^ 0xFFFFFFFF (first XOR of a new computation)
            if (w8 == 0xFFFFFFFFL && w9 <= 0xFF) {
                inCrc[0] = true;
                inputBytes.clear();
                eorCount.set(0);
                crcState[0] = 0xFFFFFFFFL;
                inputBytes.add((int) w9);
                System.out.println("\n===== CRC32 START =====");
                this.traceStream.println("===== CRC32 START =====");
                System.out.println("  PC: 0x" + Long.toHexString(pc));
                System.out.printf("  Init CRC=0xFFFFFFFF, first byte=0x%02x%n", w9);
            }
            // Detect final inversion: crc ^ 0xFFFFFFFF (w8=0xFFFFFFFF, w9=final crc)
            else if (w8 == 0xFFFFFFFFL && w9 > 0xFF && inCrc[0]) {
                long result = (w9 ^ 0xFFFFFFFFL) & 0xFFFFFFFFL;
                System.out.println("===== CRC32 END =====");
                this.traceStream.println("===== CRC32 END =====");
                System.out.printf("  CRC before invert: 0x%08x%n", w9);
                System.out.printf("  CRC32 result:      0x%08x%n", result);
                System.out.printf("  Input length:      %d bytes%n", inputBytes.size());

                // Print input bytes hex dump
                byte[] data = new byte[inputBytes.size()];
                for (int i = 0; i < inputBytes.size(); i++) {
                    data[i] = inputBytes.get(i).byteValue();
                }
                System.out.printf("  Input hex:         %s%n", bytesToHex(data));
                Inspector.inspect(data, "CRC32 Input (" + data.length + " bytes)");

                inCrc[0] = false;
            }
            // Inside CRC32: byte XOR step — w9 is byte (<=0xFF), w8 is current CRC
            else if (inCrc[0] && w9 <= 0xFF && w8 > 0xFFFF) {
                inputBytes.add((int) w9);
                if ((int) w9 == 0x2b) {
                    traceStream.printf("\n===== CRC32 POINT ======");
                }
            }

            return true;
        });
    }

    public void trace() {
        //核心 trace 开启代码，也可以自己指定函数地址和偏移量
        emulator.traceCode(module.base, module.base + module.size).setRedirect(traceStream);
    }

    @Override
    public long callLongMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "java/lang/Long->longValue()J":
                return (Long) dvmObject.getValue();
            case "android/os/BatteryManager->getLongProperty(Lint;)Ljava/lang/Object;":
                // 剩余电量(微安时)
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
                return false;
            default:
                return super.callBooleanMethodV(vm, dvmObject, signature, vaList);
        }
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "android/content/Context->getSystemService(Ljava/lang/String;)Ljava/lang/Object;": {
                String arg = (String) vaList.getObjectArg(0).getValue();
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
            case "android/telephony/TelephonyManager->getNetworkCountryIso()Ljava/lang/Object;": {
                return new StringObject(vm, "CN");
            }
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
                return 999999L;
            case "android/content/pm/PackageInfo->lastUpdateTime:J":
//                return System.currentTimeMillis();
                return 888888L;
        }
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public boolean callStaticBooleanMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "android/app/ActivityManager->isUserAMonkey()Z":
                return true;
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
                switch (vaList.getIntArg(0)) {
                    case 1428086509:
                        // 返回6个MMKV native函数指针
                        System.out.println("[t.b] tag=1428086509 → returning MMKV function pointers");
                        return new LongArray(vm, mmkvFuncPtrs);
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
                            DvmField dvmField = new DvmField(clazz, name, null, false);
                            DvmObject<?> result = vm.resolveClass("java/lang/reflect/Field").newObject(dvmField);
                            clazz.setFieldId(result.hashCode(), dvmField);
                            return result;
                        } else {
                            // 获取 Method
                            DvmObject<?>[] signatureArgs = (DvmObject<?>[]) signatureObj.getValue();
                            StringBuilder methodSignature = new StringBuilder("(");
                            for (DvmObject<?> signatureArg : signatureArgs) {
                                if (signatureArg.getValue().getClass() == String.class) {
                                    methodSignature.append("L")
                                            .append(signatureArg.getValue().getClass().getName().replaceAll("\\.", "/"))
                                            .append(";");
                                } else {
                                    methodSignature.append(signatureArg.getValue().getClass().getName());
                                }
                            }
                            methodSignature.append(")Ljava/lang/Object;");
                            DvmMethod dvmMethod = new DvmMethod(clazz, name, methodSignature.toString(), true);
                            DvmObject<?> result = vm.resolveClass("java/lang/reflect/Method").newObject(dvmMethod);
                            clazz.setMethodID(result.hashCode(), dvmMethod);
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

                        DvmMethod dvmMethod = new DvmMethod(clazz, name, methodSignature.toString(), true);
                        DvmObject<?> result = vm.resolveClass("java/lang/reflect/Method").newObject(dvmMethod);
                        clazz.setMethodID(result.hashCode(), dvmMethod);
                        return result;
                    }
                    case -2126679615:
                        return new StringObject(vm, "1080,2280,440");
                    case -1268893863:
                        return vm.resolveClass("android/content/Intent").newObject(vm);
                    case -1120247918:
                        return new StringObject(vm, "wifi");
                    case 1798473208:
                        // Tag 0x6B2FBB68: 安全检测 (sub_51F9E4)
                        // 返回一个空数组表示无安全事件
                        System.out.println("[JNI] tag 1798473208 (0x6B2FBB68) security detection, returning empty array");
                        return new ArrayObject();
                    case -118611111:
                        // Tag 0xF8EE2359: returns Float (battery temp or sensor), used in "t" field generation
                        System.out.println("[JNI] tag -118611111 (0xF8EE2359) called, returning null");
                        return null;
                    case -86480061: {
                        // 反射获取静态字段值: Field.get(null)
                        // objArr[0] = 类名(String) 或 Class, objArr[1] = 字段名(String)
                        ArrayObject arrayObject = vaList.getObjectArg(1);
                        DvmObject<?> classObj = arrayObject.getValue()[0];
                        String fieldName = (String) arrayObject.getValue()[1].getValue();

                        String className;
                        if (classObj instanceof DvmClass) {
                            className = ((DvmClass) classObj).getClassName();
                        } else {
                            className = ((String) classObj.getValue()).replaceAll("\\.", "/");
                        }

                        String fieldKey = className + "->" + fieldName;
                        switch (fieldKey) {
                            case "android/os/Build->TIME":
                                return DvmLong.valueOf(vm, 1700000000000L);
                            case "Version->SDK_INT":
                            case "android/os/Build$Version->SDK_INT":
                                return DvmInteger.valueOf(vm, 33);
                            default:
                                System.out.println("[JNI] case -86480061: unhandled field " + fieldKey);
                                return null;
                        }
                    }
                    case 1124881467:
                        return new StringObject(vm, "com.xingin.xhs");
                    default:
                        System.out.println("[JNI] unknown call self tag: " + vaList.getIntArg(0));
                        return null;
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
                if (arg1.equals("screen_brightness")) {
                    return 123456;
                } else if (arg1.equals("screen_brightness_mode")) {
                    return 123457;
                }
            }
            case "android/provider/Settings$Secure->getInt(Landroid/content/ContentResolver;Ljava/lang/String;)I": {
                String arg1 = (String) vaList.getObjectArg(1).getValue();
                if (arg1.equals("accessibility_enabled")) {
                    return 123458;
                } else if (arg1.equals("location_mode")) {
                    return 123459;
                }
            }
            case "android/provider/Settings$Global->getInt(Landroid/content/ContentResolver;Ljava/lang/String;)I": {
                String arg1 = (String) vaList.getObjectArg(1).getValue();
                if (arg1.equals("adb_enabled")) {
                    return 123460;
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

    public void sig(String pad) {
        DvmObject<?> result = a(
                -1754486979,
                "GET",
                "edith.xiaohongshu.com",
                "/api/sns/v3/note/guide/callback",
                "ug_role=-1" + pad,
//                "testtest".getBytes(StandardCharsets.UTF_8)
                null
        );
//        Map mapResult = (Map) result.getValue();
//        System.out.println("mapResult:" + mapResult);
    }

    public void init1() {
        a(-934400877, 10000L);
    }

    public void init2() {
        a(-117791318);
    }

    public void init3() {
        a(1039552848,
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
    }

    /**
     * 读取b_addr文件，对每个br/blr地址设置断点，记录实际跳转目标
     * 输出格式: offset;目标地址;指令类型;模块名;符号名
     */
    public void hookBAddr(String inputPath, String outputPath) throws IOException {
        this.bAddrOutputPath = outputPath;
        List<String> lines = Files.readAllLines(Paths.get(inputPath));
        Debugger debugger = emulator.attach();
        long base = module.base;

        int count = 0;
        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty()) continue;
            String[] parts = line.split(";");
            if (parts.length < 3) continue;

            String offsetStr = parts[0].trim();
            String reg = parts[1].trim();
            String insn = parts[2].trim();
            long offset = Long.parseLong(offsetStr.substring(2), 16); // 去掉0x前缀

            int regConst = regNameToArm64Const(reg);
            if (regConst == -1) {
                System.err.println("[-] Unknown register: " + reg + " at " + offsetStr);
                continue;
            }

            final String fOffsetStr = offsetStr;
            final String fInsn = insn;

            debugger.addBreakPoint(base + offset, (emu, addr) -> {
                Backend backend = emu.getBackend();
                long regValue = backend.reg_read(regConst).longValue();

                // 查找目标地址所属模块
                Module targetModule = emu.getMemory().findModuleByAddress(regValue);
                String moduleName;
                String symbolName = "";
                String targetOffsetHex;

                if (targetModule != null) {
                    moduleName = targetModule.name;
                    // 输出SO内偏移，而非绝对地址，与IDA地址对齐
                    long targetOffset = regValue - targetModule.base;
                    targetOffsetHex = "0x" + Long.toHexString(targetOffset);
                    com.github.unidbg.Symbol sym = targetModule.findClosestSymbolByAddress(regValue, true);
                    if (sym != null) {
                        symbolName = sym.getName();
                    }
                } else {
                    moduleName = "no pointerModule";
                    targetOffsetHex = "0x" + Long.toHexString(regValue);
                }

                String result = fOffsetStr + ";" + targetOffsetHex + ";" + fInsn + ";" + moduleName + ";" + symbolName;

                // 用Set去重，同一个地址可能多次命中但跳转目标不同
                bAddrResults.computeIfAbsent(fOffsetStr, k -> new LinkedHashSet<>()).add(result);

                return true; // 继续执行
            });
            count++;
        }
        System.out.println("[get_b_addr] Hooked " + count + " addresses from " + inputPath);
    }

    /**
     * 执行完毕后，将结果写入文件
     */
    public void flushBAddrResult() throws FileNotFoundException {
        if (bAddrOutputPath == null) return;

        try (PrintStream ps = new PrintStream(new FileOutputStream(bAddrOutputPath), true)) {
            int totalLines = 0;
            for (Map.Entry<String, Set<String>> entry : bAddrResults.entrySet()) {
                for (String line : entry.getValue()) {
                    ps.println(line);
                    totalLines++;
                }
            }
            System.out.println("[get_b_addr] Wrote " + totalLines + " results to " + bAddrOutputPath);
        }
    }

}
