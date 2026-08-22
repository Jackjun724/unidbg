package com.xhs;

import capstone.Arm64_const;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.utils.Inspector;
import com.github.unidbg.virtualmodule.android.AndroidModule;
import com.github.unidbg.virtualmodule.android.JniGraphics;
import com.github.unidbg.virtualmodule.android.MediaNdkModule;
import com.github.unidbg.virtualmodule.android.SystemProperties;
import okhttp3.*;
import okio.Buffer;
import okio.BufferedSink;
import org.apache.commons.codec.binary.Base64;

import java.io.*;
import java.nio.charset.Charset;

public class Xhs921Shield extends AbstractJni implements IOResolver {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;
    public long num;
    public DvmClass xhsNative;
    public DvmObject<?> xhshttpinterceptorObject;
    private Request request;
    private String url;
    private String deviceId;
    private String hmac;

    Xhs921Shield(String deviceId, String hmac) {
        this.deviceId = deviceId;
        this.hmac = hmac;
        // 创建模拟器实例
        emulator = AndroidEmulatorBuilder.for64Bit().setProcessName("com.xingin.xhs").addBackendFactory(new Unicorn2Factory(false)).build();
        emulator.getSyscallHandler().addIOResolver(this);
        // 获取模拟器的内存操作接口
        final Memory memory = emulator.getMemory();
        // 设置系统类库解析
        memory.setLibraryResolver(new AndroidResolver(23));
        // 创建Android虚拟机,传入APK，Unidbg可以替我们做部分签名校验的工作
        vm = emulator.createDalvikVM(new File("unidbg-android/src/test/resources/xiaohongshu.apk"));
        // 4个虚拟模块
        new AndroidModule(emulator, vm);
        new MediaNdkModule(emulator, vm);
        new JniGraphics(emulator, vm);
        new SystemProperties(emulator, null);
        // 设置JNI
        vm.setJni(this);
        // 打印日志
        vm.setVerbose(false);
        // 加载目标SO
        DalvikModule dm = vm.loadLibrary("xyass", true);
        //获取本SO模块的句柄,后续需要用它
        module = dm.getModule();
        dm.callJNI_OnLoad(emulator);
        xhsNative = vm.resolveClass("com/xingin/shield/http/Native");

        url = "https://rec.xiaohongshu.com/api/sns/v1/followings/reddot?isStartUp=false";
        request = new Request.Builder()
                .url(url)
                .addHeader("xy-direction", "69")
                .addHeader("xy-scene", "fs=0&point=3019")
                .addHeader("xy-common-params", "fid=&gid=7cbab264fb2d549589ed3bb00dcd73c0b9aae20947359b9177d43ef6&device_model=phone&tz=America%2FNew_York&channel=JTdCJTdE&versionName=9.21.0&deviceId=c9cdb5b0-a9e9-361b-baa3-daf23ea927d7&platform=android&sid=session.1775219135513939616235&identifier_flag=4&cpu_abi=arm64-v8a&nqe_score=91&project_id=ECFAAF&x_trace_page_current=welcome_page&lang=zh-Hans&app_id=ECFAAF01&uis=light&teenager=0&active_ctry=CN&cpu_name=Qualcomm+Technologies%2C+Inc+SM8150&dlang=zh&data_ctry=CN&SUE=1&launch_id=1775250326&id_token=VjEAAO%2F3DhnXYfkcszLc5l3fQl%2B3%2Fz%2F5cddCCMIGmuzVIseipOQiGCoikxmrE7rS2c%2BbhrcMWTFDh6R3Lin9WPaw6SFNC98wXb%2F0CCgXfM1mC4ZOSEhnxs8ko6bygW%2FRJEZyzkKu&device_level=4&origin_channel=JTdCJTdE&overseas_channel=0&mlanguage=zh_cn&folder_type=none&auto_trans=0&t=1775286738&build=9210803&holder_ctry=CN&did=1dfba70e48e5ec95edfa093c4e16d8ce")
                .get()
                .build();
    }

    public static void main(String[] args) {
        Xhs921Shield demo = new Xhs921Shield(
                "c9cdb5b0-a9e9-361b-baa3-daf23ea927d7",
                "XSeQjYAIFBUENihTfXDg0uKh3jf78KvsdtrZexs9jUcz5bcDBDIEG2I0nx0E+y3yHGuOrFx8WkNzfUy5WrtZahGKMDL3p6Plk4hhN0TGxU2HXGzJRuxGRKBBjliBdaqQ"
        );
        // demo.trace();
        System.out.println("1");
        demo.callinitializeNative();
        System.out.println("2");
        demo.callinitialize();
        System.out.println("3");
        demo.callfun();

    }

    public FileResult resolve(Emulator emulator, String pathname, int oflags) {
        // System.out.println("open file:" + pathname);
        return null;
    }

    public void callinitializeNative() {
        xhsNative.callStaticJniMethod(emulator, "initializeNative()V");
    }

    public void callinitialize() {
        xhshttpinterceptorObject = xhsNative.newObject("xhs");
        num = xhshttpinterceptorObject.callJniMethodLong(emulator, "initialize(Ljava/lang/String;)J", "main");
        // System.out.println("num=======>" + num);
    }

    public void callfun() {
        DvmObject<?> chain = vm.resolveClass("okhttp3/Interceptor$Chain").newObject(null);

        xhshttpinterceptorObject.callJniMethodObject(emulator, "intercept(Lokhttp3/Interceptor$Chain;J)Lokhttp3/Response;", chain, num);

        String shield = request.headers().get("shield");
        System.out.println("shield:" + shield);

        // Dump shield raw bytes for analysis
        if (shield != null && shield.startsWith("XY")) {
            String b64Part = shield.substring(2);
            byte[] rawBytes = Base64.decodeBase64(b64Part);
            System.out.println("\n====== [SHIELD] Raw bytes analysis ======");
            System.out.println("[SHIELD] Total raw bytes: " + rawBytes.length);
            Inspector.inspect(rawBytes, "[SHIELD] Full raw shield bytes");

            // 解析 header (前16字节)
            if (rawBytes.length >= 16) {
                System.out.println("[SHIELD] Header bytes [0-3]:  " + String.format("%02x %02x %02x %02x", rawBytes[0], rawBytes[1], rawBytes[2], rawBytes[3]));
                System.out.println("[SHIELD] Header bytes [4-7]:  " + String.format("%02x %02x %02x %02x", rawBytes[4], rawBytes[5], rawBytes[6], rawBytes[7]));
                System.out.println("[SHIELD] Header bytes [8-11]: " + String.format("%02x %02x %02x %02x", rawBytes[8], rawBytes[9], rawBytes[10], rawBytes[11]));
                System.out.println("[SHIELD] Header bytes [12-15]:" + String.format("%02x %02x %02x %02x", rawBytes[12], rawBytes[13], rawBytes[14], rawBytes[15]));
                System.out.println("[SHIELD] Data portion length: " + (rawBytes.length - 16) + " bytes");
            }
        }

    }

    public void HookByConsoleDebugger() {
        Debugger debugger = emulator.attach();

        debugger.addBreakPoint(module.findSymbolByName("memcpy").getAddress(), (emulator, address) -> {
            RegisterContext context = emulator.getContext();
            int len = context.getIntArg(2);
            UnidbgPointer pointer1 = context.getPointerArg(0);
            UnidbgPointer pointer2 = context.getPointerArg(1);
            Inspector.inspect(pointer2.getByteArray(0, len), "dest " + Long.toHexString(pointer1.peer) + " src " + Long.toHexString(pointer2.peer));
            return true;
        });
    }

    public void trace() {
        String traceFile = "unidbg-android/src/test/java/com/xhs/trace_shield.txt";
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
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {
        switch (signature) {
            case "com/xingin/shield/http/ContextHolder->sLogger:Lcom/xingin/shield/http/ShieldLogger;": {
                return vm.resolveClass("com/xingin/shield/http/ShieldLogger").newObject(null);
            }
            case "com/xingin/shield/http/ContextHolder->sDeviceId:Ljava/lang/String;": {
                return new StringObject(vm, deviceId);
            }
        }
        return super.getStaticObjectField(vm, dvmClass, signature);
    }

    @Override
    public void callVoidMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "com/xingin/shield/http/ShieldLogger->nativeInitializeStart()V":
            case "com/xingin/shield/http/ShieldLogger->nativeInitializeEnd()V":
            case "com/xingin/shield/http/ShieldLogger->initializeStart()V":
            case "com/xingin/shield/http/ShieldLogger->initializedEnd()V":
            case "com/xingin/shield/http/ShieldLogger->buildSourceStart()V":
            case "com/xingin/shield/http/ShieldLogger->buildSourceEnd()V":
            case "com/xingin/shield/http/ShieldLogger->calculateStart()V":
            case "com/xingin/shield/http/ShieldLogger->calculateEnd()V": {
                return;
            }
            case "okhttp3/RequestBody->writeTo(Lokio/BufferedSink;)V": {
                BufferedSink bufferedSink = (BufferedSink) vaList.getObjectArg(0).getValue();
                RequestBody requestBody = (RequestBody) dvmObject.getValue();
                if (requestBody != null) {
                    try {
                        requestBody.writeTo(bufferedSink);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
                return;
            }
        }
        super.callVoidMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "java/nio/charset/Charset->defaultCharset()Ljava/nio/charset/Charset;": {
                return dvmClass.newObject(Charset.defaultCharset());
            }
            case "com/xingin/shield/http/Base64Helper->decode(Ljava/lang/String;)[B": {
                String input = vaList.getObjectArg(0).getValue().toString();
                return new ByteArray(vm, Base64.decodeBase64(input));
            }
        }
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public int getStaticIntField(BaseVM vm, DvmClass dvmClass, String signature) {
        switch (signature) {
            case "com/xingin/shield/http/ContextHolder->sAppId:I": {
                return -319115519;
            }
        }
        return super.getStaticIntField(vm, dvmClass, signature);
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "android/content/Context->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;": {
                return vm.resolveClass("android/content/SharedPreferences").newObject(vaList.getObjectArg(0).getValue().toString());
            }
            case "android/content/SharedPreferences->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;": {
                String fileName = dvmObject.getValue().toString();
                 System.out.println("fileName:" + fileName);
                if (fileName.equals("s")) {
                    String key = vaList.getObjectArg(0).getValue().toString();
                     System.out.println("key:" + key);
                    switch (key) {
                        case "main": {
                            return new StringObject(vm, "");
                        }
                        case "main_hmac": {
                            return new StringObject(vm, hmac);
                        }
                    }
                }
            }
            case "okhttp3/Interceptor$Chain->request()Lokhttp3/Request;": {
                return vm.resolveClass("okhttp3/Request").newObject(request);
            }
            case "okhttp3/Request->url()Lokhttp3/HttpUrl;": {
                return vm.resolveClass("okhttp3/HttpUrl").newObject(request.url());
            }
            case "okhttp3/HttpUrl->encodedPath()Ljava/lang/String;": {
                HttpUrl httpUrl = (HttpUrl) dvmObject.getValue();
                return new StringObject(vm, httpUrl.encodedPath());
            }
            case "okhttp3/HttpUrl->encodedQuery()Ljava/lang/String;": {
                HttpUrl httpUrl = (HttpUrl) dvmObject.getValue();
                return new StringObject(vm, httpUrl.encodedQuery());
            }
            case "okhttp3/Request->body()Lokhttp3/RequestBody;": {
                return vm.resolveClass("okhttp3/RequestBody").newObject(request.body());
            }
            case "okhttp3/Request->headers()Lokhttp3/Headers;": {
                return vm.resolveClass("okhttp3/Headers").newObject(request.headers());
            }
            case "okio/Buffer->writeString(Ljava/lang/String;Ljava/nio/charset/Charset;)Lokio/Buffer;": {
                Buffer buffer = (Buffer) dvmObject.getValue();
                buffer.writeString(vaList.getObjectArg(0).getValue().toString(), (Charset) vaList.getObjectArg(1).getValue());
                return dvmObject;
            }
            case "okhttp3/Headers->name(I)Ljava/lang/String;": {
                Headers headers = (Headers) dvmObject.getValue();
                return new StringObject(vm, headers.name(vaList.getIntArg(0)));
            }
            case "okhttp3/Headers->value(I)Ljava/lang/String;": {
                Headers headers = (Headers) dvmObject.getValue();
                return new StringObject(vm, headers.value(vaList.getIntArg(0)));
            }

            case "okio/Buffer->clone()Lokio/Buffer;": {
                Buffer buffer = (Buffer) dvmObject.getValue();
                return vm.resolveClass("okio/Buffer").newObject(buffer.clone());
            }
            case "okhttp3/Request->newBuilder()Lokhttp3/Request$Builder;": {
                return vm.resolveClass("okhttp3/Request$Builder").newObject(request.newBuilder());
            }
            case "okhttp3/Request$Builder->header(Ljava/lang/String;Ljava/lang/String;)Lokhttp3/Request$Builder;": {
                Request.Builder builder = (Request.Builder) dvmObject.getValue();
                builder.header(vaList.getObjectArg(0).getValue().toString(), vaList.getObjectArg(1).getValue().toString());
                return dvmObject;
            }
            case "okhttp3/Request$Builder->build()Lokhttp3/Request;": {
                Request.Builder builder = (Request.Builder) dvmObject.getValue();
                request = builder.build();
                return vm.resolveClass("okhttp3/Request").newObject(request);
            }
            case "okhttp3/Interceptor$Chain->proceed(Lokhttp3/Request;)Lokhttp3/Response;": {
                return vm.resolveClass("okhttp3/Response").newObject(null);
            }
        }
        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public DvmObject<?> newObjectV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "okio/Buffer-><init>()V": {
                return dvmClass.newObject(new Buffer());
            }
        }
        return super.newObjectV(vm, dvmClass, signature, vaList);
    }

    @Override
    public int callIntMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "okhttp3/Headers->size()I": {
                Headers headers = (Headers) dvmObject.getValue();
                return headers.size();
            }
            case "okio/Buffer->read([B)I": {
                Buffer buffer = (Buffer) dvmObject.getValue();
                return buffer.read((byte[]) vaList.getObjectArg(0).getValue());
            }
            case "okhttp3/Response->code()I": {
                return 200;
            }
        }
        return super.callIntMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public void callStaticVoidMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "com/xingin/shield/http/ContextHolder->writeLog(I)V":
                // 日志写入，直接忽略即可
                return;
            default:
                super.callStaticVoidMethodV(vm, dvmClass, signature, vaList);
        }
    }
}
