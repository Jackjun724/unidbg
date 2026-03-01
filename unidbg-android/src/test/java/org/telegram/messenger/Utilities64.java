package org.telegram.messenger;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.backend.HypervisorFactory;
import com.github.unidbg.arm.backend.KvmFactory;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.debugger.DebugRunnable;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.android.dvm.jni.ProxyClassFactory;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.utils.Inspector;
import com.github.unidbg.virtualmodule.android.AndroidModule;
import com.github.unidbg.virtualmodule.android.JniGraphics;
import junit.framework.TestCase;

import java.io.File;
import java.io.IOException;

/**
 * mvn test -Dmaven.test.skip=false -Dtest=org.telegram.messenger.Utilities64
 */
public class Utilities64 extends TestCase implements DebugRunnable<Void> {

    private static LibraryResolver createLibraryResolver() {
        return new AndroidResolver(23);
    }

    private static AndroidEmulator createARMEmulator() {
        return AndroidEmulatorBuilder
                .for64Bit()
                .setProcessName("org.telegram.messenger")
                .addBackendFactory(new HypervisorFactory(true))
                .addBackendFactory(new DynarmicFactory(true))
                .addBackendFactory(new KvmFactory(true))
                .addBackendFactory(new Unicorn2Factory(true))
                .build();
    }

    private final AndroidEmulator emulator;
    private final VM vm;

    private final DvmClass cUtilities;

    public Utilities64() {
        emulator = createARMEmulator();
        final Memory memory = emulator.getMemory();
        memory.setLibraryResolver(createLibraryResolver());

        vm = emulator.createDalvikVM();
        vm.setDvmClassFactory(new ProxyClassFactory());
        Module module = new JniGraphics(emulator, vm).register(memory);
        assert module != null;
        new AndroidModule(emulator, vm).register(memory);

        System.out.println("backend=" + emulator.getBackend());
        vm.setVerbose(true);
        File file = new File("src/test/resources/example_binaries/arm64-v8a/libtmessages.29.so");
        DalvikModule dm = vm.loadLibrary(file.canRead() ? file : new File("unidbg-android/src/test/resources/example_binaries/arm64-v8a/libtmessages.29.so"), true);
        dm.callJNI_OnLoad(emulator);

        cUtilities = vm.resolveClass("org/telegram/messenger/Utilities");
    }

    private void destroy() throws IOException {
        emulator.close();
        System.out.println("destroy");
    }

    public void test() throws Exception {
        this.aesCbcEncryptionByteArray();
        this.aesCtrDecryptionByteArray();
        this.pbkdf2();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();

        destroy();
    }

    @Override
    public Void runWithArgs(String[] args) {
        String toolName = args != null ? args[0] : null;
        if ("aesCbc".equals(toolName)) {
            byte[] input = args.length > 1 ? args[1].getBytes() : new byte[16];
            aesCbcEncryptionByteArray(input);
        } else if ("aesCtr".equals(toolName)) {
            byte[] input = args.length > 1 ? args[1].getBytes() : new byte[16];
            aesCtrDecryptionByteArray(input);
        } else if ("pbkdf2".equals(toolName)) {
            String password = args.length > 1 ? args[1] : "123456";
            int iterations = args.length > 2 ? Integer.parseInt(args[2]) : 100000;
            pbkdf2(password.getBytes(), iterations);
        } else {
            aesCbcEncryptionByteArray(new byte[16]);
            aesCtrDecryptionByteArray(new byte[16]);
            pbkdf2("123456".getBytes(), 100000);
        }
        return null;
    }

    private void runArgs() throws Exception {
        Debugger debugger = emulator.attach();
        debugger.addMcpTool("aesCbc", "Run AES-CBC encryption on input data", "input");
        debugger.addMcpTool("aesCtr", "Run AES-CTR decryption on input data", "input");
        debugger.addMcpTool("pbkdf2", "Run PBKDF2 key derivation", "password", "iterations");
        debugger.run(this);
    }

    public static void main(String[] args) throws Exception {
        final Utilities64 test = new Utilities64();

        Thread thread = new Thread(test::pbkdf2);
        thread.start();
        thread.join();

        test.aesCbcEncryptionByteArray();
        test.aesCtrDecryptionByteArray();
        test.pbkdf2();

        test.runArgs();

        test.destroy();
    }

    private void aesCbcEncryptionByteArray() {
        aesCbcEncryptionByteArray(new byte[16]);
    }

    private void aesCbcEncryptionByteArray(byte[] input) {
        long start = System.currentTimeMillis();
        ByteArray data = new ByteArray(vm, input);
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        cUtilities.callStaticJniMethod(emulator, "aesCbcEncryptionByteArray([B[B[BIIII)V", data,
                key,
                iv,
                0, data.length(), 0, 0);
        Inspector.inspect(data.getValue(), "aesCbcEncryptionByteArray offset=" + (System.currentTimeMillis() - start) + "ms");
    }

    private void aesCtrDecryptionByteArray() {
        aesCtrDecryptionByteArray(new byte[16]);
    }

    private void aesCtrDecryptionByteArray(byte[] input) {
        long start = System.currentTimeMillis();
        ByteArray data = new ByteArray(vm, input);
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        cUtilities.callStaticJniMethod(emulator, "aesCtrDecryptionByteArray([B[B[BIII)V", data,
                key,
                iv,
                0, data.length(), 0);
        Inspector.inspect(data.getValue(), "[" + emulator.getBackend() + "]aesCtrDecryptionByteArray offset=" + (System.currentTimeMillis() - start) + "ms");
    }

    private void pbkdf2() {
        pbkdf2("123456".getBytes(), 100000);
    }

    private void pbkdf2(byte[] password, int iterations) {
        byte[] salt = new byte[8];
        ByteArray dst = new ByteArray(vm, new byte[64]);
        long start = System.currentTimeMillis();
        cUtilities.callStaticJniMethod(emulator, "pbkdf2([B[B[BI)V", password,
                salt,
                dst, iterations);
        Inspector.inspect(dst.getValue(), String.format("[%s]pbkdf2 offset=%sms, backend=%s", Thread.currentThread().getName(), System.currentTimeMillis() - start, emulator.getBackend()));
    }

}
