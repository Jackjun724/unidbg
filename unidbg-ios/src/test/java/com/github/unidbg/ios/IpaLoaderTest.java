package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.backend.HypervisorFactory;
import com.github.unidbg.debugger.DebugRunnable;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.ios.classdump.ClassDumper;
import com.github.unidbg.ios.classdump.IClassDumper;
import com.github.unidbg.ios.ipa.EmulatorConfigurator;
import com.github.unidbg.ios.ipa.IpaLoader;
import com.github.unidbg.ios.ipa.IpaLoader64;
import com.github.unidbg.ios.ipa.LoadedIpa;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;

import java.io.File;

public class IpaLoaderTest implements EmulatorConfigurator, DebugRunnable<Void> {

    private Emulator<?> emulator;
    private Module module;

    public void testLoader() throws Exception {
        long start = System.currentTimeMillis();
        File ipa = new File("unidbg-ios/src/test/resources/app/TelegramMessenger-5.11.ipa");
        if (!ipa.canRead()) {
            ipa = new File("src/test/resources/app/TelegramMessenger-5.11.ipa");
        }
        IpaLoader ipaLoader = new IpaLoader64(ipa, new File("target/rootfs/ipa"));
        ipaLoader.addBackendFactory(new HypervisorFactory(true));
        ipaLoader.addBackendFactory(new DynarmicFactory(true));
        LoadedIpa loader = ipaLoader.load(this);
        emulator = loader.getEmulator();
        System.err.println("load offset=" + (System.currentTimeMillis() - start) + "ms");
        loader.callEntry();
        module = loader.getExecutable();

        Debugger debugger = emulator.attach();
        debugger.addMcpTool("dumpClass", "Dump an ObjC class definition by name", "className");
        debugger.addMcpTool("readVersion", "Read the TelegramCoreVersionString from the executable");
        debugger.run(this);
        emulator.close();
    }

    @Override
    public Void runWithArgs(String[] args) {
        String toolName = args != null ? args[0] : null;
        if ("dumpClass".equals(toolName)) {
            String className = args.length > 1 ? args[1] : "AppDelegate";
            IClassDumper classDumper = ClassDumper.getInstance(emulator);
            String classData = classDumper.dumpClass(className);
            System.out.println("dumpClass(" + className + "):\n" + classData);
        } else if ("readVersion".equals(toolName)) {
            Symbol sym = module.findSymbolByName("_TelegramCoreVersionString");
            if (sym != null) {
                Pointer pointer = UnidbgPointer.pointer(emulator, sym.getAddress());
                if (pointer != null) {
                    System.out.println("_TelegramCoreVersionString=" + pointer.getString(0));
                }
            } else {
                System.out.println("Symbol _TelegramCoreVersionString not found");
            }
        } else {
            IClassDumper classDumper = ClassDumper.getInstance(emulator);
            String classData = classDumper.dumpClass("AppDelegate");
            System.out.println("dumpClass(AppDelegate):\n" + classData);

            Symbol sym = module.findSymbolByName("_TelegramCoreVersionString");
            if (sym != null) {
                Pointer pointer = UnidbgPointer.pointer(emulator, sym.getAddress());
                if (pointer != null) {
                    System.out.println("_TelegramCoreVersionString=" + pointer.getString(0));
                }
            }
        }
        return null;
    }

    public static void main(String[] args) throws Exception {
        IpaLoaderTest test = new IpaLoaderTest();
        test.testLoader();
    }

    @Override
    public void configure(Emulator<DarwinFileIO> emulator, String executableBundlePath, File rootDir, String bundleIdentifier) {
    }

    @Override
    public void onExecutableLoaded(Emulator<DarwinFileIO> emulator, MachOModule executable) {
    }
}
