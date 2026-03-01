# unidbg

Allows you to emulate an Android native library, and an experimental iOS emulation.

This is an educational project to learn more about the ELF/MachO file format and ARM assembly.

Use it at your own risk !

## Features
- Emulation of the JNI Invocation API so JNI_OnLoad can be called.
- Support JavaVM, JNIEnv.
- Emulation of syscalls instruction.
- Support ARM32 and ARM64.
- Inline hook, thanks to [Dobby](https://github.com/jmpews/Dobby).
- Android import hook, thanks to [xHook](https://github.com/iqiyi/xHook).
- iOS [fishhook](https://github.com/facebook/fishhook) and substrate and [whale](https://github.com/asLody/whale) hook.
- [unicorn](https://github.com/zhkl0228/unicorn) backend support simple console debugger, gdb stub, instruction trace, memory read/write trace.
- Support iOS objc and swift runtime.
- Support [dynarmic](https://github.com/MerryMage/dynarmic) fast backend.
- Support Apple M1 hypervisor, the fastest ARM64 backend.
- Support Linux KVM backend with Raspberry Pi B4.
- Support [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) for AI-assisted debugging with Cursor and other AI tools.

## MCP Debugger (AI Integration)

unidbg supports [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) for AI-assisted debugging. When the debugger is active, type `mcp` in the console to start an MCP server that AI tools (e.g. Cursor) can connect to.

### Quick Start

unidbg MCP has two operating modes:

**Mode 1: Breakpoint Debug** — Attach the debugger and run your code. When a breakpoint is hit, `Breaker.debug()` pauses the emulator — type `mcp` in the console to start MCP server and let AI assist with analysis. All debugging tools are available (registers, memory, disassembly, stepping, tracing, etc). After resuming, if another breakpoint is hit the debugger pauses again. Once execution completes without hitting a breakpoint, the process exits and MCP shuts down.

```java
Debugger debugger = emulator.attach();
debugger.addBreakPoint(address);
// run your emulation logic — debugger pauses when breakpoint is hit
```

**Mode 2: Custom Tools (Repeatable)** — Register custom tools and implement `DebugRunnable` to let AI re-run target functions with different parameters. The native library is loaded once; after each execution the process stays alive and MCP remains active for the next run.

```java
Debugger debugger = emulator.attach();
debugger.addMcpTool("encrypt", "Run encryption", "input");
debugger.run(this); // implements DebugRunnable
```

When the debugger breaks, type `mcp` (or `mcp 9239` to specify port) in the console. Then add to Cursor MCP settings:

```json
{
  "mcpServers": {
    "unidbg": {
      "url": "http://localhost:9239/sse"
    }
  }
}
```

### Available MCP Tools

**Status & Info**

| Tool | Description |
|------|-------------|
| `check_connection` | Emulator status: Family, architecture, backend capabilities, isRunning, loaded modules |
| `list_modules` / `get_module_info` | List loaded modules, get detail including exported symbol count and dependencies |
| `list_exports` | List exported/dynamic symbols of a module with optional filter and C++ demangling |
| `find_symbol` | Find symbol by name or find nearest symbol at address |
| `get_threads` | List all threads/tasks in the emulator |

**Registers & Disassembly**

| Tool | Description |
|------|-------------|
| `get_registers` / `get_register` / `set_register` | Read/write CPU registers |
| `disassemble` | Disassemble instructions at address |
| `assemble` | Assemble instruction text to machine code |
| `get_callstack` | Get current call stack (backtrace) |

**Memory**

| Tool | Description |
|------|-------------|
| `read_memory` / `write_memory` | Read/write raw memory bytes |
| `read_string` / `read_std_string` | Read C string or C++ std::string (with SSO detection) |
| `read_pointer` | Read pointer chain with symbol resolution |
| `read_typed` | Read memory as typed values (int8–int64, float, double, pointer) |
| `search_memory` | Search memory for byte patterns with scope/permission filters |
| `list_memory_map` | List all memory mappings with permissions |
| `allocate_memory` / `free_memory` / `list_allocations` | Allocate (malloc/mmap), free, and track memory blocks |
| `patch` | Write assembled instructions to memory |

**Breakpoints & Execution**

| Tool | Description |
|------|-------------|
| `add_breakpoint` / `add_breakpoint_by_symbol` / `add_breakpoint_by_offset` | Add breakpoints by address, symbol, or module+offset |
| `remove_breakpoint` / `list_breakpoints` | Remove or list breakpoints (with disassembly) |
| `continue_execution` / `run_until` | Resume execution or run to target address |
| `step_over` / `step_into` / `step_out` | Step over, into (N instructions), or out of function |
| `next_block` | Break at next basic block (Unicorn only) |
| `step_until_mnemonic` | Break at next instruction matching mnemonic, e.g. `bl`, `ret` (Unicorn only) |
| `stop_emulation` | Force stop emulation (safety mechanism) |
| `poll_events` | Poll for breakpoint_hit, execution_completed, trace events |

**Tracing**

| Tool | Description |
|------|-------------|
| `trace_code` | Trace instructions with register read/write values (regs_read, prev_write) |
| `trace_read` / `trace_write` | Trace memory reads/writes in address range |

**Function Calls**

| Tool | Description |
|------|-------------|
| `call_function` | Call native function with typed arguments (hex, string, bytes, null) |

**iOS Only** (available when Family=iOS)

| Tool | Description |
|------|-------------|
| `dump_objc_class` | Dump ObjC class definition (properties, methods, protocols, ivars) |
| `dump_gpb_protobuf` | Dump GPB protobuf message schema as .proto format (64-bit only) |

### Custom MCP Tools

Register custom tools to let AI repeatedly trigger emulation with different parameters. Each custom tool call re-runs `runWithArgs` — by this point the native library is fully loaded (JNI_OnLoad / entry point already executed), so the code inside `runWithArgs` is the target function logic to analyze. AI can set breakpoints and traces before triggering a custom tool, then inspect execution results across different inputs without restarting the process.

**Android Example** — See [Utilities64.java](https://github.com/zhkl0228/unidbg/blob/master/unidbg-android/src/test/java/org/telegram/messenger/Utilities64.java) for an Android JNI example with custom MCP tools:

```java
DalvikModule dm = vm.loadLibrary(new File("libtmessages.29.so"), true);
dm.callJNI_OnLoad(emulator);
cUtilities = vm.resolveClass("org/telegram/messenger/Utilities");

Debugger debugger = emulator.attach();
debugger.addMcpTool("aesCbc", "Run AES-CBC encryption on input data", "input");
debugger.addMcpTool("aesCtr", "Run AES-CTR decryption on input data", "input");
debugger.addMcpTool("pbkdf2", "Run PBKDF2 key derivation", "password", "iterations");
debugger.run(this);
```

```java
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
    }
    return null;
}
```

**iOS Example** — See [IpaLoaderTest.java](https://github.com/zhkl0228/unidbg/blob/master/unidbg-ios/src/test/java/com/github/unidbg/ios/IpaLoaderTest.java) for an iOS IPA loading example with custom MCP tools:

```java
IpaLoader ipaLoader = new IpaLoader64(ipa, new File("target/rootfs/ipa"));
LoadedIpa loader = ipaLoader.load(this);
emulator = loader.getEmulator();
loader.callEntry();
module = loader.getExecutable();

Debugger debugger = emulator.attach();
debugger.addMcpTool("dumpClass", "Dump an ObjC class definition by name", "className");
debugger.addMcpTool("readVersion", "Read the TelegramCoreVersionString from the executable");
debugger.run(this);
```

```java
@Override
public Void runWithArgs(String[] args) {
    String toolName = args != null ? args[0] : null;
    if ("dumpClass".equals(toolName)) {
        String className = args.length > 1 ? args[1] : "AppDelegate";
        IClassDumper classDumper = ClassDumper.getInstance(emulator);
        System.out.println("dumpClass(" + className + "):\n" + classDumper.dumpClass(className));
    } else if ("readVersion".equals(toolName)) {
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
```

Once the MCP server is started, AI can call these tools via MCP to run emulations with custom parameters, set breakpoints, trace execution, and inspect results — all without restarting the process.

## Examples

Simple tests under src/test directory:
- [TTEncrypt.java](https://github.com/zhkl0228/unidbg/blob/master/unidbg-android/src/test/java/com/bytedance/frameworks/core/encrypt/TTEncrypt.java)  

![](assets/TTEncrypt.gif)
***
- [JniDispatch32.java](https://github.com/zhkl0228/unidbg/blob/master/unidbg-android/src/test/java/com/sun/jna/JniDispatch32.java)  
![](assets/JniDispatch32.gif)
***
- [JniDispatch64.java](https://github.com/zhkl0228/unidbg/blob/master/unidbg-android/src/test/java/com/sun/jna/JniDispatch64.java)  
![](assets/JniDispatch64.gif)
***
- [Utilities32.java](https://github.com/zhkl0228/unidbg/blob/master/unidbg-android/src/test/java/org/telegram/messenger/Utilities32.java)  
![](assets/Utilities32.gif)
***
- [Utilities64.java](https://github.com/zhkl0228/unidbg/blob/master/unidbg-android/src/test/java/org/telegram/messenger/Utilities64.java)  
![](assets/Utilities64.gif)

More tests:
- [QDReaderJni.java](https://github.com/zhkl0228/unidbg/blob/master/unidbg-android/src/test/java/com/github/unidbg/android/QDReaderJni.java)
- [SignUtil.java](https://github.com/zhkl0228/unidbg/blob/master/unidbg-android/src/test/java/com/anjuke/mobile/sign/SignUtil.java)

## License
- unidbg uses software libraries from [Apache Software Foundation](http://apache.org).

## Thanks
- [unicorn](https://github.com/zhkl0228/unicorn)
- [dynarmic](https://github.com/MerryMage/dynarmic)
- [HookZz](https://github.com/jmpews/Dobby)
- [xHook](https://github.com/iqiyi/xHook)
- [AndroidNativeEmu](https://github.com/AeonLucid/AndroidNativeEmu)
- [usercorn](https://github.com/lunixbochs/usercorn)
- [keystone](https://github.com/keystone-engine/keystone)
- [capstone](https://github.com/aquynh/capstone)
- [idaemu](https://github.com/36hours/idaemu)
- [jelf](https://github.com/fornwall/jelf)
- [whale](https://github.com/asLody/whale)
- [kaitai_struct](https://github.com/kaitai-io/kaitai_struct)
- [fishhook](https://github.com/facebook/fishhook)
- [runtime_class-dump](https://github.com/Tyilo/runtime_class-dump)
- [mman-win32](https://github.com/mcgarrah/mman-win32)

## Stargazers over time

[![Stargazers over time](https://starchart.cc/zhkl0228/unidbg.svg)](https://starchart.cc/zhkl0228/unidbg)

