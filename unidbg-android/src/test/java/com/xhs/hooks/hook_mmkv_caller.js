// Hook mmkv_getBytes 的调用者，找到 libtiny.so 中的调用地址
// 用法: conda activate py3.8 && frida -U -f com.xingin.xhs -l hooks/hook_mmkv_caller.js --no-pause

var offsets = {
    mmkv_getValueSize: 0x354E0,
    mmkv_getBytes:     0x3561C,
};

function readCStr(ptr) {
    if (ptr.isNull()) return "<null>";
    try { return ptr.readUtf8String(); } catch(e) { return "<err>"; }
}

function hexdump_short(ptr, len) {
    if (ptr.isNull() || len <= 0) return "";
    var show = Math.min(len, 128);
    var bytes = ptr.readByteArray(show);
    var hex = Array.from(new Uint8Array(bytes)).map(b => ('0' + b.toString(16)).slice(-2)).join(' ');
    return hex + (len > 128 ? " ..." : "");
}

var hooked = false;
function hookIfNeeded() {
    if (hooked) return;
    var mmkvBase = Module.findBaseAddress("libmmkv2.so");
    if (!mmkvBase) return;
    hooked = true;

    var tinyBase = Module.findBaseAddress("libtiny.so");
    console.log("[*] libmmkv2.so base: " + mmkvBase);
    console.log("[*] libtiny.so base: " + (tinyBase || "not loaded"));

    // Hook mmkv_getValueSize - 找调用者
    Interceptor.attach(mmkvBase.add(offsets.mmkv_getValueSize), {
        onEnter: function(args) {
            this.key = readCStr(args[1]);
            this.lr = this.context.lr;
            var callerOffset = tinyBase ? "0x" + this.lr.sub(tinyBase).toString(16) : this.lr.toString();
            console.log("[mmkv_getValueSize] key=\"" + this.key + "\" caller=" + callerOffset +
                        " (abs=" + this.lr + ")");
            if (this.key === "y1") {
                console.log("[!] y1 getValueSize caller backtrace:");
                console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(function(addr) {
                        var m = DebugSymbol.fromAddress(addr);
                        var off = tinyBase ? " (tiny+0x" + addr.sub(tinyBase).toString(16) + ")" : "";
                        return "  " + addr + off + " " + m;
                    }).join("\n"));
            }
        },
        onLeave: function(ret) {
            if (this.key === "y1") {
                console.log("[mmkv_getValueSize] y1 => size=" + ret.toInt32());
            }
        }
    });

    // Hook mmkv_getBytes - 找调用者和输出数据
    Interceptor.attach(mmkvBase.add(offsets.mmkv_getBytes), {
        onEnter: function(args) {
            this.key = readCStr(args[1]);
            this.outBuf = args[2];
            this.bufSize = args[3].toInt32();
            this.lr = this.context.lr;
            var callerOffset = tinyBase ? "0x" + this.lr.sub(tinyBase).toString(16) : this.lr.toString();
            if (this.key === "y1") {
                console.log("[mmkv_getBytes] key=\"y1\" outBuf=" + this.outBuf +
                            " bufSize=" + this.bufSize + " caller=" + callerOffset);
                console.log("[!] y1 getBytes caller backtrace:");
                console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(function(addr) {
                        var m = DebugSymbol.fromAddress(addr);
                        var off = tinyBase ? " (tiny+0x" + addr.sub(tinyBase).toString(16) + ")" : "";
                        return "  " + addr + off + " " + m;
                    }).join("\n"));
            }
        },
        onLeave: function(ret) {
            if (this.key === "y1" && ret.toInt32() === 1) {
                console.log("[mmkv_getBytes] y1 data[0:128]=" + hexdump_short(this.outBuf, Math.min(this.bufSize, 128)));
                // 也打印返回后的 LR，看数据之后怎么处理
                console.log("[mmkv_getBytes] y1 returned, next instruction at " + this.lr);
            }
        }
    });

    console.log("[*] Hooked mmkv_getValueSize + mmkv_getBytes with caller tracking");
}

["android_dlopen_ext", "dlopen"].forEach(function(fname) {
    var addr = Module.findExportByName(null, fname);
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function(args) { this.path = args[0].isNull() ? "" : args[0].readUtf8String(); },
        onLeave: function(ret) {
            if (this.path && this.path.indexOf("libmmkv2.so") !== -1) hookIfNeeded();
        }
    });
});
hookIfNeeded();
