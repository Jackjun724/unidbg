// hook_x146_global_write.js — 捕获谁写入全局SSO string qword_7B0760
// qword_7B0760 = x146 hex string的存储位置
// 写入通过 sub_1418F0 (string_assign) 完成

var hooked = false;
var base = null;
var GLOBAL_7B0760 = 0x7B0760;
var STRING_ASSIGN = 0x1418F0;  // sub_1418F0(dst, data, len)
var VM_DISPATCH_1A2128 = 0x1A2128;

Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
    onEnter: function(args) { this.path = args[0].readCString(); },
    onLeave: function(ret) {
        if (!hooked && this.path && this.path.indexOf("libtiny.so") !== -1) {
            base = Module.findBaseAddress("libtiny.so");
            if (base) { console.log("[+] libtiny.so @ " + base); installHooks(); hooked = true; }
        }
    }
});
setTimeout(function() {
    if (!hooked) {
        base = Module.findBaseAddress("libtiny.so");
        if (base) { console.log("[+] libtiny.so @ " + base); installHooks(); hooked = true; }
    }
}, 1000);

function installHooks() {
    var globalAddr = base.add(GLOBAL_7B0760);
    console.log("[+] qword_7B0760 @ " + globalAddr);

    // Hook sub_1418F0 (string_assign) — 只关注写入qword_7B0760的调用
    Interceptor.attach(base.add(STRING_ASSIGN), {
        onEnter: function(args) {
            this.dst = args[0];
            this.data = args[1];
            this.len = args[2].toInt32();

            if (this.dst.equals(globalAddr)) {
                console.log("\n[★★★ GLOBAL WRITE ★★★] string_assign(&qword_7B0760, data=" +
                    this.data + ", len=" + this.len + ")");
                console.log("[★] caller=+" + this.returnAddress.sub(base).toString(16));

                // Dump the data being written
                if (this.len > 0 && this.len <= 256) {
                    try {
                        var str = this.data.readUtf8String(this.len);
                        console.log("[★] DATA = '" + str + "'");
                    } catch(e) {}
                    try {
                        console.log("[★] hexdump:");
                        console.log(hexdump(this.data, { length: Math.min(this.len + 16, 128), ansi: true }));
                    } catch(e) {}
                }

                // Full backtrace
                console.log("[★] Backtrace:");
                var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
                for (var i = 0; i < bt.length; i++) {
                    var offset = bt[i].sub(base);
                    var inRange = bt[i].compare(base) >= 0 && offset.compare(ptr(0x800000)) < 0;
                    console.log("  [" + i + "] " + bt[i] +
                        (inRange ? " (libtiny+" + offset.toString(16) + ")" : ""));
                }

                // Dump X19 (VM state) context
                try {
                    var x19 = this.context.x19;
                    console.log("[★] X19 = " + x19);
                } catch(e) {}
            }
        },
        onLeave: function(ret) {
            if (this.dst.equals(globalAddr)) {
                console.log("[★] string_assign done, checking global:");
                try {
                    var ctrl = globalAddr.readU8();
                    if (ctrl & 1) {
                        // Long mode
                        var cap = globalAddr.readU64();
                        var len = globalAddr.add(8).readU64();
                        var dataPtr = globalAddr.add(16).readPointer();
                        console.log("[★] SSO long: cap=" + cap + " len=" + len + " ptr=" + dataPtr);
                        if (len > 0 && len <= 256) {
                            console.log("[★] VALUE = '" + dataPtr.readUtf8String(len) + "'");
                        }
                    } else {
                        // Short mode
                        var len = ctrl >> 1;
                        console.log("[★] SSO short: len=" + len);
                        if (len > 0) {
                            console.log("[★] VALUE = '" + globalAddr.add(1).readUtf8String(len) + "'");
                        }
                    }
                } catch(e) { console.log("[★] read error: " + e); }
            }
        }
    });

    // Also hook vm_dispatch_1A2128 for context
    Interceptor.attach(base.add(VM_DISPATCH_1A2128), {
        onEnter: function(args) {
            console.log("\n[vm_1A2128] ENTER: X0=" + args[0] + " X1=" + args[1] +
                " X2=" + args[2] + " X3=" + args[3]);
            // X1 = data, X2 = length
            var len = args[2].toInt32();
            if (len > 0 && len <= 256) {
                try {
                    console.log("[vm_1A2128] data = '" + args[1].readUtf8String(len) + "'");
                } catch(e) {}
            }
            console.log("[vm_1A2128] caller=+" + this.returnAddress.sub(base).toString(16));
        }
    });

    // Hook the init and sig Java calls for timing
    try {
        Java.perform(function() {
            console.log("[+] Java hooks installing...");
            // We can't easily hook native methods, but we can trace timing
        });
    } catch(e) {}

    console.log("[+] Global write hooks ready");
    console.log("[+] Monitoring string_assign calls to qword_7B0760...");
}
