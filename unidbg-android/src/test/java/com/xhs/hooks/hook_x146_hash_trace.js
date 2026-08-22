// hook_x146_hash_trace.js — 追踪28字节raw hash和56字节hex string的创建
// 策略: hook多个底层函数，捕获28/56字节数据首次出现

var hooked = false;
var base = null;

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

var found56 = false;

function isHexString(ptr, len) {
    try {
        var buf = ptr.readByteArray(len);
        var arr = new Uint8Array(buf);
        for (var i = 0; i < len; i++) {
            var c = arr[i];
            if (!((c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66) || (c >= 0x41 && c <= 0x46)))
                return false;
        }
        return true;
    } catch(e) { return false; }
}

function installHooks() {
    // Hook sub_1418F0 (string_assign) for 56-byte writes
    Interceptor.attach(base.add(0x1418F0), {
        onEnter: function(args) {
            this.dst = args[0];
            this.data = args[1];
            this.len = args[2].toInt32();

            if (this.len === 56 && !found56) {
                if (isHexString(this.data, 56)) {
                    found56 = true;
                    var str = this.data.readUtf8String(56);
                    console.log("\n[★ FIRST 56-hex assign] data='" + str + "'");
                    console.log("[★] dst=" + this.dst + " caller=+" +
                        this.returnAddress.sub(base).toString(16));
                    console.log("[★] Backtrace:");
                    var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
                    for (var i = 0; i < bt.length; i++) {
                        var off = bt[i].sub(base);
                        var inLib = bt[i].compare(base) >= 0 && off.compare(ptr(0x800000)) < 0;
                        console.log("  [" + i + "] " + bt[i] +
                            (inLib ? " (+" + off.toString(16) + ")" : ""));
                    }
                }
            }
        }
    });

    // Hook sub_5471D8 (memcpy variant used by string_assign)
    Interceptor.attach(base.add(0x5471D8), {
        onEnter: function(args) {
            this.dst = args[0];
            this.src = args[1];
            this.len = args[2].toInt32();

            // Check for 28-byte raw hash copy
            if (this.len === 28) {
                console.log("\n[memcpy 28B] dst=" + this.dst + " src=" + this.src +
                    " caller=+" + this.returnAddress.sub(base).toString(16));
                try {
                    console.log("[memcpy 28B] data:");
                    console.log(hexdump(this.src, { length: 28, ansi: true }));
                } catch(e) {}
            }

            // Check for 56-byte hex string copy
            if (this.len === 56 || this.len === 57) {
                if (isHexString(this.src, Math.min(this.len, 56))) {
                    console.log("\n[memcpy 56hex] dst=" + this.dst + " src=" + this.src +
                        " len=" + this.len +
                        " caller=+" + this.returnAddress.sub(base).toString(16));
                    try {
                        console.log("[memcpy 56hex] = '" + this.src.readUtf8String(56) + "'");
                    } catch(e) {}
                }
            }
        }
    });

    // Hook sub_547670 (another memcpy)
    Interceptor.attach(base.add(0x547670), {
        onEnter: function(args) {
            this.dst = args[0];
            this.src = args[1];
            this.len = args[2].toInt32();

            if (this.len === 28) {
                console.log("\n[memcpy2 28B] dst=" + this.dst + " src=" + this.src +
                    " caller=+" + this.returnAddress.sub(base).toString(16));
                try {
                    console.log(hexdump(this.src, { length: 28, ansi: true }));
                } catch(e) {}
            }
            if ((this.len === 56 || this.len === 57) && isHexString(this.src, Math.min(this.len, 56))) {
                console.log("\n[memcpy2 56hex] = '" + this.src.readUtf8String(56) + "'");
                console.log("  caller=+" + this.returnAddress.sub(base).toString(16));
            }
        }
    });

    // Hook sub_547210 (another memcpy)
    Interceptor.attach(base.add(0x547210), {
        onEnter: function(args) {
            this.len = args[2].toInt32();
            if (this.len === 28) {
                console.log("\n[memcpy3 28B] dst=" + args[0] + " src=" + args[1] +
                    " caller=+" + this.returnAddress.sub(base).toString(16));
                try { console.log(hexdump(args[1], { length: 28, ansi: true })); } catch(e) {}
            }
            if ((this.len === 56 || this.len === 57) && isHexString(args[1], Math.min(this.len, 56))) {
                console.log("\n[memcpy3 56hex] = '" + args[1].readUtf8String(56) + "'");
                console.log("  caller=+" + this.returnAddress.sub(base).toString(16));
            }
        }
    });

    // Hook sub_1411C0 (malloc) for 28 and 56-64 byte allocations
    var mallocCount28 = 0;
    var mallocCount56 = 0;
    Interceptor.attach(base.add(0x1411C0), {
        onEnter: function(args) {
            this.size = args[0].toInt32();
        },
        onLeave: function(ret) {
            if (this.size >= 28 && this.size <= 32) {
                mallocCount28++;
                if (mallocCount28 <= 20) {
                    console.log("[malloc(" + this.size + ")]→" + ret +
                        " caller=+" + this.returnAddress.sub(base).toString(16) +
                        " #" + mallocCount28);
                }
            }
            if (this.size >= 56 && this.size <= 64) {
                mallocCount56++;
                if (mallocCount56 <= 20) {
                    console.log("[malloc(" + this.size + ")]→" + ret +
                        " caller=+" + this.returnAddress.sub(base).toString(16) +
                        " #" + mallocCount56);
                }
            }
        }
    });

    // Hook sub_141600 (str_copy) for 28-byte raw data
    Interceptor.attach(base.add(0x141600), {
        onEnter: function(args) {
            this.dst = args[0];
            this.src = args[1];
            // Check if src SSO string has length 28 or 56
            try {
                var ctrl = this.src.readU8();
                var len;
                if (ctrl & 1) {
                    len = this.src.add(8).readU64();
                } else {
                    len = ctrl >> 1;
                }
                if (len == 28 || len == 56) {
                    var dataPtr;
                    if (ctrl & 1) {
                        dataPtr = this.src.add(16).readPointer();
                    } else {
                        dataPtr = this.src.add(1);
                    }
                    console.log("\n[str_copy len=" + len + "] dst=" + this.dst +
                        " caller=+" + this.returnAddress.sub(base).toString(16));
                    try {
                        console.log(hexdump(dataPtr, { length: Number(len), ansi: true }));
                    } catch(e) {}
                }
            } catch(e) {}
        }
    });

    console.log("[+] Hash trace hooks ready");
}
