/*
 * hook_u_jni2.js — 深入追踪 u 计算期间的 JNI 数据流
 *
 * 已知: tag 0x4339413E 在 u 计算中被调用 3 次
 * 目标: 抓取 JNI 返回的字符串值
 */

var base = null;
var hooked = false;
var inUCompute = false;

function readSSO(ptr) {
    try {
        var b = ptr.readU8();
        if ((b & 1) === 0) { var l = b >>> 1; return l === 0 ? "" : ptr.add(1).readUtf8String(l); }
        else { var s = ptr.add(8).readU64(); if(s>4096)return null; return ptr.add(16).readPointer().readUtf8String(parseInt(s)); }
    } catch(e) { return null; }
}

function hexDump(ptr, len) {
    try { return Array.from(new Uint8Array(ptr.readByteArray(len))).map(b=>b.toString(16).padStart(2,'0')).join(''); }
    catch(e) { return "<err>"; }
}

function bt(ctx) {
    return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(a => { var m=Process.findModuleByAddress(a); return m&&m.name==="libtiny.so"?"0x"+a.sub(base).toString(16):a+"["+(m?m.name:"?")+"]"; })
        .join(" → ");
}

function setupHooks() {
    if (hooked) return;
    hooked = true;
    var uAddr = base.add(0x7B34E8);

    Interceptor.attach(base.add(0x1BC844), {
        onEnter: function() { inUCompute = true; console.log("[1BC844] ▶ ENTER"); },
        onLeave: function() { inUCompute = false; console.log("[1BC844] ◀ EXIT"); }
    });

    // Hook native_entry (0x175118) 捕获 tag 和返回值
    Interceptor.attach(base.add(0x175118), {
        onEnter: function(args) {
            if (!inUCompute) return;
            this.tag = this.context.x2.toInt32() >>> 0;
            console.log("[NATIVE_ENTRY] tag=0x" + this.tag.toString(16));
        },
        onLeave: function(retval) {
            if (!inUCompute || !this.tag) return;
            console.log("[NATIVE_ENTRY] tag=0x" + this.tag.toString(16) + " ret=" + retval);
        }
    });

    // Hook ALL string_assign during u compute (any length)
    Interceptor.attach(base.add(0x1418F0), {
        onEnter: function(args) {
            if (!inUCompute) return;
            var len = args[2].toInt32();
            if (len > 0 && len <= 256) {
                try {
                    var val = args[1].readUtf8String(len);
                    console.log("[STR_ASSIGN] len=" + len + " → \"" + val + "\"");
                } catch(e) {
                    console.log("[STR_ASSIGN] len=" + len + " hex=" + hexDump(args[1], len > 64 ? 64 : len));
                }
            }
        }
    });

    // Hook GetStringUTFChars via JNI env vtable
    // The JNI env's GetStringUTFChars is at offset 676 in function table (index 169)
    // Let me hook the NewStringUTF (offset 668, index 167) and GetStringUTFChars

    // Actually, let me hook the libtiny JNI string helper functions
    // sub_4FD4FC or similar - let me hook NewStringUTF from libart

    // Try multiple symbol names for GetStringUTFChars
    var artExports = Module.enumerateExportsSync("libart.so");
    var stringFuncs = artExports.filter(function(e) {
        return e.name.indexOf("StringUTF") >= 0 || e.name.indexOf("StringChars") >= 0;
    });
    console.log("[+] String-related exports in libart.so:");
    stringFuncs.forEach(function(f) {
        console.log("  " + f.name);
    });

    // Hook any GetStringUTFChars we find
    stringFuncs.forEach(function(f) {
        if (f.name.indexOf("GetStringUTF") >= 0 && f.type === "function") {
            try {
                Interceptor.attach(f.address, {
                    onLeave: function(retval) {
                        if (inUCompute && !retval.isNull()) {
                            try {
                                var s = retval.readUtf8String();
                                console.log("[GetStringUTF] → \"" + (s.length > 100 ? s.substring(0,100)+"..." : s) + "\"");
                            } catch(e) {}
                        }
                    }
                });
                console.log("[+] Hooked " + f.name);
            } catch(e) {}
        }
    });

    // Hook str_copy → u global
    Interceptor.attach(base.add(0x141600), {
        onEnter: function(args) {
            var d = args[0].sub(uAddr).toInt32();
            if (d >= 0 && d < 24) {
                console.log("\n★ STR_COPY → U: " + readSSO(args[1]));
                console.log("  bt: " + bt(this.context));
            }
        }
    });

    // Hook sub_470130 (hex encoder) during u compute
    Interceptor.attach(base.add(0x470130), {
        onEnter: function(args) {
            if (inUCompute) {
                this.sz = args[1].toInt32();
                this.buf = args[0];
                console.log("[HEX_ENC] ENTER size=" + this.sz);
            }
        },
        onLeave: function() {
            if (inUCompute && this.sz) {
                console.log("[HEX_ENC] input=" + hexDump(this.buf, this.sz));
            }
        }
    });

    setTimeout(function() { console.log("\n=== DONE u=" + readSSO(uAddr)); }, 25000);
}

var dlopen = Module.findExportByName(null, "android_dlopen_ext") || Module.findExportByName(null, "dlopen");
Interceptor.attach(dlopen, {
    onEnter: function(args) { try { this.p = args[0].readUtf8String(); } catch(e) { this.p=""; } },
    onLeave: function() {
        if (this.p && this.p.indexOf("libtiny.so") >= 0) {
            base = Module.findBaseAddress("libtiny.so");
            if (base) { console.log("[+] libtiny.so @ " + base); setupHooks(); }
        }
    }
});
