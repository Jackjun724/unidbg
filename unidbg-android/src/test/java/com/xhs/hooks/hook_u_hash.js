/*
 * hook_u_hash.js — 在 u 值计算期间 hook hash 函数
 *
 * 关键发现: u 值在 JNI_OnLoad 之后、第一个 Java native call 时计算
 * 调用链: Java → sub_19C174 → sub_1BC844 → VM → str_copy → u global
 * u = "00000000" + 16字节hash (MD5大小)
 *
 * 策略: hook dlopen → 在 u 计算前设好 hash 函数 hook
 */

var base = null;
var hooked = false;

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
    console.log("[+] hooks setup, u=" + readSSO(uAddr));

    // ===== 1. Hook sub_64EBDC (multi-algo hash dispatcher) =====
    // a1=type: 3=MD5, 4=SHA1, 6=SHA256
    Interceptor.attach(base.add(0x64EBDC), {
        onEnter: function(args) {
            this.algo = args[0].toInt32();
            this.data = args[1];
            this.dataLen = args[2].toInt32();
            this.outBuf = args[3];
            this.outLen = args[4].toInt32();
            var algoName = {3:"MD5",4:"SHA1",5:"SHA256_224",6:"SHA256",7:"SHA384",8:"SHA512",9:"MD5+SHA1"}[this.algo] || "unk";
            console.log("[HASH] type=" + this.algo + "(" + algoName + ") inLen=" + this.dataLen + " outLen=" + this.outLen);
            if (this.dataLen > 0 && this.dataLen <= 256) {
                console.log("  input_hex: " + hexDump(this.data, this.dataLen));
                try { console.log("  input_str: " + this.data.readUtf8String(this.dataLen)); } catch(e) {}
            } else if (this.dataLen > 256) {
                console.log("  input_hex (first 64): " + hexDump(this.data, 64));
            }
            console.log("  bt: " + bt(this.context));
        },
        onLeave: function(retval) {
            if (this.outBuf && !this.outBuf.isNull()) {
                var hashLen = {3:16, 4:20, 6:32, 9:36}[this.algo] || 32;
                console.log("[HASH] output: " + hexDump(this.outBuf, hashLen));
            }
        }
    });

    // ===== 2. Hook sub_7292E0 (standalone SHA1) =====
    Interceptor.attach(base.add(0x7292E0), {
        onEnter: function(args) {
            this.sz = args[1].toInt32();
            this.out = args[2];
            console.log("[SHA1_standalone] size=" + this.sz);
        },
        onLeave: function() {
            console.log("[SHA1_standalone] out: " + hexDump(this.out, 20));
        }
    });

    // ===== 3. Hook sub_470130 (hex encoder) =====
    Interceptor.attach(base.add(0x470130), {
        onEnter: function(args) {
            this.buf = args[0];
            this.sz = args[1].toInt32();
        },
        onLeave: function() {
            if (this.sz <= 20) {
                console.log("[HEX_ENC] size=" + this.sz + " input=" + hexDump(this.buf, this.sz));
                console.log("  bt: " + bt(this.context));
            }
        }
    });

    // ===== 4. Hook sub_19C174 (Java→native for u) =====
    Interceptor.attach(base.add(0x19C174), {
        onEnter: function() {
            console.log("\n[sub_19C174] ENTER (Java→native u computation)");
            console.log("  u before: " + readSSO(uAddr));
        },
        onLeave: function() {
            console.log("[sub_19C174] EXIT, u=" + readSSO(uAddr));
        }
    });

    // ===== 5. Hook sub_1BC844 (VM dispatch for u) =====
    Interceptor.attach(base.add(0x1BC844), {
        onEnter: function() {
            console.log("[sub_1BC844] VM dispatch ENTER");
        },
        onLeave: function() {
            console.log("[sub_1BC844] VM dispatch EXIT");
        }
    });

    // ===== 6. Hook str_copy → u global =====
    Interceptor.attach(base.add(0x141600), {
        onEnter: function(args) {
            var d = args[0].sub(uAddr).toInt32();
            if (d >= 0 && d < 24) {
                var src = readSSO(args[1]);
                console.log("\n★ STR_COPY → U GLOBAL: " + src);
                console.log("  bt: " + bt(this.context));
            }
        }
    });

    setTimeout(function() {
        console.log("\n=== DONE u=" + readSSO(uAddr));
    }, 25000);
}

// Hook dlopen to catch libtiny.so load
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
var e = Module.findBaseAddress("libtiny.so");
if (e) { base = e; setupHooks(); }
