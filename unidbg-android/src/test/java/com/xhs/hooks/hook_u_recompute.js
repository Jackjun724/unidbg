/*
 * hook_u_recompute.js — Force u recomputation by making blob_load fail
 *
 * Strategy: Hook sub_2F4DB0 (blob_load) and make it return 0 (failure)
 * when called for the u blob. This forces the VM to compute u from scratch.
 * Then hook ALL hash functions to capture the computation.
 */

var base = null;
var hooked = false;
var inUCompute = false;
var forceRecompute = true; // Set to true to force recomputation

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
    if (!base) return "<no-base>";
    return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(function(a) {
            var m = Process.findModuleByAddress(a);
            if (m && m.name === "libtiny.so") return "0x" + a.sub(base).toString(16);
            return a + "[" + (m ? m.name : "?") + "]";
        }).join(" -> ");
}

function setupHooks() {
    if (hooked) return;
    hooked = true;
    var uAddr = base.add(0x7B34E8);
    console.log("[+] u global @ " + uAddr + " current=" + readSSO(uAddr));

    // Track u compute window
    Interceptor.attach(base.add(0x1BC844), {
        onEnter: function() { inUCompute = true; console.log(">>> U_COMPUTE START"); },
        onLeave: function() { inUCompute = false; console.log("<<< U_COMPUTE END, u=" + readSSO(uAddr)); }
    });

    // Hook sub_2F4DB0 (blob_load) - force failure during u compute
    Interceptor.attach(base.add(0x2F4DB0), {
        onEnter: function(args) {
            this.inU = inUCompute;
            if (this.inU) {
                var path = args[0].readUtf8String();
                var len = args[1].toInt32();
                this.outPtr = args[2];
                console.log("[BLOB_LOAD] path=\"" + path + "\" len=" + len + " key=" + args[3]);
                console.log("  bt: " + bt(this.context));
            }
        },
        onLeave: function(retval) {
            if (this.inU) {
                console.log("[BLOB_LOAD] ret=" + retval);
                if (forceRecompute) {
                    console.log("[BLOB_LOAD] FORCING FAILURE (ret=0)");
                    retval.replace(0);
                }
            }
        }
    });

    // Hook ALL hash functions
    // sub_64EBDC (multi-algo dispatcher)
    Interceptor.attach(base.add(0x64EBDC), {
        onEnter: function(args) {
            if (!inUCompute) return;
            this.algo = args[0].toInt32();
            this.data = args[1];
            this.dataLen = args[2].toInt32();
            this.outBuf = args[3];
            this.outLen = args[4].toInt32();
            var algoName = {3:"MD5",4:"SHA1",5:"SHA256_224",6:"SHA256",7:"SHA384",8:"SHA512",9:"MD5+SHA1"}[this.algo] || "unk";
            console.log("[HASH] type=" + this.algo + "(" + algoName + ") inLen=" + this.dataLen + " outLen=" + this.outLen);
            if (this.dataLen > 0 && this.dataLen <= 512) {
                console.log("  hex: " + hexDump(this.data, Math.min(this.dataLen, 128)));
                try { console.log("  str: " + this.data.readUtf8String(Math.min(this.dataLen, 128))); } catch(e) {}
            }
            console.log("  bt: " + bt(this.context));
        },
        onLeave: function(retval) {
            if (!inUCompute || !this.outBuf) return;
            var hashLen = {3:16, 4:20, 6:32, 7:48, 8:64, 9:36}[this.algo] || 32;
            console.log("[HASH] output: " + hexDump(this.outBuf, hashLen));
        }
    });

    // sub_7292E0 (SHA1 standalone)
    Interceptor.attach(base.add(0x7292E0), {
        onEnter: function(args) {
            if (!inUCompute) return;
            this.inBuf = args[0];
            this.sz = args[1].toInt32();
            this.out = args[2];
            console.log("[SHA1] size=" + this.sz);
            if (this.sz <= 256) {
                console.log("  hex: " + hexDump(this.inBuf, this.sz));
                try { console.log("  str: " + this.inBuf.readUtf8String(this.sz)); } catch(e) {}
            }
        },
        onLeave: function() {
            if (!inUCompute) return;
            console.log("[SHA1] out: " + hexDump(this.out, 20));
        }
    });

    // sub_470130 (hex encoder)
    Interceptor.attach(base.add(0x470130), {
        onEnter: function(args) {
            if (!inUCompute) return;
            this.buf = args[0];
            this.sz = args[1].toInt32();
            console.log("[HEX_ENC] size=" + this.sz + " input=" + hexDump(this.buf, this.sz));
        }
    });

    // Hook string_assign during u compute
    var saCount = 0;
    Interceptor.attach(base.add(0x1418F0), {
        onEnter: function(args) {
            if (!inUCompute) return;
            saCount++;
            var len = args[2].toInt32();
            if (len > 0 && len <= 512) {
                try {
                    var val = args[1].readUtf8String(len);
                    console.log("[SA#" + saCount + "] len=" + len + " \"" + val + "\"");
                } catch(e) {
                    console.log("[SA#" + saCount + "] len=" + len + " hex=" + hexDump(args[1], Math.min(len, 64)));
                }
            }
        }
    });

    // Hook str_copy during u compute
    var scCount = 0;
    Interceptor.attach(base.add(0x141600), {
        onEnter: function(args) {
            if (!inUCompute) return;
            scCount++;
            var src = readSSO(args[1]);
            var isU = false;
            try { isU = args[0].sub(uAddr).toInt32() >= 0 && args[0].sub(uAddr).toInt32() < 24; } catch(e){}
            var marker = isU ? " ***U***" : "";
            if (src !== null && src.length <= 200) {
                console.log("[SC#" + scCount + "]" + marker + " \"" + src + "\"");
            }
        }
    });

    // Hook sub_1A1F80 (u store)
    Interceptor.attach(base.add(0x1A1F80), {
        onEnter: function() {
            console.log("[1A1F80] U STORE ENTER");
            console.log("  bt: " + bt(this.context));
        }
    });

    // Hook sub_1A1F00 (blob load wrapper)
    Interceptor.attach(base.add(0x1A1F00), {
        onEnter: function() {
            console.log("[1A1F00] BLOB LOAD WRAPPER ENTER");
        }
    });

    // Hook memcpy for hash-sized copies
    var memcpy = Module.findExportByName(null, "memcpy");
    var mcCount = 0;
    Interceptor.attach(memcpy, {
        onEnter: function(args) {
            if (!inUCompute) return;
            var sz = args[2].toInt32();
            if (sz === 16 || sz === 20 || sz === 32 || sz === 40 || sz === 64) {
                mcCount++;
                console.log("[MC#" + mcCount + "] size=" + sz + " data=" + hexDump(args[1], sz));
            }
        }
    });

    // Hook native_entry for JNI calls
    Interceptor.attach(base.add(0x175118), {
        onEnter: function(args) {
            if (!inUCompute) return;
            var tag = this.context.x2.toInt32() >>> 0;
            console.log("[NATIVE_ENTRY] tag=0x" + tag.toString(16));
        }
    });

    // Hook sub_19C174 (Java entry)
    Interceptor.attach(base.add(0x19C174), {
        onEnter: function() {
            console.log("\n[19C174] ENTER, u=" + readSSO(uAddr));
        },
        onLeave: function() {
            console.log("[19C174] EXIT, u=" + readSSO(uAddr));
        }
    });

    setTimeout(function() {
        console.log("\n=== FINAL: u=" + readSSO(uAddr));
        console.log("=== sa=" + saCount + " sc=" + scCount + " mc=" + mcCount);
    }, 30000);
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
var e = Module.findBaseAddress("libtiny.so");
if (e) { base = e; setupHooks(); }
