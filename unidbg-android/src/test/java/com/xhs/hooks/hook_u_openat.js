/*
 * hook_u_openat.js — Hook openat/mmap to find which file stores uniform_id
 * Also truncate/delete the file to force recomputation
 */

// Hook openat to find ALL file opens
var openatAddr = Module.findExportByName("libc.so", "openat");
var mmapAddr = Module.findExportByName("libc.so", "mmap");
var unlinkAddr = Module.findExportByName("libc.so", "unlink");
var unlinkFn = new NativeFunction(unlinkAddr, 'int', ['pointer']);

// Delete ALL possible locations of the MMKV file
var paths = [
    "/data/user/0/com.xingin.xhs/cache/a6de269810198701a152619ebd19abc1",
    "/data/user/0/com.xingin.xhs/cache/a6de269810198701a152619ebd19abc1.crc",
    "/data/data/com.xingin.xhs/cache/a6de269810198701a152619ebd19abc1",
    "/data/data/com.xingin.xhs/cache/a6de269810198701a152619ebd19abc1.crc",
];
paths.forEach(function(p) {
    var r = unlinkFn(Memory.allocUtf8String(p));
    console.log("[DELETE] " + p + " => " + r);
});

// Track ALL file opens matching our patterns
Interceptor.attach(openatAddr, {
    onEnter: function(args) {
        try {
            var path = args[1].readUtf8String();
            // Log ALL opens in the app data directory that could be storage
            if (path && (path.indexOf("a6de") >= 0 || path.indexOf("bistore") >= 0 ||
                path.indexOf("uniform") >= 0 || path.indexOf("/cache/") >= 0 && path.indexOf("com.xingin.xhs") >= 0)) {
                console.log("[OPENAT] " + path + " flags=0x" + args[2].toString(16));
            }
        } catch(e) {}
    }
});

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
    console.log("[+] u @ " + uAddr + " = " + readSSO(uAddr));

    // Track u compute window
    Interceptor.attach(base.add(0x1BC844), {
        onEnter: function() { inUCompute = true; console.log(">>> VM START"); },
        onLeave: function() { inUCompute = false; console.log("<<< VM END, u=" + readSSO(uAddr)); }
    });

    // Hook blob_load
    Interceptor.attach(base.add(0x2F4DB0), {
        onEnter: function(args) {
            try {
                this.name = args[0].readUtf8String(args[1].toInt32());
                this.out = args[2];
                console.log("[BLOB_LOAD] name=" + this.name);
            } catch(e) { this.name = null; }
        },
        onLeave: function(retval) {
            if (this.name) {
                var ret = retval.toInt32();
                console.log("[BLOB_LOAD] name=" + this.name + " ret=0x" + ret.toString(16));
                if (ret & 1) {
                    var val = readSSO(this.out);
                    if (val) console.log("[BLOB_LOAD] value=" + val);
                } else {
                    console.log("[BLOB_LOAD] FAILED (data not found!)");
                }
            }
        }
    });

    // Hook ALL hash functions during u compute AND during init
    Interceptor.attach(base.add(0x64EBDC), {
        onEnter: function(args) {
            this.algo = args[0].toInt32();
            this.data = args[1];
            this.dataLen = args[2].toInt32();
            this.outBuf = args[3];
            var algoName = {3:"MD5",4:"SHA1",5:"SHA224",6:"SHA256",7:"SHA384",8:"SHA512",9:"MD5+SHA1"}[this.algo] || "unk";
            console.log("[HASH] " + algoName + " inLen=" + this.dataLen + " bt=" + bt(this.context));
            if (this.dataLen > 0 && this.dataLen <= 256) {
                console.log("  hex=" + hexDump(this.data, Math.min(this.dataLen, 64)));
                try { console.log("  str=" + JSON.stringify(this.data.readUtf8String(Math.min(this.dataLen, 128)))); } catch(e) {}
            }
        },
        onLeave: function() {
            if (this.outBuf) {
                var hl = {3:16, 4:20, 6:32, 7:48, 8:64, 9:36}[this.algo] || 32;
                console.log("[HASH] out=" + hexDump(this.outBuf, hl));
            }
        }
    });

    // Hook hex encoder for MD5-sized outputs
    Interceptor.attach(base.add(0x470130), {
        onEnter: function(args) {
            this.buf = args[0];
            this.sz = args[1].toInt32();
            if (this.sz === 16) {
                console.log("[HEX_ENC] size=16 (MD5!) input=" + hexDump(this.buf, 16) + " bt=" + bt(this.context));
            }
        }
    });

    // Hook str_copy -> u global
    Interceptor.attach(base.add(0x141600), {
        onEnter: function(args) {
            try {
                var d = args[0].sub(uAddr).toInt32();
                if (d >= 0 && d < 24) {
                    console.log("*** STR_COPY -> U: " + readSSO(args[1]) + " ***");
                    console.log("  bt: " + bt(this.context));
                }
            } catch(e) {}
        }
    });

    // Hook string_assign -> u global
    Interceptor.attach(base.add(0x1418F0), {
        onEnter: function(args) {
            try {
                var d = args[0].sub(uAddr).toInt32();
                if (d >= 0 && d < 24) {
                    var len = args[2].toInt32();
                    var val = args[1].readUtf8String(len);
                    console.log("*** STRING_ASSIGN -> U: " + val + " ***");
                    console.log("  bt: " + bt(this.context));
                }
            } catch(e) {}
        }
    });

    // Hook sub_19C174 (Java entry)
    Interceptor.attach(base.add(0x19C174), {
        onEnter: function() { console.log("[19C174] ENTER u=" + readSSO(uAddr)); },
        onLeave: function() { console.log("[19C174] EXIT u=" + readSSO(uAddr)); }
    });

    // Poll u changes
    var lastU = "";
    var poller = setInterval(function() {
        var curU = readSSO(uAddr) || "";
        if (curU !== lastU) {
            console.log("!!! U CHANGED: " + lastU + " -> " + curU);
            lastU = curU;
        }
    }, 1);

    setTimeout(function() {
        clearInterval(poller);
        console.log("\n=== FINAL u=" + readSSO(uAddr));
    }, 40000);
}

var dlopen = Module.findExportByName(null, "android_dlopen_ext") || Module.findExportByName(null, "dlopen");
Interceptor.attach(dlopen, {
    onEnter: function(args) { try { this.p = args[0].readUtf8String(); } catch(e) { this.p=""; } },
    onLeave: function() {
        if (this.p && this.p.indexOf("libtiny.so") >= 0) {
            base = Module.findBaseAddress("libtiny.so");
            if (base) { console.log("[+] libtiny @ " + base); setupHooks(); }
        }
    }
});
