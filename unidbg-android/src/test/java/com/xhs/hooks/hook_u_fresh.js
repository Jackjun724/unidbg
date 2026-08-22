/*
 * hook_u_fresh.js — Delete MMKV cache to force u recomputation
 * Then hook ALL hash/crypto functions to capture the algorithm
 */

// Step 1: Delete the MMKV file BEFORE libtiny.so loads
var rename = new NativeFunction(Module.findExportByName(null, "rename"), 'int', ['pointer', 'pointer']);
var mmkvPath = "/data/user/0/com.xingin.xhs/cache/a6de269810198701a152619ebd19abc1";
var backupPath = "/data/user/0/com.xingin.xhs/cache/a6de269810198701a152619ebd19abc1.bak";
var crcPath = mmkvPath + ".crc";
var crcBackup = backupPath + ".crc";

var r1 = rename(Memory.allocUtf8String(mmkvPath), Memory.allocUtf8String(backupPath));
var r2 = rename(Memory.allocUtf8String(crcPath), Memory.allocUtf8String(crcBackup));
console.log("[+] Renamed MMKV file: " + r1 + ", crc: " + r2);

var base = null;
var hooked = false;
var hashLog = [];

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

    // Hook ALL hash functions (always, not just during u compute)
    // sub_64EBDC (multi-algo hash dispatcher)
    Interceptor.attach(base.add(0x64EBDC), {
        onEnter: function(args) {
            this.algo = args[0].toInt32();
            this.data = args[1];
            this.dataLen = args[2].toInt32();
            this.outBuf = args[3];
            this.outLen = args[4].toInt32();
            var algoName = {3:"MD5",4:"SHA1",5:"SHA256_224",6:"SHA256",7:"SHA384",8:"SHA512",9:"MD5+SHA1"}[this.algo] || "unk"+this.algo;
            var entry = "[HASH] " + algoName + " inLen=" + this.dataLen;
            if (this.dataLen > 0 && this.dataLen <= 512) {
                entry += " hex=" + hexDump(this.data, Math.min(this.dataLen, 128));
                try { entry += " str=" + JSON.stringify(this.data.readUtf8String(Math.min(this.dataLen, 128))); } catch(e) {}
            }
            entry += " bt=" + bt(this.context);
            console.log(entry);
            this.entry = entry;
        },
        onLeave: function(retval) {
            if (this.outBuf && !this.outBuf.isNull()) {
                var hashLen = {3:16, 4:20, 5:28, 6:32, 7:48, 8:64, 9:36}[this.algo] || 32;
                var out = hexDump(this.outBuf, hashLen);
                console.log("[HASH] output=" + out);
                hashLog.push({algo: this.algo, out: out, entry: this.entry});
            }
        }
    });

    // sub_7292E0 (SHA1 standalone)
    Interceptor.attach(base.add(0x7292E0), {
        onEnter: function(args) {
            this.inBuf = args[0];
            this.sz = args[1].toInt32();
            this.out = args[2];
            var entry = "[SHA1_SA] size=" + this.sz;
            if (this.sz > 0 && this.sz <= 256) {
                entry += " hex=" + hexDump(this.inBuf, this.sz);
                try { entry += " str=" + JSON.stringify(this.inBuf.readUtf8String(this.sz)); } catch(e) {}
            }
            entry += " bt=" + bt(this.context);
            console.log(entry);
        },
        onLeave: function() {
            console.log("[SHA1_SA] out=" + hexDump(this.out, 20));
        }
    });

    // sub_470130 (hex encoder)
    Interceptor.attach(base.add(0x470130), {
        onEnter: function(args) {
            this.buf = args[0];
            this.sz = args[1].toInt32();
            if (this.sz <= 64) {
                console.log("[HEX_ENC] size=" + this.sz + " input=" + hexDump(this.buf, this.sz) + " bt=" + bt(this.context));
            }
        }
    });

    // Hook blob_load - DON'T force failure this time, just observe
    Interceptor.attach(base.add(0x2F4DB0), {
        onEnter: function(args) {
            try {
                this.name = args[0].readUtf8String(args[1].toInt32());
                this.out = args[2];
            } catch(e) { this.name = null; }
        },
        onLeave: function(retval) {
            if (this.name) {
                var ret = retval.toInt32();
                console.log("[BLOB_LOAD] name=" + this.name + " ret=" + ret);
                if (ret & 1) {
                    var val = readSSO(this.out);
                    if (val) console.log("[BLOB_LOAD] value=" + val);
                } else {
                    console.log("[BLOB_LOAD] FAILED (not found)");
                }
            }
        }
    });

    // Hook str_copy to u global
    Interceptor.attach(base.add(0x141600), {
        onEnter: function(args) {
            try {
                var d = args[0].sub(uAddr).toInt32();
                if (d >= 0 && d < 24) {
                    var src = readSSO(args[1]);
                    console.log("\n*** STR_COPY -> U: " + src + " ***");
                    console.log("  bt: " + bt(this.context));
                }
            } catch(e) {}
        }
    });

    // Hook string_assign to u global
    Interceptor.attach(base.add(0x1418F0), {
        onEnter: function(args) {
            try {
                var d = args[0].sub(uAddr).toInt32();
                if (d >= 0 && d < 24) {
                    var len = args[2].toInt32();
                    var val = args[1].readUtf8String(len);
                    console.log("\n*** STRING_ASSIGN -> U: len=" + len + " val=" + val + " ***");
                    console.log("  bt: " + bt(this.context));
                }
            } catch(e) {}
        }
    });

    // Hook sub_19C174 (Java entry for u)
    Interceptor.attach(base.add(0x19C174), {
        onEnter: function() {
            console.log("\n=== [19C174] ENTER, u=" + readSSO(uAddr));
        },
        onLeave: function() {
            console.log("=== [19C174] EXIT, u=" + readSSO(uAddr));
        }
    });

    // Hook sub_1BC844 (VM dispatch)
    Interceptor.attach(base.add(0x1BC844), {
        onEnter: function() { console.log(">>> VM_DISPATCH START"); },
        onLeave: function() { console.log("<<< VM_DISPATCH END, u=" + readSSO(uAddr)); }
    });

    // Poll u value for changes
    var lastU = "";
    var pollCount = 0;
    var poller = setInterval(function() {
        var curU = readSSO(uAddr) || "";
        if (curU !== lastU) {
            console.log("\n!!! U CHANGED: \"" + lastU + "\" -> \"" + curU + "\" !!!");
            lastU = curU;
        }
        pollCount++;
        if (pollCount > 60000) clearInterval(poller); // 60 seconds
    }, 1);

    setTimeout(function() {
        clearInterval(poller);
        console.log("\n=== FINAL u=" + readSSO(uAddr));
        console.log("=== Hash log entries: " + hashLog.length);
        hashLog.forEach(function(h) {
            console.log("  " + h.entry + " => " + h.out);
        });

        // Restore the MMKV file
        rename(Memory.allocUtf8String(backupPath), Memory.allocUtf8String(mmkvPath));
        rename(Memory.allocUtf8String(crcBackup), Memory.allocUtf8String(crcPath));
        console.log("[+] Restored MMKV file");
    }, 45000);
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
