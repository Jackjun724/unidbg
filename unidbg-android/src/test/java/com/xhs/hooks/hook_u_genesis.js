/*
 * hook_u_genesis.js — Force u regeneration by intercepting blob_load
 * for uniform_id ONLY, and hook blob_store + random to catch the generation
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
    if (!base) return "?";
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

    // Hook blob_load - ONLY fail for uniform_id
    Interceptor.attach(base.add(0x2F4DB0), {
        onEnter: function(args) {
            try { this.n = args[0].readUtf8String(args[1].toInt32()); this.o = args[2]; }
            catch(e) { this.n = null; }
        },
        onLeave: function(retval) {
            if (this.n === "uniform_id") {
                console.log("[BLOB_RD] uniform_id ret=" + retval);
                console.log("[BLOB_RD] FORCING FAIL");
                retval.replace(0);
            }
        }
    });

    // Hook vm_call_unk_1A2040 (blob_store)
    Interceptor.attach(base.add(0x1A2040), {
        onEnter: function(args) {
            var val = readSSO(args[0]);
            console.log("[BLOB_WR] store called! val=" + val);
            console.log("[BLOB_WR] bt=" + bt(this.context));
        }
    });

    // Hook __read_chk for random bytes
    var readChk = Module.findExportByName("libc.so", "__read_chk");
    if (readChk) {
        Interceptor.attach(readChk, {
            onEnter: function(args) {
                this.fd = args[0].toInt32();
                this.buf = args[1];
                this.sz = args[2].toInt32();
            },
            onLeave: function(retval) {
                if (this.sz >= 8 && this.sz <= 128) {
                    console.log("[RANDOM] fd=" + this.fd + " sz=" + this.sz + " data=" + hexDump(this.buf, this.sz));
                    console.log("[RANDOM] bt=" + bt(this.context));
                }
            }
        });
    }

    // Hook getrandom syscall wrapper
    var getrandom = Module.findExportByName("libc.so", "getrandom");
    if (getrandom) {
        Interceptor.attach(getrandom, {
            onEnter: function(args) { this.buf = args[0]; this.sz = args[1].toInt32(); },
            onLeave: function() {
                if (this.sz >= 8) {
                    console.log("[GETRANDOM] sz=" + this.sz + " data=" + hexDump(this.buf, this.sz));
                    console.log("[GETRANDOM] bt=" + bt(this.context));
                }
            }
        });
    }

    // Hook ALL hash functions
    Interceptor.attach(base.add(0x64EBDC), {
        onEnter: function(args) {
            this.algo = args[0].toInt32();
            this.data = args[1];
            this.dataLen = args[2].toInt32();
            this.outBuf = args[3];
            var names = {3:"MD5",4:"SHA1",6:"SHA256"};
            console.log("[HASH] " + (names[this.algo]||this.algo) + " len=" + this.dataLen);
            if (this.dataLen <= 128) {
                console.log("  in=" + hexDump(this.data, this.dataLen));
                try { console.log("  str=" + this.data.readUtf8String(this.dataLen)); } catch(e) {}
            }
            console.log("  bt=" + bt(this.context));
        },
        onLeave: function() {
            var hl = {3:16,4:20,6:32}[this.algo]||32;
            console.log("[HASH] out=" + hexDump(this.outBuf, hl));
        }
    });

    // Poll u global
    var lastU = "";
    setInterval(function() {
        var u = readSSO(uAddr) || "";
        if (u !== lastU) { console.log("!! U: " + lastU + " -> " + u); lastU = u; }
    }, 10);

    setTimeout(function() { console.log("=== u=" + readSSO(uAddr)); }, 30000);
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
