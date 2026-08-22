/*
 * hook_u_mmkv.js — Hook MMKV operations during u computation
 *
 * Goal: Find which MMKV key stores the u value and trace read/write
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

    // Hook MMKV getString - look for the C++ method
    // MMKV uses mmkv::MMKV::getString(const string& key, string& result)
    var mmkvMod = Process.findModuleByName("libmmkv.so");
    if (mmkvMod) {
        console.log("[+] libmmkv.so found @ " + mmkvMod.base);
        var exports = mmkvMod.enumerateExports();
        var stringOps = exports.filter(function(e) {
            return e.name.indexOf("getString") >= 0 ||
                   e.name.indexOf("getBytes") >= 0 ||
                   e.name.indexOf("decodeString") >= 0 ||
                   e.name.indexOf("encodeString") >= 0 ||
                   e.name.indexOf("set") >= 0 ||
                   e.name.indexOf("getInt") >= 0;
        });
        console.log("[+] MMKV string operations:");
        stringOps.forEach(function(f) {
            console.log("  " + f.name + " @ " + f.address);
        });

        // Hook all MMKV get/set operations
        stringOps.forEach(function(f) {
            try {
                Interceptor.attach(f.address, {
                    onEnter: function(args) {
                        if (!inUCompute) return;
                        this.fname = f.name;
                        // Try to read key from args (position depends on method)
                        // For instance methods: this=args[0], key=args[1]
                        try {
                            var key = readSSO(args[1]);
                            if (key) {
                                console.log("[MMKV] " + f.name.split("::").pop() + " key=\"" + key + "\"");
                            }
                        } catch(e) {}
                    },
                    onLeave: function(retval) {
                        if (!inUCompute) return;
                        try {
                            if (this.fname.indexOf("getString") >= 0 || this.fname.indexOf("decodeString") >= 0) {
                                // Result might be in retval or in output parameter
                                var r = retval.toInt32();
                                console.log("[MMKV] " + this.fname.split("::").pop() + " ret=" + r);
                            }
                        } catch(e) {}
                    }
                });
            } catch(e) {
                console.log("[!] Failed to hook " + f.name + ": " + e);
            }
        });
    } else {
        console.log("[!] libmmkv.so NOT found");
    }

    // Also hook MMKV JNI methods
    var mmkvJni = Process.findModuleByName("libMMKV.so"); // capital case
    if (mmkvJni && mmkvJni !== mmkvMod) {
        console.log("[+] libMMKV.so (JNI) found @ " + mmkvJni.base);
    }

    // Hook string_assign during u compute - capture ALL string values
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
                    console.log("[SA#" + saCount + "] len=" + len + " hex=" + hexDump(args[1], len > 64 ? 64 : len));
                }
            }
        }
    });

    // Hook str_copy - all copies during u compute
    var scCount = 0;
    Interceptor.attach(base.add(0x141600), {
        onEnter: function(args) {
            if (!inUCompute) return;
            scCount++;
            var src = readSSO(args[1]);
            var isU = false;
            try { isU = args[0].sub(uAddr).toInt32() >= 0 && args[0].sub(uAddr).toInt32() < 24; } catch(e){}
            var marker = isU ? " ***U_GLOBAL***" : "";
            if (src !== null && src.length <= 200) {
                console.log("[SC#" + scCount + "]" + marker + " \"" + src + "\"");
            }
        }
    });

    // Hook sub_1A1F80 (stores u to global)
    Interceptor.attach(base.add(0x1A1F80), {
        onEnter: function(args) {
            console.log("[1A1F80] ENTER (u store function)");
            console.log("  bt: " + bt(this.context));
        }
    });

    // Hook native_entry during u compute to see JNI tags
    Interceptor.attach(base.add(0x175118), {
        onEnter: function(args) {
            if (!inUCompute) return;
            var tag = this.context.x2.toInt32() >>> 0;
            console.log("[NATIVE_ENTRY] tag=0x" + tag.toString(16));
        },
        onLeave: function(retval) {
            if (!inUCompute) return;
        }
    });

    // Hook sub_19C174 - Java->native for u
    Interceptor.attach(base.add(0x19C174), {
        onEnter: function() {
            console.log("\n[19C174] Java->native u entry");
            console.log("  u before: " + readSSO(uAddr));
        },
        onLeave: function() {
            console.log("[19C174] exit, u=" + readSSO(uAddr));
        }
    });

    // Try to find MMKV within libtiny.so itself (statically linked?)
    // Search for MMKV-related strings in libtiny.so
    var ranges = Process.findModuleByName("libtiny.so").enumerateRanges("r--");
    var mmkvPatterns = ["MMKV", "mmkv", "first_launch", "last_launch", "launch_count"];

    setTimeout(function() {
        console.log("\n=== SUMMARY: sa=" + saCount + " sc=" + scCount);
        console.log("=== u=" + readSSO(uAddr));
    }, 25000);
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
