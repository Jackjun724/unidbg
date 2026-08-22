/*
 * hook_u_nuke.js — Delete ALL possible storage files and trace file I/O
 * to find where uniform_id is actually stored
 */

var unlinkFn = new NativeFunction(Module.findExportByName("libc.so", "unlink"), 'int', ['pointer']);

// Delete ALL MMKV and cache files that could store device data
var filesToDelete = [
    // Cache MMKV
    "/data/user/0/com.xingin.xhs/cache/a6de269810198701a152619ebd19abc1",
    "/data/user/0/com.xingin.xhs/cache/a6de269810198701a152619ebd19abc1.crc",
    // CAPA devicekit
    "/data/user/0/com.xingin.xhs/files/mmkv/com.capa.devicekit",
    "/data/user/0/com.xingin.xhs/files/mmkv/com.capa.devicekit.crc",
    // DID value manager
    "/data/user/0/com.xingin.xhs/files/mmkv/did_value_manager",
    "/data/user/0/com.xingin.xhs/files/mmkv/did_value_manager.crc",
    // Device params
    "/data/user/0/com.xingin.xhs/files/mmkv/device_params_saver",
    "/data/user/0/com.xingin.xhs/files/mmkv/device_params_saver.crc",
    // App preferences
    "/data/user/0/com.xingin.xhs/files/mmkv/com.xingin.xhs_preferences",
    "/data/user/0/com.xingin.xhs/files/mmkv/com.xingin.xhs_preferences.crc",
    "/data/user/0/com.xingin.xhs/files/mmkv/com.xingin.xhs",
    "/data/user/0/com.xingin.xhs/files/mmkv/com.xingin.xhs.crc",
    // SharedPrefs device info
    "/data/user/0/com.xingin.xhs/shared_prefs/device_info_file.xml",
    "/data/user/0/com.xingin.xhs/shared_prefs/pre_device.xml.xml",
    // Cold launch
    "/data/user/0/com.xingin.xhs/files/mmkv/cold_launch_pref",
    "/data/user/0/com.xingin.xhs/files/mmkv/cold_launch_pref.crc",
    // Petal
    "/data/user/0/com.xingin.xhs/files/mmkv/petal_mmkv",
    "/data/user/0/com.xingin.xhs/files/mmkv/petal_mmkv.crc",
];

filesToDelete.forEach(function(p) {
    var r = unlinkFn(Memory.allocUtf8String(p));
    if (r === 0) console.log("[DELETED] " + p);
});

// Hook ALL file I/O to trace what blob_load reads
var openatAddr = Module.findExportByName("libc.so", "openat");
var pread64Addr = Module.findExportByName("libc.so", "pread64");
var readAddr = Module.findExportByName("libc.so", "read");
var mmapAddr = Module.findExportByName("libc.so", "mmap");

var fileDescMap = {};

Interceptor.attach(openatAddr, {
    onEnter: function(args) {
        try { this.path = args[1].readUtf8String(); } catch(e) { this.path = null; }
    },
    onLeave: function(retval) {
        if (this.path) {
            var fd = retval.toInt32();
            if (fd >= 0 && (this.path.indexOf("com.xingin.xhs") >= 0 || this.path.indexOf("mmkv") >= 0 ||
                this.path.indexOf("capa") >= 0)) {
                fileDescMap[fd] = this.path;
                console.log("[OPENAT] fd=" + fd + " " + this.path);
            }
        }
    }
});

var base = null;
var hooked = false;
var inBlobLoad = false;

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
    console.log("[+] u = " + readSSO(uAddr));

    // Hook blob_load with in-function tracking
    Interceptor.attach(base.add(0x2F4DB0), {
        onEnter: function(args) {
            inBlobLoad = true;
            try {
                this.name = args[0].readUtf8String(args[1].toInt32());
                this.out = args[2];
                console.log("\n[BLOB_LOAD] >>> " + this.name);
            } catch(e) { this.name = null; }
        },
        onLeave: function(retval) {
            inBlobLoad = false;
            if (this.name) {
                var ret = retval.toInt32();
                console.log("[BLOB_LOAD] <<< " + this.name + " ret=0x" + ret.toString(16));
                if (ret & 1) {
                    var val = readSSO(this.out);
                    if (val) console.log("[BLOB_LOAD] val=" + val);
                } else {
                    console.log("[BLOB_LOAD] *** NOT FOUND ***");
                }
            }
        }
    });

    // Track read/pread during blob_load
    if (readAddr) {
        Interceptor.attach(readAddr, {
            onEnter: function(args) {
                if (!inBlobLoad) return;
                var fd = args[0].toInt32();
                var path = fileDescMap[fd] || "fd:" + fd;
                console.log("[READ] fd=" + fd + " (" + path + ") size=" + args[2].toInt32());
            }
        });
    }

    // Hook hash functions
    Interceptor.attach(base.add(0x64EBDC), {
        onEnter: function(args) {
            this.algo = args[0].toInt32();
            this.dataLen = args[2].toInt32();
            this.outBuf = args[3];
            this.data = args[1];
            var algoName = {3:"MD5",4:"SHA1",6:"SHA256"}[this.algo] || "a" + this.algo;
            console.log("[HASH] " + algoName + " len=" + this.dataLen);
            if (this.dataLen <= 128) {
                console.log("  hex=" + hexDump(this.data, this.dataLen));
                try { console.log("  str=" + this.data.readUtf8String(this.dataLen)); } catch(e) {}
            }
            console.log("  bt=" + bt(this.context));
        },
        onLeave: function() {
            var hl = {3:16, 4:20, 6:32}[this.algo] || 32;
            console.log("[HASH] out=" + hexDump(this.outBuf, hl));
        }
    });

    // Hook hex encoder for MD5-sized only
    Interceptor.attach(base.add(0x470130), {
        onEnter: function(args) {
            var sz = args[1].toInt32();
            if (sz === 16 || sz === 20) {
                console.log("[HEX_ENC] size=" + sz + " in=" + hexDump(args[0], sz) + " bt=" + bt(this.context));
            }
        }
    });

    // u global writes
    Interceptor.attach(base.add(0x141600), {
        onEnter: function(args) {
            try {
                var d = args[0].sub(uAddr).toInt32();
                if (d >= 0 && d < 24) {
                    console.log("*** U = " + readSSO(args[1]) + " bt=" + bt(this.context));
                }
            } catch(e) {}
        }
    });
    Interceptor.attach(base.add(0x1418F0), {
        onEnter: function(args) {
            try {
                var d = args[0].sub(uAddr).toInt32();
                if (d >= 0 && d < 24) {
                    var len = args[2].toInt32();
                    console.log("*** U(assign) = " + args[1].readUtf8String(len) + " bt=" + bt(this.context));
                }
            } catch(e) {}
        }
    });

    // Hook __read_chk (random bytes) during VM
    var readChk = Module.findExportByName("libc.so", "__read_chk");
    if (readChk) {
        Interceptor.attach(readChk, {
            onEnter: function(args) {
                this.fd = args[0].toInt32();
                this.buf = args[1];
                this.sz = args[2].toInt32();
            },
            onLeave: function() {
                if (this.fd >= 0 && this.sz >= 16 && this.sz <= 128) {
                    var path = fileDescMap[this.fd] || "fd:" + this.fd;
                    if (path.indexOf("urandom") >= 0 || path.indexOf("random") >= 0) {
                        console.log("[RANDOM] " + this.sz + " bytes: " + hexDump(this.buf, this.sz));
                    }
                }
            }
        });
    }

    setTimeout(function() {
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
