/*
 * hook_u_capture.js — Capture u value and find initial write path
 *
 * 1. Hook blob_load for "uniform_id" to capture current u
 * 2. List files in app data dir to find .bistore files
 * 3. Hook blob_store/write operations
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

function setupHooks() {
    if (hooked) return;
    hooked = true;
    var uAddr = base.add(0x7B34E8);

    // Read current u value
    console.log("[+] u global current value: " + readSSO(uAddr));

    // List files in app data directory using opendir/readdir
    try {
        var opendir = new NativeFunction(Module.findExportByName(null, "opendir"), 'pointer', ['pointer']);
        var readdir = new NativeFunction(Module.findExportByName(null, "readdir"), 'pointer', ['pointer']);
        var closedir = new NativeFunction(Module.findExportByName(null, "closedir"), 'int', ['pointer']);

        var paths = [
            "/data/data/com.xingin.xhs/files/",
            "/data/user/0/com.xingin.xhs/files/",
            "/data/data/com.xingin.xhs/files/mmkv/",
            "/data/user/0/com.xingin.xhs/files/mmkv/"
        ];

        paths.forEach(function(path) {
            var dir = opendir(Memory.allocUtf8String(path));
            if (!dir.isNull()) {
                console.log("\n[DIR] " + path);
                var entry;
                while (!(entry = readdir(dir)).isNull()) {
                    var name = entry.add(19).readUtf8String(); // d_name offset on arm64 android
                    if (name !== "." && name !== "..") {
                        console.log("  " + name);
                    }
                }
                closedir(dir);
            }
        });
    } catch(e) {
        console.log("[!] Dir listing error: " + e);
    }

    // Hook blob_load to see ALL blob reads
    Interceptor.attach(base.add(0x2F4DB0), {
        onEnter: function(args) {
            try {
                this.path = args[0].readUtf8String(args[1].toInt32());
                this.outPtr = args[2];
                this.key = args[3].toInt32();
                console.log("\n[BLOB_LOAD] name=\"" + this.path + "\" key=" + this.key);
            } catch(e) { this.path = null; }
        },
        onLeave: function(retval) {
            if (this.path) {
                console.log("[BLOB_LOAD] name=\"" + this.path + "\" ret=" + retval);
                if (retval.toInt32() & 1) {
                    // Success - read the output SSO string
                    var val = readSSO(this.outPtr);
                    if (val && val.length <= 200) {
                        console.log("[BLOB_LOAD] value=\"" + val + "\"");
                    }
                }
            }
        }
    });

    // Hook qword_7AFF60 reader (sub_144804) to see bistore path init
    Interceptor.attach(base.add(0x144804), {
        onLeave: function() {
            try {
                var pathPtr = base.add(0x7AFF60).readPointer();
                if (!pathPtr.isNull()) {
                    console.log("[BISTORE_PATH] " + pathPtr.readUtf8String());
                }
            } catch(e) {}
        }
    });

    // Try to read MMKV data directly
    try {
        // Find mmkv data files
        var fopen = new NativeFunction(Module.findExportByName(null, "fopen"), 'pointer', ['pointer', 'pointer']);
        var fread = new NativeFunction(Module.findExportByName(null, "fread"), 'int', ['pointer', 'int', 'int', 'pointer']);
        var fclose = new NativeFunction(Module.findExportByName(null, "fclose"), 'int', ['pointer']);
        var fseek = new NativeFunction(Module.findExportByName(null, "fseek"), 'int', ['pointer', 'int', 'int']);
        var ftell = new NativeFunction(Module.findExportByName(null, "ftell"), 'int', ['pointer']);

        var mmkvPaths = [
            "/data/user/0/com.xingin.xhs/files/mmkv/a6de2698101987011a152619ebd19abc1",
            "/data/user/0/com.xingin.xhs/files/mmkv/mmkv.default",
        ];

        mmkvPaths.forEach(function(path) {
            var f = fopen(Memory.allocUtf8String(path), Memory.allocUtf8String("rb"));
            if (!f.isNull()) {
                fseek(f, 0, 2); // SEEK_END
                var size = ftell(f);
                fseek(f, 0, 0); // SEEK_SET
                console.log("\n[MMKV] " + path + " size=" + size);
                if (size > 0 && size < 4096) {
                    var buf = Memory.alloc(size);
                    fread(buf, 1, size, f);
                    // Search for "uniform_id" in the data
                    var data = new Uint8Array(buf.readByteArray(size));
                    var needle = [0x75, 0x6e, 0x69, 0x66, 0x6f, 0x72, 0x6d, 0x5f, 0x69, 0x64]; // "uniform_id"
                    for (var i = 0; i < data.length - needle.length; i++) {
                        var match = true;
                        for (var j = 0; j < needle.length; j++) {
                            if (data[i+j] !== needle[j]) { match = false; break; }
                        }
                        if (match) {
                            console.log("[MMKV] Found 'uniform_id' at offset " + i);
                            // Read surrounding data
                            var start = Math.max(0, i - 4);
                            var end = Math.min(data.length, i + 60);
                            console.log("[MMKV] context hex: " + hexDump(buf.add(start), end - start));
                            try {
                                console.log("[MMKV] context str: " + buf.add(start).readUtf8String(end - start));
                            } catch(e) {}
                        }
                    }
                }
                fclose(f);
            }
        });
    } catch(e) {
        console.log("[!] MMKV read error: " + e);
    }

    setTimeout(function() {
        console.log("\n=== DONE u=" + readSSO(uAddr));
    }, 20000);
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
