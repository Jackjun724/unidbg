/*
 * hook_u_mmap.js — Hook mmap to find which file is mapped for .bistore data
 * Also hook open/openat to track fd→path mapping
 */

var fdMap = {};

// Hook openat to build fd→path map
var openat = Module.findExportByName("libc.so", "openat");
Interceptor.attach(openat, {
    onEnter: function(args) {
        try { this.path = args[1].readUtf8String(); } catch(e) { this.path = null; }
    },
    onLeave: function(retval) {
        var fd = retval.toInt32();
        if (fd >= 0 && this.path) {
            fdMap[fd] = this.path;
            if (this.path.indexOf("com.xingin.xhs") >= 0 && this.path.indexOf("/lib/") < 0 &&
                this.path.indexOf("oat/") < 0 && this.path.indexOf(".dex") < 0 &&
                this.path.indexOf(".apk") < 0 && this.path.indexOf("/app/") < 0) {
                console.log("[OPEN] fd=" + fd + " " + this.path);
            }
        }
    }
});

// Hook mmap to see file mappings
var mmap = Module.findExportByName("libc.so", "mmap");
Interceptor.attach(mmap, {
    onEnter: function(args) {
        this.fd = args[4].toInt32();
        this.len = args[1].toInt32();
    },
    onLeave: function(retval) {
        if (this.fd >= 0) {
            var path = fdMap[this.fd] || "fd:" + this.fd;
            if (path.indexOf("com.xingin.xhs") >= 0 && path.indexOf("/lib/") < 0 &&
                path.indexOf("oat/") < 0 && path.indexOf(".dex") < 0 &&
                path.indexOf(".apk") < 0 && path.indexOf("/app/") < 0) {
                console.log("[MMAP] fd=" + this.fd + " len=" + this.len + " addr=" + retval + " " + path);
            }
        }
    }
});

var base = null;
var hooked = false;

function readSSO(ptr) {
    try {
        var b = ptr.readU8();
        if ((b & 1) === 0) { var l = b >>> 1; return l === 0 ? "" : ptr.add(1).readUtf8String(l); }
        else { var s = ptr.add(8).readU64(); if(s>4096)return null; return ptr.add(16).readPointer().readUtf8String(parseInt(s)); }
    } catch(e) { return null; }
}

function setupHooks() {
    if (hooked) return;
    hooked = true;
    var uAddr = base.add(0x7B34E8);
    console.log("[+] u = " + readSSO(uAddr));

    Interceptor.attach(base.add(0x2F4DB0), {
        onEnter: function(args) {
            try { this.n = args[0].readUtf8String(args[1].toInt32()); this.o = args[2]; }
            catch(e) { this.n = null; }
            if (this.n) console.log("[BLOB] >>> " + this.n);
        },
        onLeave: function(retval) {
            if (this.n) {
                var r = retval.toInt32();
                console.log("[BLOB] <<< " + this.n + " r=" + r + (r&1 ? " val=" + readSSO(this.o) : " MISS"));
            }
        }
    });

    setTimeout(function() { console.log("=== u=" + readSSO(uAddr)); }, 25000);
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
