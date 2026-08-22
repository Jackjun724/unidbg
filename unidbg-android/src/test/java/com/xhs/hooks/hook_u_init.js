/*
 * hook_u_init.js — hook dlopen 捕获 libtiny.so 初始化过程中的 u 值计算
 *
 * 策略: hook android_dlopen_ext, 在 libtiny.so 加载后立即设置 hook,
 *       在 .init_array / JNI_OnLoad 执行时捕获 u 值的首次写入
 */

// Hook android_dlopen_ext to catch libtiny.so loading
var dlopen = Module.findExportByName(null, "android_dlopen_ext");
if (!dlopen) dlopen = Module.findExportByName(null, "dlopen");

var base = null;
var hooked = false;

function readSSO(ptr) {
    try {
        var b = ptr.readU8();
        if ((b & 1) === 0) {
            var len = b >>> 1;
            return len === 0 ? "" : ptr.add(1).readUtf8String(len);
        } else {
            var sz = ptr.add(8).readU64();
            if (sz > 4096) return null;
            return ptr.add(16).readPointer().readUtf8String(parseInt(sz));
        }
    } catch(e) { return null; }
}

function hexDump(ptr, len) {
    try {
        return Array.from(new Uint8Array(ptr.readByteArray(len)))
            .map(b => b.toString(16).padStart(2, '0')).join('');
    } catch(e) { return "<err>"; }
}

function bt(ctx) {
    if (!base) return "<no-base>";
    return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(function(a) {
            var m = Process.findModuleByAddress(a);
            if (m && m.name === "libtiny.so") return "0x" + a.sub(base).toString(16);
            return a + "[" + (m ? m.name : "?") + "]";
        }).join(" → ");
}

function setupHooks() {
    if (hooked) return;
    hooked = true;

    var uAddr = base.add(0x7B34E8);
    console.log("[+] Setting up hooks IMMEDIATELY after libtiny.so load");
    console.log("[+] u global @ " + uAddr);
    console.log("[+] u bytes: " + hexDump(uAddr, 24));
    console.log("[+] u SSO: " + readSSO(uAddr));

    // Hook string_assign (0x1418F0) — 只检查 dst == u 全局
    try {
        Interceptor.attach(base.add(0x1418F0), {
            onEnter: function(args) {
                var d = args[0].sub(uAddr).toInt32();
                if (d >= 0 && d < 24) {
                    var len = args[2].toInt32();
                    var val = "";
                    try { val = args[1].readUtf8String(len > 128 ? 128 : len); } catch(e) {}
                    console.log("\n★ STRING_ASSIGN → U GLOBAL ★");
                    console.log("  len=" + len + " val=" + val);
                    console.log("  bt: " + bt(this.context));
                }
            }
        });
    } catch(e) { console.log("string_assign hook failed: " + e); }

    // Hook str_copy (0x141600) — 只检查 dst == u 全局
    try {
        Interceptor.attach(base.add(0x141600), {
            onEnter: function(args) {
                var d = args[0].sub(uAddr).toInt32();
                if (d >= 0 && d < 24) {
                    var src = readSSO(args[1]);
                    console.log("\n★ STR_COPY → U GLOBAL ★");
                    console.log("  src=" + src);
                    console.log("  bt: " + bt(this.context));
                }
            }
        });
    } catch(e) { console.log("str_copy hook failed: " + e); }

    // 高频轮询 u 变化
    var lastBytes = hexDump(uAddr, 24);
    var t0 = Date.now();
    var poller = setInterval(function() {
        var cur = hexDump(uAddr, 24);
        if (cur !== lastBytes) {
            var ms = Date.now() - t0;
            console.log("\n★ U CHANGED @ " + ms + "ms ★");
            console.log("  old: " + lastBytes);
            console.log("  new: " + cur);
            console.log("  SSO: " + readSSO(uAddr));
            lastBytes = cur;
            var sso = readSSO(uAddr);
            if (sso && sso.length === 40 && sso.match(/^[0-9a-f]{40}$/)) {
                console.log("★★★ U VALUE SET: " + sso + " ★★★");
                clearInterval(poller);
            }
        }
    }, 1);

    // 同时 hook JNI_OnLoad (0x19C204)
    try {
        Interceptor.attach(base.add(0x19C204), {
            onEnter: function(args) {
                console.log("[JNI_OnLoad] ENTER, u=" + readSSO(uAddr));
            },
            onLeave: function(retval) {
                console.log("[JNI_OnLoad] EXIT, u=" + readSSO(uAddr));
            }
        });
    } catch(e) { console.log("JNI_OnLoad hook failed: " + e); }

    setTimeout(function() {
        clearInterval(poller);
        console.log("\n=== TIMEOUT: u=" + readSSO(uAddr));
    }, 25000);
}

console.log("[+] Hooking dlopen at " + dlopen);
Interceptor.attach(dlopen, {
    onEnter: function(args) {
        try {
            this.path = args[0].readUtf8String();
        } catch(e) { this.path = ""; }
    },
    onLeave: function(retval) {
        if (this.path && this.path.indexOf("libtiny.so") >= 0) {
            console.log("[dlopen] libtiny.so loaded! handle=" + retval);
            base = Module.findBaseAddress("libtiny.so");
            if (base) {
                console.log("[dlopen] base = " + base);
                setupHooks();
            }
        }
    }
});

// Also try to catch if libtiny.so is already loaded
var existing = Module.findBaseAddress("libtiny.so");
if (existing) {
    base = existing;
    console.log("[+] libtiny.so already loaded at " + base);
    setupHooks();
}
