/*
 * hook_u_vm_trace.js — 追踪 VM 内部 u 值计算的中间数据
 *
 * 在 sub_1BC844 内部，hook 所有 string_assign 和 str_copy 调用
 * 捕获 VM 处理的所有字符串中间值
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

function setupHooks() {
    if (hooked) return;
    hooked = true;
    var uAddr = base.add(0x7B34E8);

    // Track u compute window
    Interceptor.attach(base.add(0x1BC844), {
        onEnter: function() { inUCompute = true; console.log("▶ U_COMPUTE START"); },
        onLeave: function() { inUCompute = false; console.log("◀ U_COMPUTE END"); }
    });

    // ALL string_assign calls during u compute
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
            } else {
                console.log("[SA#" + saCount + "] len=" + len);
            }
        }
    });

    // ALL str_copy calls during u compute
    var scCount = 0;
    Interceptor.attach(base.add(0x141600), {
        onEnter: function(args) {
            if (!inUCompute) return;
            scCount++;
            var src = readSSO(args[1]);
            if (src !== null && src.length <= 200) {
                var isU = args[0].sub(uAddr).toInt32() >= 0 && args[0].sub(uAddr).toInt32() < 24;
                var marker = isU ? " ★U_GLOBAL★" : "";
                console.log("[SC#" + scCount + "]" + marker + " \"" + src + "\"");
            }
        }
    });

    // Hook memcpy during u compute (looking for raw byte copies)
    var memcpy = Module.findExportByName(null, "memcpy");
    var mcCount = 0;
    Interceptor.attach(memcpy, {
        onEnter: function(args) {
            if (!inUCompute) return;
            var sz = args[2].toInt32();
            if (sz === 16 || sz === 20 || sz === 40 || sz === 4) {
                mcCount++;
                console.log("[MC#" + mcCount + "] size=" + sz + " data=" + hexDump(args[1], sz));
            }
        }
    });

    setTimeout(function() { console.log("\n=== sa=" + saCount + " sc=" + scCount + " mc=" + mcCount + " u=" + readSSO(uAddr)); }, 25000);
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
