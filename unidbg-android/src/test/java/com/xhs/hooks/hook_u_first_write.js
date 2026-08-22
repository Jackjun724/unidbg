/*
 * hook_u_first_write.js
 *
 * 精确捕获 u 值全局 SSO (base+0x7B34E8) 的首次写入
 *
 * 策略: 高频轮询 SSO 变化 + hook string_assign/str_copy 检查目标地址
 *
 * Usage: conda activate py3.8 && frida -U -f com.xingin.xhs -l hooks/hook_u_first_write.js --no-pause
 */

var base = null;

function waitForLibtiny() {
    return new Promise(function(resolve) {
        var check = setInterval(function() {
            var m = Module.findBaseAddress("libtiny.so");
            if (m) {
                clearInterval(check);
                base = m;
                console.log("[+] libtiny.so base: " + base);
                resolve(base);
            }
        }, 50);
    });
}

function hexDump(ptr, len) {
    try {
        var arr = ptr.readByteArray(len);
        return Array.from(new Uint8Array(arr)).map(b => b.toString(16).padStart(2, '0')).join('');
    } catch(e) { return "<err>"; }
}

function readSSO(ptr) {
    try {
        var b = ptr.readU8();
        if ((b & 1) === 0) {
            var len = b >>> 1;
            return len === 0 ? "" : ptr.add(1).readUtf8String(len);
        } else {
            var sz = ptr.add(8).readU64();
            return ptr.add(16).readPointer().readUtf8String(parseInt(sz));
        }
    } catch(e) { return null; }
}

function bt(ctx) {
    return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(function(addr) {
            var m = Process.findModuleByAddress(addr);
            if (m && m.name === "libtiny.so")
                return "0x" + addr.sub(base).toString(16);
            return addr + "[" + (m ? m.name : "?") + "]";
        }).join(" → ");
}

waitForLibtiny().then(function(base) {
    var uAddr = base.add(0x7B34E8);
    console.log("[+] u global SSO @ " + uAddr);
    console.log("[+] Initial bytes: " + hexDump(uAddr, 24));
    console.log("[+] Initial SSO: " + readSSO(uAddr));

    var uFound = false;

    // ===== 1. Hook sub_1418F0 (string_assign) — 检查 dst 是否为 u 全局 =====
    Interceptor.attach(base.add(0x1418F0), {
        onEnter: function(args) {
            var dst = args[0];
            // 检查 dst 是否在 u 全局附近 (24字节 SSO struct)
            var diff = dst.sub(uAddr).toInt32();
            if (diff >= 0 && diff < 24) {
                this.isU = true;
                this.len = args[2].toInt32();
                try {
                    this.val = args[1].readUtf8String(this.len > 128 ? 128 : this.len);
                } catch(e) { this.val = hexDump(args[1], this.len > 64 ? 64 : this.len); }
                console.log("\n★★★ STRING_ASSIGN → U GLOBAL ★★★");
                console.log("  dst: " + dst + " (offset " + diff + " into SSO)");
                console.log("  len: " + this.len);
                console.log("  value: " + this.val);
                console.log("  backtrace: " + bt(this.context));
            }
        }
    });

    // ===== 2. Hook sub_141600 (str_copy) — 检查 dst 是否为 u 全局 =====
    Interceptor.attach(base.add(0x141600), {
        onEnter: function(args) {
            var dst = args[0];
            var diff = dst.sub(uAddr).toInt32();
            if (diff >= 0 && diff < 24) {
                var src = readSSO(args[1]);
                console.log("\n★★★ STR_COPY → U GLOBAL ★★★");
                console.log("  dst: " + dst);
                console.log("  src value: " + src);
                console.log("  backtrace: " + bt(this.context));
            }
        }
    });

    // ===== 3. Hook memcpy — 检查 dst 是否为 u 全局 =====
    var memcpy = Module.findExportByName(null, "memcpy");
    Interceptor.attach(memcpy, {
        onEnter: function(args) {
            var dst = args[0];
            var diff = dst.sub(uAddr).toInt32();
            if (diff >= -8 && diff < 32) {
                var size = args[2].toInt32();
                console.log("\n★★★ MEMCPY → U GLOBAL area ★★★");
                console.log("  dst: " + dst + " (offset " + diff + ")");
                console.log("  size: " + size);
                if (size <= 128) console.log("  data: " + hexDump(args[1], size));
                console.log("  backtrace: " + bt(this.context));
            }
        }
    });

    // ===== 4. 高频轮询 — 检测 u 值出现 =====
    var lastBytes = hexDump(uAddr, 24);
    var pollStart = Date.now();
    var pollCount = 0;
    var poller = setInterval(function() {
        pollCount++;
        var cur = hexDump(uAddr, 24);
        if (cur !== lastBytes) {
            var elapsed = Date.now() - pollStart;
            console.log("\n★ SSO CHANGED @ " + elapsed + "ms (poll #" + pollCount + ") ★");
            console.log("  old: " + lastBytes);
            console.log("  new: " + cur);
            var sso = readSSO(uAddr);
            console.log("  SSO: " + sso);
            lastBytes = cur;

            if (sso && sso.length === 40 && sso.match(/^[0-9a-f]{40}$/)) {
                console.log("\n★★★★★ U VALUE SET: " + sso + " ★★★★★");
                uFound = true;
                clearInterval(poller);
            }
        }
    }, 1); // 1ms 轮询

    // 超时
    setTimeout(function() {
        clearInterval(poller);
        console.log("\n======== FINAL ========");
        console.log("u found: " + uFound);
        console.log("SSO: " + readSSO(uAddr));
        console.log("bytes: " + hexDump(uAddr, 24));
    }, 30000);
});
