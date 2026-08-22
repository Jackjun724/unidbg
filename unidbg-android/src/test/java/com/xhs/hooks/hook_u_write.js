/*
 * hook_u_write.js
 *
 * 轻量级 hook: 只监控 string_assign (0x1418F0) 找 u 值的首次创建
 * 避免 hook str_copy 导致崩溃
 *
 * Usage: conda activate py3.8 && frida -U -f com.xingin.xhs -l hooks/hook_u_write.js --no-pause
 */

var libtiny = null;
var base = null;

function waitForLibtiny() {
    return new Promise(function(resolve) {
        var check = setInterval(function() {
            libtiny = Module.findBaseAddress("libtiny.so");
            if (libtiny) {
                clearInterval(check);
                base = libtiny;
                console.log("[+] libtiny.so base: " + base);
                resolve(base);
            }
        }, 100);
    });
}

function bt(ctx) {
    return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(function(addr) {
            var off = addr.sub(base);
            return "0x" + off.toString(16);
        }).join(" → ");
}

waitForLibtiny().then(function(base) {
    console.log("\n======== U WRITE MONITOR ========\n");

    var uWriteCount = 0;

    // ===== Hook sub_1418F0 (string_assign) =====
    // 签名: string_assign(sso_string* dst, const char* data, size_t len)
    Interceptor.attach(base.add(0x1418F0), {
        onEnter: function(args) {
            this.len = args[2].toInt32();
            if (this.len === 40) {
                try {
                    var s = args[1].readUtf8String(40);
                    if (s && s.match(/^[0-9a-f]{40}$/)) {
                        uWriteCount++;
                        console.log("\n[STRING_ASSIGN #" + uWriteCount + "] ★ U-like value ★");
                        console.log("  value: " + s);
                        console.log("  dst: " + args[0] + " (offset 0x" + args[0].sub(base).toString(16) + ")");
                        console.log("  backtrace: " + bt(this.context));
                        // Print all registers for context
                        console.log("  X19=" + this.context.x19 + " X20=" + this.context.x20);
                        console.log("  X21=" + this.context.x21 + " X22=" + this.context.x22);
                    }
                } catch(e) {}
            }
        }
    });

    // ===== Hook sub_470130 (hex_encode) 只看 size ≤ 20 =====
    Interceptor.attach(base.add(0x470130), {
        onEnter: function(args) {
            this.size = args[1].toInt32();
        },
        onLeave: function(retval) {
            if (this.size === 20 || this.size === 16 || this.size === 4) {
                console.log("[HEX_ENCODE] size=" + this.size + " bt: " + bt(this.context));
            }
        }
    });

    // ===== 直接搜索 nibble→hex 手动转换 =====
    // 如果 u 不通过 sub_470130, 可能通过 sprintf("%02x", ...) 或手动循环
    // Hook sprintf 只看 len=40 output
    var sprintf = Module.findExportByName(null, "sprintf");
    if (sprintf) {
        Interceptor.attach(sprintf, {
            onEnter: function(args) {
                this.buf = args[0];
                try {
                    this.fmt = args[1].readUtf8String(10);
                } catch(e) { this.fmt = ""; }
            },
            onLeave: function(retval) {
                if (retval.toInt32() === 40 && this.fmt.indexOf("x") >= 0) {
                    try {
                        var s = this.buf.readUtf8String(40);
                        if (s && s.match(/^[0-9a-f]{40}$/)) {
                            console.log("\n[SPRINTF] ★ U VALUE via sprintf ★");
                            console.log("  value: " + s);
                            console.log("  format: " + this.fmt);
                            console.log("  backtrace: " + bt(this.context));
                        }
                    } catch(e) {}
                }
            }
        });
    }

    // ===== 监控 memcpy 大小 = 40 或 41 (含null) =====
    var memcpy = Module.findExportByName(null, "memcpy");
    if (memcpy) {
        Interceptor.attach(memcpy, {
            onEnter: function(args) {
                var size = args[2].toInt32();
                if (size === 40 || size === 41) {
                    try {
                        var s = args[1].readUtf8String(40);
                        if (s && s.match(/^[0-9a-f]{40}$/)) {
                            console.log("\n[MEMCPY] ★ U VALUE via memcpy ★");
                            console.log("  value: " + s);
                            console.log("  src: " + args[1]);
                            console.log("  dst: " + args[0]);
                            console.log("  backtrace: " + bt(this.context));
                        }
                    } catch(e) {}
                }
            }
        });
    }

    console.log("[+] Monitoring... waiting for u value creation");
});
