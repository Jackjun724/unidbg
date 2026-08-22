/*
 * hook_u_trace.js
 *
 * 追踪 u 字段的完整计算流程
 *
 * 策略:
 *   1. Hook sub_470130 (hex编码器) — 找到哪次调用产生40字符(20字节)的u值
 *   2. Hook map_insert 0x28C7E8 — 捕获 key="u" 时的 backtrace
 *   3. Hook byte_reader 0x172278 — 捕获 u 的最终值
 *   4. Hook sub_205E0C 附近 — 追踪 PackageInfo → VM state 的数据拷贝
 *
 * Usage: conda activate py3.8 && frida -U -f com.xingin.xhs -l hooks/hook_u_trace.js --no-pause
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

function hexBytes(ptr, len) {
    var arr = ptr.readByteArray(len);
    return Array.from(new Uint8Array(arr)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function readSSOString(ptr) {
    if (ptr.isNull()) return "<null>";
    var firstByte = ptr.readU8();
    if ((firstByte & 1) === 0) {
        var len = firstByte >>> 1;
        if (len === 0) return "";
        return ptr.add(1).readUtf8String(len);
    } else {
        var len = ptr.add(8).readU64();
        var dataPtr = ptr.add(16).readPointer();
        return dataPtr.readUtf8String(parseInt(len));
    }
}

function bt(ctx) {
    return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(function(addr) {
            return "0x" + addr.sub(base).toString(16);
        }).join(" → ");
}

waitForLibtiny().then(function(base) {
    console.log("\n======== U FIELD TRACE ========\n");

    // ===== 1. Hook sub_470130 (hex编码器) =====
    // 找所有hex编码调用，特别关注 size=20 的调用（u字段是20字节→40hex）
    var hexEncodeCount = 0;
    Interceptor.attach(base.add(0x470130), {
        onEnter: function(args) {
            this.buf = args[0];
            this.size = args[1].toInt32();
            hexEncodeCount++;
        },
        onLeave: function(retval) {
            var size = this.size;
            // 记录所有调用，重点标记 size=20
            var marker = (size === 20) ? " ★★★ U FIELD ★★★" : "";
            console.log("[HEX_ENCODE #" + hexEncodeCount + "] size=" + size + marker);
            if (size <= 64 && size > 0) {
                console.log("  input_raw: " + hexBytes(this.buf, size));
                // 读取输出的SSO string
                try {
                    var result = readSSOString(this.buf);
                    console.log("  output_hex: " + result);
                } catch(e) {}
            }
            console.log("  backtrace: " + bt(this.context));
        }
    });

    // ===== 2. Hook map_insert 0x28C7E8 =====
    // 捕获所有header字段的插入，特别关注 key="u"
    var headerPhase = false;
    Interceptor.attach(base.add(0x28C7E8), {
        onEnter: function(args) {
            // args[0] = map, args[1] = key SSO string pointer
            try {
                var key = readSSOString(args[1]);
                if (key === "a") headerPhase = true;

                if (headerPhase) {
                    console.log("[MAP_INSERT] key=\"" + key + "\"");
                    if (key === "u") {
                        console.log("  ★★★ U KEY INSERTED ★★★");
                        console.log("  backtrace: " + bt(this.context));
                        // 打印 args[1] 附近的数据，查看 value
                        console.log("  key_ptr: " + args[1]);
                    }
                }
            } catch(e) {}
        }
    });

    // ===== 3. Hook sub_205E0C (PackageInfo → VM state) =====
    // 追踪哪些 PackageInfo 字段被拷贝到 VM state
    Interceptor.attach(base.add(0x205E0C), {
        onEnter: function(args) {
            console.log("\n[sub_205E0C] PackageInfo → VM state copy started");
            // X19 = VM state pointer
            var x19 = this.context.x19;
            console.log("  X19 (VM state): " + x19);

            // 读取 xmmword_7B6D50 (PackageInfo struct)
            var pkgInfo = base.add(0x7B6D50);
            console.log("  PackageInfo @ " + pkgInfo);

            // Dump PackageInfo 的 SSO strings
            for (var offset = 0; offset <= 128; offset += 24) {
                try {
                    var s = readSSOString(pkgInfo.add(offset));
                    if (s.length > 0) {
                        console.log("  [offset " + offset + "] = \"" + s + "\"");
                    }
                } catch(e) {
                    console.log("  [offset " + offset + "] = <non-string: " + hexBytes(pkgInfo.add(offset), 8) + ">");
                }
            }
            // Dump raw bytes for numeric fields
            console.log("  [offset 72-99] raw: " + hexBytes(pkgInfo.add(72), 28));
        }
    });

    // ===== 4. Hook sub_141600 (str_copy) 在 sub_205E0C 内部的调用 =====
    // 追踪具体拷贝了哪些字符串
    var in205E0C = false;
    Interceptor.attach(base.add(0x205E0C), {
        onEnter: function() { in205E0C = true; },
        onLeave: function() { in205E0C = false; }
    });

    Interceptor.attach(base.add(0x141600), {
        onEnter: function(args) {
            if (in205E0C) {
                try {
                    var src = readSSOString(args[1]);
                    console.log("  [STR_COPY] dst=" + args[0] + " src=\"" + src + "\"");
                } catch(e) {}
            }
        }
    });

    // ===== 5. Hook byte_7B77E8 读取 — 确认安全检测标志 =====
    // 在 sub_1B5E84 中，LDRB W8, [X8, #byte_7B77E8] 决定是否生成 t/u
    var flagAddr = base.add(0x7B77E8);
    console.log("[+] byte_7B77E8 @ " + flagAddr + " = " + flagAddr.readU8());

    // ===== 6. Hook vm_dispatch_15BF1C — 捕获所有key名解密 =====
    // 找到 "u" key 的加密种子字节
    Interceptor.attach(base.add(0x15BF1C), {
        onEnter: function(args) {
            this.buf = args[0];
            this.len = args[1].toInt32();
        },
        onLeave: function(retval) {
            if (this.len > 0 && this.len <= 4) {
                try {
                    var decrypted = this.buf.readUtf8String(this.len);
                    if (decrypted === "u") {
                        console.log("\n[vm_dispatch_15BF1C] ★★★ Decrypted key = \"u\" ★★★");
                        console.log("  len=" + this.len);
                        console.log("  backtrace: " + bt(this.context));
                    }
                } catch(e) {}
            }
        }
    });

    // ===== 7. Hook sub_1F95D4 入口/出口 =====
    Interceptor.attach(base.add(0x1F95D4), {
        onEnter: function(args) {
            console.log("\n[sub_1F95D4] ▶ t field builder ENTER");
            console.log("  X19: " + this.context.x19);
            console.log("  X27 (v3/security flag): " + this.context.x27);
        },
        onLeave: function(retval) {
            console.log("[sub_1F95D4] ◀ t field builder EXIT\n");
        }
    });

    // ===== 8. Hook sub_51F9E4 (安全检测) =====
    Interceptor.attach(base.add(0x51F9E4), {
        onEnter: function(args) {
            console.log("[sub_51F9E4] Security detection called");
            this.a7 = args[6]; // detection type output
            this.a8 = args[7]; // status output
        },
        onLeave: function(retval) {
            try {
                console.log("  type=" + this.a7.readS32() + " status=" + this.a8.readS32());
            } catch(e) {}
        }
    });

    // ===== 9. Hook sub_520B4C (第二组安全检测) =====
    Interceptor.attach(base.add(0x520B4C), {
        onEnter: function(args) {
            console.log("[sub_520B4C] Security detection #2 called");
        }
    });

    console.log("[+] All hooks installed. Make an API request to trigger MUA generation...");
    console.log("[+] byte_7B77E8 current value: " + flagAddr.readU8());
});
