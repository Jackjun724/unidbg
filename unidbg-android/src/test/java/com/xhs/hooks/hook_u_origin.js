/*
 * hook_u_origin.js
 *
 * 追踪 u 值 "000000007c5136f2cc1bf608898e780f02141ecf" 的首次生成
 *
 * 发现: u 值不经过 sub_470130 hex编码器，作为完整字符串传递
 * 策略: hook string_assign/str_copy 捕获首次出现 + backtrace
 *
 * Usage: conda activate py3.8 && frida -U -f com.xingin.xhs -l hooks/hook_u_origin.js --no-pause
 */

var libtiny = null;
var base = null;
var uFound = false;

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

function readSSOString(ptr) {
    if (ptr.isNull()) return null;
    try {
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
    } catch(e) {
        return null;
    }
}

function bt(ctx) {
    return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(function(addr) {
            return "0x" + addr.sub(base).toString(16);
        }).join(" → ");
}

function hexBytes(ptr, len) {
    var arr = ptr.readByteArray(len);
    return Array.from(new Uint8Array(arr)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// 检查字符串是否匹配 u 值模式: 40个hex字符，前8个是0
function isUValue(s) {
    if (!s || s.length !== 40) return false;
    if (!s.match(/^[0-9a-f]{40}$/)) return false;
    return true;
}

waitForLibtiny().then(function(base) {
    console.log("\n======== U VALUE ORIGIN TRACE ========\n");

    var uValueCount = 0;
    var firstUBacktrace = null;

    // ===== 1. Hook sub_141600 (str_copy) — 捕获 u 值的 SSO string 拷贝 =====
    Interceptor.attach(base.add(0x141600), {
        onEnter: function(args) {
            var src = readSSOString(args[1]);
            if (src && isUValue(src)) {
                uValueCount++;
                console.log("\n[STR_COPY #" + uValueCount + "] ★ U VALUE FOUND ★");
                console.log("  value: " + src);
                console.log("  dst: " + args[0]);
                console.log("  src: " + args[1]);
                console.log("  backtrace: " + bt(this.context));
                if (uValueCount === 1) {
                    firstUBacktrace = bt(this.context);
                }
            }
        }
    });

    // ===== 2. Hook sub_1418F0 (string_assign) — 另一个字符串赋值路径 =====
    Interceptor.attach(base.add(0x1418F0), {
        onEnter: function(args) {
            // string_assign(dst, data_ptr, len)
            var len = args[2].toInt32();
            if (len === 40) {
                try {
                    var s = args[1].readUtf8String(40);
                    if (isUValue(s)) {
                        uValueCount++;
                        console.log("\n[STRING_ASSIGN #" + uValueCount + "] ★ U VALUE FOUND ★");
                        console.log("  value: " + s);
                        console.log("  dst: " + args[0]);
                        console.log("  backtrace: " + bt(this.context));
                    }
                } catch(e) {}
            }
        }
    });

    // ===== 3. Hook nibble-to-hex 循环 sub_4701A0 直接 — 找任何20字节的hex编码 =====
    // sub_4701A0 是 sub_470130 内部的实际hex循环
    Interceptor.attach(base.add(0x4701A0), {
        onEnter: function(args) {
            // 从 sub_470130 的上下文中获取参数
            // sub_470130 调用 sub_4701A0 时参数已经在不同寄存器
            // 直接打印所有调用
        }
    });

    // ===== 4. Hook vm_dispatch_2B7A90 (安全检测初始化，设置 byte_7B77E8) =====
    Interceptor.attach(base.add(0x2B7A90), {
        onEnter: function(args) {
            console.log("[vm_dispatch_2B7A90] Security init called");
            console.log("  backtrace: " + bt(this.context));
        },
        onLeave: function(retval) {
            var flag = base.add(0x7B77E8).readU8();
            console.log("[vm_dispatch_2B7A90] returned, byte_7B77E8 = " + flag);
        }
    });

    // ===== 5. Hook sprintf/snprintf — 检查是否通过格式化生成 u 值 =====
    var snprintf = Module.findExportByName(null, "snprintf");
    if (snprintf) {
        Interceptor.attach(snprintf, {
            onLeave: function(retval) {
                var len = retval.toInt32();
                if (len === 40) {
                    try {
                        // this.context 不一定有 x0，但 retval 是返回值
                        // snprintf 的第一个参数是 buf
                        var buf = this.context.x0;
                        if (buf) {
                            var s = ptr(buf).readUtf8String(40);
                            if (isUValue(s)) {
                                console.log("\n[SNPRINTF] ★ U VALUE via snprintf ★");
                                console.log("  value: " + s);
                                console.log("  backtrace: " + bt(this.context));
                            }
                        }
                    } catch(e) {}
                }
            }
        });
    }

    // ===== 6. Hook sub_2B7CC8 (xmmword_7B6D50 初始化) =====
    Interceptor.attach(base.add(0x2B7CC8), {
        onEnter: function(args) {
            console.log("[sub_2B7CC8] PackageInfo struct init @ " + args[0]);
        },
        onLeave: function(retval) {
            // Dump部分PackageInfo
            var pkgInfo = base.add(0x7B6D50);
            console.log("  After init:");
            for (var off = 0; off <= 128; off += 24) {
                var s = readSSOString(pkgInfo.add(off));
                if (s && s.length > 0) {
                    console.log("    [" + off + "] = \"" + s + "\"");
                }
            }
        }
    });

    // ===== 7. Hook sub_2E17A0 (PackageInfo 字段提取器) =====
    Interceptor.attach(base.add(0x2E17A0), {
        onEnter: function(args) {
            console.log("\n[sub_2E17A0] PackageInfo extractor called");
        },
        onLeave: function(retval) {
            console.log("[sub_2E17A0] returned");
            // 检查 offset 24 (processName)
            var pkgInfo = base.add(0x7B6D50);
            var procName = readSSOString(pkgInfo.add(24));
            console.log("  processName [+24]: " + procName);
        }
    });

    // ===== 8. 监控 byte_7B77E8 的写入 =====
    // 使用 Memory.patchCode 在 byte_7B77E8 附近设置监控
    var flagAddr = base.add(0x7B77E8);
    console.log("[+] byte_7B77E8 @ " + flagAddr + " initial = " + flagAddr.readU8());

    // 定期检查 flag 变化
    var lastFlag = flagAddr.readU8();
    var flagCheck = setInterval(function() {
        var cur = flagAddr.readU8();
        if (cur !== lastFlag) {
            console.log("\n★ byte_7B77E8 CHANGED: " + lastFlag + " → " + cur + " ★");
            lastFlag = cur;
        }
    }, 50);

    // 30秒后停止检查
    setTimeout(function() {
        clearInterval(flagCheck);
        console.log("\n======== SUMMARY ========");
        console.log("U value appearances: " + uValueCount);
        if (firstUBacktrace) {
            console.log("First backtrace: " + firstUBacktrace);
        }
        console.log("byte_7B77E8 final: " + flagAddr.readU8());
    }, 30000);

    console.log("[+] All hooks installed. Waiting...");
});
