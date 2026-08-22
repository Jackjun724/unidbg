// 追踪 y1 数据的处理过程
// 策略：hook getBytes返回后，在关键处理函数入口/出口打log
// 用法: conda activate py3.8 && frida -U -f com.xingin.xhs -l hooks/hook_y1_process.js --no-pause

function readCStr(ptr) {
    if (ptr.isNull()) return "<null>";
    try { return ptr.readUtf8String(); } catch(e) { return "<err>"; }
}

function hexdump_short(ptr, len) {
    if (ptr.isNull() || len <= 0) return "";
    var show = Math.min(len, 64);
    var bytes = ptr.readByteArray(show);
    return Array.from(new Uint8Array(bytes)).map(b => ('0'+b.toString(16)).slice(-2)).join(' ');
}

var hooked = false;
function hookAll() {
    if (hooked) return;
    var mmkvBase = Module.findBaseAddress("libmmkv2.so");
    var tinyBase = Module.findBaseAddress("libtiny.so");
    if (!mmkvBase || !tinyBase) return;
    hooked = true;

    console.log("[*] libtiny.so: " + tinyBase);

    var y1Buf = null;
    var y1Size = 0;

    // Hook mmkv_getBytes
    Interceptor.attach(mmkvBase.add(0x3561C), {
        onEnter: function(args) {
            this.key = readCStr(args[1]);
            this.outBuf = args[2];
            this.bufSize = args[3].toInt32();
        },
        onLeave: function(ret) {
            if (this.key === "y1" && ret.toInt32() === 1) {
                y1Buf = this.outBuf;
                y1Size = this.bufSize;
                var count = y1Buf.readU32();
                console.log("\n[!] y1 read: " + y1Size + " bytes, " + count + " entries, buf=" + y1Buf);

                // Parse all entries to understand the data
                var pos = 4;
                for (var i = 0; i < count && pos < y1Size - 4; i++) {
                    var pkgLen = y1Buf.add(pos).readU16(); pos += 2;
                    var pkg = y1Buf.add(pos).readUtf8String(pkgLen); pos += pkgLen;
                    var status = y1Buf.add(pos).readS32(); pos += 4;
                    var labelLen = y1Buf.add(pos).readU16(); pos += 2;
                    var label = y1Buf.add(pos).readUtf8String(labelLen); pos += labelLen;
                    console.log("  [" + i + "] " + pkg + " (" + label + ") status=" + status);
                }
            }
        }
    });

    // Hook sub_70C904 - 处理结果 & 1
    Interceptor.attach(tinyBase.add(0x70C904), {
        onEnter: function(args) {
            if (y1Buf) console.log("[sub_70C904] enter (y1 processing chain)");
        },
        onLeave: function(ret) {
            if (y1Buf) {
                console.log("[sub_70C904] leave => " + ret + " (&1 = " + (ret.toInt32() & 1) + ")");
            }
        }
    });

    // Hook sub_66750C - 直接包含 y1 字符串引用
    Interceptor.attach(tinyBase.add(0x66750C), {
        onEnter: function(args) {
            if (y1Buf) console.log("[sub_66750C] enter (y1 string reference)");
        },
        onLeave: function(ret) {
            if (y1Buf) console.log("[sub_66750C] leave => " + ret);
        }
    });

    // Hook sub_2A8CC4 - 外层函数
    Interceptor.attach(tinyBase.add(0x2A8CC4), {
        onEnter: function(args) {
            console.log("\n[sub_2A8CC4] enter - orchestrator function");
        },
        onLeave: function(ret) {
            console.log("[sub_2A8CC4] leave => " + ret);
            if (y1Buf) {
                console.log("[!] y1 was processed during this call");
                y1Buf = null; // reset
            }
        }
    });

    // Hook map_insert - 只在 y1 有效时追踪
    Interceptor.attach(tinyBase.add(0x28C7E8), {
        onEnter: function(args) {
            this.key = readCStr(args[1]);
            this.isY1Active = (y1Buf !== null);
        },
        onLeave: function(ret) {
            if (this.isY1Active) {
                console.log("[Y1-ctx] map_insert key=\"" + this.key + "\"");
            }
        }
    });

    // Hook sub_47A5D0 - 收集已安装应用的函数
    Interceptor.attach(tinyBase.add(0x47A5D0), {
        onEnter: function(args) {
            console.log("[sub_47A5D0] enter - app collection function");
        },
        onLeave: function(ret) {
            console.log("[sub_47A5D0] leave => " + ret);
        }
    });

    // Hook all MMKV getValueSize to track order
    Interceptor.attach(mmkvBase.add(0x354E0), {
        onEnter: function(args) { this.key = readCStr(args[1]); },
        onLeave: function(ret) {
            console.log("[mmkv] getValueSize(\"" + this.key + "\") => " + ret.toInt32());
        }
    });

    console.log("[*] All hooks installed, waiting...");
}

["android_dlopen_ext", "dlopen"].forEach(function(fname) {
    var addr = Module.findExportByName(null, fname);
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function(args) { this.path = args[0].isNull() ? "" : args[0].readUtf8String(); },
        onLeave: function(ret) {
            if (this.path && (this.path.indexOf("libtiny.so") !== -1 || this.path.indexOf("libmmkv2.so") !== -1)) hookAll();
        }
    });
});
hookAll();
