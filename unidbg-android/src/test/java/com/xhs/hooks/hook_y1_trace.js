// 追踪 y1 MMKV 读取后生成哪些指纹字段
// 用法: conda activate py3.8 && frida -U -f com.xingin.xhs -l hooks/hook_y1_trace.js --no-pause

var offsets = {
    mmkv_getValueSize: 0x354E0,  // libmmkv2.so
    mmkv_getBytes:     0x3561C,  // libmmkv2.so
    map_insert:        0x28C7E8, // libtiny.so - SSO key → RB-tree 插入
    sub_2A8CC4:        0x2A8CC4, // libtiny.so - y1 外层调用函数
};

function readCStr(ptr) {
    if (ptr.isNull()) return "<null>";
    try { return ptr.readUtf8String(); } catch(e) { return "<err>"; }
}

function readSSOString(ptr) {
    // SSO std::string: if (byte0 & 1) → heap, else inline
    var byte0 = ptr.readU8();
    if (byte0 & 1) {
        // heap allocated: [capacity|1, size, data_ptr]
        var size = ptr.add(8).readU64();
        var dataPtr = ptr.add(16).readPointer();
        if (size > 0 && size < 1000) {
            try { return dataPtr.readUtf8String(size); } catch(e) { return "<heap-err>"; }
        }
        return "<heap-size=" + size + ">";
    } else {
        // inline: byte0 = 2*len, data at byte1..
        var len = byte0 >> 1;
        if (len > 0 && len < 23) {
            try { return ptr.add(1).readUtf8String(len); } catch(e) { return "<inline-err>"; }
        }
        return "<inline-len=" + len + ">";
    }
}

var y1Reading = false;
var y1ReadTime = 0;
var mapInsertHooked = false;

function hookAll() {
    var mmkvBase = Module.findBaseAddress("libmmkv2.so");
    var tinyBase = Module.findBaseAddress("libtiny.so");
    if (!mmkvBase || !tinyBase) return;

    console.log("[*] libmmkv2.so base: " + mmkvBase);
    console.log("[*] libtiny.so base: " + tinyBase);

    // Hook mmkv_getValueSize
    Interceptor.attach(mmkvBase.add(offsets.mmkv_getValueSize), {
        onEnter: function(args) {
            this.key = readCStr(args[1]);
        },
        onLeave: function(ret) {
            if (this.key === "y1") {
                console.log("\n[!] === y1 getValueSize => " + ret.toInt32() + " ===");
                y1Reading = true;
                y1ReadTime = Date.now();
            }
        }
    });

    // Hook mmkv_getBytes
    Interceptor.attach(mmkvBase.add(offsets.mmkv_getBytes), {
        onEnter: function(args) {
            this.key = readCStr(args[1]);
            this.outBuf = args[2];
            this.bufSize = args[3].toInt32();
        },
        onLeave: function(ret) {
            if (this.key === "y1" && ret.toInt32() === 1) {
                // Parse y1 data structure
                var count = this.outBuf.readU32();
                console.log("[!] y1 getBytes => " + this.bufSize + " bytes, " + count + " entries");

                // Parse first few entries
                var pos = 4;
                for (var i = 0; i < Math.min(count, 5); i++) {
                    var pkgLen = this.outBuf.add(pos).readU16();
                    pos += 2;
                    var pkg = this.outBuf.add(pos).readUtf8String(pkgLen);
                    pos += pkgLen;
                    var status = this.outBuf.add(pos).readS32();
                    pos += 4;
                    var labelLen = this.outBuf.add(pos).readU16();
                    pos += 2;
                    var label = this.outBuf.add(pos).readUtf8String(labelLen);
                    pos += labelLen;
                    console.log("  [" + i + "] pkg=" + pkg + " status=" + status + " label=" + label);
                }
                console.log("  ... (" + (count - 5) + " more)");
            }
        }
    });

    // Hook map_insert - track all insertions, highlight those near y1 read
    // args: (map_ptr, char* key) - key is raw C string
    if (!mapInsertHooked) {
        mapInsertHooked = true;
        Interceptor.attach(tinyBase.add(offsets.map_insert), {
            onEnter: function(args) {
                this.mapPtr = args[0];
                this.key = readCStr(args[1]);
            },
            onLeave: function(ret) {
                var timeSinceY1 = Date.now() - y1ReadTime;
                var prefix = (y1Reading && timeSinceY1 < 2000) ? "[!! Y1 !!]" : "[map]";
                console.log(prefix + " key=\"" + this.key + "\"");

                if (y1Reading && timeSinceY1 > 5000) {
                    y1Reading = false;
                }
            }
        });
    }

    // Hook sub_2A8CC4 - the outer function that processes y1
    Interceptor.attach(tinyBase.add(offsets.sub_2A8CC4), {
        onEnter: function(args) {
            console.log("[sub_2A8CC4] enter - a1=" + args[0]);
        },
        onLeave: function(ret) {
            console.log("[sub_2A8CC4] leave => " + ret);
        }
    });

    console.log("[*] All hooks installed");
}

var hooked = false;
["android_dlopen_ext", "dlopen"].forEach(function(fname) {
    var addr = Module.findExportByName(null, fname);
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function(args) { this.path = args[0].isNull() ? "" : args[0].readUtf8String(); },
        onLeave: function(ret) {
            if (!hooked && this.path && (this.path.indexOf("libtiny.so") !== -1 || this.path.indexOf("libmmkv2.so") !== -1)) {
                var t = Module.findBaseAddress("libtiny.so");
                var m = Module.findBaseAddress("libmmkv2.so");
                if (t && m) { hooked = true; hookAll(); }
            }
        }
    });
});
if (Module.findBaseAddress("libtiny.so") && Module.findBaseAddress("libmmkv2.so")) {
    hooked = true;
    hookAll();
}
