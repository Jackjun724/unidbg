// 精准追踪 y1 MMKV 读取 → 指纹字段映射
// 策略：hook getBytes包装函数 + 追踪同线程后续map_insert
// 用法: conda activate py3.8 && frida -U -f com.xingin.xhs -l hooks/hook_y1_field.js --no-pause

var offsets = {
    mmkv_getValueSize: 0x354E0,  // libmmkv2.so
    mmkv_getBytes:     0x3561C,  // libmmkv2.so
    map_insert:        0x28C7E8, // libtiny.so
    // getBytes 包装函数 - 这个是从 vm 调用 mmkv 的函数
    vm_getBytes:       0x2F4414, // libtiny.so vm_call_unk_2F4414
    vm_getValueSize:   0x2F43D0, // libtiny.so vm_call_unk_2F43D0
};

function readCStr(ptr) {
    if (ptr.isNull()) return "<null>";
    try { return ptr.readUtf8String(); } catch(e) { return "<err>"; }
}

var trackingY1 = false;
var y1Thread = 0;
var mapInsertAfterY1 = [];

var hooked = false;
function hookAll() {
    if (hooked) return;
    var mmkvBase = Module.findBaseAddress("libmmkv2.so");
    var tinyBase = Module.findBaseAddress("libtiny.so");
    if (!mmkvBase || !tinyBase) return;
    hooked = true;

    console.log("[*] libtiny.so base: " + tinyBase);
    console.log("[*] libmmkv2.so base: " + mmkvBase);

    // Hook all MMKV getValueSize calls
    Interceptor.attach(mmkvBase.add(offsets.mmkv_getValueSize), {
        onEnter: function(args) {
            this.key = readCStr(args[1]);
        },
        onLeave: function(ret) {
            console.log("[mmkv] getValueSize(\"" + this.key + "\") => " + ret.toInt32());
            if (this.key === "y1") {
                trackingY1 = true;
                y1Thread = Process.getCurrentThreadId();
                mapInsertAfterY1 = [];
                console.log("[!] y1 detected! Tracking thread " + y1Thread);
            }
        }
    });

    // Hook MMKV getBytes
    Interceptor.attach(mmkvBase.add(offsets.mmkv_getBytes), {
        onEnter: function(args) {
            this.key = readCStr(args[1]);
            this.bufSize = args[3].toInt32();
        },
        onLeave: function(ret) {
            if (this.key === "y1") {
                console.log("[!] y1 getBytes => " + this.bufSize + " bytes, ret=" + ret.toInt32());
            }
        }
    });

    // Hook map_insert - track keys after y1 read
    Interceptor.attach(tinyBase.add(offsets.map_insert), {
        onEnter: function(args) {
            this.key = readCStr(args[1]);
        },
        onLeave: function(ret) {
            if (trackingY1 && Process.getCurrentThreadId() === y1Thread) {
                mapInsertAfterY1.push(this.key);
                console.log("[!! POST-Y1 !!] map_insert key=\"" + this.key + "\" (#" + mapInsertAfterY1.length + ")");
                // After 10 inserts, stop tracking
                if (mapInsertAfterY1.length >= 10) {
                    console.log("[!] First 10 map_inserts after y1: " + JSON.stringify(mapInsertAfterY1));
                    trackingY1 = false;
                }
            }
        }
    });

    // Also hook ALL MMKV key reads to track order
    // and detect which key is read BEFORE y1 and which AFTER
    var lastMmkvKey = "";
    Interceptor.attach(mmkvBase.add(offsets.mmkv_getValueSize), {
        onEnter: function(args) {},
        onLeave: function(ret) {
            // We already handle this above
        }
    });

    console.log("[*] Hooks installed, waiting for y1...");
}

["android_dlopen_ext", "dlopen"].forEach(function(fname) {
    var addr = Module.findExportByName(null, fname);
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function(args) { this.path = args[0].isNull() ? "" : args[0].readUtf8String(); },
        onLeave: function(ret) {
            if (this.path && this.path.indexOf("libmmkv2.so") !== -1) hookAll();
            if (this.path && this.path.indexOf("libtiny.so") !== -1) hookAll();
        }
    });
});
hookAll();
