// Hook libmmkv2.so 6个MMKV native函数
// 用法: frida -U -f com.xingin.xhs -l hook_mmkv.js --no-pause

var offsets = {
    mmkv_open:         0x34EB4,  // (name, mode_str, crypto_key, root_path) → instance
    mmkv_set:          0x3534C,  // (instance, key, data_ptr, data_size) → bool
    mmkv_getValueSize: 0x354E0,  // (instance, key) → int
    mmkv_getBytes:     0x3561C,  // (instance, key, out_buf, buf_size) → bool
    mmkv_removeKey:    0x357BC,  // (instance, key) → void
    mmkv_lock:         0x358CC   // (instance, flag) → void
};

function readCStr(ptr) {
    if (ptr.isNull()) return "<null>";
    try { return ptr.readUtf8String(); } catch(e) { return "<err>"; }
}

function hexdump_short(ptr, len) {
    if (ptr.isNull() || len <= 0) return "";
    var show = Math.min(len, 64);
    var bytes = ptr.readByteArray(show);
    var hex = Array.from(new Uint8Array(bytes)).map(b => ('0' + b.toString(16)).slice(-2)).join(' ');
    return hex + (len > 64 ? " ..." : "");
}

var hooked = false;
function hookIfNeeded() {
    if (hooked) return;
    var base = Module.findBaseAddress("libmmkv2.so");
    if (!base) return;
    hooked = true;
    hookMMKV(base);
}

// dlopen hook
["android_dlopen_ext", "dlopen"].forEach(function(fname) {
    var addr = Module.findExportByName(null, fname);
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function(args) {
            this.path = args[0].isNull() ? "" : args[0].readUtf8String();
        },
        onLeave: function(ret) {
            if (this.path && this.path.indexOf("libmmkv2.so") !== -1) {
                hookIfNeeded();
            }
        }
    });
});

// 如果已经加载了，直接hook
hookIfNeeded();

function hookMMKV(base) {
    console.log("[*] libmmkv2.so base: " + base);

    // [0] mmkv_open(name, mode_str, crypto_key, root_path) → instance
    Interceptor.attach(base.add(offsets.mmkv_open), {
        onEnter: function(args) {
            this.name = readCStr(args[0]);
            this.mode = readCStr(args[1]);
            this.crypto = readCStr(args[2]);
            this.root = readCStr(args[3]);
        },
        onLeave: function(ret) {
            console.log("[mmkv_open] name=\"" + this.name + "\" mode=\"" + this.mode +
                        "\" crypto=\"" + this.crypto + "\" root=\"" + this.root +
                        "\" => " + ret);
        }
    });

    // [1] mmkv_set(instance, key, data_ptr, data_size) → bool
    Interceptor.attach(base.add(offsets.mmkv_set), {
        onEnter: function(args) {
            this.inst = args[0];
            this.key = readCStr(args[1]);
            this.dataPtr = args[2];
            this.dataSize = args[3].toInt32();
        },
        onLeave: function(ret) {
            var detail = "";
            if (!this.dataPtr.isNull() && this.dataSize > 0) {
                detail = " data=[" + hexdump_short(this.dataPtr, this.dataSize) + "]";
            } else {
                detail = " (remove)";
            }
            console.log("[mmkv_set] inst=" + this.inst + " key=\"" + this.key +
                        "\" size=" + this.dataSize + detail + " => " + ret);
        }
    });

    // [2] mmkv_getValueSize(instance, key) → int
    Interceptor.attach(base.add(offsets.mmkv_getValueSize), {
        onEnter: function(args) {
            this.inst = args[0];
            this.key = readCStr(args[1]);
        },
        onLeave: function(ret) {
            console.log("[mmkv_getValueSize] inst=" + this.inst + " key=\"" + this.key +
                        "\" => " + ret.toInt32());
        }
    });

    // [3] mmkv_getBytes(instance, key, out_buf, buf_size) → bool
    Interceptor.attach(base.add(offsets.mmkv_getBytes), {
        onEnter: function(args) {
            this.inst = args[0];
            this.key = readCStr(args[1]);
            this.outBuf = args[2];
            this.bufSize = args[3].toInt32();
        },
        onLeave: function(ret) {
            var detail = "";
            if (ret.toInt32() === 1 && !this.outBuf.isNull() && this.bufSize > 0) {
                detail = " data=[" + hexdump_short(this.outBuf, this.bufSize) + "]";
            }
            console.log("[mmkv_getBytes] inst=" + this.inst + " key=\"" + this.key +
                        "\" bufSize=" + this.bufSize + detail + " => " + ret.toInt32());
        }
    });

    // [4] mmkv_removeKey(instance, key) → void
    Interceptor.attach(base.add(offsets.mmkv_removeKey), {
        onEnter: function(args) {
            this.inst = args[0];
            this.key = readCStr(args[1]);
        },
        onLeave: function(ret) {
            console.log("[mmkv_removeKey] inst=" + this.inst + " key=\"" + this.key + "\"");
        }
    });

    // [5] mmkv_lock(instance, flag) → void
    Interceptor.attach(base.add(offsets.mmkv_lock), {
        onEnter: function(args) {
            this.inst = args[0];
            this.flag = args[1].toInt32();
        },
        onLeave: function(ret) {
            console.log("[mmkv_lock] inst=" + this.inst + " flag=" + this.flag);
        }
    });

    console.log("[*] Hooked 6 MMKV functions");
};
