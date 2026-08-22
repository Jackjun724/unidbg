// hook_x146_dump_all_blobs.js — Hook解密函数，dump所有.bistore解密后的数据
// sub_2F4DB0 是解密入口，sub_2B47D4/sub_2B4DB0 是反序列化

var base = null;
var hooked = false;
var blobCount = 0;

Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
    onEnter: function(args) { this.path = args[0].readCString(); },
    onLeave: function(ret) {
        if (!hooked && this.path && this.path.indexOf("libtiny.so") !== -1) {
            base = Module.findBaseAddress("libtiny.so");
            if (base) { console.log("[+] libtiny.so @ " + base); installHooks(); hooked = true; }
        }
    }
});
setTimeout(function() {
    if (!hooked) {
        base = Module.findBaseAddress("libtiny.so");
        if (base) { console.log("[+] libtiny.so @ " + base); installHooks(); hooked = true; }
    }
}, 1000);

function readSSOString(ptr) {
    try {
        var ctrl = ptr.readU8();
        var len, dataPtr;
        if (ctrl & 1) {
            // long mode
            len = Number(ptr.add(8).readU64());
            dataPtr = ptr.add(16).readPointer();
        } else {
            // short mode
            len = ctrl >> 1;
            dataPtr = ptr.add(1);
        }
        return { len: len, dataPtr: dataPtr };
    } catch(e) {
        return null;
    }
}

function bytesToHex(ptr, len) {
    try {
        var buf = ptr.readByteArray(len);
        var arr = new Uint8Array(buf);
        var hex = "";
        for (var i = 0; i < arr.length; i++) {
            var b = arr[i].toString(16);
            if (b.length === 1) b = "0" + b;
            hex += b;
        }
        return hex;
    } catch(e) { return "<read error>"; }
}

function isPrintable(ptr, len) {
    try {
        var buf = ptr.readByteArray(Math.min(len, 64));
        var arr = new Uint8Array(buf);
        var printable = 0;
        for (var i = 0; i < arr.length; i++) {
            if (arr[i] >= 0x20 && arr[i] < 0x7f) printable++;
        }
        return printable / arr.length > 0.8;
    } catch(e) { return false; }
}

function parseBlob(dataPtr, len) {
    // 尝试解析 [4-byte count][entries: 2B keylen, key, 2B vallen, val]
    try {
        if (len < 4) return;
        var count = dataPtr.readU32();
        if (count === 0 || count > 1000) return;  // 不像是count

        console.log("    [parse] entry count = " + count);
        var offset = 4;
        for (var i = 0; i < count && offset < len; i++) {
            // read key length (2 bytes)
            var keyLen = dataPtr.add(offset).readU16();
            offset += 2;
            if (offset + keyLen > len) break;

            // read key
            var key;
            try {
                key = dataPtr.add(offset).readUtf8String(keyLen);
            } catch(e) {
                key = bytesToHex(dataPtr.add(offset), keyLen);
            }
            offset += keyLen;

            // read value length (2 bytes)
            if (offset + 2 > len) break;
            var valLen = dataPtr.add(offset).readU16();
            offset += 2;
            if (offset + valLen > len) break;

            // read value
            var valPtr = dataPtr.add(offset);
            var val;
            if (isPrintable(valPtr, valLen)) {
                try { val = valPtr.readUtf8String(valLen); }
                catch(e) { val = bytesToHex(valPtr, Math.min(valLen, 64)); }
            } else {
                val = bytesToHex(valPtr, Math.min(valLen, 64));
                if (valLen > 64) val += "... (" + valLen + " bytes total)";
            }
            offset += valLen;

            console.log("    [" + i + "] key=\"" + key + "\" (" + keyLen + "B) → val=\"" +
                val + "\" (" + valLen + "B)");
        }
    } catch(e) {
        // 不是这种格式，忽略
    }
}

function installHooks() {
    // Hook sub_2F4DB0 (blob_load/decrypt)
    Interceptor.attach(base.add(0x2F4DB0), {
        onEnter: function(args) {
            blobCount++;
            this.blobNum = blobCount;
            this.a1 = args[0];
            this.a2 = args[1];
            this.a3 = args[2];  // output SSO string

            // 尝试读取context中的字段名
            var contextInfo = "";
            try {
                var s = this.a1.readUtf8String();
                if (s && s.length > 0 && s.length < 100) contextInfo = " ctx=\"" + s + "\"";
            } catch(e) {}

            console.log("\n[blob #" + this.blobNum + "] sub_2F4DB0(a1=" + this.a1 +
                ", index=" + this.a2 + ")" + contextInfo);
        },
        onLeave: function(ret) {
            var success = ret.toInt32();
            console.log("[blob #" + this.blobNum + "] → ret=" + success);

            if (success && this.a3) {
                var sso = readSSOString(this.a3);
                if (sso && sso.len > 0) {
                    console.log("[blob #" + this.blobNum + "] decrypted len=" + sso.len);

                    // Full hexdump for small blobs, partial for large
                    var dumpLen = Math.min(sso.len, 512);
                    console.log("[blob #" + this.blobNum + "] hexdump:");
                    console.log(hexdump(sso.dataPtr, { length: dumpLen, ansi: true }));

                    // 如果是printable, 也输出字符串
                    if (isPrintable(sso.dataPtr, sso.len)) {
                        try {
                            var str = sso.dataPtr.readUtf8String(Math.min(sso.len, 512));
                            console.log("[blob #" + this.blobNum + "] text: " + str);
                        } catch(e) {}
                    }

                    // 尝试解析为map格式
                    parseBlob(sso.dataPtr, sso.len);
                } else {
                    console.log("[blob #" + this.blobNum + "] empty or failed to read SSO");
                }
            }
        }
    });

    // Hook sub_2B47D4 (deserialize_map) 显示完整的反序列化过程
    Interceptor.attach(base.add(0x2B47D4), {
        onEnter: function(args) {
            console.log("\n[deser_map] sub_2B47D4(src=" + args[0] +
                ", index=" + args[1] + ", out_map=" + args[2] + ", flag=" + args[3] + ")");
            console.log("[deser_map] caller=+" + this.returnAddress.sub(base).toString(16));
        }
    });

    // Hook sub_2B0898 (stream_read) 显示从blob中读取的每个字段
    Interceptor.attach(base.add(0x2B0898), {
        onEnter: function(args) {
            this.stream = args[0];
            this.dst = args[1];
            this.reqLen = args[2].toInt32();
        },
        onLeave: function(ret) {
            var readLen = ret.toInt32();
            if (readLen > 2 && readLen <= 1024) {
                // 只显示有意义的读取
                if (isPrintable(this.dst, readLen)) {
                    try {
                        var s = this.dst.readUtf8String(readLen);
                        console.log("  [stream_read] " + readLen + "B: \"" + s + "\"");
                    } catch(e) {}
                } else if (readLen <= 64) {
                    console.log("  [stream_read] " + readLen + "B: " +
                        bytesToHex(this.dst, readLen));
                } else {
                    console.log("  [stream_read] " + readLen + "B (binary data)");
                }
            }
        }
    });

    console.log("[+] All blob dump hooks ready");
    console.log("[+] Waiting for blob operations...");
}
