/**
 * Hook .bistore 加载 — 改进版
 * 无论ret值如何都dump数据, 检查所有可能的输出位置
 */

var base = null;

function readSSO(ptr) {
    try {
        var ctrl = ptr.readU8();
        if (ctrl & 1) {
            var len = Number(ptr.add(8).readU64());
            if (len <= 0 || len > 100000) return null;
            return { len: len, data: ptr.add(16).readPointer() };
        } else {
            var len = ctrl >> 1;
            if (len <= 0) return null;
            return { len: len, data: ptr.add(1) };
        }
    } catch(e) { return null; }
}

function hexlify(ptr, len) {
    try {
        var arr = new Uint8Array(ptr.readByteArray(len));
        return Array.from(arr).map(b => ('0'+b.toString(16)).slice(-2)).join('');
    } catch(e) { return "<err>"; }
}

function parseBlob(dataPtr, len) {
    try {
        if (len < 4) return;
        var count = dataPtr.readU32();
        if (count === 0 || count > 1000) return;
        console.log("    [blob格式] count=" + count);
        var offset = 4;
        for (var i = 0; i < count && offset + 4 < len; i++) {
            var keyLen = dataPtr.add(offset).readU16(); offset += 2;
            if (offset + keyLen > len) break;
            var key = dataPtr.add(offset).readUtf8String(keyLen); offset += keyLen;
            if (offset + 2 > len) break;
            var valLen = dataPtr.add(offset).readU16(); offset += 2;
            if (offset + valLen > len) break;
            var val;
            try { val = dataPtr.add(offset).readUtf8String(Math.min(valLen, 200)); }
            catch(e) { val = hexlify(dataPtr.add(offset), Math.min(valLen, 64)); }
            offset += valLen;
            console.log("    [" + i + "] \"" + key + "\" → \"" + val.substring(0, 200) + "\" (" + valLen + "B)");
        }
    } catch(e) {}
}

function doHook(b) {
    base = b;
    var blobN = 0;

    // ===== sub_2F4DB0 (blob_load) =====
    Interceptor.attach(base.add(0x2F4DB0), {
        onEnter: function(args) {
            blobN++;
            this.n = blobN;
            this.x0 = this.context.x0;
            this.x1 = this.context.x1;
            this.x2 = this.context.x2;
            this.x19 = this.context.x19;

            // 尝试多种方式读取context信息
            var ctx = "";
            try { ctx = ptr(this.x0).readUtf8String(); } catch(e) {}
            if (!ctx) try { ctx = ptr(this.x1).readUtf8String(); } catch(e) {}
            console.log("\n[BLOB #" + this.n + "] sub_2F4DB0 x0=" + this.x0 +
                " x1=" + this.x1 + " x2=" + this.x2 + " ctx=\"" + ctx + "\"");
        },
        onLeave: function(retval) {
            console.log("[BLOB #" + this.n + "] ret=" + retval);

            // 检查所有可能的输出位置
            [this.x0, this.x1, this.x2].forEach(function(reg, idx) {
                var sso = readSSO(ptr(reg));
                if (sso && sso.len > 0 && sso.len < 100000) {
                    console.log("  [出口 x" + idx*2 + "] SSO len=" + sso.len);
                    console.log("    hex=" + hexlify(sso.data, Math.min(sso.len, 128)));
                    try {
                        var str = sso.data.readUtf8String(Math.min(sso.len, 200));
                        console.log("    str=\"" + str + "\"");
                    } catch(e) {}
                    parseBlob(sso.data, sso.len);
                }
            }.bind(this));

            // 也检查x0返回值
            var retSSO = readSSO(ptr(retval));
            if (retSSO && retSSO.len > 0) {
                console.log("  [返回值] SSO len=" + retSSO.len);
                console.log("    hex=" + hexlify(retSSO.data, Math.min(retSSO.len, 128)));
            }
        }
    });

    // ===== sub_2B47D4 (deserialize_map) =====
    Interceptor.attach(base.add(0x2B47D4), {
        onEnter: function(args) {
            console.log("[DESER] sub_2B47D4 x0=" + args[0] + " x1=" + args[1]);
        }
    });

    // ===== sub_2B0898 (stream_read) =====
    var srCount = 0;
    Interceptor.attach(base.add(0x2B0898), {
        onEnter: function(args) { this.dst = args[0]; },
        onLeave: function(ret) {
            srCount++;
            var sso = readSSO(this.dst);
            if (sso && sso.len > 0 && sso.len < 10000) {
                try {
                    var str = sso.data.readUtf8String(Math.min(sso.len, 200));
                    console.log("  [SREAD #" + srCount + "] " + sso.len + "B \"" + str.substring(0, 100) + "\"");
                } catch(e) {
                    console.log("  [SREAD #" + srCount + "] " + sso.len + "B " + hexlify(sso.data, Math.min(sso.len, 64)));
                }
            }
        }
    });

    // ===== openat — 捕获.bistore文件打开 =====
    Interceptor.attach(Module.findExportByName("libc.so", "openat"), {
        onEnter: function(args) {
            try { this.path = args[1].readUtf8String(); } catch(e) { this.path = null; }
        },
        onLeave: function(retval) {
            if (this.path && this.path.indexOf(".bistore") !== -1) {
                console.log("[OPEN] " + this.path + " → fd=" + retval.toInt32());
            }
        }
    });

    // ===== mmap =====
    var bistoreFd = -1;
    Interceptor.attach(Module.findExportByName("libc.so", "mmap"), {
        onEnter: function(args) {
            this.fd = args[4].toInt32();
            this.len = args[1].toInt32();
        },
        onLeave: function(retval) {
            if (this.len === 4096 || this.len === 16384) {
                // 可能是.bistore mmap
                try {
                    var header = retval.readU32();
                    if (header > 0 && header < 0x10000) {
                        console.log("[MMAP] fd=" + this.fd + " len=" + this.len + " header=0x" + header.toString(16));
                        console.log("  first32=" + hexlify(retval, 32));
                    }
                } catch(e) {}
            }
        }
    });

    console.log("[*] All hooks installed.");
}

var poll = setInterval(function() {
    var mod = Process.findModuleByName("libtiny.so");
    if (mod) {
        clearInterval(poll);
        console.log("[*] libtiny.so at " + mod.base);
        doHook(mod.base);
    }
}, 200);
