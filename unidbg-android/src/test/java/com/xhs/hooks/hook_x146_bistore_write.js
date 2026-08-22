// hook_x146_bistore_write.js — 追踪谁写入.bistore文件 (x146 hash计算入口)
// 策略: hook open/write syscall, 追踪.bistore文件的fd和写入数据

var base = null;
var hooked = false;
var bistoreFds = {};  // fd → path

Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
    onEnter: function(args) { this.path = args[0].readCString(); },
    onLeave: function(ret) {
        if (!hooked && this.path && this.path.indexOf("libtiny.so") !== -1) {
            base = Module.findBaseAddress("libtiny.so");
            if (base) { console.log("[+] libtiny.so @ " + base); hooked = true; }
        }
    }
});
setTimeout(function() {
    if (!hooked) {
        base = Module.findBaseAddress("libtiny.so");
        if (base) { console.log("[+] libtiny.so @ " + base); hooked = true; }
    }
}, 1000);

// Hook open — 追踪.bistore文件的fd
var openFunc = Module.findExportByName(null, "open");
Interceptor.attach(openFunc, {
    onEnter: function(args) {
        try {
            this.path = args[0].readCString();
            this.flags = args[1].toInt32();
        } catch(e) { this.path = null; }
    },
    onLeave: function(ret) {
        if (this.path && this.path.indexOf("bistore") !== -1) {
            var fd = ret.toInt32();
            var writable = (this.flags & 3) !== 0;  // O_WRONLY=1, O_RDWR=2
            console.log("[open] fd=" + fd + " flags=0x" + this.flags.toString(16) +
                (writable ? " ★WRITABLE" : " readonly") +
                " path=" + this.path);
            if (writable) {
                bistoreFds[fd] = this.path;
            }
        }
    }
});

// Hook openat — Android多用openat
var openatFunc = Module.findExportByName(null, "openat");
if (openatFunc) {
    Interceptor.attach(openatFunc, {
        onEnter: function(args) {
            try {
                this.path = args[1].readCString();
                this.flags = args[2].toInt32();
            } catch(e) { this.path = null; }
        },
        onLeave: function(ret) {
            if (this.path && this.path.indexOf("bistore") !== -1) {
                var fd = ret.toInt32();
                var writable = (this.flags & 3) !== 0;
                console.log("[openat] fd=" + fd + " flags=0x" + this.flags.toString(16) +
                    (writable ? " ★WRITABLE" : " readonly") +
                    " path=" + this.path);
                if (writable) {
                    bistoreFds[fd] = this.path;
                }
            }
        }
    });
}

// Hook write — 捕获写入.bistore的数据
var writeFunc = Module.findExportByName(null, "write");
Interceptor.attach(writeFunc, {
    onEnter: function(args) {
        var fd = args[0].toInt32();
        if (bistoreFds[fd]) {
            this.fd = fd;
            this.buf = args[1];
            this.len = args[2].toInt32();
            console.log("\n[★★★ BISTORE WRITE ★★★] fd=" + fd + " len=" + this.len +
                " path=" + bistoreFds[fd]);

            // Dump写入数据
            if (this.len > 0 && this.len <= 4096) {
                try {
                    console.log("[write] data hexdump:");
                    console.log(hexdump(this.buf, {
                        length: Math.min(this.len, 256),
                        ansi: true
                    }));
                } catch(e) {}

                // 检查是否包含hex string
                try {
                    var str = this.buf.readUtf8String(Math.min(this.len, 256));
                    if (str && str.indexOf("7cba") !== -1) {
                        console.log("[write] ★ CONTAINS x146 VALUE!");
                    }
                } catch(e) {}
            }

            // Backtrace
            if (base) {
                console.log("[write] Backtrace:");
                var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
                for (var i = 0; i < Math.min(bt.length, 12); i++) {
                    var off = bt[i].sub(base);
                    var inLib = bt[i].compare(base) >= 0 && off.compare(ptr(0x800000)) < 0;
                    console.log("  [" + i + "] " + bt[i] +
                        (inLib ? " (libtiny+" + off.toString(16) + ")" : ""));
                }
            }
        }
    }
});

// Hook pwrite — 某些存储用pwrite
var pwriteFunc = Module.findExportByName(null, "pwrite");
if (pwriteFunc) {
    Interceptor.attach(pwriteFunc, {
        onEnter: function(args) {
            var fd = args[0].toInt32();
            if (bistoreFds[fd]) {
                this.fd = fd;
                this.len = args[2].toInt32();
                var offset = args[3].toInt32();
                console.log("\n[★ BISTORE PWRITE ★] fd=" + fd + " len=" + this.len +
                    " offset=" + offset + " path=" + bistoreFds[fd]);
                if (this.len > 0 && this.len <= 4096) {
                    try {
                        console.log(hexdump(args[1], {
                            length: Math.min(this.len, 256), ansi: true
                        }));
                    } catch(e) {}
                }
                if (base) {
                    var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
                    for (var i = 0; i < Math.min(bt.length, 12); i++) {
                        var off = bt[i].sub(base);
                        var inLib = bt[i].compare(base) >= 0 && off.compare(ptr(0x800000)) < 0;
                        console.log("  [" + i + "] " + bt[i] +
                            (inLib ? " (libtiny+" + off.toString(16) + ")" : ""));
                    }
                }
            }
        }
    });
}

// Hook writev — mmap-based storage可能用writev
var writevFunc = Module.findExportByName(null, "writev");
if (writevFunc) {
    Interceptor.attach(writevFunc, {
        onEnter: function(args) {
            var fd = args[0].toInt32();
            if (bistoreFds[fd]) {
                console.log("\n[★ BISTORE WRITEV ★] fd=" + fd + " path=" + bistoreFds[fd]);
                if (base) {
                    var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
                    for (var i = 0; i < Math.min(bt.length, 8); i++) {
                        var off = bt[i].sub(base);
                        var inLib = bt[i].compare(base) >= 0 && off.compare(ptr(0x800000)) < 0;
                        console.log("  [" + i + "] " + bt[i] +
                            (inLib ? " (libtiny+" + off.toString(16) + ")" : ""));
                    }
                }
            }
        }
    });
}

// Hook close — 清理fd映射
var closeFunc = Module.findExportByName(null, "close");
Interceptor.attach(closeFunc, {
    onEnter: function(args) {
        var fd = args[0].toInt32();
        if (bistoreFds[fd]) {
            console.log("[close] fd=" + fd + " path=" + bistoreFds[fd]);
            delete bistoreFds[fd];
        }
    }
});

// Hook mmap — .bistore可能用mmap写入
var mmapFunc = Module.findExportByName(null, "mmap");
if (mmapFunc) {
    Interceptor.attach(mmapFunc, {
        onEnter: function(args) {
            var fd = args[4].toInt32();
            if (bistoreFds[fd]) {
                var prot = args[2].toInt32();
                var writable = (prot & 2) !== 0;  // PROT_WRITE
                console.log("[mmap] fd=" + fd + " len=" + args[1] +
                    " prot=0x" + prot.toString(16) +
                    (writable ? " ★WRITABLE" : "") +
                    " path=" + bistoreFds[fd]);
                if (writable && base) {
                    var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
                    for (var i = 0; i < Math.min(bt.length, 8); i++) {
                        var off = bt[i].sub(base);
                        var inLib = bt[i].compare(base) >= 0 && off.compare(ptr(0x800000)) < 0;
                        console.log("  [" + i + "] " + bt[i] +
                            (inLib ? " (libtiny+" + off.toString(16) + ")" : ""));
                    }
                }
            }
        }
    });
}

console.log("[+] .bistore write hooks ready — waiting for app to write...");
console.log("[+] 如果值已缓存，可能需要清除app数据后重新启动才能触发写入");
