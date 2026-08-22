/**
 * 捕获 0x2CB70C 之前的所有 SVC 调用（含VM handler中直接SVC的）
 * 重点：hook 0x27DA98 处的 SVC，读取 fstatat 的 path 和 statbuf 结果
 */

var hooked = false;
var svcLog = [];
var phase = "pre_libtiny";

Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
    onEnter: function(args) { try { this.libpath = args[0].readCString(); } catch(e) { this.libpath = ""; } },
    onLeave: function(ret) {
        if (hooked || !this.libpath || this.libpath.indexOf("libtiny.so") === -1) return;
        var mod = Process.findModuleByName("libtiny.so");
        if (!mod) return;
        hooked = true;
        var base = mod.base;
        console.log("[*] libtiny.so at " + base);
        phase = "libtiny_loaded";
        svcLog = [];

        // ===== Hook 0x27DA98: VM handler 中的 fstatat SVC =====
        Interceptor.attach(base.add(0x27DA98), {
            onEnter: function(args) {
                var x8 = parseInt(this.context.x8); // syscall number
                var x0 = this.context.x0;
                var x1 = this.context.x1;
                var x2 = this.context.x2;
                this.syscall = x8;
                this.statbuf = x2;
                var path = "";
                if (x8 === 79) { // newfstatat
                    try { path = ptr(x1).readUtf8String(); } catch(e) {}
                }
                this.path = path;
                this.entry = { syscall: x8, path: path, addr: "0x27DA98" };
            },
            onLeave: function(retval) {
                // SVC 没有 onLeave，改用下一条指令的hook
            }
        });

        // Hook 0x27DA9C (SVC后的第一条指令) 读取返回值和statbuf
        Interceptor.attach(base.add(0x27DA9C), {
            onEnter: function(args) {
                var x0 = parseInt(this.context.x0); // 返回值
                // 读取 sp 上的 statbuf
                // trace: SVC后 sp 恢复, statbuf = sp + 0x20
                var sp = this.context.sp;
                var statbuf = sp.add(0x20);

                var entry = { addr: "0x27DA98", ret: x0 };
                if (x0 >= 0) {
                    try {
                        var mtime_sec = Number(statbuf.add(0x58).readS64());
                        var mtime_nsec = Number(statbuf.add(0x60).readS64());
                        var mtime_ms = mtime_sec * 1000 + Math.floor(mtime_nsec / 1000000);
                        entry.mtime_ms = mtime_ms;
                        entry.mtime_sec = mtime_sec;
                        svcLog.push(entry);
                    } catch(e) {}
                } else {
                    svcLog.push(entry);
                }
            }
        });

        // ===== Hook 其他 SVC 地址 (在 0x2CB 区域) =====
        Interceptor.attach(base.add(0x2CB3E0), {
            onEnter: function(args) {
                var x8 = parseInt(this.context.x8);
                svcLog.push({ addr: "0x2CB3E0", syscall: x8 });
                console.log("[SVC@2CB3E0] syscall=" + x8);
            }
        });

        // ===== 0x2CB70C — TIMESTAMP STORE =====
        Interceptor.attach(base.add(0x2CB70C), {
            onEnter: function(args) {
                var x9 = parseInt(this.context.x9);
                var x20 = parseInt(this.context.x20);
                var sp = this.context.sp;

                var timestamps = [x20];
                try {
                    var v1 = parseInt(sp.add(0x20).readU64());
                    var v2 = parseInt(sp.add(0x28).readU64());
                    if (v1 > 1700000000000) timestamps.push(v1);
                    if (v2 > 1700000000000) timestamps.push(v2);
                } catch(e) {}

                console.log("\n========================================");
                console.log("=== TIMESTAMP STORE: " + timestamps.join(", ") + " ===");
                console.log("========================================");

                // 打印此时为止的所有 SVC 调用
                console.log("\n所有 SVC 调用 (" + svcLog.length + "个):");
                svcLog.forEach(function(e, i) {
                    var line = "  [" + i + "] " + e.addr + " syscall=" + (e.syscall || "?");
                    if (e.ret !== undefined) line += " ret=" + e.ret;
                    if (e.mtime_ms) line += " mtime=" + e.mtime_ms;
                    if (e.path) line += " \"" + e.path + "\"";
                    console.log(line);
                });

                // 匹配
                console.log("\n=== 匹配分析 ===");
                timestamps.forEach(function(ts) {
                    console.log("目标: " + ts);
                    var found = false;
                    svcLog.forEach(function(e) {
                        if (e.mtime_ms && Math.abs(e.mtime_ms - ts) < 5000) {
                            console.log("  MATCH: mtime=" + e.mtime_ms + " diff=" + (ts - e.mtime_ms) + "ms");
                            found = true;
                        }
                    });
                    if (!found) console.log("  无匹配 fstatat mtime");
                });
            }
        });

        // ===== sub_2CB788 =====
        Interceptor.attach(base.add(0x2CB788), {
            onEnter: function() { console.log("\n[sub_2CB788] 写入 qword_7B3CF0"); }
        });

        console.log("[+] All hooks installed before JNI_OnLoad");
    }
});
