// hook_x146_build.js — Phase A2: 精确追踪x131→x146窗口内每个native调用
// 在x131完成后开启详细监控, x146开始时停止

var hooked = false;
var base = null;
var OFF_MAP_INSERT_WRAP = 0x28C7E8;

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

var window = false;  // x131→x146窗口
var done = false;
var x19Val = null;

function installHooks() {
    hookInsertSequence();
    hookMalloc();
    hookStringCopy();
    hookTreeTraverse();
    hookMemcpy();
    console.log("[+] All hooks ready");
}

// ========== Insert序列控制 ==========
function hookInsertSequence() {
    var insertCount = 0;

    Interceptor.attach(base.add(OFF_MAP_INSERT_WRAP), {
        onEnter: function(args) {
            if (done) return;
            var key = args[1].readCString();
            insertCount++;

            if (key === "x131") {
                x19Val = this.context.x19;
                console.log("\n[ctrl] ===== x131 insert #" + insertCount + " — WINDOW OPEN =====");
                console.log("[ctrl] X19 = " + x19Val);

                // dump variant区域 (应为NULL)
                try {
                    var p = x19Val.add(0x1D20).readPointer();
                    console.log("[ctrl] [X19+0x1D20] = " + p + " (expect NULL)");
                } catch(e) {}

                window = true;
            }

            if (key === "x146") {
                window = false;
                done = true;
                console.log("\n[ctrl] ===== x146 insert #" + insertCount + " — WINDOW CLOSE =====");

                // dump最终variant
                try {
                    var p = this.context.x19.add(0x1D20).readPointer();
                    console.log("[ctrl] [X19+0x1D20] = " + p);
                    var vType = p.readU32();
                    var vLen = p.add(0x18).readU32();
                    var dataPtr = p.add(0x20).readPointer();
                    console.log("[ctrl] variant: type=" + vType + " len=" + vLen);
                    if (vType === 3 && vLen > 0) {
                        console.log("[ctrl] ★ VALUE = '" + dataPtr.readUtf8String(vLen) + "'");
                    }
                } catch(e) {}
            }
        }
    });
}

// ========== sub_1411C0 (malloc) ==========
function hookMalloc() {
    Interceptor.attach(base.add(0x1411C0), {
        onEnter: function(args) {
            if (!window) return;
            this.size = args[0].toInt32();
            console.log("[malloc] size=" + this.size + " caller=+" +
                this.returnAddress.sub(base).toString(16));
        },
        onLeave: function(ret) {
            if (!window) return;
            console.log("[malloc] → " + ret + " (size=" + this.size + ")");
        }
    });
}

// ========== sub_141600 (string copy/assign) ==========
function hookStringCopy() {
    Interceptor.attach(base.add(0x141600), {
        onEnter: function(args) {
            if (!window) return;
            this.dst = args[0];
            this.src = args[1];
            console.log("[str_copy] dst=" + this.dst + " src=" + this.src +
                " caller=+" + this.returnAddress.sub(base).toString(16));
            // dump src
            try {
                console.log("[str_copy] src dump:");
                console.log(hexdump(this.src, { length: 64, ansi: true }));
            } catch(e) {}
        },
        onLeave: function(ret) {
            if (!window) return;
            console.log("[str_copy] → ret=" + ret);
            // dump dst after copy
            try {
                console.log("[str_copy] dst after:");
                console.log(hexdump(this.dst, { length: 64, ansi: true }));
            } catch(e) {}
        }
    });
}

// ========== sub_1702D4 (tree_traverse) ==========
function hookTreeTraverse() {
    Interceptor.attach(base.add(0x1702D4), {
        onEnter: function(args) {
            if (!window) return;
            this.a1 = args[0];
            this.a2 = args[1];
            console.log("[tree_trav] a1=" + this.a1 + " a2=" + this.a2 +
                " caller=+" + this.returnAddress.sub(base).toString(16));
            // a2可能是type tag
            try {
                var tag = this.a2.toInt32();
                console.log("[tree_trav] type_tag=" + tag);
            } catch(e) {}
            // dump a1 (tree root)
            try {
                console.log("[tree_trav] a1 dump:");
                console.log(hexdump(this.a1, { length: 64, ansi: true }));
            } catch(e) {}
        },
        onLeave: function(ret) {
            if (!window) return;
            console.log("[tree_trav] → ret=" + ret);
        }
    });
}

// ========== sub_547670 / sub_547210 (memcpy variants) ==========
function hookMemcpy() {
    // sub_547670
    Interceptor.attach(base.add(0x547670), {
        onEnter: function(args) {
            if (!window) return;
            this.dst = args[0];
            this.src = args[1];
            this.len = args[2].toInt32();
            console.log("[memcpy_a] dst=" + this.dst + " src=" + this.src + " len=" + this.len +
                " caller=+" + this.returnAddress.sub(base).toString(16));
            if (this.len <= 128 && this.len > 0) {
                try {
                    console.log("[memcpy_a] src data:");
                    console.log(hexdump(this.src, { length: Math.min(this.len, 64), ansi: true }));
                } catch(e) {}
            }
        }
    });

    // sub_547210
    Interceptor.attach(base.add(0x547210), {
        onEnter: function(args) {
            if (!window) return;
            this.dst = args[0];
            this.src = args[1];
            this.len = args[2].toInt32();
            console.log("[memcpy_b] dst=" + this.dst + " src=" + this.src + " len=" + this.len +
                " caller=+" + this.returnAddress.sub(base).toString(16));
            if (this.len <= 128 && this.len > 0) {
                try {
                    console.log("[memcpy_b] src data:");
                    console.log(hexdump(this.src, { length: Math.min(this.len, 64), ansi: true }));
                } catch(e) {}
            }
        }
    });

    // 还hook sub_286ED4 (可能是RB-tree rebalance)
    Interceptor.attach(base.add(0x286ED4), {
        onEnter: function(args) {
            if (!window) return;
            console.log("[rb_rebal] a1=" + args[0] + " caller=+" +
                this.returnAddress.sub(base).toString(16));
        }
    });

    // hook sub_16FA98 (tree_free)
    Interceptor.attach(base.add(0x16FA98), {
        onEnter: function(args) {
            if (!window) return;
            console.log("[tree_free] a1=" + args[0] + " a2=" + args[1] +
                " caller=+" + this.returnAddress.sub(base).toString(16));
        }
    });
}
