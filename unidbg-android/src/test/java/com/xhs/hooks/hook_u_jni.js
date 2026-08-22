/*
 * hook_u_jni.js — 在 u 计算期间 hook JNI 调用
 *
 * u 在 sub_1BC844 VM dispatch 中计算，不调用任何 hash 函数
 * 可能通过 JNI 从 Java 层获取数据
 */

var base = null;
var hooked = false;
var inUCompute = false;

function readSSO(ptr) {
    try {
        var b = ptr.readU8();
        if ((b & 1) === 0) { var l = b >>> 1; return l === 0 ? "" : ptr.add(1).readUtf8String(l); }
        else { var s = ptr.add(8).readU64(); if(s>4096)return null; return ptr.add(16).readPointer().readUtf8String(parseInt(s)); }
    } catch(e) { return null; }
}

function bt(ctx) {
    return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(a => { var m=Process.findModuleByAddress(a); return m&&m.name==="libtiny.so"?"0x"+a.sub(base).toString(16):a+"["+(m?m.name:"?")+"]"; })
        .join(" → ");
}

function setupHooks() {
    if (hooked) return;
    hooked = true;
    var uAddr = base.add(0x7B34E8);
    console.log("[+] hooks setup, u=" + readSSO(uAddr));

    // Hook sub_1BC844 entry/exit to set inUCompute flag
    Interceptor.attach(base.add(0x1BC844), {
        onEnter: function() { inUCompute = true; console.log("[1BC844] ▶ ENTER"); },
        onLeave: function() { inUCompute = false; console.log("[1BC844] ◀ EXIT"); }
    });

    // Hook JNI GetStringUTFChars
    var getStringUTF = Module.findExportByName("libart.so", "_ZN3art3JNI18GetStringUTFCharsEP7_JNIEnvP8_jstringPh");
    if (getStringUTF) {
        Interceptor.attach(getStringUTF, {
            onLeave: function(retval) {
                if (inUCompute) {
                    try {
                        var s = retval.readUtf8String();
                        console.log("[JNI] GetStringUTFChars: \"" + (s.length>80?s.substring(0,80)+"...":s) + "\"");
                    } catch(e) {}
                }
            }
        });
    } else {
        console.log("[!] GetStringUTFChars not found in libart.so");
    }

    // Hook JNI CallObjectMethodV (captures all object returns from Java)
    var callObj = Module.findExportByName("libart.so", "_ZN3art3JNI20CallObjectMethodVEXTP7_JNIEnvP8_jobjectP10_jmethodIDSt9__va_list");
    if (!callObj) {
        // Try without the V variant
        callObj = Module.findExportByName("libart.so", "_ZN3art3JNI16CallObjectMethodEP7_JNIEnvP8_jobjectP10_jmethodIDz");
    }

    // Hook JNI wrapper in libtiny: sub_4FAD98 (get JNIEnv)
    Interceptor.attach(base.add(0x4FAD98), {
        onLeave: function(retval) {
            if (inUCompute) {
                console.log("[JNI_ENV] GetJNIEnv called during u compute");
            }
        }
    });

    // Hook wrapper_CallStaticObjectMethod in libtiny
    // From sub_2B7CC8: wrapper_CallStaticObjectMethod(env, class, method, tag, ...)
    // Let me find the actual wrapper function
    // sub_2B7D40 location shows the call pattern

    // Hook CallStaticObjectMethod via JNI function table
    // Instead of finding exact symbols, hook the JNI indirect calls
    // by hooking the tag-based dispatch in libtiny

    // Hook sub_175118 (native_entry - all JNI calls go through this)
    Interceptor.attach(base.add(0x175118), {
        onEnter: function(args) {
            if (inUCompute) {
                var x2 = this.context.x2;
                console.log("[NATIVE_ENTRY] during u compute, arg2=0x" + x2.toString(16));
            }
        }
    });

    // Hook str_copy → u global
    Interceptor.attach(base.add(0x141600), {
        onEnter: function(args) {
            var d = args[0].sub(uAddr).toInt32();
            if (d >= 0 && d < 24) {
                var src = readSSO(args[1]);
                console.log("\n★ STR_COPY → U: " + src);
                console.log("  bt: " + bt(this.context));
            }
        }
    });

    // Hook string_assign with len=40 during u compute
    Interceptor.attach(base.add(0x1418F0), {
        onEnter: function(args) {
            if (inUCompute) {
                var len = args[2].toInt32();
                if (len === 40 || len === 32 || len === 16) {
                    try {
                        var val = args[1].readUtf8String(len);
                        console.log("[STRING_ASSIGN] len=" + len + " val=" + val);
                        console.log("  bt: " + bt(this.context));
                    } catch(e) {}
                }
            }
        }
    });

    // Hook sub_470130 (hex encoder) during u compute
    Interceptor.attach(base.add(0x470130), {
        onEnter: function(args) {
            if (inUCompute) {
                this.sz = args[1].toInt32();
                this.buf = args[0];
            }
        },
        onLeave: function() {
            if (inUCompute && this.sz) {
                var hex = "";
                try { hex = Array.from(new Uint8Array(this.buf.readByteArray(this.sz))).map(b=>b.toString(16).padStart(2,'0')).join(''); } catch(e) {}
                console.log("[HEX_ENC] size=" + this.sz + " input=" + hex);
            }
        }
    });

    setTimeout(function() {
        console.log("\n=== DONE u=" + readSSO(uAddr));
    }, 25000);
}

var dlopen = Module.findExportByName(null, "android_dlopen_ext") || Module.findExportByName(null, "dlopen");
Interceptor.attach(dlopen, {
    onEnter: function(args) { try { this.p = args[0].readUtf8String(); } catch(e) { this.p=""; } },
    onLeave: function() {
        if (this.p && this.p.indexOf("libtiny.so") >= 0) {
            base = Module.findBaseAddress("libtiny.so");
            if (base) { console.log("[+] libtiny.so @ " + base); setupHooks(); }
        }
    }
});
