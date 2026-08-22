// hook_x146_blob_source.js — 追踪x146 blob的来源（SharedPreferences/文件）
// 发现: x146值存储在序列化blob中，通过sub_2B47D4反序列化

var hooked = false;
var base = null;

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

function installHooks() {
    // Hook sub_2B47D4 — the deserialization entry point
    Interceptor.attach(base.add(0x2B47D4), {
        onEnter: function(args) {
            this.a1 = args[0];
            this.a2 = args[1];
            this.a3 = args[2];
            this.a4 = args[3];
            console.log("\n[deser] sub_2B47D4 ENTER");
            console.log("[deser] a1=" + this.a1 + " a2=" + this.a2 + " a3=" + this.a3 + " a4=" + this.a4);
            console.log("[deser] caller=+" + this.returnAddress.sub(base).toString(16));

            var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
            for (var i = 0; i < Math.min(bt.length, 8); i++) {
                var off = bt[i].sub(base);
                var inLib = bt[i].compare(base) >= 0 && off.compare(ptr(0x800000)) < 0;
                console.log("  [" + i + "] " + bt[i] + (inLib ? " (+" + off.toString(16) + ")" : ""));
            }
        }
    });

    // Hook sub_2F4DB0 — the blob loader
    Interceptor.attach(base.add(0x2F4DB0), {
        onEnter: function(args) {
            this.a1 = args[0];
            this.a2 = args[1];
            this.a3 = args[2];
            this.a4 = args[3];
            console.log("\n[blob_load] sub_2F4DB0 ENTER");
            console.log("[blob_load] a1=" + this.a1 + " a2=" + this.a2);
            console.log("[blob_load] caller=+" + this.returnAddress.sub(base).toString(16));

            // Try to read a2 as string (might be a key name)
            try {
                var s = this.a2.readUtf8String();
                if (s && s.length > 0 && s.length < 200) {
                    console.log("[blob_load] a2 string = '" + s + "'");
                }
            } catch(e) {}

            // Try to dump a1
            try {
                console.log("[blob_load] a1 dump:");
                console.log(hexdump(this.a1, { length: 64, ansi: true }));
            } catch(e) {}
        },
        onLeave: function(ret) {
            console.log("[blob_load] → ret=" + ret);
            // Check if a3 (output SSO string) has data
            try {
                var ctrl = this.a3.readU8();
                var len, dataPtr;
                if (ctrl & 1) {
                    len = this.a3.add(8).readU64();
                    dataPtr = this.a3.add(16).readPointer();
                } else {
                    len = ctrl >> 1;
                    dataPtr = this.a3.add(1);
                }
                console.log("[blob_load] output SSO: len=" + len);
                if (len > 0 && len <= 4096) {
                    console.log("[blob_load] output data (first 128 bytes):");
                    console.log(hexdump(dataPtr, { length: Math.min(Number(len), 128), ansi: true }));
                }
            } catch(e) {}
        }
    });

    // Hook JNI GetStringUTFChars to catch SharedPreferences keys
    var jniEnv = Java.vm.tryGetEnv();
    if (jniEnv) {
        console.log("[+] JNI env available");
    }

    // Hook file open to detect blob file access
    var openFunc = Module.findExportByName(null, "open");
    if (openFunc) {
        Interceptor.attach(openFunc, {
            onEnter: function(args) {
                try {
                    var path = args[0].readCString();
                    if (path && (path.indexOf("tiny") !== -1 || path.indexOf("shield") !== -1 ||
                        path.indexOf("xhs") !== -1 || path.indexOf("xingin") !== -1 ||
                        path.indexOf(".dat") !== -1 || path.indexOf(".bin") !== -1)) {
                        console.log("[open] " + path);
                    }
                } catch(e) {}
            }
        });
    }

    // Hook SharedPreferences getString
    Java.perform(function() {
        try {
            var sp = Java.use("android.content.SharedPreferences");
        } catch(e) {}

        try {
            var editor = Java.use("android.app.SharedPreferencesImpl");
            // hook getString via the actual implementation
        } catch(e) {}

        // More directly, hook the native JNI calls for string access
        // sub_40E758 is identified as jni_call in the opcode map
        console.log("[+] Java hooks set up");
    });

    // Hook sub_40E758 (jni_call) to see JNI interactions near blob loading
    Interceptor.attach(base.add(0x40E758), {
        onEnter: function(args) {
            // This is called through off_75D1D0, limited logging
        }
    });

    console.log("[+] Blob source hooks ready");
}
