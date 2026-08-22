/*
 * hook_header_decrypt.js
 *
 * Capture decrypted class/method names for "u" field and "t" sub-object structure.
 *
 * Hooks:
 * 1. vm_dispatch_157C90 (class name decryptor) - captures decrypted class name for "u"
 * 2. sub_1739F0 (method name decryptor) - captures decrypted method name for "u"
 * 3. sub_29A6F0/680/610/524/4B4 (key name generators) - captures "t" field key names
 * 4. sub_28C7E8 (map_insert) in header context - captures "t" field values
 * 5. wrapper_CallStaticObjectMethod for "u" result
 * 6. byte_reader 0x172278 - captures complete header JSON
 *
 * Usage: conda activate py3.8 && frida -U -f com.xingin.xhs -l hook_header_decrypt.js --no-pause
 */

var libtiny = null;
var base = null;

function waitForLibtiny() {
    return new Promise(function(resolve) {
        var check = setInterval(function() {
            libtiny = Module.findBaseAddress("libtiny.so");
            if (libtiny) {
                clearInterval(check);
                base = libtiny;
                console.log("[+] libtiny.so base: " + base);
                resolve(base);
            }
        }, 100);
    });
}

function readCString(ptr, maxLen) {
    try {
        if (ptr.isNull()) return "<null>";
        return ptr.readUtf8String(maxLen || 256);
    } catch(e) {
        return "<err:" + e + ">";
    }
}

function readSSOString(ptr) {
    if (ptr.isNull()) return "<null>";
    var firstByte = ptr.readU8();
    if ((firstByte & 1) === 0) {
        var len = firstByte >>> 1;
        if (len === 0) return "";
        return ptr.add(1).readUtf8String(len);
    } else {
        var len = ptr.add(8).readU64();
        var dataPtr = ptr.add(16).readPointer();
        return dataPtr.readUtf8String(parseInt(len));
    }
}

function hexBytes(ptr, len) {
    var arr = ptr.readByteArray(len);
    return Array.from(new Uint8Array(arr)).map(b => b.toString(16).padStart(2, '0')).join(' ');
}

waitForLibtiny().then(function(base) {
    console.log("\n======== HEADER DECRYPT HOOKS ========\n");

    // ===== 1. Hook vm_dispatch_157C90 (class name decryptor for "u") =====
    // Called at 0x2E2568: vm_dispatch_157C90(data, 26)
    // After return, the buffer at data contains the decrypted class name
    Interceptor.attach(base.add(0x157C90), {
        onEnter: function(args) {
            this.buf = args[0];
            this.len = args[1].toInt32();
        },
        onLeave: function(retval) {
            if (this.len > 0 && this.len <= 64) {
                var decrypted = readCString(this.buf, this.len);
                console.log("[DECRYPT vm_157C90] len=" + this.len + " result=\"" + decrypted + "\"");
                console.log("  raw: " + hexBytes(this.buf, this.len));
            }
        }
    });

    // ===== 2. Hook sub_1739F0 (method name decryptor for "u") =====
    // Called at 0x2E25C8: sub_1739F0(data, 18)
    Interceptor.attach(base.add(0x1739F0), {
        onEnter: function(args) {
            this.buf = args[0];
            this.len = args[1].toInt32();
        },
        onLeave: function(retval) {
            if (this.len > 0 && this.len <= 64) {
                var decrypted = readCString(this.buf, this.len);
                console.log("[DECRYPT sub_1739F0] len=" + this.len + " result=\"" + decrypted + "\"");
                console.log("  raw: " + hexBytes(this.buf, this.len));
            }
        }
    });

    // ===== 3. Hook sub_157154 (3-byte key decryptor for "t" fields) =====
    Interceptor.attach(base.add(0x157154), {
        onEnter: function(args) {
            this.buf = args[0];
            this.len = args[1].toInt32();
        },
        onLeave: function(retval) {
            if (this.len > 0 && this.len <= 16) {
                var decrypted = readCString(this.buf, this.len);
                console.log("[DECRYPT sub_157154] len=" + this.len + " result=\"" + decrypted + "\"");
            }
        }
    });

    // ===== 4. Hook vm_dispatch_19D0EC (4-byte key decryptor for "t" fields) =====
    Interceptor.attach(base.add(0x19D0EC), {
        onEnter: function(args) {
            this.buf = args[0];
            this.len = args[1].toInt32();
        },
        onLeave: function(retval) {
            if (this.len > 0 && this.len <= 16) {
                var decrypted = readCString(this.buf, this.len);
                console.log("[DECRYPT vm_19D0EC] len=" + this.len + " result=\"" + decrypted + "\"");
            }
        }
    });

    // ===== 5. Hook FindClass wrapper sub_4FD5A8 =====
    // Captures the decrypted class name when it's actually used for FindClass
    Interceptor.attach(base.add(0x4FD5A8), {
        onEnter: function(args) {
            // args[2] = class name string pointer
            var name = readCString(args[2]);
            console.log("[FindClass] name=\"" + name + "\"");
        }
    });

    // ===== 6. Hook sub_4FE1A0 (GetMethod by reflection) =====
    Interceptor.attach(base.add(0x4FE1A0), {
        onEnter: function(args) {
            // args[3] = method name string pointer
            try {
                var name = readCString(args[3]);
                console.log("[GetMethod] name=\"" + name + "\"");
            } catch(e) {}
        }
    });

    // ===== 7. Hook byte_reader 0x172278 for complete header =====
    var jsonCount = 0;
    var inHeader = false;
    var lastKey = "";
    var headerFields = {};
    var inSubObject = false;
    var subObjKey = "";
    var subObj = {};

    Interceptor.attach(base.add(0x172278), {
        onEnter: function(args) {
            var x1 = this.context.x1;
            var val = "";
            try {
                val = readSSOString(ptr(x1));
            } catch(e) {
                val = "<err>";
            }

            jsonCount++;

            if (val === "a" && jsonCount < 5) {
                inHeader = true;
                headerFields = {};
            }
            if (val === "x0") {
                inHeader = false;
                console.log("\n======== COMPLETE HEADER JSON ========");
                console.log(JSON.stringify(headerFields, null, 2));
                console.log("======================================\n");
            }

            if (inHeader) {
                // Track nesting for "t" sub-object
                if (val.length === 1 && val.match(/^[a-z]$/)) {
                    lastKey = val;
                } else if (val.length === 2 && val.match(/^[a-z]{2}$/)) {
                    lastKey = val;
                } else if (lastKey !== "") {
                    headerFields[lastKey] = val;
                    console.log("[HEADER] " + lastKey + " = " + val);
                    lastKey = "";
                }
            }
        }
    });

    // ===== 8. Hook dispatcher 0x170b70 for integer values =====
    Interceptor.attach(base.add(0x170b70), {
        onEnter: function(args) {
            // x2 often holds the value for integer types
            if (inHeader) {
                var x2 = this.context.x2;
                if (lastKey !== "") {
                    console.log("[HEADER_DISPATCH] key=" + lastKey + " x2=" + x2);
                }
            }
        }
    });

    // ===== 9. Hook sub_2DAFA0 and sub_2DAD3C (encrypted string decoders) =====
    Interceptor.attach(base.add(0x2DAFA0), {
        onLeave: function(retval) {
            var s = readCString(retval);
            console.log("[sub_2DAFA0] decoded string=\"" + s + "\"");
        }
    });

    Interceptor.attach(base.add(0x2DAD3C), {
        onLeave: function(retval) {
            var s = readCString(retval);
            console.log("[sub_2DAD3C] decoded string=\"" + s + "\"");
        }
    });

    // ===== 10. Hook sub_2DACC0 =====
    Interceptor.attach(base.add(0x2DACC0), {
        onLeave: function(retval) {
            var s = readCString(retval);
            console.log("[sub_2DACC0] decoded string=\"" + s + "\"");
        }
    });

    console.log("[+] All hooks installed. Trigger MUA generation (make an API request)...");
});
