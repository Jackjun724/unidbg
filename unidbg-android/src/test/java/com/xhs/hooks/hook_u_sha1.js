/*
 * hook_u_sha1.js
 *
 * Hook SHA1 functions in libtiny.so to capture the u value computation.
 *
 * Key functions:
 *   sub_7292E0 — SHA1(data, size, output[20]) — standalone SHA1
 *   sub_726D50 — VM wrapper: SHA1(*(X19+0xC8), *(X19+0xC0)) → X19+0x4CC
 *   sub_64EBDC — larger hash/HMAC function (calls sub_657ACC)
 *   sub_657ACC — SHA1 finalize (incremental)
 *
 * Usage: conda activate py3.8 && frida -U -f com.xingin.xhs -l hooks/hook_u_sha1.js --no-pause
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

function hexBytes(ptr, len) {
    try {
        var arr = ptr.readByteArray(len);
        return Array.from(new Uint8Array(arr)).map(b => b.toString(16).padStart(2, '0')).join('');
    } catch(e) {
        return "<unreadable:" + e + ">";
    }
}

function tryReadString(ptr, maxLen) {
    try {
        var s = ptr.readUtf8String(maxLen);
        return s;
    } catch(e) {
        return null;
    }
}

function bt(ctx) {
    return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(function(addr) {
            return "0x" + addr.sub(base).toString(16);
        }).join(" → ");
}

function readSSOString(ptr) {
    if (ptr.isNull()) return null;
    try {
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
    } catch(e) {
        return null;
    }
}

waitForLibtiny().then(function(base) {
    console.log("\n======== SHA1 / U VALUE TRACE ========\n");

    // ===== 1. Hook sub_7292E0 (standalone SHA1) =====
    // SHA1(data_ptr, data_size, output_20bytes)
    var sha1Count = 0;
    Interceptor.attach(base.add(0x7292E0), {
        onEnter: function(args) {
            this.dataPtr = args[0];
            this.dataSize = args[1].toInt32();
            this.outPtr = args[2];
            sha1Count++;
            this.idx = sha1Count;

            console.log("\n[SHA1 #" + this.idx + "] sub_7292E0 ENTER");
            console.log("  data_ptr: " + this.dataPtr);
            console.log("  data_size: " + this.dataSize);

            if (this.dataSize > 0 && this.dataSize <= 4096) {
                console.log("  input_hex: " + hexBytes(this.dataPtr, this.dataSize));
                var s = tryReadString(this.dataPtr, this.dataSize);
                if (s) console.log("  input_str: " + s);
            }
            console.log("  output_ptr: " + this.outPtr);
            console.log("  backtrace: " + bt(this.context));
        },
        onLeave: function(retval) {
            console.log("[SHA1 #" + this.idx + "] OUTPUT:");
            var hash = hexBytes(this.outPtr, 20);
            console.log("  sha1_hash: " + hash);

            // Check if this matches u pattern (40 hex chars starting with 00000000)
            if (hash.startsWith("00000000")) {
                console.log("  ★★★ STARTS WITH 00000000 — POSSIBLE U VALUE ★★★");
            }
            // Check if the u value at global matches
            var uGlobal = readSSOString(base.add(0x7AB4E8));
            if (uGlobal && uGlobal === hash) {
                console.log("  ★★★★★ MATCHES GLOBAL U VALUE ★★★★★");
            }
        }
    });

    // ===== 2. Hook sub_726D50 (VM SHA1 wrapper) =====
    Interceptor.attach(base.add(0x726D50), {
        onEnter: function(args) {
            var x19 = this.context.x19;
            console.log("\n[VM_SHA1] sub_726D50 ENTER");
            console.log("  X19 (VM state): " + x19);

            // Read data pointer and size from VM state
            try {
                var dataPtr = ptr(x19).add(0xC8).readPointer();
                var dataSize = ptr(x19).add(0xC0).readU64();
                console.log("  data_ptr (X19+0xC8): " + dataPtr);
                console.log("  data_size (X19+0xC0): " + dataSize);

                if (dataSize > 0 && dataSize <= 4096) {
                    console.log("  input_hex: " + hexBytes(dataPtr, parseInt(dataSize)));
                    var s = tryReadString(dataPtr, parseInt(dataSize));
                    if (s) console.log("  input_str: " + s);
                }
            } catch(e) {
                console.log("  error reading VM state: " + e);
            }
            console.log("  backtrace: " + bt(this.context));
        },
        onLeave: function(retval) {
            var x19 = this.context.x19;
            try {
                var hashPtr = ptr(x19).add(0x4CC);
                console.log("[VM_SHA1] OUTPUT at X19+0x4CC:");
                console.log("  sha1_hash: " + hexBytes(hashPtr, 20));
            } catch(e) {}
        }
    });

    // ===== 3. Hook sub_64EBDC (HMAC-SHA1 or complex hash) =====
    var hmacCount = 0;
    Interceptor.attach(base.add(0x64EBDC), {
        onEnter: function(args) {
            hmacCount++;
            this.idx = hmacCount;
            console.log("\n[HMAC #" + this.idx + "] sub_64EBDC ENTER");
            console.log("  args: " + args[0] + ", " + args[1] + ", " + args[2] + ", " + args[3]);
            console.log("  backtrace: " + bt(this.context));
        },
        onLeave: function(retval) {
            console.log("[HMAC #" + this.idx + "] returned: " + retval);
        }
    });

    // ===== 4. Monitor u global (polling) =====
    var uAddr = base.add(0x7AB4E8);
    var lastUBytes = hexBytes(uAddr, 24);
    console.log("[+] Initial u global bytes: " + lastUBytes);
    console.log("[+] Initial u SSO: " + readSSOString(uAddr));

    var uPoller = setInterval(function() {
        var curBytes = hexBytes(uAddr, 24);
        if (curBytes !== lastUBytes) {
            console.log("\n★ U GLOBAL CHANGED ★");
            console.log("  old: " + lastUBytes);
            console.log("  new: " + curBytes);
            var sso = readSSOString(uAddr);
            if (sso) console.log("  SSO value: " + sso);
            lastUBytes = curBytes;

            if (sso && sso.length === 40 && sso.match(/^[0-9a-f]{40}$/)) {
                console.log("\n★★★★★ U VALUE SET: " + sso + " ★★★★★");
                clearInterval(uPoller);
            }
        }
    }, 5);

    // ===== 5. Hook sub_470130 (hex encoder) — check for 20-byte inputs =====
    Interceptor.attach(base.add(0x470130), {
        onEnter: function(args) {
            this.buf = args[0];
            this.size = args[1].toInt32();
        },
        onLeave: function(retval) {
            if (this.size === 20) {
                console.log("\n[HEX_ENCODE] ★ size=20 (SHA1 output?) ★");
                console.log("  input: " + hexBytes(this.buf, 20));
                console.log("  backtrace: " + bt(this.context));
            }
        }
    });

    // ===== 6. Hook sub_141600 (str_copy) — but ONLY for calls from 0x1F655C area =====
    // vm_load_1F655C reads u from *(X19+0x4D8)
    Interceptor.attach(base.add(0x1F6564), {
        onEnter: function(args) {
            // This is the BL str_copy inside vm_load_1F655C
            var x19 = this.context.x19;
            try {
                var srcPtr = ptr(x19).add(0x4E0).readPointer();
                var srcSSO = readSSOString(srcPtr);
                console.log("\n[VM_LOAD_U] sub_1F655C → str_copy");
                console.log("  src SSO ptr: " + srcPtr);
                console.log("  src value: " + srcSSO);
                console.log("  dst ptr: " + ptr(x19).add(0x4D8).readPointer());
            } catch(e) {
                console.log("[VM_LOAD_U] error: " + e);
            }
        }
    });

    // ===== 7. Summary after 30 seconds =====
    setTimeout(function() {
        clearInterval(uPoller);
        console.log("\n======== SUMMARY ========");
        console.log("SHA1 calls: " + sha1Count);
        console.log("HMAC calls: " + hmacCount);
        console.log("U global SSO: " + readSSOString(uAddr));
        console.log("U global bytes: " + hexBytes(uAddr, 24));
    }, 30000);

    console.log("[+] All hooks installed. Launch app and make a request...");
});
