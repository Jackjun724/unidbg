/*
 * hook_header_fields.js
 *
 * Hook libtiny.so byte_reader (0x172278) to capture MUA header JSON fields s, t, u
 * Also hook __read_chk to count 32-byte random reads and capture their caller
 *
 * Usage: frida -U -f com.xingin.xhs -l hook_header_fields.js --no-pause
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

waitForLibtiny().then(function(base) {
    console.log("[+] Starting hooks...");

    // ===== Hook 1: __read_chk to count and track random reads =====
    var readChkCount = 0;
    Interceptor.attach(Module.findExportByName(null, "__read_chk"), {
        onEnter: function(args) {
            this.fd = args[0].toInt32();
            this.buf = args[1];
            this.size = args[2].toInt32();
        },
        onLeave: function(retval) {
            readChkCount++;
            if (this.size >= 32 && this.size <= 64) {
                var data = this.buf.readByteArray(this.size);
                var hex = Array.from(new Uint8Array(data)).map(b => b.toString(16).padStart(2, '0')).join('');
                console.log("[__read_chk #" + readChkCount + "] fd=" + this.fd +
                    " size=" + this.size + " hex=" + hex);
                console.log("  caller=" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(function(addr) {
                        var m = DebugSymbol.fromAddress(addr);
                        var off = addr.sub(base);
                        return "0x" + off.toString(16) + " (" + m.name + ")";
                    }).join("\n         "));
            }
        }
    });

    // ===== Hook 2: byte_reader 0x172278 to capture header JSON =====
    var jsonCount = 0;
    var inHeader = false;
    var lastKey = "";
    var headerFields = {};

    Interceptor.attach(base.add(0x172278), {
        onEnter: function(args) {
            var x1 = this.context.x1;
            var val = "";
            try {
                val = readSSOString(ptr(x1));
            } catch(e) {
                val = "<err:" + e + ">";
            }

            jsonCount++;

            // Detect header start
            if (val === "a" && jsonCount < 5) inHeader = true;
            if (val === "x0") {
                inHeader = false;
                console.log("\n====== HEADER JSON FIELDS ======");
                console.log(JSON.stringify(headerFields, null, 2));
                console.log("================================\n");
            }

            if (inHeader) {
                // Single char keys: these are header field names
                if (val.length === 1 && val.match(/^[a-z]$/)) {
                    lastKey = val;
                } else if (lastKey !== "") {
                    headerFields[lastKey] = val;
                    console.log("[HEADER] " + lastKey + " = " + val);

                    // For s, t, u fields: dump register context and backtrace
                    if (lastKey === "s" || lastKey === "t" || lastKey === "u") {
                        console.log("  X1 (SSO ptr) = " + ptr(this.context.x1));
                        console.log("  backtrace: " + Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(function(addr) {
                                return "0x" + addr.sub(base).toString(16);
                            }).join(" -> "));
                    }
                    lastKey = "";
                }
            }
        }
    });

    // ===== Hook 3: X25519 scalar multiply at 0x53973C =====
    var ecdhCount = 0;
    Interceptor.attach(base.add(0x53973C), {
        onEnter: function(args) {
            ecdhCount++;
            var x0 = this.context.x0;
            var x1 = this.context.x1;
            var x2 = this.context.x2;

            try {
                var scalar = ptr(x0).readByteArray(32);
                var point = ptr(x1).readByteArray(32);
                var scalarHex = Array.from(new Uint8Array(scalar)).map(b => b.toString(16).padStart(2, '0')).join('');
                var pointHex = Array.from(new Uint8Array(point)).map(b => b.toString(16).padStart(2, '0')).join('');
                console.log("[X25519 #" + ecdhCount + "]");
                console.log("  scalar = " + scalarHex);
                console.log("  point  = " + pointHex);
                console.log("  output = " + ptr(x2));

                this._x2 = ptr(x2);
            } catch(e) {
                console.log("[X25519 #" + ecdhCount + "] error: " + e);
            }
        },
        onLeave: function(retval) {
            if (this._x2) {
                try {
                    var result = this._x2.readByteArray(32);
                    var resultHex = Array.from(new Uint8Array(result)).map(b => b.toString(16).padStart(2, '0')).join('');
                    console.log("  result = " + resultHex);
                } catch(e) {}
            }
        }
    });

    console.log("[+] All hooks installed. Waiting for MUA generation...");
});
