/*
 * hook_u_bistore.js — 最轻量: 只 hook deserialize 的 insert
 */
var base = null;
function waitForLibtiny() {
    return new Promise(function(resolve) {
        var check = setInterval(function() {
            var m = Module.findBaseAddress("libtiny.so");
            if (m) { clearInterval(check); base = m; resolve(m); }
        }, 50);
    });
}
function readSSO(ptr) {
    try {
        var b = ptr.readU8();
        if ((b & 1) === 0) {
            var len = b >>> 1;
            return len === 0 ? "" : ptr.add(1).readUtf8String(len);
        } else {
            var sz = ptr.add(8).readU64();
            if (sz > 4096) return null;
            return ptr.add(16).readPointer().readUtf8String(parseInt(sz));
        }
    } catch(e) { return null; }
}

waitForLibtiny().then(function(base) {
    console.log("[+] base: " + base);
    console.log("[+] u SSO = " + readSSO(base.add(0x7B34E8)));

    var n = 0;
    Interceptor.attach(base.add(0x2B4EF4), {
        onEnter: function(args) {
            n++;
            try {
                var k = readSSO(args[1]);
                var v = readSSO(args[2]);
                if (k && v) {
                    var s = v.length > 60 ? v.substring(0,40)+"..." : v;
                    console.log("#" + n + " " + k + " = " + s);
                }
            } catch(e) {}
        }
    });

    setTimeout(function() {
        console.log("=== " + n + " inserts, u=" + readSSO(base.add(0x7B34E8)));
    }, 20000);
});
