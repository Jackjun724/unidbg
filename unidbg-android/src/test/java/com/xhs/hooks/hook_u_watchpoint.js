/*
 * hook_u_watchpoint.js
 *
 * Use mprotect + exception handler to catch writes to the u value global at base+0x7AB4E8
 * This tells us exactly which code creates/stores the u value.
 *
 * Usage: conda activate py3.8 && frida -U -f com.xingin.xhs -l hooks/hook_u_watchpoint.js --no-pause
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

function bt(ctx) {
    return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(function(addr) {
            var m = Process.findModuleByAddress(addr);
            if (m && m.name === "libtiny.so") {
                return "0x" + addr.sub(base).toString(16) + " [libtiny]";
            }
            return addr + " [" + (m ? m.name : "???") + "]";
        }).join("\n    → ");
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

function hexDump(ptr, len) {
    try {
        var arr = ptr.readByteArray(len);
        return Array.from(new Uint8Array(arr)).map(b => b.toString(16).padStart(2, '0')).join(' ');
    } catch(e) {
        return "<unreadable>";
    }
}

waitForLibtiny().then(function(base) {
    console.log("\n======== U VALUE WATCHPOINT ========\n");

    var targetAddr = base.add(0x7AB4E8);
    var pageSize = Process.pageSize;
    var targetPage = targetAddr.and(ptr(~(pageSize - 1)));

    console.log("[+] Target: " + targetAddr);
    console.log("[+] Page: " + targetPage + " (size=" + pageSize + ")");
    console.log("[+] Initial bytes at target: " + hexDump(targetAddr, 24));
    console.log("[+] Initial SSO read: " + readSSOString(targetAddr));

    var writeCount = 0;
    var protectionActive = false;
    var reprotectTimer = null;

    // Set up exception handler BEFORE changing protection
    Process.setExceptionHandler(function(details) {
        if (details.type === 'access-violation' &&
            details.memory &&
            details.memory.operation === 'write') {

            var writeAddr = ptr(details.memory.address);

            // Check if write is to our target page
            var writePage = writeAddr.and(ptr(~(pageSize - 1)));
            if (writePage.equals(targetPage)) {
                writeCount++;

                // Check if it's specifically near our target (0x7AB4E8, 24-byte SSO struct)
                var offset = writeAddr.sub(targetAddr).toInt32();
                var isTarget = (offset >= 0 && offset < 24);

                if (isTarget || writeCount <= 20) {
                    var marker = isTarget ? " ★★★ U SSO STRUCT ★★★" : "";
                    console.log("\n[WRITE #" + writeCount + "]" + marker);
                    console.log("  write to: " + writeAddr + " (page offset 0x" + writeAddr.sub(targetPage).toString(16) + ")");
                    console.log("  from PC: " + details.address);

                    var pcOffset = details.address.sub(base);
                    var pcOffHex = "0x" + pcOffset.toString(16);
                    console.log("  PC offset: " + pcOffHex + " in libtiny.so");
                    console.log("  backtrace:\n    → " + bt(details.context));
                }

                // Make writable to allow the write
                Memory.protect(targetPage, pageSize, 'rwx');
                protectionActive = false;

                // Re-protect after a short delay
                if (reprotectTimer) {
                    clearTimeout(reprotectTimer);
                }
                reprotectTimer = setTimeout(function() {
                    try {
                        // Check if u value appeared
                        var sso = readSSOString(targetAddr);
                        if (sso && sso.length === 40 && sso.match(/^[0-9a-f]{40}$/)) {
                            console.log("\n★★★★★ U VALUE MATERIALIZED ★★★★★");
                            console.log("  u = " + sso);
                            console.log("  Total writes to page: " + writeCount);
                            console.log("  NOT re-protecting (u found)");
                            return;
                        }
                        Memory.protect(targetPage, pageSize, 'r-x');
                        protectionActive = true;
                    } catch(e) {
                        console.log("[!] Re-protect failed: " + e);
                    }
                }, 5);

                return true; // exception handled
            }
        }
        return false;
    });

    // Wait a bit for libtiny init, then start monitoring
    setTimeout(function() {
        console.log("\n[+] Activating write protection on page " + targetPage);
        console.log("[+] Current SSO at target: " + readSSOString(targetAddr));
        console.log("[+] Current bytes: " + hexDump(targetAddr, 24));

        try {
            Memory.protect(targetPage, pageSize, 'r-x');
            protectionActive = true;
            console.log("[+] Page is now read-only. Waiting for writes...");
        } catch(e) {
            console.log("[!] Failed to set protection: " + e);
            console.log("[!] Trying alternative: monitor via polling");
            startPolling();
        }
    }, 500);

    // Fallback: polling approach
    function startPolling() {
        var lastValue = readSSOString(targetAddr);
        var lastBytes = hexDump(targetAddr, 24);
        console.log("[POLL] Initial: bytes=" + lastBytes + " sso=" + lastValue);

        var pollCount = 0;
        var poller = setInterval(function() {
            pollCount++;
            var curBytes = hexDump(targetAddr, 24);
            if (curBytes !== lastBytes) {
                var curValue = readSSOString(targetAddr);
                console.log("\n[POLL #" + pollCount + "] ★ CHANGE DETECTED ★");
                console.log("  old bytes: " + lastBytes);
                console.log("  new bytes: " + curBytes);
                console.log("  old sso: " + lastValue);
                console.log("  new sso: " + curValue);

                if (curValue && curValue.length === 40 && curValue.match(/^[0-9a-f]{40}$/)) {
                    console.log("\n★★★★★ U VALUE FOUND ★★★★★");
                    console.log("  u = " + curValue);
                    clearInterval(poller);
                }

                lastBytes = curBytes;
                lastValue = curValue;
            }
        }, 1); // 1ms polling - very fast
    }

    // Status check every 5 seconds
    var statusInterval = setInterval(function() {
        var sso = readSSOString(targetAddr);
        console.log("[STATUS] writes=" + writeCount + " sso=" + sso + " protected=" + protectionActive);
        if (sso && sso.length === 40 && sso.match(/^[0-9a-f]{40}$/)) {
            console.log("★ U value present: " + sso);
            clearInterval(statusInterval);
        }
    }, 5000);

    // Timeout
    setTimeout(function() {
        clearInterval(statusInterval);
        if (protectionActive) {
            Memory.protect(targetPage, pageSize, 'rwx');
        }
        console.log("\n======== FINAL STATUS ========");
        console.log("Total writes to page: " + writeCount);
        console.log("Final SSO: " + readSSOString(targetAddr));
        console.log("Final bytes: " + hexDump(targetAddr, 24));
    }, 60000);
});
