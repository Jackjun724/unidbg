// hook sub_28C7E8 (map_insert) - 捕获所有 RB-tree map set(key, value)
//
// variant 结构:
//   +0: type byte (3=string, 5=int64, 6=bool, 7=float, 1=map, 2=array, 4=bytes, 8=nested)
//   +8: data (type 3/1/2/4/8 = pointer, type 5/6/7 = inline value)
//
// type=3 string: variant+8 = pointer → SSO string
//   SSO inline  (byte[0] & 1 == 0): len = byte[0] >> 1, data at byte[1..22]
//   SSO heap    (byte[0] & 1 == 1): cap at +0, len at +8, data ptr at +16
//
// 用法: frida -U -f com.xingin.xhs -l hooks/hook_map_insert.js --no-pause

var moduleName = "libtiny.so";
var map_insert_offset = 0x28C7E8;
var json_serialize_offset = 0x170B70;

var TYPE_NAMES = {
    0: "empty", 1: "map", 2: "array", 3: "string",
    4: "bytes", 5: "int64", 6: "bool", 7: "float", 8: "nested",
};

function readSSOString(p) {
    try {
        if (p.isNull()) return "<null>";
        var flag = p.readU8();
        if ((flag & 1) === 0) {
            // inline: len = flag >> 1, data at p+1
            var len = flag >>> 1;
            if (len === 0) return "";
            if (len > 22) return "<bad inline len=" + len + ">";
            return p.add(1).readUtf8String(len);
        } else {
            // heap: cap at +0 (with bit0), len at +8, data ptr at +16
            var len = p.add(8).readU64().toNumber();
            if (len === 0) return "";
            if (len > 1000000) return "<bad heap len=" + len + ">";
            var dataPtr = p.add(16).readPointer();
            if (dataPtr.isNull()) return "<null data>";
            return dataPtr.readUtf8String(len);
        }
    } catch (e) {
        return "<sso err: " + e.message + ">";
    }
}

function readVariantValue(p) {
    try {
        var type = p.readU8();
        var typeName = TYPE_NAMES[type] || ("type" + type);
        var dp = p.add(8);

        switch (type) {
            case 0:
                return typeName + ": null";

            case 3: {
                // string: dp 是指向 SSO string 的指针
                var ssoPtr = dp.readPointer();
                var s = readSSOString(ssoPtr);
                if (s.length > 100) s = s.substring(0, 100) + "...(" + s.length + ")";
                return typeName + ': "' + s + '"';
            }

            case 5: {
                // int64: 直接存在 dp
                var val = dp.readS64();
                return typeName + ": " + val;
            }

            case 6: {
                // bool
                var b = dp.readU64().toNumber();
                return typeName + ": " + (b ? "true" : "false");
            }

            case 7: {
                // float/double
                var d = dp.readDouble();
                return typeName + ": " + d;
            }

            case 1: case 8: {
                // map / nested: dp 是指向 tree 的指针
                var treePtr = dp.readPointer();
                return typeName + ": " + treePtr;
            }

            case 2: {
                // array: dp 是指向 vector 的指针
                var vecPtr = dp.readPointer();
                try {
                    var begin = vecPtr.readPointer();
                    var end = vecPtr.add(8).readPointer();
                    var count = end.sub(begin).toInt32() / 16; // 每个 variant 16 bytes
                    return typeName + ": [" + count + " elements]";
                } catch (e) {
                    return typeName + ": " + vecPtr;
                }
            }

            case 4: {
                // bytes
                var bytesPtr = dp.readPointer();
                try {
                    var begin = bytesPtr.readPointer();
                    var end = bytesPtr.add(8).readPointer();
                    var blen = end.sub(begin).toInt32();
                    if (blen > 0 && blen <= 64) {
                        var hex = hexdump_short(begin.readByteArray(blen));
                        return typeName + ": [" + blen + "] " + hex;
                    }
                    return typeName + ": [" + blen + " bytes]";
                } catch (e) {
                    return typeName + ": " + bytesPtr;
                }
            }

            default: {
                var raw = hexdump_short(dp.readByteArray(16));
                return typeName + ": raw=" + raw;
            }
        }
    } catch (e) {
        return "err: " + e.message;
    }
}

function hexdump_short(buf) {
    var a = new Uint8Array(buf);
    var s = "";
    for (var i = 0; i < Math.min(a.length, 32); i++) {
        s += ("0" + a[i].toString(16)).slice(-2);
    }
    return s;
}

function pad(s, w) {
    s = String(s);
    if (w > 0) { while (s.length < w) s = " " + s; }
    else { w = -w; while (s.length < w) s = s + " "; }
    return s;
}

function hookMapInsert() {
    var base = Module.findBaseAddress(moduleName);
    if (!base) {
        console.log("[-] " + moduleName + " not loaded, retrying...");
        setTimeout(hookMapInsert, 1000);
        return;
    }
    console.log("[+] " + moduleName + " base: " + base);

    var map_insert = base.add(map_insert_offset);
    var json_ser = base.add(json_serialize_offset);
    var count = 0;
    var slots = []; // { key, slotPtr, seq }

    // --- Hook 1: map_insert 记录 key + slot 指针 ---
    Interceptor.attach(map_insert, {
        onEnter: function (args) {
            try { this.key = args[1].readUtf8String(); }
            catch (e) { this.key = "?"; }
            this.lr = this.context.lr;
            count++;
            this.seq = count;
        },
        onLeave: function (retval) {
            var off = this.lr.sub(base);
            slots.push({
                key: this.key,
                slotPtr: ptr(retval.toString()),
                seq: this.seq
            });
            console.log("[INSERT] #" + this.seq + " key=\"" + this.key + "\" slot=" + retval + " lr=" + moduleName + "!0x" + off.toString(16));
        }
    });

    // --- Hook 2: json_serialize 时 dump 所有 value ---
    var dumpCount = 0;
    Interceptor.attach(json_ser, {
        onEnter: function (args) {
            if (slots.length === 0) return;

            var variant = args[1];
            try {
                var vtype = variant.readU8();
                if (vtype !== 1) return; // 只关心顶层 map
            } catch (e) { return; }

            dumpCount++;
            console.log("\n========== json_serialize #" + dumpCount + " (map with " + slots.length + " entries) ==========\n");
            console.log(pad("#", 4) + "  " + pad("key", -16) + "  value");
            console.log("-".repeat(80));

            for (var i = 0; i < slots.length; i++) {
                var s = slots[i];
                var val = readVariantValue(s.slotPtr);
                console.log(pad(s.seq, 4) + "  " + pad(s.key, -16) + "  " + val);
            }

            console.log("\n[+] Total: " + slots.length + " entries\n");

            // 清空，准备下一轮
            slots = [];
            count = 0;
        }
    });

    console.log("[+] Hooked map_insert at " + map_insert);
    console.log("[+] Hooked json_serialize at " + json_ser);
    console.log("[+] Insert 实时打印 key, serialize 时 dump 全部 value");
}

setTimeout(hookMapInsert, 500);
