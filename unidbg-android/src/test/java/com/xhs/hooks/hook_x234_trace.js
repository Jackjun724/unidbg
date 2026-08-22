/**
 * Dump x234 全局map的3个时间戳值
 * RB-tree node layout (from sub_286958):
 *   +0x00: left (or next)
 *   +0x08: right
 *   +0x10: parent
 *   +0x18: color/flags?
 *   +0x20: key SSO (24 bytes: +0x20 to +0x37)
 *   +0x38: value type byte
 *   +0x40: value data (8 bytes)
 */

var base = null;

function readSSO(ptr) {
    try {
        var first = ptr.readU8();
        if ((first & 1) === 0) {
            var len = first >> 1;
            if (len === 0) return "";
            if (len > 200) return "<bad>";
            return ptr.add(1).readUtf8String(len);
        } else {
            var slen = ptr.add(8).readU64();
            if (slen > 4096) return "<long>";
            return ptr.add(16).readPointer().readUtf8String(slen);
        }
    } catch(e) { return "<err>"; }
}

function dumpNode(node, depth) {
    if (node.isNull() || depth > 6) return;
    try {
        // key at +0x20 (32 bytes offset), value at +0x38 (56 bytes)
        var key = readSSO(node.add(0x20));
        var valType = node.add(0x38).readU8();
        var valData = node.add(0x40).readS64();

        var typeStr = ["?","map","arr","str","bytes","int64","bool","float"][valType] || "t" + valType;
        console.log("  " + "  ".repeat(depth) + "node key=\"" + key + "\" type=" + valType + "(" + typeStr + ") val=" + valData);

        if (valData > 1700000000000 && valData < 1900000000000) {
            console.log("  " + "  ".repeat(depth) + ">>> TIMESTAMP: " + valData + " (" + new Date(Number(valData)).toISOString() + ")");
        }

        // RB-tree: left at +0, right at +8
        var left = node.readPointer();
        var right = node.add(8).readPointer();
        // sentinel check: left/right might point to the tree header
        if (!left.isNull() && left.compare(node) !== 0) {
            dumpNode(left, depth + 1);
        }
        if (!right.isNull() && right.compare(node) !== 0) {
            dumpNode(right, depth + 1);
        }
    } catch(e) {
        console.log("  " + "  ".repeat(depth) + "error: " + e);
    }
}

function hook() {
    var globalVariant = base.add(0x7B3CF0);
    var onceFlag = base.add(0x7B6070);

    console.log("[*] once_flag = " + onceFlag.readU8());
    var t = globalVariant.readU8();
    console.log("[*] variant type = " + t);

    if (t === 1) {
        // tree结构: byte flag(+0), qword tree_root_container(+8)
        // tree_root_container: +0=root_or_begin, +8=end, +16=size
        var treeContainer = globalVariant.add(8).readPointer();
        console.log("[*] tree container = " + treeContainer);

        if (!treeContainer.isNull()) {
            // container+0 points to the root (or begin node)
            var begin = treeContainer.readPointer();
            var size = treeContainer.add(16).readU64();
            console.log("[*] tree size = " + size);
            console.log("[*] tree begin = " + begin);

            // dump raw container
            console.log("[*] container dump:");
            console.log(hexdump(treeContainer, {length: 32, ansi: false}));

            if (!begin.isNull()) {
                // begin可能是sentinel node，root在sentinel->left或container->root
                // 从sub_286958: v4=container, *v4=sentinel(header+8), *(v4+8)=end, *(v4+16)=count
                // header结构: +0=begin(smallest), +8=root
                // 试多种offset
                console.log("\n=== Trying root at container+0 ===");
                dumpNode(begin, 0);

                var root2 = treeContainer.add(8).readPointer();
                if (!root2.isNull() && root2.compare(begin) !== 0) {
                    console.log("\n=== Trying root at container+8 ===");
                    dumpNode(root2, 0);
                }

                // 也试: begin可能是header, header+0=left(begin), header+8=root
                try {
                    var headerLeft = begin.readPointer();
                    var headerRoot = begin.add(8).readPointer();
                    if (!headerLeft.isNull() && headerLeft.compare(begin) !== 0) {
                        console.log("\n=== Trying begin->left ===");
                        dumpNode(headerLeft, 0);
                    }
                    if (!headerRoot.isNull() && headerRoot.compare(begin) !== 0 && headerRoot.compare(headerLeft) !== 0) {
                        console.log("\n=== Trying begin->right (root) ===");
                        dumpNode(headerRoot, 0);
                    }
                } catch(e) {}
            }
        }
    }
}

function waitForLib() {
    var mod = Process.findModuleByName("libtiny.so");
    if (mod) {
        base = mod.base;
        console.log("[*] libtiny.so at " + base);
        hook();
    } else {
        setTimeout(waitForLib, 200);
    }
}

setTimeout(waitForLib, 500);
