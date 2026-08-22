// hook_x146_dump_bistore.js — 用Frida从app进程内dump .bistore文件
// 不需要root，因为app自身有读权限

Java.perform(function() {
    var File = Java.use("java.io.File");
    var FileInputStream = Java.use("java.io.FileInputStream");

    var bistorePath = "/data/user/0/com.xingin.xhs/.bistore/a6de269810198701a152619ebd19abc1";
    var f = File.$new(bistorePath);

    if (f.exists()) {
        var len = f.length();
        console.log("[+] .bistore exists, size=" + len + " bytes");

        var fis = FileInputStream.$new(f);
        var buf = Java.array('byte', new Array(Number(len)).fill(0));
        fis.read(buf);
        fis.close();

        // 输出为hex
        var hex = "";
        for (var i = 0; i < buf.length; i++) {
            var b = (buf[i] & 0xFF).toString(16);
            if (b.length === 1) b = "0" + b;
            hex += b;
        }
        console.log("[+] .bistore hex dump (" + buf.length + " bytes):");
        console.log(hex);

        // 也尝试dump .crc文件
        var crcPath = bistorePath + ".crc";
        var cf = File.$new(crcPath);
        if (cf.exists()) {
            var crcLen = cf.length();
            var cfis = FileInputStream.$new(cf);
            var crcBuf = Java.array('byte', new Array(Number(crcLen)).fill(0));
            cfis.read(crcBuf);
            cfis.close();
            var crcHex = "";
            for (var i = 0; i < crcBuf.length; i++) {
                var b = (crcBuf[i] & 0xFF).toString(16);
                if (b.length === 1) b = "0" + b;
                crcHex += b;
            }
            console.log("[+] .bistore.crc hex (" + crcBuf.length + " bytes):");
            console.log(crcHex);
        }

        // 列出所有.bistore文件
        var dir = File.$new("/data/user/0/com.xingin.xhs/.bistore/");
        var files = dir.listFiles();
        if (files) {
            console.log("\n[+] All .bistore files:");
            for (var i = 0; i < files.length; i++) {
                console.log("  " + files[i].getName() + " (" + files[i].length() + " bytes)");
            }
        }
    } else {
        console.log("[-] .bistore file not found at " + bistorePath);

        // 搜索.bistore目录
        var dir = File.$new("/data/user/0/com.xingin.xhs/.bistore/");
        if (dir.exists()) {
            var files = dir.listFiles();
            console.log("[+] .bistore directory exists, files:");
            for (var i = 0; i < files.length; i++) {
                console.log("  " + files[i].getName() + " (" + files[i].length() + " bytes)");
            }
        } else {
            console.log("[-] .bistore directory not found");
        }
    }
});
