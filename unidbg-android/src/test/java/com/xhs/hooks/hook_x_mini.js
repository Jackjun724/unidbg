
// Hook __read_chk 用于固定mua生成的加密密钥
Interceptor.attach(Module.findExportByName(null, "__read_chk"), {
  onEnter: function (args) {
    // console.log("[+] hook  __read_chk");
    this.fd = args[0].toInt32();
    this.buffer = args[1];
    this.size = args[2].toInt32();
    this.bufsize = args[3].toInt32();
  },
  onLeave: function (retval) {
    if (this.size == 32) {
      // console.log("[+] Original __read_chk data:", hexdump(this.buffer, { length: 0x20 }));

      // 定义要填入的hex字符串
      const hexValues = [
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
      ];

      // 根据实际size决定写入多少数据
      const writeSize = Math.min(this.size, hexValues.length);

      // 写入数据
      for (var i = 0; i < writeSize; i++) {
        Memory.writeU8(this.buffer.add(i), hexValues[i]);
      }

      // console.log("[+] Modified __read_chk data:", hexdump(this.buffer, { length: 0x20 }));
      // console.log("[+] Modified /dev/urandom __read_chk:", this.size, "bytes");
    }
  }
});

// hook x-mini-mua
Java.perform(function () {

  let f = Java.use("fka.f");
  let Base64 = Java.use("android.util.Base64");
  let HashMap = Java.use("java.util.HashMap");
  let MapEntry = Java.use("java.util.Map$Entry");
  let logId = 0;

  f["k"].implementation = function (str, str2, bArr) {
    logId++;
    let id = logId;
    let ts = new Date().toLocaleTimeString();

    let bArrBase64 = "<null>";
    try {
      if (bArr != null) {
        bArrBase64 = Base64.encodeToString(bArr, 2);
      }
    } catch (e) {
      bArrBase64 = `<base64_error: ${e}>`;
    }

    console.log(`\n┌─────────────────────────────────────────┐`);
    console.log(`│  fka.f.k()  #${id}  [${ts}]`);
    console.log(`├─────────── params ───────────┤`);
    console.log(`│  str1 : ${str}`);
    console.log(`│  str2 : ${str2}`);
    console.log(`│  bArr : ${bArrBase64}`);

    let result = this["k"](str, str2, bArr);

    console.log(`├─────────── result ───────────┤`);
    try {
      let map = Java.cast(result, HashMap);
      let entries = map.entrySet().toArray();
      for (let i = 0; i < entries.length; i++) {
        let entry = Java.cast(entries[i], MapEntry);
        console.log(`│  ${entry.getKey()} : ${entry.getValue()}`);
      }
    } catch (e) {
      console.log(`│  ${result}`);
    }
    console.log(`└─────────────────────────────────────────┘\n`);

    return result;
  };
})
