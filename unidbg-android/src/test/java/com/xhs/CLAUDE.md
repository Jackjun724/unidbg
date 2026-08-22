# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

小红书(Xiaohongshu) native library逆向分析项目，基于 unidbg ARM64 模拟器，分析 libtiny.so（设备指纹采集）和 libxyass.so（Shield v9.21 请求签名）。

最终目标：生成4个请求头字段：
- **x-shield** — `Xhs921Shield.java` 生成，libxyass.so Shield v9.21 签名
- **x-mini-mua** — `Xhs921.java` 生成，设备指纹信息（145+字段的加密载荷）
- **x-mini-s1** — `Xhs921.java` 生成，时间戳签名
- **x-mini-sig** — `Xhs921.java` 生成，请求内容签名

## Build & Run

```bash
# 一键运行 (执行 Xhs921.java main)
/bin/zsh /Users/jackjun/Desktop/unidbg/run.sh

# 或手动编译运行
cd /Users/jackjun/Desktop/unidbg
mvn -q -pl unidbg-android -am compile test-compile -Dmaven.test.skip=false
java -cp "unidbg-android/target/classes:unidbg-android/target/test-classes:$(mvn -pl unidbg-android dependency:build-classpath -q -DincludeScope=test -Dmdep.outputFile=/dev/stdout)" com.xhs.Xhs921
```

也可通过 IDE 直接运行 `Xhs921.java` 或 `Xhs921Shield.java` 的 main() 方法。

需要 APK 资源文件：`unidbg-android/src/test/resources/xiaohongshu.apk`

## Tools

### unidbg (ARM64 模拟器)
- 运行方式: `/bin/zsh /Users/jackjun/Desktop/unidbg/run.sh` 或 IDE 直接运行
- 用途: 模拟执行 libtiny.so / libxyass.so，生成签名字段，trace 指令流

### Frida 14.2.2 (动态 hook)
- **前置条件**: 需要先 `conda activate py3.8` 切换到 Python 3.8 环境
- 用途: 真机动态分析，hook native 函数，dump 运行时数据
- 运行示例: `frida -U -f com.xingin.xhs -l hook脚本.js --no-pause`

### IDA Pro MCP (静态分析)
- 通过 `.mcp.json` 配置，直接连接分析 libtiny.so
- 用途: 反编译、字节搜索(find_bytes)、xref 分析、函数查询

### scrcpy (手机投屏)
- 可以获取连接手机的屏幕画面

### JADX MCP
- APK 反编译，查看 Java 层代码

## Architecture

```
Xhs921.java (指纹 + 签名)
  ├─ AndroidEmulator (ARM64 + Unicorn2 backend)
  ├─ DalvikVM → 加载 xiaohongshu.apk → libtiny.so
  ├─ AbstractJni (mock Android API: Battery, Intent, Settings等)
  ├─ HookZz (函数hook: JSON序列化、加密、系统调用)
  └─ IOResolver (虚拟文件系统: .bistore 加密数据库)
  → 输出: x-mini-mua, x-mini-s1, x-mini-sig

Xhs921Shield.java (Shield签名)
  ├─ libxyass.so → Shield v9.21
  └─ 算法链: AES-CBC → HMAC-MD5 → RC4 → Base64("XY"+ciphertext)
  → 输出: x-shield
```

## Directory Structure

```
xhs/
├── Xhs921.java           # 主分析类：指纹+签名（libtiny.so）→ mua/s1/sig
├── Xhs921Shield.java     # Shield v9.21 签名（libxyass.so）→ x-shield
├── hooks/                 # Frida hook 脚本（真机动态分析）
│   ├── mini_mua.js        # 真机指纹配置（145+字段，部分可变）
│   ├── hook_x_mini.js     # hook真机x-mini系列字段，配合py解密mua
│   ├── hook_x146_*.js     # x146 hash字段追踪系列
│   ├── hook_x234_*.js     # x234 字段分析
│   ├── hook_x32_intent.js # Battery Intent hook
│   └── hook_bistore_read.js
├── docs/                  # 逆向分析文档
│   ├── fp.md              # 指纹字段映射（37KB，145+字段详情）
│   ├── vm_opcode_map.md   # VM opcode 文档
│   └── x146_*.md          # x146 hash 逆向分析步骤
├── scripts/               # Python 算法实现
│   └── shield_v921.py     # Shield v9.21 纯Python实现
├── context/               # 真机指纹数据
│   └── mini_mua.js        # 真机指纹JSON配置
├── trace/                 # 运行时 trace 输出
└── .mcp.json              # IDA Pro MCP 服务配置
```

## 算法参考 (/Users/jackjun/Desktop/xhs_algo/)

外部 Python 算法实现，用于验证和调试：

| 文件 | 用途 | 核心算法 |
|------|------|----------|
| `x_mini_mua.py` | MUA 解密/加密 | X25519 ECDH(全零私钥) + AES-CBC + zlib |
| `x_mini_s1.py` | S1 签名生成 | BionicRandom + 4阶段S-Box + AES-128-CBC + CRC32 |
| `x_mini_sig.py` | SIG 签名生成 | SHA256 + GF(2^8) 矩阵乘法 |
| `hex_sbox_transform.py` | SHA256 S-Box 变换 | 4阶段 nibble/CRC/XOR 混淆 |
| `shield_v921.py` | Shield 签名 | AES-CBC + HMAC-MD5 + RC4 |
| `api.py` | FastAPI 签名服务 | 封装 s1/sig/mua 计算 |

### MUA 解密使用说明
- `x_mini_mua.py` 可解密 mua token → JSON 明文（设备指纹）
- **前提**: mua 必须是通过 unidbg 生成的，或者通过 Frida 固定了真机的 `__read_chk`（`hooks/hook_x_mini.js` 将 32 字节随机数置零）
- S1/SIG 签名输入格式: `"{method}\n{path}\n{query}\n{body_sha256}\n{mua}"`

## Key Addresses (libtiny.so)

| 地址 | 函数 | 用途 |
|------|------|------|
| 0x28C7E8 | map_insert | SSO key → RB-tree 插入 |
| 0x172278 | byte_reader | JSON value 逐字节写入 |
| 0x170B70 | dispatcher | JSON 元素分发 |
| 0x175118 | native_entry | 所有 JNI 调用入口 |
| 0x141600 | str_copy | SSO string 复制 |
| 0x1418F0 | string_assign | std::string::assign |
| 0x2F4DB0 | blob_load | .bistore 解密加载 |
| 0x2B47D4 | deserialize_map | 反序列化 blob → map |

## Analysis Workflow

**核心原则**: 优先通过 Frida 或 IDA Pro 确定关键地址，优先动态分析。在确定 unidbg 有对应流程时，可通过 trace unidbg 加速关键节点的确定。

指纹字段追踪分两条路径：

1. **unidbg trace 可追踪的字段**（值存在但不正确）：trace 文件中定位 map_insert → 回溯 VM 寄存器写入 → 找到 ultimate source (JNI/syscall/VM常量) → 修复 mock
2. **.bistore 存储的字段**（完全缺失）：Frida 真机 hook map_insert → IDA 反编译找全局变量 → xrefs_to 追踪写入链 → dump blob 解密内容 → 注入 unidbg 虚拟文件系统

详细流程参见 custom command: `trace-fp-field`

### Frida 真机调试流程
```bash
conda activate py3.8
frida -U -f com.xingin.xhs -l hooks/hook_x_mini.js --no-pause  # hook x-mini 系列
# 输出的 mua 可通过 xhs_algo/x_mini_mua.py 解密
```

## ARM64 STR 指令编码（用于 IDA find_bytes）

`STR Xt, [Xn, #offset]` 编码规则（64-bit store, unsigned offset）：
```
imm12 = offset / 8
Rn = 寄存器编号 (如 X19=19)
byte0 = Rt（未知，用 ??）
byte1 = ((Rn & 0x7) << 5) | ((imm12 & 0x3F) << 2) 的低8位
       = (imm12 & 0x3F) << 2 | (Rn >> 3)    -- 因为 Rn[2:0] 在 bit[7:5]
byte2 = (imm12 >> 6)                          -- STR: opc=00, 高2位为0
byte3 = 0xF9

STR: byte2 = (imm12 >> 6)          → find_bytes: "?? byte1 byte2 F9"
LDR: byte2 = (imm12 >> 6) | 0x40   → find_bytes: "?? byte1 byte2 F9"
```
示例：`STR Xt, [X19, #0xBE0]` → imm12=0x17C → byte1=0xF2, byte2=0x05 → `"?? F2 05 F9"`
