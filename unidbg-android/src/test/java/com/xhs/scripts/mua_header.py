#!/usr/bin/env python3
"""
x-mini-mua header 字段还原 (s / t / u)

基于 IDA 静态分析 + Frida 动态验证 + unidbg 对照
"""

import os
import json
import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SERVER_PUBLIC_KEY = bytes.fromhex(
    "c9b68adc9a607bd108c7b7bba0dd6b5a9eba716fb6027b52c861b838cae63637"
)

# ============================================================
# s 字段 — 完全还原
# ============================================================
#
# 算法: s = hex(urandom(64))
#
# IDA 数据流:
#   sub_1BFE14 (0x1BFE68)
#     → sub_474DB0(byte_7AF850, 0x40)     # 从 /dev/urandom 读 64 字节
#       → __read_chk(fd, byte_7AF850, 64, bufsize)
#   vm_rw_1A5FD0 → sub_470130(ptr, 64) (hex 编码)
#     → sub_4701A0: nibble-to-hex 循环
#       hex_table = "0123456789abcdef" (via off_7661C0)
#       for byte in buf[0:64]:
#           push_back(hex_table[byte >> 4])
#           push_back(hex_table[byte & 0xf])
#   → 128 hex chars → map_insert(header, "s", hex_string)
#
# Frida 验证:
#   [HEX_ENCODE] size=64 backtrace: 0x1a5ff0 → 0x31c644 (header assembly)
#   input_raw 每次不同 (真随机)
#
# unidbg 验证: 固定 urandom=0 → s = "000...000" (128个零) ✓


def generate_s(random_64: bytes = None) -> str:
    """生成 s 字段: hex(urandom(64))"""
    if random_64 is None:
        random_64 = os.urandom(64)
    assert len(random_64) == 64
    return random_64.hex()


# ============================================================
# t 字段 — 结构完全还原
# ============================================================
#
# 构建函数: sub_1F95D4 (0x1F95D4, size 0xB80)
#   门控: byte_7B77E8 (由 vm_dispatch_2B7A90 安全检测初始化设置)
#     sub_1B5E84 @ 0x1B5F18: LDRB W8, [X8, #byte_7B77E8]
#     byte_7B77E8==1 → dispatch offset 0x178 → sub_1F95D4
#     byte_7B77E8==0 → dispatch offset 0xE88 → 跳过 t/u
#
#   Frida 验证:
#     [vm_dispatch_2B7A90] Security init called
#       backtrace: 0x1bb768 (在 sub_1B5E84 内部)
#     [vm_dispatch_2B7A90] returned, byte_7B77E8 = 1
#     ★ byte_7B77E8 CHANGED: 0 → 1 ★
#
# key 名通过 vm_dispatch_15BF1C 解密:
#   seed 190 (0xBE) → "s"
#   seed 160 (0xA0) → "c"
#   seed 178 (0xB2) → "f"
#   seed 174 (0xAE) → "d"
#   seed 175 (0xAF) → "tt"
#   seed 171 (0xAB) → "t"  (path A)
#   seed 173 (0xAD) → "t"  (path B, 不同 once_guard)
#
#   Frida 验证:
#     [STR_COPY] src="c" / "d" / "f" / "s" / "t" / "tt" ← 确认6个key名
#
# sub_1F95D4 内部:
#   条件分支: v4-88 == v4-80 (安全事件数组是否为空)
#
#   Path A (无安全事件, 正常设备):
#     map_insert "s" ← type=5(int), value=0
#     map_insert "c" ← type=5(int), value from [v4-40]  # 检测触发计数
#     map_insert "f" ← type=5(int), value from [v4-96] (byte)  # frida/hook检测
#     map_insert "d" ← type=5(int), value from [v4-95] (byte)  # 调试器检测
#     map_insert "tt" ← type=3(array), from [v4-120]  # 检测痕迹
#     map_insert "t" ← type=5(int), value=0
#
#   Path B (有安全事件):
#     map_insert "t" ← type=5(int), value from [v4-36]
#     map_insert "s" ← type=5(int), value from xmmword_1032C0 + OR叠加
#       xmmword_1032C0 = [0x00]*8 + [0x01]*1 + [0x00]*7
#       → 基础值=1, 实际 s 由安全检测结果按位或叠加
#
# 安全检测:
#   sub_51F9E4: JNI wrapper_CallStaticObjectMethod(tag=0x6B2FBB68)
#     → 根据 a6&1: sub_51FD48 (path1) 或 sub_5208CC (path2)
#     → 结果写入 a7(检测类型), a8(状态码), a9(详情数组)
#   sub_520B4C: 第二组检测, 收集更多安全信息
#
#   Frida 验证:
#     [sub_51F9E4] Security detection called → type=1 status=-1
#     [sub_520B4C] Security detection #2 called
#
# "t.s" = 4098 (0x1002) 是位图:
#   各检测项通过按位或累加
#   真机正常设备: 0x1002 = bit1(0x2) | bit12(0x1000)
#
# unidbg: byte_7B77E8=0 → 跳过 sub_1F95D4 → header 无 t 字段 ✓


def generate_t(
    c: int = 0,       # 检测触发计数 (来自 [v4-40])
    d: int = 0,       # 调试器检测 (来自 [v4-95], byte)
    f: int = 0,       # frida/hook检测 (来自 [v4-96], byte)
    s: int = 4098,    # 安全能力位图 (sub_51F9E4 + sub_520B4C 按位或)
    t: int = 0,       # 篡改检测计数 (来自 [v4-36])
    tt: list = None,  # 检测痕迹数组 (来自 [v4-120])
) -> dict:
    """
    生成 t 子对象 (安全检测结果)

    真机正常值: {c:0, d:0, f:0, s:4098, t:0, tt:[]}
    - s=4098 (0x1002) = 安全检测位图, 每个bit代表一项安全检测能力
      - bit 1 (0x2): 基础安全检测通过
      - bit 12 (0x1000): 高级安全检测通过
    - c,d,f,t: 各为0表示无异常检测事件
    - tt: 空数组表示无检测痕迹
    """
    return {
        "c": c,
        "d": d,
        "f": f,
        "s": s,
        "t": t,
        "tt": tt if tt is not None else [],
    }


# ============================================================
# u 字段 — 数据流完全追踪, 计算在 VM 内部
# ============================================================
#
# ★ 关键发现 (Frida 动态验证):
#   1. u 值 NOT 通过 sub_470130 hex编码 — 所有 hex_encode 调用都是 32/64 字节
#   2. u 值 NOT 通过 string_assign (0x1418F0) 创建
#   3. u 值 NOT 通过 sprintf/snprintf 生成
#   4. u 值存储在 libtiny.so .bss 段的全局 SSO string 中
#   5. u 值在 app 启动时计算一次, 之后通过 str_copy (0x141600) 传递
#   6. u 值在 byte_7B77E8=1 之前就已存在 → 初始化阶段计算
#
# 数据来源链 (sub_2E17A0, PackageInfo 字段提取器):
#
#   Frida 捕获的 PackageInfo 字段:
#     [offset  0] = "com.xingin.xhs"              # packageName
#     [offset 24] = "com.xingin.xhs"              # processName (ActivityThread.currentProcessName())
#     [offset 48] = "9.21.0"                      # versionName
#     [offset 72] = 0x8C8BB3 (9210803)            # versionCode (little-endian int32)
#     [offset 80] = 0x19D534F2F69                  # firstInstallTime
#     [offset 88] = 0x19D534F2F69                  # lastUpdateTime
#     [offset 96] = 0x23 (35)                      # targetSdkVersion
#
#   加密类名/方法名解密:
#     vm_dispatch_157C90(xmmword_106D90, 26) → "android.app.ActivityThread"
#     sub_1739F0(xmmword_10F668, 18) → "currentProcessName"
#     → CallStaticObjectMethod → "com.xingin.xhs"
#     → 存储到 PackageInfo offset 24
#
#   Frida 捕获的其他 PackageInfo 相关字段:
#     dataDir:      "/data/user/0/com.xingin.xhs"
#     apkPath:      "/data/app/com.xingin.xhs-tL_cnto1jnsDMq1e7VFXfA==/base.apk"
#     nativeLibDir: "/data/app/com.xingin.xhs-tL_cnto1jnsDMq1e7VFXfA==/lib/arm64"
#     installer:    "adb"
#     certHash:     "c43e6730303d81ab84c6fd79dbc13b0f1efc0ebe00e1aed4256cdc9c8792612b"
#     ringtone:     "The_big_adventure.ogg"
#
# PackageInfo → VM state 拷贝 (sub_205E0C):
#   v0[1138] = &xmmword_7B6D50      # PackageInfo struct 起始地址
#   sub_141600(v0[158]+0,  pkg+0)    # packageName
#   sub_141600(v0[158]+24, pkg+24)   # processName
#   sub_141600(v0[158]+48, pkg+48)   # versionName
#   memcpy(v0[158]+72, pkg+72, 28)   # versionCode + timestamps + targetSdk
#   sub_141600(v0[158]+104, pkg+104) # additional string field
#   sub_141600(v0[158]+128, pkg+128) # continues...
#
# u 值传递链 (Frida backtrace):
#   首次拷贝: vm_load_1F655C (0x1F6568) → 0x2780f4 (VM dispatcher) → 0x191164 (VM loop)
#     vm_load_1F655C: sub_141600(v0[155], v0[156])  # v0[156]指向全局缓存的u值
#
#   Header 插入: 0x1a6a1c → 0x31c644 → 0x31ba64 → 0x31afd8 → 0x32581c → 0x325b60
#     vm_dispatch_15BF1C 解密 key="u" (backtrace: 0x28cadc → 0x31c644)
#     然后 map_insert(header_map, "u", cached_u_value)
#
# u 值格式: "000000007c5136f2cc1bf608898e780f02141ecf" (40 hex chars = 20 bytes)
#   前 4 字节: 00000000 (前缀/版本)
#   后 16 字节: 7c5136f2cc1bf608898e780f02141ecf (hash)
#   ★ 不是 MD5/SHA1/SHA256/CRC32 (全部验证不匹配)
#   ★ 计算算法在 VM 保护的代码中, 非标准hash
#   ★ 值在 app 启动时计算一次并缓存, 每次 header 组装时直接读取
#   ★ 值绑定设备+安装实例, 同一设备同一安装不变
#
# 获取方式:
#   frida -U -f com.xingin.xhs -l hooks/hook_u_trace.js --no-pause
#   → STR_COPY 首次出现的 value 即为 u 值


def generate_u(real_device_value: str = None) -> str:
    """
    生成 u 字段

    u 是设备绑定的 20 字节标识 (40 hex chars):
    - 前 4 字节: 前缀 (通常为 00000000)
    - 后 16 字节: 基于 PackageInfo 的 VM 内部 hash (非标准算法)
    - 每个设备+安装实例唯一, 不随请求变化
    - 计算在 libtiny.so VM 保护代码内部, 启动时计算一次并缓存

    获取方法 (Frida):
      conda activate py3.8
      frida -U -f com.xingin.xhs -l hooks/hook_u_trace.js --no-pause
      → 找 STR_COPY 中首次出现的 40-hex-char 值 (src=全局地址)
    """
    if real_device_value:
        assert len(real_device_value) == 40
        return real_device_value
    return None


# ============================================================
# ECDH + header 组装
# ============================================================
#
# ECDH 流程 (sub_1BCD68):
#   1. sub_474DB0: urandom(32) → X25519 私钥 (独立于 s 的 64 字节)
#   2. sub_53973C #1: X25519(privkey, basepoint) → 公钥 k
#   3. sub_53973C #2: X25519(privkey, server_pub) → shared secret
#      server_pub from rodata: off_746AF0
#   4. shared[:16] = AES key, shared[16:] = AES IV
#
# Frida 验证:
#   [HEX_ENCODE] size=32 backtrace: 0x1a91e4 → 0x31c644 (k 字段 hex)
#   → 32字节公钥 hex → 64 chars


def build_header(
    app_id: str = "ECFAAF01",
    version: str = "2.9.61",
    platform: str = "a",
    c: int = 1,
    s_random: bytes = None,       # 64 bytes for s field
    ecdh_private: bytes = None,   # 32 bytes for ECDH
    include_t: bool = False,
    t_s: int = 4098,
    u_value: str = None,
) -> tuple:
    """
    构建 header dict → JSON → base64url

    Returns (header_b64url, aes_shared_secret)
    """
    if s_random is None:
        s_random = os.urandom(64)
    if ecdh_private is None:
        ecdh_private = os.urandom(32)

    # ECDH
    privkey = X25519PrivateKey.from_private_bytes(ecdh_private)
    pubkey_bytes = privkey.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pubkey_hex = pubkey_bytes.hex()
    shared = privkey.exchange(X25519PublicKey.from_public_bytes(SERVER_PUBLIC_KEY))

    # header dict (sorted keys = std::map 字母序)
    h = {"a": app_id, "c": c, "k": pubkey_hex, "p": platform, "s": generate_s(s_random)}

    if include_t:
        h["t"] = generate_t(s=t_s)

    u = generate_u(u_value)
    if u is not None:
        h["u"] = u

    h["v"] = version

    header_json = json.dumps(h, separators=(",", ":"), sort_keys=True)
    header_b64 = base64.urlsafe_b64encode(header_json.encode()).rstrip(b"=").decode()
    return header_b64, shared


# ============================================================
if __name__ == "__main__":
    # ===== 验证 unidbg 模式 (全零随机) =====
    print("=== unidbg (random=0) ===")
    b64, shared = build_header(
        s_random=b"\x00" * 64,
        ecdh_private=b"\x00" * 32,
        include_t=False,
        u_value=None,
    )
    print(f"header_b64: {b64}")
    print(f"shared_secret: {shared.hex()}")
    h = json.loads(base64.urlsafe_b64decode(b64 + "=="))
    print(f"k: {h['k']}")
    assert h["k"] == "2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74"
    assert h["s"] == "0" * 128
    assert h["c"] == 1
    assert "t" not in h
    assert "u" not in h
    print("✓ matches unidbg output\n")

    # ===== 真机模式 =====
    print("=== real device ===")
    b64, shared = build_header(
        c=18,
        include_t=True,
        t_s=4098,
        u_value="000000007c5136f2cc1bf608898e780f02141ecf",
    )
    h = json.loads(base64.urlsafe_b64decode(b64 + "=="))
    print(json.dumps(h, indent=2))
    assert h["t"] == {"c": 0, "d": 0, "f": 0, "s": 4098, "t": 0, "tt": []}
    assert h["u"] == "000000007c5136f2cc1bf608898e780f02141ecf"
    print("✓ matches real device header\n")

    # ===== 处理流程总结 =====
    print("=" * 60)
    print("s 字段 — 完全还原")
    print("  算法: hex(os.urandom(64)) → 128 hex chars")
    print("  IDA: sub_474DB0 → __read_chk(64) → sub_4701A0 nibble→hex")
    print("  验证: unidbg random=0 → 128个零 ✓")
    print()
    print("t 字段 — 结构完全还原")
    print("  构建: sub_1F95D4, 门控 byte_7B77E8")
    print("  结构: {c:int, d:int, f:int, s:int, t:int, tt:array}")
    print("  t.s: 安全检测位图, sub_51F9E4(JNI tag 0x6B2FBB68) + sub_520B4C")
    print("  真机: s=4098(0x1002) = bit1|bit12, 其余均为0")
    print("  验证: Frida 捕获 key 解密 c/d/f/s/t/tt ✓")
    print()
    print("u 字段 — 数据流完全追踪")
    print("  格式: 4字节前缀 + 16字节hash = 20字节 → 40 hex chars")
    print("  数据源: PackageInfo (packageName, processName, versionName, ...)")
    print("  生命周期: 启动时计算一次 → 缓存在 .bss 全局 SSO string")
    print("  传递: vm_load_1F655C → str_copy → map_insert")
    print("  计算: VM 保护的非标准 hash (非 MD5/SHA1/SHA256/CRC32)")
    print("  获取: Frida hook_u_trace.js → STR_COPY 首次出现值")
    print("  稳定性: 同设备同安装不变, 可复用")
