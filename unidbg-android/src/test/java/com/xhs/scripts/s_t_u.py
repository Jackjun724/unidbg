#!/usr/bin/env python3
"""
s_t_u.py — 小红书 libtiny.so 请求头 s / t / u 字段生成

=== 逆向分析工具 ===
- Frida 14.2.2 动态 hook (Pixel 4 真机, Android 10)
- IDA Pro MCP 静态反编译 (libtiny.so ARM64)
- unidbg ARM64 模拟验证

=== 分析结论 ===
s: 纯随机 64 字节 → hex (128字符)
t: 固定 JSON 结构（安全检测结果，检测 flag=0 时输出默认值）
u: 设备持久化标识 uniform_id，首次启动由 VM 内部生成后缓存
"""

import os
import json
import hashlib
from pathlib import Path


# ============================================================
# s 字段
# ============================================================

def generate_s() -> str:
    """
    s 字段: 128 字符随机 hex

    === 证据链 ===

    1. Frida hook __read_chk:
       - 确认从 /dev/urandom 读取 64 字节
       - [RANDOM] fd=X sz=64 data=<random_bytes>

    2. IDA sub_470130 (hex encoder):
       - sub_470130(buf, 64) 逐字节转换为小写 hex
       - 输入 64 字节 → 输出 128 字符

    3. Frida hook sub_470130:
       - [HEX_ENCODE] size=64 input_raw=<64字节>
       - backtrace: 0x1f8474 → 0x2780f4 → 0x191164

    结论: s = hex(urandom(64))，每次请求重新生成
    """
    return os.urandom(64).hex()


# ============================================================
# t 字段
# ============================================================

def generate_t() -> str:
    """
    t 字段: 安全检测结果 JSON

    === 证据链 ===

    1. IDA sub_1B5E84 (安全检测 dispatch):
       - 检查 byte_7B77E8 (安全检测 flag)
       - byte_7B77E8 = 0 → offset 3720 → 跳过检测, 输出默认值
       - byte_7B77E8 = 1 → offset 376 → 执行 root/frida/hook 检测
       - unidbg/正常环境下 byte_7B77E8 = 0

    2. Frida hook map_insert (0x28C7E8):
       - 捕获 key="t" value=此 JSON
       - 确认在未检测到异常时输出固定默认值

    3. 字段含义:
       - s=4098 (0x1002): 固定 status flags
       - c/d/f/t=0: 各检测项未触发
       - tt=[]: 检测详情列表为空

    结论: t = 固定 JSON, 安全检测全部跳过
    """
    return json.dumps(
        {"c": 0, "d": 0, "f": 0, "s": 4098, "t": 0, "tt": []},
        separators=(",", ":"),
    )


# ============================================================
# u 字段
# ============================================================

# 持久化存储路径 (模拟设备的 MMKV 存储行为)
_U_CACHE_FILE = Path(__file__).parent / ".uniform_id_cache"


def generate_u(device_u: str | None = None) -> str:
    """
    u 字段: 设备持久化标识 (uniform_id)

    格式: "00000000" + 32 字符 hex (共 40 字符)
    含义: 4字节版本前缀(0x00000000) + 16字节设备标识(hex编码)

    === 证据链 (READ 路径 — 完整追踪) ===

    1. Frida hook sub_19C174 (Java→native 入口):
       - Java 调用 native 方法获取 u

    2. IDA sub_1A1E98 → sub_1A1F00 (blob_load wrapper):
       - 加锁 pthread_mutex (stru_7B34A0)
       - 从 qword_7AFF60 读取 blob name (解密后 = "uniform_id")
       - 调用 sub_2F4DB0(name, strlen, &sso_output, 0)
       - Blob name 加密存储: 0x1040E0 字节 f5 88 92 66 ed 6b bb 3b 4b 23
         → 经 sub_19E824 解密为 "uniform_id"

    3. Frida hook sub_2F4DB0 (blob_load):
       - blob_load("uniform_id", 10, &output, 0)
       - 返回 0x1 (成功), output = "000000007c5136f2cc1bf608898e780f02141ecf"

    4. IDA sub_1A1F80 (u global 写入):
       - str_copy(u_global @ base+0x7B34E8, loaded_value)
       - 设置 init flag = 1

    5. Frida hook sub_141600/sub_1418F0 (str_copy/string_assign):
       - *** U = "000000007c5136f2cc1bf608898e780f02141ecf"
       - backtrace: 0x1a1f94 → 0x19c188

    === 证据链 (存储位置) ===

    6. MMKV 文件 (Frida mmap/openat hook):
       - 路径: /data/user/0/com.xingin.xhs/cache/a6de269810198701a152619ebd19abc1
       - MMKV keys: first_launch_time, last_launch_time, launch_count, uniform_id
       - MMKV 静态链接在 libtiny.so 内部 (非独立 libmmkv.so)

    7. Frida hook_u_recompute.js memcpy 追踪:
       - MC#43: first_launch_time=1775470588
       - MC#49-54: uniform_id 数据在 MMKV protobuf 中的原始编码
       - 值: "000000007c5136f2cc1bf608898e780f02141ecf"

    === 证据链 (FAIL 路径 — 无重新生成) ===

    8. Frida 强制 blob_load 返回 0 (失败):
       - blob_load("uniform_id") 原本返回 0x1 → 强制替换为 0
       - 结果: u 保持空, VM 直接返回, 不触发重新生成
       - IDA sub_1A1FD0: 仅 free + mutex_unlock, 无生成逻辑

    === 证据链 (生成算法 — VM 内部) ===

    9. 生成路径分析:
       - 生成发生在首次启动的独立 JNI 调用中, 非 u-read 路径 (sub_19C174)
       - Frida hash hook (sub_64EBDC): 生成期间未触发任何外部 hash 函数
       - IDA xref sub_470130: 所有调用者 size=32/64, 无 size=16 调用
       - 结论: VM bytecode 内联 hash + hex 实现, 无外部函数调用

    10. 文件删除实验 (Frida hook_u_nuke.js):
        - 删除 16 个存储文件 (cache MMKV, com.capa.devicekit, did_value_manager 等)
        - blob_load("uniform_id") 仍然返回 0x1 → MMKV mmap 内存缓存

    11. unidbg 验证:
        - 无 bistore 文件时, u 字段为空 → 确认生成在独立初始化路径

    === 生成算法结论 ===

    u 的生成由 VM bytecode (sub_1BC844) 内部完成:
    - 16 字节输出 (MD5 大小), VM 内联 hash 实现
    - 格式化为 "00000000" + hex(16_bytes)
    - 通过 blob_store (sub_1A2040) 持久化到 MMKV
    - 后续启动直接从 MMKV 读取, 不再重新生成

    VM 内部算法不可逆 (computed BR dispatch, 47831 handlers),
    但输出行为等价于: "00000000" + hex(random_or_hash_16_bytes)
    服务端将 u 作为设备标识追踪, 要求格式正确且每设备唯一.

    === 使用方式 ===

    方式1 (推荐): 从真机 Frida 捕获
        frida -U -f com.xingin.xhs -l hooks/hook_u_capture.js --no-pause
        # 或: readSSO(base.add(0x7B34E8))
        u = generate_u("000000007c5136f2cc1bf608898e780f02141ecf")

    方式2: 自动生成 (格式正确, 每次调用生成新设备身份)
        u = generate_u()  # 自动生成并缓存

    方式3: 从 unidbg 获取 (需提供 bistore 文件)
        # 将真机 MMKV 文件 pull 到本地:
        # adb pull /data/user/0/com.xingin.xhs/cache/a6de269810198701a152619ebd19abc1 bistore_main.bin
        # adb pull /data/user/0/com.xingin.xhs/cache/a6de269810198701a152619ebd19abc1.crc bistore_crc.bin
    """
    if device_u is not None:
        # 使用指定的 u 值 (从真机捕获)
        assert len(device_u) == 40 and device_u[:8] == "00000000", \
            f"u 格式错误: 需要 '00000000' + 32hex, 实际: {device_u}"
        return device_u

    # 自动生成: 检查缓存
    if _U_CACHE_FILE.exists():
        cached = _U_CACHE_FILE.read_text().strip()
        if len(cached) == 40 and cached[:8] == "00000000":
            return cached

    # 首次生成: "00000000" + 16 随机字节 hex
    # 模拟 VM 内部行为: 生成一次, 持久化缓存
    u = "00000000" + os.urandom(16).hex()
    _U_CACHE_FILE.write_text(u)
    return u


# ============================================================
# 主函数
# ============================================================

if __name__ == "__main__":
    s = generate_s()
    t = generate_t()

    # 从 Pixel 4 设备通过 Frida 捕获的 u 值
    DEVICE_U = "000000007c5136f2cc1bf608898e780f02141ecf"
    u = generate_u(DEVICE_U)

    print(f"s = {s}")
    print(f"  长度: {len(s)}, 纯随机 hex")
    print(f"t = {t}")
    print(f"  固定 JSON, 安全检测跳过")
    print(f"u = {u}")
    print(f"  设备标识, 格式: 00000000 + {u[8:]}")

    print("\n--- 自动生成模式 ---")
    u_auto = generate_u()
    print(f"u (auto) = {u_auto}")
    print(f"  缓存文件: {_U_CACHE_FILE}")
