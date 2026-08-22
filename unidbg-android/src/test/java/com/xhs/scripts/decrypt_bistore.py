#!/usr/bin/env python3
"""
解密 MMKV .bistore 文件 (AES-128-CFB-128)

文件格式:
  [0:4]  actual_size (uint32 LE)
  [4:]   AES-128-CFB 加密的 protobuf KV pairs
         每条: varint(key_len) + key + varint(outer_val_len) + varint(inner_val_len) + raw_value

MMKV 是 append-only 日志，同一个 key 可能出现多次，最后一次为准。

用法:
  python3 decrypt_bistore.py <bistore_file> [crypto_key] [--iv HEX]
"""

import struct
import sys
import json
from Crypto.Cipher import AES


def pad_key(key_str: str) -> bytes:
    """MMKV key: 截断/零填充到 16 字节"""
    key = key_str.encode("utf-8")
    return key[:16].ljust(16, b"\x00")


def encode_varint32(value: int) -> bytes:
    """编码 protobuf varint32"""
    parts = []
    while value >= 0x80:
        parts.append((value & 0x7F) | 0x80)
        value >>= 7
    parts.append(value)
    return bytes(parts)


def read_varint32(data: bytes, offset: int):
    """protobuf varint32"""
    result = 0
    shift = 0
    while offset < len(data):
        b = data[offset]
        offset += 1
        result |= (b & 0x7F) << shift
        if b < 0x80:
            break
        shift += 7
        if shift >= 35:
            raise ValueError("varint32 overflow")
    return result, offset


def parse_kv_pairs(plaintext: bytes):
    """解析 varint(key_len)+key+varint(val_len)+value 格式"""
    pairs = []
    offset = 0
    while offset < len(plaintext):
        if plaintext[offset] == 0:
            break
        try:
            key_len, new_off = read_varint32(plaintext, offset)
            if key_len <= 0 or key_len > 10000 or new_off + key_len > len(plaintext):
                break
            key = plaintext[new_off:new_off + key_len]
            new_off += key_len

            val_len, new_off = read_varint32(plaintext, new_off)
            if val_len < 0 or new_off + val_len > len(plaintext):
                break
            val = plaintext[new_off:new_off + val_len]
            new_off += val_len
            pairs.append((key, val))
            offset = new_off
        except (ValueError, IndexError):
            break
    return pairs


def dedup_pairs(pairs):
    """MMKV append-only: 保留每个 key 的最后一次出现"""
    seen = {}
    for key, val in pairs:
        seen[key] = val
    return list(seen.items())


def strip_inner_varint(val: bytes) -> bytes:
    """剥离 MMKV value 的 varint 长度前缀，返回 raw data"""
    if len(val) >= 2:
        try:
            inner_len, inner_off = read_varint32(val, 0)
            if inner_off + inner_len == len(val) and inner_len > 0:
                return val[inner_off:]
        except (ValueError, IndexError):
            pass
    return val


def heuristic_parse(raw: bytes):
    """
    启发式解析 MMKV 二进制 value。
    自动识别 uint32(count) + repeated entries 结构。
    每个 field 是 uint16(len)+str 或 uint32(int/sub-count)。
    支持固定宽度和可变宽度(含 sub-count 嵌套列表)两种模式。
    """
    if len(raw) < 8:
        return None

    count = struct.unpack_from("<I", raw, 0)[0]
    if count == 0 or count > 5000:
        return None

    def try_read_str(data, off):
        """尝试在 off 处读 uint16(len)+str, 返回 (text, new_off) 或 None"""
        if off + 2 > len(data):
            return None
        slen = struct.unpack_from("<H", data, off)[0]
        if slen <= 0 or slen >= 4096 or off + 2 + slen > len(data):
            return None
        s = data[off + 2:off + 2 + slen]
        # 判断是否为可读文本: 尝试 UTF-8 解码, 检查可打印字符比例
        try:
            text = s.decode("utf-8")
            if slen > 2:
                printable = sum(1 for c in text if c.isprintable())
                if printable < len(text) * 0.5:
                    return None
        except UnicodeDecodeError:
            if slen > 2 and sum(1 for b in s if 32 <= b < 127) <= slen * 0.3:
                return None
            text = s.decode("utf-8", errors="replace")
        return text, off + 2 + slen

    def try_read_list(data, off):
        """尝试在 off 处读 uint32(sub_count) + sub_count 个 str, 返回 (list, new_off) 或 None"""
        if off + 4 > len(data):
            return None
        sub_count = struct.unpack_from("<I", data, off)[0]
        if sub_count == 0 or sub_count > 500:
            return None
        sub_off = off + 4
        items = []
        for _ in range(sub_count):
            r = try_read_str(data, sub_off)
            if r is None:
                return None
            items.append(r[0])
            sub_off = r[1]
        return items, sub_off

    def parse_one_entry(data, off, schema=None):
        """
        从 off 处解析一条 entry。
        schema=None 时自动发现; schema 给定时按 schema 解析。
        返回 (fields, new_off, schema) 或 None。
        """
        fields = []
        discovered = []
        idx = 0
        while off < len(data):
            if schema and idx >= len(schema):
                break
            expected = schema[idx] if schema else None

            if expected == "str" or expected is None:
                r = try_read_str(data, off)
                if r is not None:
                    fields.append(("str", r[0]))
                    discovered.append("str")
                    off = r[1]
                    idx += 1
                    if schema is None and len(fields) >= 20:
                        break
                    continue

            if expected == "list" or expected is None:
                r = try_read_list(data, off)
                if r is not None:
                    fields.append(("list", r[0]))
                    discovered.append("list")
                    off = r[1]
                    idx += 1
                    continue

            if expected == "u32" or expected is None:
                if off + 4 <= len(data):
                    val = struct.unpack_from("<I", data, off)[0]
                    fields.append(("u32", val))
                    discovered.append("u32")
                    off += 4
                    idx += 1
                    continue

            break

        if not fields:
            return None
        return fields, off, tuple(discovered)

    # Step 1: 贪心解析 entry 1 的所有可能 fields
    r1 = parse_one_entry(raw, 4)
    if r1 is None:
        return None
    all_fields, end_off, all_schema = r1

    # count=1 特殊处理: 无法通过重复验证 schema,
    # 使用贪心解析结果作为单条 entry (须消耗所有数据)
    if count == 1:
        if end_off >= len(raw) * 0.9 and len(all_fields) >= 2:
            return [all_fields]
        return None

    # Step 2: 尝试每种 schema 长度 (1, 2, 3, ...),
    # 找到最短的能成功解析所有 count 条 entry 的 schema
    for schema_len in range(1, min(len(all_schema) + 1, 15)):
        candidate_schema = all_schema[:schema_len]
        # 用 entry 1 的前 schema_len 个 fields 作为第一条
        # 需要重新解析以获取正确的 offset
        r = parse_one_entry(raw, 4, candidate_schema)
        if r is None:
            continue
        entries = [r[0]]
        off = r[1]
        ok = True
        for _ in range(count - 1):
            r = parse_one_entry(raw, off, candidate_schema)
            if r is None or r[2] != candidate_schema:
                ok = False
                break
            entries.append(r[0])
            off = r[1]
        if ok and len(entries) == count:
            return entries

    return None


def try_decode_value(val: bytes, key_name: bytes = None) -> str:
    """尝试解析 value 内部结构"""
    raw = strip_inner_varint(val)

    # 启发式结构化解析
    parsed = heuristic_parse(raw)
    if parsed is not None:
        return f"<structured: {len(parsed)} entries>"

    # 尝试 UTF-8 字符串
    try:
        text = raw.decode("utf-8")
        if all(c.isprintable() or c in "\n\r\t" for c in text):
            if len(text) <= 200:
                return repr(text)
            return repr(text[:100]) + f"... ({len(text)} chars)"
    except UnicodeDecodeError:
        pass

    if len(raw) <= 64:
        return raw.hex()
    return raw[:48].hex() + f"... ({len(raw)} bytes)"


def recover_iv_from_known_plaintext(ciphertext_block: bytes, expected_plain: bytes, key: bytes) -> bytes:
    """从已知明文恢复 AES-CFB IV"""
    aes_enc_iv = bytes(a ^ b for a, b in zip(expected_plain, ciphertext_block))
    return AES.new(key, AES.MODE_ECB).decrypt(aes_enc_iv)


def recover_iv(data: bytes, key: bytes) -> bytes:
    """
    自动恢复 IV:
    1. 用 IV=key 解密 (blocks 2+ 正确, block 1 错误)
    2. 在解密数据中找已知 key name 确定第一个 entry 的 key
    3. 从 blocks 2+ 中反推出第二个 entry 的偏移来计算 outer_val_len
    4. 构造 block 1 明文, 恢复 IV
    """
    # Step 1: 用 IV=key 解密, blocks 2+ 正确
    test_cipher = AES.new(key, AES.MODE_CFB, iv=key, segment_size=128)
    full_pt = test_cipher.decrypt(data)

    known_keys = [b"x14", b"x8", b"x13", b"x17", b"y1", b"uniform_id",
                  b"launch_count", b"last_launch_time", b"first_launch_time", b"111"]

    # Step 2: 找第二个 entry 的起始位置 (在 block 2+ 区域, offset >= 16)
    second_entry_offset = None
    second_key_name = None
    for try_off in range(16, min(len(full_pt), 10000)):
        b = full_pt[try_off]
        if b == 0 or b > 127:
            continue
        for kn in known_keys:
            if b == len(kn) and full_pt[try_off + 1:try_off + 1 + len(kn)] == kn:
                # 验证: 此处往后能继续解析多个 entry
                test_off = try_off
                valid_count = 0
                for _ in range(5):
                    try:
                        kl, o = read_varint32(full_pt, test_off)
                        if kl <= 0 or kl > 1000 or o + kl > len(full_pt):
                            break
                        o += kl
                        vl, o = read_varint32(full_pt, o)
                        if vl < 0 or o + vl > len(full_pt):
                            break
                        o += vl
                        valid_count += 1
                        test_off = o
                    except:
                        break
                if valid_count >= 3:
                    second_entry_offset = try_off
                    second_key_name = kn
                    break
        if second_entry_offset is not None:
            break

    if second_entry_offset is None:
        print("WARNING: Could not find second entry, using IV=key")
        return key

    print(f"  Found second entry at offset {second_entry_offset}: key={second_key_name.decode()!r}")

    # Step 3: 第一个 entry 从 offset 0 开始, 第二个在 second_entry_offset
    # 反推第一个 entry 的 key (在 block 1 的已知 key name 搜索)
    # 在 offset 1-15 中查找 key name
    first_key = None
    first_key_varint_end = None
    for kn in known_keys:
        varint_bytes = encode_varint32(len(kn))
        expected_start = len(varint_bytes)
        # key name 应该从 expected_start 开始
        # 但 block 1 是错的, 无法直接搜索
        # 改用: 从 second_entry_offset 反推
        # first_entry_size = second_entry_offset
        # = len(varint(key_len)) + key_len + len(varint(outer_val_len)) + outer_val_len
        header_size = len(varint_bytes) + len(kn)
        remaining = second_entry_offset - header_size
        if remaining <= 0:
            continue
        # remaining = len(varint(outer_val_len)) + outer_val_len
        # 尝试不同的 varint 长度
        for vl_size in range(1, 5):
            outer_val_len = remaining - vl_size
            if outer_val_len <= 0:
                continue
            test_varint = encode_varint32(outer_val_len)
            if len(test_varint) == vl_size:
                # 验证: 用这个 key 构造 block 1 明文
                p0 = bytearray(16)
                prefix = varint_bytes + kn + test_varint
                if len(prefix) > 16:
                    continue
                p0[:len(prefix)] = prefix
                # 剩余填充: value 的前几个字节
                # 从 blocks 2+ 的数据中推断 (如果 value 跨越 block 边界)
                val_start_in_pt = len(prefix)
                # value 数据在 full_pt[val_start_in_pt:] 但 block 1 部分不可信
                # 尝试用 confirmed data (同 key 的后续 entry) 的 value 结构
                # 查找同 key 的后续 entry
                found_later_val = None
                search_off = second_entry_offset
                while search_off < len(full_pt):
                    try:
                        skl, so = read_varint32(full_pt, search_off)
                        if skl <= 0 or skl > 10000 or so + skl > len(full_pt):
                            break
                        sk = full_pt[so:so + skl]
                        so += skl
                        svl, so = read_varint32(full_pt, so)
                        if svl < 0 or so + svl > len(full_pt):
                            break
                        if sk == kn:
                            found_later_val = full_pt[so:so + svl]
                        so += svl
                        search_off = so
                    except:
                        break

                # 用 confirmed value 的结构推断 block 1 中的 value 开头
                if found_later_val and len(prefix) < 16:
                    # value 开头结构相似: varint(inner_len) + raw_data
                    # inner_len 不同, 但 raw_data 头部可能相同
                    try:
                        later_inner_len, later_inner_off = read_varint32(found_later_val, 0)
                    except:
                        later_inner_off = 0
                    # 当前 entry 的 inner_len = outer_val_len - varint_size(inner_len)
                    for inner_vl_size in range(1, 4):
                        inner_len = outer_val_len - inner_vl_size
                        if inner_len <= 0:
                            continue
                        inner_varint = encode_varint32(inner_len)
                        if len(inner_varint) != inner_vl_size:
                            continue
                        # 构造 value 开头
                        val_header = inner_varint
                        pos = len(prefix)
                        for b in val_header:
                            if pos < 16:
                                p0[pos] = b
                            pos += 1
                        # 用 confirmed value 的 raw data 填充剩余
                        if found_later_val and later_inner_off > 0:
                            raw_data_start = 0
                            while pos < 16:
                                if raw_data_start < len(found_later_val) - later_inner_off:
                                    p0[pos] = found_later_val[later_inner_off + raw_data_start]
                                raw_data_start += 1
                                pos += 1

                        candidate_iv = recover_iv_from_known_plaintext(data[:16], bytes(p0), key)
                        # 验证
                        vc = AES.new(key, AES.MODE_CFB, iv=candidate_iv, segment_size=128)
                        vpt = vc.decrypt(data[:second_entry_offset + 32])
                        try:
                            vkl, voff = read_varint32(vpt, 0)
                            if 0 < vkl < 200:
                                vkey = vpt[voff:voff + vkl]
                                if vkey == kn:
                                    # 进一步验证: 第二个 entry 也能解析
                                    vkl2, voff2 = read_varint32(vpt, second_entry_offset)
                                    if 0 < vkl2 < 200:
                                        vkey2 = vpt[voff2:voff2 + vkl2]
                                        if vkey2 == second_key_name:
                                            print(f"  Recovered IV: {candidate_iv.hex()}")
                                            print(f"  First entry: key={kn.decode()!r}, outer_val_len={outer_val_len}")
                                            return candidate_iv
                        except:
                            pass

    print("WARNING: IV recovery failed, using IV=key (first 16 bytes may be wrong)")
    return key


def decrypt_bistore(filepath: str, crypto_key: str = None, iv_hex: str = None):
    with open(filepath, "rb") as f:
        raw = f.read()

    actual_size = struct.unpack_from("<I", raw, 0)[0]
    data = raw[4:4 + actual_size]

    print(f"File:         {filepath}")
    print(f"File size:    {len(raw)}")
    print(f"Actual size:  {actual_size} (0x{actual_size:x})")
    print()

    if not crypto_key:
        plaintext = data
        print("No crypto key — treating as plaintext")
    else:
        key = pad_key(crypto_key)

        if iv_hex:
            iv = bytes.fromhex(iv_hex)
        else:
            # 先尝试 IV=key, 如果 block 1 解析失败则自动恢复 IV
            test_cipher = AES.new(key, AES.MODE_CFB, iv=key, segment_size=128)
            test_pt = test_cipher.decrypt(data[:32])
            try:
                kl, off = read_varint32(test_pt, 0)
                if 0 < kl < 200:
                    k = test_pt[off:off + kl]
                    if all(32 <= b < 127 for b in k):
                        iv = key
                        print("IV=key works (standard MMKV)")
                    else:
                        raise ValueError()
                else:
                    raise ValueError()
            except:
                print("IV=key failed, attempting IV recovery...")
                iv = recover_iv(data, key)

        print(f"Crypto key:   {repr(crypto_key)} -> {key.hex()}")
        print(f"IV:           {iv.hex()}")
        cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
        plaintext = cipher.decrypt(data)
        print()

    # 解析 KV
    all_pairs = parse_kv_pairs(plaintext)
    pairs = dedup_pairs(all_pairs)

    print(f"Parsed {len(all_pairs)} entries, {len(pairs)} unique keys:")
    print("=" * 100)
    for i, (key_bytes, val) in enumerate(pairs):
        try:
            key_str = key_bytes.decode("utf-8")
        except UnicodeDecodeError:
            key_str = f"[hex:{key_bytes.hex()}]"
        print(f"[{i:3d}] {key_str:40s} ({len(val):5d}B) = {try_decode_value(val, key_bytes)}")
    print("=" * 100)

    # 详细输出结构化字段
    for key_bytes, val in pairs:
        raw = strip_inner_varint(val)
        parsed = heuristic_parse(raw)
        if parsed is None:
            continue
        key_str = key_bytes.decode("utf-8", errors="replace")
        print(f"\n--- {key_str} ({len(parsed)} entries) ---")
        for entry in parsed:
            parts = []
            for ftype, fval in entry:
                if ftype == "str":
                    parts.append(fval)
                elif ftype == "u32":
                    parts.append(f"[{fval}]" if fval != 0xFFFFFFFF else "[-1]")
                elif ftype == "list":
                    if len(fval) <= 3:
                        parts.append("{" + ", ".join(fval) + "}")
                    else:
                        parts.append("{" + ", ".join(fval[:3]) + f" ... +{len(fval)-3}" + "}")
            print(f"  {' | '.join(parts)}")

    # 导出
    out_path = filepath + ".decrypted"
    with open(out_path, "wb") as f:
        f.write(plaintext)
    print(f"\nRaw decrypted: {out_path}")

    # 导出 JSON (结构化)
    kv_json = {}
    for key_bytes, val in pairs:
        try:
            ks = key_bytes.decode("utf-8")
        except UnicodeDecodeError:
            ks = key_bytes.hex()
        raw = strip_inner_varint(val)

        # 启发式结构化解析
        parsed = heuristic_parse(raw)
        if parsed is not None:
            def entry_to_json(entry):
                if len(entry) == 1:
                    return entry[0][1]
                obj = {}
                str_idx = 0
                for ftype, fval in entry:
                    if ftype == "str":
                        obj[f"s{str_idx}"] = fval
                        str_idx += 1
                    elif ftype == "u32":
                        obj[f"i{str_idx}"] = fval if fval != 0xFFFFFFFF else -1
                        str_idx += 1
                    elif ftype == "list":
                        obj[f"l{str_idx}"] = fval
                        str_idx += 1
                return obj
            kv_json[ks] = [entry_to_json(e) for e in parsed]
            continue

        # 尝试 UTF-8 字符串
        try:
            kv_json[ks] = raw.decode("utf-8")
            continue
        except UnicodeDecodeError:
            pass
        kv_json[ks] = raw.hex()

    json_path = filepath + ".json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(kv_json, f, ensure_ascii=False, indent=2)
    print(f"JSON export:   {json_path}")


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        print("Usage: decrypt_bistore.py <file> [crypto_key] [--iv HEX]")
        sys.exit(1)

    filepath = args[0]
    crypto_key = None
    iv_hex = None

    i = 1
    while i < len(args):
        if args[i] == "--iv" and i + 1 < len(args):
            iv_hex = args[i + 1]
            i += 2
        elif not crypto_key:
            crypto_key = args[i]
            i += 1
        else:
            i += 1

    decrypt_bistore(filepath, crypto_key, iv_hex)
#python3 decrypt_bistore.py /Users/jackjun/MyFile/hooker/com.xingin.xhs/a6de269810198701a152619ebd19abc1 12354