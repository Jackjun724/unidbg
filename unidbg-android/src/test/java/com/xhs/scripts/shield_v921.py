"""
小红书 Shield v9.21 签名算法 (简洁版)

流程:
  device_id + hmac_b64 → AES-CBC解密 → 64字节HMAC密钥
  HMAC密钥 + url_params → HMAC-MD5 → 16字节hash
  build_id + device_id + hash → 数据块组装(83字节)
  数据块 → RC4加密(seed="std::abort();")
  Header(16字节) + 密文 → "XY" + base64

v9.21 变化 (相比旧版):
  - 数据块控制字段: 1字节 → 4字节大端 int32 (67B → 83B)
  - Shield Header[0:4]: 00 00 00 01 → 00 04 00 04
"""

import base64
import struct

# ==================== 工具函数 ====================

def _u32(v):
    return v & 0xFFFFFFFF

def _rol32(v, n):
    v &= 0xFFFFFFFF
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

def _ror32(v, n):
    return _rol32(v, 32 - n)


# ==================== AES 常量 ====================

# 加密 T-table (Te0), 用于密钥扩展
_TE0 = [
    0xC66363A5, 0xF87C7C84, 0xEE777799, 0xF67B7B8D, 0xFFF2F20D, 0xD66B6BBD, 0xDE6F6FB1, 0x91C5C554,
    0x60303050, 0x02010103, 0xCE6767A9, 0x562B2B7D, 0xE7FEFE19, 0xB5D7D762, 0x4DABABE6, 0xEC76769A,
    0x8FCACA45, 0x1F82829D, 0x89C9C940, 0xFA7D7D87, 0xEFFAFA15, 0xB25959EB, 0x8E4747C9, 0xFBF0F00B,
    0x41ADADEC, 0xB3D4D467, 0x5FA2A2FD, 0x45AFAFEA, 0x239C9CBF, 0x53A4A4F7, 0xE4727296, 0x9BC0C05B,
    0x75B7B7C2, 0xE1FDFD1C, 0x3D9393AE, 0x4C26266A, 0x6C36365A, 0x7E3F3F41, 0xF5F7F702, 0x83CCCC4F,
    0x6834345C, 0x51A5A5F4, 0xD1E5E534, 0xF9F1F108, 0xE2717193, 0xABD8D873, 0x62313153, 0x2A15153F,
    0x0804040C, 0x95C7C752, 0x46232365, 0x9DC3C35E, 0x30181828, 0x379696A1, 0x0A05050F, 0x2F9A9AB5,
    0x0E070709, 0x24121236, 0x1B80809B, 0xDFE2E23D, 0xCDEBEB26, 0x4E272769, 0x7FB2B2CD, 0xEA75759F,
    0x1209091B, 0x1D83839E, 0x582C2C74, 0x341A1A2E, 0x361B1B2D, 0xDC6E6EB2, 0xB45A5AEE, 0x5BA0A0FB,
    0xA45252F6, 0x763B3B4D, 0xB7D6D661, 0x7DB3B3CE, 0x5229297B, 0xDDE3E33E, 0x5E2F2F71, 0x13848497,
    0xA65353F5, 0xB9D1D168, 0x00000000, 0xC1EDED2C, 0x40202060, 0xE3FCFC1F, 0x79B1B1C8, 0xB65B5BED,
    0xD46A6ABE, 0x8DCBCB46, 0x67BEBED9, 0x7239394B, 0x944A4ADE, 0x984C4CD4, 0xB05858E8, 0x85CFCF4A,
    0xBBD0D06B, 0xC5EFEF2A, 0x4FAAAAE5, 0xEDFBFB16, 0x864343C5, 0x9A4D4DD7, 0x66333355, 0x11858594,
    0x8A4545CF, 0xE9F9F910, 0x04020206, 0xFE7F7F81, 0xA05050F0, 0x783C3C44, 0x259F9FBA, 0x4BA8A8E3,
    0xA25151F3, 0x5DA3A3FE, 0x804040C0, 0x058F8F8A, 0x3F9292AD, 0x219D9DBC, 0x70383848, 0xF1F5F504,
    0x63BCBCDF, 0x77B6B6C1, 0xAFDADA75, 0x42212163, 0x20101030, 0xE5FFFF1A, 0xFDF3F30E, 0xBFD2D26D,
    0x81CDCD4C, 0x180C0C14, 0x26131335, 0xC3ECEC2F, 0xBE5F5FE1, 0x359797A2, 0x884444CC, 0x2E171739,
    0x93C4C457, 0x55A7A7F2, 0xFC7E7E82, 0x7A3D3D47, 0xC86464AC, 0xBA5D5DE7, 0x3219192B, 0xE6737395,
    0xC06060A0, 0x19818198, 0x9E4F4FD1, 0xA3DCDC7F, 0x44222266, 0x542A2A7E, 0x3B9090AB, 0x0B888883,
    0x8C4646CA, 0xC7EEEE29, 0x6BB8B8D3, 0x2814143C, 0xA7DEDE79, 0xBC5E5EE2, 0x160B0B1D, 0xADDBDB76,
    0xDBE0E03B, 0x64323256, 0x743A3A4E, 0x140A0A1E, 0x924949DB, 0x0C06060A, 0x4824246C, 0xB85C5CE4,
    0x9FC2C25D, 0xBDD3D36E, 0x43ACACEF, 0xC46262A6, 0x399191A8, 0x319595A4, 0xD3E4E437, 0xF279798B,
    0xD5E7E732, 0x8BC8C843, 0x6E373759, 0xDA6D6DB7, 0x018D8D8C, 0xB1D5D564, 0x9C4E4ED2, 0x49A9A9E0,
    0xD86C6CB4, 0xAC5656FA, 0xF3F4F407, 0xCFEAEA25, 0xCA6565AF, 0xF47A7A8E, 0x47AEAEE9, 0x10080818,
    0x6FBABAD5, 0xF0787888, 0x4A25256F, 0x5C2E2E72, 0x381C1C24, 0x57A6A6F1, 0x73B4B4C7, 0x97C6C651,
    0xCBE8E823, 0xA1DDDD7C, 0xE874749C, 0x3E1F1F21, 0x964B4BDD, 0x61BDBDDC, 0x0D8B8B86, 0x0F8A8A85,
    0xE0707090, 0x7C3E3E42, 0x71B5B5C4, 0xCC6666AA, 0x904848D8, 0x06030305, 0xF7F6F601, 0x1C0E0E12,
    0xC26161A3, 0x6A35355F, 0xAE5757F9, 0x69B9B9D0, 0x17868691, 0x99C1C158, 0x3A1D1D27, 0x279E9EB9,
    0xD9E1E138, 0xEBF8F813, 0x2B9898B3, 0x22111133, 0xD26969BB, 0xA9D9D970, 0x078E8E89, 0x339494A7,
    0x2D9B9BB6, 0x3C1E1E22, 0x15878792, 0xC9E9E920, 0x87CECE49, 0xAA5555FF, 0x50282878, 0xA5DFDF7A,
    0x038C8C8F, 0x59A1A1F8, 0x09898980, 0x1A0D0D17, 0x65BFBFDA, 0xD7E6E631, 0x844242C6, 0xD06868B8,
    0x824141C3, 0x299999B0, 0x5A2D2D77, 0x1E0F0F11, 0x7BB0B0CB, 0xA85454FC, 0x6DBBBBD6, 0x2C16163A,
]

# 解密 T-table (Td0), 其余通过旋转派生
_TD0 = [
    0x51F4A750, 0x7E416553, 0x1A17A4C3, 0x3A275E96, 0x3BAB6BCB, 0x1F9D45F1, 0xACFA58AB, 0x4BE30393,
    0x2030FA55, 0xAD766DF6, 0x88CC7691, 0xF5024C25, 0x4FE5D7FC, 0xC52ACBD7, 0x26354480, 0xB562A38F,
    0xDEB15A49, 0x25BA1B67, 0x45EA0E98, 0x5DFEC0E1, 0xC32F7502, 0x814CF012, 0x8D4697A3, 0x6BD3F9C6,
    0x038F5FE7, 0x15929C95, 0xBF6D7AEB, 0x955259DA, 0xD4BE832D, 0x587421D3, 0x49E06929, 0x8EC9C844,
    0x75C2896A, 0xF48E7978, 0x99583E6B, 0x27B971DD, 0xBEE14FB6, 0xF088AD17, 0xC920AC66, 0x7DCE3AB4,
    0x63DF4A18, 0xE51A3182, 0x97513360, 0x62537F45, 0xB16477E0, 0xBB6BAE84, 0xFE81A01C, 0xF9082B94,
    0x70486858, 0x8F45FD19, 0x94DE6C87, 0x527BF8B7, 0xAB73D323, 0x724B02E2, 0xE31F8F57, 0x6655AB2A,
    0xB2EB2807, 0x2FB5C203, 0x86C57B9A, 0xD33708A5, 0x302887F2, 0x23BFA5B2, 0x02036ABA, 0xED16825C,
    0x8ACF1C2B, 0xA779B492, 0xF307F2F0, 0x4E69E2A1, 0x65DAF4CD, 0x0605BED5, 0xD134621F, 0xC4A6FE8A,
    0x342E539D, 0xA2F355A0, 0x058AE132, 0xA4F6EB75, 0x0B83EC39, 0x4060EFAA, 0x5E719F06, 0xBD6E1051,
    0x3E218AF9, 0x96DD063D, 0xDD3E05AE, 0x4DE6BD46, 0x91548DB5, 0x71C45D05, 0x0406D46F, 0x605015FF,
    0x1998FB24, 0xD6BDE997, 0x894043CC, 0x67D99E77, 0xB0E842BD, 0x07898B88, 0xE7195B38, 0x79C8EEDB,
    0xA17C0A47, 0x7C420FE9, 0xF8841EC9, 0x00000000, 0x09808683, 0x322BED48, 0x1E1170AC, 0x6C5A724E,
    0xFD0EFFFB, 0x0F853856, 0x3DAED51E, 0x362D3927, 0x0A0FD964, 0x685CA621, 0x9B5B54D1, 0x24362E3A,
    0x0C0A67B1, 0x9357E70F, 0xB4EE96D2, 0x1B9B919E, 0x80C0C54F, 0x61DC20A2, 0x5A774B69, 0x1C121A16,
    0xE293BA0A, 0xC0A02AE5, 0x3C22E043, 0x121B171D, 0x0E090D0B, 0xF28BC7AD, 0x2DB6A8B9, 0x141EA9C8,
    0x57F11985, 0xAF75074C, 0xEE99DDBB, 0xA37F60FD, 0xF701269F, 0x5C72F5BC, 0x44663BC5, 0x5BFB7E34,
    0x8B432976, 0xCB23C6DC, 0xB6EDFC68, 0xB8E4F163, 0xD731DCCA, 0x42638510, 0x13972240, 0x84C61120,
    0x854A247D, 0xD2BB3DF8, 0xAEF93211, 0xC729A16D, 0x1D9E2F4B, 0xDCB230F3, 0x0D8652EC, 0x77C1E3D0,
    0x2BB3166C, 0xA970B999, 0x119448FA, 0x47E96422, 0xA8FC8CC4, 0xA0F03F1A, 0x567D2CD8, 0x223390EF,
    0x87494EC7, 0xD938D1C1, 0x8CCAA2FE, 0x98D40B36, 0xA6F581CF, 0xA57ADE28, 0xDAB78E26, 0x3FADBFA4,
    0x2C3A9DE4, 0x5078920D, 0x6A5FCC9B, 0x547E4662, 0xF68D13C2, 0x90D8B8E8, 0x2E39F75E, 0x82C3AFF5,
    0x9F5D80BE, 0x69D0937C, 0x6FD52DA9, 0xCF2512B3, 0xC8AC993B, 0x10187DA7, 0xE89C636E, 0xDB3BBB7B,
    0xCD267809, 0x6E5918F4, 0xEC9AB701, 0x834F9AA8, 0xE6956E65, 0xAAFFE67E, 0x21BCCF08, 0xEF15E8E6,
    0xBAE79BD9, 0x4A6F36CE, 0xEA9F09D4, 0x29B07CD6, 0x31A4B2AF, 0x2A3F2331, 0xC6A59430, 0x35A266C0,
    0x744EBC37, 0xFC82CAA6, 0xE090D0B0, 0x33A7D815, 0xF104984A, 0x41ECDAF7, 0x7FCD500E, 0x1791F62F,
    0x764DD68D, 0x43EFB04D, 0xCCAA4D54, 0xE49604DF, 0x9ED1B5E3, 0x4C6A881B, 0xC12C1FB8, 0x4665517F,
    0x9D5EEA04, 0x018C355D, 0xFA877473, 0xFB0B412E, 0xB3671D5A, 0x92DBD252, 0xE9105633, 0x6DD64713,
    0x9AD7618C, 0x37A10C7A, 0x59F8148E, 0xEB133C89, 0xCEA927EE, 0xB761C935, 0xE11CE5ED, 0x7A47B13C,
    0x9CD2DF59, 0x55F2733F, 0x1814CE79, 0x73C737BF, 0x53F7CDEA, 0x5FFDAA5B, 0xDF3D6F14, 0x7844DB86,
    0xCAAFF381, 0xB968C43E, 0x3824342C, 0xC2A3405F, 0x161DC372, 0xBCE2250C, 0x283C498B, 0xFF0D9541,
    0x39A80171, 0x080CB3DE, 0xD8B4E49C, 0x6456C190, 0x7BCB8461, 0xD532B670, 0x486C5C74, 0xD0B85742,
]

# 派生解密 T-tables (通过旋转 Td0)
_TD1 = [_rol32(x, 8) for x in _TD0]   # TBox_8
_TD2 = [_rol32(x, 16) for x in _TD0]  # TBox_7
_TD3 = [_rol32(x, 24) for x in _TD0]  # TBox_6

# S-Box (从 Te0 提取) 和 逆S-Box
_SBOX = [(_TE0[i] >> 16) & 0xFF for i in range(256)]
_INV_SBOX = [0] * 256
for _i in range(256):
    _INV_SBOX[_SBOX[_i]] = _i

# 密钥扩展 XOR 常量
_AES_XOR = [0xF1892131, 0xFF001123, 0xF1001356, 0xF1234890]

# 轮常量 (非标准)
_AES_RCON = [
    0x12310000, 0x02000100, 0x04020000, 0x08020200, 0x10102000,
    0x30020400, 0x40002000, 0x80002000, 0x1B002000, 0x36200200,
]

# CBC 解密初始 IV
_CBC_IV = bytes([0x31, 0x01, 0x32, 0x34, 0x04, 0x02, 0x08, 0x61,
                 0x66, 0x7A, 0x66, 0x66, 0x07, 0x17, 0x66, 0x39])


# ==================== MD5 常量 ====================

_MD5_K = [
    0xE9C9B756, 0xD71BA479, 0x241081DB, 0x681088D9, 0x9B14F7AF, 0xFF1F5BB1, 0x881CD7BE, 0x66666122,
    0xF6666193, 0xA619639E, 0x49140921, 0xC11DCEEE, 0xF51C0FAF, 0x4717C62A, 0xA9104613, 0xFD169501,
    0xF6002500, 0x02741453, 0xD221E691, 0xE20011C9, 0x2261CDE6, 0xF2D50D97, 0x425A14ED, 0xA277E905,
    0xF277A3F9, 0x626F12D9, 0x922A4C9A, 0xC040B340, 0x265E5A51, 0xE9100000, 0xD63F105D, 0xC35707D6,
    0xFFFC3942, 0x977CD691, 0xA4BCEA44, 0x4BDCCFA9, 0xBEBCBC70, 0x288C7EC6, 0xF6CC4B60, 0xD4EC1095,
    0xEAAC27FA, 0xE6DC88E5, 0xD9DCD039, 0x048C1D05, 0x1FA27CF9, 0x6D9D6122, 0xC4AC5665, 0xFDE5391C,
    0xF4292244, 0xAB9423A7, 0xF593A039, 0x655B59C3, 0x452AFF97, 0xF5EF247D, 0x85845DD1, 0x850CCC92,
    0xF99926E0, 0xF9997E4F, 0xA9994314, 0xC5537E82, 0x450811A1, 0x450811A6, 0xBD3AF235, 0xEB86D391,
]

# 初始状态 (注意: 顺序与标准 MD5 相反)
_MD5_IV = [0x10325476, 0x98BADCFE, 0xEFCDAB89, 0x67452301]

_M32 = 0xFFFFFFFF


# ==================== AES-ECB 解密 ====================

def _aes_sub_rot_word(w):
    """SubWord(RotWord(w)) — 密钥扩展子操作"""
    b = [(w >> s) & 0xFF for s in (0, 8, 16, 24)]
    return (_SBOX[b[2]] << 24) | (_SBOX[b[1]] << 16) | (_SBOX[b[0]] << 8) | _SBOX[b[3]]


def _aes_key_expand(device_id: str) -> list:
    """AES-128 密钥扩展 (使用 device_id XOR 固定常量)"""
    key_hex = device_id.encode().hex()
    ctx = [0] * 64
    ctx[60] = 10  # AES-128: 10 轮

    # 初始密钥 = device_id 前16字节的hex值 XOR 固定常量
    for i in range(4):
        ctx[i] = int(key_hex[i * 8:(i + 1) * 8], 16) ^ _AES_XOR[i]

    # 密钥扩展
    for r in range(10):
        base = r * 4
        ctx[base + 4] = ctx[base] ^ _aes_sub_rot_word(ctx[base + 3]) ^ _AES_RCON[r]
        ctx[base + 5] = ctx[base + 1] ^ ctx[base + 4]
        ctx[base + 6] = ctx[base + 2] ^ ctx[base + 5]
        ctx[base + 7] = ctx[base + 3] ^ ctx[base + 6]

    return ctx


def _aes_inv_key_schedule(ctx: list):
    """反转密钥顺序 + InvMixColumns (用于解密)"""
    nr = ctx[60]  # 10

    # 交换首尾轮密钥
    for i in range(nr * 2):  # 0..19
        lo, hi = i, (nr - i // 4) * 4 + (i % 4)
        if lo >= hi:
            break
        ctx[lo], ctx[hi] = ctx[hi], ctx[lo]

    # 对中间轮密钥做 InvMixColumns
    for r in range(1, nr):
        base = r * 4
        for j in range(4):
            w = ctx[base + j]
            b = [(w >> s) & 0xFF for s in (0, 8, 16, 24)]
            s = [_SBOX[x] for x in b]
            ctx[base + j] = _TD1[s[0]] ^ _TD0[s[3]] ^ _TD3[s[2]] ^ _TD2[s[1]]


def _aes_decrypt_block(ctx: list, block: bytes) -> bytes:
    """AES-ECB 解密单个 16 字节块"""
    # 输入: 4个大端 uint32
    s = [struct.unpack('>I', block[i * 4:(i + 1) * 4])[0] ^ ctx[i] for i in range(4)]

    # 9 轮标准解密 (InvShiftRows + InvSubBytes + InvMixColumns + AddRoundKey)
    for r in range(1, 10):
        rk = r * 4
        t = [0] * 4
        for i in range(4):
            t[i] = (_TD0[(s[i] >> 24) & 0xFF] ^
                    _TD3[(s[(i + 3) % 4] >> 16) & 0xFF] ^
                    _TD2[(s[(i + 2) % 4] >> 8) & 0xFF] ^
                    _TD1[s[(i + 1) % 4] & 0xFF] ^
                    ctx[rk + i])
        s = t

    # 最后一轮 (InvShiftRows + InvSubBytes + AddRoundKey, 无 MixColumns)
    out = bytearray(16)
    for i in range(4):
        w = ((_INV_SBOX[(s[i] >> 24) & 0xFF] << 24) |
             (_INV_SBOX[(s[(i + 3) % 4] >> 16) & 0xFF] << 16) |
             (_INV_SBOX[(s[(i + 2) % 4] >> 8) & 0xFF] << 8) |
             _INV_SBOX[s[(i + 1) % 4] & 0xFF])
        w ^= ctx[40 + i]
        struct.pack_into('>I', out, i * 4, w)

    return bytes(out)


def aes_decrypt_hmac_key(device_id: str, hmac_b64: str) -> bytes:
    """
    AES-CBC 解密 HMAC 密钥

    输入: device_id (用于生成 AES 密钥), hmac_b64 (base64 编码的加密密钥)
    输出: 64 字节的 HMAC 密钥
    """
    ctx = _aes_key_expand(device_id)
    _aes_inv_key_schedule(ctx)

    ciphertext = base64.b64decode(hmac_b64)
    iv = bytearray(_CBC_IV)
    plaintext = bytearray()

    for i in range(len(ciphertext) // 16):
        block = ciphertext[i * 16:(i + 1) * 16]
        decrypted = _aes_decrypt_block(ctx, block)
        plaintext.extend(d ^ v for d, v in zip(decrypted, iv))
        iv = bytearray(block)

    # 跳过首尾各 16 字节, 返回中间 64 字节
    return bytes(plaintext[16:-16])


# ==================== 自定义 MD5 ====================
#
# 注意: 此 MD5 与标准 MD5 存在以下差异 (属于 native 库的混淆):
#   1. 轮移位量不同 (Round 1 第一组为 [26,19,15,11] 而非标准 [25,20,15,10])
#   2. K 常量全部替换为自定义值 (从 Frida Stalker trace 反推)

def _md5_compress(state: list, block: bytes):
    """处理单个 64 字节块, 就地更新 state[0:4]"""
    # 解析 16 个小端 uint32 消息字
    w = [struct.unpack_from('<I', block, i * 4)[0] for i in range(16)]
    K = _MD5_K

    a, b, c, d = state[0], state[1], state[2], state[3]

    # 辅助函数
    def F(x, y, z): return ((y ^ z) & x) ^ z
    def G(x, y, z): return ((x ^ y) & z) ^ y
    def H(x, y, z): return x ^ y ^ z
    def I(x, y, z): return (x | (z ^ _M32)) ^ y
    def S(target, addend, fn, k, m, s):
        return _u32(_ror32(_u32(target + fn + k + m), s) + addend)

    # ---- Round 1: F 函数 ----
    a = S(a, b, F(b, c, d), K[0],  w[0],  26)
    d = S(d, a, F(a, b, c), K[1],  w[1],  19)
    c = S(c, d, F(d, a, b), K[2],  w[2],  15)
    b = S(b, c, F(c, d, a), K[3],  w[3],  11)

    a = S(a, b, F(b, c, d), K[4],  w[4],  25)
    d = S(d, a, F(a, b, c), K[5],  w[5],  20)
    c = S(c, d, F(d, a, b), K[6],  w[6],  15)
    b = S(b, c, F(c, d, a), K[7],  w[7],  12)

    a = S(a, b, F(b, c, d), K[8],  w[8],  25)
    d = S(d, a, F(a, b, c), K[9],  w[9],  20)
    c = S(c, d, F(d, a, b), K[10], w[10], 16)
    b = S(b, c, F(c, d, a), K[11], w[11], 10)

    a = S(a, b, F(b, c, d), K[12], w[12], 25)
    d = S(d, a, F(a, b, c), K[13], w[13], 19)
    c = S(c, d, F(d, a, b), K[14], w[14], 15)
    b = S(b, c, F(c, d, a), K[15], w[15], 10)

    # ---- Round 2: G 函数 ----
    a = S(a, b, G(b, c, d), K[16], w[1],  27)
    d = S(d, a, G(a, b, c), K[17], w[6],  23)
    c = S(c, d, G(d, a, b), K[18], w[11], 18)
    b = S(b, c, G(c, d, a), K[19], w[0],  12)

    a = S(a, b, G(b, c, d), K[20], w[5],  27)
    d = S(d, a, G(a, b, c), K[21], w[10], 23)
    c = S(c, d, G(d, a, b), K[22], w[15], 18)
    b = S(b, c, G(c, d, a), K[23], w[4],  12)

    a = S(a, b, G(b, c, d), K[24], w[9],  27)
    d = S(d, a, G(a, b, c), K[25], w[14], 23)
    c = S(c, d, G(d, a, b), K[26], w[3],  18)
    b = S(b, c, G(c, d, a), K[27], w[8],  12)

    a = S(a, b, G(b, c, d), K[28], w[13], 27)
    d = S(d, a, G(a, b, c), K[29], w[2],  23)
    c = S(c, d, G(d, a, b), K[30], w[7],  18)
    b = S(b, c, G(c, d, a), K[31], w[12], 12)

    # ---- Round 3: H 函数 (非标准执行顺序, 第3组a先于第2组b执行) ----
    # Group 1: 标准顺序 a,d,c,b
    a = S(a, b, H(b, c, d), K[32], w[5],  28)
    d = S(d, a, H(a, b, c), K[33], w[8],  21)
    c = S(c, d, H(d, a, b), K[34], w[11], 16)
    b = S(b, c, H(c, d, a), K[35], w[14], 9)

    # Group 2: a,d,c 先执行
    a = S(a, b, H(b, c, d), K[36], w[1],  28)
    d = S(d, a, H(a, b, c), K[37], w[4],  21)
    c = S(c, d, H(d, a, b), K[38], w[7],  16)
    # Group 3 的 a 插入执行 (在 Group 2 的 b 之前)
    a = S(a, b, H(b, c, d), K[39], w[13], 28)
    # Group 2 的 b 延后执行 (使用已更新的 a)
    b = S(b, c, H(c, d, a), K[40], w[10], 9)
    # Group 3 继续: c,d,b
    c = S(c, d, H(d, a, b), K[41], w[3],  16)
    d = S(d, a, H(a, b, c), K[42], w[0],  21)
    b = S(b, c, H(c, d, a), K[43], w[6],  9)

    # Group 4: 标准顺序 a,d,c,b
    a = S(a, b, H(b, c, d), K[44], w[9],  28)
    d = S(d, a, H(a, b, c), K[45], w[12], 21)
    c = S(c, d, H(d, a, b), K[46], w[15], 16)
    b = S(b, c, H(c, d, a), K[47], w[2],  9)

    # ---- Round 4: I 函数 ----
    a = S(a, b, I(b, c, d), K[48], w[0],  26)
    d = S(d, a, I(a, b, c), K[49], w[7],  22)
    c = S(c, d, I(d, a, b), K[50], w[14], 17)
    b = S(b, c, I(c, d, a), K[51], w[5],  11)

    a = S(a, b, I(b, c, d), K[52], w[12], 26)
    d = S(d, a, I(a, b, c), K[53], w[3],  22)
    c = S(c, d, I(d, a, b), K[54], w[10], 17)
    b = S(b, c, I(c, d, a), K[55], w[1],  11)

    a = S(a, b, I(b, c, d), K[56], w[8],  26)
    d = S(d, a, I(a, b, c), K[57], w[15], 22)
    c = S(c, d, I(d, a, b), K[58], w[6],  17)
    b = S(b, c, I(c, d, a), K[59], w[13], 11)

    a = S(a, b, I(b, c, d), K[60], w[4],  26)
    d = S(d, a, I(a, b, c), K[61], w[11], 22)
    c = S(c, d, I(d, a, b), K[62], w[2],  17)
    b = S(b, c, I(c, d, a), K[63], w[9],  11)

    # 累加到状态
    state[0] = _u32(state[0] + a)
    state[1] = _u32(state[1] + b)
    state[2] = _u32(state[2] + c)
    state[3] = _u32(state[3] + d)


def md5(data: bytes) -> bytes:
    """
    自定义 MD5 哈希 (非标准移位量和自定义 K 常量)
    输入: 任意长度字节
    输出: 16 字节哈希
    """
    state = list(_MD5_IV)

    # 处理完整的 64 字节块
    offset = 0
    while offset + 64 <= len(data):
        _md5_compress(state, data[offset:offset + 64])
        offset += 64

    # 填充 (标准 MD5 padding)
    remainder = bytearray(data[offset:])
    bit_count = len(data) * 8
    remainder.append(0x80)
    while len(remainder) % 64 != 56:
        remainder.append(0x00)
    remainder += struct.pack('<Q', bit_count & 0xFFFFFFFFFFFFFFFF)

    # 处理填充后的块
    for i in range(0, len(remainder), 64):
        _md5_compress(state, bytes(remainder[i:i + 64]))

    # 输出: 小端序
    return b''.join(struct.pack('<I', h) for h in state)


# ==================== HMAC-MD5 ====================

def hmac_md5(key_64: bytes, message: bytes) -> bytes:
    """
    HMAC-MD5: H(opad || H(ipad || message))

    输入: 64 字节密钥, 任意长度消息
    输出: 16 字节 HMAC
    """
    ipad = bytes(k ^ 0x36 for k in key_64)
    opad = bytes(k ^ 0x5C for k in key_64)
    inner = md5(ipad + message)
    return md5(opad + inner)


# ==================== RC4 流密码 ====================

_RC4_SEED = b"std::abort();"  # 13 字节


def rc4(data: bytes, seed: bytes = _RC4_SEED) -> bytes:
    """
    RC4 加密/解密

    使用 256 项 int 表 (与标准 RC4 等价), 种子 = "std::abort();" (13字节)
    KSA 和 PRGA 均为标准 RC4 算法, 仅种子特殊
    """
    seed_len = len(seed)

    # KSA: 密钥调度
    S = list(range(256))
    j = 0
    ki = 0
    for i in range(256):
        j = (j + S[i] + seed[ki]) & 0xFF
        S[i], S[j] = S[j], S[i]
        ki += 1
        if ki == seed_len:
            ki = 0

    # PRGA: 伪随机生成 + XOR 加密
    i = j = 0
    out = bytearray(len(data))
    for idx in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out[idx] = data[idx] ^ S[(S[i] + S[j]) & 0xFF]

    return bytes(out)


# ==================== 数据块组装 (v9.21) ====================

def build_data_block(build_id: str, device_id: str, hmac_hash: bytes) -> bytes:
    """
    组装 Shield 数据块 (v9.21)

    格式: 6个大端 int32 头部 (24B) + build_id + device_id + HMAC hash
    总长: 24 + len(build_id) + len(device_id) + 16 = 83B (典型值)

    v9.21 变化: 控制字段从 1 字节扩展为 4 字节大端 int32
    """
    header = struct.pack('>6I',
                         1,                   # version
                         0xECFAAF01,           # sAppId (固定)
                         2,                    # hmac_flag (2=有HMAC)
                         len(build_id),        # build_id 长度
                         len(device_id),       # device_id 长度
                         16)                   # md5 结果长度 (固定16)

    return header + build_id.encode() + device_id.encode() + hmac_hash


# ==================== Shield 主流程 ====================

def get_shield(url_params: str, device_id: str, build_id: str, hmac_b64: str) -> str:
    """
    生成 Shield v9.21 签名

    参数:
      url_params: 签名输入字符串 (uri + params + common_params + ...)
      device_id:  设备ID (如 "c9cdb5b0-a9e9-361b-baa3-daf23ea927d7")
      build_id:   APP版本号 (如 "9210803")
      hmac_b64:   Base64 编码的加密 HMAC 密钥

    返回:
      "XY" + Base64 编码的 (16字节Header + RC4密文)
    """
    print(f"\n{'='*60}")
    print(f"[get_shield] 开始生成 Shield v9.21 签名")
    print(f"{'='*60}")
    print(f"[输入] url_params长度: {len(url_params)}")
    print(f"[输入] device_id: {device_id}")
    print(f"[输入] build_id: {build_id}")
    print(f"[输入] hmac_b64: {hmac_b64[:40]}...")

    # 1. AES 解密 HMAC 密钥 (64字节)
    print(f"\n[步骤1] AES-CBC 解密 HMAC 密钥...")
    hmac_key = aes_decrypt_hmac_key(device_id, hmac_b64)
    print(f"[步骤1] HMAC 密钥 ({len(hmac_key)}字节): {hmac_key.hex()}")

    # 2. HMAC-MD5 签名
    print(f"\n[步骤2] HMAC-MD5 签名...")
    print(f"[步骤2] 签名输入 (前80字符): {url_params[:80]}...")
    hmac_hash = hmac_md5(hmac_key, url_params.encode())
    print(f"[步骤2] HMAC-MD5 结果 ({len(hmac_hash)}字节): {hmac_hash.hex()}")

    # 3. 组装数据块 (83字节)
    print(f"\n[步骤3] 组装数据块...")
    data_block = build_data_block(build_id, device_id, hmac_hash)
    print(f"[步骤3] 数据块 ({len(data_block)}字节): {data_block.hex()}")

    # 4. RC4 加密
    print(f"\n[步骤4] RC4 加密 (seed='std::abort();')...")
    encrypted = rc4(data_block)
    print(f"[步骤4] RC4 密文 ({len(encrypted)}字节): {encrypted.hex()}")

    # 5. 拼接 Header + Base64
    print(f"\n[步骤5] 拼接 Header + Base64 编码...")
    data_len = len(encrypted)
    header = struct.pack('>HH', 4, 4)       # v9.21: 00 04 00 04
    header += struct.pack('>I', 1)           # 固定值 1
    header += struct.pack('>I', data_len)    # 加密数据长度
    header += struct.pack('>I', data_len)    # 加密数据长度 (重复)
    print(f"[步骤5] Header (16字节): {header.hex()}")
    print(f"[步骤5] Header + 密文 ({len(header) + len(encrypted)}字节): {(header + encrypted).hex()}")

    result = 'XY' + base64.b64encode(header + encrypted).decode()
    print(f"\n[结果] Shield 签名: {result}")
    print(f"{'='*60}\n")

    return result


# ==================== 测试 ====================

if __name__ == '__main__':
    device_id = "c9cdb5b0-a9e9-361b-baa3-daf23ea927d7"
    build_id = "9210803"
    hmac_b64 = "XSeQjYAIFBUENihTfXDg0uKh3jf78KvsdtrZexs9jUcz5bcDBDIEG2I0nx0E+y3yHGuOrFx8WkNzfUy5WrtZahGKMDL3p6Plk4hhN0TGxU2HXGzJRuxGRKBBjliBdaqQ"

    sign_input = (
        '/api/sns/v1/followings/reddotisStartUp=falsefid=&gid=7cbab264fb2d549589ed3bb00dcd73c0b9aae20947359b9177d43ef6&device_model=phone&tz=America%2FNew_York&channel=JTdCJTdE&versionName=9.21.0&deviceId=c9cdb5b0-a9e9-361b-baa3-daf23ea927d7&platform=android&sid=session.1775219135513939616235&identifier_flag=4&cpu_abi=arm64-v8a&nqe_score=91&project_id=ECFAAF&x_trace_page_current=welcome_page&lang=zh-Hans&app_id=ECFAAF01&uis=light&teenager=0&active_ctry=CN&cpu_name=Qualcomm+Technologies%2C+Inc+SM8150&dlang=zh&data_ctry=CN&SUE=1&launch_id=1775250326&id_token=VjEAAO%2F3DhnXYfkcszLc5l3fQl%2B3%2Fz%2F5cddCCMIGmuzVIseipOQiGCoikxmrE7rS2c%2BbhrcMWTFDh6R3Lin9WPaw6SFNC98wXb%2F0CCgXfM1mC4ZOSEhnxs8ko6bygW%2FRJEZyzkKu&device_level=4&origin_channel=JTdCJTdE&overseas_channel=0&mlanguage=zh_cn&folder_type=none&auto_trans=0&t=1775286738&build=9210803&holder_ctry=CN&did=1dfba70e48e5ec95edfa093c4e16d8ce69platform=android&build=9210803&deviceId=c9cdb5b0-a9e9-361b-baa3-daf23ea927d7fs=0&point=3019'
    )

    result = get_shield(sign_input, device_id, build_id, hmac_b64)
    print(f"Shield: {result}")
