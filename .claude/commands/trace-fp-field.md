# 追踪指纹字段来源

追踪小红书 libtiny.so 中指定指纹字段的数据来源，输出完整数据流链。

## 输入

用户提供字段名（如 `x146`、`x97`），可选提供：
- 该字段在 JSON 输出中的序号（来自 hookJsonPut）
- 已知的真机值
- unidbg 中的表现（缺失/错误值）

## 工作流程

### Phase 1: 确认字段状态

1. 在 unidbg trace 输出中搜索该字段的 map_insert（grep `trace_ts_set_*.txt` 中的 key 字符串）
2. 在 hookJsonPut 输出中搜索 `[JsonValue #N] value="字段名"` 确认 JSON 序号
3. 判断字段状态：
   - **存在但值错** → Phase 2A（unidbg trace 追踪）
   - **完全缺失** → Phase 2B（Frida 真机追踪，可能是 .bistore 存储）

### Phase 2A: unidbg trace 追踪（字段存在但值错）

1. 在 trace 文件中定位 map_insert 调用（搜索 `sub_28C7E8` 或 `sub_28C890`）
2. 从 insert 点向前回溯，找 value 写入 VM 寄存器的位置
3. 继续回溯找到 ultimate source（JNI/syscall/VM常量/.bss/ioctl）
4. 参考来源分类体系修复 Xhs921.java 中的 JNI mock

### Phase 2B: Frida 真机追踪（字段缺失）

#### Step 1: 确认真机上字段存在
```bash
# conda active py3.8
# 使用现有脚本 hook_x146_build.js 的模板，修改目标 key
frida -U -f com.xingin.xhs -l hook脚本.js --no-pause
```

Hook `sub_28C7E8`(map_insert, 0x28C7E8)，确认该 key 在真机上被插入，记录：
- Insert 序号（#N）
- X19 值（VM state 地址）
- 调用栈（Backtracer.ACCURATE）

#### Step 2: 定位全局存储
1. 从 insert handler 反编译（IDA `decompile`），找到 value 来自哪个 VM 寄存器偏移 `[X19+offset]`
2. 用 IDA `find_bytes` 搜索 `STR X?, [X19, #offset]` 的 ARM64 编码，找到所有写入者
3. 反编译写入者，判断数据来源：
   - 来自另一个 VM 寄存器 → 继续追踪
   - 来自全局变量（.bss/.data）→ Step 3
   - 来自函数调用返回值 → 反编译该函数

#### Step 3: 追踪全局变量写入
1. 用 IDA `xrefs_to` 找全局变量的所有引用
2. 区分读 vs 写：
   - `sub_141600(dst, &global)` — global 作为第二参数 = **读取**
   - `sub_1418F0(&global, data, len)` — global 作为第一参数 = **写入**
3. Frida hook 写入函数，当 dst == global 地址时 dump 数据和 backtrace

#### Step 4: 确认是否 .bistore 存储
如果全局变量的写入链经过反序列化函数（sub_2B47D4 → sub_2B4DB0 → sub_2B0898），则值存储在 .bistore 加密文件中：
1. 运行 `hook_x146_dump_all_blobs.js` dump 所有 blob 解密内容
2. 找到目标字段在哪个 blob index 中
3. 记录 blob 格式和内容

#### Step 5: 修复 unidbg
- **.bistore 字段**: 需要从真机 dump .bistore 文件并注册到 unidbg 虚拟文件系统，或 hook blob_load 返回点注入解密数据
- **JNI 字段**: 修改 Xhs921.java 中对应的 JNI mock 返回值
- **syscall 字段**: 修改 unidbg 的 syscall handler
- **VM 常量**: 无需修复（值由 libtiny.so 自身决定）

### Phase 3: 文档化

1. 将追踪结果写入 `fp.md`（字段来源记录）
2. 更新 `mini_mua.js`（字段注释）
3. 如有新的方法论发现，保存到 memory

## 关键地址速查

| 地址 | 函数 | 用途 |
|------|------|------|
| 0x28C7E8 | map_insert | SSO key → RB-tree 插入 |
| 0x1702D4 | tree_traverse | 遍历/序列化 |
| 0x141600 | str_copy | SSO string 复制 |
| 0x1418F0 | string_assign | std::string::assign |
| 0x1411C0 | malloc | 内存分配 |
| 0x2F4DB0 | blob_load | .bistore 解密加载 |
| 0x2B47D4 | deserialize_map | 反序列化 blob → map |
| 0x7B0760 | qword_7B0760 | x146 全局 SSO |
| 0x7B33A8 | stru_7B33A8 | x146 互斥锁 |
| 0x172278 | byte_reader | JSON value 逐字节写入 |
| 0x170b70 | dispatcher | JSON 元素分发 |
| 0x175118 | native_entry | 所有 JNI 调用入口 |

## ARM64 STR 指令编码

计算 `STR Xt, [X19, #offset]` 的字节模式：
```
imm12 = offset / 8
byte0 = 0x60 | Rt  (Rt = 0-30)
byte1 = (imm12 & 0x3F) << 2 | (19 >> 3)  
byte2 = (imm12 >> 6) | ((19 & 0x7) << 5)
byte3 = 0xF9
→ find_bytes 搜索: "?? byte1 byte2 F9"
```

常用偏移编码：
- `[X19, #0x1D20]` → `?? 92 0E F9`
- `[X19, #0x0050]` → `?? 72 00 F9`
- `[X19, #0x02C8]` → `?? 72 05 F9`

## Frida 脚本模板

所有脚本在 `unidbg-android/src/test/java/com/xhs/` 目录：
- `hook_x146_build.js` — 窗口内 native 调用追踪（模板）
- `hook_x146_global_write.js` — 全局 SSO 写入捕获
- `hook_x146_hash_trace.js` — 28/56 字节数据首次出现
- `hook_x146_blob_source.js` — blob 文件来源
- `hook_x146_dump_all_blobs.js` — dump 所有 blob 解密内容
- `hook_x146_bistore_write.js` — 追踪 blob 首次写入
