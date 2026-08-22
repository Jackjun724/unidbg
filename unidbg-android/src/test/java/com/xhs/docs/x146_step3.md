# x146 逆向分析 Step 3 — 完整数据流追踪

> 日期: 2026-04-06
> 状态: 完整数据流已确认，待追踪原始hash计算
> 前置: x146_investigation.md (Step 1), x146_step2.md (Step 2)

## 1. 核心发现

### 1.1 x146 value的完整数据流

```
[持久化存储]
  .bistore/a6de269810198701a152619ebd19abc1  (自定义KV文件)
      ↓ open + read
[反序列化]
  sub_2F4DB0 (blob_load, index=2)
      ↓ 返回78字节blob
  sub_2B47D4 (deserialization entry)
      ↓ 解析blob格式
  sub_2B4DB0 (read_string_from_stream)
      ↓ sub_2B0898 (stream_read → memcpy 56字节)
[写入全局]
  vm_dispatch_1A2128 (mutex_lock → string_assign → mutex_unlock)
      ↓ sub_1418F0(&qword_7B0760, data, 56)  // string_assign
[全局SSO字符串]
  qword_7B0760 = "7cba9aac1237549589ed32900dcd73c0b9aaeae947359bfc7757c2b5"
      ↓ (受stru_7B33A8互斥锁保护)
[读入VM寄存器]
  sub_1E0268: str_copy([X19+0x2C8], &qword_7B0760)
      ↓ (从全局复制到VM寄存器区域)
[VM寄存器传递]
  [X19+0x2C8] → [X19+0x1D20]  (通过VM handler链传递)
      ↓
[Map插入]
  vm_call_28C7E8_1DCF38: map_insert(map=[X19+0x50], key="x146")
      ↓ value从[X19+0x1D20] variant取出
[最终输出]
  map序列化 → JSON → HTTP请求header
```

### 1.2 Blob文件位置

```
/data/user/0/com.xingin.xhs/.bistore/a6de269810198701a152619ebd19abc1
/data/user/0/com.xingin.xhs/.bistore/a6de269810198701a152619ebd19abc1.crc
```

文件名 `a6de269810198701a152619ebd19abc1` 可能是存储key的MD5/hash。

### 1.3 Blob序列化格式

```
Blob (78 bytes):
  [00-03] 01 00 00 00         — entry count = 1 (LE uint32)
  [04-05] 0E 00               — key length = 14 (LE uint16)
  [06-19] "com.xingin.xhs"    — key (14 bytes)
  [20-21] 38 00               — value length = 56 (LE uint16)
  [22-77] "7cba9aac..."       — value (56 bytes hex string)

通用格式:
  [4字节 entry数量]
  [entries...]:
    [2字节 key长度][key bytes]
    [2字节 value长度][value bytes]
```

### 1.4 反序列化调用链 (Frida backtrace)

```
libtiny+0x1A2180  — vm_dispatch_1A2128 (string_assign with mutex)
libtiny+0x1BBBE0  — sub_1BBB94 (calls sub_1A2418)
libtiny+0x1BDF40  — sub_1BDF24 (calls sub_1BBB94)
libtiny+0x19C188  — sub_19C174 (entry: calls sub_1BC844)
```

## 2. 关键函数分析

### 2.1 sub_1418F0 — string_assign(dst, data, len)

```c
// std::string::assign 实现
// a1 = destination SSO string
// a2 = source data pointer
// a3 = length
// 处理SSO short/long mode切换和reallocation
```

写入qword_7B0760时的参数:
- dst = &qword_7B0760 (libtiny+0x7B0760)
- data = 0x754bd41940 (heap上的56字符hex string)
- len = 56

### 2.2 sub_2B0898 — stream_read(stream, dst, len, eof_flag)

```c
// 从流缓冲区读取数据
// stream+8 = data buffer base
// stream+16 = total length
// stream+24 = current position
// 返回: 实际读取字节数
// eof_flag: 设为0(未结束) 或 1(已结束)
```

### 2.3 sub_2B4DB0 — read_string_from_stream(stream_ctx)

```c
// 从stream读取length-prefixed string
// 1. 读2字节 → string length
// 2. malloc(length) → temp buffer
// 3. 读length字节 → temp buffer
// 4. 创建SSO string from temp buffer
// 5. free temp buffer
```

### 2.4 sub_2B47D4 — deserialize_map(blob_source, index, output_map, flag)

```c
// 完整的map反序列化
// 1. sub_2F4DB0(blob_source, index, &blob_data, flag) → 加载blob
// 2. 创建stream对象 (vtable=off_738148 → sub_2B0898)
// 3. 读4字节header → entry count
// 4. 循环count次:
//    a. sub_2B4C70 → 读key (length-prefixed string)
//    b. sub_2B4DB0 → 读value (length-prefixed string)
//    c. sub_2B4EF4 → 插入output_map
```

### 2.5 sub_2F4DB0 — blob_load(context, index, output, flag)

```
// 从.bistore文件加载原始blob数据
// context包含字符串列表 ("x8", "x9", "x11" 等字段名)
// index=2 对应x146的blob
// 返回SSO string, len=78 (完整的序列化blob)
```

### 2.6 vm_dispatch_1A2128 — write_global_x146(buf, data, len, flag)

```asm
; 锁定互斥锁 stru_7B33A8
; 调用 sub_1418F0(&qword_7B0760, data, len) 写入全局
; 解锁互斥锁
; 根据flag分支到不同的下一个handler
```

### 2.7 sub_1E0268 — copy_global_to_vm_reg

```c
// 在x131→x146窗口内执行
// 1. sub_1702D4(tree_traverse) — 遍历某个tree
// 2. pthread_mutex_lock(&stru_7B33A8)
// 3. sub_141600([X19+0x2C8], &qword_7B0760) — 复制全局值到VM寄存器
// 4. pthread_mutex_unlock(&stru_7B33A8)
// 5. 从复制的值提取标志和长度
```

## 3. 全局状态

### 3.1 qword_7B0760 — x146全局SSO字符串

```
地址: libtiny+0x7B0760 (.bss段)
类型: std::string (SSO, libc++)
互斥锁: stru_7B33A8

SSO long mode布局:
  +0x00: capacity | 1  (0x41 = 64+1, long mode flag)
  +0x08: length         (0x38 = 56)
  +0x10: data_ptr       (→ heap, 56字节hex字符串)

Xrefs:
  写入者: vm_dispatch_1A2128 (通过sub_1418F0 string_assign)
  读取者: sub_1E0268, sub_276148, vm_cmp_sel_1AB358, sub_29E624
  初始化: sub_1453D8 (清零)
```

### 3.2 .bistore 存储

```
路径: /data/user/0/com.xingin.xhs/.bistore/a6de269810198701a152619ebd19abc1
CRC:  .bistore/a6de269810198701a152619ebd19abc1.crc
格式: 自定义KV序列化 (见2.3节)
```

## 4. 关键线索: Blob中的其他数据

### 4.1 blob_load #1 (a2=0xa, caller=+1a1f30)

```
len=40, value="00000000808161cd54f2f58d651e89cdd838c88f"
```
这是uniform_id (设备ID), 40字符hex = 20字节hash

### 4.2 blob_load #2 (a2=0x2, caller=+2b4810) — x146

```
len=78, contains: key="com.xingin.xhs" + value="7cba9aac..." (56字符hex)
```

### 4.3 blob_load #3 (a2=0x3, caller=+2b0444)

```
len=1777, contains URL列表: www.xiaohongshu.com, /api/sns/v1/system_service/popup_window, ...
```
这是URL白名单/路由表

## 5. unidbg修复方案

### 方案A: 提供.bistore文件 (推荐)

从真机pull .bistore目录，放入unidbg虚拟文件系统:
```java
// Xhs921.java
vm.getFileSystem().addIOFile(
    "/data/user/0/com.xingin.xhs/.bistore/a6de269810198701a152619ebd19abc1",
    new SimpleFileIO(...)
);
```

**优点**: 最简单，不需要理解hash算法
**缺点**: 值固定，可能被服务端检测为重放

### 方案B: Hook全局写入

在unidbg中hook sub_1418F0，当目标是qword_7B0760时注入值:
```java
// 在libtiny.so加载后
emulator.getBackend().hook_add_new(new CodeHook() {
    @Override
    public void hook(Backend backend, long address, int size, Object user) {
        // 检查X0是否指向qword_7B0760
        // 如果是，修改X1指向我们的hex string, X2=56
    }
}, module.base + 0x1418F0, module.base + 0x1418F0 + 4, null);
```

### 方案C: 追踪hash计算 (完整方案)

需要找到.bistore文件的写入时机:
1. Hook文件写入 (write syscall) 针对.bistore文件
2. 找到触发写入的VM handler链
3. 反向追踪hash算法 (可能是VM内嵌的SHA-224)
4. 在unidbg中模拟完整的设备指纹收集和hash计算

## 6. Phase A2 Frida输出分析

### 6.1 x131→x146窗口内的操作序列

```
1. memcpy "x131" — x131 key复制
2. RB-tree rebalance + malloc(72) — tree node分配
3. tree_traverse(tree_root, type=0) — 遍历空tree
4. str_copy from variant@0x7538b38760 — ★ 复制x146 value
   - src variant: cap=0x41, len=0x38(56), data→hex string
   - 触发 malloc(64) + memcpy(57 bytes) — SSO long mode分配
5. malloc(24) + str_copy — 再次复制到map node
```

### 6.2 variant来源

Frida显示str_copy的src variant在地址 `base+0x7B0760` 附近:
- `0x7538b38760 - 0x7538388000 = 0x7B0760` — 这就是qword_7B0760！

确认: x131→x146窗口内，sub_1E0268直接从全局qword_7B0760复制。

## 7. 已确认的完整调用链

```
[App启动 / init3]
  写入 .bistore/a6de269810198701a152619ebd19abc1
  (hash计算和序列化在此完成)

[sig() 调用时]
  open(.bistore/a6de269810198701a152619ebd19abc1)
  sub_2F4DB0(ctx, 2, &blob) → 读78字节blob
  sub_2B47D4(blob_source, 2, map, 0) → 反序列化
    sub_2B4DB0 → sub_2B0898 → memcpy(56字节hex string)
  vm_dispatch_1A2128 → sub_1418F0(&qword_7B0760, hex_str, 56)
  
  ... (VM执行其他字段) ...
  
  [x131 insert #63]
  sub_1E0268:
    sub_1702D4(tree_traverse)
    mutex_lock(stru_7B33A8)
    sub_141600([X19+0x2C8], &qword_7B0760) → 复制到VM寄存器
    mutex_unlock(stru_7B33A8)
  
  ... (VM handler传递 [X19+0x2C8] → [X19+0x1D20]) ...
  
  [x146 insert #64]
  vm_call_28C7E8_1DCF38:
    map_insert(map=[X19+0x50], "x146")
    value从[X19+0x1D20] variant写入RB-tree节点
```

## 8. 文件清单

| 文件 | 说明 |
|------|------|
| x146_investigation.md | Step 1 调查记录 |
| x146_step2.md | Step 2 VM分析+动态捕获 |
| x146_step3.md | 本文件 (Step 3 完整数据流) |
| hook_x146_global_write.js | Frida脚本: 捕获全局写入 |
| hook_x146_hash_trace.js | Frida脚本: 追踪28/56字节数据创建 |
| hook_x146_blob_source.js | Frida脚本: 追踪blob来源 |
| hook_x146_build.js | Frida脚本: x131→x146窗口native调用 |

## 9. 下一步

### 9.1 最优先: 验证方案A (提供.bistore文件)

```bash
adb pull /data/user/0/com.xingin.xhs/.bistore/ ./bistore/
```

然后在unidbg中注册这些文件到虚拟文件系统。

### 9.2 追踪hash计算 (如果需要动态生成)

Hook .bistore文件的写入:
```javascript
// Frida: 监控write syscall, fd指向.bistore文件
Interceptor.attach(Module.findExportByName(null, "write"), {
    onEnter: function(args) {
        // 检查fd是否指向.bistore文件
        // 如果是, dump写入数据和backtrace
    }
});
```

### 9.3 理解x146 hash算法 (长期目标)

从写入blob的调用链反向追踪:
1. blob写入时刻的backtrace → 找到计算函数
2. 计算函数可能在VM handler中 (128个XOR + 120个MUL)
3. 或通过JNI回调Java层的MessageDigest
