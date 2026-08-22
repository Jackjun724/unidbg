# x146 逆向分析 Step 2 — VM Opcode Mapping + 动态捕获

> 日期: 2026-04-06
> 状态: value已捕获，待追踪计算过程
> 前置: x146_investigation.md (Step 1)

## 1. 本次工作成果

### 1.1 成功捕获x146的value

```
VALUE = '7cba9aac1237549589ed32900dcd73c0b9aaeae947359bfc7757c2b5'
LENGTH = 56 chars = 28 bytes hex编码
```

- **同设备多次请求值相同** — 不是随机值，是设备指纹的确定性hash
- 与investigation.md中记录的真机值 `7cbc14b691b6...` 前缀相似但不同（`7cb`开头），说明**每次安装/重置后微变**
- Insert顺序: #64（x131之后，x185之前）

### 1.2 value的内存位置已定位

value在map insert时已经计算好，存在VM寄存器中：

```
[X19+0x1D20] → variant结构 (存在于VM state区域)

Variant布局 (40 bytes):
+0x00: type    (uint64) = 3 (string)
+0x08: metadata_ptr     (heap address, 每次不同)
+0x10: capacity (uint64) = 0x41 (65)
+0x18: length   (uint64) = 0x38 (56)
+0x20: data_ptr          → 指向heap上的56字符hex字符串
```

### 1.3 VM Opcode Map完成

对libtiny.so的47,831个VM handler完成了分类和重命名。

## 2. VM架构分析

### 2.1 核心架构

| 指标 | 值 |
|------|-----|
| VM类型 | Handler-threaded interpreter (非bytecode) |
| 总handler数 | 47,831 |
| 平均大小 | 103 bytes, 中位数 72 bytes |
| 状态寄存器 | X19 (指向~8KB VM context struct) |
| Dispatch机制 | BR X8/X9/X10 计算跳转 |
| 编码常量 | handler_addr + 0x31421C0 = encoded |

### 2.2 Handler分类

| 类别 | 数量 | 占比 | 说明 |
|------|------|------|------|
| DISPATCH | 17,945 | 37.5% | 纯跳转/goto/trampoline |
| CMP_SELECT | 9,627 | 20.1% | 比较+条件选择(CSEL) |
| VM_RW | 5,752 | 12.0% | 读VM寄存器→计算→写VM寄存器 |
| VM_LOAD | 5,255 | 11.0% | 读VM寄存器 |
| CMP_SET | 3,190 | 6.7% | 比较+设置标志(CSET) |
| VM_STORE | 2,014 | 4.2% | 写VM寄存器 |
| CALL | 3,798 | 7.9% | BLR调用native函数 |
| XOR | 128 | 0.3% | 异或运算 |
| MUL | 120 | 0.3% | 乘法运算 |

### 2.3 条件分支点

1,739个multi-target dispatch handler:
- 2路分支: 535个 (if/else)
- 3路: 402个
- 4路: 326个
- 5路: 264个
- 6路: 212个

### 2.4 VM寄存器文件

```
主工作寄存器区 (高频读写):
  [X19+0x0408] ~ [X19+0x0488] — 约20个寄存器, 每个4/8字节

次要寄存器区:
  [X19+0x03C0] ~ [X19+0x0404]

特殊寄存器:
  [X19+0x0028] — 高读低写, 可能是PC或SP
  [X19+0x0050] — map指针 (x146 insert时使用)
  [X19+0x0098] — context指针
  [X19+0x0DEB] — 标志/条件寄存器

指针寄存器区:
  [X19+0x1D20] — ★ x146 value variant存储位置
  [X19+0x1D4D] — 临时字节存储
  [X19+0x1D50] — 指针寄存器 (post-insert advance)
```

### 2.5 VM类型系统 (sub_287A44)

| Type ID | 名称 | 说明 |
|---------|------|------|
| 1 | Tree/Map | 红黑树键值对 |
| 2 | Array | 动态数组 vector\<variant\> |
| 3 | String | SSO字符串 ★x146 value是这个类型 |
| 4 | Bytes | 原始字节缓冲区 |
| 5 | Int64 | 64位整数 |
| 6 | Bool | 布尔值 |
| 7 | Float | 浮点数(可能) |
| 8 | Nested | 嵌套map/对象 |

### 2.6 Top Native函数调用

| 次数 | 函数 | 语义 | 说明 |
|------|------|------|------|
| 1,864 | (unresolved) | 各种 | IDA未解析的BLR目标 |
| 190 | sub_1702D4 | tree_traverse | RB-tree遍历/序列化 |
| 163 | sub_28C7E8 | map_insert | SSO key→RB-tree插入 |
| 105 | sub_6F01C4 | log_error | vsnprintf "mod load failed: %s" |
| 86 | sub_16FA34 | tree_free | 递归树节点释放 |
| 64 | sub_44BF68 | vector_push | vector push_back |
| 47 | sub_16FA98 | tree_free2 | 另一种树清理 |
| 41 | sub_40E758 | jni_call | 通过off_75D1D0间接调用 |
| 26 | sub_287A44 | variant_copy | 深拷贝variant(递归) |
| 14 | sub_17004C | int_to_str | 数字→字符串(localeconv) |

### 2.7 Dispatch机制

```
中央跳板 vm_dispatch_17B44C:
  MOV X9, #-0x31421C0
  ADD X8, X8, X9        ; target = encoded - 0x31421C0
  BR  X8

全局Offset表 (用于计算handler地址和数据访问):
  off_745B80 = 0xFFFFFFFFBEF7A00C
  off_746350 = 0xFFFFFFFFA2BB544C
  off_7453D0 = 0x03404B0C
  off_73AD70 = 0x03260ACC
  off_744AC0 = 0x6C08F0A4
  off_73EC18 = 0x2DFE28E0

Handler地址编码示例:
  off_745B80 + 0x413127DC = 0x28C7E8 (sub_28C7E8 = map_insert)
```

## 3. 动态分析过程

### 3.1 Phase 1 — 节点捕获

**发现**: sub_286958 (RB-tree insert) 返回的节点value区域**在insert时全是零**。value不是在insert时写入的。

节点布局:
```
ret - 0x20: key SSO (24 bytes) → "x146"
ret + 0x00: value area → 全零 (insert时)
```

### 3.2 节点地址不可靠

RB-tree rebalance后节点会被移动或重新分配，不能用insert时的返回地址持续监控。

### 3.3 Phase 1.5 — Variant发现

Hook handler `0x1DCF68` (BLR返回后)，发现 `[X19+0x1D20]` 指向的variant已经包含完整的x146 value字符串。

这说明：
- value在map_insert**之前**就已经计算好
- 存在VM寄存器variant中
- insert只是把key和value关联到RB-tree节点

### 3.4 排除的来源

| 来源 | 状态 | 原因 |
|------|------|------|
| snprintf "%02x" | ❌ 排除 | 在x131→x146窗口内无%02x调用 |
| sprintf "%02x" | ❌ 排除 | 同上 |
| memcpy 56字节hex | ❌ 排除 | 未捕获到hex字符串的memcpy |
| memcpy 28字节raw | ❌ 排除 | 捕获到的28字节都是无关字符串 |
| Java MessageDigest | 未测试 | Phase 3未执行完整 |
| sub_64EBDC (native hash) | ❌ 排除 | Step 1已排除 (Frida hook未触发) |

**结论**: hex编码不经过libc的sprintf/snprintf，很可能是**VM内部实现的hex编码函数**或查表法。

## 4. x146 Insert上下文

### 4.1 Insert序列 (每次稳定)

```
#60 x80
#61 x87
#62 x120
#63 x131
#64 x146    ★ 目标
#65 x185
#66 x186
#67 x187
#68 x194
#69 x202
#70 x203
#71 x206
#72 x207
#73 1
#74 2
#75 3
#76 x234
...
#80 x243
```

总共约80次insert (unidbg trace中是105次，差异可能因为版本/环境)

### 4.2 x146 Handler执行链 (Frida backtrace)

```
0x191164  → 入口
0x2780f4  → setup VM context
0x1f64a4  → VM dispatcher
0x1f212c  → VM dispatcher
0x1f1f44  → alloc 496-byte state, init, lock mutex
0x1dcf68  → ★ vm_call_28C7E8_1DCF38 (x146 map insert)
              ↓
          sub_28C7E8 → sub_286958 (RB-tree insert)
```

## 5. 文件清单

| 文件 | 说明 |
|------|------|
| x146_investigation.md | Step 1 调查记录 |
| x146_step2.md | 本文件 (Step 2) |
| vm_opcode_map.md | 完整VM opcode map文档 |
| hook_x146_build.js | Frida动态分析脚本 (当前版本: variant读取) |
| hook_x146_sha224.js | Step 1的Frida脚本 (SHA-224 hook) |
| hook_x146_trace.js | Java层interceptor脚本 |
| libtiny.so.i64 | IDA数据库 (47,831 handler已重命名) |

## 6. 未来计划

### 6.1 Phase A: 追踪谁写入 [X19+0x1D20] (最高优先级)

value在x146 insert前已经存在于 `[X19+0x1D20]` variant中。需要找到写入者。

**方案**:
1. 在x131 insert (#63) 完成后，记录 `[X19+0x1D20]` 的当前值
2. Hook所有写入 `[X19+0x1D20]` 附近内存的VM handler
3. 或者: 用Stalker在x131→x146窗口内trace所有handler，找到操作0x1D20 offset的那些

**具体实现**:
```javascript
// 在x131 insert后，监控 X19+0x1D20 区域
// 方法1: MemoryAccessMonitor (页粒度，可能噪音大)
// 方法2: Hook所有 vm_store_* 和 vm_rw_* handler中写0x1D20的
// 方法3: 在x131后启动Stalker，trace到x146，过滤写入0x1D20的指令
```

### 6.2 Phase B: 追踪hex编码

x146的value是28字节hash的hex编码（56字符）。编码过程不经过libc sprintf。

**方案**:
1. 搜索libtiny.so中的hex查表: `"0123456789abcdef"` 或类似字符串
2. 用IDA找到引用这个table的函数 → 就是hex编码函数
3. Hook该函数，捕获28字节raw hash输入

### 6.3 Phase C: 追踪raw hash来源

一旦找到hex编码函数，下一步是找28字节raw hash的来源:
1. 可能是VM内部实现的SHA-224 (28字节 = SHA-224标准输出)
2. 可能是自定义hash (多个短hash拼接)
3. 可能是通过JNI调用Java层的MessageDigest

### 6.4 Phase D: unidbg修复

确认hash算法和输入后:
1. 在unidbg中模拟缺失的数据来源 (设备指纹数据)
2. 或者直接在Xhs921.java中注入x146的值
3. 对比修复前后的请求是否能通过服务端校验

### 6.5 Phase E: 全量VM反编译 (可选，工作量大)

如果上述针对性追踪不够:
1. 基于opcode map建立VM bytecode反汇编器
2. 符号执行重建高层逻辑
3. 从VM层面理解完整的指纹计算流程

## 7. 关键线索总结

1. **x146 = 设备指纹hash**, 56字符hex (28字节), 同设备稳定, 每次安装微变
2. **value在insert前已计算好**, 存在VM寄存器 `[X19+0x1D20]` variant(type=3, len=56)
3. **hex编码在VM内部完成**, 不经过libc sprintf/snprintf
4. **hash函数不是sub_64EBDC** (Step 1已排除), 可能是VM内嵌实现或JNI回调Java
5. **VM是handler-threaded架构**, 47,831个handler, 用计算跳转串联
6. **IDA中所有handler已重命名**, 可按类型搜索 (vm_call_*, vm_xor_*, vm_mul_* 等)
7. **128个XOR handler + 120个MUL handler** 可能是hash算法核心
