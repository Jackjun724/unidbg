# x146 追踪调查记录

> 状态: 进行中
> 日期: 2026-04-06
> 目标: 找到x146的值来源并在unidbg中修复

## 1. 基本信息

| 项目 | 值 |
|------|-----|
| **字段** | x146 |
| **unidbg输出** | **缺失** (未生成，map中不存在) |
| **真机值** | `"7cbc14b691b6549589ed369e0dcd73c0b9aae789473594c4776afccc"` |
| **值特征** | 56个hex字符 = 28字节 |
| **mini_mua.js注释** | `[怀疑] 设备唯一指纹 (多维度hash, 每次微变)` |

## 2. 已确认的事实

### 2.1 unidbg trace分析 (trace_ts_set_1773776029582.txt)

- **Map插入总数**: 105次，全部通过 `sub_28C890` (offset 0x28c890)
- **x146不在这105次插入中** — key从未被写入map
- **相邻key**: x131 (line 246014) → x14 (line 246542) → x15 (line 247172)，x146的位置完全缺失
- **其他同样缺失的key**: x6, x97, x98, x99, x232, x237, x269
- **SHA-224调用链完全未执行**: `sub_64EBDC`, `sub_649C70`, `sub_648224` 均0次出现
- **唯一的sha256调用** (line 13686289): 用于请求签名，输入是HTTP请求 "GET\n/api/..." 长度0x53b

### 2.2 Frida真机hook结果

#### 第一次hook (库加载后hook):
- `[MapInsert #80] ★★★ key="x146" FOUND ★★★` — **x146确实通过sub_28C890插入**
- 调用栈:
  ```
  0x28c894  ← sub_28C890 返回地址 (bl sub_286958之后)
  0x1dcf68  ← VM字节码handler
  0x1f1f44  ← VM dispatcher
  0x1f212c  ← VM dispatcher
  0x1f64a4  ← VM dispatcher
  0x2780f4  ← 更上层函数
  0x191164  ← 入口
  ```
- **SHA-224 hook (`sub_64EBDC`) 没有触发**

#### 第二次hook (dlopen拦截，JNI_OnLoad前hook):
- **SHA-224 hook仍然没有触发**
- 说明x146的hash**不是**通过 `sub_64EBDC` 计算的

### 2.3 IDA静态分析结果

#### SHA-224实现 (可能不是x146的来源)
- `sub_64EBDC`: 多算法hash分发函数，case 5 = SHA-224
- SHA-224 IV确认: `0x1036F0` = c1059ed8 367cd507 3070dd17 f70e5939
- 调用链: VM handler `sub_648224` → `sub_649C70` → `sub_64CF68` → `sub_64EBDC(5,...)`
- **结论: 这个SHA-224函数不是x146的来源** (Frida两次hook都没触发)

#### 另一个sha256函数
- `sha256` at `0x72436c`: 独立SHA-256实现，用于请求签名
- 使用SHA-256标准IV (0x1034E0, 0x1034F0)
- 条件截断: `if (!v17) a3[7] = bswap32(...)` — 但v17始终为0，总是输出32字节
- **结论: 也不是x146的来源**

#### Map插入函数
- `sub_286958`: 核心红黑树插入函数
- `sub_28C890` / `sub_28C7E8`: wrapper，取C字符串→创建SSO→调用sub_286958
- `sub_28B5EC`: 另一个wrapper (功能相同)
- 其他调用者: `sub_2EE570`, `sub_2EF11C`, `sub_2B62F4`, `sub_44BDD4` 等

#### 关键VM offsets
- `0x1dcf68`: x146插入时的VM handler地址 (来自Frida backtrace)
- `0x1f1f44`, `0x1f212c`, `0x1f64a4`: VM dispatcher chain
- `0x2780f4`: 上层调用
- `0x191164`: 入口函数

## 3. 排除的假设

| 假设 | 状态 | 原因 |
|------|------|------|
| x146 = SHA-224 via sub_64EBDC | ❌ 排除 | Frida hook两次都没触发 |
| x146 = 截断的SHA-256 via sha256@0x72436c | ❌ 排除 | 该函数总输出32字节，且仅用于签名 |
| x146在JNI_OnLoad中计算 | ❌ 排除 | dlopen拦截后hook仍没捕获到hash调用 |
| x146通过其他map插入路径 | ❌ 排除 | 真机backtrace确认走sub_28C890 |

## 4. 未解之谜

**核心问题: 56个hex字符(28字节)的值是怎么计算的？**

可能的解释:
1. **VM内部实现的hash** — hash算法可能完全在VM字节码中实现，不调用任何native hash函数。VM interpreter把每条字节码翻译为ARM指令执行，但hash逻辑被拆散到大量微操作中，无法通过hook单个native函数捕获。
2. **不是hash** — 56个hex字符可能不是标准hash，而是自定义的accumulation/mixing函数，或者多个短hash拼接。
3. **通过JNI回调Java层计算** — hash可能由Java层的MessageDigest计算，然后通过JNI返回给native层。

## 5. 下一步调查方案

### 方案A: Hook Java层MessageDigest (优先尝试)
```javascript
// 如果hash通过Java层计算
Java.perform(function() {
    var md = Java.use("java.security.MessageDigest");
    md.getInstance.overload("java.lang.String").implementation = function(algo) {
        console.log("[MessageDigest] algo=" + algo);
        if (algo.indexOf("224") !== -1 || algo.indexOf("SHA") !== -1) {
            console.log(Java.use("android.util.Log").getStackTraceString(
                Java.use("java.lang.Exception").$new()));
        }
        return this.getInstance(algo);
    };
    md.digest.overload().implementation = function() {
        var result = this.digest();
        if (result.length === 28) {
            console.log("[MessageDigest] 28-byte digest! hex=" + bytesToHex(result));
        }
        return result;
    };
});
```

### 方案B: Hook hex编码函数
x146的值是hex字符串，最终肯定有byte→hex转换。可以:
1. Hook `snprintf`/`sprintf` 拦截 "%02x" 格式化
2. Hook `std::string` append/push_back，监控hex字符 [0-9a-f] 的逐字拼接
3. 在VM offset `0x1dcf68` 处设断点，向前追踪value来源

### 方案C: 对比两次请求的x146值
如果"每次微变"，对比两次值的差异可以推断hash输入中哪些部分在变:
- 完全不同 → 包含时间戳/随机数
- 部分相同 → 可能是多段拼接，固定部分是设备ID，变化部分是时间

### 方案D: IDA分析VM offset 0x1dcf68
用IDA反编译 `0x1dcf68` 处的代码，向前追踪x146的value是从哪个VM寄存器读取的。

```
IDA操作:
1. mcp__ida-pro-mcp__decompile addr=0x1dcf68
2. 找到该handler写入map前读取value的VM寄存器偏移
3. 反向追踪该寄存器的写入者
```

### 方案E: unidbg对比分析
在unidbg中hook VM offset `0x1dcf68` 附近的代码:
1. 检查为什么这个VM handler在unidbg中没被执行
2. 找到控制x146生成的条件分支
3. 对比真机和unidbg在该分支处的寄存器值差异

## 6. 项目上下文

### 文件位置
- **Xhs921.java**: `/Users/jackjun/Desktop/unidbg/unidbg-android/src/test/java/com/xhs/Xhs921.java`
  - `init1()` → `a(-934400877, 10000L)` — 初始化
  - `init3()` → `a(1039552848, "ECFAAF01", ...)` — 指纹收集
  - `sig("")` → `a(-1754486979, "GET", ...)` — 请求签名，map序列化在此阶段
  - 所有native调用入口: offset `0x175118`
- **trace文件**: `trace_ts_set_1773776029582.txt` (14.2M行)
- **fp.md**: 所有字段的详细追踪记录
- **mini_mua.js**: 指纹字段注释汇总
- **hook_x146_sha224.js**: Frida hook脚本 (当前版本含dlopen拦截)
- **back.js**: 第一版hook脚本备份

### 指纹构建流程
1. `init1()` → JNI_OnLoad + 初始化
2. `init3()` → 收集设备指纹原始数据 (传感器/系统属性/JNI调用等)
3. `sig("")` → 构建JSON map (105次insert) + 序列化 + 请求签名
4. x146在真机的sig阶段 #80 被插入map
5. x146在unidbg的sig阶段完全未被插入

### VM架构要点
- VM dispatcher在 `0x17e330` 入口
- Key是XOR加密存储，运行时解密 (如x185: 0xa968a4a9 → "x185")
- Value type: 3=string, 5=int64, 6=bool
- Key处理: byte reader `0x172278` → dispatcher `0x170b70` → handler输出
- 所有key通过caller loop `0x17105c` 遍历红黑树输出JSON
