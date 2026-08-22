# 小红书设备指纹字段追踪记录

> trace文件: `trace_ts_set_1773776029582.txt` (ts=1773776029582)
> unidbg类: `Xhs921.java`
> SO: `libtiny.so`

## 通用机制

- **byte reader** `0x172278`: 逐字节读取 key string (SSO格式)
- **dispatcher** `0x170b70`: 根据 value type 跳转到对应 handler 输出值
- **caller** `0x17105c`: 循环遍历 JSON 树节点，依次调用 byte reader 读 key → dispatcher 写 value
- **value type**: type=5 整数, type=6 整数(布尔), 存储在 JsonValue 节点首字节

---

## x32 — 电池是否存在 (Battery Present)

| 项目 | 值 |
|------|-----|
| **unidbg输出** | `0` |
| **真机值** | `1` (true) |
| **来源** | `Intent.getBooleanExtra("present", true)` |
| **Action** | `android.intent.action.BATTERY_CHANGED` |

### 数据流

```
JNI: FindClass("android/content/Intent")
  → NewGlobalRef (缓存 jclass)
  → GetMethodID("getBooleanExtra", "(Ljava/lang/String;Z)Z")
  → CallBooleanMethodV(intent_obj, methodID, "present", default=true)
  → 返回 w0=1 (true)

offset 0x1e2470: mov w4, #1              ← 默认值 true
offset 0x1e2478: bl #0x122fca28          ← 内部wrapper, 调用 CallBooleanMethodV
offset 0x1e2480: strb w0, [x8, #0x565]   ← 写入VM寄存器
    ↓ VM handler 复制
offset 0x1ccf88: ldrb → str              ← 写入临时槽 (type=6, value=1)
offset 0x1dca28: str x10, [x8, #8]       ← 写入JSON节点 0x12b28f90
    ↓ 输出
offset 0x170df8: ldr x1, [x20, #8]       ← dispatcher读取, 输出 "1"
```

### trace关键行号

| 事件 | 行号 | offset |
|------|------|--------|
| JNI wrapper 入口 | ~165036 | 0x4fb19c |
| FindClass | ~165050 | JNI 0x30 |
| GetMethodID (getBooleanExtra) | ~165200 | JNI 0x108 |
| mov w4, #1 (默认值) | 165336 | 0x1e2470 |
| CallBooleanMethodV | 165338 | 0x1e2478 |
| 写入VM寄存器 | 165340 | 0x1e2480 |
| 写入JSON节点 value | 166352 | 0x1dca28 |
| byte reader 读 "x32" | ~283150 | 0x172278 |
| dispatcher 输出值 | ~283404 | 0x170df8 |

### Intent 初始化缓存的方法列表 (offset 0x4fb19c)

一次性缓存以下 method ID:
- `<init>`, `getIntExtra`, `getBooleanExtra`, `putExtra`
- `addCategory`, `setComponent`, `setPackage`, `setClassName`
- `parseUri` (static)

### unidbg修复建议

在 `Xhs921.java` 的 `callBooleanMethodV` 中，对 `getBooleanExtra("present", ...)` 返回 `true`。

---

## x33 — 电池状态 (Battery Status)

| 项目 | 值 |
|------|-----|
| **unidbg输出** | `0` |
| **真机值** | `4` (BATTERY_STATUS_FULL) / `2` (CHARGING) |
| **来源** | `Intent.getIntExtra("status", 1)` |
| **Action** | `android.intent.action.BATTERY_CHANGED` |

### 状态码

- 1 = UNKNOWN, 2 = CHARGING, 3 = DISCHARGING, 4 = NOT_CHARGING/FULL, 5 = FULL

---

## x34 — 电池刻度 (Battery Scale)

| 项目 | 值 |
|------|-----|
| **unidbg输出** | `0` |
| **真机值** | `100` |
| **来源** | `Intent.getIntExtra("scale", -1)` |
| **Action** | `android.intent.action.BATTERY_CHANGED` |

---

## x35 — 电池电量 (Battery Level)

| 项目 | 值 |
|------|-----|
| **unidbg输出** | `0` |
| **真机值** | `100` |
| **来源** | `Intent.getIntExtra("level", -1)` |
| **Action** | `android.intent.action.BATTERY_CHANGED` |

### 百分比计算

实际电量 = `level * 100 / scale`

---

## x36 — 充电方式 (Battery Plugged)

| 项目 | 值 |
|------|-----|
| **unidbg输出** | `0` |
| **真机值** | `1` (AC) |
| **来源** | `Intent.getIntExtra("plugged", 0)` |
| **Action** | `android.intent.action.BATTERY_CHANGED` |

### 充电类型

- 0 = 未充电, 1 = AC, 2 = USB, 4 = Wireless

---

## x45 — 容器元素计数

| 项目 | 值 |
|------|-----|
| **unidbg输出** | `0` |
| **真机值** | `7` / `339` (每次变化) |
| **来源** | native层 `std::vector` 的 `end - begin` |
| **value type** | 5 (整数) |

### 数据流

```
offset 0x1eeee8  (指纹构建器)
  → 0x2afdf0    (key-value 插入wrapper)
    → 0x2afdc0: sub x8, x21, x20     ← end - begin, 两个迭代器相等 → 0
    → 0x2afdc4: mov w9, #5           ← type=5
    → 0x2afdc8: stp x9, x8, [sp, #8] ← 压栈 {type=5, value=0}
    → 0x2afe0c: str x8, [x0, #8]     ← 写入JSON节点 value=0
```

### trace关键行号

| 事件 | 行号 | offset |
|------|------|--------|
| sub x8, x21, x20 (计算size) | 233461 | 0x2afdc0 |
| 写入JSON节点 type | 233951 | 0x2afdfc |
| 写入JSON节点 value | 233955 | 0x2afe0c |
| byte reader 读 "x45" | ~289673 | 0x172278 |
| dispatcher 输出 '0' | ~289931 | 0x170ff4 |

### 分析

- 两个迭代器都指向 `0x19cfd4a478e` (=1773776029582，即ts时间戳)
- 容器存储的是时间戳相关数据
- unidbg中容器为空(begin==end)所以值=0
- 真机中容器有数据，值随运行状态变化(7/339)
- 可能是某种事件计数器或采样缓冲区的大小

### unidbg修复建议

需要进一步确认该容器的填充逻辑，可能与 `/proc` 文件读取或传感器采样有关。

---

## x70 — VM字节码常量

| 项目 | 值 |
|------|-----|
| **unidbg输出** | `1` |
| **真机值** | `90` / `29` (每次变化) |
| **来源** | VM bytecode数据表硬编码常量 |
| **value type** | 5 (整数) |

### 数据流

```
offset 0x1d0138: ldr w8, [x8, x9]     ← 从 0x1273c244 (libtiny.so数据段) 加载 w8=1
offset 0x1d0148: str w8, [x19, #0x19ec] ← 写入VM字节码寄存器
offset 0x1e9c24: ldrsw x8, [x19, #0x19ec] ← 读取VM寄存器
offset 0x1e9c40: str x8, [x9]          ← 写入VM临时槽
offset 0x1cfb50: str x8, [x9]          ← 写入JSON节点
```

### trace关键行号

| 事件 | 行号 | offset |
|------|------|--------|
| 从数据表加载常量 | 180813 | 0x1d0138 |
| 写入VM寄存器 | 180814 | 0x1d0148 |
| 写入JSON节点 | 181519 | 0x1cfb50 |
| byte reader 读 "x70" | ~291560 | 0x172278 |
| dispatcher 输出 | ~291729 | 0x170b70 |

### 分析

unidbg中值为1（常量），真机值每次变化。真机的实际值可能由其他代码路径动态填充，在unidbg环境中走了fallback常量路径。

---

## x72 — 事件时间戳 (Sentinel)

| 项目 | 值 |
|------|-----|
| **unidbg输出** | `-1` |
| **真机值** | `1773701282149` (时间戳) |
| **来源** | VM bytecode常量 -1 (sentinel) |
| **GOT地址** | `0x1273c250` |

### 分析

-1 是 sentinel 值，表示"未设置"。真机中该值由 SharedPreferences 缓存的事件时间戳填充。unidbg 环境中未触发相关 JNI 回调，走了 sentinel 默认值。

---

## x73 — 事件时间戳 (Sentinel)

| 项目 | 值 |
|------|-----|
| **unidbg输出** | `-1` |
| **真机值** | `1774883131415` (时间戳) |
| **来源** | VM bytecode常量 -1 (sentinel) |
| **GOT地址** | `0x1273c258` (紧邻x72的0x1273c250) |

### 分析

与 x72 相同模式，相邻内存槽，均为 sentinel -1。

---

## x79 — 音量最大值 (AudioManager)

| 项目 | 值 |
|------|-----|
| **unidbg输出** | `100` |
| **真机值** | `11297` / `16384` (每次变化) |
| **来源** | JNI `AudioManager.getStreamMaxVolume()` |
| **PLT** | `0x732ee0` |

### 数据流

```
offset 0x1ec8a4: blr x8 (x8=0x121702d4)  ← VM JNI bridge
  → PLT 0x732ee0 → GOT 0x127aed48 → JNI handler
  → 返回 w0=0x64 (100)
offset 0x1ec8f4: str x9, [x8]             ← 写入VM寄存器 [0xe4ff5928]
offset 0x1eab4c: str x10, [x8]            ← 写入JSON节点
```

### trace关键行号

| 事件 | 行号 | offset |
|------|------|--------|
| JNI call | 184033 | 0x732eec |
| 写入VM寄存器 | 184042 | 0x1ec8f4 |
| 写入JSON节点 | 184851 | 0x1eab4c |
| byte reader 读 "x79" | ~293010 | 0x172278 |

---

## x80 — 电池属性 (BatteryManager)

| 项目 | 值 |
|------|-----|
| **unidbg输出** | `100` |
| **真机值** | `843` / `846` (微小变化) |
| **来源** | JNI `BatteryManager.getLongProperty()` |
| **PLT** | `0x732fb0` |

### 数据流

```
offset 0x1eab78: blr x8 (x8=0x121702d4)  ← VM JNI bridge
  → PLT 0x732fb0 → GOT 0x127aedb0 → JNI handler
  → 返回 w0=0x64 (100)
offset 0x1eab80: str w0, [x19, #0x1b4c]  ← 写入VM字节码寄存器
offset 0x1ed01c: str x8, [x9]            ← 写入JSON节点
```

### trace关键行号

| 事件 | 行号 | offset |
|------|------|--------|
| JNI call | 184867 | 0x732fbc |
| 写入VM寄存器 | 184868 | 0x1eab80 |
| 写入JSON节点 | 185607 | 0x1ed01c |
| byte reader 读 "x80" | ~293846 | 0x172278 |

---

## x92 — targetSdkVersion

| 项目 | 值 |
|------|-----|
| **unidbg输出** | `23` |
| **真机值** | `35` |
| **来源** | JNI `ApplicationInfo.targetSdkVersion` 字段访问 |
| **Xhs921.java** | line 990: `return 23` |

### 数据流

```
JNI: getIntField("android/content/pm/ApplicationInfo->targetSdkVersion:I")
  → Xhs921.java 返回 23 (0x17)
offset 0x2dafc4: mov w0, #0x17
  → VM寄存器 [0xe4ff8e18] → [0xe4ff6028]
offset 0x1da5dc: str x10, [x8]  ← 写入JSON节点 [0x12b286d0]
```

### trace关键行号

| 事件 | 行号 | offset |
|------|------|--------|
| JNI返回值 | 109333 | 0x2dafc4 |
| 写入VM寄存器 | 118646 | 0x1dfe58 |
| 写入JSON节点 | 119286 | 0x1da5dc |
| byte reader 读 "x92" | ~295190 | 0x172278 |

### unidbg修复建议

将 `Xhs921.java:990` 的返回值从 `23` 改为 `35` 以匹配真机。

---

## x98 — 设备安全属性 (String)

| 项目 | 值 |
|------|-----|
| **unidbg输出** | `"0"` |
| **真机值** | `"0"` |
| **来源** | 预初始化全局结构体 `0x12b39000 + 0x140` |
| **value type** | 3 (字符串) |

### 数据流

```
全局数据结构 0x12b39000 (GOT: [0x127b0000+0xb80])
  → offset 0x140 处存储字符串 "0"
offset 0x1d242c: str q0, [x19]     ← SIMD复制到VM栈
offset 0x141628: str q0, [x19]     ← 复制到新分配的 0x12b18860
offset 0x1d1e64: str x10, [x8, #8] ← 写入JSON节点指针
```

### 分析

值 "0" 在库初始化阶段由 JNI 调用填充到全局结构体中。可能是 `ro.debuggable`、root 检测结果等设备安全属性。

---

## x131 — Root/Magisk 检测标志

| 项目 | 值 |
|------|-----|
| **unidbg输出** | `"1"` (误报) |
| **真机值** | `"0"` |
| **来源** | `gettid()` 哨兵比较 → 条件分支选择 "0" 或 "1" |
| **value type** | 3 (字符串) |

### 数据流

```
offset 0x1dbcd0: svc #0 (x8=0xb2)    ← gettid() syscall, 返回 x0=0x64
offset 0x1dbd00: str → VM寄存器 [x19+0x1c78] = 0x64
offset 0x1ee94c: ldr w8 = 0x64, ldr w9 = 0x64
offset 0x1ee95c: cmp w9, w8          ← 比较: 0x64 == 0x64 → EQUAL
offset 0x1ee960: csel x8, x11, x10, eq ← 选择 x11=0x127462f8 ("1"路径)
  → 字符串 "1" 从 0x12b17088 复制到 0x12b3f080
```

### trace关键行号

| 事件 | 行号 | offset |
|------|------|--------|
| gettid() syscall | 187860 | 0x1dbcd0 |
| 哨兵比较 | 188020 | 0x1ee95c |
| 条件选择 | 188022 | 0x1ee960 |
| 字符串复制 | 188068 | 0x29e468 |
| 写入JSON节点 | 188785 | 0x1ca130 |
| byte reader 读 "x131" | ~246047 | 0x172278 |

### 分析

unidbg 中 gettid() 返回固定值 0x64，两个比较值相等导致走"检测到"分支，输出 "1"。真机中两个值不等（一个是 gettid 实时值，另一个是预存的sentinel），正常走 "0" 路径。这是 **unidbg 环境导致的误报**。

---

## x206 — 平板检测

| 项目 | 值 |
|------|-----|
| **unidbg输出** | `0` |
| **真机值** | `0` |
| **来源** | `.bss` 全局标志 `0x127b3d50` (ldar load-acquire) |
| **value type** | 6 (整数/布尔) |

### 数据流

```
offset 0x1daffc: ldar w8, [x8]  ← 从 0x127b3d50 读取, w8=0 (未初始化)
  → VM寄存器 [x19+0x1f5c]
  → type=6, value=NULL → dispatcher默认输出 '0'
```

### 分析

标志位在 `.bss` 段，使用 `ldar` (load-acquire) 读取，说明预期由其他线程/JNI回调写入。在unidbg中未触发平板检测JNI逻辑（可能查询 `PackageManager.hasSystemFeature("android.hardware.type.tablet")` 或屏幕尺寸），标志保持默认0。

---

## x207 — 折叠屏检测

| 项目 | 值 |
|------|-----|
| **unidbg输出** | `0` |
| **真机值** | `0` |
| **来源** | `.bss` 全局标志 `0x127b3d54` (ldar, 紧邻x206的0x127b3d50) |
| **value type** | 6 (整数/布尔) |

### 分析

与 x206 相同模式，相邻4字节。`ldar` 读取，预期由后台JNI检测线程设置。在unidbg中未触发，默认0。

---

## x263 — 进程 Dumpable 状态

| 项目 | 值 |
|------|-----|
| **unidbg输出** | `0` |
| **真机值** | `0` |
| **来源** | `prctl(PR_GET_DUMPABLE)` syscall |
| **syscall** | `svc #0`, x8=0xa7, x0=3 |

### 数据流

```
offset 0x1d268c: svc #0          ← prctl(PR_GET_DUMPABLE), 返回 x0=0
  → VM寄存器 [x19+0x24f8]
  → type=5, value=0
offset 0x1e2878: str x10, [x8]   ← 写入JSON节点 [0x12b29c60]
```

### trace关键行号

| 事件 | 行号 | offset |
|------|------|--------|
| prctl syscall | 219690 | 0x1d268c |
| 写入JSON节点 | 220658 | 0x1e2878 |
| byte reader 读 "x263" | ~270701 | 0x172278 |

### 分析

`PR_GET_DUMPABLE` 返回0 = 进程不可dump (SUID_DUMP_DISABLE)。这是反调试检测指标之一。

---

## x264 — Timer Slack

| 项目 | 值 |
|------|-----|
| **unidbg输出** | `0` |
| **真机值** | `0` |
| **来源** | `prctl(PR_GET_TIMERSLACK)` syscall |
| **syscall** | `svc #0`, x8=0xa7, x0=0x27 (39) |

### 数据流

```
offset 0x1c98f4: svc #0          ← prctl(PR_GET_TIMERSLACK), 返回 x0=0
  → VM寄存器 [x19+0x2558]
  → type=5, value=0
offset 0x1c952c: str x9, [x8]    ← 写入JSON节点 [0x12b29bc0]
```

### trace关键行号

| 事件 | 行号 | offset |
|------|------|--------|
| prctl syscall | 220717 | 0x1c98f4 |
| 写入JSON节点 | 221720 | 0x1c952c |
| byte reader 读 "x264" | ~271094 | 0x172278 |

### 分析

`PR_GET_TIMERSLACK` 返回定时器松弛值(纳秒)。unidbg返回0作为默认值。真机上也通常为0或很小的值。可能用于模拟器/沙箱检测。

---

## x272 — 飞行模式

| 项目 | 值 |
|------|-----|
| **unidbg输出** | `0` |
| **真机值** | `0` |
| **来源** | `.bss` 未初始化字节 `0x127b3d70` |

### 数据流

```
offset 0x1d45a0: ldrb w8, [x8]   ← 从 0x127b3d70 读取, w8=0 (未初始化)
  → type=5, value=0
offset 0x1ec654: str x10, [x8]   ← 写入JSON节点 [0x12b29fd0]
```

### trace关键行号

| 事件 | 行号 | offset |
|------|------|--------|
| 读取.bss标志 | 224170 | 0x1d45a0 |
| 写入JSON节点 | 224958 | 0x1ec654 |
| byte reader 读 "x272" | ~272863 | 0x172278 |

### 分析

飞行模式标志位在 `.bss` 中，预期由 JNI 调用 `Settings.Global.getInt("airplane_mode_on")` 设置。unidbg中未触发该回调，保持默认0。注意：紧邻的 `0x127b3d71` 被 x290 处理时设为1，说明这是一个标志数组区域。

---

## x290 — 电源供应状态

| 项目 | 值 |
|------|-----|
| **unidbg输出** | `-1` |
| **真机值** | `1` |
| **来源** | 硬编码常量 `mov w9, #-1` (fallback) |

### 数据流

```
offset 0x1d4b3c: mov w9, #-1     ← 硬编码 fallback 常量
  → 标志位 0x127b3d71 设为 1 (已处理)
  → type=5, value=-1
offset 0x1d8b68: str x8, [x9]    ← 写入JSON节点 [0x12b2a020]
```

### trace关键行号

| 事件 | 行号 | offset |
|------|------|--------|
| 设置处理标志 | 225072 | — |
| mov w9, #-1 | 225076 | 0x1d4b3c |
| 写入JSON节点 | 225795 | 0x1d8b68 |
| byte reader 读 "x290" | ~277511 | 0x172278 |

### 分析

正常路径会读 `/sys/class/power_supply/` 获取充电状态，但 unidbg 中 sysfs 不可用，直接走 fallback 返回 -1。真机值为1表示正在供电。

---

## x293 — 可用内存 (sysinfo)

| 项目 | 值 |
|------|-----|
| **unidbg输出** | `2090195` |
| **真机值** | `2108538` / `31464714` (大幅变化) |
| **来源** | `sysinfo()` syscall + XOR时间戳编码 |
| **syscall** | `svc #0`, x8=0xb2 (178) |

### 数据流

```
offset 0x1dbcd0: svc #0 (x8=0xb2)        ← sysinfo() syscall, 填充栈上 struct sysinfo
  → 提取 freeram 字段
offset 0x2afd58: mov w8, #0xe44d          ← 构建原始内存值
             movk w8, #0x1f, lsl #16
             add x8, x20, x8             ← x20=timestamp + meminfo_value
             eor x8, x21, x8             ← XOR编码: timestamp ⊕ (timestamp + value)
offset 0x2afdb0: str x8, [x0, #8]        ← 写入JSON节点 [0x12b2a298]
```

### trace关键行号

| 事件 | 行号 | offset |
|------|------|--------|
| sysinfo() syscall | 187859 | 0x1dbcd0 |
| XOR编码 | 232845 | 0x2afd58 |
| 写入JSON节点 | 233457 | 0x2afdb0 |
| byte reader 读 "x293" | ~277921 | 0x172278 |

### 分析

值经过 XOR 时间戳编码：`result = timestamp ⊕ (timestamp + freeram)`。每次运行值不同因为 freeram 是实时内存状态。

---

## x296 — 空字符串

| 项目 | 值 |
|------|-----|
| **unidbg输出** | `""` |
| **真机值** | `""` |
| **来源** | 空 `std::string` 分配，未填充 |
| **value type** | 3 (字符串) |

### trace关键行号

| 事件 | 行号 | offset |
|------|------|--------|
| 空string分配 | 228488 | 0x141624 |
| 写入JSON节点 | 229250 | 0x1c88a0 |
| byte reader 读 "x296" | ~278395 | 0x172278 |

### 分析

VM 分配空 string 但从未填充。可能需要 JNI `getActiveNetworkInfo` 或类似网络 API 触发填充。

---

## x304 — 网络连接状态

| 项目 | 值 |
|------|-----|
| **unidbg输出** | `1` |
| **真机值** | `1` |
| **来源** | `.rodata` 预计算常量 `0x121032c0` + `ioctl(0x2b)` 确认 |
| **value type** | 5 (整数) |

### 数据流

```
offset 0x2b3a80: ioctl (x8=0x2b)         ← 成功返回 0，确认网络连通
offset 0x1e272c: ldr q0, [x9, #0x2c0]    ← 从 .rodata 加载 {type=5, value=1}
offset 0x1e273c: str q0, [x8]            ← 写入VM变量
offset 0x1eeeb0: str x8, [x9]            ← 写入JSON节点 [0x12b2a200]
```

### trace关键行号

| 事件 | 行号 | offset |
|------|------|--------|
| ioctl 成功 | 112102 | 0x2b3a80 |
| 从.rodata加载 | 231327 | 0x1e272c |
| 写入JSON节点 | 232242 | 0x1eeeb0 |
| byte reader 读 "x304" | ~281996 | 0x172278 |

### 分析

先通过 `ioctl` 检查网络连通性，成功后保持 .rodata 默认值 1（已连接）。

---

## x305 — 信号强度

| 项目 | 值 |
|------|-----|
| **unidbg输出** | `0` |
| **真机值** | `-3` |
| **来源** | VM 默认值（ioctl 查询信号强度失败） |
| **value type** | 5 (整数) |

### 数据流

```
offset 0x2b3c20: ioctl (x8=0x2b)         ← 返回 -1 (失败，无无线接口)
  → VM寄存器 [x19+0x287c] 保持默认 0
offset 0x1d7180: ldrsw x8, [x19, #0x287c] ← 读取 0
offset 0x1e9c9c: str x8, [x9]            ← 写入JSON节点 [0x12b2a0c0]
```

### trace关键行号

| 事件 | 行号 | offset |
|------|------|--------|
| ioctl 失败 | 113075 | 0x2b3c20 |
| 读取默认值 | 227628 | 0x1d7180 |
| 写入JSON节点 | 228398 | 0x1e9c9c |
| byte reader 读 "x305" | ~282402 | 0x172278 |

### 分析

`ioctl` 查询信号强度失败（unidbg无无线接口），VM寄存器保持默认0。真机值 -3 可能来自 RSSI 或 dBm 值。

---

## 附录: Frida Hook 脚本

### Intent.getBooleanExtra / getIntExtra

文件: `hook_x32_intent.js`

```javascript
Java.perform(function () {
    var Intent = Java.use("android.content.Intent");
    Intent.getBooleanExtra.implementation = function (key, defaultValue) {
        var result = this.getBooleanExtra(key, defaultValue);
        console.log("[getBooleanExtra] key=" + key + " default=" + defaultValue + " result=" + result);
        console.log("    action=" + this.getAction());
        return result;
    };
    Intent.getIntExtra.implementation = function (key, defaultValue) {
        var result = this.getIntExtra(key, defaultValue);
        console.log("[getIntExtra] key=" + key + " default=" + defaultValue + " result=" + result);
        return result;
    };
});
```

---

## x185 — 传感器存在标记 (Sensor Presence Flags)

| 项目 | 值 |
|------|-----|
| **unidbg输出** | `"IiGg"` |
| **真机值** | `"IiGgSsKkCVvEeP"` |
| **来源** | `.bss` 预初始化全局字符串 (`0x127b0730`)，JNI_OnLoad阶段通过SensorManager.getSensorList()构建 |
| **value type** | 0x3 (string, handler 0x170d74) |

### 传感器字母编码

每个字母对(大写/小写)代表一个传感器类型存在：

| 字母对 | 传感器类型 | TYPE常量 | unidbg | 真机 |
|--------|-----------|---------|--------|------|
| I/i | Accelerometer (加速度计) | 1 | ✅ | ✅ |
| G/g | Gyroscope (陀螺仪) | 4 | ✅ | ✅ |
| S/s | Magnetic Field (磁力计) | 2 | ❌ | ✅ |
| K/k | Light (光线传感器) | 5 | ❌ | ✅ |
| C | Pressure (气压计) | 6 | ❌ | ✅ |
| V/v | Proximity (距离传感器) | 8 | ❌ | ✅ |
| E/e | Gravity (重力传感器) | 9 | ❌ | ✅ |
| P | Linear Acceleration (线性加速度) | 10 | ❌ | ✅ |

### 数据流

```
[.bss预初始化阶段 — JNI_OnLoad / .init_array, trace开始前]
  SensorManager.getSensorList(Sensor.TYPE_ALL)
    → 枚举传感器类型 → 每种传感器追加对应字母
    → 结果存入 .bss 全局 SSO string @ 0x127b0730
    → guard @ 0x127b06a0 置位

[JSON构建阶段 — trace可见]
Line 189053: ldarb w8, [0x127b2440] => 0x0     ← key guard未初始化
  → bl __cxa_guard_acquire(0x127b2440)          ← 获取初始化锁
Line 189179: str x9(=0xa968a4a9), [sp]          ← 加密key字节入栈
Line 189185: bl #0x12547210                     ← XOR解密 → "x185"
Line 189201: str x0, [0x127b2448]               ← 解密后key指针存入 .bss
Line 189204: bl __cxa_guard_release(0x127b2440)  ← 释放guard

Line 189228: ldr x1, [0x127b2448] => 0x12b17b80 ← 加载key "x185"
Line 189233: blr x8 (map::find_or_insert)        ← 查找/插入map
Line 189750: add x0, x21, #0x38 => 0x12b295c8   ← 返回value descriptor

[值写入]
Line 188916: bl string_copy_ctor(0x127b0730)     ← 从.bss全局拷贝sensor字符串
Line 188917-920: ldr q0 / str q0                 ← SIMD 16字节拷贝 (SSO inline)
Line 188973: bl malloc(0x18) => 0x12b3f0a0       ← 分配heap SSO
Line 189000-001: str x10 / str q0 [0x12b3f0a0]  ← 拷贝 "IiGg" 到heap

[值关联]
Line 189775: ldrb w8 => 0x3                      ← type = string
Line 189779: strb w8, [0x12b295c8]               ← 写入type字节
Line 189812: str 0x12b3f0a0, [0x12b295d0]        ← 值指针写入descriptor

[输出]
Line 249770: bl 0x172278 (byte reader)           ← 读key "x185"
Line 250046: bl 0x170b70 (dispatcher)            ← 输出value "IiGg"
```

### trace关键行号

| 事件 | 行号 | offset / 地址 |
|------|------|---------------|
| .bss sensor字符串拷贝 | 188916 | `bl string_copy_ctor` src=0x127b0730 |
| heap SSO分配 | 188973 | `bl malloc(0x18)` → 0x12b3f0a0 |
| key XOR解密 | 189185 | `bl 0x12547210` 解密 0xa968a4a9 → "x185" |
| map查找 | 189233 | `blr x8` map::find_or_insert |
| value descriptor返回 | 189750 | x0=0x12b295c8 |
| type写入 | 189779 | `strb 0x3` @ 0x12b295c8 |
| value指针写入 | 189812 | `str 0x12b3f0a0` @ 0x12b295d0 |
| key读取 | 249770 | `bl 0x172278` |
| value输出 | 250046 | `bl 0x170b70` handler=0x170d74 |

### 根因分析

sensor字符串在 `JNI_OnLoad` / `.init_array` 阶段初始化(trace开始前)，通过JNI调用 `SensorManager.getSensorList()` 枚举设备传感器。Xhs921.java 的 `getSystemService("sensor")` 返回null，native层走fallback路径，仅生成默认的 `"IiGg"`（假设最基本的加速度计+陀螺仪存在）。

### unidbg修复建议

在 `callObjectMethodV` 中添加传感器相关mock：

```java
// 1. getSystemService("sensor") → 返回mock SensorManager
case "android/content/Context->getSystemService":
    if ("sensor".equals(args[0])) return vm.resolveClass("android/hardware/SensorManager").newObject(null);

// 2. SensorManager.getSensorList(int) → 返回包含全部传感器的List
case "android/hardware/SensorManager->getSensorList(I)Ljava/util/List;":
    int[] types = {1, 2, 4, 5, 6, 8, 9, 10};
    List<DvmObject<?>> sensors = new ArrayList<>();
    for (int t : types) {
        sensors.add(vm.resolveClass("android/hardware/Sensor").newObject(t));
    }
    return ProxyDvmObject.createObject(vm, sensors);

// 3. Sensor.getType() → 返回对应类型ID
case "android/hardware/Sensor->getType()I":
    return (int) thisObj.getValue();
```

---

## x146 — 设备指纹SHA-224 Hash

| 项目 | 值 |
|------|-----|
| **unidbg输出** | **缺失** (未生成) |
| **真机值** | `"7cbc14b691b6549589ed369e0dcd73c0b9aae789473594c4776afccc"` |
| **来源** | SHA-224 hash，通过VM字节码调用native crypto库 |
| **value type** | 0x3 (string, 56 hex chars = 28 bytes) |

### IDA静态分析

#### SHA-224实现

`sub_64EBDC` 是一个多算法hash分发函数，通过参数 `a1` 选择算法：

| case | 算法 | 输出长度 | IV地址 |
|------|------|---------|--------|
| 3 | MD5 | 16 bytes | `xmmword_103D40` |
| 4 | HMAC-MD5 | 20 bytes | `xmmword_103D40` |
| **5** | **SHA-224** | **28 bytes** | **`0x1036F0` + `0x103970`** |
| 6 | SHA-256 | 32 bytes | `0x1034E0` + `0x1034F0` |
| 7 | SHA-384 | 48 bytes | `xmmword_103B80` + ... |
| 8 | SHA-512 | 64 bytes | `xmmword_1036E0` + ... |
| 9 | MD5+SHA256 | 36 bytes | 组合 |
| 10-13 | SHA-3/SHAKE | 可变 | 各自IV |

SHA-224 IV确认 (地址 `0x1036F0`):
```
c1059ed8 367cd507 3070dd17 f70e5939  ← SHA-224标准初始值H0-H3
```
第二组IV (地址 `0x103970`):
```
ffc00b31 68581511 64f98fa7 befa4fa4  ← SHA-224标准初始值H4-H7
```

#### 调用链

```
VM bytecode dispatcher
  → sub_648224 (VM handler, 跳转表入口)
    → sub_649C70 (VM wrapper, 计算参数)
      → sub_64CF68 (RSA/crypto wrapper, 0xcb8字节)
        → sub_64EBDC(a1=5, data, len, output, outSize)  ← SHA-224
          → sub_641D54 (SHA-224 压缩循环)
          → sub_642004 (SHA-224 最终块处理)
```

#### 另一个SHA-256函数 (对比)

`sha256` at `0x72436c` 是独立的SHA-256实现，用于请求签名 (`sig()`)。它只在trace的line 13686289被调用一次，输入是HTTP请求字符串 (`"GET\n/api/sns/v1/tag/reobpage..."`, 长度0x53b)。此函数**不是**x146的来源。

### Trace分析

| 事实 | 详情 |
|------|------|
| Map插入总数 | 105次 (全部通过 `sub_28C890`) |
| x146在map中 | **不存在** (已通过injectX146注入) |
| SHA-224调用链 | **完全未执行** (`sub_64EBDC`, `sub_649C70`, `sub_648224` 均未出现在trace) |
| 其他缺失字段 | x6, x97, x98, x99, x232, x237, x269 |

---

## x231 / x232 / x236 / x237 存储空间字段 (2026-04-06 Frida+unidbg分析)

### 字段值对比

| 字段 | 真机值 | unidbg值 | 状态 |
|------|--------|---------|------|
| x231 | 53684973568 (~50GB) | 13478064128 (~12.5GB) | **值错** - DirectoryFileIO硬编码 |
| x232 | 53684973568 | **缺失** | **缺失** - VM可能跳过 |
| x236 | 42785001472 (~40GB) | 11634356224 (~10.8GB) | **值错** - statfs("/sdcard")失败后残留 |
| x237 | 42785001472 | **缺失** | **缺失** - 同x236 |

### 数据来源 (Frida确认)

**x231/x232 — 内部存储 (native statfs64)**
- 调用链: libtiny.so → `svc #0` (syscall 43, statfs64) → 内部存储路径
- 真机Frida捕获: `statvfs('/data/user/0/com.xingin.xhs/files')` → total=53684973568, avail=40604020736
- x231 = f_blocks × f_bsize (总空间)
- x232 = f_bavail × f_bsize (可用空间)
- **unidbg问题**: 路径解析到DirectoryFileIO，statfs返回硬编码值 (f_blocks=0x3235af, f_bsize=0x1000 → ~12.5GB)

**x236/x237 — 外部存储 (native statfs64 on "/sdcard")**
- 调用链: libtiny.so → `svc #0` (syscall 43, statfs64) → path="/sdcard"
- 真机Frida捕获: `StatFs('/storage/emulated/0')` → `statvfs('/storage/emulated/0')` → total=53684973568
- **unidbg问题**: `/sdcard` 未在虚拟文件系统注册 → `resolve()` 返回null → ENOENT → statfs失败

### unidbg修复方案

重写 DirectoryFileIO.statfs 硬编码值为合理设备值，并注册 `/sdcard` 路径到虚拟文件系统。

---

## x234 时间戳字段 (2026-04-06 Frida+IDA+trace 完整分析)

### 字段值对比

| 子键 | 真机值 (Frida dump确认) | unidbg值 | 说明 |
|------|------------------------|---------|------|
| "1" | 1771798025013 | 0 | 2026-02-22T22:07:05.013Z |
| "2" | 1771798024580 | 0 | 2026-02-22T22:07:04.580Z |
| "3" | 1771798024400 | 0 | 2026-02-22T22:07:04.400Z |

### Frida 真机确认

```
真机 qword_7B3CF0 dump (Frida直接读取全局RB-tree):
  once_flag (byte_7B6070) = 1  ← call_once已执行
  variant type = 1 (Map), tree size = 3
  node key="1" type=5(int64) val=1771798025013  ✓
  node key="2" type=5(int64) val=1771798024580  ✓
  node key="3" type=5(int64) val=1771798024400  ✓
  
unidbg:
  once_flag (byte_7B6070) = 0  ← call_once未触发
  variant type = 0 (空) → x234 = {1:0, 2:0, 3:0}
```

### 排除的来源 (Frida hook确认)

| 来源 | Hook方式 | 结果 |
|------|---------|------|
| JNI GetLongField | hook libart.so JNI函数表 idx=101 | ✗ 无1771798xxx范围值 |
| JNI CallLongMethod | hook JNI函数表 idx=52-54 | ✗ 无命中 |
| File.lastModified | Java hook | ✗ 无匹配时间戳 |
| SharedPreferences.getLong | Java hook | ✗ 无命中 |
| Field.getLong (反射) | Java hook | ✗ 无命中 |
| native stat() mtime | hook libc stat/fstat/lstat | ✗ 近似但差15秒且无ms精度 |
| .bistore blob_load | hook sub_2F4DB0 | ✗ 未触发(数据已缓存) |

### 完整数据流 (trace + IDA + Frida 三方确认)

```
init阶段:
  前置条件(推测.bistore加载) → std::call_once(byte_7B6070)
    → sub_2CB788 填充3个Int64时间戳到全局map qword_7B3CF0
    → byte_7B6070 = 1

sig()阶段 (unidbg trace line 106872→203428):
  1. handler 0x1c5fa0: 分配栈variant slot → [X19+0x340] = 0xe4ff5760
  2. sub_1E5490: variant_copy(slot, &qword_7B3CF0) → 复制Map到VM寄存器
  3. sub_287A44: 写入 type=1(Map) + tree_ptr 到 slot
  4. vm_rw_1EE4B4(0x1ee4e0): sub_28C7E8("x234", slot) → 插入输出map
```

### 根因

`byte_7B6070` (`std::call_once` flag) 在 unidbg 中为0 → `sub_2CB788` 从未执行 → `qword_7B3CF0` 为空map → x234 子键值全为0。

与 x146 是**同一根因** — init 阶段的前置条件(推测.bistore加载)在 unidbg 中不满足，导致 call_once 初始化被跳过。

### 关键地址

| 地址 | 名称 | 说明 |
|------|------|------|
| 0x7B3CF0 | qword_7B3CF0 | x234全局variant (type=1 Map, 3个Int64子键) |
| 0x7B6070 | byte_7B6070 | std::call_once flag (真机=1, unidbg=0) |
| 0x2CB788 | sub_2CB788 | call_once回调: 向qword_7B3CF0插入时间戳 |
| 0x28A93C | sub_28A93C | 返回子key字符串("1","2","3") |
| 0x2CB718 | — | 清零qword_7B3CF0入口 |
| 0x1EE4B4 | vm_rw_1EE4B4 | sig()中复制qword_7B3CF0并插入"x234"的handler |
| 0x1E5490 | sub_1E5490 | variant_copy(VM_reg, &qword_7B3CF0) |

### unidbg修复方案

与x146相同根因，统一修复:
1. **提供.bistore文件** — 使call_once前置条件满足，自动触发初始化
2. **直接注入** — hook sig()入口，手动设置 byte_7B6070=1 并填充 qword_7B3CF0
3. **Hook sub_2CB788** — 在init3()后手动调用该函数注入时间戳

---

## .bistore 文件格式分析 (2026-04-06)

### 关键发现: 非加密，自定义二进制KV存储

通过删除.bistore后重新生成并dump + OpenSSL crypto hook确认:
- EVP_CipherInit/AES/RC4 hooks在.bistore创建过程中**零触发** → **不使用OpenSSL加密**
- 新建的.bistore有效载荷仅11字节，其余全0 → **明文存储**
- 数据随使用逐步积累(4096B → 16384B)

### 文件结构

**主文件** (page-aligned, 4096B或16384B):
```
[4B LE] 有效数据长度
[N bytes] blob数据 (格式: [4B LE count][entries: 2B keylen, key, 2B vallen, val])
[填充0至页边界]
```

**CRC文件** (.crc, 同大小):
```
[4B] magic: 0xf1145ff0
[4B LE] 版本: 4
[4B LE] 条目数
[16B] 数据CRC/hash校验
[4B LE] 数据长度
[4B LE] 附加计数
[填充0]
```

**文件名**: `a6de269810198701a152619ebd19abc1` = MD5 hash(可能是包名或设备标识的MD5)

### unidbg适配

将真机.bistore文件通过IOResolver直接提供，**无需解密**:
```
/data/user/0/com.xingin.xhs/.bistore/a6de269810198701a152619ebd19abc1
/data/user/0/com.xingin.xhs/.bistore/a6de269810198701a152619ebd19abc1.crc
```

### 数据来源 (最终确认, 2026-04-07)

**x234 = 设备初始化时创建的系统目录 mtime（毫秒精度）**

通过 Frida dlopen hook 在 JNI_OnLoad 前安装，完整捕获了生成流程:

```
设备初始化/刷机 (2026-02-23 06:07:04)
  → 系统依次创建 /data/vendor_ce/0, /data/misc_ce/0,
    /data/user/0/com.android.providers.settings 等目录
  → 各目录 mtime 间隔 180-613ms

libtiny.so JNI_OnLoad:
  → sysinfo (syscall 113) 获取系统信息
  → VM handler 在 0x27DA98 通过 SVC #0 (syscall 79, newfstatat)
    直接 stat 3个系统目录 (绕过libc)
  → 读取 st_mtime + st_mtime_nsec → 计算 ms 级时间戳
  → 值存入 x20 和栈 [sp+0x20]/[sp+0x28]
  → 0x2CB70C: stp x9(type=5), x20(timestamp) 写入VM寄存器
  → sub_2CB788 (call_once) 将 3 个时间戳 map_insert 到 qword_7B3CF0
  → sig()时 variant_copy → vm_rw_1EE4B4 → map_insert("x234")
```

**匹配的系统目录 (Frida stat确认)**:

| x234子键 | 值 (ms) | 匹配目录 | mtime (秒) |
|---------|---------|---------|-----------|
| "3" | 1771798024400 | /data/vendor_ce/0 | 1771798024 |
| "2" | 1771798024580 | /data/misc_ce/0 | 1771798024 |
| "1" | 1771798025013 | /data/user/0/com.android.providers.settings | 1771798024-25 |

- pm clear 不影响这些值（系统目录 mtime 不变）
- 与 .bistore 无关（blob_load 未触发但值存在）
- libc fstatat hook 抓不到（VM handler 通过 SVC 直接调用绕过 libc）

### unidbg 中 x234=0 的根因

unidbg 的 `fstatat64` (syscall 79) 对 `/data/vendor_ce/0` 等系统路径返回 **-1 (ENOENT)**
→ stat 失败 → timestamp 计算结果为 0
→ sub_2CB788 写入 type=5, value=**0**
→ x234 = {"1":0, "2":0, "3":0}

### unidbg 修复方案

在 `Xhs921.java` 的 IOResolver 中注册这 3 个系统路径，使 fstatat 返回成功并填充合理的 st_mtime/st_mtime_nsec：
```java
// 为 /data/vendor_ce/0, /data/misc_ce/0,
// /data/user/0/com.android.providers.settings 注册虚拟目录
// 使 stat 返回 st_mtime=1771798024, st_mtime_nsec=400000000 等
```

**状态**: [已确认] 来源=系统目录mtime，通过VM SVC fstatat读取，Frida多轮验证确认

### 根因分析

x146的SHA-224计算代码路径在unidbg中完全没有被执行。可能原因：

1. **前置条件缺失**: x146是多维度设备指纹的hash，可能依赖其他字段(x97安全检测/x99 CRC/x232存储空间等)作为hash输入。这些字段在unidbg中同样缺失，导致VM字节码跳过了hash计算。

2. **JNI调用失败**: SHA-224的输入可能来自JNI调用的结果(如安全检测API)，unidbg未正确mock这些调用导致返回异常值，VM逻辑判断数据不完整后跳过hash。

3. **init3参数**: `init3()` 调用传入的布尔/浮点参数可能控制哪些指纹维度被收集。如果参数不匹配真机值，某些收集路径被跳过。

### Frida验证脚本

```javascript
// Hook SHA-224 函数 sub_64EBDC 和 map插入函数 sub_286958
// 用于在真机上追踪x146的生成

var base = Module.findBaseAddress("libtiny.so");

// Hook sub_64EBDC (多算法hash函数)
Interceptor.attach(base.add(0x64EBDC), {
    onEnter: function(args) {
        this.algo = args[0].toInt32();
        this.data = args[1];
        this.dataLen = args[2].toUInt32();
        this.output = args[3];
        this.outSize = args[4].toUInt32();
        if (this.algo === 5) { // SHA-224
            console.log("[SHA-224] input len=" + this.dataLen + " outSize=" + this.outSize);
            if (this.dataLen > 0 && this.dataLen < 4096) {
                console.log("[SHA-224] input hex: " + hexdump(this.data, {length: Math.min(this.dataLen, 256)}));
            }
        }
    },
    onLeave: function(ret) {
        if (this.algo === 5 && ret.toInt32() === 0) {
            console.log("[SHA-224] output: " + hexdump(this.output, {length: 28}));
            // 转hex字符串
            var hex = "";
            for (var i = 0; i < 28; i++) {
                hex += ("0" + this.output.add(i).readU8().toString(16)).slice(-2);
            }
            console.log("[SHA-224] hash = " + hex);
        }
    }
});

// Hook map insert sub_28C7E8 / sub_28C890 → 打印key
Interceptor.attach(base.add(0x286958), {
    onEnter: function(args) {
        // args[1] = SSO string (key)
        var sso = args[1];
        var firstByte = sso.readU8();
        var len, str;
        if (firstByte & 1) {
            // long string
            len = sso.add(8).readUInt();
            str = sso.add(16).readPointer().readUtf8String(len);
        } else {
            // short string (SSO)
            len = firstByte >> 1;
            str = sso.add(1).readUtf8String(len);
        }
        console.log("[MapInsert] key=\"" + str + "\"");
    }
});

// Hook sub_649C70 (SHA-224 VM wrapper) 入口
Interceptor.attach(base.add(0x649C70), {
    onEnter: function(args) {
        console.log("[SHA224-VMWrapper] called from " + this.returnAddress.sub(base));
    }
});
```
