PIXEL_MINI_MUA =
{
    // ==================== 应用基本信息 ====================
    "x0": "com.xingin.xhs",       // [已确认] 应用包名 (package name)
    "x1": "9.21.0",               // [已确认] App 版本号 (app version)
    "x2": 9210803,                // [已确认] App 版本号(数字形式, versionCode)
    "x3": 1773600513442,          // [已确认] App 首次安装时间戳 (PackageInfo.firstInstallTime, ms)
    "x4": 1773600513442,          // [已确认] App 最后更新时间戳 (PackageInfo.lastUpdateTime, ms)
    "x5": "JTdCJTdE",             // [已确认] Base64 编码, 解码为 "%7B%7D" 即 "{}" (init3 传入的配置参数)
    "x6": 1774926324961,          // [怀疑] 上次活跃/启动时间戳 (ms), 每次运行变化
    "x7": "msmnile",              // [已确认] 硬件平台 (Build.HARDWARE / ro.board.platform)
    "x8": 1589408786000,          // [已确认] 系统构建时间戳 (Build.TIME, ms)
    "x9": "QQ3A.200605.002.A1",   // [已确认] 系统显示版本 (Build.DISPLAY)

    // ==================== Build 系统信息 ====================
    "x10": "google/flame/flame:10/QQ3A.200605.002.A1/6492478:user/release-keys", // [已确认] Build.FINGERPRINT
    "x11": "abfarm833",           // [已确认] 设备主机名 (Build.HOST)
    "x12": "QQ3A.200605.002.A1",  // [已确认] 系统构建ID (Build.ID)
    "x13": "release-keys",        // [已确认] 构建签名类型 (Build.TAGS)
    "x14": "user",                // [已确认] 构建类型 (Build.TYPE)
    "x15": "6492478",             // [已确认] Build.VERSION.INCREMENTAL
    "x16": "10",                  // [已确认] Android 版本号 (Build.VERSION.RELEASE)
    "x17": 29,                    // [已确认] Android SDK 版本 (Build.VERSION.SDK_INT)
    "x18": "2020-06-05",          // [已确认] 安全补丁日期 (Build.VERSION.SECURITY_PATCH)
    "x19": "flame",               // [已确认] 设备代号 (Build.DEVICE)

    // ==================== 硬件信息 ====================
    "x20": "google",              // [已确认] 设备品牌 (Build.BRAND)
    "x21": "arm64-v8a,armeabi-v7a,armeabi", // [已确认] CPU ABI 列表 (Build.SUPPORTED_ABIS)
    "x22": "flame",               // [已确认] 主板名称 (Build.BOARD)
    "x23": "Google",              // [已确认] 设备制造商 (Build.MANUFACTURER)
    "x24": "Pixel 4",             // [已确认] 设备型号 (Build.MODEL)
    "x25": "flame",               // [已确认] 产品名称 (Build.PRODUCT)
    "x26": "aarch64",             // [已确认] CPU 架构 (os.arch)
    "x27": "4.14.170-g666300e62136-ab6386400", // [已确认] Linux 内核版本 (uname)
    "x28": "#1 SMP PREEMPT Fri Apr 10 23:08:31 UTC 2020", // [已确认] 内核编译信息
    "x29": "g8150-00063-200409-B-6382684", // [已确认] 基带版本 (Build.getRadioVersion())

    // ==================== 屏幕 & 显示 ====================
    "x30": "1080,2280,440",       // [已确认] 屏幕参数: 宽度,高度,DPI (JNI dispatcher case -2126679615 返回)
    "x31": 28,                    // [已确认-R1R3] Settings.System.getInt("screen_brightness") 屏幕亮度值

    // ==================== 电池 Intent (ACTION_BATTERY_CHANGED sticky broadcast) ====================
    "x32": 1,                     // [已确认-trace] Intent.getBooleanExtra("present",true) 电池是否存在; JNI via FindClass("android/content/Intent")
    "x33": 2,                     // [已确认-R2R3] Intent.getIntExtra("status") 充电状态 (2=CHARGING, 5=FULL)
    "x34": 100,                   // [已确认-R2R3] Intent.getIntExtra("scale") 电池满电刻度 (通常=100)
    "x35": 80,                    // [已确认-R2R3] Intent.getIntExtra("level") 电池电量 (0~scale)
    "x36": 1,                     // [已确认-R2R3] Intent.getIntExtra("plugged") 充电器类型 (1=AC, 2=USB, 4=无线)

    // ==================== 系统设置 ====================
    "x37": 0,                     // [已确认-R1R3] Settings.Secure.getInt("accessibility_enabled") 辅助功能开关
    "x38": 1,                     // [已确认-R1R3] Settings.Global.getInt("adb_enabled") ADB调试开关

    // ==================== 电信 SIM卡 (第一卡槽) ====================
    "x40": 1,                     // [已确认-R1R3] TelephonyManager.getSimState() SIM卡状态 (1=ABSENT, 5=READY)
    "x41": "",                    // [已确认-R1R3] TelephonyManager.getSimOperatorName() 运营商名称
    "x42": "",                    // [已确认-R1R3] TelephonyManager.getSimOperator() MCC+MNC 运营商代码

    // ==================== 网络 ====================
    "x43": "wifi",                // [已确认-R3] NetworkInfo.getType() int→string映射 (JNI污染int后输出"unknown"确认)
    "x44": 1775123097370,         // [已确认] System.currentTimeMillis() 当前时间戳 (ms)
    "x45": 7,                     // [已确认-trace] native层空容器size(vector.end-begin), 真机非零(7/339)因容器有数据, unidbg=0因容器为空; 来源: 0x2afdc0 sub x8,x21,x20 其中迭代器指向ts时间戳区域

    // ==================== 统计 & 计数器 ====================
    "x70": 90,                    //
    "x72": 1773701282149,         // [已确认] .bistore->first_launch_time
    "x73": 1774883131415,         // [已确认] .bistore->last_launch_time
    "x78": 10214,                 // [已确认-R3] native getuid() 系统调用 (进程 UID, JNI层污染确认)
    "x79": 11297,                 //
    "x80": 843,                   //
    "x87": 1775123096344,         // [怀疑] 本次启动时间戳 (ms), 每次运行变化

    // ==================== 安全检测 ====================
    "x92": 35,                    // [已确认-trace] JNI ApplicationInfo.targetSdkVersion; Xhs921.java:990返回23, 真机=35
    "x93": 0,                     // [已确认-R1R3] Settings.Secure.getInt("location_mode") 定位模式
    "x97": "...",                 // [已确认-R2] 风控检测结果JSON, 包含 d1-d13(检测项) 和 s1-s11(检测结果) {"d1":"","d10":"","d11":"","d12":"","d13":"","d4":"","d6":"","d9":"","s1":"0|0|0|0|*|0|0","s10":"0|*|0|*|*","s11":"*|0|0","s2":"1|*|0","s3":"*|0|0|0|0|0|0","s4":"*|*|*|*","s5":"0|*|*|*|0|0|0|0|0|*|0|0","s6":"*|0|*|*|0|0|0|0|0|*|0|0","s7":"0|0|0|0","s8":"0|0|0|0|0|0|0","s9":"*|0|0|0"}
    "x98": "0",                   // ios这里是风控sdkversion
    "x99": "3106481332",          // 97的一个crc，直接用真机的就行

    "x120": "0",                  // [已确认-R3] ActivityManager.isUserAMonkey() (污染返回1→字段变为"1"确认)
    "x131": "0",                  // [已确认-trace] gettid()哨兵比较决定分支, Root/Magisk检测标志; unidbg=1(误报), 真机="0"

    "x146": "7cbc14b691b6549589ed369e0dcd73c0b9aae789473594c4776afccc", // 未知，来自.bistore  这个就是 gid

    // ==================== 传感器 ====================
    "x185": "IiGgSsKkCVvEeP",     // [确定] 传感器存在标记, 大小写字母对代表不同传感器类型 (运行间微变)
    "x186": -1,                   // [怀疑] 加速度计采样率 (-1=未获取到)
    "x187": -1,                   // [怀疑] 陀螺仪采样率 (-1=未获取到)

    // ==================== 权限 & 特性 ====================
    "x194": "1",                  // [怀疑] Google Play Services 是否可用
    "x202": "1",                  // [怀疑] 存储权限是否授予
    "x203": "1",                  // [怀疑] 相机权限是否授予
    "x206": 0,                    // [已确认-trace] .bss全局标志(0x127b3d50, ldar), 平板检测; JNI未触发故=0
    "x207": 0,                    // [已确认-trace] .bss全局标志(0x127b3d54, ldar), 折叠屏检测; JNI未触发故=0

    // ==================== 存储 & 硬件资源 ====================
    "x231": 53684973568,          // [已确认] 内部存储总空间 (bytes), native statfs64→statvfs('/data/user/0/PKG/files'), f_blocks*f_bsize
    "x232": 53684973568,          // [已确认] 内部存储可用空间 (bytes), 同statfs64, f_bavail*f_bsize; unidbg缺失
    "x234": {                     // [已确认] 系统目录mtime(ms精度), VM SVC fstatat读取 /data/vendor_ce/0, /data/misc_ce/0, /data/user/0/com.android.providers.settings; call_once→sub_2CB788→qword_7B3CF0; unidbg中fstatat返回-1→值全0
        "1": 1771798025013,
        "2": 1771798024580,
        "3": 1771798024400
    },
    "x235": 2280000,              // [已确认] BatteryManager.getLongProperty(1) 剩余电量(微安时, μAh)
    "x236": 42785001472,          // [已确认] 外部存储总空间 (bytes), native statfs64("/sdcard")→statvfs('/storage/emulated/0'), f_blocks*f_bsize
    "x237": 42785001472,          // [已确认] 外部存储可用空间 (bytes), 同statfs64("/sdcard"), f_bavail*f_bsize; unidbg缺失
    "x238": "cn",                 // [怀疑] 设备地区/国家代码 (Locale.getCountry)

    // ==================== 设备环境 ====================
    "x242": [],                   //
    "x243": 1775123096320,        // [确定] JNI onload Time
    "x247": {                     // [怀疑] CPU 各核心频率/使用率, 可能native读 /sys/devices/system/cpu/
        "0": 71.42857142857143,
        "1": 0,
        "2": 71.42857142857143,
        "3": 32,
        "4": 85.71428571428571,
        "5": 71.42857142857143
    },

    // ==================== 系统设置 & 状态 (续) ====================
    "x258": 0,                    // [未知] 同一次启动不同请求会变                                                     |JD  全局请求计数器
    "x259": 0,                    // [未知] 同一次启动不同请求会变                                                    ｜JD   非首次运行
    "x260": 1775123097370,        // [确定] 数据采集时间戳 (ms), 与x44一样
    "x261": 1,                    // [已确认-R1R3] TelephonyManager.getPhoneType() 手机网络类型 (1=GSM, 2=CDMA)
    "x263": 0,                    // [已确认-trace] prctl(PR_GET_DUMPABLE) syscall返回0, 进程不可dump                ｜JD 	ART/运行正常
    "x264": 0,                    // [已确认-trace] prctl(PR_GET_TIMERSLACK) syscall返回0, 定时器松弛值(ns)           ｜JD  ART/运行正常
    "x267": 1,                    // [已确认-R1R3] Settings.System.getInt("screen_brightness_mode") 亮度模式
    "x269": 1230768000000,        // [未确认] 时间戳 2009-01-01, 固定不变, 可能出厂默认值或Account创建时间
    "x272": 0,                    // [已确认-trace] .bss未初始化字节(0x127b3d70), 飞行模式标志; JNI Settings回调未触发=0

    // ==================== 充电 & 内存 ====================
    "x289": 1775123097375,        // [确定] ，也是sig时期的getCurrentTimeMillis
    "x290": 1,                    // [已确认-trace] 硬编码常量mov w9,#-1(0x1d4b3c), /sys/class/power_supply/不可用时fallback; unidbg=-1
    "x293": 2108538,              // [未知] ，同一次启动不同请求会变，
    "x296": "",                   // [已确认-trace] 空std::string, native未填充; 可能需JNI getActiveNetworkInfo触发

    "x301": "ABSENT",             // [怀疑] SIM卡状态字符串, getSimState()返回值的字符串映射
    "x302": "",                   // [未知] "62FCB7F1A33947657F000C213A9D9C04"
    "x303": "",                   // [未知] "MEQCICih3eJWR2cYTGYb7brWGzD7UFVdwGb/iXKncQFoSDlQAiAVZNa8g8fLmRJTMhyDaJnrqA+miH4K8rtuYjOPPGpLOA=="
    "x304": 1,                    // [已确认-trace] .rodata常量(0x121032c0)+ioctl(0x2b)成功确认网络连通; unidbg=1
    "x305": -3                    // [已确认-trace] ioctl(0x2b)查询信号强度失败(-1)→VM默认值0; unidbg=0, 真机=-3
}

/*
 * ==================== 三轮污点追踪汇总 ====================
 *
 * 第一轮 (77xx, Java层直接hook) 已确认 9 个字段:
 *   x31, x37, x38, x40, x41, x42, x93, x261, x267
 *
 * 第二轮 (888xx, JNI反射+Intent hook) 新确认 6 个字段:
 *   x33, x34, x35, x36, x97, x99
 *
 * 第三轮 (999xx, JNI函数表hook) 新确认 5 个字段:
 *   x43  ← NetworkInfo.getType() int→string映射 (间接命中: int污染→输出"unknown")
 *   x78  ← native getuid() (JNI层直接命中: 99978)
 *   x120 ← ActivityManager.isUserAMonkey() (间接命中: 返回1→"0"变"1")
 *   x258 ← enabled_accessibility_services 非空检查 (间接命中: 污染字符串→0变1)
 *   x259 ← enabled_accessibility_services 服务数量 (间接命中: 污染字符串→0变1)
 *
 * 其他已确认:
 *   x78  ← native getuid() (R3 JNI直接命中)
 *   x120 ← ActivityManager.isUserAMonkey() (R3 间接命中)
 *   x235 ← BatteryManager.getLongProperty(1) (R2)
 *
 * 仍未命中的字段来源推测:
 *   1. Native syscall: getuid(x78已确认), uname(x27/x28), 读/proc /sys文件
 *   2. /proc/stat → x247 CPU使用率
 *   3. /proc/meminfo → x79, x293 内存信息
 *   4. /sys/devices/system/cpu/cpuN/cpufreq → x247 CPU频率
 *   5. /sys/class/power_supply/ → x290 充电状态
 *   6. native statfs64(syscall 43) → x231/x232 内部存储(resolved path), x236/x237 外部存储("/sdcard")
 *   7. native socket/ioctl → x304/x305 网络状态
 *   8. SharedPreferences → x72/x73 事件时间戳
 *   9. JNI dispatcher 内部逻辑 → x30屏幕, x206/x207设备类型
 *  10. 进程/应用遍历 → x92 应用数量
 */
