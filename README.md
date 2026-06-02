# apatch-selinux-oracle

> 一款 APatch / KernelPatch 内核模块（KPM），用于阻断"SELinux Oracle"侧信道型 Root 检测。

[![Build & Release KPM](https://github.com/Wenpiner/apatch-selinux-oracle/actions/workflows/build.yml/badge.svg)](https://github.com/Wenpiner/apatch-selinux-oracle/actions/workflows/build.yml)
[![Release](https://img.shields.io/github/v/release/Wenpiner/apatch-selinux-oracle)](https://github.com/Wenpiner/apatch-selinux-oracle/releases/latest)
[![License](https://img.shields.io/badge/license-GPL--2.0--or--later-blue)](#许可证)

---

## 目录

- [背景：什么是 "SELinux Oracle"](#背景什么是-selinux-oracle)
- [本模块原理](#本模块原理)
- [兼容性](#兼容性)
- [安装与加载](#安装与加载)
- [配置：args 与 conf 文件](#配置args-与-conf-文件)
- [验证效果](#验证效果)
- [从源码构建](#从源码构建)
- [运行时管理](#运行时管理)
- [代码结构](#代码结构)
- [安全考量与已知限制](#安全考量与已知限制)
- [FAQ](#faq)
- [许可证](#许可证)

---

## 背景：什么是 "SELinux Oracle"

近年部分 App / 风控 SDK 在传统 Root 检测（找 `su` 二进制、扫 Magisk 文件、查包名）被各种隐藏方案绕过后，开始使用一种**纯内核侧信道**的探测手段，业内俗称 **SELinux Oracle**：

```
App 进程 ──写 /proc/self/attr/current──> 内核 LSM(selinux) ──> 内核返回 errno
                                                                    │
                              ┌─────────────────────────────────────┘
                              ▼
                     纯净系统：始终 -EINVAL
                     被 Root 的系统：可能是 -EACCES / 0 / 其它，泄漏底层策略
```

具体流程：

1. 应用在自身进程（通常是 `untrusted_app` 或 `app_zygote` 域）里，向 `/proc/self/attr/current`、`/proc/self/attr/exec` 等 `procattr` 节点写入"看起来像 Root 方案私有 SELinux label"的字符串，例如：
   - `u:r:magisk:s0`
   - `u:r:magisk_file:s0`
   - `u:r:su:s0`
   - `magisk`、`kernelsu`、`ksud` 等裸字符串
2. 内核 LSM 入口 `security_setprocattr()` 调用到 SELinux，SELinux 试图把字符串解析为一个**合法的 security context**：
   - **干净系统**：`magisk` 这种 type 根本没在策略里定义 → SELinux 在 `security_context_to_sid_core()` 阶段就拒绝 → 一路返回 `-EINVAL`。
   - **被 Root 过的系统**：底层为了让 magiskd / KernelSU daemon 能用，往策略里**新增了**这些 type/domain。此时字符串能被解析成有效 SID，再走到后面的 `setprocattr_*` 检查时，因 caller 不是允许域而被拒，返回的就不再是 `-EINVAL`，而是 `-EACCES`、`-EPERM` 或别的状态码。
3. 应用只要观察 errno 是不是 `-EINVAL`，就能把整台设备**二分类**为"干净 / 被 Root"——它根本不需要文件系统访问，不需要 root 权限，不需要任何敏感 API，常规的"路径隐藏 / 文件重定向 / Zygisk 拒绝列表"统统拦不住这条侧信道。

这就是所谓的 **Oracle**：把内核当成一个返回布尔值的黑盒预言机来盲测。

---

## 本模块原理

核心思路只有一句：**让内核对任何敏感 label 写入都返回干净系统的标准响应 `-EINVAL`，让 Oracle 永远拿到"未被 Root"的答案。**

### Hook 点选择

`security_setprocattr` 是 LSM 框架在 `procattr` 写入路径上的**唯一总入口**，所有 SELinux/AppArmor/SMACK hook 都挂在它后面。在这里短路，等价于在 LSM 链路最前端就拒绝请求，**SELinux 根本没机会做任何 type 查表 → 完全没有侧信道泄漏**。

在 Linux 4.14（本模块的主要目标内核）上，函数原型是 **4 参数**：

```c
int security_setprocattr(struct task_struct *p, char *name,
                         void *value, size_t size);
```

> v4.20+ / GKI 5.10+ 改成 3 参数（`p` 被移除），切换上游内核时需要把 `hook_wrap4` 改成 `hook_wrap3`。

### Hook 动作

```
before_setprocattr(args) {
    if (is_blacklisted(args->value, args->size)) {
        args->skip_origin = 1;     // 不再调用原 LSM 链路
        args->ret = -EINVAL;       // 伪装为"该 SELinux 域不存在"
    }
    // 未命中 → 什么都不做，原函数正常执行
}
```

关键点：

- **before-only**：只挂 `hook_wrap4` 的 before 阶段，命中立即短路，不挂 after。链路最短，对未命中流量的性能损耗近似 0。
- **不二次拷贝**：`value` 在到达这里之前已被 `proc_pid_attr_write()` 通过 `memdup_user()` 拷贝到内核缓冲区，**直接按字节读即可**，绝对不能再 `copy_from_user`（会触发 KFENCE 报警或更严重）。
- **扫描上限 96 字节**：合法的 SELinux context 通常 `<48` 字节，96 已经留够余量；扫描更长内容只会浪费 cache。
- **子串匹配**：不要求精确等于。`u:r:magisk:s0`、`u:r:magisk_file:s0`、`u:object_r:magisk_file:s0` 全部因为包含 `magisk` 子串而被一击命中。

### 不会留下任何痕迹

由于在 LSM 入口就 `skip_origin`，SELinux 自身**完全没机会运行**，意味着：

- 不会产生 `audit: avc:` 拒绝日志
- 不会触发任何 LSM 后续 hook（`yama_*`、`bpf_*` 等）
- 不会留下 task_struct 的 `security` 字段变化

对外可观察行为与"内核根本没编译 SELinux"等效。

---

## 兼容性

| 维度 | 支持范围 | 备注 |
|---|---|---|
| 内核版本 | Linux 4.14 LTS（arm64） | 主要测试目标 |
| 内核版本（其它） | 4.19 / 5.4 / 5.10 / 5.15 | **需手动改 hook 参数数量**，详见[源码注释](selinux_oracle_bypass.c#L260) |
| 架构 | `aarch64` (ARMv8-A) | KPM 仅支持 ARM64 |
| Loader | APatch（KernelPatch ≥ 0.10.x） | Magisk / KernelSU 不能加载 KPM |
| Android | 8.0 - 14（Android 15 需 5.15+ 内核，要改 hook 参数） | LSM 入口名稱跨版本稳定 |

---

## 安装与加载

### 方式 1：APatch App（推荐）

1. 在 Release 页面下载最新版的 `selinux_oracle_bypass.kpm` 和 `selinux_oracle_bypass.conf`（可选）。
2. 打开 **APatch App → KPM 模块 → 从文件安装**，选择 `.kpm` 文件。
3. 若需要自定义关键字：把 `selinux_oracle_bypass.conf` push 到 `/data/adb/kpm/`，并在 APatch 的 KPM args 输入框填写：
   ```
   default,config=/data/adb/kpm/selinux_oracle_bypass.conf
   ```
4. 重启设备，模块随 KernelPatch 自动加载。

### 方式 2：命令行热加载（便于调试）

```bash
adb push selinux_oracle_bypass.kpm  /data/local/tmp/
adb push selinux_oracle_bypass.conf /data/adb/kpm/
adb push load.sh                    /data/adb/kpm/
adb shell
su
sh /data/adb/kpm/load.sh
```

`load.sh` 会：

1. 自动检测 conf 文件是否存在，存在则用 `default,config=...`，否则降级为 `default`。
2. 如果模块已加载，先 `apd kpm unload` 再 load，避免冲突。
3. 加载完毕后退出，可通过 `dmesg | grep oracle_bypass` 查看生效的关键字列表。

> 注意：热加载在**重启后失效**，仅用于调试。生产环境用方式 1。

---

## 配置：args 与 conf 文件

模块支持三种配置来源，可以任意组合：

### A. 内置默认（零配置时自动启用）

源码 `g_defaults[]` 数组：

```c
"magisk", "kernelsu", "kernel_su", "ksud", "supolicy",
":su:", ":su\n",
```

这套默认值能挡住 99% 的开源 Root 方案（Magisk / KernelSU / SukiSU / APatch 自身）以及它们的衍生 daemon。

### B. KPM args 行内字面量

加载时把关键字塞到 args 里，逗号或分号分隔：

```
magisk,kernelsu,my_custom_root
```

特殊 token：

| Token | 含义 |
|---|---|
| `default` / `defaults` | 装入内置默认列表 |
| `config=/some/path.conf` | 从文件加载更多关键字 |
| `debug` / `verbose` | 启用 per-call 日志（每次 hook 命中入口都打一行，用于排错） |
| 其它字面量 | 直接作为关键字添加 |

例：

| args | 最终关键字 |
|---|---|
| `""` | 内置默认 |
| `"default"` | 内置默认 |
| `"magisk,ksu"` | `magisk` + `ksu`（不含默认） |
| `"default,foo"` | 内置默认 + `foo` |
| `"config=/data/adb/kpm/x.conf"` | 仅来自 conf |
| `"default,config=/data/adb/kpm/x.conf"` | 内置默认 + conf 内容 |
| `"default,debug"` | 内置默认 + 启动即开调试日志 |

### C. 配置文件

格式（参考 [`selinux_oracle_bypass.conf`](selinux_oracle_bypass.conf)）：

```ini
# '#' 开头是注释；空行忽略
# 每行一个关键字，子串匹配
kernelsu_next
sukisu
my_custom_root
```

读取限制：

- 单文件 ≤ 4 KB（`CONFIG_BUF_SZ`）
- 单关键字 ≤ 63 字节（`MAX_KW_LEN`）
- 总条目 ≤ 32（`MAX_KEYWORDS`，含默认）

> 这些上限是为了避免在 init 路径上占用过多静态空间。需要更大改宏重编即可。

### 自动兜底机制

无论 args 是什么形态、conf 文件读不读得到，**只要最终关键字表为空**，模块会自动装入内置默认列表，并打印警告日志：

```
[oracle_bypass] no keywords parsed, falling back to built-in defaults
```

这保证模块"加载成功 = 至少具备基础防护能力"，永远不会出现"加载成功但完全裸奔"的状态。

---

## 验证效果

### 1. 看 dmesg

加载完毕后：

```bash
dmesg | grep oracle_bypass
```

正常输出：

```
[oracle_bypass] loading config from /data/adb/kpm/selinux_oracle_bypass.conf
[oracle_bypass] installed @ ffffff80xxxxxxxx nr_keywords=9
[oracle_bypass]   [0] magisk
[oracle_bypass]   [1] kernelsu
[oracle_bypass]   [2] kernel_su
[oracle_bypass]   [3] ksud
[oracle_bypass]   [4] supolicy
[oracle_bypass]   [5] :su:
[oracle_bypass]   [6] :su\n
[oracle_bypass]   [7] my_custom_root    ← 来自 conf
[oracle_bypass]   [8] vendor_su         ← 来自 conf
```

### 2. 在普通 App 进程里跑探测脚本

```bash
adb shell
run-as com.example.youroapp                # 或任意 untrusted_app 进程
for L in \
    "u:r:magisk:s0" \
    "u:r:magisk_file:s0" \
    "u:r:su:s0" \
    "magisk" \
    "kernelsu" \
    "ksud" \
    "definitely_not_a_real_label_zzz"
do
    printf '%s' "$L" > /proc/self/attr/current 2>&1
    echo "  [$L] errno=$?"
done
```

**期望结果**：所有写入 errno **统一为 `1`**（shell 把 `-EINVAL` 转成 `1`），且与对照组 `definitely_not_a_real_label_zzz` **完全一致**——这正是 Oracle 在"干净系统"上观察到的行为。

> Java/Kotlin 侧：`FileOutputStream("/proc/self/attr/current").write(...)` 抛出的 `IOException` 的 `Os.errno()` 应当固定为 `OsConstants.EINVAL` (22)。

### 3. 看 SELinux audit 是否寂静

```bash
dmesg | grep -E "avc: |type=1400" | tail -20
```

成功拦截时，**不应该**出现关于上面那些字符串的拒绝日志（因为我们在 LSM 入口就短路，根本没让 SELinux 跑起来）。

---

## 故障排查：没生效怎么办

> v1.2.0 起内置 **debug 开关** 和 **调用计数器**，绝大多数"看起来没生效"都能在 5 分钟内定位。

### 第 0 步：日志去向

KPM 用 kernel `printk` 输出，**不会自动进入普通 `logcat` 主缓冲**。三个查看入口任选：

| 命令 | 适用 | 备注 |
|---|---|---|
| `dmesg \| grep oracle_bypass` | 所有 Android | 最稳，需 root |
| `dmesg -w \| grep oracle_bypass` | 所有 Android | 实时跟随；调试时单开一个窗口 |
| `logcat -b kernel \| grep oracle_bypass` | Android 9+ | logd 默认从 `/dev/kmsg` 读 kernel ring buffer 到这个独立 buffer |
| `cat /proc/kmsg` | 所有 Android | 阻塞读，需 root，会一次性消费 |

> `logcat`（默认 `main` buffer）**看不到** kernel printk。必须加 `-b kernel`。

### 第 1 步：确认模块装上了

```bash
adb shell su -c 'dmesg | grep oracle_bypass | tail -20'
```

应看到（缺任何一行就说明那一步失败）：

```
[oracle_bypass] installed @ ffffff80xxxxxxxx nr_keywords=N debug=0 event=... args=...
[oracle_bypass]   [0] magisk
[oracle_bypass]   [1] kernelsu
...
```

- 没有 `installed @ ...` → 模块没加载，去 APatch App 检查 KPM 状态
- `kallsyms_lookup_name` 找不到 `security_setprocattr` → `installed` 那行不会出现，但会有 `security_setprocattr not found`
- `hook_wrap4 failed: X` → KP inline-hook 失败，看 X 错误码（`HOOK_BAD_ADDRESS=4095` / `HOOK_DUPLICATED=4094` / `HOOK_NO_MEM=4093` / `HOOK_BAD_RELO=4092`）

### 第 2 步：打开 debug，看探测器实际写了什么

```bash
# 运行时开（推荐，免重启）：
adb shell su -c 'apd kpm control selinux_oracle_bypass "debug on"'

# 或加载时就开：args 里加 debug
#   APatch App → KPM args = "default,debug"
#   或 load.sh 里改 ARGS="default,debug,config=..."

# 跟随日志
adb shell su -c 'dmesg -w | grep oracle_bypass'
```

然后让探测器跑一次。`debug on` 之后每次 `security_setprocattr` 进入都会打：

```
[oracle_bypass] call name=current size=14 BLOCK value="u:r:magisk:s0"
[oracle_bypass] call name=current size=12 pass  value="u:r:zygote:s0"
[oracle_bypass] call name=exec    size=17 pass  value="u:r:untrusted_app"
```

- `BLOCK` = 命中黑名单，已短路返回 `-EINVAL`
- `pass` = 未命中，原样放行
- `value="..."` 里不可打印字节会被替换成 `.`

### 第 3 步：根据 debug 输出对症下药

| 现象 | 结论 | 处理 |
|---|---|---|
| `debug on` 之后探测器跑了，**完全没有 `call` 日志** | hook 没在被探测的进程上触发，可能：① 探测器没经过 setprocattr 路径；② 内核版本对应不上 hook 签名 | 用 `apd kpm control selinux_oracle_bypass stats` 看 `calls` 是不是 0；如果是 0，先尝试自己 `echo magisk > /proc/self/attr/current` 看 `calls` 是否增长 |
| 有 `call` 日志但全是 `pass`，能看到探测器写的字符串 | 字符串不在黑名单里 | 复制 `value="..."` 里的实际内容，加到 `selinux_oracle_bypass.conf` 后 reload |
| 有 `BLOCK` 日志但探测器仍然报"检测到 Root" | 探测器**不是只用** SELinux Oracle 这一条；或者它在比对错误码以外的额外信号 | 不属于本模块范围，需要看探测器其它检测面 |

### 第 4 步：查看累计统计

```bash
adb shell su -c 'apd kpm control selinux_oracle_bypass stats'
adb shell su -c 'dmesg | grep "oracle_bypass.*stats" | tail -1'
```

输出：

```
[oracle_bypass] stats calls=12345 blocks=37 debug=1 nr_keywords=9
```

- `calls` 持续增长 = hook 工作正常
- `blocks` 增长 = 确实在拦截
- 长时间 `calls=0` = hook 没触发，回到第 3 步

### 第 5 步：debug 用完关掉（避免日志风暴）

```bash
adb shell su -c 'apd kpm control selinux_oracle_bypass "debug off"'
```

> debug 模式下每个 setprocattr 调用都会打日志，普通使用会很吵。生产环境保持 off。

---

## 从源码构建

### 依赖

- KernelPatch 源码：`git clone https://github.com/bmax121/KernelPatch.git`
- 工具链二选一：
  - Arm GNU bare-metal toolchain（`aarch64-none-elf-`，KernelPatch 上游默认）
  - Android NDK r26d / r27d（推荐 r27d）

### 方式 A：bare-metal toolchain

```bash
export TARGET_COMPILE=aarch64-none-elf-
export KP_DIR=/path/to/KernelPatch
make
```

### 方式 B：Android NDK

```bash
export ANDROID_NDK=/path/to/android-ndk-r27d
export KP_DIR=/path/to/KernelPatch
make USE_NDK=1 -j"$(nproc)"
```

产物：`selinux_oracle_bypass.kpm`（ARM64 relocatable ELF）。

### CI 自动构建

每次 push tag `v*` 会触发 [`.github/workflows/build.yml`](.github/workflows/build.yml) 自动产出 release，包含：

- `selinux_oracle_bypass.kpm`
- `selinux_oracle_bypass.conf`
- `load.sh`
- `SHA256SUMS`

---

## 运行时管理

### 查看当前生效的关键字列表

```bash
apd kpm control selinux_oracle_bypass list
dmesg | grep oracle_bypass | tail -20
```

> CTL0 接口不回写 user buffer，只往 dmesg 打印（避免依赖跨内核版本的 `copy_to_user` 兼容性），所以需要配合 `dmesg` 一起看。

### 修改关键字 → 编辑 conf → reload

```bash
# 1) 编辑配置
adb push selinux_oracle_bypass.conf /data/adb/kpm/

# 2) 重新加载
adb shell su -c sh /data/adb/kpm/load.sh
```

或重启设备（如果是 APatch 永久安装模式）。

### 卸载

```bash
apd kpm unload selinux_oracle_bypass
```

---

## 代码结构

```
apatch-selinux-oracle/
├── selinux_oracle_bypass.c     # 模块主体（~340 行）
├── selinux_oracle_bypass.conf  # 示例配置
├── Makefile                    # KP bare-metal + NDK 双工具链
├── load.sh                     # 设备端加载脚本
├── .github/workflows/build.yml # CI：编译 + 自动 release
└── README.md                   # 本文件
```

`selinux_oracle_bypass.c` 内部分区：

| 区段 | 行数 | 职责 |
|---|---|---|
| Include 与 KPM 元信息 | 1-60 | 注释说明 include 顺序的硬约束 |
| 字符串小工具 | 72-99 | 不依赖 libc，避免链接外部符号 |
| 关键字表管理 | 101-129 | `kw_add` / `kw_already_have` / `kw_add_defaults` |
| 配置文件读取 | 130-195 | 通过 `kallsyms_lookup_name` 找 `filp_open` / `kernel_read` |
| args 解析与兜底 | 196-249 | 关键的"空表自动补默认"逻辑在这里 |
| Hook 回调 | 261-282 | `before_setprocattr`，整个模块的热路径 |
| 模块生命周期 | 284-341 | `KPM_INIT` / `KPM_CTL0` / `KPM_EXIT` |

---

## 安全考量与已知限制

### ✅ 设计上保证的

- **零误伤合法 LSM 流量**：未命中关键字的写入 100% 走原路径，行为字节级等价于未加载本模块。
- **不会 Kernel Panic**：所有指针访问都做了 NULL 检查；size 上限固定；不调用任何可能阻塞的 API。
- **不依赖 KP 自动导出符号**：`filp_open` / `kernel_read` 在运行时通过 `kallsyms_lookup_name` 解析，跨 KP 版本稳定。
- **可观察性**：所有路径都打 `pr_info` / `pr_warn` / `pr_err`，故障可追溯。

### ⚠️ 已知限制 / 注意事项

1. **仅覆盖写路径**：探测器若改用 `getprocattr` 之类的读路径做 Oracle（实际很少见，因为 SELinux 读返回的是当前进程自己的 label，没有信息泄漏面），本模块不会拦截。
2. **关键字静态匹配**：纯子串匹配，不支持正则。如果探测器使用**变形 label**（例如随机大小写、unicode 等价字符），可能漏过——不过 SELinux 解析器本身对大小写敏感，所以这种"变形"探测器自己就会失败，反而帮我们挡住了。
3. **conf 文件路径必须在 init 阶段就可读**：早期 init 时 `/data` 可能未挂载，建议 conf 放在 `/data/adb/kpm/`，并让 APatch loader 在 `/data` ready 之后再加载本模块（默认行为）。如果使用 Embed 模式（编译进 KP），需要把 conf 内容直接以字面量形式写到 args 里，或接受模块自动降级为内置默认。
4. **跨内核版本签名变化**：4.20+ 的 `security_setprocattr` 是 3 参数，本模块当前用 `hook_wrap4`，到那种内核上需要改成 `hook_wrap3` 并相应调整 `before_setprocattr` 的取参方式。
5. **不防"暴力字典"探测器**：如果某个探测器把"业内所有 Root 私有 type"都扫一遍，理论上你需要把这些字符串都加到 conf 里。但实际工程上覆盖 `magisk`/`kernelsu`/`ksu`/`ksud`/`supolicy`/`:su:` 这 6 个已经能挡住目前已知的全部公开实现。

---

## FAQ

**Q1：和 Magisk / KernelSU 的 SELinux 隐藏方案有什么区别？**
A：常见 Root 方案是在策略层"把 magisk 域隐藏 / 重命名"，但 type 的存在本身就是侧信道。本模块走的是**LSM 层短路**，在内核还没碰到 SELinux 策略时就拒绝，对探测器而言**底层就是干净的**。

**Q2：会不会影响系统正常的 SELinux 切换（比如 `seapp_contexts` 重载）？**
A：不会。系统正常切换 label 的字符串（`u:r:untrusted_app:s0` 之类）不在黑名单里，会原样放行。

**Q3：我用的内核是 5.10 / 5.15，能直接跑吗？**
A：模块本身能加载，但 hook 签名可能不匹配导致取参数错误。改 `hook_wrap4` → `hook_wrap3`、把 `args->arg1` / `arg2` / `arg3` 重新对齐到新签名即可，约 5 行改动。需要可以提 issue。

**Q4：为什么不用 `tracepoint` 或 `kprobe`？**
A：`tracepoint` 不能修改返回值；`kprobe` 改返回值要走 `kretprobe`，且**无法跳过原函数**——但本模块的核心需求就是"不让原函数运行"，所以只能用 KP 的 inline hook。

**Q5：能不能动态加 / 删关键字而不重启模块？**
A：目前只读，`KPM_CTL0` 仅暴露 `list` 命令。动态修改需要 RCU 或 seqlock 来保护读写并发，已在 roadmap 里，需要可以提 issue。

---

## 许可证

GPL-2.0-or-later，与 Linux 内核保持一致。详见源码 SPDX header。

## 致谢

- [bmax121/KernelPatch](https://github.com/bmax121/KernelPatch) — 提供整套 KPM 框架与 inline-hook 基建
- [bmax121/APatch](https://github.com/bmax121/APatch) — 提供用户态加载器和管理 App
