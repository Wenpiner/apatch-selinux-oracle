/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * selinux_oracle_bypass.c — APatch / KernelPatch Module (KPM)
 *
 * 用途：阻断 Root 检测工具基于 SELinux 侧信道的盲探。
 *   - Hook 点优先级（自 v1.7.0 起四档）：
 *       1) selinux_setprocattr      —— kallsyms 查 SELinux LSM 叶子回调；经函数
 *          指针调用无法内联，内核态缓冲区，代价最低。
 *       2a) proc_pid_attr_write     —— kallsyms 查该 VFS write 回调符号。
 *       2b) proc_pid_attr_write     —— **不依赖 kallsyms**：filp_open
 *          "/proc/self/attr/current" 拿到 struct file*，读 f_op->write，即为
 *          proc_pid_attr_write 真实入口地址。MIUI / Xiaomi 4.14 等 vendor 内核
 *          kallsyms 表不含 static 函数符号时，**这是唯一可用的解析路径**。
 *          代价：buf 是 __user 指针，需 copy_from_user。
 *       3) security_setprocattr     —— LSM 顶层入口，最不可靠（4.14 vendor 构建
 *          常把它内联到 proc_pid_attr_write，挂上去等于没挂）。仅在前面全部失败
 *          时尝试。
 *   - 命中黑名单 → skip_origin=1 + ret=-EINVAL，伪装为"内核不认识该域"
 *
 * 配置方式（KPM 加载 args，逗号或分号分隔）：
 *   ""                                  -> 仅内置默认（等价于 "default"）
 *   "default,foo,bar"                   -> 默认 + foo + bar
 *   "magisk,ksu"                        -> 仅这两个（不含默认）
 *   "config=/data/adb/kpm/xxx.conf"     -> 从文件读取（Install 模式可用）
 *   "default,config=/data/adb/kpm/xxx.conf"
 *   "default,debug"                     -> 显式打开 pass 日志（v1.7.1 起默认关）
 *   "default,quiet"                     -> 关闭 pass 日志，仅保留 BLOCK 输出
 *
 * 日志策略：
 *   - 命中拦截（BLOCK）：始终打一行，含 PID/TGID/comm/name/value
 *   - 未命中（pass）   ：debug 模式下打，用于排查"该拦的没拦"
 *   debug 默认 *关闭*（v1.7.1 起）。args 里写 "debug"/"verbose" 可开启；
 *   运行时也可 `apd kpm control selinux_oracle_bypass "debug on"` 切换。
 *
 * 调试：
 *   apd kpm control selinux_oracle_bypass stats        查看调用/拦截计数
 *   apd kpm control selinux_oracle_bypass "debug on"   运行时开 pass 日志
 *   apd kpm control selinux_oracle_bypass "debug off"  关闭
 *   日志去向：dmesg、或 Android 9+ 的 `logcat -b kernel`
 *
 * 失败兜底：无论 args 长什么样，只要解析完毕关键字表仍为空（例如配置文件
 * 路径错误、文件全是注释、Embed 阶段 /data 未挂载等），自动装入内置默认列表，
 * 保证模块加载成功后至少具备基础防护能力。
 *
 * 配置文件格式（纯文本）：
 *   - 每行一个关键字（子串匹配，ASCII 大小写不敏感）
 *   - '#' 起始行为注释；空行忽略；行首尾空白自动 trim
 *   - 因此 "magisk" 一个关键字即可覆盖 "Magisk"、"MAGISK"、"Magisk file" 等变体
 *
 * 查询当前生效列表：
 *   apd kpm control selinux_oracle_bypass list   (然后 dmesg 看输出)
 *
 * 修改配置：编辑 conf -> apd kpm unload + apd kpm load（见 load.sh）
 */

/*
 * 注意 include 顺序：
 *   1. <compiler.h> 必须排在 <kpmodule.h> 之前。kpmodule.h 内 mod_ctl0call_t
 *      的 typedef 用到 __user 宏，未定义会导致原型被错误解析为 2 参版本，
 *      最终 KPM_CTL0 报"incompatible function pointer types"。
 *   2. 不要直接 #include <linux/types.h>、<linux/fcntl.h>——KernelPatch
 *      头树里没有它们，编译器会回落到 Android NDK sysroot，与 KP 的
 *      <ktypes.h> 在 __s64/__u64/__kernel_fd_set 上发生 typedef 重定义。
 *      所需类型/常量经由 KP 自带的 <linux/fs.h> 传递引入即可。
 */
#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kallsyms.h>
#include <taskext.h>
#include <linux/printk.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/errno.h>

KPM_NAME("selinux_oracle_bypass");
KPM_VERSION("1.7.1");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Wenpiner");
KPM_DESCRIPTION("Block SELinux side-channel probes; keywords configurable");

#define SCAN_LIMIT      96
#define MAX_KEYWORDS    32
#define MAX_KW_LEN      63
#define CONFIG_BUF_SZ   4096
#define CONFIG_PATH_MAX 256

static void *g_target;
static const char *g_target_sym;          /* 记录实际命中的符号名，便于日志/卸载 */
/* before 回调有两种实现：
 *   - before_setprocattr             用于 security_setprocattr / selinux_setprocattr
 *     （buf 是内核地址，直接读）
 *   - before_proc_pid_attr_write     用于 proc_pid_attr_write
 *     （buf 是 __user 指针，需要 copy_from_user）
 * g_cb 记录实际挂上的那个，unhook 时一致即可。 */
static void (*g_cb)(hook_fargs4_t *, void *);

/* arm64 4.14 用户拷贝：__arch_copy_from_user 是导出符号；_copy_from_user 是
 * static inline 拿不到。这里两个都查一遍以兼容轻度魔改的内核。 */
static unsigned long (*p_copy_from_user)(void *to, const void __user *from,
                                         unsigned long n);
static char  g_kws[MAX_KEYWORDS][MAX_KW_LEN + 1];
static int   g_nr_kws;
static char  g_config_buf[CONFIG_BUF_SZ];   /* 仅 init 期使用的一次性缓冲 */

/* 调试/诊断
 *   g_debug : 控制 *未命中* 路径是否也打日志。命中（BLOCK）路径总是会打，
 *             因为发生频率极低且对排查最有价值。
 *             *默认 0（关）*（v1.7.1 起）——生产环境不污染 dmesg；
 *             args 含 "debug"/"verbose" 或运行时
 *             `apd kpm control selinux_oracle_bypass "debug on"` 可以开启。
 *   g_calls : security_setprocattr 进入次数（含未命中）。
 *   g_blocks: 实际被短路（返回 -EINVAL）的次数。
 * 这三个值通过 CTL0 "stats" 也能查询。
 */
static int           g_debug = 0;
static unsigned long g_calls;
static unsigned long g_blocks;

/* 进程名解析：__get_task_comm 在 4.14/Android 内核普遍可解析，
 * 解析失败时 comm 字段降级为 "?"，PID/TGID 不受影响。 */
#define COMM_LEN 16
static char *(*p_get_task_comm)(char *to, unsigned long len, void *tsk);

static const char *const g_defaults[] = {
    "magisk", "kernelsu", "kernel_su", "ksud", "supolicy",
    ":su:", ":su\n",
};
#define NR_DEFAULTS (sizeof(g_defaults) / sizeof(g_defaults[0]))

/* ===================== 字符串小工具（不依赖外部链接） ===================== */

static inline char kp_tolower(char c)
{
    return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
}

/* ASCII 大小写不敏感子串匹配。
 * 探测器（如 Duck Detector）会用大写首字母的伪 label（"Magisk"、"Magisk file"）
 * 来探刺 /proc/self/attr/current —— 真实的 SELinux type 全是小写，所以这种
 * 变形不会与合法策略冲突，case-insensitive 匹配是严格更宽的安全超集。 */
static int kp_memcontains(const char *hay, size_t hlen, const char *needle)
{
    size_t nlen = 0, i, j;
    while (needle[nlen]) nlen++;
    if (nlen == 0 || nlen > hlen) return 0;
    for (i = 0; i + nlen <= hlen; i++) {
        for (j = 0; j < nlen && kp_tolower(hay[i + j]) == kp_tolower(needle[j]); j++) ;
        if (j == nlen) return 1;
    }
    return 0;
}

static size_t kp_strlen(const char *s)
{
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

static int kp_strneq(const char *a, const char *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        if (a[i] != b[i]) return 0;
    return 1;
}

/* ===================== 关键字表管理 ===================== */

static int kw_already_have(const char *s, size_t n)
{
    int i;
    for (i = 0; i < g_nr_kws; i++)
        if (kp_strlen(g_kws[i]) == n && kp_strneq(g_kws[i], s, n))
            return 1;
    return 0;
}

static int kw_add(const char *s, size_t n)
{
    int i;
    if (n == 0 || n > MAX_KW_LEN) return -EINVAL;
    if (g_nr_kws >= MAX_KEYWORDS)  return -ENOSPC;
    if (kw_already_have(s, n))     return 0;
    for (i = 0; i < (int)n; i++) g_kws[g_nr_kws][i] = s[i];
    g_kws[g_nr_kws][n] = '\0';
    g_nr_kws++;
    return 0;
}

static void kw_add_defaults(void)
{
    size_t i;
    for (i = 0; i < NR_DEFAULTS; i++)
        kw_add(g_defaults[i], kp_strlen(g_defaults[i]));
}

/* ===================== 配置文件读取 =====================
 *
 * 不依赖 KP 自动链接：filp_open / filp_close / kernel_read 在运行时
 * 通过 kallsyms_lookup_name 解析（4.14 kallsyms 表中均存在）。
 *
 * 注意：Embed 模式下 KPM 在 pre-kernel-init 加载，此时 /data 未挂载，
 * 文件打开必然失败 —— 此函数返回错误码，由调用者降级为 args/默认配置。
 */
static int read_config_file(const char *path)
{
    struct file *(*p_filp_open)(const char *, int, umode_t);
    int (*p_filp_close)(struct file *, void *);
    ssize_t (*p_kernel_read)(struct file *, void *, size_t, loff_t *);
    struct file *fp;
    ssize_t n, i, start, end;
    loff_t pos = 0;

    p_filp_open   = (void *)kallsyms_lookup_name("filp_open");
    p_filp_close  = (void *)kallsyms_lookup_name("filp_close");
    p_kernel_read = (void *)kallsyms_lookup_name("kernel_read");
    if (!p_filp_open || !p_filp_close || !p_kernel_read) {
        pr_err("[oracle_bypass] vfs syms unresolved; skip %s\n", path);
        return -ENOSYS;
    }

    fp = p_filp_open(path, O_RDONLY, 0);
    if (IS_ERR_OR_NULL(fp)) {
        long e = IS_ERR(fp) ? PTR_ERR(fp) : -ENOENT;
        pr_err("[oracle_bypass] open(%s) failed: %ld\n", path, e);
        return (int)e;
    }

    n = p_kernel_read(fp, g_config_buf, CONFIG_BUF_SZ - 1, &pos);
    p_filp_close(fp, NULL);
    if (n < 0) {
        pr_err("[oracle_bypass] read(%s) failed: %zd\n", path, n);
        return (int)n;
    }
    g_config_buf[n] = '\0';

    /* 按行解析：trim 首尾空白，跳过 '#' 注释和空行 */
    i = 0;
    while (i < n) {
        while (i < n && (g_config_buf[i] == ' ' || g_config_buf[i] == '\t'))
            i++;
        start = i;
        while (i < n && g_config_buf[i] != '\n' && g_config_buf[i] != '\r')
            i++;
        end = i;
        while (end > start &&
               (g_config_buf[end - 1] == ' ' || g_config_buf[end - 1] == '\t'))
            end--;
        if (end > start && g_config_buf[start] != '#') {
            int rc = kw_add(&g_config_buf[start], end - start);
            if (rc == -ENOSPC) {
                pr_warn("[oracle_bypass] keyword table full, drop rest\n");
                break;
            }
        }
        while (i < n && (g_config_buf[i] == '\n' || g_config_buf[i] == '\r'))
            i++;
    }
    return 0;
}

/* ===================== proc_pid_attr_write 真实地址解析 =====================
 *
 * 背景：部分 vendor 内核（Xiaomi MIUI 4.14 等）的 kallsyms 表里不含 static
 * 函数符号——`selinux_setprocattr`、`proc_pid_attr_write` 都查不到，能查到
 * 的 `security_setprocattr` 又被编译器内联了。结果三个 kallsyms 档位全部
 * 失效，模块加载成功但 hook 永远不触发。
 *
 * 解决思路：`proc_pid_attr_write` 的地址本来就被存在 `proc_pid_attr_operations
 * .write` 函数指针里，VFS 通过它调用本函数。只要在内核态打开 /proc/<pid>/
 * attr/current 拿到 struct file*，读 f_op->write，就是该函数的入口地址，
 * **完全绕过 kallsyms 表**。
 *
 * 路径选择（v1.7.0 实测修正）：
 *   - 最初用固定 "/proc/1/attr/current"，但在 hidepid=2 的 procfs 挂载下，
 *     内核线程访问 init(pid 1) 目录被判定无权 ptrace，**直接返回 ENOENT(-2)**
 *     伪装成不存在（这是 hidepid=2 的语义，hidepid=1 才返回 EACCES）。
 *     Redmi 21091116AC / MIUI 4.14 实测即此现象。
 *   - 改为优先 "/proc/self/attr/current"：/proc/self 永远指向访问者自身，
 *     hidepid 不会隐藏自己；内核线程也有自己的 attr/current 入口，必然可开。
 *     再加 "/proc/thread-self/..." 与 "/proc/1/..." 双兜底，逐个尝试。
 *   - filp_open 成功后只读 f_op，不做 read/write，无副作用。
 *   - 该函数应只在 init 阶段调用一次，不放热路径。
 *
 * struct 布局说明：KernelPatch 头树里 `<linux/fs.h>` 仅前向声明 `struct file`，
 * 直接 `fp->f_op` 会编译报 "incomplete type"。为此定义 shadow 视图，按 ARM64
 * Linux 4.14 的已知布局以纯偏移方式解引用：
 *   struct file 头部（共 40 字节）：
 *     +0   union { llist_node; rcu_head } f_u   = 16B (rcu_head 是较大成员)
 *     +16  struct path f_path                   = 16B（vfsmount* + dentry*）
 *     +32  struct inode *f_inode                = 8B
 *     +40  const struct file_operations *f_op   <— 目标字段
 *   struct file_operations 头部：
 *     +0   struct module *owner                 = 8B
 *     +8   loff_t (*llseek)(...)                = 8B
 *     +16  ssize_t (*read)(...)                 = 8B
 *     +24  ssize_t (*write)(...)                <— 目标字段
 * 这套偏移在 4.14 主线 + Android common + MIUI vendor 上一致（未启用
 * CONFIG_PREEMPT_RT；ARM64 Android 4.14 默认未开）。
 */

/* shadow 视图：与 KP 头中前向声明的 struct file 解耦，纯按偏移读字段。 */
struct oracle_fops_view {
    void *owner;       /* +0  struct module *                     */
    void *llseek;      /* +8                                       */
    void *read;        /* +16                                      */
    void *write;       /* +24  ssize_t (*write)(file*, __user*, size_t, loff_t*) */
};
struct oracle_file_view {
    unsigned char _pad0[40];                         /* f_u + f_path + f_inode  */
    const struct oracle_fops_view *f_op;             /* +40                     */
};

static void *resolve_proc_pid_attr_write_via_fop(void)
{
    /* 候选路径：self 优先（hidepid 不隐藏自身），thread-self 次之，
     * 固定 pid 1 最后（hidepid=2 下会 ENOENT，仅作非 hidepid 内核的兜底）。 */
    static const char *const cand[] = {
        "/proc/self/attr/current",
        "/proc/thread-self/attr/current",
        "/proc/1/attr/current",
    };
    struct file *(*p_filp_open)(const char *, int, umode_t);
    int (*p_filp_close)(struct file *, void *);
    struct file *fp;
    const struct oracle_file_view *fv;
    void *addr = 0;
    size_t i;

    p_filp_open  = (void *)kallsyms_lookup_name("filp_open");
    p_filp_close = (void *)kallsyms_lookup_name("filp_close");
    if (!p_filp_open || !p_filp_close) {
        pr_warn("[oracle_bypass] filp_open/close unresolved; f_op fallback disabled\n");
        return 0;
    }

    for (i = 0; i < sizeof(cand) / sizeof(cand[0]); i++) {
        fp = p_filp_open(cand[i], O_RDONLY, 0);
        if (IS_ERR_OR_NULL(fp)) {
            long e = IS_ERR(fp) ? PTR_ERR(fp) : -ENOENT;
            pr_warn("[oracle_bypass] open %s for f_op deref failed: %ld\n", cand[i], e);
            continue;
        }

        fv = (const struct oracle_file_view *)fp;
        if (fv->f_op) {
            addr = fv->f_op->write;
            if (!addr)
                pr_warn("[oracle_bypass] %s f_op->write is NULL (write_iter only?)\n", cand[i]);
        } else {
            pr_warn("[oracle_bypass] %s fp->f_op is NULL, unexpected\n", cand[i]);
        }
        p_filp_close(fp, NULL);

        if (addr) {
            pr_info("[oracle_bypass] resolved proc_pid_attr_write via %s f_op deref\n", cand[i]);
            return addr;
        }
    }

    return 0;
}

/* ===================== args 解析（逗号/分号分隔） ===================== */

static void parse_args(const char *args)
{
    size_t i = 0, len, start, end;
    char path[CONFIG_PATH_MAX];

    if (!args) args = "";
    len = kp_strlen(args);

    while (i < len) {
        while (i < len && (args[i] == ',' || args[i] == ';' ||
                           args[i] == ' ' || args[i] == '\t')) i++;
        start = i;
        while (i < len && args[i] != ',' && args[i] != ';') i++;
        end = i;
        while (end > start && (args[end - 1] == ' ' || args[end - 1] == '\t'))
            end--;
        if (end == start) continue;

        /* token = "default" / "defaults" */
        if (((end - start) == 7 && kp_strneq(&args[start], "default",  7)) ||
            ((end - start) == 8 && kp_strneq(&args[start], "defaults", 8))) {
            kw_add_defaults();
            continue;
        }
        /* token = "debug" / "verbose"：打开 pass 日志（v1.7.1 起默认关闭）。 */
        if (((end - start) == 5 && kp_strneq(&args[start], "debug",   5)) ||
            ((end - start) == 7 && kp_strneq(&args[start], "verbose", 7))) {
            g_debug = 1;
            continue;
        }
        /* token = "quiet" / "silent"：明确关闭 pass 日志（v1.7.1 起已是默认行为，
         * 此 token 保留供 args 明示或与旧版配置兼容。） */
        if (((end - start) == 5 && kp_strneq(&args[start], "quiet",  5)) ||
            ((end - start) == 6 && kp_strneq(&args[start], "silent", 6))) {
            g_debug = 0;
            continue;
        }
        /* token = "config=/some/path"
         * 读失败时不要把整个加载流程拖死，只打日志；
         * 最终是否补默认由本函数末尾的兜底逻辑决定。 */
        if ((end - start) > 7 && kp_strneq(&args[start], "config=", 7)) {
            size_t plen = (end - start) - 7;
            size_t k;
            int rc;
            if (plen >= CONFIG_PATH_MAX) plen = CONFIG_PATH_MAX - 1;
            for (k = 0; k < plen; k++) path[k] = args[start + 7 + k];
            path[plen] = '\0';
            pr_info("[oracle_bypass] loading config from %s\n", path);
            rc = read_config_file(path);
            if (rc < 0)
                pr_warn("[oracle_bypass] config %s unreadable (%d)\n", path, rc);
            continue;
        }
        /* 普通关键字字面量 */
        kw_add(&args[start], end - start);
    }

    /* 兜底：无论 args 是什么形态，只要最终关键字表为空（包括 args 为空、
     * config 文件读不到且全是注释、用户拼写错误等情况），统统补内置默认，
     * 避免 KPM 加载成功却毫无防护效果。 */
    if (g_nr_kws == 0) {
        pr_warn("[oracle_bypass] no keywords parsed, falling back to built-in defaults\n");
        kw_add_defaults();
    }
}

/* ===================== 命中检测 ===================== */

static int is_blacklisted(const char *buf, size_t len)
{
    int i;
    for (i = 0; i < g_nr_kws; i++)
        if (kp_memcontains(buf, len, g_kws[i])) return 1;
    return 0;
}

/* ===================== Hook 回调 =====================
 *
 * 只挂 before：命中即 skip_origin + 设 ret；未命中则原样放行。
 * 不挂 after，链路最短、最快。
 *
 * value 由 proc_pid_attr_write 调 memdup_user 拷到内核，已是内核缓冲区，
 * 因此直接按字节读取即可，不得再 copy_from_user。
 */
static void before_setprocattr(hook_fargs4_t *args, void *udata)
{
    const char *name  = (const char *)args->arg1;
    const char *value = (const char *)args->arg2;
    size_t size       = (size_t)args->arg3;
    int hit;

    if (!name || !value || size == 0) return;
    if (size > SCAN_LIMIT) size = SCAN_LIMIT;

    g_calls++;
    hit = is_blacklisted(value, size);

    /* 命中（BLOCK）始终打日志；未命中（pass）仅在 debug 模式下打。
     * 这样默认情况下 dmesg 不会被淹没，又能让人立刻看见所有拦截事件；
     * 排查"该拦的没拦"时打开 debug，能看到 app 实际写了什么字符串、
     * 来自哪个 PID，从而决定是否扩充黑名单。
     * 把 value 中的不可打印字节替换为 '.'，避免污染 dmesg 文本格式。 */
    if (hit || g_debug) {
        char dbg[SCAN_LIMIT + 1];
        char comm[COMM_LEN] = "?";
        struct task_ext *te = get_current_task_ext();
        pid_t pid  = task_ext_valid(te) ? te->pid  : -1;
        pid_t tgid = task_ext_valid(te) ? te->tgid : -1;
        size_t j;

        if (p_get_task_comm)
            p_get_task_comm(comm, sizeof(comm), (void *)current);

        for (j = 0; j < size; j++) {
            char c = value[j];
            dbg[j] = (c >= 0x20 && c < 0x7f) ? c : '.';
        }
        dbg[size] = '\0';

        pr_info("[oracle_bypass] %s pid=%d tgid=%d comm=%s name=%s size=%zu value=\"%s\"\n",
                hit ? "BLOCK" : "pass ",
                pid, tgid, comm, name, size, dbg);
    }

    if (hit) {
        g_blocks++;
        args->skip_origin = 1;
        args->ret = -EINVAL;
    }
}

/* proc_pid_attr_write(struct file *file, const char __user *buf,
 *                     size_t count, loff_t *ppos)
 *
 * 用于绕过 "security_setprocattr 被 vendor 内核内联导致符号 hook 不触发" 的
 * 情况。VFS 通过 proc_pid_attr_operations.write 函数指针调用本函数，**编译器
 * 无法把函数指针指向的目标内联到调用方**。
 *
 * 与 before_setprocattr 的关键差异：
 *   1. buf 是 __user 指针，必须经 copy_from_user 拷到内核栈，不能直接读，
 *      否则触发 page fault 甚至 oops。
 *   2. 没有"name"参数（attr 名隐藏在 file->f_path.dentry->d_name 里）；为了
 *      避免依赖 struct file/path/dentry/qstr 的具体偏移（不同 vendor 内核
 *      可能有差异），日志里 name 直接写死 "procattr"，已足够定位事件来源。
 *   3. 设 ret=-EINVAL 后 proc_pid_attr_write 自身的 memdup_user / find_task 等
 *      序言通通跳过，对 userspace 与 v1.4.0 / v1.5.0 拦截行为字节级等价。
 */
static void before_proc_pid_attr_write(hook_fargs4_t *args, void *udata)
{
    const void __user *ubuf = (const void __user *)args->arg1;
    size_t count            = (size_t)args->arg2;
    char kbuf[SCAN_LIMIT];
    size_t to_copy;
    int hit;

    if (!ubuf || count == 0 || !p_copy_from_user) return;

    to_copy = count > SCAN_LIMIT ? SCAN_LIMIT : count;
    if (p_copy_from_user(kbuf, ubuf, to_copy)) return;

    g_calls++;
    hit = is_blacklisted(kbuf, to_copy);

    if (hit || g_debug) {
        char dbg[SCAN_LIMIT + 1];
        char comm[COMM_LEN] = "?";
        struct task_ext *te = get_current_task_ext();
        pid_t pid  = task_ext_valid(te) ? te->pid  : -1;
        pid_t tgid = task_ext_valid(te) ? te->tgid : -1;
        size_t j;

        if (p_get_task_comm)
            p_get_task_comm(comm, sizeof(comm), (void *)current);

        for (j = 0; j < to_copy; j++) {
            char c = kbuf[j];
            dbg[j] = (c >= 0x20 && c < 0x7f) ? c : '.';
        }
        dbg[to_copy] = '\0';

        pr_info("[oracle_bypass] %s pid=%d tgid=%d comm=%s name=procattr size=%zu value=\"%s\"\n",
                hit ? "BLOCK" : "pass ",
                pid, tgid, comm, to_copy, dbg);
    }

    if (hit) {
        g_blocks++;
        args->skip_origin = 1;
        args->ret = -EINVAL;
    }
}

/* ===================== 模块生命周期 ===================== */

static long selinux_oracle_init(const char *args, const char *event,
                                void *__user reserved)
{
    hook_err_t err;
    int i;

    g_nr_kws = 0;
    parse_args(args);

    /* 选择 hook 符号（v1.7.0 四档优先级）：
     *   1.  selinux_setprocattr   —— kallsyms 查 SELinux LSM 叶子回调；经函数
     *       指针调用无法内联，value 已是内核缓冲区，开销最小，故为首选。
     *   2a. proc_pid_attr_write   —— kallsyms 查 VFS write 回调符号。
     *   2b. proc_pid_attr_write   —— 同一个函数，但通过 filp_open + f_op
     *       函数指针解引用拿到地址，**完全绕过 kallsyms**。专门解决 Xiaomi
     *       MIUI 4.14 等 vendor 内核 kallsyms 表不含 static 函数符号的情况。
     *   3.  security_setprocattr  —— LSM 顶层入口，最不可靠（被内联时挂上去
     *       等于没挂）。仅在前三档全部失败时才尝试。
     * before_setprocattr 与 before_proc_pid_attr_write 都是 4 参签名，但语义
     * 不同；g_cb 记录实际挂上的那个，unhook 时配对使用。 */
    g_target = (void *)kallsyms_lookup_name("selinux_setprocattr");
    if (g_target) {
        g_target_sym = "selinux_setprocattr";
        g_cb = before_setprocattr;
    } else {
        g_target = (void *)kallsyms_lookup_name("proc_pid_attr_write");
        if (g_target) {
            g_target_sym = "proc_pid_attr_write";
            g_cb = before_proc_pid_attr_write;
            pr_warn("[oracle_bypass] selinux_setprocattr missing, using VFS layer proc_pid_attr_write (kallsyms)\n");
        } else {
            /* 档位 2b：kallsyms 查不到时通过 /proc/self/attr/current 的 f_op
             * 函数指针解出 proc_pid_attr_write 真实地址（详见解析函数注释，
             * 已避开 hidepid=2 的 /proc/1 ENOENT 问题）。MIUI 4.14 走这里。 */
            g_target = resolve_proc_pid_attr_write_via_fop();
            if (g_target) {
                g_target_sym = "proc_pid_attr_write(fop)";
                g_cb = before_proc_pid_attr_write;
                pr_warn("[oracle_bypass] selinux_setprocattr & proc_pid_attr_write missing in kallsyms, using f_op deref result @ %px\n", g_target);
            } else {
                g_target = (void *)kallsyms_lookup_name("security_setprocattr");
                if (g_target) {
                    g_target_sym = "security_setprocattr";
                    g_cb = before_setprocattr;
                    pr_warn("[oracle_bypass] all VFS resolution paths failed, falling back to security_setprocattr (may be inlined and ineffective)\n");
                } else {
                    pr_err("[oracle_bypass] no hookable target found (kallsyms+fop all exhausted)\n");
                    return -1;
                }
            }
        }
    }

    /* 进程名解析是 nice-to-have；解析不到也不影响 hook 主功能。 */
    p_get_task_comm = (void *)kallsyms_lookup_name("__get_task_comm");
    if (!p_get_task_comm)
        pr_warn("[oracle_bypass] __get_task_comm unresolved, comm will be '?'\n");

    /* 用户拷贝符号：仅在 hook proc_pid_attr_write 时需要。arm64 4.14 导出的是
     * __arch_copy_from_user；同时尝试 _copy_from_user 兼容个别魔改内核。 */
    if (g_cb == before_proc_pid_attr_write) {
        p_copy_from_user = (void *)kallsyms_lookup_name("__arch_copy_from_user");
        if (!p_copy_from_user)
            p_copy_from_user = (void *)kallsyms_lookup_name("_copy_from_user");
        if (!p_copy_from_user) {
            pr_err("[oracle_bypass] copy_from_user symbol unresolved, cannot hook proc_pid_attr_write\n");
            g_target = 0;
            g_target_sym = 0;
            g_cb = 0;
            return -3;
        }
    }

    err = hook_wrap4(g_target, g_cb, 0, 0);
    if (err != HOOK_NO_ERR) {
        pr_err("[oracle_bypass] hook_wrap4(%s) failed: %d\n", g_target_sym, err);
        g_target = 0;
        g_target_sym = 0;
        g_cb = 0;
        return -2;
    }

    pr_info("[oracle_bypass] installed sym=%s @ %px nr_keywords=%d debug=%d comm=%d event=%s args=%s\n",
            g_target_sym, g_target, g_nr_kws, g_debug, p_get_task_comm ? 1 : 0,
            event ? event : "", args ? args : "");
    for (i = 0; i < g_nr_kws; i++)
        pr_info("[oracle_bypass]   [%d] %s\n", i, g_kws[i]);
    return 0;
}

/* CTL0 命令（输出全部走 kernel log，可用 dmesg 或 logcat -b kernel 查看）：
 *   list           列出当前生效关键字
 *   stats          打印调用 / 拦截计数 + debug 开关状态
 *   debug on|off   运行时开 / 关 per-call 日志
 * 不回写 out_msg，避免依赖 compat_copy_to_user 的具体可用性。 */
static long selinux_oracle_control0(const char *args, char *__user out_msg, int outlen)
{
    const char *cmd = args ? args : "";
    int i;

    if (kp_strlen(cmd) >= 8 && kp_strneq(cmd, "debug on",  8)) {
        g_debug = 1;
        pr_info("[oracle_bypass] debug=1\n");
        return 0;
    }
    if (kp_strlen(cmd) >= 9 && kp_strneq(cmd, "debug off", 9)) {
        g_debug = 0;
        pr_info("[oracle_bypass] debug=0\n");
        return 0;
    }
    if (kp_strlen(cmd) == 5 && kp_strneq(cmd, "stats", 5)) {
        pr_info("[oracle_bypass] stats calls=%lu blocks=%lu debug=%d nr_keywords=%d\n",
                g_calls, g_blocks, g_debug, g_nr_kws);
        return 0;
    }

    /* 默认 / "list"：导出关键字列表 */
    pr_info("[oracle_bypass] ctl0 cmd=%s nr_keywords=%d calls=%lu blocks=%lu debug=%d\n",
            cmd[0] ? cmd : "(null)", g_nr_kws, g_calls, g_blocks, g_debug);
    for (i = 0; i < g_nr_kws; i++)
        pr_info("[oracle_bypass]   [%d] %s\n", i, g_kws[i]);
    return 0;
}

static long selinux_oracle_exit(void *__user reserved)
{
    if (g_target && g_cb) {
        hook_unwrap(g_target, g_cb, 0);
        g_target = 0;
        g_target_sym = 0;
        g_cb = 0;
    }
    pr_info("[oracle_bypass] uninstalled\n");
    return 0;
}

KPM_INIT(selinux_oracle_init);
KPM_CTL0(selinux_oracle_control0);
KPM_EXIT(selinux_oracle_exit);

