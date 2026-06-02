/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * selinux_oracle_bypass.c — APatch / KernelPatch Module (KPM)
 *
 * 用途：阻断 Root 检测工具基于 SELinux 侧信道的盲探。
 *   - Hook 点：security_setprocattr（4.14 LSM 顶层入口，4 参数签名）
 *   - 命中黑名单 → skip_origin=1 + ret=-EINVAL，伪装为"内核不认识该域"
 *
 * 配置方式（KPM 加载 args，逗号或分号分隔）：
 *   ""                                  -> 仅内置默认（等价于 "default"）
 *   "default,foo,bar"                   -> 默认 + foo + bar
 *   "magisk,ksu"                        -> 仅这两个（不含默认）
 *   "config=/data/adb/kpm/xxx.conf"     -> 从文件读取（Install 模式可用）
 *   "default,config=/data/adb/kpm/xxx.conf"
 *
 * 失败兜底：无论 args 长什么样，只要解析完毕关键字表仍为空（例如配置文件
 * 路径错误、文件全是注释、Embed 阶段 /data 未挂载等），自动装入内置默认列表，
 * 保证模块加载成功后至少具备基础防护能力。
 *
 * 配置文件格式（纯文本）：
 *   - 每行一个关键字（子串匹配）
 *   - '#' 起始行为注释；空行忽略；行首尾空白自动 trim
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
#include <linux/printk.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/errno.h>

KPM_NAME("selinux_oracle_bypass");
KPM_VERSION("1.1.1");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("anon");
KPM_DESCRIPTION("Block SELinux side-channel probes; keywords configurable");

#define SCAN_LIMIT      96
#define MAX_KEYWORDS    32
#define MAX_KW_LEN      63
#define CONFIG_BUF_SZ   4096
#define CONFIG_PATH_MAX 256

static void *g_target;
static char  g_kws[MAX_KEYWORDS][MAX_KW_LEN + 1];
static int   g_nr_kws;
static char  g_config_buf[CONFIG_BUF_SZ];   /* 仅 init 期使用的一次性缓冲 */

static const char *const g_defaults[] = {
    "magisk", "kernelsu", "kernel_su", "ksud", "supolicy",
    ":su:", ":su\n",
};
#define NR_DEFAULTS (sizeof(g_defaults) / sizeof(g_defaults[0]))

/* ===================== 字符串小工具（不依赖外部链接） ===================== */

static int kp_memcontains(const char *hay, size_t hlen, const char *needle)
{
    size_t nlen = 0, i, j;
    while (needle[nlen]) nlen++;
    if (nlen == 0 || nlen > hlen) return 0;
    for (i = 0; i + nlen <= hlen; i++) {
        for (j = 0; j < nlen && hay[i + j] == needle[j]; j++) ;
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

    if (!name || !value || size == 0) return;
    if (size > SCAN_LIMIT) size = SCAN_LIMIT;

    if (is_blacklisted(value, size)) {
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

    g_target = (void *)kallsyms_lookup_name("security_setprocattr");
    if (!g_target) {
        pr_err("[oracle_bypass] security_setprocattr not found\n");
        return -1;
    }

    err = hook_wrap4(g_target, before_setprocattr, 0, 0);
    if (err != HOOK_NO_ERR) {
        pr_err("[oracle_bypass] hook_wrap4 failed: %d\n", err);
        g_target = 0;
        return -2;
    }

    pr_info("[oracle_bypass] installed @ %px nr_keywords=%d event=%s args=%s\n",
            g_target, g_nr_kws, event ? event : "", args ? args : "");
    for (i = 0; i < g_nr_kws; i++)
        pr_info("[oracle_bypass]   [%d] %s\n", i, g_kws[i]);
    return 0;
}

/* CTL0：唯一命令是 "list"，把当前关键字列表打到 dmesg。
 * （不回写 out_msg，避免依赖 compat_copy_to_user 的具体可用性） */
static long selinux_oracle_control0(const char *args, char *__user out_msg, int outlen)
{
    int i;
    pr_info("[oracle_bypass] ctl0 cmd=%s nr_keywords=%d\n",
            args ? args : "(null)", g_nr_kws);
    for (i = 0; i < g_nr_kws; i++)
        pr_info("[oracle_bypass]   [%d] %s\n", i, g_kws[i]);
    return 0;
}

static long selinux_oracle_exit(void *__user reserved)
{
    if (g_target) {
        hook_unwrap(g_target, before_setprocattr, 0);
        g_target = 0;
    }
    pr_info("[oracle_bypass] uninstalled\n");
    return 0;
}

KPM_INIT(selinux_oracle_init);
KPM_CTL0(selinux_oracle_control0);
KPM_EXIT(selinux_oracle_exit);

