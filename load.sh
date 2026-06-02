#!/system/bin/sh
# load.sh — 加载 / 重载 selinux_oracle_bypass.kpm，使用配置文件 conf
#
# 使用：
#   su -c sh /data/adb/kpm/load.sh
#
# 行为：
#   - 若 conf 文件存在，则把 args 设置为 "default,config=$CONF"
#     -> KPM 会先加载默认黑名单，再从 conf 文件追加用户自定义关键字
#   - 若 conf 不存在，则 args 为 "default"，仅生效默认列表
#   - 如果 KPM 已加载，先 unload 再 load
#
# 验证：
#   dmesg | grep oracle_bypass    # 查看 init 阶段打印的关键字列表
#   apd kpm control selinux_oracle_bypass list   # 任何时刻再次输出列表

set -u

KPM_PATH="${KPM_PATH:-/data/adb/kpm/selinux_oracle_bypass.kpm}"
CONF="${CONF:-/data/adb/kpm/selinux_oracle_bypass.conf}"
NAME="selinux_oracle_bypass"
APD="${APD:-apd}"

if [ ! -f "$KPM_PATH" ]; then
    echo "[load.sh] error: $KPM_PATH not found" >&2
    exit 1
fi

# 1) 构造 args
if [ -f "$CONF" ]; then
    ARGS="default,config=${CONF}"
else
    echo "[load.sh] warning: $CONF missing, falling back to defaults only" >&2
    ARGS="default"
fi

# 2) 如已加载，先卸载
if "$APD" kpm list 2>/dev/null | grep -q "^${NAME}\b"; then
    echo "[load.sh] unloading existing $NAME ..."
    "$APD" kpm unload "$NAME" || {
        echo "[load.sh] unload failed; continue anyway" >&2
    }
fi

# 3) 加载
echo "[load.sh] loading $KPM_PATH with args: $ARGS"
exec "$APD" kpm load "$KPM_PATH" "$ARGS"
