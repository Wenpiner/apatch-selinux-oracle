# Makefile for selinux_oracle_bypass.kpm
#
# 使用方式（任选其一）：
#
#   方式 A —— 官方 bare-metal 工具链（推荐，与 KernelPatch 上游一致）
#     1. 下载 aarch64-none-elf-* (Arm GNU Toolchain)，加到 PATH
#     2. 克隆 https://github.com/bmax121/KernelPatch 到本机
#     3. 编译：
#          export TARGET_COMPILE=aarch64-none-elf-
#          export KP_DIR=/path/to/KernelPatch
#          make
#
#   方式 B —— Android NDK (clang)
#          export ANDROID_NDK=/path/to/android-ndk-r26d
#          export KP_DIR=/path/to/KernelPatch
#          make USE_NDK=1
#
# 输出：selinux_oracle_bypass.kpm（即一个 ARM64 可重定位 ELF 对象，KernelPatch
# 运行时由 module loader 自行做 relocation + section 解析）。

TARGET   := selinux_oracle_bypass
SRCS     := selinux_oracle_bypass.c
OBJS     := $(SRCS:.c=.o)

# --- KernelPatch 源码头文件路径 ---
ifndef KP_DIR
$(error 请先 `export KP_DIR=/path/to/KernelPatch`)
endif

INCLUDE_DIRS := \
    . \
    include \
    patch/include \
    linux/include \
    linux/arch/arm64/include \
    linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach d,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(d))

# --- 工具链选择 ---
ifeq ($(USE_NDK),1)
    ifndef ANDROID_NDK
    $(error 使用 NDK 时请先 `export ANDROID_NDK=/path/to/android-ndk`)
    endif
    HOSTTAG := $(shell uname | tr A-Z a-z)-x86_64
    TC      := $(ANDROID_NDK)/toolchains/llvm/prebuilt/$(HOSTTAG)/bin
    CC      := $(TC)/aarch64-linux-android31-clang
    LD      := $(TC)/ld.lld
    STRIP   := $(TC)/llvm-strip
else
    TARGET_COMPILE ?= aarch64-none-elf-
    CC      := $(TARGET_COMPILE)gcc
    LD      := $(TARGET_COMPILE)ld
    STRIP   := $(TARGET_COMPILE)strip
endif

# 与官方 demo-inlinehook 一致的标志集合：
#   -fno-pic / -fno-pie       : KPM 由 KernelPatch 自行重定位，禁掉 PIC/PIE
#   -fno-stack-protector      : 内核态没有 __stack_chk_*
#   -fno-asynchronous-unwind-tables : 去掉 .eh_frame，减小体积
#   -mgeneral-regs-only       : ARM64 内核态禁用 SIMD/FP 寄存器
#   -ffreestanding -nostdinc  : 不依赖宿主 libc
CFLAGS := \
    -O2 -Wall \
    -fno-pic -fno-pie \
    -fno-stack-protector \
    -fno-asynchronous-unwind-tables \
    -fno-unwind-tables \
    -fno-common \
    -fvisibility=hidden \
    -ffreestanding \
    -mgeneral-regs-only \
    -U_FORTIFY_SOURCE \
    $(INCLUDE_FLAGS)

LDFLAGS := -r -nostdlib

.PHONY: all clean
all: $(TARGET).kpm

$(TARGET).kpm: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^
	$(STRIP) -g --strip-unneeded --remove-section=.comment --remove-section=.note.GNU-stack $@
	@echo ">>> built $@"

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET).kpm
