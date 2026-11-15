# make -C $KDIR ARCH=arm64 M=$(pwd) modules
# For ddk: ddk build android17-6.18  (KDIR set by container)

KDIR ?= /lib/modules/$(shell uname -r)/build
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
ODIR := $(MDIR)
KMI := $(notdir $(patsubst %/,%,$(KDIR)))

ifeq ($(KMI),android17-6.18)
KBUILD_ARGS := M=$(MDIR) MO=$(ODIR)
else
KBUILD_ARGS := M=$(MDIR)
endif

obj-m += kasumi_lkm.o
# core/kasumi_sop_shadow.o owns the sb->s_op shadow used by dirhijack's virtual
# inode reclaim callbacks. The dead features/kasumi_sop_override.o stub it
# supersedes was removed.
kasumi_lkm-objs := \
	kasumi_main.o \
	core/kasumi_module_sysfs.o \
	core/kasumi_instance.o \
	core/kasumi_bootstrap.o \
	core/kasumi_runtime.o \
	core/kasumi_identity.o \
	core/kasumi_batch.o \
	core/kasumi_live_rules.o \
	core/kasumi_fop_bridge.o \
	core/kasumi_vnode.o \
	core/kasumi_vnode_handle.o \
	core/kasumi_rwsem_compat.o \
	core/kasumi_dirhijack.o \
	core/kasumi_hide_events.o \
	core/kasumi_hide_rules.o \
	core/kasumi_sop_shadow.o \
	core/kasumi_root_detection.o \
	control/kasumi_ioctl.o \
	control/kasumi_transaction.o \
	control/kasumi_conflict.o \
	core/kasumi_module_guard.o \
	core/kasumi_config_guard.o \
	policy/kasumi_path_policy.o \
	overlay/kasumi_overlay.o \
	hooks/kasumi_proc_hooks.o \
	hooks/kasumi_proc_read_hooks.o \
	hooks/kasumi_proc_seq.o \
	hooks/kasumi_vfs_hooks.o \
	hooks/kasumi_ftrace_hooks.o \
	features/kasumi_iop_override.o \
	features/kasumi_maps_rules.o \
	features/kasumi_exec_view.o \
	features/kasumi_notify_view.o \
	features/kasumi_notify_rules.o \
	features/kasumi_notify_watch.o \
	features/kasumi_notify_fanotify.o \
	features/kasumi_io_notify.o \
	features/kasumi_io_notify_unlink.o \
	features/kasumi_file_lock.o \
	features/kasumi_rename_view.o \
	features/kasumi_vfs_view.o \
	features/kasumi_mount_view.o \
	features/kasumi_mount_query.o \
	features/kasumi_mount_stat.o \
	features/kasumi_dir_view.o \
	features/kasumi_fop_override.o \
	features/kasumi_fake_mountinfo.o \
	features/kasumi_fake_selinuxfs_access.o

kasumi_lkm-$(CONFIG_ARM64) += hooks/arm64/kasumi_patch_memory.o

ccflags-y += -gz=none
# Keep native rwsem inlines without requiring newer Android tracing helpers.
kasumi-rwsem-starttime-decl := $(shell sed -n '/^void _trace_android_vh_record_pcpu_rwsem_starttime/{:a; /;/!{N;ba};p;}' $(srctree)/include/linux/percpu-rwsem.h)
ifneq ($(findstring struct percpu_rw_semaphore,$(kasumi-rwsem-starttime-decl)),)
ccflags-y += -DKASUMI_RWSEM_STARTTIME_USES_SEM
endif
kasumi-rwsem-compat-cflags := \
	-D_trace_android_vh_record_pcpu_rwsem_starttime=kasumi_trace_pcpu_rwsem_starttime \
	-D_trace_android_vh_record_pcpu_rwsem_time_early=kasumi_trace_pcpu_rwsem_time_early
CFLAGS_core/kasumi_vnode.o += $(kasumi-rwsem-compat-cflags)
# Applying the same names here makes the kernel declarations check our ABI.
CFLAGS_core/kasumi_rwsem_compat.o += $(kasumi-rwsem-compat-cflags)

# Match the VFS allocation APIs exposed by the build headers.
kasumi-public-alloc-inode := $(shell grep -E '^[[:space:]]*(extern[[:space:]]+)?struct[[:space:]]+inode[[:space:]]*\*[[:space:]]*alloc_inode\b' $(srctree)/include/linux/fs.h)
ifneq ($(kasumi-public-alloc-inode),)
CFLAGS_core/kasumi_sop_shadow.o += -DKASUMI_VFS_ALLOC_INODE_PUBLIC
endif
kasumi-iget5-locked-rcu := $(shell grep -E '^[[:space:]]*(extern[[:space:]]+)?struct[[:space:]]+inode[[:space:]]*\*[[:space:]]*iget5_locked_rcu\b' $(srctree)/include/linux/fs.h)
ifneq ($(kasumi-iget5-locked-rcu),)
CFLAGS_core/kasumi_sop_shadow.o += -DKASUMI_HAS_IGET5_LOCKED_RCU
endif
CFLAGS_hooks/kasumi_proc_seq.o += -I$(srctree)
CFLAGS_features/kasumi_exec_view.o += -I$(srctree)
CFLAGS_features/kasumi_vfs_view.o += -I$(srctree)
CFLAGS_features/kasumi_mount_view.o += -I$(srctree)
CFLAGS_features/kasumi_mount_query.o += -I$(srctree)
CFLAGS_features/kasumi_mount_stat.o += -I$(srctree)

# Module sysfs metadata is private to the target kernel. Probe its allocation
# layout so backports use the matching cleanup, independently of the version.
kasumi-module-sysfs-src := $(srctree)/kernel/module/sysfs.c
ifeq ($(wildcard $(kasumi-module-sysfs-src)),)
kasumi-module-sysfs-src := $(srctree)/kernel/module.c
endif
ifneq ($(shell sed -n '/^struct module_notes_attrs {/,/^};/p' $(kasumi-module-sysfs-src) | grep -c 'struct attribute_group grp'),0)
CFLAGS_core/kasumi_module_sysfs.o += -DKASUMI_MODULE_NOTES_USE_GROUP
endif
ifneq ($(shell grep -c 'kfree(sect_attrs->grp.bin_attrs)' $(kasumi-module-sysfs-src)),0)
CFLAGS_core/kasumi_module_sysfs.o += -DKASUMI_MODULE_SECT_SEPARATE_BIN_ATTRS
endif

ifneq ($(shell grep -c 'eventfd_signal(struct eventfd_ctx \*ctx)' $(srctree)/include/linux/eventfd.h),0)
CFLAGS_core/kasumi_instance.o += -DKASUMI_EVENTFD_SIGNAL_NO_COUNT
endif

# Linux 6.18 exposes the external module source as srcroot when M/MO are
# used. Older kernels keep using src, which may be relative to srctree.
ifneq ($(KBUILD_EXTMOD),)
ifneq ($(srcroot),)
KASUMI_SRC_DIR := $(srcroot)
endif
endif
ifndef KASUMI_SRC_DIR
ifeq ($(filter /%,$(src)),)
KASUMI_SRC_DIR := $(srctree)/$(src)
else
KASUMI_SRC_DIR := $(src)
endif
endif

ccflags-y += -I$(KASUMI_SRC_DIR)/include
ccflags-y += -I$(KASUMI_SRC_DIR)/internal
ccflags-y += -I$(KASUMI_SRC_DIR)/core
ccflags-y += -I$(KASUMI_SRC_DIR)/control
ccflags-y += -I$(KASUMI_SRC_DIR)/policy
ccflags-y += -I$(KASUMI_SRC_DIR)/overlay
ccflags-y += -I$(KASUMI_SRC_DIR)/hooks
ccflags-y += -I$(KASUMI_SRC_DIR)/features
# Do not force CONFIG_DYNAMIC_FTRACE / CONFIG_FUNCTION_TRACER from module flags.
# They must follow target kernel Kconfig, otherwise some arches/toolchains
# (e.g. x86 with missing fentry flags) fail at asm/ftrace.h checks.
# Do NOT add -fno-sanitize=cfi here: init/exit must have kernel-expected CFI type for
# do_one_initcall. Use KASUMI_NOCFI only on functions that make indirect calls to resolved symbols.

all:
	$(MAKE) -C $(KDIR) $(KBUILD_ARGS) ARCH=arm64 modules

clean:
	$(MAKE) -C $(KDIR) $(KBUILD_ARGS) clean 2>/dev/null || true
	rm -rf .tmp_versions
	@find . -maxdepth 1 -type f ! -name '*.c' ! -name '*.h' ! -name 'Makefile' ! -name '*.md' ! -name '.gitignore' -exec rm -f {} + 2>/dev/null || true
.PHONY: all clean
