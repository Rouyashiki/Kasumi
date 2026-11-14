/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - isolated mountinfo views and proc maps filtering.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/wait.h>

#include "kasumi_fake_mountinfo.h"
#include "kasumi_maps_rules.h"
#include "kasumi_mount_view.h"
#include "kasumi_proc_seq.h"
#include "kasumi_runtime.h"
#include "kasumi_vnode.h"
#include "kasumi_proc_read_hooks.h"

static DEFINE_MUTEX(kasumi_proc_users_lock);
static unsigned int kasumi_proc_users;
static bool kasumi_proc_core_held;
static bool kasumi_proc_mount_held;

static struct kprobe kasumi_caps_probe;
static atomic_t kasumi_caps_active = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(kasumi_caps_wait);
static void (*kasumi_caps_tasks_barrier)(void);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
static KASUMI_NOCFI int kasumi_caps_read(struct mnt_idmap *idmap,
	const struct dentry *dentry, struct cpu_vfs_cap_data *caps)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
static KASUMI_NOCFI int kasumi_caps_read(struct user_namespace *idmap,
	const struct dentry *dentry, struct cpu_vfs_cap_data *caps)
#else
static KASUMI_NOCFI int kasumi_caps_read(const struct dentry *dentry,
	struct cpu_vfs_cap_data *caps)
#endif
{
	struct kasumi_internal_vfs_guard guard;
	bool handled;
	int ret;

	kasumi_vfs_internal_enter(&guard);
	ret = kasumi_vnode_read_caps(dentry, caps, &handled);
	if (!handled) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
		ret = kasumi_get_vfs_caps_from_disk(idmap, dentry, caps);
#else
		ret = kasumi_get_vfs_caps_from_disk(dentry, caps);
#endif
	}
	kasumi_vfs_internal_leave(&guard);
	if (atomic_dec_and_test(&kasumi_caps_active))
		wake_up_all(&kasumi_caps_wait);
	return ret;
}

static int kasumi_caps_pre(struct kprobe *probe, struct pt_regs *regs)
{
#if defined(CONFIG_ARM64)
	const struct dentry *dentry;

	if (!READ_ONCE(kasumi_fscap_kretprobe_registered) ||
	    !READ_ONCE(kasumi_fscaps_enabled) || kasumi_vfs_internal_current())
		return 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	dentry = (void *)regs->regs[1];
#else
	dentry = (void *)regs->regs[0];
#endif
	if (!dentry || !kasumi_vnode_is_ours(d_inode(dentry)))
		return 0;
	atomic_inc(&kasumi_caps_active);
	instruction_pointer_set(regs, (unsigned long)kasumi_caps_read);
	return 1;
#else
	return 0;
#endif
}

static void kasumi_caps_init(void)
{
#if defined(CONFIG_ARM64)
	int ret;

	if (!kasumi_get_vfs_caps_from_disk)
		return;
	kasumi_caps_tasks_barrier =
		(void *)kasumi_lookup_callable_quiet("synchronize_rcu_tasks");
	if (!kasumi_caps_tasks_barrier)
		return;
	kasumi_caps_probe.addr = (void *)kasumi_lookup_name_quiet(
		"get_vfs_caps_from_disk");
	kasumi_caps_probe.pre_handler = kasumi_caps_pre;
	ret = register_kprobe(&kasumi_caps_probe);
	if (!ret)
		WRITE_ONCE(kasumi_fscap_kretprobe_registered, 1);
	else
		pr_warn("kasumi: source file-capability hook failed (%d)\n", ret);
#endif
}

static KASUMI_NOCFI void kasumi_caps_stop(void)
{
	if (!READ_ONCE(kasumi_fscap_kretprobe_registered))
		return;
	WRITE_ONCE(kasumi_fscap_kretprobe_registered, 0);
	unregister_kprobe(&kasumi_caps_probe);
	wait_event(kasumi_caps_wait, !atomic_read(&kasumi_caps_active));
	kasumi_caps_tasks_barrier();
}


static int kasumi_proc_acquire(bool require_mount)
{
	int ret = 0;

	mutex_lock(&kasumi_proc_users_lock);
	if (!kasumi_proc_users) {
		kasumi_proc_mount_held = kasumi_fake_mi_init() == 0;
		ret = kasumi_proc_seq_init();
		if (ret) {
			if (kasumi_proc_mount_held)
				kasumi_fake_mi_exit();
			kasumi_proc_mount_held = false;
			goto out;
		}
		WRITE_ONCE(kasumi_proc_proxy_registered, 1);
	}
	if (require_mount && (!kasumi_mount_view_available() ||
	    !(kasumi_mount_view_capabilities() & KASUMI_MOUNT_CAP_INFO))) {
		ret = -EOPNOTSUPP;
		if (!kasumi_proc_users) {
			WRITE_ONCE(kasumi_proc_proxy_registered, 0);
			kasumi_proc_seq_stop();
			if (kasumi_proc_mount_held)
				kasumi_fake_mi_exit();
			kasumi_proc_mount_held = false;
		}
		goto out;
	}
	kasumi_proc_users++;
out:
	mutex_unlock(&kasumi_proc_users_lock);
	return ret;
}

int kasumi_proc_proxy_get(void)
{
	return kasumi_proc_acquire(true);
}

void kasumi_proc_proxy_put(void)
{
	mutex_lock(&kasumi_proc_users_lock);
	if (WARN_ON_ONCE(!kasumi_proc_users))
		goto out;
	if (!--kasumi_proc_users) {
		WRITE_ONCE(kasumi_proc_proxy_registered, 0);
		kasumi_proc_seq_stop();
		if (kasumi_proc_mount_held)
			kasumi_fake_mi_exit();
		kasumi_proc_mount_held = false;
	}
out:
	mutex_unlock(&kasumi_proc_users_lock);
}

void kasumi_proc_read_hooks_init(void)
{
	kasumi_proc_core_held = kasumi_proc_acquire(false) == 0;
	if (!kasumi_proc_core_held)
		pr_warn("kasumi: native proc adapters unavailable\n");
	kasumi_caps_init();
}

void kasumi_proc_read_hooks_stop_new(void)
{
	if (kasumi_proc_core_held) {
		kasumi_proc_core_held = false;
		kasumi_proc_proxy_put();
	}
	kasumi_caps_stop();
}

unsigned int kasumi_proc_proxy_live(void)
{
	return 0;
}

void kasumi_proc_read_hooks_exit(void)
{
	kasumi_proc_read_hooks_stop_new();
	kasumi_maps_rules_clear();
}
