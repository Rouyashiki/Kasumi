/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - shared runtime state, rule stores, and common cleanup helpers.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0) && !defined(arch_ftrace_get_regs)
#define arch_ftrace_get_regs(fregs) (NULL)
#endif
#include <linux/kprobes.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/jhash.h>
#include <linux/kdev_t.h>
#include <linux/hashtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/sched/task.h>
#include <linux/fs_struct.h>
#include <linux/dirent.h>
#include <linux/stat.h>
#include <linux/time.h>
#include <linux/anon_inodes.h>
#include <linux/fcntl.h>
#include <linux/percpu.h>
#include <linux/smp.h>
#include <linux/mount.h>
#include <linux/xattr.h>
#include <linux/seq_file.h>
#include <uapi/linux/magic.h>

#include "kasumi_runtime.h"
#include "kasumi_store.h"
#include "kasumi_batch.h"
#include "kasumi_live_rules.h"
#include "kasumi_notify_watch.h"
#include "kasumi_notify_fanotify.h"
#include "kasumi_maps_rules.h"
#include "kasumi_fake_mountinfo.h"
#include "kasumi_iop_override.h"
#include "kasumi_vfs_view.h"
#include "kasumi_path_policy.h"
#include "kasumi_fop_override.h"

bool kasumi_enabled;
atomic_t kasumi_rule_count = ATOMIC_INIT(0);
atomic_t kasumi_hide_count = ATOMIC_INIT(0);
struct kasumi_hook_stats kasumi_hook_stats;

#define KASUMI_INTERNAL_VFS_HASH_BITS 5

static DEFINE_HASHTABLE(kasumi_internal_vfs_tasks,
			KASUMI_INTERNAL_VFS_HASH_BITS);
static spinlock_t kasumi_internal_vfs_locks[1 << KASUMI_INTERNAL_VFS_HASH_BITS] = {
	[0 ... (1 << KASUMI_INTERNAL_VFS_HASH_BITS) - 1] =
		__SPIN_LOCK_UNLOCKED(kasumi_internal_vfs_locks),
};
static atomic_t kasumi_internal_vfs_active = ATOMIC_INIT(0);
static u64 kasumi_rules_epoch = 1;

u64 kasumi_rules_generation(void)
{
	return smp_load_acquire(&kasumi_rules_epoch);
}

void kasumi_rules_changed(void)
{
	kasumi_rules_publish(kasumi_rules_generation() + 1);
	kasumi_notify_watch_rules_changed();
	kasumi_notify_fanotify_rules_changed();
}

void kasumi_rules_publish(u64 generation)
{
	smp_store_release(&kasumi_rules_epoch, generation);
	kasumi_fake_mi_invalidate_all();
}

void kasumi_vfs_internal_enter(struct kasumi_internal_vfs_guard *guard)
{
	spinlock_t *lock = &kasumi_internal_vfs_locks[
		hash_min((unsigned long)current, KASUMI_INTERNAL_VFS_HASH_BITS)];
	unsigned long flags;

	guard->task = current;
	spin_lock_irqsave(lock, flags);
	hash_add(kasumi_internal_vfs_tasks, &guard->node,
		 (unsigned long)current);
	atomic_inc(&kasumi_internal_vfs_active);
	spin_unlock_irqrestore(lock, flags);
}

void kasumi_vfs_internal_leave(struct kasumi_internal_vfs_guard *guard)
{
	spinlock_t *lock = &kasumi_internal_vfs_locks[
		hash_min((unsigned long)guard->task, KASUMI_INTERNAL_VFS_HASH_BITS)];
	unsigned long flags;

	spin_lock_irqsave(lock, flags);
	hash_del(&guard->node);
	atomic_dec(&kasumi_internal_vfs_active);
	spin_unlock_irqrestore(lock, flags);
}

bool kasumi_vfs_internal_current(void)
{
	spinlock_t *lock = &kasumi_internal_vfs_locks[
		hash_min((unsigned long)current, KASUMI_INTERNAL_VFS_HASH_BITS)];
	struct kasumi_internal_vfs_guard *guard;
	unsigned long flags;
	bool found = false;

	if (!atomic_read(&kasumi_internal_vfs_active))
		return false;
	spin_lock_irqsave(lock, flags);
	hash_for_each_possible(kasumi_internal_vfs_tasks, guard, node,
			       (unsigned long)current) {
		if (guard->task == current) {
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(lock, flags);
	return found;
}

int KASUMI_NOCFI kasumi_vfs_getattr_unprojected(
	const struct path *path, struct kstat *stat, u32 request_mask,
	unsigned int query_flags)
{
	struct kasumi_internal_vfs_guard guard;
	int ret;

	if (!kasumi_vfs_getattr)
		return -EOPNOTSUPP;
	kasumi_vfs_internal_enter(&guard);
	ret = kasumi_vfs_getattr(path, stat, request_mask, query_flags);
	kasumi_vfs_internal_leave(&guard);
	return ret;
}

/*
 * Parse the source file's on-disk capabilities via the kernel's own reader, so
 * an exec of a redirected setcap binary keeps its file capabilities.  Sleepable
 * (reads security.capability): call from vnode-create context, never from a
 * kprobe handler.  @out is filled and 0 returned only when the source carries
 * caps; any error (incl. -ENODATA) leaves @out untouched.
 */
int KASUMI_NOCFI kasumi_source_vfs_caps(const struct path *src,
					struct cpu_vfs_cap_data *out)
{
	if (!src || !src->dentry || !src->mnt || !out ||
	    !kasumi_get_vfs_caps_from_disk)
		return -EOPNOTSUPP;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	return kasumi_get_vfs_caps_from_disk(mnt_idmap(src->mnt), src->dentry,
					     out);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	return kasumi_get_vfs_caps_from_disk(mnt_user_ns(src->mnt), src->dentry,
					     out);
#else
	return kasumi_get_vfs_caps_from_disk(src->dentry, out);
#endif
}

/* Metadata-only device namespace for virtual nodes.  No real superblock is
 * registered: pathname hooks, virtual descriptors and proc projections all
 * publish this identity from the rule snapshot. */
#define KASUMI_VNODE_MINOR 0x4b5
static atomic64_t kasumi_vnode_allocated_count = ATOMIC64_INIT(0);
static atomic_t kasumi_vnode_live_count = ATOMIC_INIT(0);

dev_t kasumi_vnode_device(void)
{
	return MKDEV(0, KASUMI_VNODE_MINOR);
}

/*
 * Scheme A: publish the device a real file at the visible path would report,
 * so a virtual node's st_dev matches its sibling real files instead of an
 * anonymous vnode minor (which is itself an odd-dev-out tell).  Resolves the
 * visible path, or its parent directory when nothing is backed there yet, and
 * falls back to the captured /system dev, then to the vnode minor, so a valid
 * non-zero device is always published.  Sleepable context only (path lookup).
 */
KASUMI_NOCFI dev_t kasumi_vnode_visible_dev(const char *visible_path)
{
	struct path p;
	dev_t dev = kasumi_system_dev;
	char *parent;
	char *slash;

	if (!visible_path || !*visible_path || !kasumi_kern_path)
		goto out;
	if (kasumi_kern_path(visible_path, LOOKUP_FOLLOW, &p) == 0) {
		if (p.dentry && p.dentry->d_sb)
			dev = p.dentry->d_sb->s_dev;
		kasumi_path_put(&p);
		goto out;
	}
	parent = kstrdup(visible_path, GFP_KERNEL);
	if (parent) {
		slash = strrchr(parent, '/');
		if (slash && slash != parent) {
			*slash = '\0';
			if (kasumi_kern_path(parent, LOOKUP_FOLLOW, &p) == 0) {
				if (p.dentry && p.dentry->d_sb)
					dev = p.dentry->d_sb->s_dev;
				kasumi_path_put(&p);
			}
		}
		kfree(parent);
	}
out:
	if (!dev)
		dev = kasumi_vnode_device();
	return dev;
}

u64 kasumi_vnode_allocated(void)
{
	return (u64)atomic64_read(&kasumi_vnode_allocated_count);
}

unsigned int kasumi_vnode_live(void)
{
	return (unsigned int)atomic_read(&kasumi_vnode_live_count);
}


atomic_long_t kasumi_ioctl_tgid = ATOMIC_LONG_INIT(0);
atomic_long_t kasumi_xattr_source_tgid = ATOMIC_LONG_INIT(0);

struct kmem_cache *kasumi_filldir_cache;

unsigned long (*kasumi_kallsyms_lookup_name)(const char *name);

DEFINE_HASHTABLE(kasumi_paths, KASUMI_HASH_BITS);
DEFINE_HASHTABLE(kasumi_targets, KASUMI_HASH_BITS);
DEFINE_HASHTABLE(kasumi_hide_paths, KASUMI_HASH_BITS);
DEFINE_HASHTABLE(kasumi_inject_dirs, KASUMI_HASH_BITS);
DEFINE_HASHTABLE(kasumi_xattr_sbs, KASUMI_HASH_BITS);
DEFINE_HASHTABLE(kasumi_merge_dirs, KASUMI_HASH_BITS);

DEFINE_HASHTABLE(kasumi_spoof_kstat_path, KASUMI_HASH_BITS);
DEFINE_HASHTABLE(kasumi_spoof_kstat_ino, KASUMI_HASH_BITS);
atomic_t kasumi_spoof_kstat_count = ATOMIC_INIT(0);

DEFINE_MUTEX(kasumi_config_mutex);

kasumi_ksu_uid_should_umount_fn kasumi_ksu_uid_should_umount_ptr;

bool kasumi_debug_enabled;
bool kasumi_stealth_enabled;

pid_t kasumi_daemon_pid;

int kasumi_getxattr_kprobe_registered;
int kasumi_mount_hide_vfsmnt_registered;
int kasumi_mount_hide_mountinfo_registered;
int kasumi_proc_proxy_registered;
int kasumi_feature_enabled_mask;
int kasumi_statfs_kretprobe_registered;
int kasumi_fscap_kretprobe_registered;
int kasumi_fscaps_enabled = 1;
int kasumi_device_sources_enabled = 1;
int kasumi_reboot_kprobe_registered;
bool kasumi_vfs_use_ftrace;

DECLARE_BITMAP(kasumi_path_bloom, KASUMI_BLOOM_SIZE);
DECLARE_BITMAP(kasumi_hide_bloom, KASUMI_BLOOM_SIZE);

dev_t kasumi_system_dev;

int (*kasumi_kern_path)(const char *, unsigned int, struct path *);
int (*kasumi_vfs_getattr)(const struct path *, struct kstat *, u32, unsigned int);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
int (*kasumi_notify_change)(struct mnt_idmap *, struct dentry *,
			    struct iattr *, struct inode **);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
int (*kasumi_notify_change)(struct user_namespace *, struct dentry *,
			    struct iattr *, struct inode **);
#else
int (*kasumi_notify_change)(struct dentry *, struct iattr *, struct inode **);
#endif
struct file *(*kasumi_dentry_open)(const struct path *, int, const struct cred *);
ssize_t (*kasumi_vfs_read)(struct file *, char __user *, size_t, loff_t *);
int (*kasumi_rw_verify_area)(int, struct file *, const loff_t *, size_t);
typeof(security_file_permission) *kasumi_security_file_permission;
void (*kasumi_fput_sync)(struct file *);
ssize_t (*kasumi_vfs_write)(struct file *, const char __user *, size_t, loff_t *);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
int (*kasumi_get_vfs_caps_from_disk)(struct mnt_idmap *, const struct dentry *,
				     struct cpu_vfs_cap_data *);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
int (*kasumi_get_vfs_caps_from_disk)(struct user_namespace *,
				     const struct dentry *,
				     struct cpu_vfs_cap_data *);
#else
int (*kasumi_get_vfs_caps_from_disk)(const struct dentry *,
				     struct cpu_vfs_cap_data *);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
typeof(security_inode_getlsmprop) *kasumi_security_inode_getlsmprop;
#else
typeof(security_inode_getsecid) *kasumi_security_inode_getsecid;
#endif
typeof(security_inode_getsecctx) *kasumi_security_inode_getsecctx;
typeof(security_inode_notifysecctx) *kasumi_security_inode_notifysecctx;
typeof(security_release_secctx) *kasumi_security_release_secctx;
char *(*kasumi_d_absolute_path)(const struct path *, char *, int);
char *(*kasumi_dentry_path_raw)(const struct dentry *, char *, int);
char *(*kasumi_d_path)(const struct path *, char *, int);
struct dentry *(*kasumi_d_lookup_ptr)(const struct dentry *,
				      const struct qstr *);
struct dentry *(*kasumi_d_hash_and_lookup)(struct dentry *, const struct qstr *);
void *kasumi_vfs_getxattr_addr;
void *kasumi_vfs_listxattr_addr;
void *kasumi_vfs_setxattr_addr;
void *kasumi_vfs_removexattr_addr;
void *kasumi_mnt_want_write_addr;
void *kasumi_mnt_drop_write_addr;
int (*kasumi_vfs_path_lookup)(struct dentry *, struct vfsmount *,
			      const char *, unsigned int, struct path *);
const char *(*kasumi_vfs_get_link)(struct dentry *, struct delayed_call *);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
typeof(lookup_one) *kasumi_lookup_one;
#else
typeof(lookup_one_len) *kasumi_lookup_one;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
int (*kasumi_vfs_create)(struct mnt_idmap *, struct inode *, struct dentry *, umode_t, bool);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
struct dentry *(*kasumi_vfs_mkdir)(struct mnt_idmap *, struct inode *,
				   struct dentry *, umode_t);
#else
int (*kasumi_vfs_mkdir)(struct mnt_idmap *, struct inode *, struct dentry *, umode_t);
#endif
int (*kasumi_vfs_mknod)(struct mnt_idmap *, struct inode *, struct dentry *, umode_t, dev_t);
int (*kasumi_vfs_symlink)(struct mnt_idmap *, struct inode *, struct dentry *, const char *);
int (*kasumi_vfs_unlink)(struct mnt_idmap *, struct inode *, struct dentry *, struct inode **);
int (*kasumi_vfs_rmdir)(struct mnt_idmap *, struct inode *, struct dentry *);
int (*kasumi_vfs_link)(struct dentry *, struct mnt_idmap *, struct inode *, struct dentry *, struct inode **);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
int (*kasumi_vfs_create)(struct user_namespace *, struct inode *, struct dentry *, umode_t, bool);
int (*kasumi_vfs_mkdir)(struct user_namespace *, struct inode *, struct dentry *, umode_t);
int (*kasumi_vfs_mknod)(struct user_namespace *, struct inode *, struct dentry *, umode_t, dev_t);
int (*kasumi_vfs_symlink)(struct user_namespace *, struct inode *, struct dentry *, const char *);
int (*kasumi_vfs_unlink)(struct user_namespace *, struct inode *, struct dentry *, struct inode **);
int (*kasumi_vfs_rmdir)(struct user_namespace *, struct inode *, struct dentry *);
int (*kasumi_vfs_link)(struct dentry *, struct user_namespace *, struct inode *, struct dentry *, struct inode **);
#else
int (*kasumi_vfs_create)(struct inode *, struct dentry *, umode_t, bool);
int (*kasumi_vfs_mkdir)(struct inode *, struct dentry *, umode_t);
int (*kasumi_vfs_mknod)(struct inode *, struct dentry *, umode_t, dev_t);
int (*kasumi_vfs_symlink)(struct inode *, struct dentry *, const char *);
int (*kasumi_vfs_unlink)(struct inode *, struct dentry *, struct inode **);
int (*kasumi_vfs_rmdir)(struct inode *, struct dentry *);
int (*kasumi_vfs_link)(struct dentry *, struct inode *, struct dentry *, struct inode **);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
int (*kasumi_vfs_rename)(struct renamedata *);
#else
int (*kasumi_vfs_rename)(struct inode *, struct dentry *, struct inode *, struct dentry *, struct inode **, unsigned int);
#endif
void (*kasumi_path_get_ptr)(const struct path *);
void (*kasumi_path_put_ptr)(const struct path *);
void (*kasumi_free_inode_nonrcu_ptr)(struct inode *);
struct file *(*kasumi_filp_open)(const char *, int, umode_t);
int (*kasumi_filp_close)(struct file *, fl_owner_t);
char *(*kasumi_strndup_user)(const char __user *, long);
void (*kasumi_ihold)(struct inode *);
long (*kasumi_strncpy_from_user_nofault)(char *dst, const void __user *src, long count);
long (*kasumi_copy_from_user_nofault)(void *dst, const void __user *src, size_t size);
long (*kasumi_copy_to_user_nofault)(void __user *dst, const void *src, size_t size);
int (*kasumi_task_work_add_ptr)(struct task_struct *task,
				struct callback_head *work,
				enum task_work_notify_mode notify);
struct llist_node *(*kasumi_llist_del_first_ptr)(struct llist_head *head);
ssize_t (*kasumi_seq_read_iter_ptr)(struct kiocb *iocb,
				    struct iov_iter *iter);
void (*kasumi_call_srcu_ptr)(struct srcu_struct *ssp, struct rcu_head *rhp,
			     rcu_callback_t func);
void (*kasumi_srcu_barrier_ptr)(struct srcu_struct *ssp);
void (*kasumi_synchronize_rcu_tasks_ptr)(void);
int (*kasumi_module_refcount_ptr)(struct module *module);

/* Avoid load-time dependencies on GKI-trimmed exports. */
noinline KASUMI_NOCFI struct llist_node *
kasumi_llist_del_first(struct llist_head *head)
{
	return kasumi_llist_del_first_ptr(head);
}

noinline KASUMI_NOCFI struct dentry *
kasumi_d_lookup(const struct dentry *parent, const struct qstr *name)
{
	return kasumi_d_lookup_ptr(parent, name);
}

noinline KASUMI_NOCFI ssize_t kasumi_seq_read_iter(
	struct kiocb *iocb, struct iov_iter *iter)
{
	if (!kasumi_seq_read_iter_ptr)
		return -EOPNOTSUPP;
	return kasumi_seq_read_iter_ptr(iocb, iter);
}

noinline KASUMI_NOCFI void kasumi_synchronize_rcu_tasks(void)
{
	kasumi_synchronize_rcu_tasks_ptr();
}

noinline KASUMI_NOCFI int kasumi_module_refcount(struct module *module)
{
	return kasumi_module_refcount_ptr(module);
}

bool kasumi_valid_kernel_addr(unsigned long addr)
{
	if (!addr)
		return false;
	if (IS_ERR_VALUE(addr))
		return false;
#if defined(CONFIG_64BIT)
	return (addr & (1UL << 63)) != 0;
#else
	return addr >= PAGE_OFFSET;
#endif
}

KASUMI_NOCFI unsigned long kasumi_lookup_name(const char *name)
{
	if (kasumi_kallsyms_lookup_name) {
		unsigned long addr = kasumi_kallsyms_lookup_name(name);

		if (addr && !IS_ERR_VALUE(addr))
			return addr;
	}

	{
		struct kprobe kp = { .symbol_name = name };
		unsigned long addr;
		int ret;

		ret = register_kprobe(&kp);
		if (ret < 0) {
			pr_alert("Kasumi: kprobe %s failed: %d\n", name, ret);
			return 0;
		}
		addr = (unsigned long)kp.addr;
		unregister_kprobe(&kp);
		if (!addr || IS_ERR_VALUE(addr)) {
			pr_alert("Kasumi: symbol %s returned invalid addr 0x%lx\n", name, addr);
			return 0;
		}
		return addr;
	}
}

/*
 * Resolve a kernel symbol that Kasumi will CALL through a function pointer.
 *
 * On old jump-table CFI kernels (android12-5.10 .. android14-5.15) the only
 * valid indirect-call target for an address-taken function is its
 * "<name>.cfi_jt" thunk; calling the raw function body faults under strict
 * (non-permissive) CFI. Prefer the thunk; fall back to the raw symbol for
 * kCFI kernels (6.1+, where the raw addr is callable) and for functions with
 * no thunk (the raw addr is then the canonical entry).
 *
 * CAVEAT: depends on the ".cfi_jt" locals being present in kallsyms
 * (CONFIG_KALLSYMS_ALL). Not robust where they are stripped AND the target is
 * a non-exported, address-taken function: there is then no thunk to resolve
 * and no direct call available. For EXPORTED symbols prefer a direct call.
 */
KASUMI_NOCFI unsigned long kasumi_lookup_callable(const char *name)
{
	if (kasumi_kallsyms_lookup_name) {
		char jt[256];
		unsigned long addr;

		if (snprintf(jt, sizeof(jt), "%s.cfi_jt", name) < (int)sizeof(jt)) {
			addr = kasumi_kallsyms_lookup_name(jt);
			if (addr && !IS_ERR_VALUE(addr))
				return addr;
		}
	}
	return kasumi_lookup_name(name);
}

KASUMI_NOCFI unsigned long kasumi_lookup_name_quiet(const char *name)
{
	if (kasumi_kallsyms_lookup_name) {
		unsigned long addr = kasumi_kallsyms_lookup_name(name);

		if (addr && !IS_ERR_VALUE(addr))
			return addr;
	}

	{
		struct kprobe kp = { .symbol_name = name };
		unsigned long addr;
		int ret;

		ret = register_kprobe(&kp);
		if (ret < 0)
			return 0;
		addr = (unsigned long)kp.addr;
		unregister_kprobe(&kp);
		if (!addr || IS_ERR_VALUE(addr))
			return 0;
		return addr;
	}
}

/* Quiet variant of kasumi_lookup_callable (no error log on miss). See kasumi_lookup_callable. */
KASUMI_NOCFI unsigned long kasumi_lookup_callable_quiet(const char *name)
{
	if (kasumi_kallsyms_lookup_name) {
		char jt[256];
		unsigned long addr;

		if (snprintf(jt, sizeof(jt), "%s.cfi_jt", name) < (int)sizeof(jt)) {
			addr = kasumi_kallsyms_lookup_name(jt);
			if (addr && !IS_ERR_VALUE(addr))
				return addr;
		}
	}
	return kasumi_lookup_name_quiet(name);
}

void kasumi_resolve_kallsyms_lookup(void)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	int ret;

	pr_alert("Kasumi: resolving kallsyms_lookup_name...\n");
	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_alert("Kasumi: kprobe kallsyms_lookup_name failed: %d, using per-symbol kprobe\n",
			 ret);
		return;
	}
	if (!kasumi_valid_kernel_addr((unsigned long)kp.addr)) {
		pr_alert("Kasumi: kallsyms_lookup_name returned invalid address: 0x%lx\n",
			 (unsigned long)kp.addr);
		unregister_kprobe(&kp);
		return;
	}
	kasumi_kallsyms_lookup_name = (void *)kp.addr;
	unregister_kprobe(&kp);
	pr_alert("Kasumi: kallsyms_lookup_name resolved @ 0x%lx\n",
		 (unsigned long)kasumi_kallsyms_lookup_name);
}

int KASUMI_NOCFI kasumi_entry_capture_source(struct kasumi_entry *entry,
					     const char *source_path)
{
	struct path nofollow_path;
	struct inode *nofollow_inode;
	struct kstat visible_kstat;
	struct path visible_path;
	struct inode *visible_inode;
	struct inode *inode;
	struct path path;
	int ret;

	if (!entry || !source_path || !*source_path)
		return -EINVAL;
	if (entry->source_path_valid)
		return -EALREADY;
	if (!kasumi_kern_path || !kasumi_path_get_ptr || !kasumi_path_put_ptr)
		return -EOPNOTSUPP;

	ret = kasumi_kern_path(source_path, LOOKUP_FOLLOW, &path);
	if (ret)
		return ret;
	inode = d_inode(path.dentry);
	if (!inode) {
		kasumi_path_put(&path);
		return -ENOENT;
	}

	/* char/blk/fifo sources are served by a KASUMI_VNODE_F_SPECIAL wrapper: the
	 * vnode is minted S_IFREG (so it passes may_open_dev on the visible nodev
	 * mount) while its .open delegates to the pinned source via dentry_open
	 * (which bypasses may_open), and getattr projects the real type+rdev.  A
	 * socket has no openable form (sock_no_open -> -ENXIO on the real source
	 * too), so it is always rejected.  When device-source support is disabled,
	 * reject all four rather than admit a rule with no working transport. */
	if (S_ISSOCK(inode->i_mode) ||
	    (!kasumi_device_sources_enabled &&
	     (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode) ||
	      S_ISFIFO(inode->i_mode)))) {
		const char *kind = S_ISCHR(inode->i_mode) ? "character-device" :
				   S_ISBLK(inode->i_mode) ? "block-device" :
				   S_ISFIFO(inode->i_mode) ? "fifo" : "socket";
		pr_warn("Kasumi: rejecting %s source '%s': %s\n", kind, source_path,
			S_ISSOCK(inode->i_mode) ?
				"a socket has no openable vnode form" :
				"char/blk/fifo source support is disabled");
		kasumi_path_put(&path);
		return -EOPNOTSUPP;
	}

	ret = kasumi_identity_source_get(inode->i_sb ? inode->i_sb->s_dev : 0,
					 inode->i_ino, &entry->source_identity);
	if (ret) {
		kasumi_path_put(&path);
		return ret;
	}
	entry->source_path = path;
	kasumi_path_get(&entry->source_path);
	if (S_ISDIR(inode->i_mode)) {
		ret = kasumi_identity_domain_create(entry->source_identity,
			&entry->source_domain);
		if (ret)
			goto fail_identity;
	}
	if (kasumi_d_absolute_path) {
		char *buffer = kmalloc(KSM_MAX_LEN_PATHNAME, GFP_KERNEL);

		if (buffer) {
			char *canonical = kasumi_d_absolute_path(
				&path, buffer, KSM_MAX_LEN_PATHNAME);

			if (!IS_ERR_OR_NULL(canonical) && canonical[0] == '/')
				entry->source_canonical = kstrdup(canonical,
								   GFP_KERNEL);
			kfree(buffer);
		}
	}
	entry->source_inode = inode;
	entry->source_ino = inode->i_ino;
	entry->source_dev = inode->i_sb ? inode->i_sb->s_dev : 0;
	entry->source_mode = inode->i_mode;
	entry->source_uid = inode->i_uid;
	entry->source_gid = inode->i_gid;
	entry->source_size = i_size_read(inode);
	memset(&entry->source_stat, 0, sizeof(entry->source_stat));
	if (kasumi_vfs_getattr &&
	    kasumi_vfs_getattr_unprojected(&path, &entry->source_stat,
			       STATX_BASIC_STATS | STATX_BTIME,
			       AT_STATX_SYNC_AS_STAT) == 0) {
		entry->source_stat_valid = true;
	} else {
		entry->source_stat.result_mask =
			STATX_TYPE | STATX_MODE | STATX_NLINK | STATX_UID |
			STATX_GID | STATX_INO | STATX_SIZE | STATX_BLOCKS;
		entry->source_stat.dev = entry->source_dev;
		entry->source_stat.ino = entry->source_ino;
		entry->source_stat.mode = entry->source_mode;
		entry->source_stat.nlink = inode->i_nlink;
		entry->source_stat.uid = entry->source_uid;
		entry->source_stat.gid = entry->source_gid;
		entry->source_stat.rdev = inode->i_rdev;
		entry->source_stat.size = entry->source_size;
		entry->source_stat.blocks = inode->i_blocks;
		entry->source_stat.blksize = 1U << inode->i_blkbits;
		entry->source_stat_valid = true;
	}
	entry->visible_stat = entry->source_stat;
	entry->visible_stat_valid = entry->source_stat_valid;

	/* Preserve inode identity across rename and hard links without publishing
	 * the captured filesystem's raw dev/ino pair. */
	entry->visible_ino = kasumi_identity_ino(entry->source_identity);
	entry->visible_dev = kasumi_vnode_visible_dev(entry->src);
	if (entry->src &&
	    kasumi_kern_path(entry->src, LOOKUP_FOLLOW, &visible_path) == 0) {
		visible_inode = d_inode(visible_path.dentry);
		if (visible_inode) {
			entry->preserve_visible_metadata = true;
			memset(&visible_kstat, 0, sizeof(visible_kstat));
			if (kasumi_vfs_getattr &&
			    kasumi_vfs_getattr_unprojected(&visible_path,
						     &visible_kstat,
					       STATX_BASIC_STATS | STATX_BTIME,
					       AT_STATX_SYNC_AS_STAT) == 0) {
				entry->visible_stat = visible_kstat;
				/* The virtual node lives at the visible path, but its data
				 * and file kind come from the captured source. Keep visible
				 * ownership, permissions and timestamps while publishing the
				 * source type, size and backing allocation semantics. */
				entry->visible_stat.mode =
					(entry->source_stat.mode & S_IFMT) |
					(visible_kstat.mode & ~S_IFMT);
				entry->visible_stat.rdev = entry->source_stat.rdev;
				entry->visible_stat.size = entry->source_stat.size;
				entry->visible_stat.blocks = entry->source_stat.blocks;
				entry->visible_stat.blksize = entry->source_stat.blksize;
				entry->visible_stat.result_mask |=
					entry->source_stat.result_mask &
					(STATX_TYPE | STATX_MODE | STATX_SIZE |
					 STATX_BLOCKS);
				entry->visible_stat_valid = true;
			} else {
				entry->visible_stat.mode =
					(entry->source_stat.mode & S_IFMT) |
					(visible_inode->i_mode & ~S_IFMT);
				entry->visible_stat.nlink = visible_inode->i_nlink;
				entry->visible_stat.uid = visible_inode->i_uid;
				entry->visible_stat.gid = visible_inode->i_gid;
			}
		}
		kasumi_path_put(&visible_path);
	}
	entry->visible_stat.ino = entry->visible_ino;
	entry->visible_stat.dev = entry->visible_dev;
	if (kasumi_kern_path(source_path, 0, &nofollow_path) == 0) {
		nofollow_inode = d_inode(nofollow_path.dentry);
		if (nofollow_inode && S_ISLNK(nofollow_inode->i_mode)) {
			ret = kasumi_identity_source_get(
				nofollow_inode->i_sb ? nofollow_inode->i_sb->s_dev : 0,
				nofollow_inode->i_ino, &entry->nofollow_identity);
			if (ret) {
				kasumi_path_put(&nofollow_path);
				goto fail_identity;
			}
			entry->source_nofollow_path = nofollow_path;
			kasumi_path_get(&entry->source_nofollow_path);
			entry->source_nofollow_mode = nofollow_inode->i_mode;
			memset(&entry->source_nofollow_stat, 0,
			       sizeof(entry->source_nofollow_stat));
			if (kasumi_vfs_getattr &&
			    kasumi_vfs_getattr_unprojected(&nofollow_path,
					       &entry->source_nofollow_stat,
					       STATX_BASIC_STATS | STATX_BTIME,
					       AT_STATX_SYNC_AS_STAT) == 0) {
				entry->source_nofollow_stat_valid = true;
			} else {
				entry->source_nofollow_stat.result_mask =
					STATX_TYPE | STATX_MODE | STATX_NLINK |
					STATX_UID | STATX_GID | STATX_INO |
					STATX_SIZE | STATX_BLOCKS;
				entry->source_nofollow_stat.dev =
					nofollow_inode->i_sb ?
					nofollow_inode->i_sb->s_dev : 0;
				entry->source_nofollow_stat.ino =
					nofollow_inode->i_ino;
				entry->source_nofollow_stat.mode =
					nofollow_inode->i_mode;
				entry->source_nofollow_stat.nlink =
					nofollow_inode->i_nlink;
				entry->source_nofollow_stat.uid =
					nofollow_inode->i_uid;
				entry->source_nofollow_stat.gid =
					nofollow_inode->i_gid;
				entry->source_nofollow_stat.size =
					i_size_read(nofollow_inode);
				entry->source_nofollow_stat.blocks =
					nofollow_inode->i_blocks;
				entry->source_nofollow_stat.blksize =
					1U << nofollow_inode->i_blkbits;
				entry->source_nofollow_stat_valid = true;
			}
			entry->nofollow_visible_ino = kasumi_identity_ino(entry->nofollow_identity);
			entry->nofollow_visible_dev =
				kasumi_vnode_visible_dev(entry->src);
			entry->source_nofollow_stat.ino =
				entry->nofollow_visible_ino;
			entry->source_nofollow_stat.dev =
				entry->nofollow_visible_dev;
			entry->source_nofollow_path_valid = true;
		}
		kasumi_path_put(&nofollow_path);
	}
	ret = kasumi_iop_get(&entry->source_path);
	if (ret)
		goto fail_identity;
	entry->source_iop_owned = true;
	if (entry->source_nofollow_path_valid) {
		ret = kasumi_iop_get(&entry->source_nofollow_path);
		if (ret)
			goto fail_identity;
		entry->nofollow_iop_owned = true;
	}
	entry->source_path_valid = true;
	atomic64_inc(&kasumi_vnode_allocated_count);
	atomic_inc(&kasumi_vnode_live_count);
	kasumi_path_put(&path);
	return 0;
fail_identity:
	if (entry->source_iop_owned) {
		kasumi_iop_put(&entry->source_path);
		entry->source_iop_owned = false;
	}
	if (entry->nofollow_iop_owned) {
		kasumi_iop_put(&entry->source_nofollow_path);
		entry->nofollow_iop_owned = false;
	}
	if (entry->source_nofollow_path_valid) {
		kasumi_path_put(&entry->source_nofollow_path);
		memset(&entry->source_nofollow_path, 0, sizeof(entry->source_nofollow_path));
		entry->source_nofollow_path_valid = false;
	}
	kasumi_identity_put(entry->nofollow_identity);
	entry->nofollow_identity = NULL;
	kasumi_path_put(&entry->source_path);
	memset(&entry->source_path, 0, sizeof(entry->source_path));
	entry->source_inode = NULL;
	kasumi_identity_domain_put(entry->source_domain);
	entry->source_domain = NULL;
	kasumi_identity_put(entry->source_identity);
	entry->source_identity = NULL;
	kfree(entry->source_canonical);
	entry->source_canonical = NULL;
	kasumi_path_put(&path);
	return ret;
}

void KASUMI_NOCFI kasumi_entry_release_source(struct kasumi_entry *entry)
{
	if (!entry || !entry->source_path_valid)
		return;

	if (entry->source_iop_owned) {
		kasumi_iop_put(&entry->source_path);
		entry->source_iop_owned = false;
	}
	if (entry->nofollow_iop_owned) {
		kasumi_iop_put(&entry->source_nofollow_path);
		entry->nofollow_iop_owned = false;
	}
	entry->source_path_valid = false;
	atomic_dec(&kasumi_vnode_live_count);
	kasumi_path_put(&entry->source_path);
	memset(&entry->source_path, 0, sizeof(entry->source_path));
	if (entry->source_nofollow_path_valid) {
		entry->source_nofollow_path_valid = false;
		kasumi_path_put(&entry->source_nofollow_path);
		memset(&entry->source_nofollow_path, 0,
		       sizeof(entry->source_nofollow_path));
	}
	entry->source_inode = NULL;
	kasumi_identity_domain_put(entry->source_domain);
	entry->source_domain = NULL;
	kasumi_identity_put(entry->source_identity);
	kasumi_identity_put(entry->nofollow_identity);
	entry->source_identity = NULL;
	entry->nofollow_identity = NULL;
}

static void kasumi_entry_destroy(struct kasumi_entry *e)
{

	kasumi_entry_release_source(e);
	kfree(e->src);
	kfree(e->target);
	kfree(e->source_canonical);
	kfree(e);
}

void kasumi_hide_entry_free_rcu(struct rcu_head *head)
{
	struct kasumi_hide_entry *e = container_of(head, struct kasumi_hide_entry, rcu);

	kfree(e->path);
	kfree(e);
}

void kasumi_inject_entry_free_rcu(struct rcu_head *head)
{
	struct kasumi_inject_entry *e = container_of(head, struct kasumi_inject_entry, rcu);

	kfree(e->dir);
	kfree(e);
}

void kasumi_xattr_sb_entry_free_rcu(struct rcu_head *head)
{
	struct kasumi_xattr_sb_entry *entry =
		container_of(head, struct kasumi_xattr_sb_entry, rcu);

	kasumi_overlay_xattr_retire(entry);
}

static void kasumi_merge_entry_destroy(struct kasumi_merge_entry *e)
{

	if (e->target_dentry)
		dput(e->target_dentry);
	kfree(e->src);
	kfree(e->target);
	kfree(e->resolved_src);
	kfree(e);
}

static void kasumi_spoof_kstat_entry_destroy(struct kasumi_spoof_kstat_entry *entry)
{
	if (entry->iop_owned)
		kasumi_iop_put(&entry->captured_path);
	if (entry->captured_path.dentry)
		kasumi_path_put(&entry->captured_path);
	kfree(entry->target_pathname);
	kfree(entry);
}

static LLIST_HEAD(kasumi_kstats_to_free);
static LLIST_HEAD(kasumi_entries_to_free);
static LLIST_HEAD(kasumi_merges_to_free);

static void kasumi_store_free_workfn(struct work_struct *work)
{
	struct llist_node *head, *node, *next;

	kasumi_iop_retire_batch_begin();
	while ((head = llist_del_all(&kasumi_entries_to_free))) {
		llist_for_each_safe(node, next, head)
			kasumi_entry_destroy(container_of(
				node, struct kasumi_entry, free_node));
	}
	while ((head = llist_del_all(&kasumi_merges_to_free))) {
		llist_for_each_safe(node, next, head)
			kasumi_merge_entry_destroy(container_of(
				node, struct kasumi_merge_entry, free_node));
	}
	while ((head = llist_del_all(&kasumi_kstats_to_free))) {
		llist_for_each_safe(node, next, head)
			kasumi_spoof_kstat_entry_destroy(container_of(
				node, struct kasumi_spoof_kstat_entry, free_node));
	}
	kasumi_iop_retire_batch_end();
}

static DECLARE_WORK(kasumi_store_free_work, kasumi_store_free_workfn);

void kasumi_entry_free_rcu(struct rcu_head *head)
{
	struct kasumi_entry *entry = container_of(head, struct kasumi_entry, rcu);

	llist_add(&entry->free_node, &kasumi_entries_to_free);
	schedule_work(&kasumi_store_free_work);
}

void kasumi_merge_entry_free_rcu(struct rcu_head *head)
{
	struct kasumi_merge_entry *entry =
		container_of(head, struct kasumi_merge_entry, rcu);

	llist_add(&entry->free_node, &kasumi_merges_to_free);
	schedule_work(&kasumi_store_free_work);
}

void kasumi_store_drain(void)
{
	rcu_barrier();
	flush_work(&kasumi_store_free_work);
	kasumi_iop_override_drain();
}


void kasumi_spoof_kstat_entry_free_rcu(struct rcu_head *head)
{
	struct kasumi_spoof_kstat_entry *e =
		container_of(head, struct kasumi_spoof_kstat_entry, rcu);

	llist_add(&e->free_node, &kasumi_kstats_to_free);
	schedule_work(&kasumi_store_free_work);
}

struct kasumi_spoof_kstat_entry *kasumi_spoof_kstat_lookup_by_path(const char *path_str)
{
	struct kasumi_spoof_kstat_entry *e;
	u32 hash;
	u64 generation = kasumi_batch_generation() ?: kasumi_rules_generation();

	if (!path_str || !*path_str)
		return NULL;
	hash = full_name_hash(NULL, path_str, strlen(path_str));
	hlist_for_each_entry_rcu(e,
		&kasumi_spoof_kstat_path[hash_min(hash, KASUMI_HASH_BITS)], path_node) {
		if (kasumi_rule_visible(&e->life, generation) &&
		    e->path_hash == hash && e->target_pathname &&
		    strcmp(e->target_pathname, path_str) == 0)
			return e;
	}
	return NULL;
}

struct kasumi_spoof_kstat_entry *
kasumi_spoof_kstat_lookup_by_ino(unsigned long ino, unsigned long dev)
{
	struct kasumi_spoof_kstat_entry *entry, *wildcard = NULL;
	u64 generation = kasumi_rules_generation();

	if (!ino)
		return NULL;
	hlist_for_each_entry_rcu(entry,
		&kasumi_spoof_kstat_ino[hash_min(ino, KASUMI_HASH_BITS)],
		ino_node) {
		if (!kasumi_rule_visible(&entry->life, generation) ||
		    entry->target_ino != ino)
			continue;
		if (entry->target_dev_valid && entry->target_dev == dev)
			return entry;
		if (!entry->target_dev_valid)
			wildcard = entry;
	}
	return wildcard;
}

int kasumi_spoof_kstat_validate(const struct kasumi_transaction_kstat_rule *rule)
{
	if (!memchr(rule->target_pathname, '\0', sizeof(rule->target_pathname)))
		return -ENAMETOOLONG;
	if ((!rule->target_pathname[0] && !rule->target_ino) ||
	    (rule->target_pathname[0] && rule->target_pathname[0] != '/') ||
	    (rule->fields & ~KSM_KSTAT_FIELDS_ALL) ||
	    (rule->match_flags & ~KSM_MATCH_ANY_DEVICE) ||
	    rule->target_dev > U32_MAX || rule->spoofed_dev > U32_MAX ||
	    rule->spoofed_nlink > U32_MAX || rule->spoofed_blksize > U32_MAX)
		return -EINVAL;
	if (((rule->fields & KSM_KSTAT_FIELD_ATIME) && rule->spoofed_atime_nsec >= NSEC_PER_SEC) ||
	    ((rule->fields & KSM_KSTAT_FIELD_MTIME) && rule->spoofed_mtime_nsec >= NSEC_PER_SEC) ||
	    ((rule->fields & KSM_KSTAT_FIELD_CTIME) && rule->spoofed_ctime_nsec >= NSEC_PER_SEC))
		return -EINVAL;
	return 0;
}

int kasumi_spoof_kstat_stage(const struct kasumi_transaction_kstat_rule *rule,
			   u64 *resolved_ino)
{
	struct kasumi_spoof_kstat_entry *entry, *old = NULL;
	struct kasumi_internal_vfs_guard guard;
	struct path path;
	u64 generation = kasumi_batch_generation();
	int ret = kasumi_spoof_kstat_validate(rule);
	bool have_path = rule->target_pathname[0] != '\0';

	if (ret)
		return ret;
	if (!generation)
		return -EINVAL;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	entry->life.first_generation = generation;
	entry->fields = rule->fields;
	entry->target_ino = rule->target_ino;
	entry->target_dev = rule->target_dev;
	entry->target_dev_valid = !(rule->match_flags & KSM_MATCH_ANY_DEVICE);
	if (have_path) {
		entry->target_pathname = kstrdup(rule->target_pathname, GFP_KERNEL);
		if (!entry->target_pathname) {
			ret = -ENOMEM;
			goto free_entry;
		}
		entry->path_hash = full_name_hash(NULL, entry->target_pathname,
						 strlen(entry->target_pathname));
		kasumi_vfs_internal_enter(&guard);
#ifdef KASUMI_EMBEDDED
		ret = kern_path(entry->target_pathname, LOOKUP_FOLLOW, &path);
#else
		ret = kasumi_kern_path ?
		      kasumi_kern_path(entry->target_pathname, LOOKUP_FOLLOW, &path) :
		      -EOPNOTSUPP;
#endif
		kasumi_vfs_internal_leave(&guard);
		if (!ret) {
			struct inode *inode = d_inode(path.dentry);

			entry->target_ino = inode->i_ino;
			entry->target_dev = inode->i_sb->s_dev;
			entry->target_dev_valid = true;
			entry->captured_path = path;
			ret = kasumi_iop_get(&entry->captured_path);
			entry->iop_owned = !ret;
			if (ret)
				goto free_entry;
		} else if (ret != -ENOENT && ret != -ENOTDIR) {
			goto free_entry;
		}
	}
	entry->spoofed_ino = rule->spoofed_ino;
	entry->spoofed_dev = rule->spoofed_dev;
	entry->spoofed_nlink = rule->spoofed_nlink;
	entry->spoofed_size = rule->spoofed_size;
	entry->spoofed_atime_sec = rule->spoofed_atime_sec;
	entry->spoofed_atime_nsec = rule->spoofed_atime_nsec;
	entry->spoofed_mtime_sec = rule->spoofed_mtime_sec;
	entry->spoofed_mtime_nsec = rule->spoofed_mtime_nsec;
	entry->spoofed_ctime_sec = rule->spoofed_ctime_sec;
	entry->spoofed_ctime_nsec = rule->spoofed_ctime_nsec;
	entry->spoofed_blksize = rule->spoofed_blksize;
	entry->spoofed_blocks = rule->spoofed_blocks;

	mutex_lock(&kasumi_config_mutex);
	if (have_path) {
		rcu_read_lock();
		old = kasumi_spoof_kstat_lookup_by_path(entry->target_pathname);
		rcu_read_unlock();
	} else {
		struct kasumi_spoof_kstat_entry *candidate;

		hlist_for_each_entry(candidate,
			&kasumi_spoof_kstat_ino[hash_min(entry->target_ino,
						       KASUMI_HASH_BITS)], ino_node) {
			if (kasumi_rule_visible(&candidate->life, generation) &&
			    candidate->target_ino == entry->target_ino &&
			    !candidate->target_pathname &&
			    candidate->target_dev_valid == entry->target_dev_valid &&
			    (!entry->target_dev_valid || candidate->target_dev == entry->target_dev)) {
				old = candidate;
				break;
			}
		}
	}
	kasumi_batch_track(&entry->life, KASUMI_BATCH_KSTAT);
	if (have_path)
		hlist_add_head_rcu(&entry->path_node,
			&kasumi_spoof_kstat_path[hash_min(entry->path_hash, KASUMI_HASH_BITS)]);
	if (entry->target_ino)
		hlist_add_head_rcu(&entry->ino_node,
			&kasumi_spoof_kstat_ino[hash_min(entry->target_ino, KASUMI_HASH_BITS)]);
	if (old)
		kasumi_batch_expire(&old->life, KASUMI_BATCH_KSTAT);
	atomic_inc(&kasumi_spoof_kstat_count);
	if (resolved_ino)
		*resolved_ino = entry->target_ino;
	mutex_unlock(&kasumi_config_mutex);
	return 0;

free_entry:
	kasumi_spoof_kstat_entry_destroy(entry);
	return ret;
}

int kasumi_spoof_kstat_upsert(struct kasumi_spoof_kstat *rule)
{
	struct kasumi_transaction_kstat_rule value = {};
	struct kasumi_batch *batch;
	u64 resolved_ino = 0;
	int error;

	value.match_flags = KSM_MATCH_ANY_DEVICE;
	value.target_ino = rule->target_ino;
	memcpy(value.target_pathname, rule->target_pathname, sizeof(value.target_pathname));
	value.spoofed_ino = rule->spoofed_ino;
	if (rule->spoofed_ino)
		value.fields |= KSM_KSTAT_FIELD_INO;
	value.spoofed_dev = rule->spoofed_dev;
	if (rule->spoofed_dev)
		value.fields |= KSM_KSTAT_FIELD_DEV;
	value.spoofed_nlink = rule->spoofed_nlink;
	if (rule->spoofed_nlink)
		value.fields |= KSM_KSTAT_FIELD_NLINK;
	value.spoofed_size = rule->spoofed_size;
	if (rule->spoofed_size)
		value.fields |= KSM_KSTAT_FIELD_SIZE;
	value.spoofed_blksize = rule->spoofed_blksize;
	if (rule->spoofed_blksize)
		value.fields |= KSM_KSTAT_FIELD_BLKSIZE;
	value.spoofed_blocks = rule->spoofed_blocks;
	if (rule->spoofed_blocks)
		value.fields |= KSM_KSTAT_FIELD_BLOCKS;
	value.spoofed_atime_sec = rule->spoofed_atime_sec;
	value.spoofed_atime_nsec = rule->spoofed_atime_nsec;
	if (rule->spoofed_atime_sec || rule->spoofed_atime_nsec)
		value.fields |= KSM_KSTAT_FIELD_ATIME;
	value.spoofed_mtime_sec = rule->spoofed_mtime_sec;
	value.spoofed_mtime_nsec = rule->spoofed_mtime_nsec;
	if (rule->spoofed_mtime_sec || rule->spoofed_mtime_nsec)
		value.fields |= KSM_KSTAT_FIELD_MTIME;
	value.spoofed_ctime_sec = rule->spoofed_ctime_sec;
	value.spoofed_ctime_nsec = rule->spoofed_ctime_nsec;
	if (rule->spoofed_ctime_sec || rule->spoofed_ctime_nsec)
		value.fields |= KSM_KSTAT_FIELD_CTIME;
	batch = kasumi_batch_begin();
	if (IS_ERR(batch))
		return PTR_ERR(batch);
	error = kasumi_spoof_kstat_stage(&value, &resolved_ino);
	kasumi_batch_finish(batch, !error);
	if (!error)
		rule->target_ino = resolved_ino;
	return error;
}

void kasumi_mark_inode_hidden(struct inode *inode)
{
	if (inode && inode->i_mapping)
		set_bit(AS_FLAGS_KASUMI_HIDE, &inode->i_mapping->flags);
}

bool kasumi_is_inode_hidden_bit(struct inode *inode)
{
	if (!inode || !inode->i_mapping)
		return false;
	return test_bit(AS_FLAGS_KASUMI_HIDE, &inode->i_mapping->flags);
}



KASUMI_NOCFI void kasumi_clear_inode_flags_for_path(const char *path_str,
					    unsigned int bit)
{
	struct path p;

	if (!path_str || !kasumi_kern_path)
		return;
	if (kasumi_kern_path(path_str,
			     bit == AS_FLAGS_KASUMI_HIDE ? 0 : LOOKUP_FOLLOW,
			     &p) != 0)
		return;
	if (p.dentry && d_inode(p.dentry) && d_inode(p.dentry)->i_mapping)
		clear_bit(bit, &d_inode(p.dentry)->i_mapping->flags);
	kasumi_path_put(&p);
}

static u64 kasumi_rule_sequence;

int kasumi_rule_sequence_alloc(u64 *sequence)
{
	int ret = 0;

	mutex_lock(&kasumi_config_mutex);
	if (kasumi_rule_sequence == U64_MAX)
		ret = -EOVERFLOW;
	else
		*sequence = ++kasumi_rule_sequence;
	mutex_unlock(&kasumi_config_mutex);
	return ret;
}

int kasumi_store_upsert(struct kasumi_entry *replacement)
{
	struct kasumi_entry *entry, *old = NULL;
	u32 hash = replacement->src_hash;
	u64 batch_generation = kasumi_batch_generation();
	u64 generation = batch_generation ? batch_generation :
			 kasumi_rules_generation();
	bool changed = true;
	unsigned long h1, h2;

	replacement->life.first_generation = batch_generation;
	mutex_lock(&kasumi_config_mutex);
	if (kasumi_rule_sequence == U64_MAX) {
		mutex_unlock(&kasumi_config_mutex);
		return -EOVERFLOW;
	}
	replacement->sequence = ++kasumi_rule_sequence;
	hlist_for_each_entry(entry,
		&kasumi_paths[hash_min(hash, KASUMI_HASH_BITS)], node) {
		if (!kasumi_rule_visible(&entry->life, generation) ||
		    entry->src_hash != hash ||
		    strcmp(entry->src, replacement->src))
			continue;
		old = entry;
		changed = strcmp(entry->target, replacement->target) != 0;
		break;
	}
	if (old && batch_generation)
		kasumi_batch_expire(&old->life, KASUMI_BATCH_PATH);
	kasumi_batch_track(&replacement->life, KASUMI_BATCH_PATH);
	hlist_add_head_rcu(&replacement->node,
		&kasumi_paths[hash_min(hash, KASUMI_HASH_BITS)]);
#ifndef KASUMI_EMBEDDED
	hlist_add_head_rcu(&replacement->target_node,
		&kasumi_targets[hash_min(
			full_name_hash(NULL, replacement->target,
				       strlen(replacement->target)),
			KASUMI_HASH_BITS)]);
#endif
	if (old && !batch_generation) {
		hlist_del_rcu(&old->node);
#ifndef KASUMI_EMBEDDED
		hlist_del_rcu(&old->target_node);
#endif
		if (changed)
			kasumi_clear_inode_flags_for_path(
				old->target, AS_FLAGS_KASUMI_SPOOF_KSTAT);
		kasumi_rule_index_remove(&old->life);
		kasumi_live_rules_untrack(&old->life);
		call_rcu(&old->rcu, kasumi_entry_free_rcu);
	} else {
		atomic_inc(&kasumi_rule_count);
	}
	h1 = jhash(replacement->src, strlen(replacement->src), 0) &
	     (KASUMI_BLOOM_SIZE - 1);
	h2 = jhash(replacement->src, strlen(replacement->src), 1) &
	     (KASUMI_BLOOM_SIZE - 1);
	set_bit(h1, kasumi_path_bloom);
	set_bit(h2, kasumi_path_bloom);
	mutex_unlock(&kasumi_config_mutex);
	return changed;
}

void kasumi_cleanup_locked(void)
{
	struct kasumi_entry *entry;
	struct kasumi_hide_entry *hide_entry;
	struct kasumi_inject_entry *inject_entry;
	struct kasumi_xattr_sb_entry *sb_entry;
	struct kasumi_merge_entry *merge_entry;
	struct hlist_node *tmp;
	int bkt;

	/* Pair with policy readers before cleanup withdraws provider state. */
	smp_store_release(&kasumi_enabled, false);
	kasumi_stealth_enabled = false;
	kasumi_feature_enabled_mask = 0;
	/* Stop provider calls and release any external module reference. */
	kasumi_policy_disable_provider_locked();

	hash_for_each_safe(kasumi_paths, bkt, tmp, entry, node) {
		kasumi_clear_inode_flags_for_path(entry->src, AS_FLAGS_KASUMI_HIDE);
		kasumi_clear_inode_flags_for_path(entry->target, AS_FLAGS_KASUMI_SPOOF_KSTAT);
		hlist_del_rcu(&entry->node);
		hlist_del_rcu(&entry->target_node);
		kasumi_rule_index_remove(&entry->life);
		kasumi_live_rules_untrack(&entry->life);
		call_rcu(&entry->rcu, kasumi_entry_free_rcu);
	}
	hash_for_each_safe(kasumi_hide_paths, bkt, tmp, hide_entry, node) {
		kasumi_clear_inode_flags_for_path(hide_entry->path, AS_FLAGS_KASUMI_HIDE);
		hlist_del_rcu(&hide_entry->node);
		kasumi_rule_index_remove(&hide_entry->life);
		kasumi_live_rules_untrack(&hide_entry->life);
		call_rcu(&hide_entry->rcu, kasumi_hide_entry_free_rcu);
	}
	hash_for_each_safe(kasumi_inject_dirs, bkt, tmp, inject_entry, node) {
		kasumi_fop_put(inject_entry->fop_inode, true);
		inject_entry->fop_inode = NULL;
		hlist_del_rcu(&inject_entry->node);
		call_rcu(&inject_entry->rcu, kasumi_inject_entry_free_rcu);
	}
	hash_for_each_safe(kasumi_xattr_sbs, bkt, tmp, sb_entry, node) {
		hlist_del_rcu(&sb_entry->node);
		call_rcu(&sb_entry->rcu, kasumi_xattr_sb_entry_free_rcu);
	}
	hash_for_each_safe(kasumi_merge_dirs, bkt, tmp, merge_entry, node) {
		hlist_del_rcu(&merge_entry->node);
		kasumi_rule_index_remove(&merge_entry->life);
		kasumi_live_rules_untrack(&merge_entry->life);
		call_rcu(&merge_entry->rcu, kasumi_merge_entry_free_rcu);
	}
	{
		struct kasumi_spoof_kstat_entry *sk_entry;

		hash_for_each_safe(kasumi_spoof_kstat_path, bkt, tmp, sk_entry, path_node) {
			kasumi_clear_inode_flags_for_path(sk_entry->target_pathname,
							AS_FLAGS_KASUMI_SPOOF_KSTAT);
			hlist_del_rcu(&sk_entry->path_node);
			if (sk_entry->target_ino)
				hlist_del_rcu(&sk_entry->ino_node);
			call_rcu(&sk_entry->rcu, kasumi_spoof_kstat_entry_free_rcu);
		}
		hash_for_each_safe(kasumi_spoof_kstat_ino, bkt, tmp, sk_entry, ino_node) {
			hlist_del_rcu(&sk_entry->ino_node);
			call_rcu(&sk_entry->rcu, kasumi_spoof_kstat_entry_free_rcu);
		}
		atomic_set(&kasumi_spoof_kstat_count, 0);
	}


	kasumi_maps_rules_clear();

	bitmap_zero(kasumi_path_bloom, KASUMI_BLOOM_SIZE);
	bitmap_zero(kasumi_hide_bloom, KASUMI_BLOOM_SIZE);
	atomic_set(&kasumi_rule_count, 0);
	atomic_set(&kasumi_hide_count, 0);
}
