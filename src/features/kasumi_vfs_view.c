#include "kasumi_vfs_view.h"
#include "kasumi_batch.h"
#include "kasumi_entrypoints.h"
#include "kasumi_mount_view.h"
#include "kasumi_runtime.h"
#include "kasumi_store.h"
#include "kasumi_xattr_filter.h"
#include "kasumi_vnode.h"

#include <linux/cred.h>
#include <linux/fs_struct.h>
#include <linux/hashtable.h>
#include <linux/kprobes.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/nsproxy.h>
#include <linux/rcupdate.h>
#include <linux/rwsem.h>
#include <linux/sched/signal.h>
#include <linux/seq_file.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/statfs.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/xattr.h>
#include <uapi/linux/magic.h>
#include <fs/mount.h>

struct kasumi_view_guard {
	struct task_struct *task;
	struct hlist_node node;
};

static DEFINE_HASHTABLE(kasumi_view_guards, 6);
static spinlock_t kasumi_view_guard_locks[HASH_SIZE(kasumi_view_guards)] = {
	[0 ... HASH_SIZE(kasumi_view_guards) - 1] =
		__SPIN_LOCK_UNLOCKED(kasumi_view_guard_locks),
};
static atomic_t kasumi_view_active = ATOMIC_INIT(0);
static atomic_t kasumi_xattr_owned = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(kasumi_view_wait);
static bool kasumi_view_stopped = true;
static void (*kasumi_view_tasks_barrier)(void);
static bool kasumi_xattr_ready;
static bool kasumi_source_xattr_ready;
static bool kasumi_statfs_ready;
static struct workqueue_struct *kasumi_xattr_wq;
static struct rw_semaphore *kasumi_statfs_namespace_lock;
static int (*kasumi_view_statfs_orig)(const struct path *, struct kstatfs *);
static ssize_t (*kasumi_view_listxattr_orig)(struct dentry *, char *, size_t);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
#define KASUMI_XATTR_IDMAP_ARG struct mnt_idmap *idmap,
#define KASUMI_XATTR_IDMAP_CALL idmap,
#define KASUMI_XATTR_SOURCE_IDMAP(mnt) mnt_idmap(mnt),
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
#define KASUMI_XATTR_IDMAP_ARG struct user_namespace *idmap,
#define KASUMI_XATTR_IDMAP_CALL idmap,
#define KASUMI_XATTR_SOURCE_IDMAP(mnt) mnt_user_ns(mnt),
#else
#define KASUMI_XATTR_IDMAP_ARG
#define KASUMI_XATTR_IDMAP_CALL
#define KASUMI_XATTR_SOURCE_IDMAP(mnt)
#endif
static typeof(vfs_getxattr) *kasumi_view_getxattr_orig;
static typeof(vfs_setxattr) *kasumi_view_setxattr_orig;
static typeof(vfs_removexattr) *kasumi_view_removexattr_orig;
static typeof(mnt_want_write) *kasumi_view_want_write;
static typeof(mnt_drop_write) *kasumi_view_drop_write;
static int (*kasumi_view_xattr_permission)(KASUMI_XATTR_IDMAP_ARG
	struct inode *, const char *, int);
static typeof(security_inode_getxattr) *kasumi_view_security_get;
static typeof(security_inode_listxattr) *kasumi_view_security_list;
static typeof(security_inode_setxattr) *kasumi_view_security_set;
static typeof(security_inode_removexattr) *kasumi_view_security_remove;
static struct kprobe kasumi_view_get_probe;
static struct kprobe kasumi_view_list_probe;
static struct kprobe kasumi_view_set_probe;
static struct kprobe kasumi_view_remove_probe;
static struct kprobe kasumi_view_statfs_probe;
static bool kasumi_view_get_registered;
static bool kasumi_view_list_registered;
static bool kasumi_view_set_registered;
static bool kasumi_view_remove_registered;
static bool kasumi_view_statfs_registered;

static bool kasumi_view_guarded(void)
{
	spinlock_t *lock = &kasumi_view_guard_locks[
		hash_min((unsigned long)current, HASH_BITS(kasumi_view_guards))];
	struct kasumi_view_guard *guard;
	unsigned long flags;
	bool found = false;

	spin_lock_irqsave(lock, flags);
	hash_for_each_possible(kasumi_view_guards, guard, node,
			       (unsigned long)current)
	{
		if (guard->task == current) {
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(lock, flags);
	return found;
}

static void kasumi_view_enter(struct kasumi_view_guard *guard)
{
	spinlock_t *lock = &kasumi_view_guard_locks[
		hash_min((unsigned long)current, HASH_BITS(kasumi_view_guards))];
	unsigned long flags;

	guard->task = current;
	spin_lock_irqsave(lock, flags);
	hash_add(kasumi_view_guards, &guard->node, (unsigned long)current);
	spin_unlock_irqrestore(lock, flags);
}

static void kasumi_view_leave(struct kasumi_view_guard *guard)
{
	spinlock_t *lock = &kasumi_view_guard_locks[
		hash_min((unsigned long)guard->task, HASH_BITS(kasumi_view_guards))];
	unsigned long flags;

	spin_lock_irqsave(lock, flags);
	hash_del(&guard->node);
	spin_unlock_irqrestore(lock, flags);
	if (atomic_dec_and_test(&kasumi_view_active))
		wake_up_all(&kasumi_view_wait);
}

static bool kasumi_xattr_target(struct dentry *dentry)
{
	struct kasumi_xattr_sb_entry *entry;
	bool found = false;
	u64 generation = kasumi_rules_generation();

	if (!READ_ONCE(kasumi_xattr_ready) || !dentry || !dentry->d_sb ||
	    !kasumi_policy_current_is_spoof_target())
		return false;
	rcu_read_lock();
	hash_for_each_possible_rcu(kasumi_xattr_sbs, entry, node,
				   (unsigned long)dentry->d_sb)
	{
		if (entry->sb == dentry->d_sb &&
		    kasumi_rule_visible(&entry->life, generation)) {
			found = true;
			break;
		}
	}
	rcu_read_unlock();
	return found;
}

static KASUMI_NOCFI ssize_t kasumi_view_getxattr(KASUMI_XATTR_IDMAP_ARG
	struct dentry *dentry, const char *name, void *value, size_t size)
{
	struct kasumi_view_guard guard;
	struct kasumi_internal_vfs_guard source_guard;
	struct path source = {};
	struct dentry *data = dentry;
	ssize_t ret;
	int handled;

	kasumi_view_enter(&guard);
	handled = READ_ONCE(kasumi_source_xattr_ready) ?
		kasumi_vnode_source_path(dentry, &source) : 0;
	if (handled < 0) {
		ret = handled;
		goto out;
	}
	if (handled) {
		ret = kasumi_view_xattr_permission(KASUMI_XATTR_IDMAP_CALL
			d_inode(dentry), name, MAY_READ);
		if (!ret)
			ret = kasumi_view_security_get(dentry, name);
		if (ret)
			goto out;
		data = source.dentry;
		kasumi_vfs_internal_enter(&source_guard);
		ret = kasumi_view_getxattr_orig(KASUMI_XATTR_SOURCE_IDMAP(source.mnt)
			data, name, value, size);
		kasumi_vfs_internal_leave(&source_guard);
	} else {
		ret = kasumi_view_getxattr_orig(KASUMI_XATTR_IDMAP_CALL
			dentry, name, value, size);
	}
	if ((ret >= 0 || ret == -ERANGE) && kasumi_overlay_name(name) &&
	    (kasumi_xattr_target(dentry) || (handled && kasumi_xattr_target(data))))
		ret = -ENODATA;
out:
	if (source.dentry)
		path_put(&source);
	kasumi_view_leave(&guard);
	return ret;
}

static KASUMI_NOCFI int kasumi_view_setxattr(KASUMI_XATTR_IDMAP_ARG
	struct dentry *dentry, const char *name, const void *value, size_t size, int flags)
{
	struct kasumi_view_guard guard;
	struct kasumi_internal_vfs_guard source_guard;
	struct path source = {};
	int handled, ret;

	kasumi_view_enter(&guard);
	handled = kasumi_vnode_source_path(dentry, &source);
	if (handled <= 0) {
		ret = handled ?: kasumi_view_setxattr_orig(KASUMI_XATTR_IDMAP_CALL
			dentry, name, value, size, flags);
		goto out;
	}
	ret = kasumi_view_xattr_permission(KASUMI_XATTR_IDMAP_CALL
		d_inode(dentry), name, MAY_WRITE);
	if (!ret)
		ret = kasumi_view_security_set(KASUMI_XATTR_IDMAP_CALL
			dentry, name, value, size, flags);
	if (ret)
		goto out;
	ret = kasumi_view_want_write(source.mnt);
	if (ret)
		goto out;
	kasumi_vfs_internal_enter(&source_guard);
	ret = kasumi_view_setxattr_orig(KASUMI_XATTR_SOURCE_IDMAP(source.mnt)
		source.dentry, name, value, size, flags);
	kasumi_vfs_internal_leave(&source_guard);
	kasumi_view_drop_write(source.mnt);
	if (!ret && !strcmp(name, "security.selinux"))
		ret = kasumi_vnode_refresh_label(dentry);
out:
	if (source.dentry)
		path_put(&source);
	kasumi_view_leave(&guard);
	return ret;
}

static KASUMI_NOCFI int kasumi_view_removexattr(KASUMI_XATTR_IDMAP_ARG
	struct dentry *dentry, const char *name)
{
	struct kasumi_view_guard guard;
	struct kasumi_internal_vfs_guard source_guard;
	struct path source = {};
	int handled, ret;

	kasumi_view_enter(&guard);
	handled = kasumi_vnode_source_path(dentry, &source);
	if (handled <= 0) {
		ret = handled ?: kasumi_view_removexattr_orig(KASUMI_XATTR_IDMAP_CALL
			dentry, name);
		goto out;
	}
	ret = kasumi_view_xattr_permission(KASUMI_XATTR_IDMAP_CALL
		d_inode(dentry), name, MAY_WRITE);
	if (!ret)
		ret = kasumi_view_security_remove(KASUMI_XATTR_IDMAP_CALL dentry, name);
	if (ret)
		goto out;
	ret = kasumi_view_want_write(source.mnt);
	if (ret)
		goto out;
	kasumi_vfs_internal_enter(&source_guard);
	ret = kasumi_view_removexattr_orig(KASUMI_XATTR_SOURCE_IDMAP(source.mnt)
		source.dentry, name);
	kasumi_vfs_internal_leave(&source_guard);
	kasumi_view_drop_write(source.mnt);
	if (!ret && !strcmp(name, "security.selinux"))
		ret = kasumi_vnode_refresh_label(dentry);
out:
	if (source.dentry)
		path_put(&source);
	kasumi_view_leave(&guard);
	return ret;
}

static KASUMI_NOCFI ssize_t kasumi_view_listxattr(struct dentry *dentry,
						  char *list, size_t size)
{
	struct kasumi_view_guard guard;
	struct kasumi_internal_vfs_guard source_guard;
	struct path source = {};
	struct dentry *data = dentry;
	char *buffer = NULL;
	size_t output;
	ssize_t needed, ret;
	unsigned int attempt;
	int handled;
	bool filter, source_active = false;

	kasumi_view_enter(&guard);
	handled = READ_ONCE(kasumi_source_xattr_ready) ?
		kasumi_vnode_source_path(dentry, &source) : 0;
	if (handled < 0) {
		ret = handled;
		goto out;
	}
	if (handled) {
		ret = kasumi_view_security_list(dentry);
		if (ret)
			goto out;
		data = source.dentry;
	}
	filter = kasumi_xattr_target(dentry) || (handled && kasumi_xattr_target(data));
	if (handled) {
		kasumi_vfs_internal_enter(&source_guard);
		source_active = true;
	}
	if (!filter) {
		ret = kasumi_view_listxattr_orig(data, list, size);
		goto out;
	}
	for (attempt = 0; attempt < 3; attempt++) {
		needed = kasumi_view_listxattr_orig(data, NULL, 0);
		if (needed <= 0) {
			ret = needed;
			goto out;
		}
		if (needed > XATTR_LIST_MAX) {
			ret = -E2BIG;
			goto out;
		}
		buffer = kvmalloc(needed, GFP_KERNEL);
		if (!buffer) {
			ret = -ENOMEM;
			goto out;
		}
		ret = kasumi_view_listxattr_orig(data, buffer, needed);
		if (ret != -ERANGE)
			break;
		kvfree(buffer);
		buffer = NULL;
	}
	if (ret < 0)
		goto out;
	if (ret > needed) {
		ret = -EOVERFLOW;
		goto out;
	}
	ret = kasumi_xattr_filter_list(buffer, ret);
	if (ret < 0)
		goto out;
	output = ret;
	if (size) {
		if (output > size)
			ret = -ERANGE;
		else if (output && list)
			memcpy(list, buffer, output);
		else if (output)
			ret = -EFAULT;
	}
out:
	kvfree(buffer);
	if (source_active)
		kasumi_vfs_internal_leave(&source_guard);
	if (source.dentry)
		path_put(&source);
	kasumi_view_leave(&guard);
	return ret;
}

static bool kasumi_statfs_projection_active(void)
{
	return kasumi_mount_projection_active() ||
		(kasumi_mount_view_available() && kasumi_statfs_view_available() &&
		 kasumi_config_enabled() &&
		 (kasumi_config_features() & KSM_FEATURE_STATFS_SPOOF) &&
		 kasumi_policy_current_is_spoof_target());
}

static KASUMI_NOCFI int kasumi_view_statfs(const struct path *path,
					   struct kstatfs *buf)
{
	struct kasumi_view_guard guard;
	struct kasumi_mount_view *view = NULL;
	const struct kasumi_mount_record *record, *alias;
	struct path projected = {};
	struct kstatfs backing;
	unsigned int attempt;
	int ret;

	kasumi_view_enter(&guard);
	ret = kasumi_view_statfs_orig(path, buf);
	if (ret || !kasumi_statfs_projection_active())
		goto out;
	for (attempt = 0; attempt < KASUMI_MOUNT_VIEW_ATTEMPTS; attempt++) {
		if (fatal_signal_pending(current)) {
			ret = -EINTR;
			goto out;
		}
		ret = kasumi_mount_view_get_current(&view);
		if (ret && ret != -EAGAIN)
			goto out;
		if (!ret) {
			down_read(kasumi_statfs_namespace_lock);
			if (kasumi_mount_view_current(view))
				break;
			up_read(kasumi_statfs_namespace_lock);
			kasumi_mount_view_put(view);
			view = NULL;
		}
		cond_resched();
	}
	if (!view) {
		ret = -EAGAIN;
		goto out;
	}
	record = kasumi_mount_view_find(view, real_mount(path->mnt)->mnt_id, false);
	alias = kasumi_mount_view_representative(view, record);
	if (alias && alias != record) {
		projected.mnt = alias->mount;
		projected.dentry = alias->mount->mnt_root;
		path_get(&projected);
	}
	up_read(kasumi_statfs_namespace_lock);
	if (projected.mnt) {
		ret = kasumi_view_statfs_orig(&projected, &backing);
		if (!ret) {
			*buf = backing;
			atomic64_inc(&kasumi_hook_stats.statfs_spoofs);
		}
		path_put(&projected);
	}
out:
	kasumi_mount_view_put(view);
	kasumi_view_leave(&guard);
	return ret;
}

/* Only redirect here. Allocation, native VFS calls and topology inspection
 * run after the exception has returned to the original sleepable context.
 */
static int kasumi_view_pre(struct kprobe *probe, struct pt_regs *regs)
{
	unsigned long target;
	struct dentry *dentry;
	const char *name;

	if (READ_ONCE(kasumi_view_stopped) || !current->mm ||
	    kasumi_vfs_internal_current() ||
	    kasumi_view_guarded())
		return 0;
#if defined(CONFIG_ARM64)
	if (regs->pstate & PSR_I_BIT)
		return 0;
	if (probe == &kasumi_view_statfs_probe) {
		if (!READ_ONCE(kasumi_statfs_ready) ||
		    !kasumi_statfs_projection_active())
			return 0;
		atomic64_inc(&kasumi_hook_stats.statfs_entries);
		target = (unsigned long)kasumi_view_statfs;
	} else if (probe == &kasumi_view_list_probe) {
		dentry = (void *)regs->regs[0];
		if (!(READ_ONCE(kasumi_source_xattr_ready) &&
		      kasumi_vnode_is_ours(d_inode(dentry))) && !kasumi_xattr_target(dentry))
			return 0;
		target = (unsigned long)kasumi_view_listxattr;
	} else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
		dentry = (void *)regs->regs[1];
		name = (void *)regs->regs[2];
#else
		dentry = (void *)regs->regs[0];
		name = (void *)regs->regs[1];
#endif
		if (probe == &kasumi_view_set_probe || probe == &kasumi_view_remove_probe) {
			if (!READ_ONCE(kasumi_source_xattr_ready) ||
			    !kasumi_vnode_is_ours(d_inode(dentry)))
				return 0;
			target = probe == &kasumi_view_set_probe ?
				(unsigned long)kasumi_view_setxattr :
				(unsigned long)kasumi_view_removexattr;
		} else {
			if (!(READ_ONCE(kasumi_source_xattr_ready) &&
			      kasumi_vnode_is_ours(d_inode(dentry))) &&
			    (!kasumi_overlay_name(name) || !kasumi_xattr_target(dentry)))
				return 0;
			target = (unsigned long)kasumi_view_getxattr;
		}
	}
	atomic_inc(&kasumi_view_active);
	instruction_pointer_set(regs, target);
	return 1;
#else
	return 0;
#endif
}

static void kasumi_xattr_free_work(struct work_struct *work)
{
	struct kasumi_xattr_sb_entry *entry =
	    container_of(work, struct kasumi_xattr_sb_entry, free_work);

	deactivate_super(entry->sb);
	kfree(entry);
	if (atomic_dec_and_test(&kasumi_xattr_owned))
		wake_up_all(&kasumi_view_wait);
}

void kasumi_overlay_xattr_retire(struct kasumi_xattr_sb_entry *entry)
{
	queue_work(kasumi_xattr_wq, &entry->free_work);
}

KASUMI_NOCFI int kasumi_overlay_xattr_mark_at(const char *name, u64 generation)
{
	struct kasumi_xattr_sb_entry *entry, *existing;
	struct hlist_node *tmp;
	struct path path;
	int ret, bucket;

	if (!name)
		return -EINVAL;
	if (!*name) {
		mutex_lock(&kasumi_config_mutex);
		hash_for_each_safe(kasumi_xattr_sbs, bucket, tmp, entry, node)
		{
			if (kasumi_rule_visible(&entry->life, generation)) {
				kasumi_batch_track(&entry->life, KASUMI_BATCH_XATTR);
				WRITE_ONCE(entry->life.last_generation, generation - 1);
			}
		}
		mutex_unlock(&kasumi_config_mutex);
		return 0;
	}
	if (!kasumi_overlay_xattr_available())
		return -EOPNOTSUPP;
	ret = kern_path(name, LOOKUP_FOLLOW, &path);
	if (ret)
		return ret;
	if (path.dentry->d_sb->s_magic != OVERLAYFS_SUPER_MAGIC) {
		ret = -EINVAL;
		goto out_path;
	}
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		ret = -ENOMEM;
		goto out_path;
	}
	entry->life.first_generation = generation;
	entry->sb = path.dentry->d_sb;
	INIT_WORK(&entry->free_work, kasumi_xattr_free_work);
	mutex_lock(&kasumi_config_mutex);
	if (!kasumi_overlay_xattr_available()) {
		ret = -ESHUTDOWN;
		goto out_unlock;
	}
	hash_for_each_possible(kasumi_xattr_sbs, existing, node,
			       (unsigned long)entry->sb)
	{
		if (existing->sb == entry->sb &&
		    kasumi_rule_visible(&existing->life, generation))
			goto out_unlock;
	}
	if (!atomic_inc_not_zero(&entry->sb->s_active)) {
		ret = -ESHUTDOWN;
		goto out_unlock;
	}
	kasumi_batch_track(&entry->life, KASUMI_BATCH_XATTR);
	atomic_inc(&kasumi_xattr_owned);
	hash_add_rcu(kasumi_xattr_sbs, &entry->node, (unsigned long)entry->sb);
	mutex_unlock(&kasumi_config_mutex);
	path_put(&path);
	return 0;
out_unlock:
	mutex_unlock(&kasumi_config_mutex);
	kfree(entry);
out_path:
	path_put(&path);
	return ret;
}

int kasumi_overlay_xattr_mark(const char *name)
{
	return kasumi_overlay_xattr_mark_at(name, kasumi_rules_generation());
}

bool kasumi_overlay_xattr_available(void)
{
	return READ_ONCE(kasumi_xattr_ready);
}

bool kasumi_source_xattr_available(void)
{
	return READ_ONCE(kasumi_source_xattr_ready);
}

bool kasumi_statfs_view_available(void)
{
	return READ_ONCE(kasumi_statfs_ready);
}

static int kasumi_view_register(struct kprobe *probe, const char *name)
{
	probe->symbol_name = name;
	probe->pre_handler = kasumi_view_pre;
	return register_kprobe(probe);
}

int kasumi_vfs_view_init(void)
{
	int ret;

#ifndef CONFIG_ARM64
	return -EOPNOTSUPP;
#endif
	kasumi_view_tasks_barrier =
		(void *)kasumi_lookup_callable_quiet("synchronize_rcu_tasks");
	if (!kasumi_view_tasks_barrier)
		return -ENOENT;
	kasumi_xattr_wq = alloc_workqueue("kasumi_xattr_free",
					  WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
	if (!kasumi_xattr_wq)
		return -ENOMEM;
	kasumi_view_getxattr_orig = kasumi_vfs_getxattr_addr;
	kasumi_view_listxattr_orig = kasumi_vfs_listxattr_addr;
	kasumi_view_setxattr_orig = kasumi_vfs_setxattr_addr;
	kasumi_view_removexattr_orig = kasumi_vfs_removexattr_addr;
	kasumi_view_want_write = kasumi_mnt_want_write_addr;
	kasumi_view_drop_write = kasumi_mnt_drop_write_addr;
	kasumi_view_xattr_permission =
		(void *)kasumi_lookup_callable_quiet("xattr_permission");
	kasumi_view_security_get =
		(void *)kasumi_lookup_callable_quiet("security_inode_getxattr");
	kasumi_view_security_list =
		(void *)kasumi_lookup_callable_quiet("security_inode_listxattr");
	kasumi_view_security_set =
		(void *)kasumi_lookup_callable_quiet("security_inode_setxattr");
	kasumi_view_security_remove =
		(void *)kasumi_lookup_callable_quiet("security_inode_removexattr");
	kasumi_view_statfs_orig =
	    (void *)kasumi_lookup_callable_quiet("vfs_statfs");
	kasumi_statfs_namespace_lock =
		(void *)kasumi_lookup_name_quiet("namespace_sem");
	WRITE_ONCE(kasumi_view_stopped, false);
	if (kasumi_view_getxattr_orig && kasumi_view_listxattr_orig) {
		ret = kasumi_view_register(&kasumi_view_get_probe,
					   "vfs_getxattr");
		kasumi_view_get_registered = !ret;
		if (!ret) {
			ret = kasumi_view_register(&kasumi_view_list_probe,
						   "vfs_listxattr");
			kasumi_view_list_registered = !ret;
		}
		WRITE_ONCE(kasumi_xattr_ready, !ret);
	}
	if (kasumi_xattr_ready && kasumi_view_setxattr_orig &&
	    kasumi_view_removexattr_orig && kasumi_view_want_write &&
	    kasumi_view_drop_write && kasumi_view_xattr_permission &&
	    kasumi_view_security_get && kasumi_view_security_list &&
	    kasumi_view_security_set && kasumi_view_security_remove) {
		ret = kasumi_view_register(&kasumi_view_set_probe, "vfs_setxattr");
		kasumi_view_set_registered = !ret;
		if (!ret) {
			ret = kasumi_view_register(&kasumi_view_remove_probe, "vfs_removexattr");
			kasumi_view_remove_registered = !ret;
			if (ret) {
				unregister_kprobe(&kasumi_view_set_probe);
				kasumi_view_set_registered = false;
			}
		}
		WRITE_ONCE(kasumi_source_xattr_ready, !ret);
	}
	if (kasumi_view_statfs_orig && kasumi_statfs_namespace_lock &&
	    kasumi_mount_view_available()) {
		ret = kasumi_view_register(&kasumi_view_statfs_probe,
					   "vfs_statfs");
		kasumi_view_statfs_registered = !ret;
		WRITE_ONCE(kasumi_statfs_ready, !ret);
		if (!ret)
			kasumi_mount_view_publish_capabilities(KASUMI_MOUNT_CAP_STATFS, 0);
	}
	pr_info("kasumi: VFS views: overlay xattrs=%d statfs=%d\n",
		kasumi_xattr_ready, kasumi_statfs_ready);
	return 0;
}

void kasumi_vfs_view_stop(void)
{
	kasumi_mount_view_publish_capabilities(0, KASUMI_MOUNT_CAP_STATFS);
	WRITE_ONCE(kasumi_view_stopped, true);
	WRITE_ONCE(kasumi_xattr_ready, false);
	WRITE_ONCE(kasumi_source_xattr_ready, false);
	WRITE_ONCE(kasumi_statfs_ready, false);
	if (kasumi_view_get_registered) {
		unregister_kprobe(&kasumi_view_get_probe);
		kasumi_view_get_registered = false;
	}
	if (kasumi_view_list_registered) {
		unregister_kprobe(&kasumi_view_list_probe);
		kasumi_view_list_registered = false;
	}
	if (kasumi_view_set_registered) {
		unregister_kprobe(&kasumi_view_set_probe);
		kasumi_view_set_registered = false;
	}
	if (kasumi_view_remove_registered) {
		unregister_kprobe(&kasumi_view_remove_probe);
		kasumi_view_remove_registered = false;
	}
	if (kasumi_view_statfs_registered) {
		unregister_kprobe(&kasumi_view_statfs_probe);
		kasumi_view_statfs_registered = false;
	}
}

KASUMI_NOCFI void kasumi_vfs_view_drain(void)
{
	wait_event(kasumi_view_wait, !atomic_read(&kasumi_view_active));
	if (kasumi_view_tasks_barrier)
		kasumi_view_tasks_barrier();
}

void kasumi_vfs_view_exit(void)
{
	kasumi_vfs_view_stop();
	kasumi_vfs_view_drain();
	if (kasumi_xattr_wq) {
		rcu_barrier();
		flush_workqueue(kasumi_xattr_wq);
		destroy_workqueue(kasumi_xattr_wq);
		kasumi_xattr_wq = NULL;
	}
}
