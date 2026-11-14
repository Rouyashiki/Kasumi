#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/kprobes.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/sched/signal.h>
#include <linux/stat.h>
#include <linux/version.h>
#include <linux/wait.h>

#include "kasumi_mount_stat.h"
#include "kasumi_mount_view.h"
#include "kasumi_runtime.h"

struct kasumi_mount_stat_guard {
	struct hlist_node node;
	struct task_struct *task;
};

static DEFINE_HASHTABLE(kasumi_mount_stat_guards, 6);
static spinlock_t kasumi_mount_stat_guard_locks[HASH_SIZE(kasumi_mount_stat_guards)] = {
	[0 ... HASH_SIZE(kasumi_mount_stat_guards) - 1] =
		__SPIN_LOCK_UNLOCKED(kasumi_mount_stat_guard_locks),
};
static DECLARE_WAIT_QUEUE_HEAD(kasumi_mount_stat_wait);
static atomic_t kasumi_mount_stat_active = ATOMIC_INIT(0);
static bool kasumi_mount_stat_stopping = true;
static bool kasumi_mount_stat_registered;
static struct kprobe kasumi_mount_stat_probe;
static struct rw_semaphore *kasumi_mount_stat_namespace_lock;
static void (*kasumi_mount_stat_tasks_barrier)(void);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
typedef const struct path *kasumi_mount_stat_path;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
typedef struct path *kasumi_mount_stat_path;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
typedef struct filename *kasumi_mount_stat_filename;
#else
typedef const char __user *kasumi_mount_stat_filename;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
static int (*kasumi_mount_stat_original)(kasumi_mount_stat_path, int,
					struct kstat *, u32);
#else
static int (*kasumi_mount_stat_original)(int, kasumi_mount_stat_filename, int,
					struct kstat *, u32);
#endif

static bool kasumi_mount_stat_guarded(void)
{
	spinlock_t *lock = &kasumi_mount_stat_guard_locks[
		hash_min((unsigned long)current, HASH_BITS(kasumi_mount_stat_guards))];
	struct kasumi_mount_stat_guard *guard;
	unsigned long flags;
	bool found = false;

	spin_lock_irqsave(lock, flags);
	hash_for_each_possible(kasumi_mount_stat_guards, guard, node, (unsigned long)current) {
		if (guard->task == current) {
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(lock, flags);
	return found;
}

static void kasumi_mount_stat_enter(struct kasumi_mount_stat_guard *guard)
{
	spinlock_t *lock = &kasumi_mount_stat_guard_locks[
		hash_min((unsigned long)current, HASH_BITS(kasumi_mount_stat_guards))];
	unsigned long flags;

	guard->task = current;
	spin_lock_irqsave(lock, flags);
	hash_add(kasumi_mount_stat_guards, &guard->node, (unsigned long)current);
	spin_unlock_irqrestore(lock, flags);
}

static void kasumi_mount_stat_leave(struct kasumi_mount_stat_guard *guard)
{
	spinlock_t *lock = &kasumi_mount_stat_guard_locks[
		hash_min((unsigned long)guard->task, HASH_BITS(kasumi_mount_stat_guards))];
	unsigned long flags;

	spin_lock_irqsave(lock, flags);
	hash_del(&guard->node);
	spin_unlock_irqrestore(lock, flags);
	if (atomic_dec_and_test(&kasumi_mount_stat_active))
		wake_up_all(&kasumi_mount_stat_wait);
}

static bool kasumi_mount_stat_alias_root(const struct kasumi_mount_record *record,
					const struct kasumi_mount_record *alias)
{
	struct path path = { .mnt = record->mount, .dentry = record->mount->mnt_root };
	bool root;

	path_get(&path);
	while (path.mnt != alias->mount && path.dentry == path.mnt->mnt_root) {
		if (!follow_up(&path))
			break;
	}
	root = path.mnt == alias->mount && path.dentry == alias->mount->mnt_root;
	path_put(&path);
	return root;
}

static int kasumi_mount_stat_project(struct kstat *stat)
{
	const struct kasumi_mount_record *record, *alias;
	struct kasumi_mount_view *view = NULL;
	unsigned int attempt;
	bool unique = false;
	int ret;

#ifdef STATX_MNT_ID_UNIQUE
	unique = (stat->result_mask & STATX_MNT_ID_UNIQUE) != 0;
#endif
	if (!unique && !(stat->result_mask & STATX_MNT_ID))
		return 0;
	for (attempt = 0; attempt < KASUMI_MOUNT_VIEW_ATTEMPTS; attempt++) {
		if (fatal_signal_pending(current))
			return -EINTR;
		ret = kasumi_mount_view_get_current(&view);
		if (ret && ret != -EAGAIN)
			return ret;
		if (!ret) {
			down_read(kasumi_mount_stat_namespace_lock);
			if (kasumi_mount_view_current(view))
				break;
			up_read(kasumi_mount_stat_namespace_lock);
			kasumi_mount_view_put(view);
			view = NULL;
		}
		cond_resched();
	}
	if (!view)
		return -EAGAIN;
	record = kasumi_mount_view_find(view, stat->mnt_id, unique);
	alias = kasumi_mount_view_representative(view, record);
	if (record && alias && record != alias) {
		stat->mnt_id = unique ? alias->unique_id : alias->id;
		if ((stat->attributes & STATX_ATTR_MOUNT_ROOT) &&
		    !kasumi_mount_stat_alias_root(record, alias))
			stat->attributes &= ~STATX_ATTR_MOUNT_ROOT;
	}
	up_read(kasumi_mount_stat_namespace_lock);
	kasumi_mount_view_put(view);
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
static KASUMI_NOCFI int kasumi_mount_stat_entry(kasumi_mount_stat_path path, int flags,
					      struct kstat *stat, u32 request_mask)
#else
static KASUMI_NOCFI int kasumi_mount_stat_entry(int dfd, kasumi_mount_stat_filename filename,
					      int flags, struct kstat *stat, u32 request_mask)
#endif
{
	struct kasumi_mount_stat_guard guard;
	int ret;

	kasumi_mount_stat_enter(&guard);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	ret = kasumi_mount_stat_original(path, flags, stat, request_mask);
#else
	ret = kasumi_mount_stat_original(dfd, filename, flags, stat, request_mask);
#endif
	if (!ret && !READ_ONCE(kasumi_mount_stat_stopping) && kasumi_mount_projection_active())
		ret = kasumi_mount_stat_project(stat);
	kasumi_mount_stat_leave(&guard);
	return ret;
}

static int kasumi_mount_stat_pre(struct kprobe *probe, struct pt_regs *regs)
{
#ifdef CONFIG_ARM64
	if (READ_ONCE(kasumi_mount_stat_stopping) || kasumi_mount_stat_guarded() ||
	    kasumi_vfs_internal_current())
		return 0;
	atomic_inc(&kasumi_mount_stat_active);
	instruction_pointer_set(regs, (unsigned long)kasumi_mount_stat_entry);
	return 1;
#else
	return 0;
#endif
}

static u64 kasumi_mount_stat_capabilities(void)
{
	u64 capabilities = KASUMI_MOUNT_CAP_STATX;

#ifdef STATX_MNT_ID_UNIQUE
	capabilities |= KASUMI_MOUNT_CAP_UNIQUE;
#endif
	return capabilities;
}

KASUMI_NOCFI void kasumi_mount_stat_stop(void)
{
	kasumi_mount_view_publish_capabilities(0, kasumi_mount_stat_capabilities());
	WRITE_ONCE(kasumi_mount_stat_stopping, true);
	if (kasumi_mount_stat_registered) {
		unregister_kprobe(&kasumi_mount_stat_probe);
		kasumi_mount_stat_registered = false;
	}
	wait_event(kasumi_mount_stat_wait, !atomic_read(&kasumi_mount_stat_active));
	if (kasumi_mount_stat_tasks_barrier)
		kasumi_mount_stat_tasks_barrier();
}

int kasumi_mount_stat_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	const char *symbol = "vfs_statx_path";
#else
	const char *symbol = "vfs_statx";
#endif
	int ret;

	if (!READ_ONCE(kasumi_mount_stat_stopping))
		return 0;
#ifndef CONFIG_ARM64
	return -EOPNOTSUPP;
#endif
	kasumi_mount_stat_namespace_lock = (void *)kasumi_lookup_name_quiet("namespace_sem");
	kasumi_mount_stat_original = (void *)kasumi_lookup_callable_quiet(symbol);
	kasumi_mount_stat_tasks_barrier =
		(void *)kasumi_lookup_callable_quiet("synchronize_rcu_tasks");
	if (!kasumi_mount_stat_namespace_lock || !kasumi_mount_stat_original ||
	    !kasumi_mount_stat_tasks_barrier)
		return -EOPNOTSUPP;
	kasumi_mount_stat_probe.addr = (void *)kasumi_lookup_name_quiet(symbol);
	kasumi_mount_stat_probe.pre_handler = kasumi_mount_stat_pre;
	ret = register_kprobe(&kasumi_mount_stat_probe);
	if (ret)
		return ret;
	kasumi_mount_stat_registered = true;
	WRITE_ONCE(kasumi_mount_stat_stopping, false);
	kasumi_mount_view_publish_capabilities(kasumi_mount_stat_capabilities(), 0);
	return 0;
}

void kasumi_mount_stat_exit(void)
{
	kasumi_mount_stat_stop();
}
