#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fanotify.h>
#include <linux/fsnotify_backend.h>
#include <linux/hashtable.h>
#include <linux/inotify.h>
#include <linux/kprobes.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/sched/task_stack.h>
#include <linux/security.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/user_namespace.h>
#include <linux/version.h>
#include <linux/wait.h>

#include "kasumi_notify_view.h"
#include "kasumi_notify_watch.h"
#include "kasumi_notify_fanotify.h"
#include "kasumi_path_policy.h"
#include "kasumi_runtime.h"
#include "kasumi_vnode.h"

struct kasumi_notify_guard {
	struct hlist_node node;
	struct task_struct *task;
	bool native_call;
	bool inotify;
	struct file *file;
	struct kasumi_notify_pending *pending;
	struct kasumi_fanotify_pending *fan_pending;
	struct path legacy_visible;
	struct path legacy_previous;
	int legacy_error;
	bool legacy_project;
	u32 fanotify_flags;
	struct inode *visible_inode;
	struct path source;
	u64 mask;
	int error;
};

struct kasumi_notify_syscall_hook {
	struct kprobe probe;
	long (*original)(const struct pt_regs *regs);
	unsigned long entry;
	bool registered;
};

static DEFINE_HASHTABLE(kasumi_notify_guards, 6);
static spinlock_t kasumi_notify_locks[HASH_SIZE(kasumi_notify_guards)];
static DECLARE_WAIT_QUEUE_HEAD(kasumi_notify_wait);
static atomic_t kasumi_notify_active = ATOMIC_INIT(0);
static bool kasumi_notify_stopping = true;
static u32 kasumi_notify_capabilities;
static struct kasumi_notify_syscall_hook kasumi_notify_inotify;
static struct kasumi_notify_syscall_hook kasumi_notify_compat_inotify;
static struct kasumi_notify_syscall_hook kasumi_notify_fanotify;
static struct kasumi_notify_syscall_hook kasumi_notify_compat_fanotify;
static struct kprobe kasumi_notify_security_probe;
static bool kasumi_notify_security_registered;
static int (*kasumi_notify_security_original)(const struct path *, u64, unsigned int);
static void (*kasumi_notify_tasks_barrier)(void);
static const struct file_operations *kasumi_notify_inotify_fops;
static const struct file_operations *kasumi_notify_fanotify_fops;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
static typeof(user_path_at_empty) *kasumi_notify_user_path;
static struct kprobe kasumi_notify_legacy_probe;
static bool kasumi_notify_legacy_registered;
static unsigned int kasumi_notify_legacy_path_offset;
static struct kprobe kasumi_notify_find_path_probe;
static bool kasumi_notify_find_path_registered;
static int (*kasumi_notify_find_path_original)(int, const char __user *,
	struct path *, unsigned int, u64, unsigned int);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
static struct kprobe kasumi_notify_find_probe;
static struct kprobe kasumi_notify_add_probe;
static bool kasumi_notify_find_registered;
static bool kasumi_notify_add_registered;
static const struct fsnotify_ops *kasumi_notify_inotify_ops;
static void (*kasumi_notify_dec_ucount)(struct ucounts *, enum ucount_type);
static struct fsnotify_mark *(*kasumi_notify_find_original)(
	fsnotify_connp_t *, struct fsnotify_group *);
static int (*kasumi_notify_add_original)(struct fsnotify_mark *,
	fsnotify_connp_t *, unsigned int, int, __kernel_fsid_t *);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static struct kprobe kasumi_notify_find_probe;
static struct kprobe kasumi_notify_add_probe;
static bool kasumi_notify_find_registered;
static bool kasumi_notify_add_registered;
static const struct fsnotify_ops *kasumi_notify_inotify_ops;
static void (*kasumi_notify_dec_ucount)(struct ucounts *, enum ucount_type);
static typeof(fsnotify_find_mark) *kasumi_notify_find_original;
static typeof(fsnotify_add_mark_locked) *kasumi_notify_add_original;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
static int (*kasumi_notify_inode_permission)(struct mnt_idmap *, struct inode *, int);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
static int (*kasumi_notify_inode_permission)(struct user_namespace *, struct inode *, int);
#else
static int (*kasumi_notify_inode_permission)(struct inode *, int);
#endif

u32 kasumi_notify_view_capabilities(void)
{
	return READ_ONCE(kasumi_notify_stopping) ? 0 : kasumi_notify_capabilities;
}

static struct kasumi_notify_guard *kasumi_notify_current(void)
{
	struct kasumi_notify_guard *guard;
	struct kasumi_notify_guard *found = NULL;
	spinlock_t *lock = &kasumi_notify_locks[hash_min((unsigned long)current,
						     HASH_BITS(kasumi_notify_guards))];
	unsigned long flags;

	if (!atomic_read(&kasumi_notify_active))
		return NULL;
	spin_lock_irqsave(lock, flags);
	hash_for_each_possible(kasumi_notify_guards, guard, node, (unsigned long)current) {
		if (guard->task == current) {
			found = guard;
			break;
		}
	}
	spin_unlock_irqrestore(lock, flags);
	return found;
}

static KASUMI_NOCFI int kasumi_notify_source_permission(const struct path *source)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	return kasumi_notify_inode_permission(mnt_idmap(source->mnt),
					      d_inode(source->dentry), MAY_READ);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	return kasumi_notify_inode_permission(mnt_user_ns(source->mnt),
					      d_inode(source->dentry), MAY_READ);
#else
	return kasumi_notify_inode_permission(d_inode(source->dentry), MAY_READ);
#endif
}

/* Each synthetic layer retains its source path for the inode lifetime. */
KASUMI_NOCFI int kasumi_notify_resolve_source(struct path *source, u64 mask)
{
	struct path next;
	int error;

	for (;;) {
		error = kasumi_notify_source_permission(source);
		if (!error)
			error = kasumi_notify_security_original(source, mask, FSNOTIFY_OBJ_TYPE_INODE);
		if (error || !kasumi_vnode_is_ours(d_inode(source->dentry)))
			return error;
		error = kasumi_vnode_source_path(source->dentry, &next);
		if (error <= 0)
			return error ? error : -EOPNOTSUPP;
		kasumi_path_put(source);
		*source = next;
	}
}

static bool kasumi_notify_single_source(struct inode *inode)
{
	struct kasumi_vnode_info *info = inode->i_private;

	return info && info->source.mnt && info->source.dentry &&
		d_inode(info->source.dentry) &&
		(!S_ISDIR(inode->i_mode) || !info->visible_path ||
		 !kasumi_rule_directory_overridden(info->visible_path,
						   kasumi_rules_generation()));
}

/* The admitted syscall owns a mutable stack path until its native path_put(). */
static KASUMI_NOCFI int kasumi_notify_project_path(const struct path *path, u64 mask,
						 unsigned int type)
{
	struct inode *inode = d_inode(path->dentry);
	struct path source, previous;
	int ret;

	if (type != FSNOTIFY_OBJ_TYPE_INODE || !kasumi_vnode_is_ours(inode))
		return 0;
	if (!object_is_on_stack(path))
		return -EOPNOTSUPP;
	if (!kasumi_notify_single_source(inode))
		return -EOPNOTSUPP;
	ret = kasumi_vnode_source_path(path->dentry, &source);
	if (ret <= 0)
		return ret ? ret : -EOPNOTSUPP;
	ret = kasumi_notify_resolve_source(&source, mask);
	if (ret) {
		kasumi_path_put(&source);
		return ret;
	}
	previous = *path;
	*(struct path *)path = source;
	kasumi_path_put(&previous);
	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
/* Old Android callers inline the visible LSM check before native mark lookup. */
static KASUMI_NOCFI fsnotify_connp_t *kasumi_notify_source_connector(
	struct kasumi_notify_guard *guard, fsnotify_connp_t *connector)
{
	struct inode *inode = container_of(connector, struct inode, i_fsnotify_marks);
	struct kasumi_vnode_info *info;

	if (guard->pending) {
		if (guard->visible_inode != inode)
			guard->error = -EAGAIN;
		return guard->error ? NULL : connector;
	}
	if (!kasumi_vnode_is_ours(inode))
		return connector;
	if (guard->visible_inode == inode)
		return guard->error ? NULL : &d_inode(guard->source.dentry)->i_fsnotify_marks;
	if (guard->visible_inode) {
		guard->error = -EOPNOTSUPP;
		return NULL;
	}
	guard->visible_inode = inode;
	if (!kasumi_notify_single_source(inode)) {
		guard->error = -EOPNOTSUPP;
		return NULL;
	}
	/* The original syscall retains the visible inode through its owned path. */
	info = inode->i_private;
	guard->source = info->source;
	kasumi_path_get(&guard->source);
	guard->error = kasumi_notify_resolve_source(&guard->source,
		guard->mask & IN_ALL_EVENTS);
	return guard->error ? NULL : &d_inode(guard->source.dentry)->i_fsnotify_marks;
}

static KASUMI_NOCFI struct fsnotify_mark *kasumi_notify_find_entry(
	fsnotify_connp_t *connector, struct fsnotify_group *group)
{
	struct kasumi_notify_guard *guard = kasumi_notify_current();
	struct fsnotify_mark *mark = NULL;

	if (!guard || group->ops != kasumi_notify_inotify_ops)
		return kasumi_notify_find_original(connector, group);
	guard->native_call = true;
	connector = kasumi_notify_source_connector(guard, connector);
	if (connector)
		mark = kasumi_notify_find_original(connector, group);
	if (guard->pending && !guard->error) {
		guard->error = kasumi_notify_watch_select(guard->pending, group, mark);
		if (guard->error && mark) {
			fsnotify_put_mark(mark);
			mark = NULL;
		}
	}
	guard->native_call = false;
	return mark;
}

static KASUMI_NOCFI int kasumi_notify_add_entry(struct fsnotify_mark *mark,
	fsnotify_connp_t *connector, unsigned int type, int flags, __kernel_fsid_t *fsid)
{
	struct kasumi_notify_guard *guard = kasumi_notify_current();
	u32 mask = READ_ONCE(mark->mask);
	int ret;

	if (!guard || type != FSNOTIFY_OBJ_TYPE_INODE ||
	    mark->group->ops != kasumi_notify_inotify_ops)
		return kasumi_notify_add_original(mark, connector, type, flags, fsid);
	guard->native_call = true;
	if (guard->pending)
		WRITE_ONCE(mark->mask, 0);
	connector = kasumi_notify_source_connector(guard, connector);
	if (connector) {
		ret = kasumi_notify_add_original(mark, connector, type, flags, fsid);
	} else {
		ret = guard->error;
	}
	if (!ret && guard->pending)
		kasumi_notify_watch_attached(guard->pending, mark, mask);
	else if (guard->pending)
		WRITE_ONCE(mark->mask, mask);
	if (ret && guard->visible_inode) {
		/* Old native callers reserve this count before add, then only remove
		 * their idr reference when add fails. No attached mark can release it.
		 */
		kasumi_notify_dec_ucount(mark->group->inotify_data.ucounts,
					 UCOUNT_INOTIFY_WATCHES);
	}
	guard->native_call = false;
	return ret;
}

static int kasumi_notify_mark_pre(struct kprobe *probe, struct pt_regs *regs)
{
#ifdef CONFIG_ARM64
	struct kasumi_notify_guard *guard = kasumi_notify_current();
	struct fsnotify_group *group;

	if (probe == &kasumi_notify_find_probe) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
		group = (void *)regs->regs[2];
#else
		group = (void *)regs->regs[1];
#endif
	} else {
		struct fsnotify_mark *mark = (void *)regs->regs[0];

		group = mark->group;
	}

	if (!guard || !guard->inotify || group->ops != kasumi_notify_inotify_ops || guard->native_call)
		return 0;
	instruction_pointer_set(regs, probe == &kasumi_notify_find_probe ?
		(unsigned long)kasumi_notify_find_entry : (unsigned long)kasumi_notify_add_entry);
	return 1;
#else
	return 0;
#endif
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
static KASUMI_NOCFI struct fsnotify_mark *kasumi_notify_find_entry(
	void *object, unsigned int type, struct fsnotify_group *group)
#else
static KASUMI_NOCFI struct fsnotify_mark *kasumi_notify_find_entry(
	fsnotify_connp_t *object, struct fsnotify_group *group)
#endif
{
	struct kasumi_notify_guard *guard = kasumi_notify_current();
	struct fsnotify_mark *mark;
	int error;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	if (!guard || !guard->pending || type != FSNOTIFY_OBJ_TYPE_INODE ||
	    group->ops != kasumi_notify_inotify_ops)
		return kasumi_notify_find_original(object, type, group);
#else
	if (!guard || !guard->pending || group->ops != kasumi_notify_inotify_ops)
		return kasumi_notify_find_original(object, group);
#endif
	guard->native_call = true;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	mark = kasumi_notify_find_original(object, type, group);
	error = object != guard->visible_inode ? -EAGAIN : 0;
#else
	mark = kasumi_notify_find_original(object, group);
	error = object != &guard->visible_inode->i_fsnotify_marks ? -EAGAIN : 0;
#endif
	if (!error)
		error = kasumi_notify_watch_select(guard->pending, group, mark);
	if (error) {
		guard->error = error;
		if (mark)
			fsnotify_put_mark(mark);
		mark = NULL;
	}
	guard->native_call = false;
	return mark;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
static KASUMI_NOCFI int kasumi_notify_add_entry(struct fsnotify_mark *mark,
	void *object, unsigned int type, int flags)
#else
static KASUMI_NOCFI int kasumi_notify_add_entry(struct fsnotify_mark *mark,
	fsnotify_connp_t *object, unsigned int type, int flags, __kernel_fsid_t *fsid)
#endif
{
	struct kasumi_notify_guard *guard = kasumi_notify_current();
	bool projected = guard && guard->pending && type == FSNOTIFY_OBJ_TYPE_INODE &&
		mark->group->ops == kasumi_notify_inotify_ops;
	u32 mask = READ_ONCE(mark->mask);
	int error;

	if (projected) {
		guard->native_call = true;
		WRITE_ONCE(mark->mask, 0);
	}
	if (projected && guard->error) {
		error = guard->error;
	} else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
		error = kasumi_notify_add_original(mark, object, type, flags);
#else
		error = kasumi_notify_add_original(mark, object, type, flags, fsid);
#endif
	}
	if (projected) {
		if (error) {
			WRITE_ONCE(mark->mask, mask);
			kasumi_notify_dec_ucount(mark->group->inotify_data.ucounts,
				UCOUNT_INOTIFY_WATCHES);
		} else {
			kasumi_notify_watch_attached(guard->pending, mark, mask);
		}
		guard->native_call = false;
	}
	return error;
}

static int kasumi_notify_mark_pre(struct kprobe *probe, struct pt_regs *regs)
{
#ifdef CONFIG_ARM64
	struct kasumi_notify_guard *guard = kasumi_notify_current();
	struct fsnotify_group *group;

	if (probe == &kasumi_notify_find_probe) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
		group = (void *)regs->regs[2];
#else
		group = (void *)regs->regs[1];
#endif
	} else {
		struct fsnotify_mark *mark = (void *)regs->regs[0];

		group = mark->group;
	}

	if (!guard || !guard->inotify || group->ops != kasumi_notify_inotify_ops || guard->native_call || !guard->pending)
		return 0;
	instruction_pointer_set(regs, probe == &kasumi_notify_find_probe ?
		(unsigned long)kasumi_notify_find_entry : (unsigned long)kasumi_notify_add_entry);
	return 1;
#else
	return 0;
#endif
}

static KASUMI_NOCFI int kasumi_notify_security_entry(const struct path *path, u64 mask,
						  unsigned int type)
{
	struct kasumi_notify_guard *guard = kasumi_notify_current();
	int ret;

	if (!guard)
		return kasumi_notify_security_original(path, mask, type);
	guard->native_call = true;
	/* The caller already checked visible DAC. Preserve its original LSM check. */
	ret = kasumi_notify_security_original(path, mask, type);
	if (!ret && guard->inotify && guard->file &&
	    type == FSNOTIFY_OBJ_TYPE_INODE) {
		ret = kasumi_notify_watch_prepare(path, guard->mask,
			guard->file->private_data, &guard->pending);
		if (ret > 0) {
			guard->visible_inode = d_inode(path->dentry);
			ret = 0;
		} else if (!ret) {
			ret = kasumi_notify_project_path(path, mask, type);
		}
	} else if (!ret && !guard->inotify && guard->file) {
		ret = kasumi_notify_fanotify_prepare(path, guard->mask, type,
			guard->fanotify_flags, guard->file->private_data, &guard->fan_pending);
		if (ret > 0)
			ret = 0;
		else if (!ret)
			ret = kasumi_notify_project_path(path, mask, type);
	} else if (!ret) {
		ret = kasumi_notify_project_path(path, mask, type);
	}
	guard->native_call = false;
	return ret;
}

static int kasumi_notify_security_pre(struct kprobe *probe, struct pt_regs *regs)
{
#ifdef CONFIG_ARM64
	struct kasumi_notify_guard *guard = kasumi_notify_current();

	if (!guard || guard->native_call || kasumi_notify_fanotify_internal())
		return 0;
	instruction_pointer_set(regs, (unsigned long)kasumi_notify_security_entry);
	return 1;
#else
	return 0;
#endif
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
/* The old caller inlines its path LSM and enters mark_mutex immediately after
 * canonicalization. Preflight stays in this cold syscall and actual native
 * lookup verifies the same inode/group/mark before any mask mutation.
 */
static KASUMI_NOCFI int kasumi_notify_preflight(struct kasumi_notify_guard *guard,
	const struct pt_regs *regs)
{
	struct path path;
	unsigned int lookup = 0;
	int error;

	if (!guard->file || !kasumi_notify_user_path ||
	    !(kasumi_notify_capabilities & KASUMI_NOTIFY_MULTISOURCE_INOTIFY) ||
	    (guard->mask & ~ALL_INOTIFY_BITS) || !(guard->mask & ALL_INOTIFY_BITS) ||
	    ((guard->mask & IN_MASK_ADD) && (guard->mask & IN_MASK_CREATE)))
		return 0;
	if (!(guard->mask & IN_DONT_FOLLOW))
		lookup |= LOOKUP_FOLLOW;
	if (guard->mask & IN_ONLYDIR)
		lookup |= LOOKUP_DIRECTORY;
	guard->native_call = true;
	error = kasumi_notify_user_path(AT_FDCWD, (const char __user *)regs->regs[1],
		lookup, &path, NULL);
	if (error)
		goto out;
	if (!S_ISDIR(d_inode(path.dentry)->i_mode))
		goto put;
	error = kasumi_notify_source_permission(&path);
	if (!error)
		error = kasumi_notify_security_original(&path, guard->mask & IN_ALL_EVENTS,
			FSNOTIFY_OBJ_TYPE_INODE);
	if (!error)
		error = kasumi_notify_watch_prepare(&path, guard->mask,
			guard->file->private_data, &guard->pending);
	if (error > 0) {
		guard->visible_inode = d_inode(path.dentry);
		error = 0;
	}
put:
	kasumi_path_put(&path);
out:
	guard->native_call = false;
	return error;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
static KASUMI_NOCFI int kasumi_notify_find_path_entry(int descriptor,
	const char __user *name, struct path *path, unsigned int flags, u64 mask,
	unsigned int type)
{
	struct kasumi_notify_guard *guard = kasumi_notify_current();
	int error;

	if (!guard)
		return kasumi_notify_find_path_original(descriptor, name, path, flags, mask, type);
	guard->native_call = true;
	error = kasumi_notify_find_path_original(descriptor, name, path, flags, mask, type);
	if (!error) {
		if (guard->file)
			error = kasumi_notify_fanotify_prepare(path, guard->mask, type,
				flags, guard->file->private_data, &guard->fan_pending);
		if (error > 0)
			error = 0;
		else if (!error)
			error = kasumi_notify_project_path(path, mask, type);
		/* The native helper consumes its output path on every error after
		 * lookup. Its caller therefore only puts successful output paths.
		 */
		if (error)
			kasumi_path_put(path);
	}
	guard->native_call = false;
	return error;
}

static int kasumi_notify_find_path_pre(struct kprobe *probe, struct pt_regs *regs)
{
#ifdef CONFIG_ARM64
	struct kasumi_notify_guard *guard = kasumi_notify_current();

	if (!guard || guard->inotify || guard->native_call || kasumi_notify_fanotify_internal())
		return 0;
	instruction_pointer_set(regs, (unsigned long)kasumi_notify_find_path_entry);
	return 1;
#else
	return 0;
#endif
}

static int kasumi_notify_find_path_install(void)
{
	unsigned long address = kasumi_lookup_name_quiet("fanotify_find_path");
	int error;

	if (!IS_ENABLED(CONFIG_FANOTIFY) || !address)
		return -EOPNOTSUPP;
	kasumi_notify_find_path_original =
		(void *)kasumi_lookup_callable_quiet("fanotify_find_path");
	if (!kasumi_notify_find_path_original)
		return -EOPNOTSUPP;
	kasumi_notify_find_path_probe.addr = (void *)address;
	kasumi_notify_find_path_probe.pre_handler = kasumi_notify_find_path_pre;
	error = register_kprobe(&kasumi_notify_find_path_probe);
	if (!error)
		kasumi_notify_find_path_registered = true;
	return error;
}

static KASUMI_NOCFI void kasumi_notify_fanotify_preflight(struct kasumi_notify_guard *guard,
	const struct pt_regs *regs, bool compat)
{
	const char __user *name = (const char __user *)regs->regs[compat ? 5 : 4];
	int descriptor = regs->regs[compat ? 4 : 3];
	struct file *file;
	unsigned int lookup = 0;
	u64 mask = guard->mask & ALL_FSNOTIFY_EVENTS;
	int error;

	if (!kasumi_notify_legacy_registered ||
	    (guard->fanotify_flags & (FAN_MARK_FLUSH | FAN_MARK_MOUNT | FAN_MARK_FILESYSTEM)))
		return;
	guard->native_call = true;
	if (name) {
		if (!(guard->fanotify_flags & FAN_MARK_DONT_FOLLOW))
			lookup |= LOOKUP_FOLLOW;
		if (guard->fanotify_flags & FAN_MARK_ONLYDIR)
			lookup |= LOOKUP_DIRECTORY;
		error = kasumi_notify_user_path(descriptor, name, lookup, &guard->legacy_visible, NULL);
	} else {
		file = fget(descriptor);
		error = file ? 0 : -EBADF;
		if (file) {
			guard->legacy_visible = file->f_path;
			kasumi_path_get(&guard->legacy_visible);
			fput(file);
		}
	}
	if (error)
		goto out;
	guard->legacy_project = kasumi_vnode_is_ours(d_inode(guard->legacy_visible.dentry));
	if (!guard->legacy_project && !S_ISDIR(d_inode(guard->legacy_visible.dentry)->i_mode))
		goto out;
	error = kasumi_notify_source_permission(&guard->legacy_visible);
	if (!error)
		error = kasumi_notify_security_original(&guard->legacy_visible, mask,
			FSNOTIFY_OBJ_TYPE_INODE);
	if (error)
		goto out;
	if (guard->file) {
		error = kasumi_notify_fanotify_prepare(&guard->legacy_visible, guard->mask,
			FSNOTIFY_OBJ_TYPE_INODE, guard->fanotify_flags,
			guard->file->private_data, &guard->fan_pending);
		if (error) {
			guard->legacy_project = true;
			if (error > 0)
				error = 0;
			goto out;
		}
	}
	if (!guard->legacy_project)
		goto out;
	if (!kasumi_notify_single_source(d_inode(guard->legacy_visible.dentry))) {
		error = -EOPNOTSUPP;
		goto out;
	}
	error = kasumi_vnode_source_path(guard->legacy_visible.dentry, &guard->source);
	if (error > 0)
		error = kasumi_notify_resolve_source(&guard->source, mask);
	else if (!error)
		error = -EOPNOTSUPP;
out:
	guard->legacy_error = error;
	guard->native_call = false;
}

/* This probe runs at the verified native return from inode_permission(). The
 * potentially blocking lookups/LSM checks and source path reference are owned
 * by the syscall guard. Only reference transfer occurs in the atomic handler.
 */
static int kasumi_notify_legacy_permission_pre(struct kprobe *probe, struct pt_regs *regs)
{
#ifdef CONFIG_ARM64
	struct kasumi_notify_guard *guard = kasumi_notify_current();
	struct path *path;

	if (!guard || guard->inotify || guard->native_call || (int)regs->regs[0] ||
	    (guard->fanotify_flags & (FAN_MARK_FLUSH | FAN_MARK_MOUNT | FAN_MARK_FILESYSTEM)))
		return 0;
	path = (struct path *)(regs->sp + kasumi_notify_legacy_path_offset);
	if (!object_is_on_stack(path))
		return 0;
	if (!guard->legacy_project && !kasumi_vnode_is_ours(d_inode(path->dentry)))
		return 0;
	if (path->dentry != guard->legacy_visible.dentry ||
	    path->mnt != guard->legacy_visible.mnt) {
		regs->regs[0] = (unsigned long)-EAGAIN;
		return 0;
	}
	if (guard->legacy_error) {
		regs->regs[0] = (unsigned long)guard->legacy_error;
		return 0;
	}
	if (guard->fan_pending)
		return 0;
	if (!guard->source.dentry || guard->legacy_previous.dentry) {
		regs->regs[0] = (unsigned long)-EAGAIN;
		return 0;
	}
	guard->legacy_previous = *path;
	*path = guard->source;
	memset(&guard->source, 0, sizeof(guard->source));
#endif
	return 0;
}

static KASUMI_NOCFI int kasumi_notify_legacy_install(void)
{
	unsigned long function = kasumi_lookup_name_quiet("do_fanotify_mark");
	unsigned long permission = kasumi_lookup_name_quiet("inode_permission");
	unsigned long size, offset;
	int (*lookup_size)(unsigned long, unsigned long *, unsigned long *);
	long (*read_code)(void *, const void *, size_t);
	u32 *instructions;
	unsigned int count, index, candidate = 0, frame = 0, path_offset = 0;
	int error = -EOPNOTSUPP;

	if (!IS_ENABLED(CONFIG_FANOTIFY) || !function || !permission || !kasumi_notify_user_path)
		return -EOPNOTSUPP;
	lookup_size = (void *)kasumi_lookup_callable_quiet("kallsyms_lookup_size_offset");
	read_code = (void *)kasumi_lookup_callable_quiet("copy_from_kernel_nofault");
	if (!lookup_size || !read_code || !lookup_size(function, &size, &offset) ||
	    offset || size < 32 || size > SZ_16K || (size & 3))
		return -EOPNOTSUPP;
	instructions = kmalloc(size, GFP_KERNEL);
	if (!instructions)
		return -ENOMEM;
	if (read_code(instructions, (void *)function, size))
		goto out;
	count = size / sizeof(*instructions);
	for (index = 0; index < min(count, 16U); index++) {
		u32 instruction = instructions[index];

		if ((instruction & 0xffc003ffU) == 0xd10003ffU)
			frame = (instruction >> 10) & 0xfff;
	}
	for (index = 8; index + 1 < count; index++) {
		u32 instruction = instructions[index];
		unsigned long target;
		unsigned int before, dentry_register = 32, dentry_slot = 0;
		unsigned int inode_argument = LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0) ? 1 : 0;

		if ((instruction & 0xfc000000U) != 0x94000000U)
			continue;
		target = function + index * 4 + sign_extend64(instruction & 0x03ffffffU, 25) * 4;
		if (target != permission)
			continue;
		/* A native CBZ W0 must consume the permission result next. */
		if ((instructions[index + 1] & 0xff00001fU) != 0x34000000U || candidate)
			goto out;
		for (before = index; before-- > index - 8;) {
			u32 load = instructions[before];
			unsigned int destination = load & 31, base = (load >> 5) & 31;
			unsigned int displacement = ((load >> 10) & 0xfff) * 8;

			if ((load & 0xffc00000U) != 0xf9400000U)
				continue;
			if (destination == inode_argument && displacement == offsetof(struct dentry, d_inode))
				dentry_register = base;
			else if (destination == dentry_register && base == 31) {
				dentry_slot = displacement;
				break;
			}
		}
		/* Volatile dentry/inode argument registers cannot survive the native
		 * permission call. The supported old callers reload this stack path.
		 */
		if (dentry_register > 18 || dentry_slot < offsetof(struct path, dentry) ||
		    !frame || dentry_slot + sizeof(void *) > frame)
			goto out;
		path_offset = dentry_slot - offsetof(struct path, dentry);
		candidate = index + 1;
	}
	if (!candidate)
		goto out;
	kasumi_notify_legacy_path_offset = path_offset;
	kasumi_notify_legacy_probe.addr = (void *)(function + candidate * 4);
	kasumi_notify_legacy_probe.pre_handler = kasumi_notify_legacy_permission_pre;
	error = register_kprobe(&kasumi_notify_legacy_probe);
	if (!error)
		kasumi_notify_legacy_registered = true;
out:
	kfree(instructions);
	return error;
}
#endif

static KASUMI_NOCFI long kasumi_notify_syscall(const struct pt_regs *regs,
					     struct kasumi_notify_syscall_hook *hook)
{
	struct kasumi_notify_guard guard = { .task = current };
	spinlock_t *lock = &kasumi_notify_locks[hash_min((unsigned long)current,
						     HASH_BITS(kasumi_notify_guards))];
	unsigned long flags;
	long ret;

#ifdef CONFIG_ARM64
	guard.inotify = hook == &kasumi_notify_inotify || hook == &kasumi_notify_compat_inotify;
	guard.mask = regs->regs[2];
	guard.fanotify_flags = regs->regs[1];
	if (hook == &kasumi_notify_compat_fanotify)
		guard.mask = (u64)(u32)regs->regs[2] | ((u64)(u32)regs->regs[3] << 32);
	if (guard.inotify ? kasumi_notify_inotify_fops != NULL : kasumi_notify_fanotify_fops != NULL) {
		const struct file_operations *expected = guard.inotify ?
			kasumi_notify_inotify_fops : kasumi_notify_fanotify_fops;

		guard.file = fget(regs->regs[0]);
		if (guard.file && guard.file->f_op != expected) {
			fput(guard.file);
			guard.file = NULL;
		}
	}
#endif
	spin_lock_irqsave(lock, flags);
	hash_add(kasumi_notify_guards, &guard.node, (unsigned long)current);
	spin_unlock_irqrestore(lock, flags);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	if (!guard.inotify)
		kasumi_notify_fanotify_preflight(&guard, regs, hook == &kasumi_notify_compat_fanotify);
	ret = guard.inotify ? kasumi_notify_preflight(&guard, regs) : 0;
	if (!ret)
#endif
		ret = hook->original(regs);
	if (guard.error)
		ret = guard.error;
	guard.native_call = true;
	kasumi_notify_watch_complete(guard.pending, ret);
	kasumi_notify_fanotify_complete(guard.fan_pending, ret);
	if (guard.file)
		fput(guard.file);
	if (guard.source.dentry)
		kasumi_path_put(&guard.source);
	if (guard.legacy_previous.dentry)
		kasumi_path_put(&guard.legacy_previous);
	if (guard.legacy_visible.dentry)
		kasumi_path_put(&guard.legacy_visible);
	spin_lock_irqsave(lock, flags);
	hash_del(&guard.node);
	spin_unlock_irqrestore(lock, flags);
	if (atomic_dec_and_test(&kasumi_notify_active))
		wake_up_all(&kasumi_notify_wait);
	return ret;
}

static long kasumi_notify_inotify_entry(const struct pt_regs *regs)
{
	return kasumi_notify_syscall(regs, &kasumi_notify_inotify);
}

static long kasumi_notify_compat_inotify_entry(const struct pt_regs *regs)
{
	return kasumi_notify_syscall(regs, &kasumi_notify_compat_inotify);
}

static long kasumi_notify_fanotify_entry(const struct pt_regs *regs)
{
	return kasumi_notify_syscall(regs, &kasumi_notify_fanotify);
}

static long kasumi_notify_compat_fanotify_entry(const struct pt_regs *regs)
{
	return kasumi_notify_syscall(regs, &kasumi_notify_compat_fanotify);
}

static int kasumi_notify_syscall_pre(struct kprobe *probe, struct pt_regs *regs)
{
#ifdef CONFIG_ARM64
	struct kasumi_notify_syscall_hook *hook =
		container_of(probe, struct kasumi_notify_syscall_hook, probe);

	if (READ_ONCE(kasumi_notify_stopping) || kasumi_notify_current())
		return 0;
	atomic_inc(&kasumi_notify_active);
	instruction_pointer_set(regs, hook->entry);
	return 1;
#else
	return 0;
#endif
}

static int kasumi_notify_install(struct kasumi_notify_syscall_hook *hook,
				const char *name, unsigned long entry, bool optional)
{
	unsigned long address = kasumi_lookup_name_quiet(name);
	int ret;

	if (!address)
		return optional ? 0 : -EOPNOTSUPP;
	/* ARM32 inotify can share the native entry because all arguments fit u32. */
	if (address == (unsigned long)kasumi_notify_inotify.probe.addr &&
	    kasumi_notify_inotify.registered)
		return 0;
	hook->original = (void *)kasumi_lookup_callable_quiet(name);
	if (!hook->original)
		return -EOPNOTSUPP;
	hook->entry = entry;
	hook->probe.addr = (void *)address;
	hook->probe.pre_handler = kasumi_notify_syscall_pre;
	ret = register_kprobe(&hook->probe);
	if (!ret)
		hook->registered = true;
	return ret;
}

static void kasumi_notify_remove(struct kasumi_notify_syscall_hook *hook)
{
	if (hook->registered) {
		unregister_kprobe(&hook->probe);
		hook->registered = false;
	}
}

KASUMI_NOCFI void kasumi_notify_view_stop(void)
{
	WRITE_ONCE(kasumi_notify_stopping, true);
	kasumi_notify_remove(&kasumi_notify_compat_fanotify);
	kasumi_notify_remove(&kasumi_notify_fanotify);
	kasumi_notify_remove(&kasumi_notify_compat_inotify);
	kasumi_notify_remove(&kasumi_notify_inotify);
	/* Admitted operations finish using the same path selection throughout. */
	wait_event(kasumi_notify_wait, !atomic_read(&kasumi_notify_active));
	kasumi_notify_fanotify_exit();
	kasumi_notify_watch_stop();
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	if (kasumi_notify_find_path_registered) {
		unregister_kprobe(&kasumi_notify_find_path_probe);
		kasumi_notify_find_path_registered = false;
	}
	if (kasumi_notify_legacy_registered) {
		unregister_kprobe(&kasumi_notify_legacy_probe);
		kasumi_notify_legacy_registered = false;
	}
#endif
	if (kasumi_notify_add_registered) {
		unregister_kprobe(&kasumi_notify_add_probe);
		kasumi_notify_add_registered = false;
	}
	if (kasumi_notify_find_registered) {
		unregister_kprobe(&kasumi_notify_find_probe);
		kasumi_notify_find_registered = false;
	}
	if (kasumi_notify_security_registered) {
		unregister_kprobe(&kasumi_notify_security_probe);
		kasumi_notify_security_registered = false;
	}
	if (kasumi_notify_tasks_barrier)
		kasumi_notify_tasks_barrier();
	kasumi_notify_capabilities = 0;
}

int kasumi_notify_view_init(void)
{
	unsigned int bucket;
	int ret;

	if (!READ_ONCE(kasumi_notify_stopping))
		return 0;
	if (!IS_ENABLED(CONFIG_ARM64) || !IS_ENABLED(CONFIG_SECURITY))
		return -EOPNOTSUPP;
	for (bucket = 0; bucket < ARRAY_SIZE(kasumi_notify_locks); bucket++)
		spin_lock_init(&kasumi_notify_locks[bucket]);
	kasumi_notify_security_original =
		(void *)kasumi_lookup_callable_quiet("security_path_notify");
	kasumi_notify_inode_permission =
		(void *)kasumi_lookup_callable_quiet("inode_permission");
	kasumi_notify_tasks_barrier =
		(void *)kasumi_lookup_callable_quiet("synchronize_rcu_tasks");
	if (!kasumi_notify_security_original || !kasumi_notify_inode_permission ||
	    !kasumi_notify_tasks_barrier)
		return -EOPNOTSUPP;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	kasumi_notify_user_path = (void *)kasumi_lookup_callable_quiet("user_path_at_empty");
#endif
	kasumi_notify_inotify_fops =
		(void *)kasumi_lookup_name_quiet("inotify_fops");
	kasumi_notify_fanotify_fops =
		(void *)kasumi_lookup_name_quiet("fanotify_fops");
	kasumi_notify_find_original =
		(void *)kasumi_lookup_callable_quiet("fsnotify_find_mark");
	kasumi_notify_add_original =
		(void *)kasumi_lookup_callable_quiet("fsnotify_add_mark_locked");
	kasumi_notify_inotify_ops =
		(void *)kasumi_lookup_name_quiet("inotify_fsnotify_ops");
	kasumi_notify_dec_ucount =
		(void *)kasumi_lookup_callable_quiet("dec_ucount");
	if (!kasumi_notify_find_original || !kasumi_notify_add_original ||
	    !kasumi_notify_inotify_ops || !kasumi_notify_dec_ucount)
		return -EOPNOTSUPP;
	kasumi_notify_find_probe.addr =
		(void *)kasumi_lookup_name_quiet("fsnotify_find_mark");
	kasumi_notify_find_probe.pre_handler = kasumi_notify_mark_pre;
	ret = register_kprobe(&kasumi_notify_find_probe);
	if (ret)
		return ret;
	kasumi_notify_find_registered = true;
	kasumi_notify_add_probe.addr =
		(void *)kasumi_lookup_name_quiet("fsnotify_add_mark_locked");
	kasumi_notify_add_probe.pre_handler = kasumi_notify_mark_pre;
	ret = register_kprobe(&kasumi_notify_add_probe);
	if (ret)
		goto fail;
	kasumi_notify_add_registered = true;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	kasumi_notify_security_probe.addr =
		(void *)kasumi_lookup_name_quiet("security_path_notify");
	kasumi_notify_security_probe.pre_handler = kasumi_notify_security_pre;
	ret = register_kprobe(&kasumi_notify_security_probe);
	if (ret)
		goto fail;
	kasumi_notify_security_registered = true;
#endif
	if (IS_ENABLED(CONFIG_INOTIFY_USER)) {
		ret = kasumi_notify_install(&kasumi_notify_inotify, "__arm64_sys_inotify_add_watch",
			(unsigned long)kasumi_notify_inotify_entry, false);
		if (ret)
			goto fail;
		if (IS_ENABLED(CONFIG_COMPAT)) {
			ret = kasumi_notify_install(&kasumi_notify_compat_inotify,
				"__arm64_compat_sys_inotify_add_watch",
				(unsigned long)kasumi_notify_compat_inotify_entry, true);
			if (ret)
				goto fail;
		}
		kasumi_notify_capabilities |= KASUMI_NOTIFY_INOTIFY;
		if (kasumi_notify_inotify_fops &&
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
		    kasumi_notify_user_path &&
#endif
		    !kasumi_notify_watch_init())
			kasumi_notify_capabilities |= KASUMI_NOTIFY_MULTISOURCE_INOTIFY;
	}
	if (IS_ENABLED(CONFIG_FANOTIFY) &&
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	    (!kasumi_notify_find_path_install() || !kasumi_notify_legacy_install())
#else
	    true
#endif
	   ) {
		ret = kasumi_notify_install(&kasumi_notify_fanotify, "__arm64_sys_fanotify_mark",
			(unsigned long)kasumi_notify_fanotify_entry, false);
		if (ret)
			goto fail;
		if (IS_ENABLED(CONFIG_COMPAT)) {
			ret = kasumi_notify_install(&kasumi_notify_compat_fanotify,
				"__arm64_compat_sys_fanotify_mark",
				(unsigned long)kasumi_notify_compat_fanotify_entry, false);
			if (ret)
				goto fail;
		}
		kasumi_notify_capabilities |= KASUMI_NOTIFY_FANOTIFY_INODE;
		if (kasumi_notify_fanotify_fops && !kasumi_notify_fanotify_init())
			kasumi_notify_capabilities |= KASUMI_NOTIFY_MULTISOURCE_FANOTIFY;
	}
	WRITE_ONCE(kasumi_notify_stopping, false);
	return 0;
fail:
	kasumi_notify_view_stop();
	return ret;
}

void kasumi_notify_view_exit(void)
{
	kasumi_notify_view_stop();
}
