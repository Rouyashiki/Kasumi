/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Rename control flow adapted from Linux fs/namei.c.
 * Copyright (C) 1991, 1992 Linus Torvalds
 */
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/kprobes.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/sched/signal.h>
#include <linux/security.h>
#include <linux/version.h>
#include <linux/wait.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
#include <linux/filelock.h>
#endif

#include "kasumi_path_policy.h"
#include "kasumi_rename_view.h"
#include "kasumi_runtime.h"
#include "kasumi_vnode.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
#define KSM_RENAME_IDMAP(mount) mnt_idmap(mount),
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
#define KSM_RENAME_IDMAP(mount) mnt_user_ns(mount),
#else
#define KSM_RENAME_IDMAP(mount)
#endif

struct kasumi_rename_guard {
	struct hlist_node node;
	struct task_struct *task;
};

static DEFINE_HASHTABLE(kasumi_rename_guards, 6);
static spinlock_t kasumi_rename_guard_locks[HASH_SIZE(kasumi_rename_guards)] = {
	[0 ... HASH_SIZE(kasumi_rename_guards) - 1] =
		__SPIN_LOCK_UNLOCKED(kasumi_rename_guard_locks),
};
static DECLARE_WAIT_QUEUE_HEAD(kasumi_rename_wait);
static atomic_t kasumi_rename_active = ATOMIC_INIT(0);
static bool kasumi_rename_stopping = true;
static bool kasumi_rename_registered;
static struct kprobe kasumi_rename_probe;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
static struct filename *(*kasumi_rename_parent_native)(int, struct filename *,
	unsigned int, struct path *, struct qstr *, int *);
#else
static int (*kasumi_rename_parent_native)(int, struct filename *, unsigned int,
	struct path *, struct qstr *, int *, const struct path *);
#endif
static struct dentry *(*kasumi_rename_lookup)(const struct qstr *, struct dentry *,
					     unsigned int);
static typeof(lock_rename) *kasumi_rename_lock;
static typeof(unlock_rename) *kasumi_rename_unlock;
static typeof(d_ancestor) *kasumi_rename_ancestor;
static void (*kasumi_rename_exchange)(struct dentry *, struct dentry *);
static typeof(mnt_want_write) *kasumi_rename_want_write;
static typeof(mnt_drop_write) *kasumi_rename_drop_write;
static typeof(putname) *kasumi_rename_putname;
#ifdef CONFIG_SECURITY_PATH
static typeof(security_path_rename) *kasumi_rename_path_security;
#endif
static typeof(security_inode_rename) *kasumi_rename_inode_security;
#ifdef CONFIG_FILE_LOCKING
static typeof(__break_lease) *kasumi_rename_break_lease;
#endif
static void (*kasumi_rename_tasks_barrier)(void);

static bool kasumi_rename_guarded(void)
{
	spinlock_t *lock = &kasumi_rename_guard_locks[
		hash_min((unsigned long)current, HASH_BITS(kasumi_rename_guards))];
	struct kasumi_rename_guard *guard;
	unsigned long flags;
	bool found = false;

	spin_lock_irqsave(lock, flags);
	hash_for_each_possible(kasumi_rename_guards, guard, node, (unsigned long)current) {
		if (guard->task == current) {
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(lock, flags);
	return found;
}

static KASUMI_NOCFI int kasumi_rename_parent(int fd, struct filename **name,
	unsigned int flags, struct path *parent, struct qstr *last, int *type)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
	*name = kasumi_rename_parent_native(fd, *name, flags, parent, last, type);
	return PTR_ERR_OR_ZERO(*name);
#else
	return kasumi_rename_parent_native(fd, *name, flags, parent, last, type, NULL);
#endif
}

static int kasumi_rename_source_parent(struct path *path, struct path *visible,
				       const struct qstr *last)
{
	struct inode *inode = d_inode(path->dentry);
	struct kasumi_vnode_info *info;
	char *visible_path;
	int ret;

	if (!kasumi_vnode_is_ours(inode))
		return 0;
	info = inode->i_private;
	if (!info || !info->source.dentry)
		return -EXDEV;
	if (kasumi_vnode_is_ours(d_inode(info->source.dentry)))
		return -ELOOP;
	/* Resolve policy aliases before acquiring any source rename locks. */
	visible_path = kasumi_vnode_visible_path(path->dentry);
	if (IS_ERR(visible_path))
		return PTR_ERR(visible_path);
	ret = kasumi_rule_child_mutation(inode, visible_path, last);
	kfree(visible_path);
	if (ret)
		return ret;
	*visible = *path;
	*path = info->source;
	path_get(path);
	return 0;
}

static KASUMI_NOCFI struct dentry *kasumi_rename_lookup_child(
	const struct qstr *name, struct dentry *parent, bool projected,
	unsigned int flags)
{
	struct qstr source_name = *name;
	int ret;

	if (projected) {
		/* Name hashes are salted with the parent dentry. */
		source_name.hash = full_name_hash(parent, name->name, name->len);
		if (parent->d_flags & DCACHE_OP_HASH) {
			ret = parent->d_op->d_hash(parent, &source_name);
			if (ret < 0)
				return ERR_PTR(ret);
		}
	}
	return kasumi_rename_lookup(&source_name, parent, flags);
}

static KASUMI_NOCFI int kasumi_rename_security(const struct path *old_path,
	struct dentry *old_dentry, const struct path *new_path,
	struct dentry *new_dentry, unsigned int flags)
{
#ifdef CONFIG_SECURITY_PATH
	return kasumi_rename_path_security(old_path, old_dentry, new_path, new_dentry, flags);
#else
	return 0;
#endif
}

static KASUMI_NOCFI int kasumi_rename_visible_security(
    const struct path *old_view, const struct path *new_view,
    struct dentry *old_child, struct dentry *new_child, unsigned int flags)
{
	int ret;

	ret = inode_permission(KSM_RENAME_IDMAP(old_view->mnt)
			       d_inode(old_view->dentry), MAY_WRITE | MAY_EXEC);
	if (!ret && new_view->dentry != old_view->dentry)
		ret = inode_permission(KSM_RENAME_IDMAP(new_view->mnt)
				       d_inode(new_view->dentry), MAY_WRITE | MAY_EXEC);
	if (ret)
		return ret;
	ret = kasumi_rename_security(old_view, old_child, new_view, new_child, flags);
	if (!ret)
		ret = kasumi_rename_inode_security(d_inode(old_view->dentry), old_child,
						   d_inode(new_view->dentry), new_child, flags);
	return ret;
}

struct kasumi_rename_source_locks {
	struct mutex *rename;
	struct inode *first;
	struct inode *second;
};

static void
kasumi_rename_unlock_sources(struct kasumi_rename_source_locks *locks)
{
	if (locks->second)
		inode_unlock(locks->second);
	if (locks->first)
		inode_unlock(locks->first);
	if (locks->rename)
		mutex_unlock(locks->rename);
	memset(locks, 0, sizeof(*locks));
}

/* The visible parents are already locked. Try source locks so overlapping
 * projections cannot invert native rename or directory-mutation lock order. */
static KASUMI_NOCFI struct dentry *kasumi_rename_lock_sources(
    const struct path *old_path, const struct path *new_path,
    const struct path *old_visible, const struct path *new_visible,
    struct kasumi_rename_source_locks *locks)
{
	struct dentry *old = old_path->dentry, *new = new_path->dentry;
	struct dentry *trap = NULL, *old_root, *new_root;
	int error = -EAGAIN;

	if (old != new && d_inode(old) == d_inode(new))
		return ERR_PTR(-EXDEV);
	if (old != new && (old->d_sb != old_visible->dentry->d_sb ||
			   old_visible->dentry == new_visible->dentry)) {
		if (!mutex_trylock(&old->d_sb->s_vfs_rename_mutex))
			return ERR_PTR(error);
		locks->rename = &old->d_sb->s_vfs_rename_mutex;
	}
	if (!inode_trylock(d_inode(old)))
		goto fail;
	locks->first = d_inode(old);
	if (new != old) {
		if (!inode_trylock(d_inode(new)))
			goto fail;
		locks->second = d_inode(new);
		for (old_root = old; !IS_ROOT(old_root);
		     old_root = old_root->d_parent)
			;
		for (new_root = new; !IS_ROOT(new_root);
		     new_root = new_root->d_parent)
			;
		if (old_root != new_root) {
			error = -EXDEV;
			goto fail;
		}
		trap = kasumi_rename_ancestor(old, new);
		if (!trap)
			trap = kasumi_rename_ancestor(new, old);
	}
	return trap;
fail:
	kasumi_rename_unlock_sources(locks);
	return ERR_PTR(error);
}

static bool kasumi_rename_matches(struct dentry *visible,
				  const struct path *parent,
				  struct dentry *source)
{
	struct inode *inode = d_inode(visible);
	struct kasumi_vnode_info *info;

	if (!inode)
		return d_is_negative(source);
	if (!kasumi_vnode_is_ours(inode))
		return false;
	info = inode->i_private;
	return info && !info->visible_path && info->source.dentry == source &&
	       info->source.mnt == parent->mnt && d_is_positive(source);
}

static void kasumi_rename_sequence(const struct path *old,
				   const struct path *new)
{
	struct kasumi_vnode_info *info = d_inode(old->dentry)->i_private;

	atomic_inc_return(&info->rename_seq);
	if (new->dentry != old->dentry) {
		info = d_inode(new->dentry)->i_private;
		atomic_inc_return(&info->rename_seq);
	}
}

static KASUMI_NOCFI int kasumi_rename_delegation(struct inode **delegated)
{
	int ret = 0;
#ifdef CONFIG_FILE_LOCKING
	struct file_lock_context *context = READ_ONCE((*delegated)->i_flctx);

	if (context) {
		smp_mb();
		if (!list_empty_careful(&context->flc_lease))
			ret = kasumi_rename_break_lease(*delegated, O_WRONLY, FL_DELEG);
	}
#endif
	iput(*delegated);
	*delegated = NULL;
	return ret;
}

static KASUMI_NOCFI int kasumi_rename_source(const struct path *old_path,
	struct dentry *old_dentry, const struct path *new_path,
	struct dentry *new_dentry, struct inode **delegated, unsigned int flags)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	struct renamedata rd = {};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	rd.old_parent = old_path->dentry;
	rd.new_parent = new_path->dentry;
	rd.mnt_idmap = mnt_idmap(old_path->mnt);
#else
	rd.old_dir = d_inode(old_path->dentry);
	rd.new_dir = d_inode(new_path->dentry);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	rd.old_mnt_idmap = mnt_idmap(old_path->mnt);
	rd.new_mnt_idmap = mnt_idmap(new_path->mnt);
#else
	rd.old_mnt_userns = mnt_user_ns(old_path->mnt);
	rd.new_mnt_userns = mnt_user_ns(new_path->mnt);
#endif
#endif
	rd.old_dentry = old_dentry;
	rd.new_dentry = new_dentry;
	rd.delegated_inode = delegated;
	rd.flags = flags;
	return kasumi_vfs_rename(&rd);
#else
	return kasumi_vfs_rename(d_inode(old_path->dentry), old_dentry,
				 d_inode(new_path->dentry), new_dentry, delegated, flags);
#endif
}

static KASUMI_NOCFI int kasumi_rename_execute(int oldfd, struct filename *from,
				int newfd, struct filename *to, unsigned int flags)
{
	struct dentry *old_dentry, *new_dentry, *trap;
	struct dentry *old_child = NULL, *new_child = NULL;
	struct path old_path, new_path, old_visible = {}, new_visible = {};
	const struct path *old_view, *new_view;
	struct kasumi_rename_source_locks source_locks = {};
	struct qstr old_last, new_last;
	struct inode *delegated = NULL;
	struct inode *old_child_lock = NULL, *new_child_lock = NULL;
	struct vfsmount *visible_write = NULL;
	struct kasumi_internal_vfs_guard internal;
	unsigned int lookup_flags = 0, target_flags = LOOKUP_RENAME_TARGET;
	int old_type, new_type, error = -EINVAL;
	bool should_retry = false, projected, retry_locks = false, moved;

	if (flags & ~(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT))
		goto put_names;
	if ((flags & (RENAME_NOREPLACE | RENAME_WHITEOUT)) && (flags & RENAME_EXCHANGE))
		goto put_names;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	target_flags |= LOOKUP_CREATE;
	if (flags & RENAME_NOREPLACE)
		target_flags |= LOOKUP_EXCL;
#endif
	if (flags & RENAME_EXCHANGE)
		target_flags = 0;
retry:
	error = kasumi_rename_parent(oldfd, &from, lookup_flags, &old_path, &old_last, &old_type);
	if (error)
		goto put_names;
	error = kasumi_rename_parent(newfd, &to, lookup_flags, &new_path, &new_last, &new_type);
	if (error)
		goto exit_old;
	error = -EXDEV;
	if (old_path.mnt != new_path.mnt)
		goto exit_paths;
	error = -EBUSY;
	if (old_type != LAST_NORM)
		goto exit_paths;
	if (flags & RENAME_NOREPLACE)
		error = -EEXIST;
	if (new_type != LAST_NORM)
		goto exit_paths;
	error = kasumi_rename_want_write(old_path.mnt);
	if (error)
		goto exit_paths;
	visible_write = old_path.mnt;
	error = kasumi_rename_source_parent(&old_path, &old_visible, &old_last);
	if (!error)
		error = kasumi_rename_source_parent(&new_path, &new_visible, &new_last);
	if (error)
		goto drop_visible_write;
	error = -EXDEV;
	if (old_path.mnt != new_path.mnt)
		goto drop_visible_write;
	/* A native destination cannot host a projected dentry after vfs_rename
	 * has already moved its backing dentry into the same namespace slot. */
	if (!!old_visible.dentry != !!new_visible.dentry)
		goto drop_visible_write;
	if (old_path.mnt != visible_write) {
		error = kasumi_rename_want_write(old_path.mnt);
		if (error)
			goto drop_visible_write;
	}
	projected = old_visible.dentry || new_visible.dentry;
	old_view = projected ? &old_visible : &old_path;
	new_view = projected ? &new_visible : &new_path;
retry_delegation:
	retry_locks = false;
	trap = kasumi_rename_lock(new_view->dentry, old_view->dentry);
	if (IS_ERR(trap)) {
		error = PTR_ERR(trap);
		goto after_unlock;
	}
	if (projected) {
		old_child = kasumi_rename_lookup_child(
		    &old_last, old_visible.dentry, false, lookup_flags);
		if (IS_ERR(old_child)) {
			error = PTR_ERR(old_child);
			old_child = NULL;
			goto unlock;
		}
		new_child = kasumi_rename_lookup_child(
		    &new_last, new_visible.dentry, false,
		    lookup_flags | target_flags);
		if (IS_ERR(new_child)) {
			error = PTR_ERR(new_child);
			new_child = NULL;
			goto unlock;
		}
		error = -ENOENT;
		if (d_is_negative(old_child) ||
		    ((flags & RENAME_EXCHANGE) && d_is_negative(new_child)))
			goto unlock;
		error = -EINVAL;
		if (old_child == trap)
			goto unlock;
		error = flags & RENAME_EXCHANGE ? -EINVAL : -ENOTEMPTY;
		if (new_child == trap)
			goto unlock;
		error = -EBUSY;
		if (d_mountpoint(old_child) || d_mountpoint(new_child))
			goto unlock;
		if (d_is_dir(old_child) &&
		    old_visible.dentry != new_visible.dentry) {
			inode_lock_nested(d_inode(old_child), I_MUTEX_CHILD);
			old_child_lock = d_inode(old_child);
		}
		if (d_is_dir(new_child) &&
		    d_inode(new_child) != old_child_lock &&
		    (old_visible.dentry != new_visible.dentry ||
		     !(flags & RENAME_EXCHANGE))) {
			inode_lock(d_inode(new_child));
			new_child_lock = d_inode(new_child);
		}
		trap = kasumi_rename_lock_sources(&old_path, &new_path,
						  &old_visible, &new_visible,
						  &source_locks);
		if (IS_ERR(trap)) {
			error = PTR_ERR(trap);
			retry_locks = error == -EAGAIN;
			goto unlock;
		}
		kasumi_vfs_internal_enter(&internal);
	}
	old_dentry = kasumi_rename_lookup_child(&old_last, old_path.dentry,
		old_visible.dentry != NULL, lookup_flags);
	error = PTR_ERR(old_dentry);
	if (IS_ERR(old_dentry))
		goto unlock_sources;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
	error = -ENOENT;
	if (d_is_negative(old_dentry))
		goto put_old;
#endif
	new_dentry = kasumi_rename_lookup_child(&new_last, new_path.dentry,
		new_visible.dentry != NULL, lookup_flags | target_flags);
	error = PTR_ERR(new_dentry);
	if (IS_ERR(new_dentry))
		goto put_old;
	/* Static rule aliases cannot be renamed by an underlying filesystem. */
	error = -EXDEV;
	if (kasumi_vnode_is_ours(d_inode(old_dentry)) || kasumi_vnode_is_ours(d_inode(new_dentry)))
		goto put_new;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
	error = -EEXIST;
	if ((flags & RENAME_NOREPLACE) && d_is_positive(new_dentry))
		goto put_new;
#endif
	if (flags & RENAME_EXCHANGE) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
		error = -ENOENT;
		if (d_is_negative(new_dentry))
			goto put_new;
#endif
		if (!d_is_dir(new_dentry) && new_last.name[new_last.len]) {
			error = -ENOTDIR;
			goto put_new;
		}
	}
	if (!d_is_dir(old_dentry) && (old_last.name[old_last.len] ||
	    (!(flags & RENAME_EXCHANGE) && new_last.name[new_last.len]))) {
		error = -ENOTDIR;
		goto put_new;
	}
	error = -EINVAL;
	if (old_dentry == trap)
		goto put_new;
	if (!(flags & RENAME_EXCHANGE))
		error = -ENOTEMPTY;
	if (new_dentry == trap)
		goto put_new;
	if (projected) {
		error = -ESTALE;
		if (!kasumi_rename_matches(old_child, &old_path, old_dentry) ||
		    !kasumi_rename_matches(new_child, &new_path, new_dentry))
			goto put_new;
		error = kasumi_rename_visible_security(
		    &old_visible, &new_visible, old_child, new_child, flags);
		if (error)
			goto put_new;
	}
	moved = d_inode(old_dentry) != d_inode(new_dentry);
	if (projected)
		kasumi_rename_sequence(&old_visible, &new_visible);
	error = kasumi_rename_security(&old_path, old_dentry, &new_path, new_dentry, flags);
	if (!error)
		error = kasumi_rename_source(&old_path, old_dentry, &new_path, new_dentry,
					     &delegated, flags);
	if (!error && projected && moved) {
		if (flags & RENAME_EXCHANGE) {
			kasumi_rename_exchange(old_child, new_child);
		} else {
			if (d_is_dir(new_child))
				d_inode(new_child)->i_flags |= S_DEAD;
			d_move(old_child, new_child);
		}
	}
	if (projected)
		kasumi_rename_sequence(&old_visible, &new_visible);
put_new:
	dput(new_dentry);
put_old:
	dput(old_dentry);
unlock_sources:
	if (projected) {
		kasumi_vfs_internal_leave(&internal);
		kasumi_rename_unlock_sources(&source_locks);
	}
unlock:
	if (new_child_lock) {
		inode_unlock(new_child_lock);
		new_child_lock = NULL;
	}
	if (old_child_lock) {
		inode_unlock(old_child_lock);
		old_child_lock = NULL;
	}
	dput(new_child);
	dput(old_child);
	new_child = old_child = NULL;
	kasumi_rename_unlock(new_view->dentry, old_view->dentry);
after_unlock:
	if (retry_locks) {
		schedule_timeout_killable(1);
		if (!signal_pending(current))
			goto retry_delegation;
		error = -ERESTARTSYS;
	}
	if (delegated) {
		error = kasumi_rename_delegation(&delegated);
		if (!error)
			goto retry_delegation;
	}
	if (old_path.mnt != visible_write)
		kasumi_rename_drop_write(old_path.mnt);
drop_visible_write:
	kasumi_rename_drop_write(visible_write);
	visible_write = NULL;
exit_paths:
	should_retry = error == -ESTALE && !(lookup_flags & LOOKUP_REVAL);
	path_put(&new_path);
	if (new_visible.dentry) {
		path_put(&new_visible);
		new_visible.dentry = NULL;
	}
exit_old:
	path_put(&old_path);
	if (old_visible.dentry) {
		path_put(&old_visible);
		old_visible.dentry = NULL;
	}
	if (should_retry) {
		should_retry = false;
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
put_names:
	if (!IS_ERR(from))
		kasumi_rename_putname(from);
	if (!IS_ERR(to))
		kasumi_rename_putname(to);
	return error;
}

static KASUMI_NOCFI int kasumi_rename_entry(int oldfd, struct filename *from,
				int newfd, struct filename *to, unsigned int flags)
{
	struct kasumi_rename_guard guard = { .task = current };
	spinlock_t *lock = &kasumi_rename_guard_locks[
		hash_min((unsigned long)guard.task, HASH_BITS(kasumi_rename_guards))];
	unsigned long irqflags;
	int ret;

	spin_lock_irqsave(lock, irqflags);
	hash_add(kasumi_rename_guards, &guard.node, (unsigned long)current);
	spin_unlock_irqrestore(lock, irqflags);
	ret = kasumi_rename_execute(oldfd, from, newfd, to, flags);
	spin_lock_irqsave(lock, irqflags);
	hash_del(&guard.node);
	spin_unlock_irqrestore(lock, irqflags);
	if (atomic_dec_and_test(&kasumi_rename_active))
		wake_up_all(&kasumi_rename_wait);
	return ret;
}

static int kasumi_rename_pre(struct kprobe *probe, struct pt_regs *regs)
{
#ifdef CONFIG_ARM64
	if (READ_ONCE(kasumi_rename_stopping) || kasumi_rename_guarded() ||
	    kasumi_vfs_internal_current())
		return 0;
	atomic_inc(&kasumi_rename_active);
	instruction_pointer_set(regs, (unsigned long)kasumi_rename_entry);
	return 1;
#else
	return 0;
#endif
}

KASUMI_NOCFI void kasumi_rename_view_stop(void)
{
	WRITE_ONCE(kasumi_rename_stopping, true);
	if (kasumi_rename_registered) {
		unregister_kprobe(&kasumi_rename_probe);
		kasumi_rename_registered = false;
	}
	wait_event(kasumi_rename_wait, !atomic_read(&kasumi_rename_active));
	if (kasumi_rename_tasks_barrier)
		kasumi_rename_tasks_barrier();
}

int kasumi_rename_view_init(void)
{
	int ret;

	if (!READ_ONCE(kasumi_rename_stopping))
		return 0;
#ifndef CONFIG_ARM64
	return -EOPNOTSUPP;
#endif
#define RESOLVE(member, symbol) \
	do { \
		member = (void *)kasumi_lookup_callable_quiet(symbol); \
		if (!member) \
			return -EOPNOTSUPP; \
	} while (0)
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
	RESOLVE(kasumi_rename_parent_native, "filename_parentat");
	RESOLVE(kasumi_rename_lookup, "__lookup_hash");
#else
	RESOLVE(kasumi_rename_parent_native, "__filename_parentat");
	RESOLVE(kasumi_rename_lookup, "lookup_one_qstr_excl");
#endif
	RESOLVE(kasumi_rename_lock, "lock_rename");
	RESOLVE(kasumi_rename_unlock, "unlock_rename");
	RESOLVE(kasumi_rename_ancestor, "d_ancestor");
	RESOLVE(kasumi_rename_exchange, "d_exchange");
	RESOLVE(kasumi_rename_want_write, "mnt_want_write");
	RESOLVE(kasumi_rename_drop_write, "mnt_drop_write");
	RESOLVE(kasumi_rename_putname, "putname");
	RESOLVE(kasumi_rename_inode_security, "security_inode_rename");
#ifdef CONFIG_SECURITY_PATH
	RESOLVE(kasumi_rename_path_security, "security_path_rename");
#endif
#ifdef CONFIG_FILE_LOCKING
	RESOLVE(kasumi_rename_break_lease, "__break_lease");
#endif
	RESOLVE(kasumi_rename_tasks_barrier, "synchronize_rcu_tasks");
#undef RESOLVE
	if (!kasumi_vfs_rename)
		return -EOPNOTSUPP;
	kasumi_rename_probe.addr = (void *)kasumi_lookup_name_quiet("do_renameat2");
	kasumi_rename_probe.pre_handler = kasumi_rename_pre;
	ret = register_kprobe(&kasumi_rename_probe);
	if (ret)
		return ret;
	kasumi_rename_registered = true;
	WRITE_ONCE(kasumi_rename_stopping, false);
	return 0;
}

void kasumi_rename_view_exit(void)
{
	kasumi_rename_view_stop();
}
