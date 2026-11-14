#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/hash.h>
#include <linux/kprobes.h>
#include <linux/sched/signal.h>
#include <linux/security.h>
#include <linux/wait.h>

#include "kasumi_file_lock.h"
#include "kasumi_runtime.h"
#include "kasumi_vnode.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
#define KFL_FILE(lock) ((lock)->c.flc_file)
#define KFL_OWNER(lock) ((lock)->c.flc_owner)
#define KFL_FLAGS(lock) ((lock)->c.flc_flags)
#define KFL_TYPE(lock) ((lock)->c.flc_type)
#define KFL_WAIT(lock) ((lock)->c.flc_wait)
#define KFL_BLOCKED(lock) ((lock)->c.flc_blocked_member)
#else
#define KFL_FILE(lock) ((lock)->fl_file)
#define KFL_OWNER(lock) ((lock)->fl_owner)
#define KFL_FLAGS(lock) ((lock)->fl_flags)
#define KFL_TYPE(lock) ((lock)->fl_type)
#define KFL_WAIT(lock) ((lock)->fl_wait)
#define KFL_BLOCKED(lock) ((lock)->fl_blocked_member)
#endif

struct kasumi_file_lock_guard {
	struct hlist_node node;
	struct task_struct *task;
	struct file *granted;
};

struct kasumi_file_lock_bucket {
	spinlock_t lock;
	struct hlist_head guards;
};

struct kasumi_file_lock_hook {
	const char *name;
	struct kprobe probe;
	long (*original)(const struct pt_regs *);
	unsigned long entry;
	bool registered;
};

static struct kasumi_file_lock_bucket kasumi_file_lock_buckets[64];
static DECLARE_WAIT_QUEUE_HEAD(kasumi_file_lock_wait);
static atomic_t kasumi_file_lock_active = ATOMIC_INIT(0);
static atomic_t kasumi_file_lock_files = ATOMIC_INIT(0);
static bool kasumi_file_lock_stopping = true;
static long (*kasumi_file_fcntl)(int, unsigned int, unsigned long, struct file *);
static typeof(security_file_fcntl) *kasumi_file_security_fcntl;
static typeof(security_file_lock) *kasumi_file_security_lock;
static typeof(vfs_lock_file) *kasumi_file_vfs_lock;
static typeof(vfs_test_lock) *kasumi_file_test_lock;
static typeof(locks_delete_block) *kasumi_file_delete_block;
static typeof(locks_lock_inode_wait) *kasumi_file_inode_wait;
static typeof(locks_remove_posix) *kasumi_file_remove_posix;
static typeof(vfs_setlease) *kasumi_file_setlease;
static void (*kasumi_file_tasks_barrier)(void);

static long kasumi_file_fcntl_entry(const struct pt_regs *regs);
#ifdef CONFIG_COMPAT
static long kasumi_file_compat_fcntl_entry(const struct pt_regs *regs);
static long kasumi_file_compat_fcntl64_entry(const struct pt_regs *regs);
#endif

static struct kasumi_file_lock_hook kasumi_file_lock_hooks[] = {
	{ .name = "__arm64_sys_fcntl", .entry = (unsigned long)kasumi_file_fcntl_entry },
#ifdef CONFIG_COMPAT
	{ .name = "__arm64_compat_sys_fcntl", .entry = (unsigned long)kasumi_file_compat_fcntl_entry },
	{ .name = "__arm64_compat_sys_fcntl64", .entry = (unsigned long)kasumi_file_compat_fcntl64_entry },
#endif
};

static struct kasumi_file_lock_bucket *kasumi_file_lock_bucket(void)
{
	return &kasumi_file_lock_buckets[hash_ptr(current, 6)];
}

static struct kasumi_file_lock_guard *
kasumi_file_lock_find(struct kasumi_file_lock_bucket *bucket)
{
	struct kasumi_file_lock_guard *guard;

	hlist_for_each_entry(guard, &bucket->guards, node)
		if (guard->task == current)
			return guard;
	return NULL;
}

static bool kasumi_file_lock_guarded(void)
{
	struct kasumi_file_lock_bucket *bucket = kasumi_file_lock_bucket();
	unsigned long flags;
	bool guarded;

	spin_lock_irqsave(&bucket->lock, flags);
	guarded = kasumi_file_lock_find(bucket) != NULL;
	spin_unlock_irqrestore(&bucket->lock, flags);
	return guarded;
}

static void kasumi_file_lock_granted(struct file *real)
{
	struct kasumi_file_lock_bucket *bucket = kasumi_file_lock_bucket();
	struct kasumi_file_lock_guard *guard;
	unsigned long flags;

	spin_lock_irqsave(&bucket->lock, flags);
	guard = kasumi_file_lock_find(bucket);
	if (guard && !guard->granted)
		guard->granted = get_file(real);
	spin_unlock_irqrestore(&bucket->lock, flags);
}

static void kasumi_file_lock_enter(struct kasumi_file_lock_guard *guard)
{
	struct kasumi_file_lock_bucket *bucket = kasumi_file_lock_bucket();
	unsigned long flags;

	guard->task = current;
	guard->granted = NULL;
	spin_lock_irqsave(&bucket->lock, flags);
	hlist_add_head(&guard->node, &bucket->guards);
	spin_unlock_irqrestore(&bucket->lock, flags);
}

static void kasumi_file_lock_leave(struct kasumi_file_lock_guard *guard)
{
	struct kasumi_file_lock_bucket *bucket = kasumi_file_lock_bucket();
	unsigned long flags;

	spin_lock_irqsave(&bucket->lock, flags);
	hlist_del(&guard->node);
	spin_unlock_irqrestore(&bucket->lock, flags);
	if (guard->granted)
		fput(guard->granted);
	if (atomic_dec_and_test(&kasumi_file_lock_active))
		wake_up_all(&kasumi_file_lock_wait);
}

static void kasumi_file_sync_async(struct file *file, struct file *real)
{
	spin_lock(&file->f_lock);
	file->f_flags = (file->f_flags & ~FASYNC) | (READ_ONCE(real->f_flags) & FASYNC);
	spin_unlock(&file->f_lock);
}

static bool kasumi_file_owner_command(unsigned int command)
{
	switch (command) {
	case F_GETOWN:
	case F_SETOWN:
	case F_GETOWN_EX:
	case F_SETOWN_EX:
	case F_GETSIG:
	case F_SETSIG:
	case F_GETLEASE:
	case F_SETLEASE:
#ifdef F_GETOWNER_UIDS
	case F_GETOWNER_UIDS:
#endif
		return true;
	default:
		return false;
	}
}

static bool kasumi_file_posix_command(unsigned int command)
{
	return command == F_SETLK || command == F_SETLKW ||
		command == F_SETLK64 || command == F_SETLKW64;
}

static KASUMI_NOCFI long kasumi_file_fcntl_dispatch(const struct pt_regs *regs,
						  unsigned int hook)
{
	struct kasumi_file_lock_guard guard;
	unsigned int fd = regs->regs[0], command = regs->regs[1];
	unsigned long argument = regs->regs[2];
	struct file *file = NULL, *real;
	long ret;

	if (hook)
		argument = (u32)argument;
	kasumi_file_lock_enter(&guard);
	if (!kasumi_file_owner_command(command))
		goto native;
	file = fget_raw(fd);
	if (!file || (file->f_mode & FMODE_PATH) ||
	    !kasumi_vnode_is_ours(file_inode(file)) || !file->private_data)
		goto native;
	real = file;
	ret = kasumi_file_security_fcntl(file, command, argument);
	while (!ret && kasumi_vnode_is_ours(file_inode(real)) && real->private_data) {
		real = real->private_data;
		ret = kasumi_file_security_fcntl(real, command, argument);
	}
	if (!ret) {
		ret = kasumi_file_fcntl(fd, command, argument, real);
		kasumi_file_sync_async(file, real);
	}
	goto out;
native:
	ret = kasumi_file_lock_hooks[hook].original(regs);
	/* Native close-race recovery may skip the empty outer inode lock context. */
	if (ret == -EBADF && guard.granted)
		kasumi_file_remove_posix(guard.granted, current->files);
out:
	if (file)
		fput(file);
	kasumi_file_lock_leave(&guard);
	return ret;
}

static long kasumi_file_fcntl_entry(const struct pt_regs *regs)
{
	return kasumi_file_fcntl_dispatch(regs, 0);
}

#ifdef CONFIG_COMPAT
static long kasumi_file_compat_fcntl_entry(const struct pt_regs *regs)
{
	return kasumi_file_fcntl_dispatch(regs, 1);
}

static long kasumi_file_compat_fcntl64_entry(const struct pt_regs *regs)
{
	return kasumi_file_fcntl_dispatch(regs, 2);
}
#endif

static int kasumi_file_fcntl_pre(struct kprobe *probe, struct pt_regs *regs)
{
#ifdef CONFIG_ARM64
	struct kasumi_file_lock_hook *hook = container_of(probe, struct kasumi_file_lock_hook, probe);
	const struct pt_regs *arguments = (const void *)regs->regs[0];
	unsigned int command = arguments->regs[1];

	if (READ_ONCE(kasumi_file_lock_stopping) || !atomic_read(&kasumi_file_lock_files) ||
	    (!kasumi_file_owner_command(command) && !kasumi_file_posix_command(command)) ||
	    kasumi_file_lock_guarded())
		return 0;
	atomic_inc(&kasumi_file_lock_active);
	instruction_pointer_set(regs, hook->entry);
	return 1;
#else
	return 0;
#endif
}

KASUMI_NOCFI int kasumi_file_lock_posix(struct file *file, int command,
				      struct file_lock *lock)
{
	struct file *real = file->private_data;
	bool posix = !(KFL_FLAGS(lock) & FL_OFDLCK);
	int ret;

	if (!real)
		return -EBADF;
	if (!kasumi_file_lock_ready())
		return -EOPNOTSUPP;
	KFL_FILE(lock) = real;
	if (!posix)
		KFL_OWNER(lock) = real;
	if (command == F_GETLK)
		return kasumi_file_test_lock(real, lock);
	ret = kasumi_file_security_lock(real, KFL_TYPE(lock));
	if (ret)
		return ret;
	for (;;) {
		ret = kasumi_file_vfs_lock(real, command, lock, NULL);
		if (ret != FILE_LOCK_DEFERRED)
			break;
		ret = wait_event_interruptible(KFL_WAIT(lock), list_empty(&KFL_BLOCKED(lock)));
		if (ret)
			break;
	}
	kasumi_file_delete_block(lock);
	if (!ret && posix && KFL_TYPE(lock) != F_UNLCK)
		kasumi_file_lock_granted(real);
	return ret;
}

KASUMI_NOCFI int kasumi_file_lock_flock(struct file *file, int command,
				      struct file_lock *lock)
{
	struct file *real = file->private_data;
	int ret;

	if (!real)
		return -EBADF;
	if (!kasumi_file_lock_ready())
		return -EOPNOTSUPP;
	KFL_FILE(lock) = real;
	KFL_OWNER(lock) = real;
	ret = kasumi_file_security_lock(real, KFL_TYPE(lock));
	if (ret)
		return ret;
	return real->f_op->flock ? real->f_op->flock(real, command, lock) :
		kasumi_file_inode_wait(file_inode(real), lock);
}

KASUMI_NOCFI int kasumi_file_lock_setlease(struct file *file,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	int argument,
#else
	long argument,
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
	struct file_lease **lease,
#else
	struct file_lock **lease,
#endif
	void **private)
{
	struct file *real = file->private_data;
	int ret;

	if (!real)
		return -EBADF;
	if (!kasumi_file_lock_ready())
		return -EOPNOTSUPP;
	if (lease && *lease) {
		KFL_FILE(*lease) = real;
		if (KFL_OWNER(*lease) == file)
			KFL_OWNER(*lease) = real;
	}
	if (argument == F_UNLCK && private && *private == file)
		ret = kasumi_file_setlease(real, argument, lease, (void **)&real);
	else
		ret = kasumi_file_setlease(real, argument, lease, private);
	kasumi_file_sync_async(file, real);
	return ret;
}

KASUMI_NOCFI int kasumi_file_lock_flush(struct file *file, fl_owner_t owner)
{
	struct file *real = file->private_data;
	int ret = 0;

	if (!real)
		return 0;
	if (real->f_op->flush)
		ret = real->f_op->flush(real, owner);
	if (kasumi_file_remove_posix)
		kasumi_file_remove_posix(real, owner);
	return ret;
}

KASUMI_NOCFI int kasumi_file_lock_fasync(int fd, struct file *file, int on)
{
	struct file *real = file->private_data;
	int ret;

	if (!real || !real->f_op->fasync)
		return 0;
	ret = real->f_op->fasync(fd, real, on);
	if (ret >= 0)
		kasumi_file_sync_async(file, real);
	return ret;
}

void kasumi_file_lock_opened(void)
{
	atomic_inc(&kasumi_file_lock_files);
}

void kasumi_file_lock_released(void)
{
	atomic_dec(&kasumi_file_lock_files);
}

bool kasumi_file_lock_ready(void)
{
	return !READ_ONCE(kasumi_file_lock_stopping);
}

bool kasumi_file_lock_busy(void)
{
	return atomic_read(&kasumi_file_lock_files) || atomic_read(&kasumi_file_lock_active);
}

KASUMI_NOCFI void kasumi_file_lock_stop(void)
{
	unsigned int i;

	WRITE_ONCE(kasumi_file_lock_stopping, true);
	for (i = 0; i < ARRAY_SIZE(kasumi_file_lock_hooks); i++) {
		struct kasumi_file_lock_hook *hook = &kasumi_file_lock_hooks[i];

		if (hook->registered) {
			unregister_kprobe(&hook->probe);
			hook->registered = false;
		}
	}
	wait_event(kasumi_file_lock_wait, !atomic_read(&kasumi_file_lock_active));
	if (kasumi_file_tasks_barrier)
		kasumi_file_tasks_barrier();
}

int kasumi_file_lock_init(void)
{
	unsigned int i;
	int ret;

	if (kasumi_file_lock_ready())
		return 0;
	if (!IS_ENABLED(CONFIG_ARM64) || !IS_ENABLED(CONFIG_FILE_LOCKING))
		return -EOPNOTSUPP;
	for (i = 0; i < ARRAY_SIZE(kasumi_file_lock_buckets); i++) {
		spin_lock_init(&kasumi_file_lock_buckets[i].lock);
		INIT_HLIST_HEAD(&kasumi_file_lock_buckets[i].guards);
	}
	kasumi_file_fcntl = (void *)kasumi_lookup_callable_quiet("do_fcntl");
	kasumi_file_security_fcntl = (void *)kasumi_lookup_callable_quiet("security_file_fcntl");
	kasumi_file_security_lock = (void *)kasumi_lookup_callable_quiet("security_file_lock");
	kasumi_file_vfs_lock = (void *)kasumi_lookup_callable_quiet("vfs_lock_file");
	kasumi_file_test_lock = (void *)kasumi_lookup_callable_quiet("vfs_test_lock");
	kasumi_file_delete_block = (void *)kasumi_lookup_callable_quiet("locks_delete_block");
	kasumi_file_inode_wait = (void *)kasumi_lookup_callable_quiet("locks_lock_inode_wait");
	kasumi_file_remove_posix = (void *)kasumi_lookup_callable_quiet("locks_remove_posix");
	kasumi_file_setlease = (void *)kasumi_lookup_callable_quiet("vfs_setlease");
	kasumi_file_tasks_barrier = (void *)kasumi_lookup_callable_quiet("synchronize_rcu_tasks");
	if (!kasumi_file_fcntl || !kasumi_file_security_fcntl || !kasumi_file_security_lock ||
	    !kasumi_file_vfs_lock || !kasumi_file_test_lock || !kasumi_file_delete_block ||
	    !kasumi_file_inode_wait || !kasumi_file_remove_posix || !kasumi_file_setlease ||
	    !kasumi_file_tasks_barrier)
		return -EOPNOTSUPP;
	for (i = 0; i < ARRAY_SIZE(kasumi_file_lock_hooks); i++) {
		struct kasumi_file_lock_hook *hook = &kasumi_file_lock_hooks[i];

		hook->original = (void *)kasumi_lookup_callable_quiet(hook->name);
		hook->probe.addr = (void *)kasumi_lookup_name_quiet(hook->name);
		if (!hook->original || !hook->probe.addr) {
			ret = -EOPNOTSUPP;
			goto fail;
		}
		hook->probe.pre_handler = kasumi_file_fcntl_pre;
		ret = register_kprobe(&hook->probe);
		if (ret)
			goto fail;
		hook->registered = true;
	}
	WRITE_ONCE(kasumi_file_lock_stopping, false);
	return 0;
fail:
	kasumi_file_lock_stop();
	return ret;
}

void kasumi_file_lock_exit(void)
{
	kasumi_file_lock_stop();
}
