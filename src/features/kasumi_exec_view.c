#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/kprobes.h>
#include <linux/wait.h>

#include "fs/internal.h"

#include "kasumi_exec_view.h"
#include "kasumi_runtime.h"
#include "kasumi_vnode.h"

struct kasumi_exec_guard {
	struct hlist_node node;
	struct task_struct *task;
};

static DEFINE_HASHTABLE(kasumi_exec_guards, 6);
static spinlock_t kasumi_exec_guard_locks[HASH_SIZE(kasumi_exec_guards)] = {
	[0 ... HASH_SIZE(kasumi_exec_guards) - 1] =
		__SPIN_LOCK_UNLOCKED(kasumi_exec_guard_locks),
};
static DECLARE_WAIT_QUEUE_HEAD(kasumi_exec_wait);
static atomic_t kasumi_exec_active = ATOMIC_INIT(0);
static bool kasumi_exec_stopping = true;
static bool kasumi_exec_registered;
static struct kprobe kasumi_exec_probe;
static struct file *(*kasumi_exec_original)(int, struct filename *, int);
static void (*kasumi_exec_tasks_barrier)(void);
static struct file *(*kasumi_exec_open_original)(int, struct filename *,
						 const struct open_flags *);
static bool kasumi_exec_open_fallback;

bool kasumi_exec_view_ready(void)
{
	return !READ_ONCE(kasumi_exec_stopping);
}

static bool kasumi_exec_guarded(void)
{
	spinlock_t *lock = &kasumi_exec_guard_locks[
		hash_min((unsigned long)current, HASH_BITS(kasumi_exec_guards))];
	struct kasumi_exec_guard *guard;
	unsigned long flags;
	bool found = false;

	spin_lock_irqsave(lock, flags);
	hash_for_each_possible(kasumi_exec_guards, guard, node, (unsigned long)current) {
		if (guard->task == current) {
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(lock, flags);
	return found;
}

static KASUMI_NOCFI struct file *
kasumi_exec_entry(int fd, struct filename *name, unsigned long argument)
{
	struct kasumi_exec_guard guard = { .task = current };
	spinlock_t *lock = &kasumi_exec_guard_locks[
		hash_min((unsigned long)guard.task, HASH_BITS(kasumi_exec_guards))];
	struct file *file;
	unsigned long irqflags;

	spin_lock_irqsave(lock, irqflags);
	hash_add(kasumi_exec_guards, &guard.node, (unsigned long)current);
	spin_unlock_irqrestore(lock, irqflags);
	if (kasumi_exec_open_fallback) {
		file = kasumi_exec_open_original(fd, name, (void *)argument);
		/* do_open_execat will acquire the deny token on this source
		 * file. */
		file = kasumi_vnode_exec_open(file);
	} else {
		file = kasumi_exec_original(fd, name, (int)argument);
		file = kasumi_vnode_exec_file(file);
	}
	spin_lock_irqsave(lock, irqflags);
	hash_del(&guard.node);
	spin_unlock_irqrestore(lock, irqflags);
	if (atomic_dec_and_test(&kasumi_exec_active))
		wake_up_all(&kasumi_exec_wait);
	return file;
}

static int kasumi_exec_pre(struct kprobe *probe, struct pt_regs *regs)
{
	(void)probe;
#ifdef CONFIG_ARM64
	if (READ_ONCE(kasumi_exec_stopping))
		return 0;
	if (kasumi_exec_open_fallback) {
		const struct open_flags *flags = (void *)regs->regs[2];

		if (!flags || !(flags->open_flag & __FMODE_EXEC))
			return 0;
	}
	if (kasumi_exec_guarded())
		return 0;
	atomic_inc(&kasumi_exec_active);
	instruction_pointer_set(regs, (unsigned long)kasumi_exec_entry);
	return 1;
#else
	return 0;
#endif
}

KASUMI_NOCFI void kasumi_exec_view_stop(void)
{
	WRITE_ONCE(kasumi_exec_stopping, true);
	if (kasumi_exec_registered) {
		unregister_kprobe(&kasumi_exec_probe);
		kasumi_exec_registered = false;
	}
	wait_event(kasumi_exec_wait, !atomic_read(&kasumi_exec_active));
	if (kasumi_exec_tasks_barrier)
		kasumi_exec_tasks_barrier();
}

int kasumi_exec_view_init(void)
{
	int ret;

	if (!READ_ONCE(kasumi_exec_stopping))
		return 0;
#ifndef CONFIG_ARM64
	return -EOPNOTSUPP;
#endif
	kasumi_exec_original = (void *)kasumi_lookup_callable_quiet("do_open_execat");
	kasumi_exec_tasks_barrier =
		(void *)kasumi_lookup_callable_quiet("synchronize_rcu_tasks");
	kasumi_exec_open_fallback = !kasumi_exec_original;
	if (kasumi_exec_open_fallback)
		kasumi_exec_open_original =
		    (void *)kasumi_lookup_callable_quiet("do_filp_open");
	if ((!kasumi_exec_original && !kasumi_exec_open_original) ||
	    !kasumi_exec_tasks_barrier)
		return -EOPNOTSUPP;
	kasumi_exec_probe.addr = (void *)kasumi_lookup_name_quiet(
	    kasumi_exec_open_fallback ? "do_filp_open" : "do_open_execat");
	kasumi_exec_probe.pre_handler = kasumi_exec_pre;
	ret = register_kprobe(&kasumi_exec_probe);
	if (ret)
		return ret;
	kasumi_exec_registered = true;
	WRITE_ONCE(kasumi_exec_stopping, false);
	return 0;
}

void kasumi_exec_view_exit(void)
{
	kasumi_exec_view_stop();
}
