#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/mount.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/wait.h>
#include <linux/xattr.h>

#include "fs/internal.h"

#include "kasumi_exec_view.h"
#include "kasumi_runtime.h"
#include "kasumi_vnode.h"

struct kasumi_exec_guard {
	struct hlist_node node;
	struct task_struct *task;
};

struct kasumi_exec_file {
	struct hlist_node node;
	struct file *file;
	struct file *source;
};

static DEFINE_HASHTABLE(kasumi_exec_files, 6);
static DEFINE_SPINLOCK(kasumi_exec_files_lock);

int kasumi_exec_file_hold(struct file *file, struct file *source)
{
	struct kasumi_exec_file *entry;
	unsigned long flags;
	int ret;

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	ret = exe_file_deny_write_access(source);
#else
	ret = deny_write_access(source);
#endif
	if (ret) {
		kfree(entry);
		return ret;
	}
	/* Open pins the source, then transfers ownership to the visible file. */
	entry->file = file;
	entry->source = source;
	spin_lock_irqsave(&kasumi_exec_files_lock, flags);
	hash_add(kasumi_exec_files, &entry->node, (unsigned long)file);
	spin_unlock_irqrestore(&kasumi_exec_files_lock, flags);
	return 0;
}

void kasumi_exec_file_release(struct file *file)
{
	struct kasumi_exec_file *entry, *found = NULL;
	unsigned long flags;

	spin_lock_irqsave(&kasumi_exec_files_lock, flags);
	hash_for_each_possible(kasumi_exec_files, entry, node, (unsigned long)file) {
		if (entry->file == file) {
			hash_del(&entry->node);
			found = entry;
			break;
		}
	}
	spin_unlock_irqrestore(&kasumi_exec_files_lock, flags);
	if (!found)
		return;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	exe_file_allow_write_access(found->source);
#else
	allow_write_access(found->source);
#endif
	kfree(found);
}

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
static bool kasumi_exec_caps_registered;
static struct kprobe kasumi_exec_caps_probe;
static typeof(do_filp_open) *kasumi_exec_original;
static void (*kasumi_exec_tasks_barrier)(void);

#ifdef CONFIG_USER_NS
#define KASUMI_EXEC_CAPS_SYMBOL "get_vfs_caps_from_disk"
#else
/* With identity namespaces/idmaps, LTO can inline the capability parser. */
#define KASUMI_EXEC_CAPS_SYMBOL "__vfs_getxattr"
#endif

bool kasumi_exec_view_ready(void)
{
	return !smp_load_acquire(&kasumi_exec_stopping);
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
kasumi_exec_entry(int fd, struct filename *name, const struct open_flags *flags)
{
	struct kasumi_exec_guard guard = {.task = current};
	spinlock_t *lock = &kasumi_exec_guard_locks[hash_min(
	    (unsigned long)guard.task, HASH_BITS(kasumi_exec_guards))];
	struct file *file;
	unsigned long irqflags;

	spin_lock_irqsave(lock, irqflags);
	hash_add(kasumi_exec_guards, &guard.node, (unsigned long)current);
	spin_unlock_irqrestore(lock, irqflags);
	file = kasumi_exec_original(fd, name, flags);
	file = kasumi_vnode_exec_open(file);
	spin_lock_irqsave(lock, irqflags);
	hash_del(&guard.node);
	spin_unlock_irqrestore(lock, irqflags);
	if (atomic_dec_and_test(&kasumi_exec_active))
		wake_up_all(&kasumi_exec_wait);
	return file;
}

static int kasumi_exec_pre(struct kprobe *probe, struct pt_regs *regs)
{
#ifdef CONFIG_ARM64
	const struct open_flags *flags = (void *)regs->regs[2];

	(void)probe;
	if (smp_load_acquire(&kasumi_exec_stopping))
		return 0;
	if (!flags || !(flags->open_flag & __FMODE_EXEC))
		return 0;
	if (kasumi_exec_guarded())
		return 0;
	atomic_inc(&kasumi_exec_active);
	instruction_pointer_set(regs, (unsigned long)kasumi_exec_entry);
	return 1;
#else
	(void)probe;
	(void)regs;
	return 0;
#endif
}

static int kasumi_exec_caps_pre(struct kprobe *probe, struct pt_regs *regs)
{
#ifdef CONFIG_ARM64
	const struct path *source;
#ifdef CONFIG_USER_NS
	struct cpu_vfs_cap_data *caps;
#endif
	const struct dentry *dentry;

	(void)probe;
#ifdef CONFIG_USER_NS
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	dentry = (void *)regs->regs[1];
	caps = (void *)regs->regs[2];
#else
	dentry = (void *)regs->regs[0];
	caps = (void *)regs->regs[1];
#endif
#else
	dentry = (void *)regs->regs[0];
#endif
	source = kasumi_vnode_caps_source(dentry);
	if (!source)
		return 0;
#ifndef CONFIG_USER_NS
	if (strcmp((const char *)regs->regs[2], XATTR_NAME_CAPS))
		return 0;
#endif
	if (IS_ERR(source) || !READ_ONCE(kasumi_fscaps_enabled)) {
#ifdef CONFIG_USER_NS
		*caps = (struct cpu_vfs_cap_data){};
#endif
		regs->regs[0] = IS_ERR(source) ? PTR_ERR(source) : -ENODATA;
		instruction_pointer_set(regs, regs->regs[30]);
		return 1;
	}
#ifdef CONFIG_USER_NS
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	regs->regs[0] = (unsigned long)mnt_idmap(source->mnt);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	regs->regs[0] = (unsigned long)mnt_user_ns(source->mnt);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	regs->regs[1] = (unsigned long)source->dentry;
#else
	regs->regs[0] = (unsigned long)source->dentry;
#endif
#else
	regs->regs[0] = (unsigned long)source->dentry;
	regs->regs[1] = (unsigned long)d_inode(source->dentry);
#endif
#else
	(void)probe;
	(void)regs;
#endif
	return 0;
}

struct kasumi_exec_symbol {
	const char *name;
	unsigned long address;
	bool ambiguous;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
static int kasumi_exec_collect_symbol(void *data, const char *name,
				      unsigned long address)
#else
static int kasumi_exec_collect_symbol(void *data, const char *name,
				      struct module *module,
				      unsigned long address)
#endif
{
	struct kasumi_exec_symbol *symbol = data;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
	if (module)
		return 0;
#endif
	if (strcmp(name, symbol->name))
		return 0;
	if (symbol->address && symbol->address != address)
		symbol->ambiguous = true;
	symbol->address = address;
	return 0;
}

static KASUMI_NOCFI unsigned long kasumi_exec_resolve(const char *symbol)
{
	typeof(kallsyms_on_each_symbol) *each_symbol =
	    (void *)kasumi_lookup_callable_quiet("kallsyms_on_each_symbol");
	typeof(kallsyms_lookup) *lookup =
	    (void *)kasumi_lookup_callable_quiet("kallsyms_lookup");
	struct kasumi_exec_symbol target = {.name = symbol};
	unsigned long size, offset;
	char buffer[KSYM_NAME_LEN];
	char *module = NULL;
	const char *name;

	if (!each_symbol || !lookup ||
	    each_symbol(kasumi_exec_collect_symbol, &target) ||
	    target.ambiguous || !target.address || (target.address & 3))
		return 0;
	name = lookup(target.address, &size, &offset, &module, buffer);
	if (!name || module || offset || strcmp(name, symbol) ||
	    size < sizeof(u32) || size > SZ_16K || (size & 3))
		return 0;
	return target.address;
}

KASUMI_NOCFI void kasumi_exec_view_stop(void)
{
	smp_store_release(&kasumi_exec_stopping, true);
	if (kasumi_exec_registered) {
		unregister_kprobe(&kasumi_exec_probe);
		kasumi_exec_registered = false;
	}
	wait_event(kasumi_exec_wait, !atomic_read(&kasumi_exec_active));
	if (kasumi_exec_tasks_barrier)
		kasumi_exec_tasks_barrier();
	kasumi_exec_original = NULL;
	kasumi_exec_tasks_barrier = NULL;
	kasumi_exec_probe.addr = NULL;
}

static void kasumi_exec_caps_exit(void)
{
	if (kasumi_exec_caps_registered) {
		unregister_kprobe(&kasumi_exec_caps_probe);
		kasumi_exec_caps_registered = false;
		WRITE_ONCE(kasumi_fscap_kretprobe_registered, 0);
	}
	kasumi_exec_caps_probe.addr = NULL;
}

int kasumi_exec_view_init(void)
{
	bool caps_ready = kasumi_exec_caps_registered;
	unsigned long address;
	int ret;

	if (kasumi_exec_view_ready())
		return 0;
#ifndef CONFIG_ARM64
	return -EOPNOTSUPP;
#endif
	if (!caps_ready) {
		address = kasumi_exec_resolve(KASUMI_EXEC_CAPS_SYMBOL);
		if (!address) {
			pr_err("kasumi: unverified VFS capability reader\n");
			ret = -EOPNOTSUPP;
			goto fail;
		}
		kasumi_exec_caps_probe.addr = (void *)address;
		kasumi_exec_caps_probe.flags = KPROBE_FLAG_DISABLED;
		kasumi_exec_caps_probe.pre_handler = kasumi_exec_caps_pre;
		ret = register_kprobe(&kasumi_exec_caps_probe);
		if (ret)
			goto fail;
		kasumi_exec_caps_registered = true;
		if ((unsigned long)kasumi_exec_caps_probe.addr != address) {
			ret = -EOPNOTSUPP;
			goto fail;
		}
	}
	address = kasumi_exec_resolve("do_filp_open");
	if (!address) {
		pr_err("kasumi: unverified VFS exec entry: do_filp_open\n");
		ret = -EOPNOTSUPP;
		goto fail;
	}
	kasumi_exec_tasks_barrier =
	    (void *)kasumi_lookup_callable_quiet("synchronize_rcu_tasks");
	if (!kasumi_exec_tasks_barrier) {
		pr_err("kasumi: exec reader barrier unavailable\n");
		ret = -EOPNOTSUPP;
		goto fail;
	}
	kasumi_exec_probe.addr = (void *)address;
	kasumi_exec_probe.flags = KPROBE_FLAG_DISABLED;
	kasumi_exec_probe.pre_handler = kasumi_exec_pre;
	ret = register_kprobe(&kasumi_exec_probe);
	if (ret)
		goto fail;
	kasumi_exec_registered = true;
	if ((unsigned long)kasumi_exec_probe.addr != address) {
		pr_err("kasumi: VFS exec probe moved: do_filp_open\n");
		ret = -EOPNOTSUPP;
		goto fail;
	}
	kasumi_exec_original = (void *)kasumi_exec_probe.addr;
	if (!caps_ready) {
		ret = enable_kprobe(&kasumi_exec_caps_probe);
		if (ret)
			goto fail;
		WRITE_ONCE(kasumi_fscap_kretprobe_registered, 1);
	}
	ret = enable_kprobe(&kasumi_exec_probe);
	if (ret)
		goto fail;
	smp_store_release(&kasumi_exec_stopping, false);
	pr_info("kasumi: visible exec bridge via do_filp_open\n");
	return 0;
fail:
	kasumi_exec_view_stop();
	if (!caps_ready)
		kasumi_exec_caps_exit();
	return ret;
}

void kasumi_exec_view_exit(void)
{
	kasumi_exec_view_stop();
	/* Open executable vnodes still need capability reads while draining. */
	kasumi_exec_caps_exit();
	WARN_ON_ONCE(!hash_empty(kasumi_exec_files));
}
