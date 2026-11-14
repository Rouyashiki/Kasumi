/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - explicitly retired per-superblock super_operations owner.
 *
 * A shadowed superblock carries an extra s_active reference. A userspace
 * umount may therefore detach the mount, but generic_shutdown_super() cannot
 * poison busy Kasumi inodes while a rule or vnode still needs our reclaim
 * callbacks. CLEAR/PREPARE withdraw every client, wait for vnode reclaim,
 * restore s_op outside callback context, drain stale dispatches, and only then
 * release the superblock and module references.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include "kasumi_sop_shadow.h"
#include "kasumi_dirhijack.h"
#include "kasumi_runtime.h"
#include "kasumi_vnode.h"
#include "kasumi_identity.h"

#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/srcu.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/version.h>

#define KASUMI_SOP_HASH_BITS 8

struct kasumi_sop_meta {
	struct super_block *sb;
	const struct super_operations *orig_sop;
	struct super_operations shadow_sop;
	atomic_t vnode_live;
	atomic_t callback_active;
	unsigned int dh_clients;
	bool accepting_vnodes;
	bool restoring;
	bool sb_active_held;
	bool module_pin_held;
	struct hlist_node node;
	struct list_head retire_node;
};

static DEFINE_HASHTABLE(kasumi_sop_table, KASUMI_SOP_HASH_BITS);
/* Leaf lock: never allocate, wait, take s_umount, or deactivate under it. */
static DEFINE_SPINLOCK(kasumi_sop_lock);
/* Serializes install and the sleepable restore/drain/release sequence. */
static DEFINE_MUTEX(kasumi_sop_manage_lock);
static atomic_t kasumi_sop_active = ATOMIC_INIT(0);
static atomic_t kasumi_sop_live = ATOMIC_INIT(0);
static atomic_t kasumi_sop_vnodes = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(kasumi_sop_wait);
static bool kasumi_sop_ready;
static bool kasumi_sop_reap_work_enabled;
static struct kmem_cache *kasumi_inode_cache;
static void (*kasumi_inode_sb_list_add)(struct inode *inode);
static void (*kasumi_inode_rcu_free)(struct rcu_head *head);

struct kasumi_sop_reader_guard {
	struct hlist_node node;
	struct task_struct *task;
	int index;
};

static DEFINE_HASHTABLE(kasumi_sop_reader_guards, 6);
static spinlock_t kasumi_sop_reader_locks[HASH_SIZE(kasumi_sop_reader_guards)] = {
	[0 ... HASH_SIZE(kasumi_sop_reader_guards) - 1] =
		__SPIN_LOCK_UNLOCKED(kasumi_sop_reader_locks),
};
static DEFINE_MUTEX(kasumi_sop_reader_manage_lock);
DEFINE_STATIC_SRCU(kasumi_sop_readers);
static atomic_t kasumi_sop_reader_active = ATOMIC_INIT(0);
static bool kasumi_sop_readers_stopping = true;
static unsigned int kasumi_sop_reader_registered;
static struct inode *(*kasumi_sop_native_alloc)(struct super_block *sb);
static void (*kasumi_sop_native_evict)(struct inode *inode);
static void (*kasumi_sop_native_destroy)(struct inode *inode);

static bool kasumi_sop_reader_guarded(void)
{
	spinlock_t *lock = &kasumi_sop_reader_locks[
		hash_min((unsigned long)current, HASH_BITS(kasumi_sop_reader_guards))];
	struct kasumi_sop_reader_guard *guard;
	unsigned long flags;
	bool found = false;

	spin_lock_irqsave(lock, flags);
	hash_for_each_possible(kasumi_sop_reader_guards, guard, node,
			       (unsigned long)current) {
		if (guard->task == current) {
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(lock, flags);
	return found;
}

static void kasumi_sop_reader_enter(struct kasumi_sop_reader_guard *guard)
{
	spinlock_t *lock = &kasumi_sop_reader_locks[
		hash_min((unsigned long)current, HASH_BITS(kasumi_sop_reader_guards))];
	unsigned long flags;

	guard->index = srcu_read_lock(&kasumi_sop_readers);
	guard->task = current;
	spin_lock_irqsave(lock, flags);
	hash_add(kasumi_sop_reader_guards, &guard->node, (unsigned long)current);
	spin_unlock_irqrestore(lock, flags);
}

static void kasumi_sop_reader_leave(struct kasumi_sop_reader_guard *guard)
{
	spinlock_t *lock = &kasumi_sop_reader_locks[
		hash_min((unsigned long)guard->task, HASH_BITS(kasumi_sop_reader_guards))];
	unsigned long flags;

	spin_lock_irqsave(lock, flags);
	hash_del(&guard->node);
	spin_unlock_irqrestore(lock, flags);
	srcu_read_unlock(&kasumi_sop_readers, guard->index);
	if (atomic_dec_and_test(&kasumi_sop_reader_active))
		wake_up_all(&kasumi_sop_wait);
}

static KASUMI_NOCFI struct inode *kasumi_sop_alloc_entry(struct super_block *sb)
{
	struct kasumi_sop_reader_guard guard;
	struct inode *inode;

	kasumi_sop_reader_enter(&guard);
	inode = kasumi_sop_native_alloc(sb);
	kasumi_sop_reader_leave(&guard);
	return inode;
}

static KASUMI_NOCFI void kasumi_sop_evict_entry(struct inode *inode)
{
	struct kasumi_sop_reader_guard guard;

	kasumi_sop_reader_enter(&guard);
	kasumi_sop_native_evict(inode);
	kasumi_sop_reader_leave(&guard);
}

static KASUMI_NOCFI void kasumi_sop_destroy_entry(struct inode *inode)
{
	struct kasumi_sop_reader_guard guard;

	kasumi_sop_reader_enter(&guard);
	kasumi_sop_native_destroy(inode);
	kasumi_sop_reader_leave(&guard);
}

static int kasumi_sop_alloc_pre(struct kprobe *probe, struct pt_regs *regs);
static int kasumi_sop_evict_pre(struct kprobe *probe, struct pt_regs *regs);
static int kasumi_sop_shutdown_pre(struct kprobe *probe, struct pt_regs *regs);
static int kasumi_sop_destroy_pre(struct kprobe *probe, struct pt_regs *regs);

static struct kprobe kasumi_sop_reader_probes[] = {
	{ .symbol_name = "alloc_inode", .pre_handler = kasumi_sop_alloc_pre },
	{ .symbol_name = "evict", .pre_handler = kasumi_sop_evict_pre },
	{ .symbol_name = "__destroy_inode", .pre_handler = kasumi_sop_destroy_pre },
	{ .symbol_name = "generic_shutdown_super", .pre_handler = kasumi_sop_shutdown_pre },
};

static int kasumi_sop_reader_pre(struct pt_regs *regs, unsigned long entry)
{
#ifdef CONFIG_ARM64
	if (READ_ONCE(kasumi_sop_readers_stopping) || kasumi_sop_reader_guarded())
		return 0;
	atomic_inc(&kasumi_sop_reader_active);
	instruction_pointer_set(regs, entry);
	return 1;
#else
	return 0;
#endif
}

static int kasumi_sop_alloc_pre(struct kprobe *probe, struct pt_regs *regs)
{
	return kasumi_sop_reader_pre(regs, (unsigned long)kasumi_sop_alloc_entry);
}

static int kasumi_sop_evict_pre(struct kprobe *probe, struct pt_regs *regs)
{
#ifdef CONFIG_ARM64
	struct inode *inode = (struct inode *)regs->regs[0];

	if (inode && !READ_ONCE(inode->i_nlink) && !kasumi_vnode_is_ours(inode))
		kasumi_identity_source_evict(inode->i_sb->s_dev, inode->i_ino);
#endif
	return kasumi_sop_reader_pre(regs, (unsigned long)kasumi_sop_evict_entry);
}

static int kasumi_sop_shutdown_pre(struct kprobe *probe, struct pt_regs *regs)
{
#ifdef CONFIG_ARM64
	struct super_block *sb = (struct super_block *)regs->regs[0];

	if (sb)
		kasumi_identity_source_unmount(sb->s_dev);
#endif
	return 0;
}

static int kasumi_sop_destroy_pre(struct kprobe *probe, struct pt_regs *regs)
{
	return kasumi_sop_reader_pre(regs, (unsigned long)kasumi_sop_destroy_entry);
}

static void kasumi_sop_readers_stop(void)
{
	mutex_lock(&kasumi_sop_reader_manage_lock);
	if (kasumi_sop_readers_stopping && !kasumi_sop_reader_registered)
		goto unlock;
	WRITE_ONCE(kasumi_sop_readers_stopping, true);
	while (kasumi_sop_reader_registered)
		unregister_kprobe(&kasumi_sop_reader_probes[--kasumi_sop_reader_registered]);
	wait_event(kasumi_sop_wait, !atomic_read(&kasumi_sop_reader_active));
	kasumi_synchronize_rcu_tasks();
unlock:
	mutex_unlock(&kasumi_sop_reader_manage_lock);
}

static int kasumi_sop_readers_init(void)
{
	unsigned int i;
	int ret;

#ifndef CONFIG_ARM64
	return -EOPNOTSUPP;
#endif
	kasumi_sop_native_alloc = (void *)kasumi_lookup_callable_quiet("alloc_inode");
	kasumi_sop_native_evict = (void *)kasumi_lookup_callable_quiet("evict");
	kasumi_sop_native_destroy = (void *)kasumi_lookup_callable_quiet("__destroy_inode");
	if (!kasumi_sop_native_alloc || !kasumi_sop_native_evict || !kasumi_sop_native_destroy)
		return -EOPNOTSUPP;
	for (i = 0; i < ARRAY_SIZE(kasumi_sop_reader_probes); ++i) {
		ret = register_kprobe(&kasumi_sop_reader_probes[i]);
		if (ret) {
			kasumi_sop_readers_stop();
			return ret;
		}
		kasumi_sop_reader_registered++;
	}
	WRITE_ONCE(kasumi_sop_readers_stopping, false);
	/* Pre-install callers can only retain the unmodified native vector. */
	kasumi_synchronize_rcu_tasks();
	return 0;
}

static void kasumi_sop_reap_workfn(struct work_struct *work);
static DECLARE_WORK(kasumi_sop_reap_work, kasumi_sop_reap_workfn);

static struct kasumi_sop_meta *kasumi_sop_lookup_rcu(struct super_block *sb)
{
	struct kasumi_sop_meta *m;

	hash_for_each_possible_rcu(kasumi_sop_table, m, node,
				   (unsigned long)sb) {
		if (m->sb == sb)
			return m;
	}
	return NULL;
}

static struct kasumi_sop_meta *kasumi_sop_lookup_locked(struct super_block *sb)
{
	struct kasumi_sop_meta *m;

	hash_for_each_possible(kasumi_sop_table, m, node,
				 (unsigned long)sb) {
		if (m->sb == sb)
			return m;
	}
	return NULL;
}

/* The hash entry stays published until after pointer restore + double
 * Tasks-RCU, so every stale callback can still resolve its original vector. */
static struct kasumi_sop_meta *
kasumi_sop_callback_enter(struct super_block *sb,
			  const struct super_operations **orig)
{
	struct kasumi_sop_meta *m;

	*orig = NULL;
	atomic_inc(&kasumi_sop_active);
	rcu_read_lock();
	m = kasumi_sop_lookup_rcu(sb);
	if (m) {
		atomic_inc(&m->callback_active);
		*orig = m->orig_sop;
	}
	rcu_read_unlock();
	return m;
}

static void kasumi_sop_callback_exit(struct kasumi_sop_meta *m)
{
	if (m && atomic_dec_and_test(&m->callback_active))
		wake_up_all(&kasumi_sop_wait);
	if (atomic_dec_and_test(&kasumi_sop_active))
		wake_up_all(&kasumi_sop_wait);
}

KASUMI_NOCFI static void kasumi_sop_destroy_inode(struct inode *inode)
{
	struct kasumi_sop_meta *m;
	const struct super_operations *orig;

	m = kasumi_sop_callback_enter(inode ? inode->i_sb : NULL, &orig);
	if (kasumi_vnode_is_ours(inode)) {
		kasumi_vnode_free_info(inode);
		inode->free_inode = kasumi_free_inode_nonrcu_ptr;
	} else {
		if (orig && orig->destroy_inode) {
			orig->destroy_inode(inode);
			if (!orig->free_inode)
				goto out;
		}
		inode->free_inode = orig ? orig->free_inode : NULL;
	}
	/* The kernel callback outlives this module and retains the native free ABI. */
	call_rcu(&inode->i_rcu, kasumi_inode_rcu_free);
out:
	kasumi_sop_callback_exit(m);
}

struct inode *KASUMI_NOCFI kasumi_sop_new_inode(struct super_block *sb)
{
	struct inode *inode;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	inode = alloc_inode_sb(sb, kasumi_inode_cache, GFP_KERNEL);
#else
	inode = kmem_cache_alloc(kasumi_inode_cache, GFP_KERNEL);
#endif
	if (!inode)
		return NULL;
	if (inode_init_always(sb, inode)) {
		kasumi_free_inode_nonrcu_ptr(inode);
		return NULL;
	}
	spin_lock(&inode->i_lock);
	inode->i_state = 0;
	INIT_LIST_HEAD(&inode->i_sb_list);
	spin_unlock(&inode->i_lock);
	kasumi_inode_sb_list_add(inode);
	return inode;
}

KASUMI_NOCFI static void kasumi_sop_evict_inode(struct inode *inode)
{
	struct kasumi_sop_meta *m;
	const struct super_operations *orig;

	m = kasumi_sop_callback_enter(inode ? inode->i_sb : NULL, &orig);
	kasumi_dh_reclaim_evict_inode(inode, orig);
	kasumi_sop_callback_exit(m);
}

KASUMI_NOCFI static int kasumi_sop_drop_inode(struct inode *inode)
{
	struct kasumi_sop_meta *m;
	const struct super_operations *orig;
	int ret;

	m = kasumi_sop_callback_enter(inode ? inode->i_sb : NULL, &orig);
	ret = kasumi_dh_reclaim_drop_inode(inode, orig);
	kasumi_sop_callback_exit(m);
	return ret;
}

static void kasumi_sop_drop_install_refs(struct super_block *sb,
					 bool active_held,
					 bool module_held)
{
	/* A control fd plus the bootstrap lifecycle pin remains held while this
	 * helper runs, so module_put() cannot unmap the function returning here. */
	if (active_held)
		deactivate_super(sb);
	if (module_held)
		module_put(THIS_MODULE);
}

int kasumi_sop_shadow_register_dh(struct super_block *sb)
{
	struct kasumi_sop_meta *m, *spare;
	const struct super_operations *orig;
	bool active_held = false;
	bool module_held = false;
	int ret = 0;

	if (!sb || !READ_ONCE(sb->s_op))
		return -EINVAL;
	if (!READ_ONCE(kasumi_sop_ready))
		return -ESHUTDOWN;

	spare = kzalloc(sizeof(*spare), GFP_KERNEL);
	if (!spare)
		return -ENOMEM;

	mutex_lock(&kasumi_sop_manage_lock);
	spin_lock(&kasumi_sop_lock);
	m = kasumi_sop_lookup_locked(sb);
	if (m) {
		if (!READ_ONCE(kasumi_sop_ready) || m->restoring ||
		    READ_ONCE(sb->s_op) != &m->shadow_sop) {
			ret = -ESHUTDOWN;
		} else {
			m->dh_clients++;
			m->accepting_vnodes = true;
		}
		spin_unlock(&kasumi_sop_lock);
		goto out_unlock;
	}
	spin_unlock(&kasumi_sop_lock);

	/* s_umount excludes a concurrent shutdown transition while the extra
	 * s_active reference is acquired. The caller still owns a live path. */
	down_read(&sb->s_umount);
	if (!READ_ONCE(kasumi_sop_ready) ||
	    !(READ_ONCE(sb->s_flags) & SB_BORN) ||
	    !atomic_inc_not_zero(&sb->s_active)) {
		ret = -ESHUTDOWN;
		goto out_s_umount;
	}
	active_held = true;
	if (!try_module_get(THIS_MODULE)) {
		ret = -ESHUTDOWN;
		goto out_s_umount;
	}
	module_held = true;

	orig = READ_ONCE(sb->s_op);
	if (!orig) {
		ret = -EINVAL;
		goto out_s_umount;
	}
	spare->sb = sb;
	spare->orig_sop = orig;
	spare->shadow_sop = *orig;
	atomic_set(&spare->vnode_live, 0);
	atomic_set(&spare->callback_active, 0);
	spare->dh_clients = 1;
	spare->accepting_vnodes = true;
	spare->sb_active_held = true;
	spare->module_pin_held = true;

	/* The synchronous trampoline queues the kernel's own RCU free callback.
	 * A NULL free_inode prevents VFS from overwriting its per-inode choice. */
	spare->shadow_sop.destroy_inode = kasumi_sop_destroy_inode;
	spare->shadow_sop.free_inode = NULL;
	spare->shadow_sop.evict_inode = kasumi_sop_evict_inode;
	spare->shadow_sop.drop_inode = kasumi_sop_drop_inode;

	spin_lock(&kasumi_sop_lock);
	if (!READ_ONCE(kasumi_sop_ready) || READ_ONCE(sb->s_op) != orig ||
	    kasumi_sop_lookup_locked(sb)) {
		ret = -EAGAIN;
	} else {
		hash_add_rcu(kasumi_sop_table, &spare->node,
			     (unsigned long)sb);
		atomic_inc(&kasumi_sop_live);
		smp_wmb();
		smp_store_release(&sb->s_op, &spare->shadow_sop);
		spare = NULL;
		active_held = false;
		module_held = false;
	}
	spin_unlock(&kasumi_sop_lock);

out_s_umount:
	up_read(&sb->s_umount);
	if (ret)
		kasumi_sop_drop_install_refs(sb, active_held, module_held);
out_unlock:
	mutex_unlock(&kasumi_sop_manage_lock);
	kfree(spare);
	if (!ret)
		kasumi_log("sop_shadow: client registered on sb %p\n", sb);
	return ret;
}

void kasumi_sop_shadow_unregister_dh(struct super_block *sb)
{
	struct kasumi_sop_meta *m;

	if (!sb)
		return;
	spin_lock(&kasumi_sop_lock);
	m = kasumi_sop_lookup_locked(sb);
	if (m) {
		if (WARN_ON_ONCE(!m->dh_clients)) {
			m->accepting_vnodes = false;
		} else if (!--m->dh_clients) {
			m->accepting_vnodes = false;
		}
	}
	spin_unlock(&kasumi_sop_lock);
	wake_up_all(&kasumi_sop_wait);
}

bool kasumi_sop_vnode_get(struct super_block *sb)
{
	struct kasumi_sop_meta *m;
	bool got = false;

	if (!sb)
		return false;
	spin_lock(&kasumi_sop_lock);
	m = kasumi_sop_lookup_locked(sb);
	if (m && m->accepting_vnodes && !m->restoring) {
		atomic_inc(&m->vnode_live);
		atomic_inc(&kasumi_sop_vnodes);
		got = true;
	}
	spin_unlock(&kasumi_sop_lock);
	return got;
}

void kasumi_sop_vnode_put(struct super_block *sb)
{
	struct kasumi_sop_meta *m;

	if (!sb)
		return;
	spin_lock(&kasumi_sop_lock);
	m = kasumi_sop_lookup_locked(sb);
	if (WARN_ON_ONCE(!m || atomic_read(&m->vnode_live) <= 0)) {
		spin_unlock(&kasumi_sop_lock);
		return;
	}
	if (atomic_dec_and_test(&m->vnode_live) && !m->dh_clients &&
	    !m->restoring && kasumi_sop_reap_work_enabled) {
		/* schedule_work() is atomic-safe; queueing under this lock pairs
		 * with exit's disable-before-cancel sequence.
		 */
		schedule_work(&kasumi_sop_reap_work);
	}
	atomic_dec(&kasumi_sop_vnodes);
	spin_unlock(&kasumi_sop_lock);
	/* vnode_put() runs from the synchronous destroy_inode trampoline.  Reaping
	 * takes s_umount, waits for callbacks, synchronizes RCU and may deactivate
	 * the superblock, so only request it here and do the work in process
	 * context.
	 */
	wake_up_all(&kasumi_sop_wait);
}

static void kasumi_sop_restore_meta(struct kasumi_sop_meta *m)
{
	struct super_block *sb = m->sb;

	/* The retained s_active reference excludes shutdown during restoration. */
	down_read(&sb->s_umount);
	spin_lock(&kasumi_sop_lock);
	if (READ_ONCE(sb->s_op) == &m->shadow_sop)
		smp_store_release(&sb->s_op, m->orig_sop);
	else
		WARN_ON_ONCE(READ_ONCE(sb->s_op) != m->orig_sop);
	spin_unlock(&kasumi_sop_lock);
	up_read(&sb->s_umount);
}

static void kasumi_sop_reap_batch(struct list_head *retiring)
{
	struct kasumi_sop_meta *m, *next;

	list_for_each_entry(m, retiring, retire_node)
		kasumi_sop_restore_meta(m);
	/* Drain dispatches which loaded any of the withdrawn operation vectors. */
	kasumi_synchronize_rcu_tasks();
	synchronize_srcu(&kasumi_sop_readers);
	/* Cover __destroy_inode returning to an inlined caller's cached vector. */
	kasumi_synchronize_rcu_tasks();
	list_for_each_entry(m, retiring, retire_node)
		wait_event(kasumi_sop_wait, !atomic_read(&m->callback_active));
	/* Cover callback epilogues after their active count reached zero. */
	kasumi_synchronize_rcu_tasks();

	spin_lock(&kasumi_sop_lock);
	list_for_each_entry(m, retiring, retire_node) {
		WARN_ON_ONCE(m->dh_clients || atomic_read(&m->vnode_live));
		hash_del_rcu(&m->node);
		atomic_dec(&kasumi_sop_live);
	}
	spin_unlock(&kasumi_sop_lock);
	synchronize_rcu();

	list_for_each_entry_safe(m, next, retiring, retire_node) {
		struct super_block *sb = m->sb;
		bool active_held = m->sb_active_held;
		bool module_held = m->module_pin_held;

		list_del(&m->retire_node);
		kasumi_log("sop_shadow: retired sb %p\n", sb);
		kfree(m);
		/* The last active reference may trigger the native shutdown path. */
		kasumi_sop_drop_install_refs(sb, active_held, module_held);
	}
	wake_up_all(&kasumi_sop_wait);
}

void kasumi_sop_shadow_reap(void)
{
	struct kasumi_sop_meta *m;
	LIST_HEAD(retiring);
	int bucket;

	mutex_lock(&kasumi_sop_manage_lock);
	spin_lock(&kasumi_sop_lock);
	hash_for_each(kasumi_sop_table, bucket, m, node) {
		if (!m->restoring && !m->dh_clients &&
		    !atomic_read(&m->vnode_live)) {
			m->accepting_vnodes = false;
			m->restoring = true;
			list_add_tail(&m->retire_node, &retiring);
		}
	}
	spin_unlock(&kasumi_sop_lock);
	if (!list_empty(&retiring))
		kasumi_sop_reap_batch(&retiring);
	mutex_unlock(&kasumi_sop_manage_lock);
}

static void kasumi_sop_reap_workfn(struct work_struct *work)
{
	(void)work;
	kasumi_sop_shadow_reap();
}

int kasumi_sop_shadow_init(void)
{
	struct kmem_cache **cache;
	int ret;

	cache = (void *)kasumi_lookup_name_quiet("inode_cachep");
	kasumi_inode_sb_list_add =
		(void *)kasumi_lookup_callable_quiet("inode_sb_list_add");
	kasumi_inode_rcu_free = (void *)kasumi_lookup_callable_quiet("i_callback");
	if (!cache || !READ_ONCE(*cache) || !kasumi_inode_sb_list_add ||
	    !kasumi_inode_rcu_free || !kasumi_free_inode_nonrcu_ptr)
		return -EOPNOTSUPP;
	kasumi_inode_cache = READ_ONCE(*cache);
	hash_init(kasumi_sop_table);
	atomic_set(&kasumi_sop_active, 0);
	atomic_set(&kasumi_sop_live, 0);
	atomic_set(&kasumi_sop_vnodes, 0);
	ret = kasumi_sop_readers_init();
	if (ret)
		return ret;
	WRITE_ONCE(kasumi_sop_reap_work_enabled, true);
	WRITE_ONCE(kasumi_sop_ready, true);
	pr_info("Kasumi: sop_shadow initialized\n");
	return 0;
}

bool kasumi_sop_shadow_available(void)
{
	return READ_ONCE(kasumi_sop_ready);
}

unsigned int kasumi_sop_shadow_installed(void)
{
	return (unsigned int)atomic_read(&kasumi_sop_live);
}

unsigned int kasumi_sop_shadow_active(void)
{
	return (unsigned int)atomic_read(&kasumi_sop_active);
}

void kasumi_sop_shadow_stop_new(void)
{
	struct kasumi_sop_meta *m;
	int bkt;

	WRITE_ONCE(kasumi_sop_ready, false);
	spin_lock(&kasumi_sop_lock);
	hash_for_each(kasumi_sop_table, bkt, m, node)
		m->accepting_vnodes = false;
	spin_unlock(&kasumi_sop_lock);
	kasumi_sop_shadow_reap();
	/* Pair with a late final vnode_put() that may have queued the sleepable
	 * reap while stop_new() was scanning the table.
	 */
	flush_work(&kasumi_sop_reap_work);
}

bool kasumi_sop_shadow_quiesced(void)
{
	if (READ_ONCE(kasumi_sop_ready))
		return false;
	kasumi_sop_shadow_reap();
	flush_work(&kasumi_sop_reap_work);
	/* The worker may have waited behind the synchronous pass.  Scan once more
	 * so the result reflects every candidate visible before the flush.
	 */
	kasumi_sop_shadow_reap();
	if (!atomic_read(&kasumi_sop_live))
		kasumi_sop_readers_stop();
	return !atomic_read(&kasumi_sop_live) &&
	       !atomic_read(&kasumi_sop_active) &&
	       !atomic_read(&kasumi_sop_vnodes);
}

void kasumi_sop_shadow_exit(void)
{
	kasumi_sop_shadow_stop_new();
	/* No live owner may remain at module exit (each one pins THIS_MODULE).
	 * Disable new requests under the same lock used by vnode_put(), then drain
	 * the reusable static work item before module text can disappear.
	 */
	spin_lock(&kasumi_sop_lock);
	WRITE_ONCE(kasumi_sop_reap_work_enabled, false);
	spin_unlock(&kasumi_sop_lock);
	cancel_work_sync(&kasumi_sop_reap_work);
	kasumi_sop_shadow_reap();
	WARN_ON_ONCE(atomic_read(&kasumi_sop_live));
	WARN_ON_ONCE(atomic_read(&kasumi_sop_active));
	WARN_ON_ONCE(atomic_read(&kasumi_sop_vnodes));
	kasumi_sop_readers_stop();
	synchronize_rcu();
	pr_info("Kasumi: sop_shadow exited\n");
}
