/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - lookup-time inode_operations shadow installation for fast getattr spoofing.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include "kasumi_entrypoints.h"
#include "kasumi_iop_override.h"
#include "kasumi_runtime.h"
#include "kasumi_dirhijack.h"

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/version.h>
#include <linux/namei.h>

#define KASUMI_IOP_HASH_BITS 10

struct kasumi_iop_meta {
	struct inode *inode;
	const struct inode_operations *orig_iop;
	struct inode_operations shadow_iop;
	struct hlist_node node;
	struct list_head retire_node;
	struct path retiring_path;
	unsigned int owners;
	atomic_t active;
	bool published;
};

static DEFINE_HASHTABLE(kasumi_iop_table, KASUMI_IOP_HASH_BITS);
static LIST_HEAD(kasumi_iop_retiring);
static DEFINE_MUTEX(kasumi_iop_quiesce_lock);
static DECLARE_WAIT_QUEUE_HEAD(kasumi_iop_quiesce_wait);
static atomic_t kasumi_iop_active_callbacks = ATOMIC_INIT(0);
static atomic_t kasumi_iop_live = ATOMIC_INIT(0);
static bool kasumi_iop_ready;
static bool kasumi_iop_callbacks_quiesced;
static struct task_struct *kasumi_iop_batch_owner;

static struct kasumi_iop_meta *kasumi_iop_lookup_rcu(struct inode *inode)
{
	struct kasumi_iop_meta *meta;

	hash_for_each_possible_rcu(kasumi_iop_table, meta, node, (unsigned long)inode)
		if (meta->inode == inode)
			return meta;
	return NULL;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0))
KASUMI_NOCFI static int kasumi_shadow_getattr(struct mnt_idmap *idmap,
					  const struct path *path,
					  struct kstat *stat,
					  u32 request_mask,
					  unsigned int query_flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct kasumi_iop_meta *m;
	const struct inode_operations *orig = NULL;
	int ret;

	atomic_inc(&kasumi_iop_active_callbacks);
	atomic64_inc(&kasumi_hook_stats.iop_getattr_entries);
	rcu_read_lock();
	m = kasumi_iop_lookup_rcu(inode);
	if (m) {
		atomic_inc(&m->active);
		orig = m->orig_iop;
	}
	rcu_read_unlock();

	if (orig && orig->getattr)
		ret = orig->getattr(idmap, path, stat, request_mask, query_flags);
	else {
		generic_fillattr(idmap, request_mask, inode, stat);
		ret = 0;
	}

	if (ret == 0 && m && READ_ONCE(m->owners)) {
		kasumi_apply_kstat_spoof(inode, stat);
		atomic64_inc(&kasumi_hook_stats.iop_getattr_spoofs);
	}
	if (m && atomic_dec_and_test(&m->active))
		wake_up_all(&kasumi_iop_quiesce_wait);
	if (atomic_dec_and_test(&kasumi_iop_active_callbacks))
		wake_up_all(&kasumi_iop_quiesce_wait);
	return ret;
}
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0))
KASUMI_NOCFI static int kasumi_shadow_getattr(struct user_namespace *userns,
					  const struct path *path,
					  struct kstat *stat,
					  u32 request_mask,
					  unsigned int query_flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct kasumi_iop_meta *m;
	const struct inode_operations *orig = NULL;
	int ret;

	atomic_inc(&kasumi_iop_active_callbacks);
	atomic64_inc(&kasumi_hook_stats.iop_getattr_entries);
	rcu_read_lock();
	m = kasumi_iop_lookup_rcu(inode);
	if (m) {
		atomic_inc(&m->active);
		orig = m->orig_iop;
	}
	rcu_read_unlock();

	if (orig && orig->getattr)
		ret = orig->getattr(userns, path, stat, request_mask, query_flags);
	else {
		generic_fillattr(userns, inode, stat);
		ret = 0;
	}

	if (ret == 0 && m && READ_ONCE(m->owners)) {
		kasumi_apply_kstat_spoof(inode, stat);
		atomic64_inc(&kasumi_hook_stats.iop_getattr_spoofs);
	}
	if (m && atomic_dec_and_test(&m->active))
		wake_up_all(&kasumi_iop_quiesce_wait);
	if (atomic_dec_and_test(&kasumi_iop_active_callbacks))
		wake_up_all(&kasumi_iop_quiesce_wait);
	return ret;
}
#else
KASUMI_NOCFI static int kasumi_shadow_getattr(const struct path *path,
					  struct kstat *stat,
					  u32 request_mask,
					  unsigned int query_flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct kasumi_iop_meta *m;
	const struct inode_operations *orig = NULL;
	int ret;

	atomic_inc(&kasumi_iop_active_callbacks);
	atomic64_inc(&kasumi_hook_stats.iop_getattr_entries);
	rcu_read_lock();
	m = kasumi_iop_lookup_rcu(inode);
	if (m) {
		atomic_inc(&m->active);
		orig = m->orig_iop;
	}
	rcu_read_unlock();

	if (orig && orig->getattr)
		ret = orig->getattr(path, stat, request_mask, query_flags);
	else {
		generic_fillattr(inode, stat);
		ret = 0;
	}

	if (ret == 0 && m && READ_ONCE(m->owners)) {
		kasumi_apply_kstat_spoof(inode, stat);
		atomic64_inc(&kasumi_hook_stats.iop_getattr_spoofs);
	}
	if (m && atomic_dec_and_test(&m->active))
		wake_up_all(&kasumi_iop_quiesce_wait);
	if (atomic_dec_and_test(&kasumi_iop_active_callbacks))
		wake_up_all(&kasumi_iop_quiesce_wait);
	return ret;
}
#endif

static int kasumi_iop_publish(struct kasumi_iop_meta *meta)
{
	int ret = kasumi_dirhijack_replace_iops(meta->inode, meta->orig_iop,
					       &meta->shadow_iop);

	if (!ret) {
		meta->published = true;
		set_bit(AS_FLAGS_KASUMI_IOP_INSTALLED, &meta->inode->i_mapping->flags);
		set_bit(AS_FLAGS_KASUMI_SPOOF_KSTAT, &meta->inode->i_mapping->flags);
	}
	return ret;
}

static int kasumi_iop_withdraw(struct kasumi_iop_meta *meta)
{
	int ret;

	if (!meta->published)
		return 0;
	ret = kasumi_dirhijack_replace_iops(meta->inode, &meta->shadow_iop, meta->orig_iop);
	if (!ret) {
		meta->published = false;
		clear_bit(AS_FLAGS_KASUMI_IOP_INSTALLED, &meta->inode->i_mapping->flags);
		clear_bit(AS_FLAGS_KASUMI_SPOOF_KSTAT, &meta->inode->i_mapping->flags);
	}
	return ret;
}

static void kasumi_iop_retire_workfn(struct work_struct *work)
{
	struct kasumi_iop_meta *meta, *next;

	mutex_lock(&kasumi_iop_quiesce_lock);
	if (list_empty(&kasumi_iop_retiring))
		goto unlock;
	/* Keep the lookup table intact until every stale callback has entered. */
	kasumi_synchronize_rcu_tasks();
	kasumi_dirhijack_synchronize_iops();
	list_for_each_entry(meta, &kasumi_iop_retiring, retire_node)
		wait_event(kasumi_iop_quiesce_wait, !atomic_read(&meta->active));
	kasumi_synchronize_rcu_tasks();
	list_for_each_entry(meta, &kasumi_iop_retiring, retire_node)
		hash_del_rcu(&meta->node);
	synchronize_rcu();
	list_for_each_entry_safe(meta, next, &kasumi_iop_retiring, retire_node) {
		list_del_init(&meta->retire_node);
		atomic_dec(&kasumi_iop_live);
		path_put(&meta->retiring_path);
		kfree(meta);
	}
unlock:
	mutex_unlock(&kasumi_iop_quiesce_lock);
}

static DECLARE_WORK(kasumi_iop_retire_work, kasumi_iop_retire_workfn);

void kasumi_iop_retire_batch_begin(void)
{
	mutex_lock(&kasumi_iop_quiesce_lock);
	WRITE_ONCE(kasumi_iop_batch_owner, current);
}

void kasumi_iop_retire_batch_end(void)
{
	WRITE_ONCE(kasumi_iop_batch_owner, NULL);
	if (!list_empty(&kasumi_iop_retiring))
		schedule_work(&kasumi_iop_retire_work);
	mutex_unlock(&kasumi_iop_quiesce_lock);
}

const struct inode_operations *kasumi_iop_original_iops(const struct inode *inode)
{
	const struct inode_operations *operations;
	struct kasumi_iop_meta *meta;

	rcu_read_lock();
	meta = kasumi_iop_lookup_rcu((struct inode *)inode);
	operations = meta ? meta->orig_iop : kasumi_dirhijack_original_iops(inode);
	rcu_read_unlock();
	return operations;
}

int kasumi_iop_get(const struct path *path)
{
	struct inode *inode = path && path->dentry ? d_inode(path->dentry) : NULL;
	struct kasumi_iop_meta *meta;
	int ret = 0;

	if (!inode || !path->mnt || !inode->i_mapping)
		return -EINVAL;
	mutex_lock(&kasumi_iop_quiesce_lock);
	if (!kasumi_iop_ready) {
		ret = -ESHUTDOWN;
		goto unlock;
	}
	meta = kasumi_iop_lookup_rcu(inode);
	if (meta) {
		if (!meta->published) {
			ret = kasumi_iop_publish(meta);
			if (ret)
				goto unlock;
		}
		meta->owners++;
		if (meta->retiring_path.dentry) {
			list_del_init(&meta->retire_node);
			path_put(&meta->retiring_path);
			memset(&meta->retiring_path, 0, sizeof(meta->retiring_path));
		}
		goto unlock;
	}
	meta = kzalloc(sizeof(*meta), GFP_KERNEL);
	if (!meta) {
		ret = -ENOMEM;
		goto unlock;
	}
	meta->inode = inode;
	meta->orig_iop = kasumi_dirhijack_original_iops(inode);
	if (!meta->orig_iop) {
		kfree(meta);
		ret = -EINVAL;
		goto unlock;
	}
	meta->shadow_iop = *meta->orig_iop;
	meta->shadow_iop.getattr = kasumi_shadow_getattr;
	meta->owners = 1;
	atomic_set(&meta->active, 0);
	INIT_LIST_HEAD(&meta->retire_node);
	hash_add_rcu(kasumi_iop_table, &meta->node, (unsigned long)inode);
	ret = kasumi_iop_publish(meta);
	if (ret) {
		hash_del_rcu(&meta->node);
		synchronize_rcu();
		kfree(meta);
	} else {
		atomic_inc(&kasumi_iop_live);
	}
unlock:
	mutex_unlock(&kasumi_iop_quiesce_lock);
	return ret;
}

void kasumi_iop_put(const struct path *path)
{
	struct kasumi_iop_meta *meta;
	int ret;
	bool batch = READ_ONCE(kasumi_iop_batch_owner) == current;

	if (!path || !path->dentry)
		return;
	if (!batch)
		mutex_lock(&kasumi_iop_quiesce_lock);
	meta = kasumi_iop_lookup_rcu(d_inode(path->dentry));
	if (!meta || WARN_ON_ONCE(!meta->owners))
		goto unlock;
	if (--meta->owners)
		goto unlock;
	/* Retirement owns a temporary path until all shadow readers drain. */
	meta->retiring_path = *path;
	path_get(&meta->retiring_path);
	ret = kasumi_iop_withdraw(meta);
	if (WARN_ON_ONCE(ret))
		goto unlock;
	list_add_tail(&meta->retire_node, &kasumi_iop_retiring);
	if (!batch)
		schedule_work(&kasumi_iop_retire_work);
unlock:
	if (!batch)
		mutex_unlock(&kasumi_iop_quiesce_lock);
}

/* The disabled legacy probe may only observe an existing rule-owned hook. */
int kasumi_iop_install(struct inode *inode)
{
	bool present;

	rcu_read_lock();
	present = inode && kasumi_iop_lookup_rcu(inode);
	rcu_read_unlock();
	return present ? 0 : -EOPNOTSUPP;
}

void kasumi_iop_override_drain(void)
{
	flush_work(&kasumi_iop_retire_work);
}

int kasumi_iop_override_init(void)
{
	hash_init(kasumi_iop_table);
	atomic_set(&kasumi_iop_active_callbacks, 0);
	atomic_set(&kasumi_iop_live, 0);
	kasumi_iop_callbacks_quiesced = false;
	WRITE_ONCE(kasumi_iop_ready, true);
	return 0;
}

void kasumi_iop_override_stop_new(void)
{
	struct kasumi_iop_meta *meta;
	int bucket;
	bool restored = true;

	mutex_lock(&kasumi_iop_quiesce_lock);
	WRITE_ONCE(kasumi_iop_ready, false);
	if (kasumi_iop_callbacks_quiesced)
		goto unlock;
	hash_for_each(kasumi_iop_table, bucket, meta, node) {
		if (kasumi_iop_withdraw(meta)) {
			restored = false;
			continue;
		}
		if (!meta->owners && list_empty(&meta->retire_node))
			list_add_tail(&meta->retire_node, &kasumi_iop_retiring);
	}
	if (!list_empty(&kasumi_iop_retiring))
		schedule_work(&kasumi_iop_retire_work);
	if (!restored)
		goto unlock;
	kasumi_synchronize_rcu_tasks();
	kasumi_dirhijack_synchronize_iops();
	wait_event(kasumi_iop_quiesce_wait, !atomic_read(&kasumi_iop_active_callbacks));
	kasumi_synchronize_rcu_tasks();
	kasumi_iop_callbacks_quiesced = true;
unlock:
	mutex_unlock(&kasumi_iop_quiesce_lock);
}

unsigned int kasumi_iop_override_active(void)
{
	return (unsigned int)atomic_read(&kasumi_iop_active_callbacks);
}

bool kasumi_iop_override_quiesced(void)
{
	return READ_ONCE(kasumi_iop_callbacks_quiesced);
}

void kasumi_iop_override_exit(void)
{
	kasumi_iop_override_stop_new();
	kasumi_iop_override_drain();
}
