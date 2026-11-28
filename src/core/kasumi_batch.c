#include <linux/err.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include "kasumi_batch.h"
#include "kasumi_live_rules.h"
#include "kasumi_notify_watch.h"
#include "kasumi_notify_fanotify.h"
#include "kasumi_dirhijack.h"
#include "kasumi_fop_override.h"
#include "kasumi_runtime.h"
#include "kasumi_store.h"
#include "kasumi_maps_rules.h"
#include "kasumi_path_policy.h"
#include "kasumi_proc_seq.h"
#include "kasumi_mount_view.h"
#include "kasumi_vfs_view.h"
#include "kasumi_fake_selinuxfs_access.h"

struct kasumi_batch {
	struct rcu_head rcu;
	struct list_head changes;
	struct kasumi_dirhijack_batch *directories;
	struct kasumi_live_batch *live;
	u64 generation;
	struct kasumi_view_settings previous_settings;
	struct kasumi_view_settings settings;
	struct kasumi_maps_batch *maps;
#ifndef KASUMI_EMBEDDED
	struct kasumi_policy_batch *policy;
#endif
};

static struct task_struct *kasumi_batch_owner;
static struct kasumi_batch *kasumi_current_batch;
static struct kasumi_batch __rcu *kasumi_publishing_batch;

static struct kasumi_view_settings kasumi_config_settings(void)
{
	struct kasumi_view_settings settings;
	struct kasumi_batch *batch;
	u64 generation;

	rcu_read_lock();
	generation = kasumi_rules_generation();
	/* Clearing the pointer also publishes the scalar settings below. */
	batch = unrcu_pointer(smp_load_acquire(&kasumi_publishing_batch));
	if (batch) {
		settings = generation >= batch->generation ?
			   batch->settings : batch->previous_settings;
	} else {
		settings.features = READ_ONCE(kasumi_feature_enabled_mask);
		settings.enabled = smp_load_acquire(&kasumi_enabled);
		settings.stealth = READ_ONCE(kasumi_stealth_enabled);
		settings.debug = READ_ONCE(kasumi_debug_enabled);
	}
	rcu_read_unlock();
	return settings;
}

bool kasumi_config_enabled(void)
{
	return kasumi_config_settings().enabled;
}

u32 kasumi_config_features(void)
{
	return kasumi_config_settings().features;
}

bool kasumi_config_stealth(void)
{
	return kasumi_config_settings().stealth;
}

bool kasumi_config_debug(void)
{
	return kasumi_config_settings().debug;
}

u64 kasumi_batch_generation(void)
{
	if (READ_ONCE(kasumi_batch_owner) != current)
		return 0;
	return kasumi_current_batch->generation;
}

void kasumi_batch_track(struct kasumi_rule_lifetime *life,
			enum kasumi_batch_store store)
{
	u64 generation = kasumi_batch_generation();

	life->batch_store = store;
	kasumi_rule_index_add(life);
	if (!generation || life->batch_generation == generation)
		return;
	WARN_ON_ONCE(life->batch_generation);
	life->previous_last_generation = life->last_generation;
	life->batch_generation = generation;
	life->batch_store = store;
	if (life->first_generation == generation)
		kasumi_live_rules_track(life);
	list_add_tail(&life->batch_node, &kasumi_current_batch->changes);
}

void kasumi_batch_expire(struct kasumi_rule_lifetime *life,
			 enum kasumi_batch_store store)
{
	kasumi_batch_track(life, store);
	WRITE_ONCE(life->last_generation, kasumi_batch_generation() - 1);
}

struct kasumi_dirhijack_batch *kasumi_batch_dir(void)
{
	if (READ_ONCE(kasumi_batch_owner) != current)
		return NULL;
	return kasumi_current_batch->directories;
}

struct kasumi_live_batch *kasumi_batch_live(void)
{
	if (READ_ONCE(kasumi_batch_owner) != current)
		return NULL;
	return kasumi_current_batch->live;
}

struct kasumi_batch *kasumi_batch_begin(void)
{
	struct kasumi_batch *batch;

	if (WARN_ON(READ_ONCE(kasumi_batch_owner)))
		return ERR_PTR(-EBUSY);
	if (kasumi_rules_generation() == U64_MAX)
		return ERR_PTR(-EOVERFLOW);
	batch = kzalloc(sizeof(*batch), GFP_KERNEL);
	if (!batch)
		return ERR_PTR(-ENOMEM);
	INIT_LIST_HEAD(&batch->changes);
	batch->generation = kasumi_rules_generation() + 1;
	batch->previous_settings = kasumi_config_settings();
	batch->settings = batch->previous_settings;
	batch->directories = kasumi_dirhijack_batch_begin(batch->generation);
	if (IS_ERR(batch->directories)) {
		int error = PTR_ERR(batch->directories);

		kfree(batch);
		return ERR_PTR(error);
	}
	batch->live = kasumi_live_rules_begin();
	if (IS_ERR(batch->live)) {
		int error = PTR_ERR(batch->live);

		kasumi_dirhijack_batch_finish(batch->directories, false);
		kfree(batch);
		return ERR_PTR(error);
	}
	kasumi_current_batch = batch;
	WRITE_ONCE(kasumi_batch_owner, current);
	return batch;
}

int kasumi_batch_configure(const struct kasumi_batch_configuration *configuration)
{
	struct kasumi_batch *batch = kasumi_current_batch;
	struct kasumi_view_settings settings;
	u32 features, index;
	int error;

	if (!kasumi_batch_generation())
		return -EINVAL;
	settings = configuration->fields & KSM_TX_CONFIG_SETTINGS ?
		   configuration->settings : batch->settings;
	if (configuration->fields & KSM_TX_CONFIG_SETTINGS) {
		features = settings.features;
		if (features & ~(KSM_FEATURE_MOUNT_HIDE | KSM_FEATURE_MAPS_SPOOF |
				 KSM_FEATURE_STATFS_SPOOF | KSM_FEATURE_SELINUX_FIX))
			return -EINVAL;
		if ((features & KSM_FEATURE_MAPS_SPOOF) &&
		    !kasumi_proc_maps_available())
			return -EOPNOTSUPP;
		if ((features & KSM_FEATURE_STATFS_SPOOF) && !kasumi_statfs_view_available())
			return -EOPNOTSUPP;
		if ((features & KSM_FEATURE_SELINUX_FIX) &&
		    !kasumi_fake_selinuxfs_proc_attr_active())
			return -EOPNOTSUPP;
		if (features & KSM_FEATURE_MOUNT_HIDE) {
			u64 required = kasumi_mount_view_required_capabilities();

			if (!kasumi_mount_view_available() ||
			    (kasumi_mount_view_capabilities() & required) != required)
				return -EOPNOTSUPP;
		}
	}
#ifdef KASUMI_EMBEDDED
	if (configuration->fields & (KSM_TX_CONFIG_POLICY | KSM_TX_CONFIG_RESET_POLICY))
		return -EOPNOTSUPP;
#else
	if ((configuration->fields & (KSM_TX_CONFIG_POLICY | KSM_TX_CONFIG_RESET_POLICY)) ||
	    settings.enabled != batch->previous_settings.enabled) {
		batch->policy = kasumi_policy_batch_prepare(batch->generation,
			!!(configuration->fields & KSM_TX_CONFIG_POLICY),
			!!(configuration->fields & KSM_TX_CONFIG_RESET_POLICY),
			configuration->policy_owner, configuration->policy_flags,
			configuration->allow_uids, configuration->allow_count,
			configuration->deny_uids, configuration->deny_count,
			settings.enabled);
		if (IS_ERR(batch->policy)) {
			error = PTR_ERR(batch->policy);
			batch->policy = NULL;
			return error;
		}
	}
#endif
	if (configuration->fields & KSM_TX_CONFIG_MAPS) {
		batch->maps = kasumi_maps_batch_prepare(configuration->maps_rules,
						 configuration->maps_count,
						 batch->generation);
		if (IS_ERR(batch->maps)) {
			error = PTR_ERR(batch->maps);
			batch->maps = NULL;
			return error;
		}
	}
	if (configuration->fields & KSM_TX_CONFIG_KSTAT) {
		struct kasumi_spoof_kstat_entry *entry;
		int bucket;

		hash_for_each(kasumi_spoof_kstat_path, bucket, entry, path_node)
			kasumi_batch_expire(&entry->life, KASUMI_BATCH_KSTAT);
		hash_for_each(kasumi_spoof_kstat_ino, bucket, entry, ino_node)
			kasumi_batch_expire(&entry->life, KASUMI_BATCH_KSTAT);
		for (index = 0; index < configuration->kstat_count; index++) {
			error = kasumi_spoof_kstat_stage(&configuration->kstat_rules[index], NULL);
			if (error)
				return error;
		}
	}
	batch->settings = settings;
	return 0;
}

int kasumi_batch_clear_paths(void)
{
	struct kasumi_entry *entry;
	struct kasumi_hide_entry *hide;
	struct kasumi_inject_entry *inject;
	struct kasumi_merge_entry *merge;
	u64 generation = kasumi_batch_generation();
	struct kasumi_dirhijack_batch *directories = kasumi_batch_dir();
	int bucket, result;

	if (!generation)
		return -EINVAL;
	kasumi_live_rules_clear_paths(kasumi_current_batch->live);
	hash_for_each(kasumi_paths, bucket, entry, node) {
		if (!kasumi_rule_visible(&entry->life, generation))
			continue;
		result = kasumi_dirhijack_batch_del(directories, entry->src);
		if (result && result != -ENOENT)
			return result;
		kasumi_batch_expire(&entry->life, KASUMI_BATCH_PATH);
	}
	hash_for_each(kasumi_hide_paths, bucket, hide, node) {
		if (!kasumi_rule_visible(&hide->life, generation))
			continue;
		result = kasumi_dirhijack_batch_del(directories, hide->path);
		if (result && result != -ENOENT)
			return result;
		kasumi_batch_expire(&hide->life, KASUMI_BATCH_HIDE);
	}
	hash_for_each(kasumi_inject_dirs, bucket, inject, node)
		kasumi_batch_expire(&inject->life, KASUMI_BATCH_INJECT);
	hash_for_each(kasumi_merge_dirs, bucket, merge, node)
		kasumi_batch_expire(&merge->life, KASUMI_BATCH_MERGE);
	return kasumi_batch_clear_xattrs();
}

int kasumi_batch_clear_xattrs(void)
{
	struct kasumi_xattr_sb_entry *xattr;
	u64 generation = kasumi_batch_generation();
	int bucket;

	if (!generation)
		return -EINVAL;
	kasumi_live_rules_clear_xattrs(kasumi_current_batch->live);
	hash_for_each(kasumi_xattr_sbs, bucket, xattr, node)
		kasumi_batch_expire(&xattr->life, KASUMI_BATCH_XATTR);
	return 0;
}

static void kasumi_batch_retire(struct kasumi_rule_lifetime *life)
{
	kasumi_live_rules_untrack(life);
	kasumi_rule_index_remove(life);
	switch (life->batch_store) {
	case KASUMI_BATCH_PATH: {
		struct kasumi_entry *entry = container_of(life, struct kasumi_entry, life);

		hlist_del_rcu(&entry->node);
#ifndef KASUMI_EMBEDDED
		hlist_del_rcu(&entry->target_node);
#endif
		atomic_dec(&kasumi_rule_count);
		call_rcu(&entry->rcu, kasumi_entry_free_rcu);
		break;
	}
	case KASUMI_BATCH_HIDE: {
		struct kasumi_hide_entry *entry = container_of(life, struct kasumi_hide_entry, life);

		hlist_del_rcu(&entry->node);
		atomic_dec(&kasumi_hide_count);
		call_rcu(&entry->rcu, kasumi_hide_entry_free_rcu);
		break;
	}
	case KASUMI_BATCH_INJECT: {
		struct kasumi_inject_entry *entry = container_of(life, struct kasumi_inject_entry, life);

		hlist_del_rcu(&entry->node);
		atomic_dec(&kasumi_rule_count);
		kasumi_fop_put(entry->fop_inode, true);
		entry->fop_inode = NULL;
		call_rcu(&entry->rcu, kasumi_inject_entry_free_rcu);
		break;
	}
	case KASUMI_BATCH_MERGE: {
		struct kasumi_merge_entry *entry = container_of(life, struct kasumi_merge_entry, life);

		hlist_del_rcu(&entry->node);
		call_rcu(&entry->rcu, kasumi_merge_entry_free_rcu);
		break;
	}
	case KASUMI_BATCH_XATTR: {
		struct kasumi_xattr_sb_entry *entry = container_of(life, struct kasumi_xattr_sb_entry, life);

		hlist_del_rcu(&entry->node);
		call_rcu(&entry->rcu, kasumi_xattr_sb_entry_free_rcu);
		break;
	}
	case KASUMI_BATCH_KSTAT: {
		struct kasumi_spoof_kstat_entry *entry =
			container_of(life, struct kasumi_spoof_kstat_entry, life);

		if (!hlist_unhashed(&entry->path_node))
			hlist_del_rcu(&entry->path_node);
		if (!hlist_unhashed(&entry->ino_node))
			hlist_del_rcu(&entry->ino_node);
		atomic_dec(&kasumi_spoof_kstat_count);
		call_rcu(&entry->rcu, kasumi_spoof_kstat_entry_free_rcu);
		break;
	}
	}
}

void kasumi_batch_finish(struct kasumi_batch *batch, bool publish)
{
	struct kasumi_rule_lifetime *life, *next;

	if (publish) {
		rcu_assign_pointer(kasumi_publishing_batch, batch);
		kasumi_rules_publish(batch->generation);
	}
	kasumi_dirhijack_batch_finish(batch->directories, publish);
	/* A reader retaining the previous generation must finish first. */
	synchronize_rcu();
	kasumi_maps_batch_finish(batch->maps, publish);
#ifndef KASUMI_EMBEDDED
	kasumi_policy_batch_finish(batch->policy, publish);
#endif
	if (publish) {
		WRITE_ONCE(kasumi_feature_enabled_mask, batch->settings.features);
		WRITE_ONCE(kasumi_stealth_enabled, batch->settings.stealth);
		WRITE_ONCE(kasumi_debug_enabled, batch->settings.debug);
		smp_store_release(&kasumi_enabled, batch->settings.enabled);
		smp_store_release(&kasumi_publishing_batch, NULL);
	}
	mutex_lock(&kasumi_config_mutex);
	list_for_each_entry_safe(life, next, &batch->changes, batch_node) {
		bool retire = publish ?
			life->last_generation && life->last_generation < batch->generation :
			life->first_generation == batch->generation;

		list_del_init(&life->batch_node);
		life->batch_generation = 0;
		if (!publish)
			WRITE_ONCE(life->last_generation, life->previous_last_generation);
		if (retire)
			kasumi_batch_retire(life);
	}
	mutex_unlock(&kasumi_config_mutex);
	kasumi_live_rules_finish(batch->live, publish);
	WRITE_ONCE(kasumi_batch_owner, NULL);
	kasumi_current_batch = NULL;
	if (publish) {
		kasumi_notify_watch_rules_changed();
		kasumi_notify_fanotify_rules_changed();
	}
	kfree_rcu(batch, rcu);
}
