/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - path redirect, hide-policy, and allowlist decision logic.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0) && !defined(arch_ftrace_get_regs)
#define arch_ftrace_get_regs(fregs) (NULL)
#endif
#include <linux/kprobes.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/jhash.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/sched/task.h>
#include <linux/fs_struct.h>
#include <linux/dirent.h>
#include <linux/stat.h>
#include <linux/time.h>
#include <linux/anon_inodes.h>
#include <linux/fcntl.h>
#include <linux/percpu.h>
#include <linux/smp.h>
#include <linux/mount.h>
#include <linux/xattr.h>
#include <linux/seq_file.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/xarray.h>
#include <linux/sort.h>
#include <uapi/linux/magic.h>
#ifndef EROFS_SUPER_MAGIC
#define EROFS_SUPER_MAGIC 0xe0f5e1e2
#endif
#include <asm/unistd.h>
#include "kasumi_root_detection.h"
#include "kasumi_runtime.h"
#include "kasumi_dir_view.h"
#include "kasumi_vnode.h"
#include "kasumi_store.h"
#include "kasumi_path_policy.h"
#include "kasumi_dirhijack.h"
#include "kasumi_hide_rules.h"
#include "kasumi_batch.h"

#define KASUMI_MEDIA_RW_GID 1023

/* ======================================================================
 * Part 11: Core Logic - Privileged Check / Allowlist
 * ====================================================================== */

bool kasumi_is_privileged_process(void)
{
	pid_t pid = task_tgid_vnr(current);

	if (unlikely(uid_eq(current_uid(), GLOBAL_ROOT_UID)))
		return true;
	if (READ_ONCE(kasumi_daemon_pid) > 0 && pid == READ_ONCE(kasumi_daemon_pid))
		return true;
	return false;
}

/*
 * KernelSU's kernel_umount caller gates ksu_uid_should_umount() with these
 * Android app/isolated ranges. The scalar provider alone can return its
 * default profile for shell or system UIDs, which are not policy targets.
 * Keep the same outer boundary for every Kasumi policy owner.
 */
#define KASUMI_ANDROID_PER_USER_RANGE      100000
#define KASUMI_ANDROID_FIRST_APP_UID        10000
#define KASUMI_ANDROID_LAST_APP_UID         19999
#define KASUMI_ANDROID_FIRST_ISOLATED_UID   90000
#define KASUMI_ANDROID_LAST_ISOLATED_UID    99999

static inline bool kasumi_uid_is_app(uid_t uid)
{
	uid_t appid = uid % KASUMI_ANDROID_PER_USER_RANGE;

	return appid >= KASUMI_ANDROID_FIRST_APP_UID &&
	       appid <= KASUMI_ANDROID_LAST_APP_UID;
}

static inline bool kasumi_uid_is_isolated(uid_t uid)
{
	uid_t appid = uid % KASUMI_ANDROID_PER_USER_RANGE;

	return appid >= KASUMI_ANDROID_FIRST_ISOLATED_UID &&
	       appid <= KASUMI_ANDROID_LAST_ISOLATED_UID;
}

struct kasumi_policy_snapshot {
	struct rcu_head rcu;
	u64 generation;
	u32 owner;
	u32 flags;
	u32 allow_count;
	u32 deny_count;
	struct xarray allow_uids;
	struct xarray deny_uids;
	u32 *allow_uid_list;
	u32 *deny_uid_list;
};

static struct kasumi_policy_snapshot __rcu *kasumi_policy_current;
static atomic64_t kasumi_policy_generation = ATOMIC64_INIT(0);
static struct module *kasumi_ksu_provider_module;
static struct module *kasumi_ksu_allow_provider_module;
static bool (*kasumi_ksu_allow_uid_ptr)(uid_t uid);
static struct module *kasumi_apatch_provider_module;
static struct module *(*kasumi_module_address_ptr)(unsigned long addr);
static int (*kasumi_core_kernel_text_ptr)(unsigned long addr);

struct kasumi_policy_runtime {
	u32 root_mask;
	u32 owner;
	bool spoof_allowed;
	bool ksu_available;
	bool apatch_stable;
	kasumi_ksu_uid_should_umount_fn ksu;
	bool (*ksu_allow)(uid_t uid);
	int (*apatch)(uid_t uid);
	struct module *ksu_module;
	struct module *ksu_allow_module;
	struct module *apatch_module;
};

struct kasumi_policy_batch {
	struct rcu_head rcu;
	u64 generation;
	bool enabled;
	struct kasumi_policy_snapshot *previous;
	struct kasumi_policy_snapshot *replacement;
	struct kasumi_policy_runtime previous_runtime;
	struct kasumi_policy_runtime runtime;
};

static struct kasumi_policy_batch __rcu *kasumi_policy_pending;

static struct kasumi_policy_runtime kasumi_policy_capture_runtime(void)
{
	struct kasumi_policy_runtime runtime = {
		.root_mask = READ_ONCE(kasumi_root_mask),
		.owner = READ_ONCE(kasumi_root_policy_owner),
		.spoof_allowed = READ_ONCE(kasumi_root_spoof_allowed),
		.ksu_available = READ_ONCE(kasumi_ksu_policy_available),
		.apatch_stable = kasumi_apatch_policy_lifetime_stable,
		.ksu = READ_ONCE(kasumi_ksu_uid_should_umount_ptr),
		.ksu_allow = READ_ONCE(kasumi_ksu_allow_uid_ptr),
		.apatch = READ_ONCE(kasumi_ap_get_mod_exclude),
		.ksu_module = kasumi_ksu_provider_module,
		.ksu_allow_module = kasumi_ksu_allow_provider_module,
		.apatch_module = kasumi_apatch_provider_module,
	};

	return runtime;
}

static void kasumi_policy_restore_runtime(const struct kasumi_policy_runtime *old)
{
	if (kasumi_ksu_provider_module != old->ksu_module &&
	    kasumi_ksu_provider_module)
		module_put(kasumi_ksu_provider_module);
	if (kasumi_ksu_allow_provider_module != old->ksu_allow_module &&
	    kasumi_ksu_allow_provider_module)
		module_put(kasumi_ksu_allow_provider_module);
	if (kasumi_apatch_provider_module != old->apatch_module &&
	    kasumi_apatch_provider_module)
		module_put(kasumi_apatch_provider_module);
	kasumi_ksu_provider_module = old->ksu_module;
	kasumi_ksu_allow_provider_module = old->ksu_allow_module;
	kasumi_apatch_provider_module = old->apatch_module;
	WRITE_ONCE(kasumi_root_mask, old->root_mask);
	WRITE_ONCE(kasumi_root_policy_owner, old->owner);
	WRITE_ONCE(kasumi_root_spoof_allowed, old->spoof_allowed);
	WRITE_ONCE(kasumi_ksu_policy_available, old->ksu_available);
	kasumi_apatch_policy_lifetime_stable = old->apatch_stable;
	WRITE_ONCE(kasumi_ksu_uid_should_umount_ptr, old->ksu);
	WRITE_ONCE(kasumi_ksu_allow_uid_ptr, old->ksu_allow);
	WRITE_ONCE(kasumi_ap_get_mod_exclude, old->apatch);
}

/* The caller holds RCU while using either the snapshot or its provider. */
static struct kasumi_policy_snapshot *
kasumi_policy_read_at(u64 generation, struct kasumi_policy_runtime *runtime)
{
	struct kasumi_policy_batch *batch = rcu_dereference(kasumi_policy_pending);

	if (batch) {
		if (generation >= batch->generation) {
			if (runtime)
				*runtime = batch->runtime;
			return batch->replacement;
		}
		if (runtime)
			*runtime = batch->previous_runtime;
		return batch->previous;
	}
	if (runtime) {
		runtime->root_mask = READ_ONCE(kasumi_root_mask);
		runtime->owner = READ_ONCE(kasumi_root_policy_owner);
		runtime->spoof_allowed = READ_ONCE(kasumi_root_spoof_allowed);
		runtime->ksu = READ_ONCE(kasumi_ksu_uid_should_umount_ptr);
		runtime->ksu_allow = READ_ONCE(kasumi_ksu_allow_uid_ptr);
		runtime->apatch = READ_ONCE(kasumi_ap_get_mod_exclude);
	}
	return rcu_dereference(kasumi_policy_current);
}

static KASUMI_NOCFI bool kasumi_policy_resolve_module_address(void)
{
	if (!kasumi_module_address_ptr)
		kasumi_module_address_ptr =
			(void *)kasumi_lookup_callable_quiet("__module_address");
	return kasumi_module_address_ptr != NULL;
}

static KASUMI_NOCFI bool kasumi_policy_pin_stable_provider(unsigned long addr,
							    struct module **owner)
{
	struct module *provider;
	bool module_address;

	if (!addr)
		return false;
	if (*owner)
		return true;
	if (!kasumi_policy_resolve_module_address())
		return false;
	if (!kasumi_core_kernel_text_ptr)
		kasumi_core_kernel_text_ptr =
			(void *)kasumi_lookup_callable_quiet("core_kernel_text");
	preempt_disable();
	provider = kasumi_module_address_ptr(addr);
	module_address = provider != NULL;
	if (provider && !try_module_get(provider))
		provider = NULL;
	preempt_enable();
	if (provider)
		*owner = provider;
	if (module_address)
		return provider != NULL;
	/* Reject unpinnable vmalloc/KPM text; only built-in core text is stable. */
	return kasumi_core_kernel_text_ptr && kasumi_core_kernel_text_ptr(addr);
}

static KASUMI_NOCFI bool kasumi_policy_pin_linux_module(unsigned long addr,
						 struct module **owner,
						 bool *is_module)
{
	struct module *provider;

	if (!addr)
		return false;
	if (*owner) {
		*is_module = true;
		return true;
	}
	if (!kasumi_policy_resolve_module_address())
		return false;
	preempt_disable();
	provider = kasumi_module_address_ptr(addr);
	*is_module = provider != NULL;
	if (provider && !try_module_get(provider))
		provider = NULL;
	preempt_enable();
	if (provider)
		*owner = provider;
	return provider != NULL;
}

static void kasumi_policy_unpin_provider(void)
{
	if (kasumi_ksu_allow_provider_module) {
		module_put(kasumi_ksu_allow_provider_module);
		kasumi_ksu_allow_provider_module = NULL;
	}
	if (kasumi_ksu_provider_module) {
		module_put(kasumi_ksu_provider_module);
		kasumi_ksu_provider_module = NULL;
	}
	if (kasumi_apatch_provider_module) {
		module_put(kasumi_apatch_provider_module);
		kasumi_apatch_provider_module = NULL;
	}
}

static int kasumi_policy_owner_valid(u32 owner)
{
	switch (owner) {
	case KSM_POLICY_OWNER_AUTO:
	case KSM_POLICY_OWNER_KERNELSU:
	case KSM_POLICY_OWNER_APATCH:
	case KSM_POLICY_OWNER_MANUAL:
	case KSM_POLICY_OWNER_DISABLED:
		return 0;
	case KSM_POLICY_OWNER_MAGISK:
		return -EOPNOTSUPP;
	default:
		return -EINVAL;
	}
}

static int kasumi_policy_values_valid(u32 owner, u32 flags,
				      const u32 *allow_uids, u32 allow_count,
				      const u32 *deny_uids, u32 deny_count)
{
	u32 supported = KSM_POLICY_FLAG_USE_ALLOW_UIDS |
			KSM_POLICY_FLAG_USE_DENY_UIDS |
			KSM_POLICY_FLAG_INCLUDE_ISOLATED_UIDS;
	u32 i;
	int ret;

	ret = kasumi_policy_owner_valid(owner);
	if (ret)
		return ret;
	if (flags & ~supported)
		return -EINVAL;
	if ((flags & KSM_POLICY_FLAG_INCLUDE_ISOLATED_UIDS) &&
	    !(flags & KSM_POLICY_FLAG_USE_ALLOW_UIDS))
		return -EINVAL;
	if (owner == KSM_POLICY_OWNER_MANUAL &&
	    !(flags & KSM_POLICY_FLAG_USE_ALLOW_UIDS))
		return -EINVAL;
	if (allow_count > KASUMI_ALLOWLIST_UID_MAX ||
	    deny_count > KASUMI_ALLOWLIST_UID_MAX)
		return -E2BIG;
	if ((allow_count && !allow_uids) || (deny_count && !deny_uids))
		return -EINVAL;
	if (allow_count && !(flags & KSM_POLICY_FLAG_USE_ALLOW_UIDS))
		return -EINVAL;
	if (deny_count && !(flags & KSM_POLICY_FLAG_USE_DENY_UIDS))
		return -EINVAL;
	for (i = 0; i < allow_count; i++)
		if (allow_uids[i] == 0)
			return -EINVAL;
	for (i = 0; i < deny_count; i++)
		if (deny_uids[i] == 0)
			return -EINVAL;
	return 0;
}

static void kasumi_policy_snapshot_destroy(struct kasumi_policy_snapshot *policy)
{
	if (!policy)
		return;
	xa_destroy(&policy->allow_uids);
	xa_destroy(&policy->deny_uids);
	kfree(policy->allow_uid_list);
	kfree(policy->deny_uid_list);
	kfree(policy);
}

static void kasumi_policy_snapshot_free_rcu(struct rcu_head *head)
{
	struct kasumi_policy_snapshot *policy =
		container_of(head, struct kasumi_policy_snapshot, rcu);

	kasumi_policy_snapshot_destroy(policy);
}

static int kasumi_policy_uid_compare(const void *left, const void *right)
{
	u32 a = *(const u32 *)left;
	u32 b = *(const u32 *)right;

	return (a > b) - (a < b);
}

static int kasumi_policy_build_uid_list(struct xarray *xa, u32 **snapshot,
					u32 *snapshot_count, const u32 *uids,
					u32 count)
{
	u32 *dense = NULL;
	u32 i;
	u32 out = 0;
	int ret;

	if (count) {
		dense = kmalloc_array(count, sizeof(*dense), GFP_KERNEL);
		if (!dense)
			return -ENOMEM;
	}
	for (i = 0; i < count; i++) {
		if (xa_load(xa, uids[i]))
			continue;
		ret = xa_err(xa_store(xa, uids[i], KASUMI_UID_ALLOW_MARKER,
				      GFP_KERNEL));
		if (ret) {
			kfree(dense);
			return ret;
		}
		dense[out++] = uids[i];
	}
	/* Canonical snapshots make GET results stable across input ordering. */
	sort(dense, out, sizeof(*dense), kasumi_policy_uid_compare, NULL);
	*snapshot = dense;
	*snapshot_count = out;
	return 0;
}

static struct kasumi_policy_snapshot *
kasumi_policy_snapshot_create(u32 owner, u32 flags,
			      const u32 *allow_uids, u32 allow_count,
			      const u32 *deny_uids, u32 deny_count)
{
	struct kasumi_policy_snapshot *policy;
	int ret;

	ret = kasumi_policy_values_valid(owner, flags, allow_uids, allow_count,
					 deny_uids, deny_count);
	if (ret)
		return ERR_PTR(ret);
	policy = kzalloc(sizeof(*policy), GFP_KERNEL);
	if (!policy)
		return ERR_PTR(-ENOMEM);
	xa_init(&policy->allow_uids);
	xa_init(&policy->deny_uids);
	policy->owner = owner;
	policy->flags = flags;

	ret = kasumi_policy_build_uid_list(&policy->allow_uids,
					   &policy->allow_uid_list,
					   &policy->allow_count,
					   allow_uids, allow_count);
	if (ret)
		goto err;
	ret = kasumi_policy_build_uid_list(&policy->deny_uids,
					   &policy->deny_uid_list,
					   &policy->deny_count,
					   deny_uids, deny_count);
	if (ret)
		goto err;
	return policy;

err:
	kasumi_policy_snapshot_destroy(policy);
	return ERR_PTR(ret);
}

static void kasumi_policy_publish_locked(struct kasumi_policy_snapshot *policy)
{
	struct kasumi_policy_snapshot *old;

	lockdep_assert_held(&kasumi_config_mutex);
	old = rcu_dereference_protected(kasumi_policy_current,
					lockdep_is_held(&kasumi_config_mutex));
	policy->generation = atomic64_inc_return(&kasumi_policy_generation);
	rcu_assign_pointer(kasumi_policy_current, policy);
	if (old)
		call_rcu(&old->rcu, kasumi_policy_snapshot_free_rcu);
}

static int kasumi_policy_publish_values_locked(u32 owner, u32 flags,
					       const u32 *allow_uids,
					       u32 allow_count,
					       const u32 *deny_uids,
					       u32 deny_count)
{
	struct kasumi_policy_snapshot *policy;

	lockdep_assert_held(&kasumi_config_mutex);
	policy = kasumi_policy_snapshot_create(owner, flags, allow_uids,
					       allow_count, deny_uids,
					       deny_count);
	if (IS_ERR(policy))
		return PTR_ERR(policy);
	kasumi_policy_publish_locked(policy);
	return 0;
}

u32 kasumi_policy_configured_owner(void)
{
	const struct kasumi_policy_snapshot *policy;
	u32 owner = KSM_POLICY_OWNER_AUTO;

	rcu_read_lock();
	policy = kasumi_policy_read_at(kasumi_batch_generation() ?
		kasumi_batch_generation() : kasumi_rules_generation(), NULL);
	if (policy)
		owner = policy->owner;
	rcu_read_unlock();
	return owner;
}

static u32 kasumi_policy_validate_effective_owner(u32 owner)
{
	if (owner == KSM_POLICY_OWNER_AUTO)
		owner = READ_ONCE(kasumi_root_policy_owner);
	if (owner == KSM_POLICY_OWNER_KERNELSU &&
	    (!(READ_ONCE(kasumi_root_mask) & KASUMI_ROOT_KSU) ||
	     !READ_ONCE(kasumi_ksu_policy_available)))
		return KSM_POLICY_OWNER_DISABLED;
	if (owner == KSM_POLICY_OWNER_APATCH &&
	    (!(READ_ONCE(kasumi_root_mask) & KASUMI_ROOT_APATCH) ||
	     !kasumi_ap_get_mod_exclude))
		return KSM_POLICY_OWNER_DISABLED;
	if (owner == KSM_POLICY_OWNER_MAGISK || owner == KSM_POLICY_OWNER_AUTO)
		return KSM_POLICY_OWNER_DISABLED;
	return owner;
}

u32 kasumi_policy_effective_owner(void)
{
	return kasumi_policy_validate_effective_owner(
		kasumi_policy_configured_owner());
}

int kasumi_policy_replace(u32 owner, u32 flags,
			  const u32 *allow_uids, u32 allow_count,
			  const u32 *deny_uids, u32 deny_count)
{
	int ret;

	mutex_lock(&kasumi_config_mutex);
	if (kasumi_config_enabled())
		ret = -EBUSY;
	else
		ret = kasumi_policy_publish_values_locked(owner, flags,
							  allow_uids, allow_count,
							  deny_uids, deny_count);
	mutex_unlock(&kasumi_config_mutex);
	return ret;
}

int kasumi_set_policy_owner(u32 owner, u32 flags)
{
	const struct kasumi_policy_snapshot *old;
	const u32 *allow_uids = NULL;
	const u32 *deny_uids = NULL;
	u32 allow_count = 0;
	u32 deny_count = 0;
	int ret;

	mutex_lock(&kasumi_config_mutex);
	if (kasumi_config_enabled()) {
		mutex_unlock(&kasumi_config_mutex);
		return -EBUSY;
	}
	old = rcu_dereference_protected(kasumi_policy_current,
					lockdep_is_held(&kasumi_config_mutex));
	if (old) {
		allow_uids = old->allow_uid_list;
		allow_count = old->allow_count;
		deny_uids = old->deny_uid_list;
		deny_count = old->deny_count;
	}
	if (!(flags & KSM_POLICY_FLAG_USE_ALLOW_UIDS)) {
		allow_uids = NULL;
		allow_count = 0;
	}
	if (!(flags & KSM_POLICY_FLAG_USE_DENY_UIDS)) {
		deny_uids = NULL;
		deny_count = 0;
	}
	ret = kasumi_policy_publish_values_locked(owner, flags, allow_uids,
						  allow_count, deny_uids,
						  deny_count);
	mutex_unlock(&kasumi_config_mutex);
	return ret;
}

int kasumi_replace_policy_uid_list(u32 list, const u32 *uids, u32 count)
{
	const struct kasumi_policy_snapshot *old;
	const u32 *allow_uids = NULL;
	const u32 *deny_uids = NULL;
	u32 owner = KSM_POLICY_OWNER_AUTO;
	u32 flags = 0;
	u32 allow_count = 0;
	u32 deny_count = 0;
	int ret;

	if (list != KSM_POLICY_UID_LIST_ALLOW &&
	    list != KSM_POLICY_UID_LIST_DENY)
		return -EINVAL;
	if (count > KASUMI_ALLOWLIST_UID_MAX)
		return -E2BIG;
	if (count && !uids)
		return -EINVAL;

	mutex_lock(&kasumi_config_mutex);
	if (kasumi_config_enabled()) {
		mutex_unlock(&kasumi_config_mutex);
		return -EBUSY;
	}
	old = rcu_dereference_protected(kasumi_policy_current,
					lockdep_is_held(&kasumi_config_mutex));
	if (old) {
		owner = old->owner;
		flags = old->flags;
		allow_uids = old->allow_uid_list;
		allow_count = old->allow_count;
		deny_uids = old->deny_uid_list;
		deny_count = old->deny_count;
	}
	if (list == KSM_POLICY_UID_LIST_ALLOW) {
		allow_uids = uids;
		allow_count = count;
		flags |= KSM_POLICY_FLAG_USE_ALLOW_UIDS;
	} else {
		deny_uids = uids;
		deny_count = count;
		flags |= KSM_POLICY_FLAG_USE_DENY_UIDS;
	}
	ret = kasumi_policy_publish_values_locked(owner, flags, allow_uids,
						  allow_count, deny_uids,
						  deny_count);
	mutex_unlock(&kasumi_config_mutex);
	return ret;
}

int kasumi_clear_policy_uid_list(u32 list)
{
	const struct kasumi_policy_snapshot *old;
	const u32 *allow_uids = NULL;
	const u32 *deny_uids = NULL;
	u32 owner = KSM_POLICY_OWNER_AUTO;
	u32 flags = 0;
	u32 allow_count = 0;
	u32 deny_count = 0;
	int ret;

	if (list != KSM_POLICY_UID_LIST_ALLOW &&
	    list != KSM_POLICY_UID_LIST_DENY &&
	    list != KSM_POLICY_UID_LIST_ALL)
		return -EINVAL;

	mutex_lock(&kasumi_config_mutex);
	if (kasumi_config_enabled()) {
		mutex_unlock(&kasumi_config_mutex);
		return -EBUSY;
	}
	old = rcu_dereference_protected(kasumi_policy_current,
					lockdep_is_held(&kasumi_config_mutex));
	if (old) {
		owner = old->owner;
		flags = old->flags;
		allow_uids = old->allow_uid_list;
		allow_count = old->allow_count;
		deny_uids = old->deny_uid_list;
		deny_count = old->deny_count;
	}
	if (list == KSM_POLICY_UID_LIST_ALLOW ||
	    list == KSM_POLICY_UID_LIST_ALL) {
		allow_uids = NULL;
		allow_count = 0;
		flags &= ~KSM_POLICY_FLAG_INCLUDE_ISOLATED_UIDS;
		/* MANUAL with an empty allow set is a valid fail-closed policy. */
		if (owner != KSM_POLICY_OWNER_MANUAL)
			flags &= ~KSM_POLICY_FLAG_USE_ALLOW_UIDS;
	}
	if (list == KSM_POLICY_UID_LIST_DENY ||
	    list == KSM_POLICY_UID_LIST_ALL) {
		deny_uids = NULL;
		deny_count = 0;
		flags &= ~KSM_POLICY_FLAG_USE_DENY_UIDS;
	}
	ret = kasumi_policy_publish_values_locked(owner, flags, allow_uids,
						  allow_count, deny_uids,
						  deny_count);
	mutex_unlock(&kasumi_config_mutex);
	return ret;
}

void kasumi_policy_get_state(struct kasumi_policy_state_arg *state)
{
	const struct kasumi_policy_snapshot *policy;

	if (!state)
		return;
	rcu_read_lock();
	policy = rcu_dereference(kasumi_policy_current);
	if (policy) {
		state->generation = policy->generation;
		state->owner = policy->owner;
		state->flags = policy->flags;
		state->allow_count = policy->allow_count;
		state->deny_count = policy->deny_count;
	} else {
		state->generation = 0;
		state->owner = KSM_POLICY_OWNER_AUTO;
		state->flags = 0;
		state->allow_count = 0;
		state->deny_count = 0;
	}
	state->effective_owner =
		kasumi_policy_validate_effective_owner(state->owner);
	state->detected_roots = READ_ONCE(kasumi_root_mask);
	state->max_uid_count = KASUMI_ALLOWLIST_UID_MAX;
	state->enabled = kasumi_config_enabled();
	rcu_read_unlock();
}

int kasumi_policy_copy_uids(u32 list, u32 *uids, u32 capacity,
			    u32 *copied, u32 *total, u64 *generation)
{
	const struct kasumi_policy_snapshot *policy;
	const u32 *source = NULL;
	u32 count = 0;
	u32 nr;
	u64 gen = 0;

	if (list != KSM_POLICY_UID_LIST_ALLOW &&
	    list != KSM_POLICY_UID_LIST_DENY)
		return -EINVAL;
	if (capacity && !uids)
		return -EINVAL;

	rcu_read_lock();
	policy = rcu_dereference(kasumi_policy_current);
	if (policy) {
		gen = policy->generation;
		if (list == KSM_POLICY_UID_LIST_ALLOW) {
			source = policy->allow_uid_list;
			count = policy->allow_count;
		} else {
			source = policy->deny_uid_list;
			count = policy->deny_count;
		}
	}
	nr = min(capacity, count);
	if (nr)
		memcpy(uids, source, nr * sizeof(*uids));
	rcu_read_unlock();

	if (copied)
		*copied = nr;
	if (total)
		*total = count;
	if (generation)
		*generation = gen;
	return 0;
}

int kasumi_policy_reset(void)
{
	int error = kasumi_policy_replace(KSM_POLICY_OWNER_AUTO, 0, NULL, 0, NULL, 0);

	if (!error)
		kasumi_invalidate_apatch_cache();
	return error;
}

void kasumi_policy_shutdown_locked(void)
{
	struct kasumi_policy_snapshot *old;

	lockdep_assert_held(&kasumi_config_mutex);
	old = rcu_dereference_protected(kasumi_policy_current,
					lockdep_is_held(&kasumi_config_mutex));
	RCU_INIT_POINTER(kasumi_policy_current, NULL);
	if (old)
		call_rcu(&old->rcu, kasumi_policy_snapshot_free_rcu);
	kasumi_policy_unpin_provider();
}

static KASUMI_NOCFI enum kasumi_policy_scope
kasumi_policy_scope_for_uid(uid_t uid, bool require_enabled)
{
	struct kasumi_policy_snapshot *policy;
	struct kasumi_policy_runtime runtime;
	u32 configured_owner;
	u32 owner;
	u32 flags;
	enum kasumi_policy_scope scope = KASUMI_POLICY_SCOPE_NONE;
	bool allow_gate = true;
	bool denied = false;

	/* Provider/list state is published by SET_ENABLED; a disabled provider
	 * projects nothing for anyone. */
	if (require_enabled && !kasumi_config_enabled())
		return KASUMI_POLICY_SCOPE_NONE;
	/* Non-app, non-isolated UIDs -- system_server, init, native daemons, root,
	 * shell -- default to VIEW so the system actually applies the module: PMS
	 * and the OverlayManager must scan and enable a redirected priv-app / RRO,
	 * init reads module files at boot, and so on. A detector cannot obtain a
	 * system/root/shell UID, so there is no concealment need here; app and
	 * isolated UIDs continue through the per-observer policy below. */
	if (!kasumi_uid_is_app(uid) && !kasumi_uid_is_isolated(uid))
		return KASUMI_POLICY_SCOPE_VIEW;
	/* Isolated app processes always receive concealment, independently of
	 * their transient UID and of any host-app allow/deny list.
	 */
	if (kasumi_uid_is_isolated(uid))
		return KASUMI_POLICY_SCOPE_SPOOF;

	rcu_read_lock();
	policy = kasumi_policy_read_at(kasumi_rules_generation(), &runtime);
	configured_owner = policy ? policy->owner : KSM_POLICY_OWNER_AUTO;
	flags = policy ? policy->flags : 0;
	owner = configured_owner == KSM_POLICY_OWNER_AUTO ?
		runtime.owner : configured_owner;

	/* AUTO is valid only when root detection selected one supported provider. */
	if (configured_owner == KSM_POLICY_OWNER_AUTO &&
	    !runtime.spoof_allowed)
		goto out;

	switch (owner) {
	case KSM_POLICY_OWNER_KERNELSU: {
		kasumi_ksu_uid_should_umount_fn provider;

		if (!(runtime.root_mask & KASUMI_ROOT_KSU))
			break;
		provider = runtime.ksu;
		if (!provider)
			break;
		scope = provider(uid) ? KASUMI_POLICY_SCOPE_SPOOF :
			KASUMI_POLICY_SCOPE_VIEW;
		break;
	}
	case KSM_POLICY_OWNER_APATCH: {
		int (*provider)(uid_t uid) = runtime.apatch;

		if ((runtime.root_mask & KASUMI_ROOT_APATCH) &&
		    provider)
			scope = provider(uid) != 0 ?
				KASUMI_POLICY_SCOPE_SPOOF : KASUMI_POLICY_SCOPE_VIEW;
		break;
	}
	case KSM_POLICY_OWNER_MANUAL:
		/* Manual policy has no inverse provider set. Its explicit allow
		 * list therefore names spoof targets and never implicitly grants a
		 * virtual view to every other application.
		 */
		if (flags & KSM_POLICY_FLAG_USE_ALLOW_UIDS)
			scope = KASUMI_POLICY_SCOPE_SPOOF;
		break;
	case KSM_POLICY_OWNER_DISABLED:
	case KSM_POLICY_OWNER_MAGISK:
	case KSM_POLICY_OWNER_AUTO:
	default:
		break;
	}

	/* MANUAL is fail-closed without an explicit allow policy. */
	if (owner == KSM_POLICY_OWNER_MANUAL &&
	    !(flags & KSM_POLICY_FLAG_USE_ALLOW_UIDS))
		allow_gate = false;
	else if (flags & KSM_POLICY_FLAG_USE_ALLOW_UIDS)
		allow_gate = policy && xa_load(&policy->allow_uids, uid) != NULL;

	/* A deny entry is the final decision and wins over every other source. */
	if ((flags & KSM_POLICY_FLAG_USE_DENY_UIDS) && policy)
		denied = xa_load(&policy->deny_uids, uid) != NULL;

out:
	rcu_read_unlock();
	return allow_gate && !denied ? scope : KASUMI_POLICY_SCOPE_NONE;
}

KASUMI_NOCFI enum kasumi_policy_scope kasumi_policy_current_scope(void)
{
	if (kasumi_hide_rules_resolving() || kasumi_vfs_internal_current())
		return KASUMI_POLICY_SCOPE_NONE;
	return kasumi_policy_scope_for_uid(__kuid_val(task_uid(current)), true);
}

bool kasumi_rule_scope_active(void)
{
	long tgid = atomic_long_read(&kasumi_ioctl_tgid);

	return kasumi_config_enabled() &&
	       !kasumi_vfs_internal_current() &&
	       !kasumi_hide_rules_resolving() &&
	       (tgid <= 0 || tgid != (long)task_tgid_vnr(current));
}

bool kasumi_rule_current_sees(u32 flags)
{
	return kasumi_rule_scope_active() &&
	       ((flags & KSM_RULE_BYPASS_POLICY) ||
		kasumi_policy_current_is_view_target());
}

bool kasumi_policy_current_is_view_target(void)
{
	return kasumi_policy_current_scope() == KASUMI_POLICY_SCOPE_VIEW;
}

bool kasumi_hide_storage_parent(const struct inode *parent)
{
	return parent && (parent->i_sb->s_magic == FUSE_SUPER_MAGIC ||
			  gid_eq(READ_ONCE(parent->i_gid),
				 KGIDT_INIT(KASUMI_MEDIA_RW_GID)));
}

KASUMI_NOCFI bool kasumi_hide_scope_allowed(bool storage_managed,
						   u32 flags)
{
	long ioctl_tgid;
	uid_t uid = __kuid_val(current_uid());
	bool allowed = false;

	if (!kasumi_rule_scope_active())
		return false;
	if (flags & KSM_RULE_BYPASS_POLICY)
		return true;

	/* Pair with enable/disable publication before serving hide rules. */
	if (!kasumi_config_enabled() ||
	    kasumi_is_privileged_process())
		return false;
	if (kasumi_uid_is_app(uid)) {
		struct kasumi_policy_runtime runtime;
		struct kasumi_policy_snapshot *policy;
		u32 owner;

		rcu_read_lock();
		policy = kasumi_policy_read_at(kasumi_rules_generation(), &runtime);
		owner = policy && policy->owner != KSM_POLICY_OWNER_AUTO ?
			policy->owner : runtime.owner;
		if (runtime.ksu_allow && owner == KSM_POLICY_OWNER_KERNELSU)
			allowed = runtime.ksu_allow(uid);
		rcu_read_unlock();
		if (allowed)
			return false;
	}
	/* Storage services need the backing view, not a global hide exemption. */
	if (storage_managed && in_group_p(KGIDT_INIT(KASUMI_MEDIA_RW_GID)))
		return false;
	ioctl_tgid = atomic_long_read(&kasumi_ioctl_tgid);
	return ioctl_tgid <= 0 || ioctl_tgid != (long)task_tgid_vnr(current);
}

bool kasumi_policy_current_is_hide_target(const struct inode *parent)
{
	return kasumi_hide_scope_allowed(kasumi_hide_storage_parent(parent), 0);
}

bool kasumi_rule_current_hides(const struct inode *parent, u32 flags)
{
	return kasumi_hide_scope_allowed(kasumi_hide_storage_parent(parent),
					 flags);
}

bool kasumi_policy_current_is_spoof_target(void)
{
	return kasumi_policy_current_scope() == KASUMI_POLICY_SCOPE_SPOOF;
}

bool kasumi_policy_current_is_isolated(void)
{
	return kasumi_uid_is_isolated(__kuid_val(task_uid(current)));
}

KASUMI_NOCFI bool kasumi_policy_uid_is_view_target(uid_t uid)
{
	return kasumi_policy_scope_for_uid(uid, false) ==
		KASUMI_POLICY_SCOPE_VIEW;
}

KASUMI_NOCFI bool kasumi_policy_uid_is_spoof_target(uid_t uid)
{
	return kasumi_policy_scope_for_uid(uid, false) ==
		KASUMI_POLICY_SCOPE_SPOOF;
}

static void kasumi_policy_mark_ksu_available(void)
{
	u32 root_mask = READ_ONCE(kasumi_root_mask);
	bool ambiguous;

	root_mask |= KASUMI_ROOT_KSU;
	root_mask &= ~KASUMI_ROOT_NON_ROOT;
	ambiguous = root_mask &
		(KASUMI_ROOT_APATCH | KASUMI_ROOT_MAGISK | KASUMI_ROOT_MULTI);
	/* A newly available second provider makes AUTO ambiguous and fail-closed. */
	if (ambiguous) {
		WRITE_ONCE(kasumi_root_spoof_allowed, false);
		root_mask |= KASUMI_ROOT_MULTI;
		WRITE_ONCE(kasumi_root_policy_owner, KSM_POLICY_OWNER_DISABLED);
	} else {
		WRITE_ONCE(kasumi_root_policy_owner, KSM_POLICY_OWNER_KERNELSU);
	}
	WRITE_ONCE(kasumi_root_mask, root_mask);
	WRITE_ONCE(kasumi_ksu_policy_available, true);
	if (!ambiguous)
		WRITE_ONCE(kasumi_root_spoof_allowed, true);
}

static void kasumi_policy_mark_ksu_unavailable(void)
{
	WRITE_ONCE(kasumi_ksu_policy_available, false);
	if (READ_ONCE(kasumi_root_policy_owner) == KSM_POLICY_OWNER_KERNELSU) {
		WRITE_ONCE(kasumi_root_policy_owner, KSM_POLICY_OWNER_DISABLED);
		WRITE_ONCE(kasumi_root_spoof_allowed, false);
	}
}

/*
 * GKI kernels protect many VFS symbols behind namespaces or don't export
 * them at all. We resolve ALL problematic VFS symbols via kprobe at init
 * time, so the module has zero direct VFS symbol dependencies.
 */
/*
 * Reload the KernelSU provider. Only ksu_uid_should_umount is authoritative:
 * bulk and on-disk profiles omit live default-profile semantics, so using
 * either as a substitute could select the wrong apps.
 */
static bool kasumi_policy_prepare_ksu_locked(void)
{
	unsigned long addr;

	lockdep_assert_held(&kasumi_config_mutex);
	if (!kasumi_ksu_uid_should_umount_ptr) {
		addr = kasumi_lookup_callable_quiet("ksu_uid_should_umount");
		if (addr && kasumi_valid_kernel_addr(addr) &&
		    kasumi_policy_pin_stable_provider(addr,
					       &kasumi_ksu_provider_module))
			WRITE_ONCE(kasumi_ksu_uid_should_umount_ptr,
				   (kasumi_ksu_uid_should_umount_fn)addr);
	}
	if (kasumi_ksu_uid_should_umount_ptr) {
		if (!kasumi_policy_pin_stable_provider(
			(unsigned long)kasumi_ksu_uid_should_umount_ptr,
			&kasumi_ksu_provider_module)) {
			WRITE_ONCE(kasumi_ksu_uid_should_umount_ptr, NULL);
			kasumi_policy_mark_ksu_unavailable();
			return false;
		}
		kasumi_policy_mark_ksu_available();
		if (!kasumi_ksu_allow_uid_ptr) {
			addr =
			    kasumi_lookup_callable_quiet("__ksu_is_allow_uid");
			if (addr && kasumi_valid_kernel_addr(addr) &&
			    kasumi_policy_pin_stable_provider(
				addr, &kasumi_ksu_allow_provider_module))
				WRITE_ONCE(kasumi_ksu_allow_uid_ptr,
					   (bool (*)(uid_t))addr);
		}
		return true;
	}

	/*
	 * Bulk/file fallbacks cannot reproduce ksu_uid_should_umount(): they omit
	 * the live default non-root profile or have version-specific layouts. An
	 * approximate cache risks selecting the wrong apps, so fail closed.
	 */
	kasumi_policy_mark_ksu_unavailable();
	return false;
}

static bool kasumi_policy_prepare_apatch_addr_locked(unsigned long addr,
						      bool lifetime_stable)
{
	bool is_module = false;

	lockdep_assert_held(&kasumi_config_mutex);
	if (!addr)
		return false;
	if (kasumi_policy_pin_linux_module(addr,
					   &kasumi_apatch_provider_module,
					   &is_module))
		return true;
	if (is_module)
		goto unavailable;
	if (lifetime_stable)
		return true;
	if (kasumi_policy_pin_stable_provider(addr, &kasumi_apatch_provider_module))
		return true;
unavailable:
	WRITE_ONCE(kasumi_ap_get_mod_exclude, NULL);
	WRITE_ONCE(kasumi_root_spoof_allowed, false);
	WRITE_ONCE(kasumi_root_policy_owner, KSM_POLICY_OWNER_DISABLED);
	return false;
}

bool kasumi_policy_prepare_enable_locked(void)
{
	unsigned long apatch_addr = 0;
	unsigned long ksu_addr;
	bool apatch_stable = false;
	bool apatch_available;
	bool ksu_available;
	u32 configured_owner;
	u32 provider_owner;
	u32 root_mask;
	bool ready = true;

	lockdep_assert_held(&kasumi_config_mutex);
	configured_owner = kasumi_policy_configured_owner();
	provider_owner = configured_owner;
	root_mask = READ_ONCE(kasumi_root_mask) &
		(KASUMI_ROOT_KSU_RDR | KASUMI_ROOT_MAGISK);
	/* AUTO is the default and must notice providers loaded after Kasumi. */
	if (provider_owner == KSM_POLICY_OWNER_AUTO) {
		ksu_addr = kasumi_lookup_callable_quiet("ksu_uid_should_umount");
		ksu_available = ksu_addr && kasumi_valid_kernel_addr(ksu_addr);
		apatch_available = kasumi_probe_apatch_policy(&apatch_addr,
							 &apatch_stable);
		if (ksu_available)
			root_mask |= KASUMI_ROOT_KSU;
		if (apatch_available)
			root_mask |= KASUMI_ROOT_APATCH;
		if (root_mask & (KASUMI_ROOT_KSU | KASUMI_ROOT_APATCH |
				 KASUMI_ROOT_MAGISK))
			root_mask &= ~KASUMI_ROOT_NON_ROOT;
		else
			root_mask |= KASUMI_ROOT_NON_ROOT;
		if ((root_mask & KASUMI_ROOT_KSU) &&
		    (root_mask & (KASUMI_ROOT_APATCH | KASUMI_ROOT_MAGISK)))
			root_mask |= KASUMI_ROOT_MULTI;
		WRITE_ONCE(kasumi_root_mask, root_mask);
	}
	if (provider_owner == KSM_POLICY_OWNER_AUTO) {
		if (root_mask & KASUMI_ROOT_MULTI) {
			provider_owner = KSM_POLICY_OWNER_DISABLED;
			WRITE_ONCE(kasumi_root_policy_owner,
				   KSM_POLICY_OWNER_DISABLED);
			WRITE_ONCE(kasumi_root_spoof_allowed, false);
			ready = false;
		} else if ((root_mask & KASUMI_ROOT_KSU) &&
			 !(root_mask & (KASUMI_ROOT_APATCH | KASUMI_ROOT_MAGISK)))
			provider_owner = KSM_POLICY_OWNER_KERNELSU;
		else if ((root_mask & KASUMI_ROOT_APATCH) &&
			 !(root_mask & (KASUMI_ROOT_KSU | KASUMI_ROOT_MAGISK)))
			provider_owner = KSM_POLICY_OWNER_APATCH;
		else {
			provider_owner = KSM_POLICY_OWNER_DISABLED;
			ready = false;
		}
	}
	if (provider_owner == KSM_POLICY_OWNER_KERNELSU)
		ready = kasumi_policy_prepare_ksu_locked();
	else if (provider_owner == KSM_POLICY_OWNER_APATCH) {
		if (!apatch_addr)
			apatch_available = kasumi_probe_apatch_policy(
				&apatch_addr, &apatch_stable);
		ready = apatch_available &&
			kasumi_policy_prepare_apatch_addr_locked(apatch_addr,
								 apatch_stable);
		if (ready)
			WRITE_ONCE(kasumi_ap_get_mod_exclude,
				   (int (*)(uid_t))apatch_addr);
		if (ready) {
			root_mask = READ_ONCE(kasumi_root_mask) |
				KASUMI_ROOT_APATCH;
			root_mask &= ~KASUMI_ROOT_NON_ROOT;
			WRITE_ONCE(kasumi_root_mask, root_mask);
		}
	}
	if (configured_owner == KSM_POLICY_OWNER_AUTO) {
		if (ready && provider_owner != KSM_POLICY_OWNER_DISABLED) {
			WRITE_ONCE(kasumi_root_policy_owner, provider_owner);
			WRITE_ONCE(kasumi_root_spoof_allowed, true);
		} else {
			WRITE_ONCE(kasumi_root_policy_owner,
				   KSM_POLICY_OWNER_DISABLED);
			WRITE_ONCE(kasumi_root_spoof_allowed, false);
		}
	}
	return ready;
}

void kasumi_policy_disable_provider_locked(void)
{
	lockdep_assert_held(&kasumi_config_mutex);
	kasumi_invalidate_apatch_cache();
	WRITE_ONCE(kasumi_ksu_allow_uid_ptr, NULL);
	WRITE_ONCE(kasumi_ksu_uid_should_umount_ptr, NULL);
	WRITE_ONCE(kasumi_ap_get_mod_exclude, NULL);
	kasumi_apatch_policy_lifetime_stable = false;
	kasumi_policy_mark_ksu_unavailable();
	/* Readers hold rcu_read_lock() while calling the provider. */
	synchronize_rcu();
	kasumi_policy_unpin_provider();
}

struct kasumi_policy_batch *kasumi_policy_batch_prepare(
	u64 generation, bool replace, bool reset, u32 owner, u32 flags,
	const u32 *allow_uids, u32 allow_count,
	const u32 *deny_uids, u32 deny_count, bool enabled)
{
	struct kasumi_policy_batch *batch;
	struct kasumi_policy_snapshot *old;
	bool ready = true;
	int error;

	if (!generation || generation != kasumi_batch_generation())
		return ERR_PTR(-EINVAL);
	batch = kzalloc(sizeof(*batch), GFP_KERNEL);
	if (!batch)
		return ERR_PTR(-ENOMEM);
	mutex_lock(&kasumi_config_mutex);
	old = rcu_dereference_protected(kasumi_policy_current,
				       lockdep_is_held(&kasumi_config_mutex));
	if (!replace) {
		owner = old ? old->owner : KSM_POLICY_OWNER_AUTO;
		flags = old ? old->flags : 0;
		allow_uids = old ? old->allow_uid_list : NULL;
		allow_count = old ? old->allow_count : 0;
		deny_uids = old ? old->deny_uid_list : NULL;
		deny_count = old ? old->deny_count : 0;
	}
	batch->replacement = reset ? NULL : kasumi_policy_snapshot_create(owner, flags,
		allow_uids, allow_count, deny_uids, deny_count);
	if (IS_ERR(batch->replacement)) {
		error = PTR_ERR(batch->replacement);
		mutex_unlock(&kasumi_config_mutex);
		kfree(batch);
		return ERR_PTR(error);
	}
	batch->generation = generation;
	batch->enabled = enabled;
	batch->previous = old;
	batch->previous_runtime = kasumi_policy_capture_runtime();
	batch->runtime = batch->previous_runtime;
	if (batch->replacement)
		batch->replacement->generation =
			atomic64_inc_return(&kasumi_policy_generation);
	rcu_assign_pointer(kasumi_policy_pending, batch);
	/* Provider discovery can change globals. Existing readers use the
	 * captured provider state until the common generation is published. */
	synchronize_rcu();
	if (reset)
		kasumi_invalidate_apatch_cache();
	if (enabled) {
		ready = kasumi_policy_prepare_enable_locked();
		batch->runtime = kasumi_policy_capture_runtime();
	} else {
		batch->runtime.ksu = NULL;
		batch->runtime.ksu_allow = NULL;
		batch->runtime.apatch = NULL;
		batch->runtime.spoof_allowed = false;
	}
	mutex_unlock(&kasumi_config_mutex);
	if (!ready) {
		kasumi_policy_batch_finish(batch, false);
		return ERR_PTR(-ENODEV);
	}
	return batch;
}

void kasumi_policy_batch_finish(struct kasumi_policy_batch *batch, bool publish)
{
	if (!batch)
		return;
	mutex_lock(&kasumi_config_mutex);
	if (publish) {
		rcu_assign_pointer(kasumi_policy_current, batch->replacement);
		if (!batch->enabled)
			kasumi_policy_disable_provider_locked();
	} else {
		kasumi_policy_restore_runtime(&batch->previous_runtime);
	}
	rcu_assign_pointer(kasumi_policy_pending, NULL);
	mutex_unlock(&kasumi_config_mutex);
	if (publish) {
		if (batch->previous)
			call_rcu(&batch->previous->rcu, kasumi_policy_snapshot_free_rcu);
	} else if (batch->replacement) {
		call_rcu(&batch->replacement->rcu, kasumi_policy_snapshot_free_rcu);
	}
	kfree_rcu(batch, rcu);
}

/* ======================================================================
 * Part 12: Forward Redirect (resolve_target)
 * ====================================================================== */

char *kasumi_resolve_target(const char *pathname)
{
	u64 generation;
	struct kasumi_entry *entry;
	u32 hash;
	char *target = NULL;
	size_t path_len;
	pid_t pid;

	if (unlikely(!kasumi_config_enabled() || !pathname ||
		     !kasumi_rule_scope_active()))
		return NULL;

	pid = task_tgid_vnr(current);
	if (READ_ONCE(kasumi_daemon_pid) > 0 && pid == READ_ONCE(kasumi_daemon_pid))
		return NULL;
	path_len = strlen(pathname);
	hash = full_name_hash(NULL, pathname, path_len);

	/* Fast path: atomic + bloom before rcu_read_lock */
	if (atomic_read(&kasumi_rule_count) == 0)
		return NULL;
	{
		unsigned long bh1 = jhash(pathname, (u32)path_len, 0) & (KASUMI_BLOOM_SIZE - 1);
		unsigned long bh2 = jhash(pathname, (u32)path_len, 1) & (KASUMI_BLOOM_SIZE - 1);
		if (!test_bit(bh1, kasumi_path_bloom) || !test_bit(bh2, kasumi_path_bloom))
			return NULL;
	}

	rcu_read_lock();
	generation = kasumi_rules_generation();
	hlist_for_each_entry_rcu(entry,
		&kasumi_paths[hash_min(hash, KASUMI_HASH_BITS)], node) {
		if (!kasumi_rule_visible(&entry->life, generation))
			continue;
		if (!kasumi_rule_current_sees(entry->rule_flags))
			continue;
		if (entry->src_hash == hash &&
		    strcmp(entry->src, pathname) == 0) {
			target = kstrdup(entry->target, GFP_ATOMIC);
			rcu_read_unlock();
			return target;
		}
	}
	/*
	 * Merge trie is NOT consulted here for path redirect. Merge rules
	 * only affect directory listing (inject via iterate_dir). Individual
	 * file redirects are materialized into kasumi_paths at ADD_MERGE_RULE
	 * time, so the bloom+hash exact match above handles them.
	 *
	 * The KPM version validated merge targets with kern_path() before
	 * redirecting. In LKM kprobe context we cannot sleep, so blind
	 * merge-trie redirect would send EVERY path under the merge prefix
	 * to the module dir — including original system files that don't
	 * exist there — breaking PMS and causing bootloop.
	 */

	rcu_read_unlock();
	return target;
}

#define KASUMI_SYMLINK_LIMIT 40

static bool kasumi_relative_path_safe(const char *path)
{
	const char *component = path;

	while (component && *component) {
		const char *slash = strchr(component, '/');
		size_t length = slash ? (size_t)(slash - component) :
			strlen(component);

		if ((length == 1 && component[0] == '.') ||
		    (length == 2 && component[0] == '.' && component[1] == '.'))
			return false;
		component = slash ? slash + 1 : NULL;
	}
	return true;
}

static bool KASUMI_NOCFI kasumi_rule_get_source_flags_depth(
	const char *pathname, unsigned int lookup_flags,
	struct kasumi_rule_source *source, unsigned int symlink_depth);

void kasumi_project_visible_stat(struct kstat *result,
				 const struct kstat *source_stat,
				 const struct kstat *visible_template,
				 bool preserve_visible_metadata,
				 unsigned long visible_ino,
				 unsigned long visible_dev)
{
	if (!result || !source_stat)
		return;
	if (preserve_visible_metadata && visible_template) {
		*result = *visible_template;
		result->mode = (source_stat->mode & S_IFMT) |
			       (visible_template->mode & ~S_IFMT);
		result->rdev = source_stat->rdev;
		result->size = source_stat->size;
		result->blocks = source_stat->blocks;
		result->blksize = source_stat->blksize;
		result->result_mask |= source_stat->result_mask &
			(STATX_TYPE | STATX_MODE | STATX_SIZE | STATX_BLOCKS);
	} else {
		*result = *source_stat;
	}
	result->ino = visible_ino;
	result->dev = visible_dev;
}

static int kasumi_visible_access_ids(const struct kstat *stat, int mode,
				     const struct cred *cred, kuid_t uid,
				     kgid_t gid)
{
	umode_t granted;

	if (!stat)
		return -ENOENT;
	if (!mode)
		return 0;
	if (uid_eq(uid, stat->uid))
		granted = (stat->mode >> 6) & 7;
	else if (gid_eq(gid, stat->gid) || in_group_p(stat->gid))
		granted = (stat->mode >> 3) & 7;
	else
		granted = stat->mode & 7;
	if (!(mode & ~granted))
		return 0;

	/* Match access(2)'s namespace-root DAC override while retaining the
	 * ordinary rule that a regular executable needs at least one x bit. */
	if (uid_eq(uid, make_kuid(cred->user_ns, 0)) &&
	    (!(mode & MAY_EXEC) || !S_ISREG(stat->mode) ||
	     (stat->mode & 0111)))
		return 0;
	return -EACCES;
}

int kasumi_visible_access(const struct kstat *stat, int mode,
			  bool effective_ids)
{
	const struct cred *cred = current_cred();
	kuid_t uid = effective_ids ? cred->euid : cred->uid;
	kgid_t gid = effective_ids ? cred->egid : cred->gid;

	return kasumi_visible_access_ids(stat, mode, cred, uid, gid);
}

int kasumi_visible_open_access(const struct kstat *stat, int mode)
{
	const struct cred *cred = current_cred();

	return kasumi_visible_access_ids(stat, mode, cred, cred->fsuid,
					 cred->fsgid);
}

void kasumi_rule_source_put(struct kasumi_rule_source *source)
{
	if (source->path.dentry)
		kasumi_path_put(&source->path);
	memset(&source->path, 0, sizeof(source->path));
	kasumi_identity_put(source->identity);
	source->identity = NULL;
}

static bool kasumi_rule_refresh_exact_source(
	struct kasumi_rule_source *source)
{
	struct kstat source_stat;
	int ret;

	if (!source || !source->path.dentry || !source->path.mnt)
		return false;
	if (!kasumi_vfs_getattr)
		return source->stat_valid;
	memset(&source_stat, 0, sizeof(source_stat));
	ret = kasumi_vfs_getattr_unprojected(&source->path, &source_stat,
				 STATX_BASIC_STATS | STATX_BTIME,
				 AT_STATX_SYNC_AS_STAT);
	if (ret) {
		kasumi_rule_source_put(source);
		source->stat_valid = false;
		source->error = ret;
		return false;
	}
	/* The pinned path fixes object identity across rename/unlink, but mutable
	 * inode metadata must retain ordinary VFS behaviour after rule install. */
	source->source_mode = source_stat.mode;
	kasumi_project_visible_stat(&source->stat, &source_stat, &source->stat,
				    source->preserve_visible_metadata,
				    source->visible_ino,
				    source->visible_dev);
	source->stat_valid = true;
	return true;
}

static bool kasumi_rule_source_from_path(struct path *resolved,
	struct kasumi_rule_source *source, struct kasumi_identity_domain *domain)
{
	struct inode *inode;
	struct kstat stat;
	int ret;

	inode = resolved && resolved->dentry ? d_inode(resolved->dentry) : NULL;
	if (!inode) {
		kasumi_path_put(resolved);
		source->error = -ENOENT;
		return false;
	}
	memset(&stat, 0, sizeof(stat));
	ret = kasumi_vfs_getattr_unprojected(resolved, &stat,
				 STATX_BASIC_STATS | STATX_BTIME,
				 AT_STATX_SYNC_AS_STAT);
	if (ret) {
		kasumi_path_put(resolved);
		source->error = ret;
		return false;
	}
	ret = kasumi_identity_domain_source_get(domain, inode->i_sb->s_dev,
		inode->i_ino, GFP_NOFS, &source->identity);
	if (ret) {
		kasumi_path_put(resolved);
		source->error = ret;
		return false;
	}
	source->path = *resolved;
	source->stat = stat;
	source->visible_ino = kasumi_identity_ino(source->identity);
	/* Scheme A: dynamic (directory/merge) sources have no cached visible dev.
	 * Publish the captured /system dev — a real device and the correct one for
	 * the common /system masquerade — rather than the anonymous vnode minor. */
	source->visible_dev = kasumi_system_dev ? kasumi_system_dev :
						  kasumi_vnode_device();
	source->stat.ino = source->visible_ino;
	source->stat.dev = source->visible_dev;
	source->source_mode = stat.mode;
	source->stat_valid = true;
	source->preserve_visible_metadata = false;
	return true;
}

static KASUMI_NOCFI int kasumi_read_link_target(const struct path *link,
					char *target, size_t target_size)
{
	struct delayed_call done = {};
	const char *value;
	size_t length;
	int ret = 0;

	if (!link || !link->dentry || !target || target_size < 2 ||
	    !kasumi_vfs_get_link)
		return -EOPNOTSUPP;
	value = kasumi_vfs_get_link(link->dentry, &done);
	if (IS_ERR(value)) {
		ret = PTR_ERR(value);
		goto out;
	}
	if (!value) {
		ret = -EIO;
		goto out;
	}
	length = strnlen(value, target_size);
	if (length >= target_size) {
		ret = -ENAMETOOLONG;
		goto out;
	}
	memcpy(target, value, length + 1);
out:
	do_delayed_call(&done);
	return ret;
}

static bool KASUMI_NOCFI kasumi_follow_absolute_link(
	const char *target, const char *remaining, unsigned int lookup_flags,
	struct kasumi_rule_source *source, unsigned int symlink_depth)
{
	struct path resolved;
	char *next;
	size_t target_len;
	size_t remaining_len;
	int ret;

	if (lookup_flags & LOOKUP_BENEATH) {
		source->error = -EXDEV;
		return false;
	}
	if (symlink_depth >= KASUMI_SYMLINK_LIMIT) {
		source->error = -ELOOP;
		return false;
	}
	target_len = strlen(target);
	remaining_len = remaining ? strlen(remaining) : 0;
	if (target_len + remaining_len + 1 > KSM_MAX_LEN_PATHNAME) {
		source->error = -ENAMETOOLONG;
		return false;
	}
	next = kmalloc(target_len + remaining_len + 1, GFP_KERNEL);
	if (!next) {
		source->error = -ENOMEM;
		return false;
	}
	memcpy(next, target, target_len);
	if (remaining_len) {
		if (next[target_len - 1] == '/' &&
		    remaining[0] == '/') {
			memcpy(next + target_len, remaining + 1, remaining_len);
		} else {
			memcpy(next + target_len, remaining, remaining_len + 1);
		}
	} else {
		next[target_len] = '\0';
	}
	if (kasumi_rule_get_source_flags_depth(next, lookup_flags, source,
					       symlink_depth + 1)) {
		kfree(next);
		return true;
	}
	if (source->error) {
		kfree(next);
		return false;
	}
	if (kasumi_should_hide(next)) {
		source->error = -ENOENT;
		kfree(next);
		return false;
	}
	ret = kasumi_kern_path(next, lookup_flags, &resolved);
	kfree(next);
	if (ret) {
		source->error = ret;
		return false;
	}
	return kasumi_rule_source_from_path(&resolved, source, NULL);
}

static bool KASUMI_NOCFI
kasumi_directory_rule_source(const char *pathname, size_t path_len,
			     unsigned int lookup_flags,
			     struct kasumi_rule_source *source,
			     unsigned int symlink_depth)
{
	u64 generation;
	struct kasumi_entry *entry;
	struct path directory = {};
	struct kasumi_identity_domain *domain = NULL;
	bool found;
	struct path resolved;
	char *relative;
	char *cursor;
	size_t prefix_len = path_len;
	bool pinned = false;
	int ret;

	if (!kasumi_vfs_path_lookup || !kasumi_vfs_getattr)
		return false;
	while (prefix_len > 1) {
		size_t slash = prefix_len;
		u32 hash;

		while (slash > 0 && pathname[slash - 1] != '/')
			slash--;
		if (slash <= 1)
			break;
		prefix_len = slash - 1;
		if (!kasumi_relative_path_safe(pathname + prefix_len + 1))
			return false;
		if (!test_bit(jhash(pathname, (u32)prefix_len, 0) &
			      (KASUMI_BLOOM_SIZE - 1), kasumi_path_bloom) ||
		    !test_bit(jhash(pathname, (u32)prefix_len, 1) &
			      (KASUMI_BLOOM_SIZE - 1), kasumi_path_bloom))
			continue;
		hash = full_name_hash(NULL, pathname, prefix_len);
		rcu_read_lock();
		generation = kasumi_rules_generation();
		hlist_for_each_entry_rcu(entry,
			&kasumi_paths[hash_min(hash, KASUMI_HASH_BITS)], node) {
			if (!kasumi_rule_visible(&entry->life, generation))
				continue;
			if (!kasumi_rule_current_sees(entry->rule_flags))
				continue;
			if (entry->src_hash != hash ||
			    strlen(entry->src) != prefix_len ||
			    memcmp(entry->src, pathname, prefix_len) != 0 ||
			    !entry->source_path_valid ||
			    !S_ISDIR(entry->source_mode))
				continue;
			domain = entry->source_domain;
			kasumi_identity_domain_get(domain);
			directory = entry->source_path;
			kasumi_path_get(&directory);
			pinned = true;
			break;
		}
		rcu_read_unlock();
		if (pinned)
			break;
	}
	if (!pinned)
		return false;
	relative = kstrdup(pathname + prefix_len + 1, GFP_KERNEL);
	if (!relative) {
		kasumi_path_put(&directory);
		kasumi_identity_domain_put(domain);
		source->error = -ENOMEM;
		return false;
	}
	ret = kasumi_vfs_path_lookup(directory.dentry, directory.mnt, relative,
				     lookup_flags | LOOKUP_NO_SYMLINKS,
				     &resolved);
	if (!ret) {
		kasumi_path_put(&directory);
		kfree(relative);
		found = kasumi_rule_source_from_path(&resolved, source, domain);
		kasumi_identity_domain_put(domain);
		return found;
	}
	if (ret != -ELOOP || (lookup_flags & LOOKUP_NO_SYMLINKS)) {
		source->error = ret;
		goto out_relative;
	}
	if (kasumi_vfs_get_link) {
		cursor = relative;
		while (*cursor) {
			struct path probe;
			char target[KSM_MAX_LEN_PATHNAME];
			char *slash = strchr(cursor, '/');
			bool final = !slash;
			char saved = '\0';

			if (slash) {
				saved = *slash;
				*slash = '\0';
			}
			ret = kasumi_vfs_path_lookup(
				directory.dentry, directory.mnt, relative,
				lookup_flags & ~(LOOKUP_FOLLOW |
						 LOOKUP_NO_SYMLINKS), &probe);
			if (slash)
				*slash = saved;
			if (ret) {
				source->error = ret;
				goto out_relative;
			}
			if (d_is_symlink(probe.dentry)) {
				if (lookup_flags & LOOKUP_NO_SYMLINKS) {
					kasumi_path_put(&probe);
					source->error = -ELOOP;
					goto out_relative;
				}
				if (!(final && !(lookup_flags & LOOKUP_FOLLOW))) {
					if (lookup_flags & LOOKUP_CACHED) {
						kasumi_path_put(&probe);
						source->error = -EAGAIN;
						goto out_relative;
					}
					ret = kasumi_read_link_target(
						&probe, target, sizeof(target));
					if (ret) {
						kasumi_path_put(&probe);
						if (lookup_flags &
						    LOOKUP_NO_MAGICLINKS) {
							source->error = -ELOOP;
							goto out_relative;
						}
						goto lookup_full;
					}
					if (target[0] == '/' &&
					    !(lookup_flags & LOOKUP_IN_ROOT)) {
						const char *remaining = slash ? slash : "";

						bool found;

						kasumi_path_put(&probe);
						kasumi_path_put(&directory);
						found = kasumi_follow_absolute_link(
							target, remaining, lookup_flags,
							source, symlink_depth);
						kfree(relative);
						kasumi_identity_domain_put(domain);
						return found;
					}
				}
			}
			kasumi_path_put(&probe);
			if (!slash)
				break;
			cursor = slash + 1;
		}
	}
lookup_full:
	ret = kasumi_vfs_path_lookup(directory.dentry, directory.mnt, relative,
				     lookup_flags, &resolved);
	if (ret) {
		source->error = ret;
		goto out_relative;
	}
	kasumi_path_put(&directory);
	kfree(relative);
	found = kasumi_rule_source_from_path(&resolved, source, domain);
	kasumi_identity_domain_put(domain);
	return found;

out_relative:
	kasumi_identity_domain_put(domain);
	kasumi_path_put(&directory);
	kfree(relative);
	return false;
}

static bool KASUMI_NOCFI kasumi_rule_get_source_flags_depth(
	const char *pathname, unsigned int lookup_flags,
	struct kasumi_rule_source *source, unsigned int symlink_depth)
{
	u64 generation;
	struct kasumi_entry *entry;
	struct path exact_link = {};
	size_t path_len;
	u32 hash;
	pid_t pid;
	bool found = false;
	bool followed_exact_link = false;

	if (unlikely(!kasumi_config_enabled() || !pathname || !source ||
		     !kasumi_rule_scope_active()))
		return false;
	pid = task_tgid_vnr(current);
	if (READ_ONCE(kasumi_daemon_pid) > 0 &&
	    pid == READ_ONCE(kasumi_daemon_pid))
		return false;
	if (atomic_read(&kasumi_rule_count) == 0)
		return false;
	if (symlink_depth >= KASUMI_SYMLINK_LIMIT) {
		source->error = -ELOOP;
		return false;
	}

	path_len = strlen(pathname);
	if (test_bit(jhash(pathname, (u32)path_len, 0) &
		     (KASUMI_BLOOM_SIZE - 1), kasumi_path_bloom) &&
	    test_bit(jhash(pathname, (u32)path_len, 1) &
		     (KASUMI_BLOOM_SIZE - 1), kasumi_path_bloom)) {
		hash = full_name_hash(NULL, pathname, path_len);
		rcu_read_lock();
		generation = kasumi_rules_generation();
		hlist_for_each_entry_rcu(entry,
			&kasumi_paths[hash_min(hash, KASUMI_HASH_BITS)], node) {
			if (!kasumi_rule_visible(&entry->life, generation))
				continue;
			if (!kasumi_rule_current_sees(entry->rule_flags))
				continue;
			if (entry->src_hash != hash ||
			    strcmp(entry->src, pathname) != 0)
				continue;
			if (entry->source_path_valid && entry->source_path.dentry &&
			    entry->source_path.mnt) {
				if (!(lookup_flags & LOOKUP_FOLLOW) &&
				    entry->source_nofollow_path_valid) {
					source->path = entry->source_nofollow_path;
					source->stat = entry->source_nofollow_stat;
					source->source_mode =
						entry->source_nofollow_mode;
					source->visible_ino =
						entry->nofollow_visible_ino;
					source->visible_dev =
						entry->nofollow_visible_dev;
					source->stat_valid =
						entry->source_nofollow_stat_valid;
					source->preserve_visible_metadata = false;
				} else {
					if ((lookup_flags & LOOKUP_NO_SYMLINKS) &&
					    entry->source_nofollow_path_valid) {
						source->error = -ELOOP;
						break;
					}
					source->path = entry->source_path;
					source->stat = entry->visible_stat;
					source->source_mode = entry->source_mode;
					source->visible_ino = entry->visible_ino;
					source->visible_dev = entry->visible_dev;
					source->stat_valid =
						entry->visible_stat_valid;
					source->preserve_visible_metadata =
						entry->preserve_visible_metadata;
					if (entry->source_nofollow_path_valid) {
						exact_link =
							entry->source_nofollow_path;
						kasumi_path_get(&exact_link);
						followed_exact_link = true;
					}
				}
				source->identity = !(lookup_flags & LOOKUP_FOLLOW) &&
					entry->source_nofollow_path_valid ?
					entry->nofollow_identity : entry->source_identity;
				kasumi_identity_get(source->identity);
				kasumi_path_get(&source->path);
				found = true;
			}
			break;
		}
		rcu_read_unlock();
	}
	if (found && !kasumi_rule_refresh_exact_source(source)) {
		if (followed_exact_link)
			kasumi_path_put(&exact_link);
		return false;
	}
	if (found && followed_exact_link) {
		char target[KSM_MAX_LEN_PATHNAME];
		int ret = kasumi_read_link_target(&exact_link, target,
						  sizeof(target));

		kasumi_path_put(&exact_link);
		if (ret) {
			if (lookup_flags & LOOKUP_NO_MAGICLINKS) {
				kasumi_rule_source_put(source);
				source->error = -ELOOP;
				return false;
			}
			return true;
		}
		if (target[0] == '/' && !(lookup_flags & LOOKUP_IN_ROOT)) {
			struct kasumi_rule_source redirected = {};

			if (kasumi_follow_absolute_link(target, "", lookup_flags,
							&redirected,
							symlink_depth)) {
				kasumi_rule_source_put(source);
				*source = redirected;
				return true;
			}
			if (redirected.error) {
				kasumi_rule_source_put(source);
				source->error = redirected.error;
				return false;
			}
		}
	}
	if (found || source->error)
		return found;
	return kasumi_directory_rule_source(pathname, path_len, lookup_flags,
					    source, symlink_depth);
}

bool KASUMI_NOCFI kasumi_rule_get_source_flags(
	const char *pathname, unsigned int lookup_flags,
	struct kasumi_rule_source *source)
{
	if (source) {
		source->error = 0;
		source->preserve_visible_metadata = false;
	}
	return kasumi_rule_get_source_flags_depth(pathname, lookup_flags,
						 source, 0);
}

bool kasumi_rule_get_source(const char *pathname,
			    struct kasumi_rule_source *source)
{
	return kasumi_rule_get_source_flags(pathname, LOOKUP_FOLLOW, source);
}

static int kasumi_source_path_depth(const struct path *source,
				    const struct path *root)
{
	struct dentry *cursor;
	unsigned int depth = 0;

	if (!source || !root || source->mnt != root->mnt ||
	    !source->dentry || !root->dentry)
		return -1;
	cursor = source->dentry;
	for (;;) {
		struct dentry *parent;

		if (cursor == root->dentry)
			return (int)depth;
		parent = READ_ONCE(cursor->d_parent);
		if (!parent || parent == cursor || ++depth >= KSM_MAX_LEN_PATHNAME)
			return -1;
		cursor = parent;
	}
}

static bool kasumi_compose_visible_path(const struct kasumi_entry *entry,
					const struct path *source,
					char *visible_path,
					size_t visible_path_size)
{
	struct dentry *cursor = source->dentry;
	char *end;
	size_t relative_len;
	size_t root_len;

	if (!entry || !entry->src || !entry->source_path.dentry ||
	    visible_path_size < 2)
		return false;
	end = visible_path + visible_path_size;
	*--end = '\0';
	while (cursor != entry->source_path.dentry) {
		const unsigned char *name;
		struct dentry *parent;
		unsigned int name_len;

		name_len = READ_ONCE(cursor->d_name.len);
		name = READ_ONCE(cursor->d_name.name);
		parent = READ_ONCE(cursor->d_parent);
		if (!name || !name_len || !parent || parent == cursor ||
		    (size_t)(end - visible_path) <= name_len)
			return false;
		end -= name_len;
		memcpy(end, name, name_len);
		*--end = '/';
		cursor = parent;
	}

	root_len = strlen(entry->src);
	relative_len = strlen(end);
	if (root_len == 1 && entry->src[0] == '/' && relative_len) {
		if (relative_len + 1 > visible_path_size)
			return false;
		memmove(visible_path, end, relative_len + 1);
		return true;
	}
	if (root_len + relative_len + 1 > visible_path_size)
		return false;
	memmove(visible_path + root_len, end, relative_len + 1);
	memcpy(visible_path, entry->src, root_len);
	return true;
}

static KASUMI_NOCFI bool kasumi_rule_get_visible_path_canonical(
	const struct path *source, char *visible_path, size_t visible_path_size)
{
	u64 generation;
	struct kasumi_entry *entry;
	char *source_buffer;
	char *source_path;
	size_t best_length = 0;
	int bkt;
	bool found = false;

	if (!kasumi_d_absolute_path)
		return false;
	source_buffer = kmalloc(KSM_MAX_LEN_PATHNAME, GFP_ATOMIC);
	if (!source_buffer)
		return false;
	source_path = kasumi_d_absolute_path(source, source_buffer,
					     KSM_MAX_LEN_PATHNAME);
	if (IS_ERR_OR_NULL(source_path) || source_path[0] != '/')
		goto out;
	rcu_read_lock();
	generation = kasumi_rules_generation();
	hash_for_each_rcu(kasumi_paths, bkt, entry, node) {
		size_t root_length;
		const char *suffix;
		size_t suffix_length;
		size_t visible_root_length;

		if (!kasumi_rule_visible(&entry->life, generation))
			continue;
		if (!kasumi_rule_current_sees(entry->rule_flags))
			continue;
		if (!entry->source_path_valid || !S_ISDIR(entry->source_mode) ||
		    !entry->source_canonical)
			continue;
		root_length = strlen(entry->source_canonical);
		if (root_length < best_length ||
		    strncmp(source_path, entry->source_canonical, root_length) ||
		    (!(root_length == 1 && entry->source_canonical[0] == '/') &&
		     source_path[root_length] &&
		     source_path[root_length] != '/'))
			continue;
		suffix = root_length == 1 && entry->source_canonical[0] == '/' ?
			source_path : source_path + root_length;
		suffix_length = strlen(suffix);
		visible_root_length = strlen(entry->src);
		if (visible_root_length == 1 && entry->src[0] == '/' &&
		    suffix[0] == '/') {
			if (suffix_length + 1 > visible_path_size)
				continue;
			memcpy(visible_path, suffix, suffix_length + 1);
		} else {
			if (visible_root_length + suffix_length + 1 >
			    visible_path_size)
				continue;
			memcpy(visible_path, entry->src, visible_root_length);
			memcpy(visible_path + visible_root_length, suffix,
			       suffix_length + 1);
		}
		best_length = root_length;
		found = true;
	}
	rcu_read_unlock();
out:
	kfree(source_buffer);
	return found;
}

/* ---- Slice 4c-v2: pure-virtual directory topology rule-table queries ----- */

static struct rb_root kasumi_rule_prefixes = RB_ROOT;
static DEFINE_RWLOCK(kasumi_rule_prefix_lock);

static DEFINE_HASHTABLE(kasumi_rule_sources, KASUMI_HASH_BITS);

static void kasumi_rule_source_add(struct kasumi_rule_source_index *index,
				   const struct kasumi_entry *entry,
				   const struct path *path,
				   const struct kasumi_inode_identity *identity)
{
	const struct inode *inode = d_inode(path->dentry);
	dev_t dev = inode->i_sb ? inode->i_sb->s_dev : 0;

	index->entry = entry;
	index->inode = inode;
	index->identity = identity;
	write_lock(&kasumi_rule_prefix_lock);
	hash_add_rcu(kasumi_rule_sources, &index->node,
		     (unsigned long)dev ^ inode->i_ino);
	write_unlock(&kasumi_rule_prefix_lock);
}

static void kasumi_rule_source_remove(struct kasumi_entry *entry)
{
	unsigned int i;

	write_lock(&kasumi_rule_prefix_lock);
	for (i = 0; i < ARRAY_SIZE(entry->source_index); i++) {
		if (!hlist_unhashed(&entry->source_index[i].node))
			hlist_del_init_rcu(&entry->source_index[i].node);
	}
	write_unlock(&kasumi_rule_prefix_lock);
}

unsigned long kasumi_rule_source_ino(dev_t dev, u64 ino)
{
	struct kasumi_rule_source_index *index;
	unsigned long result = 0;
	u64 generation;

	rcu_read_lock();
	generation = kasumi_rules_generation();
	hash_for_each_possible_rcu(kasumi_rule_sources, index, node,
				   (unsigned long)dev ^ (unsigned long)ino)
	{
		const struct inode *inode = index->inode;
		const struct kasumi_entry *entry = index->entry;

		if (inode->i_ino != ino ||
		    (inode->i_sb ? inode->i_sb->s_dev : 0) != dev ||
		    !kasumi_rule_visible(&entry->life, generation) ||
		    !kasumi_rule_current_sees(entry->rule_flags))
			continue;
		result = kasumi_identity_ino(index->identity);
		break;
	}
	rcu_read_unlock();
	return result;
}

static struct kasumi_rule_index *kasumi_rule_index_node(struct kasumi_rule_lifetime *life)
{
	if (life->batch_store == KASUMI_BATCH_PATH)
		return &container_of(life, struct kasumi_entry, life)->index;
	if (life->batch_store == KASUMI_BATCH_HIDE)
		return &container_of(life, struct kasumi_hide_entry, life)->index;
	if (life->batch_store == KASUMI_BATCH_MERGE)
		return &container_of(life, struct kasumi_merge_entry, life)->index;
	return NULL;
}

static void kasumi_rule_index_link(struct kasumi_rule_index *index)
{
	struct rb_node **link = &kasumi_rule_prefixes.rb_node, *parent = NULL;

	write_lock(&kasumi_rule_prefix_lock);
	while (*link) {
		struct kasumi_rule_index *other = rb_entry(*link, struct kasumi_rule_index, node);
		int order = strcmp(index->path, other->path);

		parent = *link;
		if (!order)
			order = (unsigned long)index < (unsigned long)other ? -1 : 1;
		link = order < 0 ? &parent->rb_left : &parent->rb_right;
	}
	rb_link_node(&index->node, parent, link);
	rb_insert_color(&index->node, &kasumi_rule_prefixes);
	index->linked = true;
	write_unlock(&kasumi_rule_prefix_lock);
}
void kasumi_rule_index_add(struct kasumi_rule_lifetime *life)
{
	struct kasumi_rule_index *index = kasumi_rule_index_node(life);

	if (!index || index->linked)
		return;
	index->hide = life->batch_store == KASUMI_BATCH_HIDE;
	if (life->batch_store == KASUMI_BATCH_MERGE)
		index->path = container_of(life, struct kasumi_merge_entry, life)->src;
	else
		index->path = index->hide ?
			container_of(life, struct kasumi_hide_entry, life)->path :
			container_of(life, struct kasumi_entry, life)->src;
	index->life = life;
	kasumi_rule_index_link(index);
	if (life->batch_store == KASUMI_BATCH_PATH) {
		struct kasumi_entry *entry =
		    container_of(life, struct kasumi_entry, life);

		if (entry->source_path_valid)
			kasumi_rule_source_add(&entry->source_index[0], entry,
					       &entry->source_path,
					       entry->source_identity);
		if (entry->source_nofollow_path_valid)
			kasumi_rule_source_add(&entry->source_index[1], entry,
					       &entry->source_nofollow_path,
					       entry->nofollow_identity);
	}
	if (life->batch_store == KASUMI_BATCH_MERGE) {
		struct kasumi_merge_entry *merge = container_of(life, struct kasumi_merge_entry, life);

		if (merge->resolved_src && strcmp(merge->resolved_src, merge->src)) {
			merge->alias_index.path = merge->resolved_src;
			merge->alias_index.life = life;
			kasumi_rule_index_link(&merge->alias_index);
		}
	}
}

static void kasumi_rule_index_unlink(struct kasumi_rule_index *index)
{
	if (!index || !index->linked)
		return;
	write_lock(&kasumi_rule_prefix_lock);
	rb_erase(&index->node, &kasumi_rule_prefixes);
	index->linked = false;
	write_unlock(&kasumi_rule_prefix_lock);
}

void kasumi_rule_index_remove(struct kasumi_rule_lifetime *life)
{
	if (life->batch_store == KASUMI_BATCH_PATH)
		kasumi_rule_source_remove(
		    container_of(life, struct kasumi_entry, life));
	kasumi_rule_index_unlink(kasumi_rule_index_node(life));
	if (life->batch_store == KASUMI_BATCH_MERGE)
		kasumi_rule_index_unlink(&container_of(life, struct kasumi_merge_entry, life)->alias_index);
}

/* Callers retain RCU and the index read lock while traversing. Equal names
 * retain every transaction version until the previous readers have drained. */
static struct kasumi_rule_index *kasumi_rule_prefix_first(const char *path, size_t length)
{
	struct rb_node *node = kasumi_rule_prefixes.rb_node;
	struct kasumi_rule_index *first = NULL;

	while (node) {
		struct kasumi_rule_index *index = rb_entry(node, struct kasumi_rule_index, node);
		int order = strncmp(index->path, path, length);

		if (!order && length != 1)
			order = (unsigned char)index->path[length] - '/';
		if (order < 0) {
			node = node->rb_right;
		} else {
			first = index;
			node = node->rb_left;
		}
	}
	return first;
}

static struct kasumi_rule_index *kasumi_rule_prefix_next(struct kasumi_rule_index *index)
{
	struct rb_node *node = rb_next(&index->node);

	return node ? rb_entry(node, struct kasumi_rule_index, node) : NULL;
}

static struct kasumi_rule_index *kasumi_rule_exact_first(const char *path, size_t length)
{
	struct rb_node *node = kasumi_rule_prefixes.rb_node;
	struct kasumi_rule_index *first = NULL;

	while (node) {
		struct kasumi_rule_index *index = rb_entry(node, struct kasumi_rule_index, node);

		if (strncmp(index->path, path, length) < 0) {
			node = node->rb_right;
		} else {
			first = index;
			node = node->rb_left;
		}
	}
	return first;
}

static bool kasumi_rule_prefix_matches(struct kasumi_rule_index *index,
				       const char *path, size_t length)
{
	return index && !strncmp(index->path, path, length) &&
		(!index->path[length] || length == 1 || index->path[length] == '/');
}

void kasumi_rule_dependencies(const char *path, u64 generation,
	void (*visit)(struct kasumi_rule_lifetime *, void *), void *data)
{
	struct kasumi_rule_index *index;
	size_t length, prefix;

	if (!path || path[0] != '/')
		return;
	length = strlen(path);
	rcu_read_lock();
	read_lock(&kasumi_rule_prefix_lock);
	for (prefix = 1; prefix <= length; prefix++) {
		if (prefix != 1 && prefix != length && path[prefix] != '/')
			continue;
		index = kasumi_rule_exact_first(path, prefix);
		while (index && !strncmp(index->path, path, prefix) && !index->path[prefix]) {
			if (kasumi_rule_visible(index->life, generation))
				visit(index->life, data);
			index = kasumi_rule_prefix_next(index);
		}
	}
	for (index = kasumi_rule_prefix_first(path, length);
	     kasumi_rule_prefix_matches(index, path, length);
	     index = kasumi_rule_prefix_next(index)) {
		if (kasumi_rule_visible(index->life, generation))
			visit(index->life, data);
	}
	read_unlock(&kasumi_rule_prefix_lock);
	rcu_read_unlock();
}

int kasumi_rule_vpath_collect(struct file *file, struct list_head *out,
			      u64 *generation, void *data)
{
	const char *dir = data;
	struct kasumi_entry *rule;
	struct kasumi_hide_entry *hide;
	struct kasumi_rule_index *index;
	struct kasumi_dir_entry *item;
	DECLARE_HASHTABLE(children, 6);
	size_t dir_len;
	int error = 0;

	(void)file;
	if (!dir)
		return -EINVAL;
	dir_len = strlen(dir);
	hash_init(children);
	rcu_read_lock();
	*generation = kasumi_rules_generation();
	read_lock(&kasumi_rule_prefix_lock);
	for (index = kasumi_rule_prefix_first(dir, dir_len);
	     kasumi_rule_prefix_matches(index, dir, dir_len);
	     index = kasumi_rule_prefix_next(index)) {
		const char *name, *slash;
		struct kasumi_dir_entry *existing;
		size_t name_len, prefix_len;
		u64 ino;
		u32 hash;
		u8 type;
		bool leaf;
		struct kasumi_inode_identity *identity = NULL;

		if (index->life->batch_store != KASUMI_BATCH_PATH)
			continue;
		rule = container_of(index, struct kasumi_entry, index);
		if (!kasumi_rule_visible(&rule->life, *generation) ||
		    strncmp(rule->src, dir, dir_len))
			continue;
		prefix_len = dir_len;
		if (dir_len != 1 || dir[0] != '/') {
			if (rule->src[prefix_len] != '/')
				continue;
			prefix_len++;
		}
		name = rule->src + prefix_len;
		if (!*name)
			continue;
		slash = strchr(name, '/');
		name_len = slash ? slash - name : strlen(name);
		leaf = slash == NULL;
		if (leaf) {
			umode_t mode = rule->source_nofollow_path_valid ?
				rule->source_nofollow_mode : rule->source_mode;

			identity = rule->source_nofollow_path_valid ?
				rule->nofollow_identity : rule->source_identity;
			ino = rule->source_nofollow_path_valid ?
				rule->nofollow_visible_ino : rule->visible_ino;
			type = (mode & S_IFMT) >> 12;
		} else {
			ino = 0;
			type = DT_DIR;
		}
		hash = full_name_hash(NULL, name, name_len);
		item = NULL;
		hash_for_each_possible(children, existing, name_node, hash) {
			if (existing->name_len == name_len &&
			    !memcmp(existing->name, name, name_len)) {
				item = existing;
				break;
			}
		}
		if (!item) {
			item = kasumi_dir_entry_alloc(name, name_len, GFP_ATOMIC);
			if (!item) {
				error = -ENOMEM;
				goto out;
			}
			item->redirect = true;
			list_add_tail(&item->list, out);
			hash_add(children, &item->name_node, hash);
		}
		if ((!item->direct_rule && leaf) ||
		    (item->direct_rule == leaf && rule->sequence >= item->sequence)) {
			kasumi_identity_put(item->identity);
			item->identity = identity;
			kasumi_identity_get(identity);
			item->ino = ino;
			item->type = type;
			item->direct_rule = leaf;
			item->sequence = rule->sequence;
			item->rule_flags = leaf ? rule->rule_flags : 0;
		}
		if ((rule->rule_flags & KSM_RULE_BYPASS_POLICY) &&
		    (!item->bypass_redirect || (!item->bypass_direct_rule && leaf) ||
		     (item->bypass_direct_rule == leaf &&
		      rule->sequence >= item->bypass_sequence))) {
			kasumi_identity_put(item->bypass_identity);
			item->bypass_identity = identity;
			kasumi_identity_get(identity);
			item->bypass_redirect = true;
			item->bypass_direct_rule = leaf;
			item->bypass_sequence = rule->sequence;
			item->bypass_ino = ino;
			item->bypass_type = type;
		}
	}
	for (index = kasumi_rule_prefix_first(dir, dir_len);
	     kasumi_rule_prefix_matches(index, dir, dir_len);
	     index = kasumi_rule_prefix_next(index)) {
		const char *name;
		struct kasumi_dir_entry *existing;
		size_t prefix_len = dir_len, name_len;
		u32 hash;

		if (!index->hide)
			continue;
		hide = container_of(index, struct kasumi_hide_entry, index);
		if (!kasumi_rule_visible(&hide->life, *generation) ||
		    strncmp(hide->path, dir, dir_len))
			continue;
		if (dir_len != 1 || dir[0] != '/') {
			if (hide->path[prefix_len] != '/')
				continue;
			prefix_len++;
		}
		name = hide->path + prefix_len;
		name_len = strlen(name);
		if (!name_len || strchr(name, '/'))
			continue;
		hash = full_name_hash(NULL, name, name_len);
		item = NULL;
		hash_for_each_possible(children, existing, name_node, hash) {
			if (existing->name_len == name_len &&
			    !memcmp(existing->name, name, name_len)) {
				item = existing;
				break;
			}
		}
		if (!item) {
			item = kasumi_dir_entry_alloc(name, name_len, GFP_ATOMIC);
			if (!item) {
				error = -ENOMEM;
				goto out;
			}
			list_add_tail(&item->list, out);
			hash_add(children, &item->name_node, hash);
		}
		if (!item->hide || hide->sequence >= item->hide_sequence) {
			item->hide = true;
			item->hide_sequence = hide->sequence;
			item->hide_flags = hide->rule_flags;
			item->hide_storage_managed = hide->storage_managed;
		}
	}
	out:
	read_unlock(&kasumi_rule_prefix_lock);
	rcu_read_unlock();
	list_for_each_entry(item, out, list) {
		struct kasumi_inode_identity *identity;
		char *path;

		hash_del(&item->name_node);
		if (error || (!item->redirect && !item->bypass_redirect) ||
		    (item->direct_rule &&
		    (!item->bypass_redirect || item->bypass_direct_rule)))
			continue;
		path = kasprintf(GFP_KERNEL, "%s%s%s", dir,
			strcmp(dir, "/") ? "/" : "", item->name);
		if (!path) {
			error = -ENOMEM;
			continue;
		}
		error = kasumi_identity_path_get(path, &identity);
		kfree(path);
		if (error)
			continue;
		if (!item->direct_rule) {
			item->identity = identity;
			kasumi_identity_get(identity);
			item->ino = kasumi_identity_ino(identity);
		}
		if (item->bypass_redirect && !item->bypass_direct_rule) {
			item->bypass_identity = identity;
			kasumi_identity_get(identity);
			item->bypass_ino = kasumi_identity_ino(identity);
		}
		kasumi_identity_put(identity);
	}
	return error;
}

bool kasumi_rule_directory_overridden(const char *path, u64 generation)
{
	struct kasumi_rule_index *index;
	size_t length, prefix;
	bool found = false;

	if (!path || path[0] != '/')
		return true;
	length = strlen(path);
	rcu_read_lock();
	read_lock(&kasumi_rule_prefix_lock);
	for (index = kasumi_rule_prefix_first(path, length);
	     kasumi_rule_prefix_matches(index, path, length);
	     index = kasumi_rule_prefix_next(index)) {
		if (kasumi_rule_visible(index->life, generation)) {
			found = true;
			break;
		}
	}
	for (prefix = 1; !found && prefix <= length; prefix++) {
		if (prefix != 1 && prefix != length && path[prefix] != '/')
			continue;
		for (index = kasumi_rule_exact_first(path, prefix);
		     index && !strncmp(index->path, path, prefix) && !index->path[prefix];
		     index = kasumi_rule_prefix_next(index)) {
			if (index->life->batch_store == KASUMI_BATCH_MERGE &&
			    kasumi_rule_visible(index->life, generation)) {
				found = true;
				break;
			}
		}
	}
	read_unlock(&kasumi_rule_prefix_lock);
	rcu_read_unlock();
	return found;
}

bool kasumi_rule_directory_has_injects(const char *path, u64 generation)
{
	struct kasumi_rule_index *index;
	size_t length = strlen(path);
	bool found = false;

	rcu_read_lock();
	read_lock(&kasumi_rule_prefix_lock);
	for (index = kasumi_rule_prefix_first(path, length);
	     kasumi_rule_prefix_matches(index, path, length);
	     index = kasumi_rule_prefix_next(index)) {
		const char *child = index->path + length + (length != 1);

		if (index->life->batch_store == KASUMI_BATCH_PATH &&
		    kasumi_rule_visible(index->life, generation) &&
		    *child && !strchr(child, '/')) {
			found = true;
			break;
		}
	}
	for (index = kasumi_rule_exact_first(path, length);
	     !found && index && !strcmp(index->path, path);
	     index = kasumi_rule_prefix_next(index)) {
		if (index->life->batch_store == KASUMI_BATCH_MERGE &&
		    kasumi_rule_visible(index->life, generation))
			found = true;
	}
	read_unlock(&kasumi_rule_prefix_lock);
	rcu_read_unlock();
	return found;
}

bool kasumi_rule_vpath_flags(const char *path, u64 generation, u32 *flags)
{
	struct kasumi_entry *entry;
	struct kasumi_rule_index *index;
	size_t len = strlen(path);
	bool found = false;

	*flags = 0;
	read_lock(&kasumi_rule_prefix_lock);
	for (index = kasumi_rule_prefix_first(path, len);
	     kasumi_rule_prefix_matches(index, path, len);
	     index = kasumi_rule_prefix_next(index)) {
		if (index->life->batch_store != KASUMI_BATCH_PATH)
			continue;
		entry = container_of(index, struct kasumi_entry, index);
		if (!kasumi_rule_visible(&entry->life, generation) ||
		    strncmp(entry->src, path, len) || entry->src[len] != '/')
			continue;
		*flags |= entry->rule_flags & KSM_RULE_BYPASS_POLICY;
		found = true;
	}
	read_unlock(&kasumi_rule_prefix_lock);
	return found;
}

/* A projected parent is enforced by vnode lookup and iteration. Installing its
 * hide on the source directory would affect unrelated aliases.
 */
struct kasumi_projected_parent_selection {
	const char *parent;
	size_t length;
	struct kasumi_entry *best;
	size_t best_length;
	bool virtual_prefix;
};

static void kasumi_projected_parent_visit(struct kasumi_rule_lifetime *life, void *data)
{
	struct kasumi_projected_parent_selection *selection = data;
	struct kasumi_entry *entry;
	size_t rule_length;

	if (life->batch_store != KASUMI_BATCH_PATH)
		return;
	entry = container_of(life, struct kasumi_entry, life);
	rule_length = strlen(entry->src);
	if (rule_length > selection->length &&
	    !strncmp(entry->src, selection->parent, selection->length) &&
	    (selection->length == 1 || entry->src[selection->length] == '/'))
		selection->virtual_prefix = true;
	if (rule_length > selection->length ||
	    strncmp(entry->src, selection->parent, rule_length) ||
	    (rule_length != 1 && rule_length != selection->length &&
	     selection->parent[rule_length] != '/'))
		return;
	if (!selection->best || rule_length > selection->best_length ||
	    (rule_length == selection->best_length && entry->sequence > selection->best->sequence)) {
		selection->best = entry;
		selection->best_length = rule_length;
	}
}

int KASUMI_NOCFI kasumi_rule_projected_parent(const char *visible, u64 generation,
					    struct path *source_parent)
{
	struct kasumi_internal_vfs_guard guard;
	struct kasumi_entry *best;
	struct kasumi_projected_parent_selection selection = {};
	struct path directory = {}, resolved = {};
	char *parent, *slash;
	size_t length, best_length = 0;
	bool virtual_prefix = false;
	int ret = 0;

	memset(source_parent, 0, sizeof(*source_parent));
	if (!visible || visible[0] != '/')
		return -EINVAL;
	parent = kstrdup(visible, GFP_KERNEL);
	if (!parent)
		return -ENOMEM;
	slash = strrchr(parent, '/');
	if (!slash[1]) {
		ret = -EINVAL;
		goto out;
	}
	if (slash == parent)
		slash[1] = '\0';
	else
		*slash = '\0';
	length = strlen(parent);
	rcu_read_lock();
	selection.parent = parent;
	selection.length = length;
	kasumi_rule_dependencies(parent, generation, kasumi_projected_parent_visit, &selection);
	best = selection.best;
	best_length = selection.best_length;
	virtual_prefix = selection.virtual_prefix;
	if (best) {
		if (!best->source_path_valid || !S_ISDIR(best->source_mode)) {
			ret = -ENOTDIR;
		} else {
			directory = best->source_path;
			kasumi_path_get(&directory);
		}
	}
	rcu_read_unlock();
	if (ret)
		goto out;
	if (directory.dentry && best_length == length) {
		*source_parent = directory;
		ret = 1;
		goto out;
	}
	if (!directory.dentry && !virtual_prefix)
		goto out;
	kasumi_vfs_internal_enter(&guard);
	if (directory.dentry) {
		const char *relative = parent + best_length;

		if (*relative == '/')
			relative++;
		ret = kasumi_vfs_path_lookup ?
			kasumi_vfs_path_lookup(directory.dentry, directory.mnt,
				relative, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &resolved) :
			-EOPNOTSUPP;
		kasumi_path_put(&directory);
		if (!ret) {
			*source_parent = resolved;
			ret = 1;
		} else if (ret == -ENOENT && virtual_prefix) {
			ret = 1;
		}
	} else {
		ret = kasumi_kern_path ?
			kasumi_kern_path(parent, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
					 &resolved) : -EOPNOTSUPP;
		if (!ret)
			kasumi_path_put(&resolved);
		else if (ret == -ENOENT)
			ret = 1;
	}
	kasumi_vfs_internal_leave(&guard);
out:
	kfree(parent);
	return ret;
}

bool kasumi_rule_vpath_visible(const char *path)
{
	u32 flags;
	bool visible;

	if (!path || !kasumi_rule_scope_active())
		return false;
	if (kasumi_policy_current_is_view_target())
		return true;
	rcu_read_lock();
	visible = kasumi_rule_vpath_flags(path, kasumi_rules_generation(), &flags) &&
		  (flags & KSM_RULE_BYPASS_POLICY);
	rcu_read_unlock();
	return visible;
}

static int KASUMI_NOCFI kasumi_rule_vpath_child_exact(const char *dir, const char *child,
					 struct path *leaf_src, umode_t *leaf_mode,
					 unsigned long *leaf_ino,
					 struct kasumi_inode_identity **identity)
{
	u64 generation, sequence = 0;
	struct kasumi_hide_entry *hide;
	struct kasumi_entry *entry;
	char *full;
	size_t dlen, clen, full_len;
	int kind = KASUMI_VPATH_NONE;
	int bkt;

	if (!dir || !child || !*child)
		return KASUMI_VPATH_NONE;
	dlen = strlen(dir);
	clen = strlen(child);
	full = kmalloc(dlen + 1 + clen + 1, GFP_KERNEL);
	if (!full)
		return -ENOMEM;
	memcpy(full, dir, dlen);
	full[dlen] = '/';
	memcpy(full + dlen + 1, child, clen);
	full[dlen + 1 + clen] = '\0';
	full_len = dlen + 1 + clen;

	rcu_read_lock();
	generation = kasumi_rules_generation();
	/* Exact rule at dir/child -> a leaf redirect. */
	hash_for_each_rcu(kasumi_paths, bkt, entry, node) {
		if (!kasumi_rule_visible(&entry->life, generation))
			continue;
		if (!entry->src || strcmp(entry->src, full))
			continue;
		sequence = entry->sequence;
		if (!kasumi_rule_current_sees(entry->rule_flags) ||
		    (!entry->source_path_valid && !entry->source_nofollow_path_valid))
			continue;
		if (entry->source_nofollow_path_valid) {
			if (identity) {
				*identity = entry->nofollow_identity;
				kasumi_identity_get(*identity);
			}
			if (leaf_src) {
				*leaf_src = entry->source_nofollow_path;
				kasumi_path_get(leaf_src);
			}
			if (leaf_mode)
				*leaf_mode = entry->source_nofollow_mode;
			if (leaf_ino)
				*leaf_ino = entry->nofollow_visible_ino;
		} else {
			if (identity) {
				*identity = entry->source_identity;
				kasumi_identity_get(*identity);
			}
			if (leaf_src) {
				*leaf_src = entry->source_path;
				kasumi_path_get(leaf_src);
			}
			if (leaf_mode)
				*leaf_mode = entry->source_mode;
			if (leaf_ino)
				*leaf_ino = entry->visible_ino;
		}
		kind = KASUMI_VPATH_LEAF;
		break;
	}
	hash_for_each_rcu(kasumi_hide_paths, bkt, hide, node) {
		if (kasumi_rule_visible(&hide->life, generation) &&
		    hide->sequence >= sequence && !strcmp(hide->path, full) &&
		    kasumi_hide_scope_allowed(hide->storage_managed, hide->rule_flags)) {
			kind = KASUMI_VPATH_HIDDEN;
			break;
		}
	}
	/* Otherwise, a prefix of some rule -> a deeper virtual directory. */
	if (kind == KASUMI_VPATH_NONE) {
		hash_for_each_rcu(kasumi_paths, bkt, entry, node) {
			if (!kasumi_rule_visible(&entry->life, generation))
				continue;
			if (!kasumi_rule_current_sees(entry->rule_flags))
				continue;
			if (!entry->src)
				continue;
			if (strncmp(entry->src, full, full_len) == 0 &&
			    entry->src[full_len] == '/') {
				kind = KASUMI_VPATH_VDIR;
				break;
			}
		}
	}
	rcu_read_unlock();
	if (kind == KASUMI_VPATH_HIDDEN) {
		if (leaf_src && leaf_src->dentry) {
			kasumi_path_put(leaf_src);
			memset(leaf_src, 0, sizeof(*leaf_src));
		}
		if (identity) {
			kasumi_identity_put(*identity);
			*identity = NULL;
		}
	}
	kfree(full);
	return kind;
}

int kasumi_rule_vpath_child(const char *dir, const char *child,
	struct path *leaf_src, umode_t *leaf_mode, unsigned long *leaf_ino,
	struct kasumi_inode_identity **identity, struct dentry *parent)
{
	LIST_HEAD(entries);
	struct kasumi_dir_entry *entry, *best, *hidden;
	u64 generation;
	u64 best_sequence, exact_sequence;
	u32 query_hash;
	bool view, best_direct;
	int kind;

	if (!parent || !(READ_ONCE(parent->d_flags) & DCACHE_OP_COMPARE))
		return kasumi_rule_vpath_child_exact(dir, child, leaf_src,
			leaf_mode, leaf_ino, identity);
	if (!kasumi_rule_scope_active())
		return KASUMI_VPATH_NONE;
retry:
	view = kasumi_policy_current_is_view_target();
	best = NULL;
	hidden = NULL;
	exact_sequence = 0;
	best_direct = false;
	best_sequence = 0;
	kind = kasumi_dir_name_hash(parent, child, strlen(child), &query_hash);
	if (kind)
		return kind;
	kind = kasumi_rule_vpath_collect(NULL, &entries, &generation, (void *)dir);
	if (kind)
		goto out;
	kind = KASUMI_VPATH_NONE;
	list_for_each_entry(entry, &entries, list) {
		struct dentry *candidate;
		u64 sequence = view ? entry->sequence : entry->bypass_sequence;
		u32 hash;
		bool direct = view ? entry->direct_rule : entry->bypass_direct_rule;
		bool equal;

		kind = kasumi_dir_name_hash(parent, entry->name, entry->name_len, &hash);
		if (kind)
			goto out;
		if (hash != query_hash)
			continue;
		candidate = kasumi_dir_name_probe(parent, entry->name, entry->name_len);
		if (IS_ERR(candidate)) {
			kind = PTR_ERR(candidate);
			goto out;
		}
		equal = kasumi_dir_name_equal(parent, candidate, entry->name,
			entry->name_len, child, strlen(child));
		dput(candidate);
		if (!equal)
			continue;
		if (entry->direct_rule && entry->sequence > exact_sequence)
			exact_sequence = entry->sequence;
		if (entry->hide && (!hidden || entry->hide_sequence >= hidden->hide_sequence))
			hidden = entry;
		if (!entry->redirect || (!kasumi_rule_current_sees(entry->rule_flags) &&
		    !entry->bypass_redirect))
			continue;
		if (!best || (!best_direct && direct) ||
		    (best_direct == direct && sequence >= best_sequence)) {
			best = entry;
			best_direct = direct;
			best_sequence = sequence;
		}
	}
	if (hidden && hidden->hide_sequence >= exact_sequence &&
	    kasumi_hide_scope_allowed(hidden->hide_storage_managed, hidden->hide_flags))
		kind = KASUMI_VPATH_HIDDEN;
	else
		kind = best ? kasumi_rule_vpath_child_exact(dir, best->name, leaf_src,
			leaf_mode, leaf_ino, identity) : KASUMI_VPATH_NONE;
	if (generation != kasumi_rules_generation()) {
		if (leaf_src && leaf_src->dentry) {
			kasumi_path_put(leaf_src);
			memset(leaf_src, 0, sizeof(*leaf_src));
		}
		if (identity) {
			kasumi_identity_put(*identity);
			*identity = NULL;
		}
		kasumi_dir_entries_free(&entries);
		cond_resched();
		goto retry;
	}
out:
	kasumi_dir_entries_free(&entries);
	return kind;
}


bool kasumi_rule_get_visible_path(const struct path *source,
				  char *visible_path,
				  size_t visible_path_size)
{
	u64 generation;
	struct kasumi_entry *best = NULL;
	struct kasumi_entry *entry;
	unsigned int best_depth = UINT_MAX;
	int bkt;
	bool found = false;

	if (!source || !source->dentry || !source->mnt || !visible_path ||
	    !visible_path_size || !kasumi_config_enabled() ||
	    atomic_read(&kasumi_rule_count) == 0 || !kasumi_rule_scope_active())
		return false;

	rcu_read_lock();
	generation = kasumi_rules_generation();
	hash_for_each_rcu(kasumi_paths, bkt, entry, node) {
		int depth;

		if (!kasumi_rule_visible(&entry->life, generation))
			continue;
		if (!kasumi_rule_current_sees(entry->rule_flags))
			continue;
		if (!entry->source_path_valid || !S_ISDIR(entry->source_mode))
			continue;
		depth = kasumi_source_path_depth(source, &entry->source_path);
		if (depth < 0 || (unsigned int)depth >= best_depth)
			continue;
		best = entry;
		best_depth = (unsigned int)depth;
		if (!best_depth)
			break;
	}
	if (best)
		found = kasumi_compose_visible_path(best, source, visible_path,
						    visible_path_size);
	rcu_read_unlock();
	return found || kasumi_rule_get_visible_path_canonical(
				source, visible_path, visible_path_size);
}

static bool kasumi_visible_rule_prefix(const char *pathname, size_t length,
				       bool directory_only)
{
	u64 generation;
	struct kasumi_entry *entry;
	u32 hash;
	bool found = false;

	if (!test_bit(jhash(pathname, (u32)length, 0) &
		      (KASUMI_BLOOM_SIZE - 1), kasumi_path_bloom) ||
	    !test_bit(jhash(pathname, (u32)length, 1) &
		      (KASUMI_BLOOM_SIZE - 1), kasumi_path_bloom))
		return false;
	hash = full_name_hash(NULL, pathname, length);
	rcu_read_lock();
	generation = kasumi_rules_generation();
	hlist_for_each_entry_rcu(entry,
		&kasumi_paths[hash_min(hash, KASUMI_HASH_BITS)], node) {
		if (!kasumi_rule_visible(&entry->life, generation))
			continue;
		if (!kasumi_rule_current_sees(entry->rule_flags) ||
		    entry->src_hash != hash || strlen(entry->src) != length ||
		    memcmp(entry->src, pathname, length) != 0 ||
		    !entry->source_path_valid ||
		    (directory_only && !S_ISDIR(entry->source_mode)))
			continue;
		found = true;
		break;
	}
	rcu_read_unlock();
	return found;
}

bool kasumi_rule_path_is_virtual(const char *pathname)
{
	size_t prefix_len;
	size_t path_len;
	bool exact = true;

	if (!pathname || pathname[0] != '/' || !kasumi_config_enabled() ||
	    atomic_read(&kasumi_rule_count) == 0 || !kasumi_rule_scope_active())
		return false;
	path_len = strlen(pathname);
	if (!path_len)
		return false;
	prefix_len = path_len;
	for (;;) {
		size_t slash;

		if (kasumi_visible_rule_prefix(pathname, prefix_len, !exact))
			return true;
		if (prefix_len <= 1)
			break;
		slash = prefix_len;
		while (slash > 0 && pathname[slash - 1] != '/')
			slash--;
		prefix_len = slash <= 1 ? 1 : slash - 1;
		exact = false;
	}
	return false;
}

KASUMI_NOCFI char *kasumi_resolve_target_slow(const char *pathname)
{
	u64 generation;
	struct kasumi_merge_entry *me;
	char *src = NULL;
	char *target_dir = NULL;
	char *target = NULL;
	size_t path_len;
	int bkt;
	pid_t pid;

	target = kasumi_resolve_target(pathname);
	if (target)
		return target;

	if (unlikely(!kasumi_config_enabled() || !pathname || !*pathname ||
		     !kasumi_rule_scope_active()))
		return NULL;
	pid = task_tgid_vnr(current);
	if (READ_ONCE(kasumi_daemon_pid) > 0 && pid == READ_ONCE(kasumi_daemon_pid))
		return NULL;
	if (!kasumi_kern_path)
		return NULL;

	path_len = strlen(pathname);
	rcu_read_lock();
	generation = kasumi_rules_generation();
	hash_for_each_rcu(kasumi_merge_dirs, bkt, me, node) {
		size_t src_len;

		if (!kasumi_rule_visible(&me->life, generation))
			continue;
		if (!kasumi_rule_current_sees(me->rule_flags) || !me->src ||
		    !me->target)
			continue;
		src_len = strlen(me->src);
		if (path_len <= src_len || pathname[src_len] != '/')
			continue;
		if (strncmp(pathname, me->src, src_len) != 0)
			continue;
		src = kstrdup(me->src, GFP_ATOMIC);
		target_dir = kstrdup(me->target, GFP_ATOMIC);
		break;
	}
	rcu_read_unlock();

	if (src && target_dir) {
		struct path p;
		const char *suffix = pathname + strlen(src);

		target = kasprintf(GFP_KERNEL, "%s%s", target_dir, suffix);
		if (target && kasumi_kern_path(target, LOOKUP_FOLLOW, &p) == 0) {
			if (p.dentry && d_inode(p.dentry) &&
			    S_ISDIR(d_inode(p.dentry)->i_mode)) {
				kasumi_path_put(&p);
				kfree(target);
				target = NULL;
			} else {
				kasumi_path_put(&p);
			}
		} else {
			kfree(target);
			target = NULL;
		}
	}
	kfree(src);
	kfree(target_dir);
	return target;
}

struct kasumi_entry *kasumi_reverse_lookup_target(const char *path_str)
{
	u64 generation = kasumi_rules_generation();
	struct kasumi_entry *entry;
	u32 hash;

	if (!path_str || !*path_str)
		return NULL;

	hash = full_name_hash(NULL, path_str, strlen(path_str));
	hlist_for_each_entry_rcu(entry,
		&kasumi_targets[hash_min(hash, KASUMI_HASH_BITS)], target_node) {
		if (!kasumi_rule_visible(&entry->life, generation))
			continue;
		if (strcmp(entry->target, path_str) == 0)
			return entry;
	}
	return NULL;
}

/* ======================================================================
 * Part 14: Hide Logic
 * ====================================================================== */

static bool kasumi_hide_rule_matches(const char *pathname)
{
	u64 generation;
	struct kasumi_hide_entry *he;
	u32 hash;
	size_t len;

	if (!pathname || !*pathname)
		return false;
	if (atomic_read(&kasumi_hide_count) == 0)
		return false;

	len = strlen(pathname);
	{
		unsigned long bh1 = jhash(pathname, (u32)len, 0) & (KASUMI_BLOOM_SIZE - 1);
		unsigned long bh2 = jhash(pathname, (u32)len, 1) & (KASUMI_BLOOM_SIZE - 1);

		if (!test_bit(bh1, kasumi_hide_bloom) || !test_bit(bh2, kasumi_hide_bloom))
			return false;
	}

	hash = full_name_hash(NULL, pathname, len);
	rcu_read_lock();
	generation = kasumi_rules_generation();
	hlist_for_each_entry_rcu(he,
		&kasumi_hide_paths[hash_min(hash, KASUMI_HASH_BITS)], node) {
		if (!kasumi_rule_visible(&he->life, generation))
			continue;
		if (he->path_hash == hash && strcmp(he->path, pathname) == 0) {
			bool hidden = kasumi_hide_scope_allowed(
			    READ_ONCE(he->storage_managed),
			    READ_ONCE(he->rule_flags));

			rcu_read_unlock();
			return hidden;
		}
	}
	rcu_read_unlock();
	return false;
}

int kasumi_rule_child_mutation(struct inode *parent, const char *visible_path,
			       const struct qstr *name)
{
	const struct kasumi_vnode_info *info =
		kasumi_vnode_is_ours(parent) ? parent->i_private : NULL;
	char *child;
	u64 generation;
	int kind, ret;

	if (!name || !name->len || name->len > NAME_MAX)
		return -EINVAL;
	child = kstrndup(name->name, name->len, GFP_KERNEL);
	if (!child)
		return -ENOMEM;
	do {
		generation = kasumi_rules_generation();
		ret = 0;
		if (kasumi_dirhijack_hidden(parent, child, name->len)) {
			ret = -ENOENT;
		} else {
			kind = kasumi_dirhijack_child_visible(parent, child, name->len);
			if (kind > 0)
				ret = -EXDEV;
			else if (kind < 0 && visible_path) {
				kind = kasumi_rule_vpath_child(visible_path, child,
					NULL, NULL, NULL, NULL,
					info ? info->source.dentry : NULL);
				ret = kind < 0 ? kind : kind != KASUMI_VPATH_NONE ?
					-EXDEV : 0;
			}
		}
	} while (generation != kasumi_rules_generation());
	kfree(child);
	return ret;
}

bool kasumi_should_hide(const char *pathname)
{
	if (!kasumi_rule_scope_active())
		return false;
	return kasumi_hide_rule_matches(pathname);
}

static bool __maybe_unused kasumi_should_replace(const char *pathname)
{
	u64 generation;
	struct kasumi_entry *entry;
	u32 hash;
	size_t path_len;
	pid_t pid;

	if (unlikely(!kasumi_config_enabled() || !pathname))
		return false;

	pid = task_tgid_vnr(current);
	if (READ_ONCE(kasumi_daemon_pid) > 0 && pid == READ_ONCE(kasumi_daemon_pid))
		return false;
	if (atomic_read(&kasumi_rule_count) == 0)
		return false;

	path_len = strlen(pathname);
	{
		unsigned long bh1 = jhash(pathname, (u32)path_len, 0) & (KASUMI_BLOOM_SIZE - 1);
		unsigned long bh2 = jhash(pathname, (u32)path_len, 1) & (KASUMI_BLOOM_SIZE - 1);

		if (!test_bit(bh1, kasumi_path_bloom) || !test_bit(bh2, kasumi_path_bloom))
			return false;
	}

	hash = full_name_hash(NULL, pathname, path_len);
	rcu_read_lock();
	generation = kasumi_rules_generation();
	hlist_for_each_entry_rcu(entry,
		&kasumi_paths[hash_min(hash, KASUMI_HASH_BITS)], node) {
		if (!kasumi_rule_visible(&entry->life, generation))
			continue;
		if (entry->src_hash == hash && strcmp(entry->src, pathname) == 0) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();
	return false;
}
