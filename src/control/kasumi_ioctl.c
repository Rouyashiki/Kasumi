/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - userspace control plane, ioctl dispatch, and daemon-facing anon-fd setup.
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
#include <linux/kdev_t.h>
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
#include <uapi/linux/magic.h>
#ifndef EROFS_SUPER_MAGIC
#define EROFS_SUPER_MAGIC 0xe0f5e1e2
#endif
#include <asm/unistd.h>
#include "kasumi_runtime.h"
#include "kasumi_dirhijack.h"
#include "kasumi_hide_rules.h"
#include "kasumi_vnode.h"
#include "kasumi_bootstrap.h"
#include "kasumi_conflict.h"
#include "kasumi_instance.h"
#include "kasumi_store.h"
#include "kasumi_batch.h"
#include "kasumi_transaction.h"
#include "kasumi_vfs_view.h"
#include "kasumi_exec_view.h"
#include "kasumi_notify_view.h"
#include "kasumi_io_notify.h"
#include "kasumi_file_lock.h"
#include "kasumi_rename_view.h"
#include "kasumi_live_rules.h"
#include "kasumi_maps_rules.h"
#include "kasumi_entrypoints.h"
#include "kasumi_path_policy.h"
#include "kasumi_overlay.h"
#include "kasumi_proc_hooks.h"
#include "kasumi_vfs_hooks.h"
#include "kasumi_fop_bridge.h"
#include "kasumi_iop_override.h"
#include "kasumi_fop_override.h"
#include "kasumi_sop_shadow.h"
#include "kasumi_fake_mountinfo.h"
#include "kasumi_mount_view.h"
#include "kasumi_proc_seq.h"
#include "kasumi_fake_selinuxfs_access.h"
/* ======================================================================
 * Part 15: Dispatch Handler (ioctl only; all commands use KSM_IOC_* from kasumi_uapi.h)
 * GET_FD is delivered by reboot task_work -> kasumi_install_anon_fd()
 * ====================================================================== */

static bool kasumi_policy_header_valid(u32 version, u32 size, size_t min_size)
{
	return version == KSM_POLICY_API_VERSION && size >= min_size;
}

static bool kasumi_u32_reserved_zero(const u32 *reserved, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		if (reserved[i])
			return false;
	return true;
}

static int kasumi_ioctl_set_policy(void __user *arg)
{
	struct kasumi_policy_config_arg a;
	int ret;

	if (copy_from_user(&a, arg, sizeof(a)))
		return -EFAULT;
	if (!kasumi_policy_header_valid(a.version, a.size, sizeof(a)) ||
	    !kasumi_u32_reserved_zero(a.reserved, ARRAY_SIZE(a.reserved)))
		ret = -EINVAL;
	else
		ret = kasumi_set_policy_owner(a.owner, a.flags);
	a.err = ret;
	if (copy_to_user(arg, &a, sizeof(a)))
		return -EFAULT;
	return ret;
}

static int kasumi_ioctl_get_policy(void __user *arg)
{
	struct kasumi_policy_state_arg input;
	struct kasumi_policy_state_arg a = { };
	int ret = 0;

	if (copy_from_user(&input, arg, sizeof(input)))
		return -EFAULT;
	if (!kasumi_policy_header_valid(input.version, input.size,
					sizeof(input)) ||
	    input.enabled ||
	    !kasumi_u32_reserved_zero(input.reserved,
				      ARRAY_SIZE(input.reserved)))
		ret = -EINVAL;
	else
		kasumi_policy_get_state(&a);
	a.version = KSM_POLICY_API_VERSION;
	a.size = sizeof(a);
	a.err = ret;
	if (copy_to_user(arg, &a, sizeof(a)))
		return -EFAULT;
	return ret;
}

static int kasumi_ioctl_set_policy_uids(void __user *arg)
{
	struct kasumi_policy_uid_list_arg a;
	u32 *uids = NULL;
	int ret;

	if (copy_from_user(&a, arg, sizeof(a)))
		return -EFAULT;
	if (!kasumi_policy_header_valid(a.version, a.size, sizeof(a)) ||
	    a.reserved || a.generation || a.total ||
	    (!a.count && a.uids)) {
		ret = -EINVAL;
		goto out;
	}
	if (a.count > KASUMI_ALLOWLIST_UID_MAX) {
		ret = -E2BIG;
		goto out;
	}
	if (a.count) {
		if (!a.uids) {
			ret = -EINVAL;
			goto out;
		}
		uids = kmalloc_array(a.count, sizeof(*uids), GFP_KERNEL);
		if (!uids) {
			ret = -ENOMEM;
			goto out;
		}
		if (copy_from_user(uids,
				   (const void __user *)(unsigned long)a.uids,
				   a.count * sizeof(*uids))) {
			ret = -EFAULT;
			goto out;
		}
	}
	ret = kasumi_replace_policy_uid_list(a.list, uids, a.count);
	if (!ret) {
		u32 copied;

		ret = kasumi_policy_copy_uids(a.list, NULL, 0, &copied,
					      &a.total, &a.generation);
	}

out:
	a.version = KSM_POLICY_API_VERSION;
	a.size = sizeof(a);
	a.err = ret;
	if (copy_to_user(arg, &a, sizeof(a)))
		ret = -EFAULT;
	kfree(uids);
	return ret;
}

static int kasumi_ioctl_clear_policy_uids(void __user *arg)
{
	struct kasumi_policy_uid_list_arg a;
	int ret;

	if (copy_from_user(&a, arg, sizeof(a)))
		return -EFAULT;
	if (!kasumi_policy_header_valid(a.version, a.size, sizeof(a)) ||
	    a.reserved || a.generation || a.count || a.total || a.uids)
		ret = -EINVAL;
	else
		ret = kasumi_clear_policy_uid_list(a.list);
	a.count = 0;
	a.total = 0;
	if (!ret) {
		struct kasumi_policy_state_arg state = { };

		kasumi_policy_get_state(&state);
		a.generation = state.generation;
	}
	a.version = KSM_POLICY_API_VERSION;
	a.size = sizeof(a);
	a.err = ret;
	if (copy_to_user(arg, &a, sizeof(a)))
		return -EFAULT;
	return ret;
}

static int kasumi_ioctl_get_policy_uids(void __user *arg)
{
	struct kasumi_policy_uid_list_arg input;
	struct kasumi_policy_uid_list_arg a = { };
	u32 *uids = NULL;
	u32 copied = 0;
	u32 total = 0;
	u64 generation = 0;
	int ret = 0;

	if (copy_from_user(&input, arg, sizeof(input)))
		return -EFAULT;
	if (!kasumi_policy_header_valid(input.version, input.size,
					sizeof(input)) || input.reserved ||
	    input.generation || input.total || (!input.count && input.uids)) {
		ret = -EINVAL;
		goto out;
	}
	if (input.count > KASUMI_ALLOWLIST_UID_MAX) {
		ret = -E2BIG;
		goto out;
	}
	if (input.count && !input.uids) {
		ret = -EINVAL;
		goto out;
	}
	if (input.count) {
		uids = kmalloc_array(input.count, sizeof(*uids), GFP_KERNEL);
		if (!uids) {
			ret = -ENOMEM;
			goto out;
		}
	}
	ret = kasumi_policy_copy_uids(input.list, uids, input.count,
				      &copied, &total, &generation);
	if (!ret && copied &&
	    copy_to_user((void __user *)(unsigned long)input.uids, uids,
			 copied * sizeof(*uids)))
		ret = -EFAULT;

out:
	a.version = KSM_POLICY_API_VERSION;
	a.size = sizeof(a);
	a.list = input.list;
	a.count = copied;
	a.total = total;
	a.uids = input.uids;
	a.generation = generation;
	a.err = ret;
	kfree(uids);
	if (copy_to_user(arg, &a, sizeof(a)))
		return -EFAULT;
	return ret;
}

static int kasumi_ioctl_replace_policy(void __user *arg)
{
	struct kasumi_policy_replace_arg a;
	u32 *allow_uids = NULL;
	u32 *deny_uids = NULL;
	int ret;

	if (copy_from_user(&a, arg, sizeof(a)))
		return -EFAULT;
	if (!kasumi_policy_header_valid(a.version, a.size, sizeof(a)) ||
	    !kasumi_u32_reserved_zero(a.reserved, ARRAY_SIZE(a.reserved))) {
		ret = -EINVAL;
		goto out;
	}
	if (a.allow_count > KASUMI_ALLOWLIST_UID_MAX ||
	    a.deny_count > KASUMI_ALLOWLIST_UID_MAX) {
		ret = -E2BIG;
		goto out;
	}
	if ((a.allow_count && !a.allow_uids) ||
	    (a.deny_count && !a.deny_uids) ||
	    (!a.allow_count && a.allow_uids) ||
	    (!a.deny_count && a.deny_uids)) {
		ret = -EINVAL;
		goto out;
	}
	if (a.allow_count) {
		allow_uids = kmalloc_array(a.allow_count, sizeof(*allow_uids),
					   GFP_KERNEL);
		if (!allow_uids) {
			ret = -ENOMEM;
			goto out;
		}
		if (copy_from_user(allow_uids,
				   (const void __user *)(unsigned long)a.allow_uids,
				   a.allow_count * sizeof(*allow_uids))) {
			ret = -EFAULT;
			goto out;
		}
	}
	if (a.deny_count) {
		deny_uids = kmalloc_array(a.deny_count, sizeof(*deny_uids),
					  GFP_KERNEL);
		if (!deny_uids) {
			ret = -ENOMEM;
			goto out;
		}
		if (copy_from_user(deny_uids,
				   (const void __user *)(unsigned long)a.deny_uids,
				   a.deny_count * sizeof(*deny_uids))) {
			ret = -EFAULT;
			goto out;
		}
	}
	ret = kasumi_policy_replace(a.owner, a.flags, allow_uids, a.allow_count,
				    deny_uids, a.deny_count);

out:
	a.version = KSM_POLICY_API_VERSION;
	a.size = sizeof(a);
	a.err = ret;
	if (copy_to_user(arg, &a, sizeof(a)))
		ret = -EFAULT;
	kfree(allow_uids);
	kfree(deny_uids);
	return ret;
}

static int kasumi_ioctl_reset_policy(void __user *arg)
{
	struct kasumi_policy_config_arg a;
	int ret;

	if (copy_from_user(&a, arg, sizeof(a)))
		return -EFAULT;
	if (!kasumi_policy_header_valid(a.version, a.size, sizeof(a)) ||
	    a.owner || a.flags ||
	    !kasumi_u32_reserved_zero(a.reserved, ARRAY_SIZE(a.reserved)))
		ret = -EINVAL;
	else
		ret = kasumi_policy_reset();
	a.owner = KSM_POLICY_OWNER_AUTO;
	a.flags = 0;
	a.version = KSM_POLICY_API_VERSION;
	a.size = sizeof(a);
	a.err = ret;
	if (copy_to_user(arg, &a, sizeof(a)))
		return -EFAULT;
	return ret;
}

static int KASUMI_NOCFI kasumi_resolve_rule_path(char **pathname,
						 struct inode **target_out,
						 struct inode **parent_out,
						 bool follow_leaf)
{
	struct path path;
	struct inode *target = NULL, *parent = NULL;
	char *buffer, *parent_name = NULL, *resolved = NULL, *text;
	const char *leaf = NULL;
	int ret;

	if (!pathname || !*pathname || (*pathname)[0] != '/')
		return -EINVAL;
	if (!kasumi_kern_path || !kasumi_d_path)
		return -EOPNOTSUPP;
	buffer = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;
	ret =
	    kasumi_kern_path(*pathname, follow_leaf ? LOOKUP_FOLLOW : 0, &path);
	if (ret == -ENOENT) {
		char *slash;

		parent_name = kstrdup(*pathname, GFP_KERNEL);
		if (!parent_name) {
			ret = -ENOMEM;
			goto out;
		}
		slash = strrchr(parent_name, '/');
		leaf = *pathname + (slash - parent_name) + 1;
		if (!*leaf) {
			ret = -EINVAL;
			goto out;
		}
		if (slash == parent_name)
			slash[1] = '\0';
		else
			*slash = '\0';
		ret = kasumi_kern_path(parent_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &path);
		if (ret == -ENOENT) {
			/* Keep the stored key deletable after its parent disappears. */
			ret = 0;
			goto out;
		}
	}
	if (ret)
		goto out;
	text = kasumi_d_path(&path, buffer, PATH_MAX);
	if (IS_ERR(text)) {
		ret = PTR_ERR(text);
		goto out_path;
	}
	if (text[0] != '/') {
		ret = -EINVAL;
		goto out_path;
	}
	if (leaf) {
		size_t prefix = strcmp(text, "/") ? strlen(text) : 0;
		size_t length = strlen(leaf);

		if (prefix + length + 2 > PATH_MAX) {
			ret = -ENAMETOOLONG;
			goto out_path;
		}
		resolved = kmalloc(prefix + length + 2, GFP_KERNEL);
		if (resolved) {
			memcpy(resolved, text, prefix);
			resolved[prefix] = '/';
			memcpy(resolved + prefix + 1, leaf, length + 1);
		}
		parent = d_inode(path.dentry);
	} else {
		resolved = kstrdup(text, GFP_KERNEL);
		target = d_inode(path.dentry);
		parent = d_inode(path.dentry->d_parent);
	}
	if (!resolved) {
		ret = -ENOMEM;
		goto out_path;
	}
	if (target_out && target) {
		kasumi_ihold(target);
		*target_out = target;
	}
	if (parent_out && parent) {
		kasumi_ihold(parent);
		*parent_out = parent;
	}
	kfree(*pathname);
	*pathname = resolved;
out_path:
	kasumi_path_put(&path);
out:
	kfree(parent_name);
	kfree(buffer);
	return ret;
}

static int kasumi_control_bind(const char *visible, const struct path *source,
			       unsigned long ino, u8 flags)
{
	struct kasumi_dirhijack_batch *batch = kasumi_batch_dir();

	if (batch)
		return kasumi_dirhijack_batch_add(batch, visible, source, ino,
						 flags, false);
	return kasumi_dirhijack_add(visible, source, ino, flags);
}

static int kasumi_control_hide(const char *visible, u32 flags)
{
	struct kasumi_dirhijack_batch *batch = kasumi_batch_dir();

	if (batch)
		return kasumi_dirhijack_batch_hide(batch, visible, flags);
	return kasumi_dirhijack_hide(visible, flags);
}

static int kasumi_control_unbind(const char *visible)
{
	struct kasumi_dirhijack_batch *batch = kasumi_batch_dir();

	if (batch)
		return kasumi_dirhijack_batch_del(batch, visible);
	return kasumi_dirhijack_del(visible);
}

static int KASUMI_NOCFI kasumi_resolve_delete_path(char **pathname,
						   struct inode **target_out)
{
	struct kasumi_hide_entry *entry;
	u32 hash;
	bool hidden = false;
	int ret;

	ret = kasumi_resolve_rule_path(pathname, target_out, NULL, false);
	if (ret)
		return ret;
	hash = full_name_hash(NULL, *pathname, strlen(*pathname));
	mutex_lock(&kasumi_config_mutex);
	hlist_for_each_entry(
	    entry, &kasumi_hide_paths[hash_min(hash, KASUMI_HASH_BITS)], node)
	{
		if (entry->path_hash == hash &&
		    !strcmp(entry->path, *pathname)) {
			hidden = true;
			break;
		}
	}
	mutex_unlock(&kasumi_config_mutex);
	if (hidden)
		return 0;
	if (*target_out) {
		iput(*target_out);
		*target_out = NULL;
	}
	return kasumi_resolve_rule_path(pathname, target_out, NULL, true);
}

// A replacement has either replaced the VFS child or must unbind an old hide.
int KASUMI_NOCFI kasumi_forget_hide_rule(const char *path, bool unbind)
{
	struct kasumi_hide_entry *entry;
	struct inode *inode = NULL;
	char *src;
	u32 hash;
	int ret;
	u64 generation = kasumi_batch_generation();

	if (!atomic_read(&kasumi_hide_count))
		return 0;
	src = kstrdup(path, GFP_KERNEL);
	if (!src)
		return -ENOMEM;
	ret = kasumi_resolve_rule_path(&src, &inode, NULL, false);
	if (ret)
		goto out;
	hash = full_name_hash(NULL, src, strlen(src));
	mutex_lock(&kasumi_config_mutex);
	hlist_for_each_entry(
	    entry, &kasumi_hide_paths[hash_min(hash, KASUMI_HASH_BITS)], node)
	{
		if (!kasumi_rule_visible(&entry->life,
				generation ? generation : kasumi_rules_generation()) ||
		    entry->path_hash != hash || strcmp(entry->path, src))
			continue;
		if (unbind && kasumi_dirhijack_enabled()) {
			ret = kasumi_control_unbind(src);
			if (ret && ret != -ENOENT)
				break;
			ret = 0;
		}
		if (generation) {
			kasumi_batch_expire(&entry->life, KASUMI_BATCH_HIDE);
		} else {
			hlist_del_rcu(&entry->node);
			atomic_dec(&kasumi_hide_count);
			if (inode && inode->i_mapping)
				clear_bit(AS_FLAGS_KASUMI_HIDE,
					  &inode->i_mapping->flags);
			kasumi_rule_index_remove(&entry->life);
			kasumi_live_rules_untrack(&entry->life);
			call_rcu(&entry->rcu, kasumi_hide_entry_free_rcu);
		}
		break;
	}
	mutex_unlock(&kasumi_config_mutex);
out:
	if (inode)
		iput(inode);
	kfree(src);
	return ret;
}

int KASUMI_NOCFI kasumi_add_hide_rule(const char *path, u32 rule_flags)
{
	struct kasumi_hide_entry *new_hide = NULL, *hide_entry;
	struct inode *target_inode = NULL, *parent_inode = NULL;
	struct path projected_parent = {};
	char *src;
	u32 hash;
	u64 generation = kasumi_batch_generation();
	int ret;
	bool projected;

	if (!path || path[0] != '/')
		return -EINVAL;
	src = kstrdup(path, GFP_KERNEL);
	if (!src)
		return -ENOMEM;
	ret = kasumi_rule_projected_parent(src,
		generation ? generation : kasumi_rules_generation(),
		&projected_parent);
	if (ret < 0)
		goto hide_done;
	projected = ret > 0;
	if (projected_parent.dentry) {
		parent_inode = d_inode(projected_parent.dentry);
		kasumi_ihold(parent_inode);
		kasumi_path_put(&projected_parent);
	}
	if (!projected) {
		ret = kasumi_resolve_rule_path(&src, &target_inode, &parent_inode,
					       false);
		if (ret)
			goto hide_done;
	}
	new_hide = kzalloc(sizeof(*new_hide), GFP_KERNEL);
	if (!new_hide) {
		ret = -ENOMEM;
		goto hide_done;
	}
	new_hide->path = kstrdup(src, GFP_KERNEL);
	if (!new_hide->path) {
		ret = -ENOMEM;
		goto hide_done;
	}
	new_hide->life.first_generation = generation;
	ret = kasumi_rule_sequence_alloc(&new_hide->sequence);
	if (ret)
		goto hide_done;
	new_hide->rule_flags = rule_flags;
	new_hide->storage_managed = kasumi_hide_storage_parent(parent_inode);
	if (!projected) {
		ret = kasumi_control_hide(src, rule_flags);
		if (ret)
			goto hide_done;
		if (target_inode)
			kasumi_mark_inode_hidden(target_inode);
		if (parent_inode && parent_inode->i_mapping)
			set_bit(AS_FLAGS_KASUMI_DIR_HAS_HIDDEN,
				&parent_inode->i_mapping->flags);
	}
	ret = 0;

	hash = full_name_hash(NULL, src, strlen(src));
	mutex_lock(&kasumi_config_mutex);
	hlist_for_each_entry(hide_entry,
		&kasumi_hide_paths[hash_min(hash, KASUMI_HASH_BITS)], node) {
		if (!kasumi_rule_visible(&hide_entry->life,
				generation ? generation : kasumi_rules_generation()) ||
		    hide_entry->path_hash != hash ||
		    strcmp(hide_entry->path, src))
			continue;
		if (generation) {
			kasumi_batch_expire(&hide_entry->life, KASUMI_BATCH_HIDE);
		} else {
			hlist_del_rcu(&hide_entry->node);
			atomic_dec(&kasumi_hide_count);
			kasumi_rule_index_remove(&hide_entry->life);
			kasumi_live_rules_untrack(&hide_entry->life);
			call_rcu(&hide_entry->rcu, kasumi_hide_entry_free_rcu);
		}
		break;
	}
	new_hide->path_hash = hash;
	set_bit(jhash(src, strlen(src), 0) & (KASUMI_BLOOM_SIZE - 1),
		kasumi_hide_bloom);
	set_bit(jhash(src, strlen(src), 1) & (KASUMI_BLOOM_SIZE - 1),
		kasumi_hide_bloom);
	kasumi_batch_track(&new_hide->life, KASUMI_BATCH_HIDE);
	atomic_inc(&kasumi_hide_count);
	hlist_add_head_rcu(&new_hide->node,
		&kasumi_hide_paths[hash_min(hash, KASUMI_HASH_BITS)]);
	new_hide = NULL;
	mutex_unlock(&kasumi_config_mutex);
hide_done:
	if (new_hide) {
		kfree(new_hide->path);
		kfree(new_hide);
	}
	if (target_inode)
		iput(target_inode);
	if (parent_inode)
		iput(parent_inode);
	kfree(src);
	return ret;
}

static int kasumi_apply_path_rule_owned(unsigned int cmd, char *src,
				       char *target, u32 flags);

static KASUMI_NOCFI int kasumi_dispatch_cmd(unsigned int cmd, void __user *arg)
{
	struct kasumi_syscall_arg req;
	struct kasumi_entry *entry;
	struct kasumi_hide_entry *hide_entry;
	struct kasumi_inject_entry *inject_entry;
	char *src = NULL, *target = NULL;
	int ret = 0;

	if (cmd == KSM_IOC_CLEAR_ALL) {
		kasumi_live_rules_clear();
		kasumi_hide_rules_clear();
		mutex_lock(&kasumi_config_mutex);
		kasumi_cleanup_locked();
		mutex_unlock(&kasumi_config_mutex);
		kasumi_dirhijack_clear();
		kasumi_fop_override_clear();
		kasumi_sop_shadow_reap();
		kasumi_fake_mi_invalidate_all();
		kasumi_store_drain();
		return 0;
	}

	if (cmd == KSM_IOC_SET_POLICY)
		return kasumi_ioctl_set_policy(arg);
	if (cmd == KSM_IOC_GET_POLICY)
		return kasumi_ioctl_get_policy(arg);
	if (cmd == KSM_IOC_SET_POLICY_UIDS)
		return kasumi_ioctl_set_policy_uids(arg);
	if (cmd == KSM_IOC_CLEAR_POLICY_UIDS)
		return kasumi_ioctl_clear_policy_uids(arg);
	if (cmd == KSM_IOC_GET_POLICY_UIDS)
		return kasumi_ioctl_get_policy_uids(arg);
	if (cmd == KSM_IOC_REPLACE_POLICY)
		return kasumi_ioctl_replace_policy(arg);
	if (cmd == KSM_IOC_RESET_POLICY)
		return kasumi_ioctl_reset_policy(arg);

	if (cmd == KSM_IOC_SET_DEBUG) {
		int val;
		if (copy_from_user(&val, arg, sizeof(val)))
			return -EFAULT;
		kasumi_debug_enabled = !!val;
		kasumi_log("debug mode %s\n", kasumi_debug_enabled ? "enabled" : "disabled");
		return 0;
	}

	if (cmd == KSM_IOC_SET_STEALTH) {
		int val;
		if (copy_from_user(&val, arg, sizeof(val)))
			return -EFAULT;
		kasumi_stealth_enabled = !!val;
		kasumi_log("stealth mode %s\n", kasumi_stealth_enabled ? "enabled" : "disabled");
		return 0;
	}

	if (cmd == KSM_IOC_SET_ENABLED) {
		int val;
		if (copy_from_user(&val, arg, sizeof(val)))
			return -EFAULT;
		if (val) {
			mutex_lock(&kasumi_config_mutex);
			if (READ_ONCE(kasumi_enabled)) {
				mutex_unlock(&kasumi_config_mutex);
				return 0;
			}
			if (!kasumi_policy_prepare_enable_locked()) {
				mutex_unlock(&kasumi_config_mutex);
				return -ENODEV;
			}
			/* Publish provider state; the path view is served entirely
			 * through the VFS lookup/vnode layer, with no syscall
			 * dispatcher or task-scope marker to arm. */
			smp_store_release(&kasumi_enabled, true);
			mutex_unlock(&kasumi_config_mutex);
		} else {
			mutex_lock(&kasumi_config_mutex);
			if (!READ_ONCE(kasumi_enabled)) {
				mutex_unlock(&kasumi_config_mutex);
				return 0;
			}
			/* Stop policy readers before provider pointers are withdrawn. */
			smp_store_release(&kasumi_enabled, false);
			kasumi_policy_disable_provider_locked();
			mutex_unlock(&kasumi_config_mutex);
		}
		kasumi_log("Kasumi %s\n", READ_ONCE(kasumi_enabled) ?
			   "enabled" : "disabled");
		kasumi_hide_rules_changed();
		return 0;
	}

	if (cmd == KSM_IOC_REORDER_MNT_ID) {
		/* struct mnt_namespace/mount not exposed to LKM; only KPM (built-in) supports this */
		return -EOPNOTSUPP;
	}

	if (cmd == KSM_IOC_LIST_RULES) {
		struct kasumi_syscall_list_arg list_arg;
		struct kasumi_xattr_sb_entry *sb_entry;
		struct kasumi_merge_entry *merge_entry;
		char *kbuf;
		size_t buf_size, written = 0;
		int bkt;

		if (copy_from_user(&list_arg, arg, sizeof(list_arg)))
			return -EFAULT;

		buf_size = list_arg.size;
		if (buf_size > 64 * 1024)
			buf_size = 64 * 1024;

		kbuf = kzalloc(buf_size, GFP_KERNEL);
		if (!kbuf)
			return -ENOMEM;

		rcu_read_lock();
		written += scnprintf(kbuf + written, buf_size - written,
				     "Kasumi Protocol: %d\n", KSM_PROTOCOL_VERSION);
		written += scnprintf(kbuf + written, buf_size - written,
				     "Kasumi Enabled: %d\n", kasumi_enabled ? 1 : 0);
		hash_for_each_rcu(kasumi_paths, bkt, entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "add %s %s %d\n", entry->src,
					     entry->target, entry->rule_flags);
		}
		hash_for_each_rcu(kasumi_hide_paths, bkt, hide_entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "hide %s %u\n", hide_entry->path,
					     READ_ONCE(hide_entry->rule_flags));
		}
		hash_for_each_rcu(kasumi_inject_dirs, bkt, inject_entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "inject %s\n", inject_entry->dir);
		}
		hash_for_each_rcu(kasumi_merge_dirs, bkt, merge_entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(
			    kbuf + written, buf_size - written,
			    "merge %s %s %u\n", merge_entry->src,
			    merge_entry->target, merge_entry->rule_flags);
		}
		hash_for_each_rcu(kasumi_xattr_sbs, bkt, sb_entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "hide_xattr_sb %p\n", sb_entry->sb);
		}
		/* Feature rules: mount_hide, maps_spoof, statfs_spoof, selinux_fix, stealth */
		if (kasumi_feature_enabled_mask & KSM_FEATURE_MOUNT_HIDE) {
			if (written < buf_size)
				written += scnprintf(kbuf + written, buf_size - written,
						     "mount_hide enabled\n");
		}
		if (kasumi_feature_enabled_mask & KSM_FEATURE_MAPS_SPOOF) {
			if (written < buf_size)
				written += scnprintf(kbuf + written, buf_size - written,
						     "maps_spoof enabled\n");
		}
		if (kasumi_feature_enabled_mask & KSM_FEATURE_STATFS_SPOOF) {
			if (written < buf_size)
				written += scnprintf(kbuf + written, buf_size - written,
						     "statfs_spoof enabled\n");
		}
		if (kasumi_feature_enabled_mask & KSM_FEATURE_SELINUX_FIX) {
			if (written < buf_size)
				written += scnprintf(kbuf + written, buf_size - written,
						     "selinux_fix enabled\n");
		}
		if (kasumi_stealth_enabled) {
			if (written < buf_size)
				written += scnprintf(kbuf + written, buf_size - written,
						     "stealth enabled\n");
		}
		rcu_read_unlock();

		if (copy_to_user(list_arg.buf, kbuf, written)) {
			kfree(kbuf);
			return -EFAULT;
		}
		list_arg.size = written;
		if (copy_to_user(arg, &list_arg, sizeof(list_arg))) {
			kfree(kbuf);
			return -EFAULT;
		}
		kfree(kbuf);
		return 0;
	}

	if (cmd == KSM_IOC_SET_MIRROR_PATH) {
		/* ABI slot 14 is intentionally retained, but pure virtual mode no
		 * longer owns or consumes a mirror/workdir path. */
		return -EOPNOTSUPP;
	}

	if (cmd == KSM_IOC_ADD_SPOOF_KSTAT ||
	    cmd == KSM_IOC_UPDATE_SPOOF_KSTAT) {
		struct kasumi_spoof_kstat *rule;

		rule = memdup_user(arg, sizeof(*rule));
		if (IS_ERR(rule))
			return PTR_ERR(rule);
		rule->target_pathname[KSM_MAX_LEN_PATHNAME - 1] = '\0';
		ret = kasumi_spoof_kstat_upsert(rule);
		rule->err = ret;
		if (copy_to_user(arg, rule, sizeof(*rule)))
			ret = -EFAULT;
		kfree(rule);
		return ret;
	}

	if (cmd == KSM_IOC_ADD_MAPS_RULE) {
		struct kasumi_maps_rule rule;

		if (copy_from_user(&rule, arg, sizeof(rule)))
			return -EFAULT;
		ret = kasumi_maps_rules_upsert(&rule);
		rule.err = ret;
		if (copy_to_user(arg, &rule, sizeof(rule)))
			return -EFAULT;
		return ret;
	}

	if (cmd == KSM_IOC_CLEAR_MAPS_RULES) {
		kasumi_maps_rules_clear();
		return 0;
	}

	if (cmd == KSM_IOC_SET_MOUNT_HIDE) {
		struct kasumi_mount_hide_arg a;
		if (copy_from_user(&a, arg, sizeof(a)))
			return -EFAULT;
		if (a.enable && !kasumi_mount_projection_available())
			return -EOPNOTSUPP;
		if (a.enable)
			kasumi_feature_enabled_mask |= KSM_FEATURE_MOUNT_HIDE;
		else
			kasumi_feature_enabled_mask &= ~KSM_FEATURE_MOUNT_HIDE;
		kasumi_fake_mi_invalidate_all();
		kasumi_log("mount hide %s\n", a.enable ? "enabled" : "disabled");
		/* path_pattern reserved for future custom hide rules */
		return 0;
	}

	if (cmd == KSM_IOC_SET_MAPS_SPOOF) {
		struct kasumi_maps_spoof_arg a;
		if (copy_from_user(&a, arg, sizeof(a)))
			return -EFAULT;
		if (a.enable && !kasumi_proc_maps_available())
			return -EOPNOTSUPP;
		if (a.enable)
			kasumi_feature_enabled_mask |= KSM_FEATURE_MAPS_SPOOF;
		else
			kasumi_feature_enabled_mask &= ~KSM_FEATURE_MAPS_SPOOF;
		/* reserved for future inline rule */
		return 0;
	}

	if (cmd == KSM_IOC_SET_STATFS_SPOOF) {
		struct kasumi_statfs_spoof_arg a;
		if (copy_from_user(&a, arg, sizeof(a)))
			return -EFAULT;
		if (a.enable && !kasumi_statfs_view_available())
			return -EOPNOTSUPP;
		if (a.enable)
			kasumi_feature_enabled_mask |= KSM_FEATURE_STATFS_SPOOF;
		else
			kasumi_feature_enabled_mask &= ~KSM_FEATURE_STATFS_SPOOF;
		/* path/spoof_f_type reserved for future custom mappings */
		return 0;
	}

	if (cmd == KSM_IOC_SELINUX_FIX) {
		int enable;

		if (copy_from_user(&enable, arg, sizeof(enable)))
			return -EFAULT;
		if (enable && !kasumi_fake_selinuxfs_proc_attr_active())
			return -EOPNOTSUPP;
		if (enable)
			kasumi_feature_enabled_mask |= KSM_FEATURE_SELINUX_FIX;
		else
			kasumi_feature_enabled_mask &= ~KSM_FEATURE_SELINUX_FIX;
		return 0;
	}

	if (cmd == KSM_IOC_GET_FEATURES) {
		int features = kasumi_bootstrap_quiesce_supported()
				   ? KSM_FEATURE_QUIESCE
				   : 0;
		if (kasumi_hide_rules_available())
			features |= KSM_FEATURE_MANAGED_HIDE;
		features |= KSM_FEATURE_KSTAT_SPOOF;
		features |= KSM_FEATURE_MERGE_DIR;
		features |= KSM_FEATURE_RULE_BYPASS;
		features |= KSM_FEATURE_SAFE_RULE_RETIRE;
		if (kasumi_overlay_xattr_available())
			features |= KSM_FEATURE_OVERLAY_XATTR_HIDE;
		if (kasumi_getxattr_kprobe_registered)
			features |= KSM_FEATURE_SELINUX_BYPASS;
		if (kasumi_mount_projection_available())
			features |= KSM_FEATURE_MOUNT_HIDE | KSM_FEATURE_FAKE_MOUNTINFO;
		if (kasumi_proc_maps_available())
			features |= KSM_FEATURE_MAPS_SPOOF;
		if (kasumi_statfs_view_available())
			features |= KSM_FEATURE_STATFS_SPOOF;
		if (kasumi_fake_selinuxfs_proc_attr_active())
			features |= KSM_FEATURE_SELINUX_FIX;
		if (copy_to_user(arg, &features, sizeof(features)))
			return -EFAULT;
		return 0;
	}

	if (cmd == KSM_IOC_GET_HOOKS) {
		struct kasumi_syscall_list_arg list_arg;
		char *kbuf;
		size_t buf_size, written = 0;
		int n;

		if (copy_from_user(&list_arg, arg, sizeof(list_arg)))
			return -EFAULT;

		buf_size = list_arg.size;
		if (buf_size > 4096)
			buf_size = 4096;

		kbuf = kzalloc(buf_size, GFP_KERNEL);
		if (!kbuf)
			return -ENOMEM;

		/* GET_FD */
		if (kasumi_reboot_kprobe_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "GET_FD: kprobe (reboot nr=%d)\n", __NR_reboot);
		else
			n = scnprintf(kbuf + written, buf_size - written, "GET_FD: none\n");
		written += n;

		/* Path redirect: served entirely through the VFS lookup/vnode
		 * layer; no syscall dispatcher or sys_enter tracepoint remains. */
		n = scnprintf(kbuf + written, buf_size - written, "path: %s\n",
			      kasumi_dirhijack_enabled() ? "VFS lookup"
							 : "unavailable");
		written += n;
		written += scnprintf(kbuf + written, buf_size - written,
				     "fop_inodes: live=%d retiring=%d\n",
				     kasumi_fop_live_count(),
				     kasumi_fop_retiring_count());

		{
			dev_t vnode_dev = kasumi_vnode_device();

			n = scnprintf(kbuf + written, buf_size - written,
				      "vnode: live=%u allocated=%llu dev=%u:%u\n",
				      kasumi_vnode_live(),
				      (unsigned long long)kasumi_vnode_allocated(),
				      MAJOR(vnode_dev), MINOR(vnode_dev));
			written += n;
		}
		n = scnprintf(kbuf + written, buf_size - written,
			      "xattr path: none\n");
		written += n;

		written += scnprintf(kbuf + written, buf_size - written,
			"source xattrs: get/list/set/remove=%u\n"
			"live source rules: available=%u desired=%u error=%d\n",
			kasumi_source_xattr_available(),
			kasumi_live_rules_available(), kasumi_live_rules_count(),
			kasumi_live_rules_error());

		/* VFS hooks */
		if (kasumi_vfs_use_ftrace)
			n = scnprintf(kbuf + written, buf_size - written,
				     "vfs_getattr,d_path,iterate_dir,vfs_getxattr: ftrace+kretprobe\n");
		else if (kasumi_getxattr_kprobe_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "vfs: getattr=iop readdir=fop d_path=none getxattr=kretprobe\n");
		else
			n = scnprintf(kbuf + written, buf_size - written,
				     "vfs: getattr=iop readdir=fop d_path=none getxattr=none\n");
		written += n;
		written += scnprintf(
		    kbuf + written, buf_size - written,
		    "selinuxfs (passthrough): access/context=%s\n"
		    "SELinux Guard: attr/current=%s delay=%uns "
		    "phase=post-EINVAL spins=%llu\n",
		    kasumi_fake_selinuxfs_access_active() ? "shadow fop"
							  : "none",
		    kasumi_fake_selinuxfs_proc_attr_active()
			? "file-open/write proxy"
			: "none",
		    kasumi_fake_selinuxfs_delay_ns(),
		    (unsigned long long)kasumi_fake_selinuxfs_spin_count());
		written += scnprintf(kbuf + written, buf_size - written,
			"mount projection: installed=%#llx required=%#llx complete=%u\n"
			"maps/smaps: native seq adapter=%u capabilities=%#llx\n"
			"statfs/fstatfs: path-aware VFS wrapper=%u entries=%llu projections=%llu\n",
			(unsigned long long)kasumi_mount_view_capabilities(),
			(unsigned long long)kasumi_mount_view_required_capabilities(),
			kasumi_mount_projection_available(),
			kasumi_proc_seq_available(),
			(unsigned long long)kasumi_proc_seq_capabilities(),
			kasumi_statfs_view_available(),
			(unsigned long long)atomic64_read(&kasumi_hook_stats.statfs_entries),
			(unsigned long long)atomic64_read(&kasumi_hook_stats.statfs_spoofs));

		list_arg.size = written;
		if (copy_to_user(arg, &list_arg, sizeof(list_arg))) {
			kfree(kbuf);
			return -EFAULT;
		}
		if (written && copy_to_user(list_arg.buf, kbuf, written)) {
			kfree(kbuf);
			return -EFAULT;
		}
		kfree(kbuf);
		return 0;
	}

	/* Commands that use kasumi_syscall_arg */
	if (copy_from_user(&req, arg, sizeof(req)))
		return -EFAULT;
	if (req.type & ~KSM_RULE_FLAGS_MASK)
		return -EINVAL;
	if (req.type && cmd != KSM_IOC_ADD_RULE &&
	    cmd != KSM_IOC_ADD_MERGE_RULE && cmd != KSM_IOC_HIDE_RULE)
		return -EINVAL;

	if (req.src) {
		src = kasumi_strndup_user(req.src, PAGE_SIZE);
		if (IS_ERR(src))
			return PTR_ERR(src);
	}
	if (req.target) {
		target = kasumi_strndup_user(req.target, PAGE_SIZE);
		if (IS_ERR(target)) {
			kfree(src);
			return PTR_ERR(target);
		}
	}

	return kasumi_apply_path_rule_owned(cmd, src, target, req.type);
}

static int kasumi_canonical_rule_path(const char *name, char **resolved,
				      char **parent)
{
	struct path path;
	char *buffer, *text, *lookup = NULL;
	const char *suffix = NULL;
	int error;

#ifndef KASUMI_EMBEDDED
	if (!kasumi_kern_path || !kasumi_d_path)
		return -EOPNOTSUPP;
#endif
#ifdef KASUMI_EMBEDDED
	error = kern_path(name, 0, &path);
#else
	error = kasumi_kern_path(name, 0, &path);
#endif
	/* A cached synthetic symlink belongs to the visible namespace. Its
	 * backing link target must never become the configuration key. */
	if (!error && S_ISLNK(d_inode(path.dentry)->i_mode) &&
	    !kasumi_vnode_is_ours(d_inode(path.dentry))) {
		kasumi_path_put(&path);
#ifdef KASUMI_EMBEDDED
		error = kern_path(name, LOOKUP_FOLLOW, &path);
#else
		error = kasumi_kern_path(name, LOOKUP_FOLLOW, &path);
#endif
	}
	if (error == -ENOENT) {
		suffix = strrchr(name, '/');
		if (!suffix)
			return -EINVAL;
		lookup = suffix == name ? kstrdup("/", GFP_KERNEL) :
			 kstrndup(name, suffix - name, GFP_KERNEL);
		if (!lookup)
			return -ENOMEM;
#ifdef KASUMI_EMBEDDED
		error = kern_path(lookup, LOOKUP_FOLLOW, &path);
#else
		error = kasumi_kern_path(lookup, LOOKUP_FOLLOW, &path);
#endif
		kfree(lookup);
		if (error == -ENOENT)
			return 0;
	}
	if (error)
		return error;
	buffer = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buffer) {
		error = -ENOMEM;
		goto put_path;
	}
#ifdef KASUMI_EMBEDDED
	text = d_path(&path, buffer, PATH_MAX);
#else
	text = kasumi_d_path(&path, buffer, PATH_MAX);
#endif
	if (IS_ERR(text)) {
		error = PTR_ERR(text);
		goto free_buffer;
	}
	if (text[0] != '/') {
		error = -ENOENT;
		goto free_buffer;
	}
	*resolved = suffix ? kasprintf(GFP_KERNEL, "%s%s",
				     !strcmp(text, "/") ? "" : text, suffix) :
			    kstrdup(text, GFP_KERNEL);
	if (!*resolved) {
		error = -ENOMEM;
		goto free_buffer;
	}
	if (strlen(*resolved) >= PATH_MAX) {
		error = -ENAMETOOLONG;
		goto free_resolved;
	}
	if (parent) {
		const char *slash = strrchr(*resolved, '/');

		*parent = slash == *resolved ? kstrdup("/", GFP_KERNEL) :
			  kstrndup(*resolved, slash - *resolved, GFP_KERNEL);
		if (!*parent) {
			error = -ENOMEM;
			goto free_resolved;
		}
	}
	goto free_buffer;
free_resolved:
	kfree(*resolved);
	*resolved = NULL;
free_buffer:
	kfree(buffer);
put_path:
#ifdef KASUMI_EMBEDDED
	path_put(&path);
#else
	kasumi_path_put(&path);
#endif
	return error;
}

static int kasumi_apply_path_rule_owned(unsigned int cmd, char *src,
				       char *target, u32 flags)
{
	struct kasumi_entry *entry;
	struct kasumi_hide_entry *hide_entry;
	struct kasumi_inject_entry *inject_entry;
	struct kasumi_batch *batch = NULL;
	u64 generation;
	u32 hash;
	bool found = false;
	int ret = 0;

	if (!kasumi_batch_generation()) {
		batch = kasumi_batch_begin();
		if (IS_ERR(batch)) {
			ret = PTR_ERR(batch);
			batch = NULL;
			goto apply_done;
		}
	}
	generation = kasumi_batch_generation();
	ret = kasumi_live_rules_record(kasumi_batch_live(), cmd, src, target, flags);
	if (ret)
		goto apply_done;

	switch (cmd) {
	case KSM_IOC_ADD_MERGE_RULE: {
		struct kasumi_merge_entry *me;
		char *mat_src = NULL, *mat_tgt = NULL;

		if (!src || !target) { ret = -EINVAL; break; }

		/* Resolve symlinks: d_absolute_path in iterate_dir returns
		 * canonical paths (e.g. /product/overlay), while userspace sends
		 * symlink paths (e.g. /system/product/overlay). Store the
		 * canonical form as resolved_src for iterate_dir matching. */
		{
			char *resolved_src = NULL;
			struct dentry *tgt_dentry = NULL;
			struct path mpath;

			ret = kasumi_canonical_rule_path(src, &resolved_src, NULL);
			if (ret)
				goto merge_done;
			if (resolved_src && !strcmp(resolved_src, src)) {
				kfree(resolved_src);
				resolved_src = NULL;
			}
			if (kasumi_kern_path(target, LOOKUP_FOLLOW, &mpath) == 0) {
				tgt_dentry = dget(mpath.dentry);
				kasumi_path_put(&mpath);
			}

			hash = full_name_hash(NULL, src, strlen(src));
			mutex_lock(&kasumi_config_mutex);

			hlist_for_each_entry(me,
				&kasumi_merge_dirs[hash_min(hash, KASUMI_HASH_BITS)], node) {
				if (kasumi_rule_visible(&me->life, generation) &&
				    strcmp(me->src, src) == 0 &&
				    strcmp(me->target, target) == 0) {
					found = true;
					break;
				}
			}
			if (!found) {
				me = kzalloc(sizeof(*me), GFP_KERNEL);
				if (me) {
					mat_src = kstrdup(src, GFP_KERNEL);
					mat_tgt = kstrdup(target, GFP_KERNEL);
					me->src = src;
					me->target = target;
					me->resolved_src = resolved_src;
					me->target_dentry = tgt_dentry;
					me->life.first_generation = generation;
					me->rule_flags = flags;
					resolved_src = NULL;
					tgt_dentry = NULL;
					kasumi_batch_track(&me->life, KASUMI_BATCH_MERGE);
					hlist_add_head_rcu(&me->node,
						&kasumi_merge_dirs[hash_min(hash, KASUMI_HASH_BITS)]);
					src = NULL;
					target = NULL;
				} else {
					ret = -ENOMEM;
				}
			} else {
				ret = -EEXIST;
			}
			mutex_unlock(&kasumi_config_mutex);
			if (!found && !ret) {
				if (!mat_src || !mat_tgt)
					ret = -ENOMEM;
				if (!ret)
					ret = kasumi_add_inject_rule(
						kstrdup(me->src, GFP_KERNEL));
				if (!ret && me->resolved_src)
					ret = kasumi_add_inject_rule(
						kstrdup(me->resolved_src, GFP_KERNEL));
				if (!ret)
					ret = kasumi_materialize_merge(
						mat_src, mat_tgt, 0, flags);
			}
merge_done:
			kfree(resolved_src);
			if (tgt_dentry)
				dput(tgt_dentry);
			kfree(mat_src);
			kfree(mat_tgt);
		}
		break;
	}

	case KSM_IOC_ADD_RULE: {
		u8 bypass_flag = (flags & KSM_RULE_BYPASS_POLICY)
				     ? KASUMI_VNODE_F_BYPASS
				     : 0;
		char *parent_dir = NULL;
		char *resolved_src = NULL;
		char *visible_src = NULL;
		struct kasumi_entry *new_entry = NULL;
		struct path captured_source = {}, captured_nofollow = {};
		int install_side_effects;
		unsigned long dh_v_ino = 0;
		umode_t dh_src_mode = 0;
		bool dh_want = false;
		unsigned long dh_nofollow_ino = 0;
		bool dh_nofollow_valid = false;

		if (!src || !target) { ret = -EINVAL; break; }

		ret = kasumi_canonical_rule_path(src, &resolved_src, &parent_dir);
		if (ret)
			goto add_rule_done;
		visible_src = kstrdup(src, GFP_KERNEL);
		if (!visible_src) {
			kfree(resolved_src);
			ret = -ENOMEM;
			goto add_rule_done;
		}

		if (resolved_src) {
			kfree(src);
			src = resolved_src;
		}

		hash = full_name_hash(NULL, src, strlen(src));
		new_entry = kzalloc(sizeof(*new_entry), GFP_KERNEL);
		if (!new_entry) {
			ret = -ENOMEM;
			goto add_rule_done;
		}
		new_entry->src = kstrdup(src, GFP_KERNEL);
		new_entry->target = kstrdup(target, GFP_KERNEL);
		new_entry->rule_flags = flags;
		new_entry->src_hash = hash;
		if (!new_entry->src || !new_entry->target) {
			ret = -ENOMEM;
			goto add_rule_done;
		}
		ret = kasumi_entry_capture_source(new_entry, target);
		if (ret)
			goto add_rule_done;
		dh_v_ino = new_entry->visible_ino;
		dh_src_mode = new_entry->source_mode;
		dh_want = true;
		/* Captured before the config_mutex section because new_entry is set to
		 * NULL once it is inserted; these feed the symlink dirhijack branch. */
		dh_nofollow_valid = new_entry->source_nofollow_path_valid;
		dh_nofollow_ino = new_entry->nofollow_visible_ino;
		/* Keep the store, metadata hook and child binding on the same
		 * captured objects even if the source pathname is replaced. */
		if (new_entry->source_path_valid) {
			captured_source = new_entry->source_path;
			kasumi_path_get(&captured_source);
		}
		if (new_entry->source_nofollow_path_valid) {
			captured_nofollow = new_entry->source_nofollow_path;
			kasumi_path_get(&captured_nofollow);
		}

		install_side_effects = kasumi_store_upsert(new_entry);
		if (install_side_effects < 0) {
			ret = install_side_effects;
			goto add_rule_done;
		}
		new_entry = NULL;

		if (install_side_effects && parent_dir) {
			ret = kasumi_add_inject_rule(parent_dir);
			parent_dir = NULL;
			if (ret)
				goto add_rule_done;
		}

		/* Tier 3: when the lookup hijack is enabled, also register this rule's
		 * visible child so VFS lookup resolves it to a Kasumi virtual inode.
		 * v1 handled regular-file sources; Slice 3 adds symlink sources, which
		 * are registered as a symlink vnode pinned to the link itself (nofollow)
		 * so lstat/readlink see the link and the kernel follows it natively. */
		if (dh_want && kasumi_dirhijack_enabled()) {
			ret = -ENOENT;
			if (dh_nofollow_valid) {
				ret = kasumi_control_bind(src, &captured_nofollow,
					dh_nofollow_ino, KASUMI_VNODE_F_LNK | bypass_flag);
			} else if (S_ISREG(dh_src_mode)) {
				ret = kasumi_control_bind(src, &captured_source,
					dh_v_ino, bypass_flag);
			} else if (S_ISDIR(dh_src_mode)) {
				ret = kasumi_control_bind(src, &captured_source,
					dh_v_ino, KASUMI_VNODE_F_DIR | bypass_flag);
			} else if ((S_ISCHR(dh_src_mode) || S_ISBLK(dh_src_mode) ||
				    S_ISFIFO(dh_src_mode)) &&
				   kasumi_device_sources_enabled) {
				ret = kasumi_control_bind(src, &captured_source,
					dh_v_ino, KASUMI_VNODE_F_SPECIAL | bypass_flag);
			}
		}

		if (!ret)
			ret = kasumi_forget_hide_rule(src, false);
		if (!ret && strcmp(visible_src, src))
			ret = kasumi_forget_hide_rule(visible_src, true);

		/* Exact rules are injected when the visible dentry is absent.  Existing
		 * real names are de-duplicated by the directory view, so no hide marker
		 * is needed for either form. */
add_rule_done:
		if (captured_source.dentry)
			kasumi_path_put(&captured_source);
		if (captured_nofollow.dentry)
			kasumi_path_put(&captured_nofollow);
		if (new_entry) {
			kasumi_entry_release_source(new_entry);
			kfree(new_entry->src);
			kfree(new_entry->target);
			kfree(new_entry->source_canonical);
			kfree(new_entry);
		}
		kfree(visible_src);
		kfree(parent_dir);
		break;
	}

	case KSM_IOC_HIDE_RULE:
		ret = kasumi_add_hide_rule(src, flags);
		break;

	case KSM_IOC_HIDE_OVERLAY_XATTRS:
		ret = src ? kasumi_overlay_xattr_mark_at(src, generation) : -EINVAL;
		break;

	case KSM_IOC_DEL_RULE: {
		struct kasumi_merge_entry *merge;
		struct inode *del_inode = NULL;

		ret = kasumi_resolve_delete_path(&src, &del_inode);
		if (ret)
			break;
		ret = kasumi_control_unbind(src);
		if (ret == -ENOENT)
			ret = 0;
		if (del_inode)
			iput(del_inode);
		if (ret)
			break;
		hash = full_name_hash(NULL, src, strlen(src));
		mutex_lock(&kasumi_config_mutex);
		hlist_for_each_entry(entry,
			&kasumi_paths[hash_min(hash, KASUMI_HASH_BITS)], node) {
			if (kasumi_rule_visible(&entry->life, generation) &&
			    entry->src_hash == hash && !strcmp(entry->src, src))
				kasumi_batch_expire(&entry->life, KASUMI_BATCH_PATH);
		}
		hlist_for_each_entry(hide_entry,
			&kasumi_hide_paths[hash_min(hash, KASUMI_HASH_BITS)], node) {
			if (kasumi_rule_visible(&hide_entry->life, generation) &&
			    hide_entry->path_hash == hash && !strcmp(hide_entry->path, src))
				kasumi_batch_expire(&hide_entry->life, KASUMI_BATCH_HIDE);
		}
		hlist_for_each_entry(inject_entry,
			&kasumi_inject_dirs[hash_min(hash, KASUMI_HASH_BITS)], node) {
			if (kasumi_rule_visible(&inject_entry->life, generation) &&
			    !strcmp(inject_entry->dir, src))
				kasumi_batch_expire(&inject_entry->life, KASUMI_BATCH_INJECT);
		}
		hlist_for_each_entry(merge,
			&kasumi_merge_dirs[hash_min(hash, KASUMI_HASH_BITS)], node) {
			if (kasumi_rule_visible(&merge->life, generation) &&
			    !strcmp(merge->src, src))
				kasumi_batch_expire(&merge->life, KASUMI_BATCH_MERGE);
		}
		mutex_unlock(&kasumi_config_mutex);
		break;
	}

	default:
		ret = -EINVAL;
		break;
	}

apply_done:
	kasumi_live_rules_end_record();
	kfree(src);
	kfree(target);
	if (batch)
		kasumi_batch_finish(batch, ret == 0);
	return ret;
}

int kasumi_apply_path_rule(unsigned int command, const char *visible,
			  const char *source, u32 flags)
{
	char *visible_copy, *source_copy = NULL;

	if (!visible)
		return -EINVAL;
	visible_copy = kstrdup(visible, GFP_KERNEL);
	if (!visible_copy)
		return -ENOMEM;
	if (source) {
		source_copy = kstrdup(source, GFP_KERNEL);
		if (!source_copy) {
			kfree(visible_copy);
			return -ENOMEM;
		}
	}
	return kasumi_apply_path_rule_owned(command, visible_copy, source_copy, flags);
}

/* ======================================================================
 * Part 16: Ioctl Handler
 * ====================================================================== */

/*
 * Rule updates have side effects outside kasumi_config_mutex (inode/dentry
 * overrides and injected-directory state). Serialize the control plane so a
 * concurrent CLEAR_ALL cannot return while an older update is still applying
 * those side effects or re-enable the module afterwards.
 */

static atomic_t kasumi_control_files = ATOMIC_INIT(0);
static u32 kasumi_quiesce_state = KSM_QUIESCE_STATE_ACTIVE;
static int kasumi_quiesce_error;
static bool kasumi_views_stopped;

static bool kasumi_control_accepting(void)
{
	return READ_ONCE(kasumi_quiesce_state) == KSM_QUIESCE_STATE_ACTIVE;
}

static void kasumi_quiesce_stop_new(void)
{
	if (READ_ONCE(kasumi_quiesce_state) == KSM_QUIESCE_STATE_ACTIVE)
		WRITE_ONCE(kasumi_quiesce_state, KSM_QUIESCE_STATE_DRAINING);
	if (READ_ONCE(kasumi_quiesce_state) != KSM_QUIESCE_STATE_DRAINING ||
	    kasumi_views_stopped)
		return;
	smp_store_release(&kasumi_enabled, false);
	if (!kasumi_live_rules_quiesce())
		return;
	if (!kasumi_hide_rules_quiesce())
		return;
	kasumi_views_stopped = true;

	/* No new object may acquire module-owned callbacks after this point. */
	kasumi_io_notify_stop();
	kasumi_notify_view_stop();
	kasumi_exec_view_stop();
	kasumi_rename_view_stop();
	kasumi_vfs_view_stop();
	kasumi_vfs_view_drain();
	kasumi_proc_hooks_stop_new();
	kasumi_vfs_hooks_exit(0);
	kasumi_fake_selinuxfs_access_stop_new();
	kasumi_dirhijack_stop_new();
	/* Reject nested vnode creation before withdrawing the lookup/fop/dentry
	 * clients that keep each superblock owner live. */
	kasumi_sop_shadow_stop_new();
	kasumi_dirhijack_clear();
	kasumi_fop_override_stop_new();
	kasumi_fop_bridge_stop_new();
	kasumi_iop_override_stop_new();

	mutex_lock(&kasumi_config_mutex);
	kasumi_cleanup_locked();
	mutex_unlock(&kasumi_config_mutex);
	kasumi_fake_mi_invalidate_all();
}

static int kasumi_ioctl_prepare_unload(void __user *arg)
{
	struct kasumi_quiesce_arg a;
	unsigned int control_files;
	unsigned int getfd;
	unsigned int proxies;
	unsigned int iop_active;
	bool iop_quiesced;
	unsigned int sop_active;
	bool sop_quiesced;
	bool file_locks_busy;
	bool aio_busy;
	unsigned int known_refs;
	unsigned int module_refs;
	bool unload_pin_held;
	bool ready;

	if (copy_from_user(&a, arg, sizeof(a)))
		return -EFAULT;
	if (a.version != KSM_QUIESCE_API_VERSION || a.size < sizeof(a) ||
	    a.flags || !kasumi_u32_reserved_zero(a.reserved,
						 ARRAY_SIZE(a.reserved))) {
		a.err = -EINVAL;
		if (copy_to_user(arg, &a, sizeof(a)))
			return -EFAULT;
		return -EINVAL;
	}
	if (!kasumi_bootstrap_quiesce_supported()) {
		a.state = KSM_QUIESCE_STATE_ACTIVE;
		a.busy_mask = 0;
		a.err = -EOPNOTSUPP;
		if (copy_to_user(arg, &a, sizeof(a)))
			return -EFAULT;
		return -EOPNOTSUPP;
	}

	kasumi_quiesce_stop_new();
	control_files = (unsigned int)atomic_read(&kasumi_control_files);
	getfd = kasumi_proc_getfd_pending();
	proxies = kasumi_proc_proxy_live();
	iop_active = kasumi_iop_override_active();
	iop_quiesced = kasumi_iop_override_quiesced();
	sop_active = kasumi_sop_shadow_active();
	sop_quiesced = kasumi_sop_shadow_quiesced();
	file_locks_busy = kasumi_file_lock_busy();
	aio_busy = kasumi_vnode_aio_busy();
	unload_pin_held = kasumi_bootstrap_unload_pin_held();
	module_refs = (unsigned int)kasumi_module_refcount(THIS_MODULE);
	known_refs = control_files + getfd + proxies +
		(unload_pin_held ? 1U : 0U);

	a.state = KSM_QUIESCE_STATE_DRAINING;
	a.busy_mask = 0;
	if (getfd)
		a.busy_mask |= KSM_QUIESCE_BUSY_GETFD;
	if (proxies)
		a.busy_mask |= KSM_QUIESCE_BUSY_PROC_PROXY;
	if (file_locks_busy)
		a.busy_mask |= KSM_QUIESCE_BUSY_FILE_LOCKS;
	if (control_files != 1)
		a.busy_mask |= KSM_QUIESCE_BUSY_CONTROL_FD;
	if (!kasumi_views_stopped || module_refs > known_refs || iop_active ||
	    sop_active || !iop_quiesced || !sop_quiesced || aio_busy)
		a.busy_mask |= KSM_QUIESCE_BUSY_OTHER;

	ready = kasumi_views_stopped && !getfd && !proxies && iop_quiesced &&
		sop_quiesced && !sop_active && !file_locks_busy && !aio_busy &&
		control_files == 1 &&
		module_refs == control_files + (unload_pin_held ? 1U : 0U);

	if (kasumi_quiesce_error) {
		a.state = KSM_QUIESCE_STATE_FAILED;
		a.err = kasumi_quiesce_error;
	} else if (ready) {
		kasumi_file_lock_stop();
		/* Publish READY before releasing the lifecycle pin.  This ioctl is
		 * serialized with all control operations, and its own anon file keeps
		 * module text alive through copy_to_user and return to VFS.
		 */
		WRITE_ONCE(kasumi_quiesce_state, KSM_QUIESCE_STATE_READY);
		if (unload_pin_held) {
			kasumi_bootstrap_release_unload_pin();
			module_refs--;
		}
		a.state = KSM_QUIESCE_STATE_READY;
		a.busy_mask = 0;
		a.err = 0;
	} else {
		a.err = 0;
	}
	if (a.state != KSM_QUIESCE_STATE_READY)
		WRITE_ONCE(kasumi_quiesce_state, a.state);
	a.pending_getfd = getfd;
	a.pending_marker = 0;
	a.pending_redirect = 0;
	a.live_proc_proxy = proxies;
	a.live_file_view = 0;
	a.control_files = control_files;
	a.module_refs = module_refs;
	if (copy_to_user(arg, &a, sizeof(a)))
		return -EFAULT;
	return 0;
}

static KASUMI_NOCFI long kasumi_dev_ioctl(struct file *file, unsigned int cmd,
					unsigned long arg)
{
	long ret;
	u64 generation;

	if (_IOC_TYPE(cmd) != KSM_IOC_MAGIC)
		return -EPROTONOSUPPORT;

	if (cmd == KSM_IOC_GET_CONFLICTS || cmd == KSM_IOC_ACK_CONFLICTS)
		return kasumi_conflict_ioctl(cmd, (void __user *)arg);
	if (cmd == KSM_IOC_GET_VERSION)
		return put_user(KSM_PROTOCOL_VERSION, (int __user *)arg);

	mutex_lock(&kasumi_mutation_mutex);
	atomic_long_set(&kasumi_ioctl_tgid, (long)task_tgid_vnr(current));
	generation = kasumi_rules_generation();
	if (!kasumi_control_accepting() && cmd != KSM_IOC_GET_FEATURES &&
	    cmd != KSM_IOC_PREPARE_UNLOAD && cmd != KSM_IOC_WATCH_INSTANCE) {
		ret = -ESHUTDOWN;
		goto out;
	}
	if (kasumi_transaction_command(cmd)) {
		struct kasumi_transaction_state *state = file->private_data;

		ret = kasumi_transaction_ioctl(&state, cmd, (void __user *)arg);
		file->private_data = state;
		goto out;
	}
	switch (cmd) {
	case KSM_IOC_WATCH_INSTANCE:
		ret = kasumi_instance_watch((void __user *)arg);
		break;
	case KSM_IOC_USER_HIDE_UPSERT:
	case KSM_IOC_USER_HIDE_DELETE:
	case KSM_IOC_USER_HIDE_QUERY:
	case KSM_IOC_USER_HIDE_RETRY:
	case KSM_IOC_USER_HIDE_CLEAR:
		ret = kasumi_hide_rules_ioctl(cmd, (void __user *)arg);
		break;
	case KSM_IOC_SET_ENABLED:
	case KSM_IOC_ADD_RULE:
	case KSM_IOC_DEL_RULE:
	case KSM_IOC_HIDE_RULE:
	case KSM_IOC_CLEAR_ALL:
	case KSM_IOC_LIST_RULES:
	case KSM_IOC_SET_DEBUG:
	case KSM_IOC_REORDER_MNT_ID:
	case KSM_IOC_SET_STEALTH:
	case KSM_IOC_HIDE_OVERLAY_XATTRS:
	case KSM_IOC_ADD_MERGE_RULE:
	case KSM_IOC_SET_MIRROR_PATH:
	case KSM_IOC_GET_HOOKS:
	case KSM_IOC_ADD_MAPS_RULE:
	case KSM_IOC_CLEAR_MAPS_RULES:
	case KSM_IOC_GET_FEATURES:
	case KSM_IOC_SET_MOUNT_HIDE:
	case KSM_IOC_SET_MAPS_SPOOF:
	case KSM_IOC_SET_STATFS_SPOOF:
	case KSM_IOC_SELINUX_FIX:
	case KSM_IOC_SET_POLICY_OWNER:
	case KSM_IOC_SET_POLICY_UIDS:
	case KSM_IOC_CLEAR_POLICY_UIDS:
	case KSM_IOC_GET_POLICY:
	case KSM_IOC_GET_POLICY_UIDS:
	case KSM_IOC_REPLACE_POLICY:
	case KSM_IOC_RESET_POLICY:
	case KSM_IOC_ADD_SPOOF_KSTAT:
	case KSM_IOC_UPDATE_SPOOF_KSTAT:
		ret = kasumi_dispatch_cmd(cmd, (void __user *)arg);
		break;
	case KSM_IOC_PREPARE_UNLOAD:
		ret = kasumi_ioctl_prepare_unload((void __user *)arg);
		break;
	default:
		ret = -EINVAL;
		break;
	}
out:
	if (kasumi_ioctl_changes_rules(cmd) &&
	    generation == kasumi_rules_generation())
		kasumi_rules_changed();
	atomic_long_set(&kasumi_ioctl_tgid, 0);
	mutex_unlock(&kasumi_mutation_mutex);
	return ret;
}

/* ======================================================================
 * Part 17: Anonymous fd (no device node; reboot task_work installs it)
 * ====================================================================== */

static int kasumi_anon_release(struct inode *inode, struct file *file)
{
	(void)inode;
	kasumi_transaction_release(file->private_data);
	if (atomic_dec_and_test(&kasumi_control_files))
		WRITE_ONCE(kasumi_daemon_pid, 0);
	return 0;
}

static const struct file_operations kasumi_anon_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = kasumi_dev_ioctl,
	.compat_ioctl   = kasumi_dev_ioctl,
	.release        = kasumi_anon_release,
	.llseek         = noop_llseek,
};

/**
 * kasumi_install_anon_fd - Install a Kasumi fd and publish its number.
 * @outp: userspace pointer receiving the new fd
 *
 * The fd number is copied before fd_install(), so a failed userspace write can
 * release both the reserved descriptor and file without requiring close_fd().
 * Returns fd on success, negative errno on failure.
 */
int kasumi_install_anon_fd(int __user *outp)
{
	struct file *file;
	int fd;
	pid_t pid;

	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return -EPERM;
	if (!kasumi_control_accepting())
		return -ESHUTDOWN;
	if (!outp)
		return -EINVAL;

	file = anon_inode_getfile("kasumi", &kasumi_anon_fops, NULL, O_RDWR);
	if (IS_ERR(file))
		return PTR_ERR(file);
	atomic_inc(&kasumi_control_files);

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0)
		goto err_file;
	if (put_user(fd, outp)) {
		put_unused_fd(fd);
		fd = -EFAULT;
		goto err_file;
	}

	fd_install(fd, file);
	pid = task_tgid_vnr(current);
	WRITE_ONCE(kasumi_daemon_pid, pid);
	kasumi_log("Controller PID auto-registered: %d\n", pid);
	return fd;

err_file:
	fput(file);
	return fd;
}
