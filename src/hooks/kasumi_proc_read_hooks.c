/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - isolated mountinfo views and proc maps filtering.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/fcntl.h>
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <linux/seq_file.h>
#include <linux/srcu.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/ctype.h>
#include <linux/jhash.h>
#include <linux/namei.h>
#include <linux/pid.h>
#include <linux/poll.h>
#include <uapi/linux/magic.h>
#include "kasumi_runtime.h"
#include "kasumi_root_detection.h"
#include "kasumi_store.h"
#include "kasumi_entrypoints.h"
#include "kasumi_path_policy.h"
#include "kasumi_proc_hooks.h"
#include "kasumi_fake_mountinfo.h"
#include "kasumi_vnode.h"

#define KASUMI_PROC_FILTER_BUF 65536
#define KASUMI_PROC_STREAM_MEMORY_BUDGET (16 * 1024 * 1024)
#define KASUMI_PROC_STREAM_ALLOCATION (KASUMI_PROC_FILTER_BUF + 1)
#define KASUMI_PROC_STREAM_MAX (1024 * 1024)

static int kasumi_filter_maps_lines(const char *src, size_t len,
				    char *dst, size_t dst_size, size_t *written,
				    bool *changed, bool *valid,
				    enum kasumi_policy_scope scope);

enum kasumi_proc_proxy_kind {
	KASUMI_PROC_PROXY_NONE = 0,
	KASUMI_PROC_PROXY_MOUNTINFO,
	KASUMI_PROC_PROXY_MOUNTS,
	KASUMI_PROC_PROXY_MAPS,
};

/*
 * Pinned proxy lifecycle:
 *   - .owner = THIS_MODULE makes the VFS hold the module from fops_get() until
 *     __fput() calls fops_put() after ->release. Therefore module exit cannot
 *     race a dispatch that already selected proxy_fops.
 *   - Every install adds the proxy to kasumi_proxy_list under
 *     kasumi_proxy_list_lock. Natural close removes it, runs the original
 *     ->release, and transfers the file's module reference to a static closed
 *     fops before freeing the per-file object. __fput() can then safely call
 *     fops_put(file->f_op) after our ->release returns.
 *   - Module exit can run only after all proxy fds close and their fops_put()
 *     calls drop the module references. No callback into module text is
 *     queued and the proxy list is empty by construction.
 */

#define KASUMI_PROXY_STATE_OPEN      0
#define KASUMI_PROXY_STATE_RELEASED  1

struct kasumi_mount_file_proxy {
	const struct file_operations *orig_fops;
	struct file_operations proxy_fops;
	enum kasumi_proc_proxy_kind kind;
	enum kasumi_policy_scope scope;
	fmode_t orig_f_mode;
	struct list_head node;
	atomic_t state;
	atomic_t filter_invalidated;
	struct mutex stream_lock;
	char *stream_raw;
	size_t stream_raw_capacity;
	char *stream_filtered;
	size_t stream_filtered_capacity;
	size_t stream_raw_len;
	size_t stream_tail_off;
	size_t stream_out_len;
	size_t stream_out_off;
	loff_t stream_orig_pos;
	loff_t stream_user_pos;
	u64 stream_generation;
	bool stream_eof;
	bool stream_failed;
	struct mnt_namespace *original_mnt_ns;
	bool mountinfo_checked;
	int mountinfo_error;
	struct kasumi_mi_snapshot *mountinfo_snapshot;
};

static LIST_HEAD(kasumi_proxy_list);
static DEFINE_SPINLOCK(kasumi_proxy_list_lock);
DEFINE_STATIC_SRCU(kasumi_proxy_srcu);
static atomic_t kasumi_proxy_shutdown = ATOMIC_INIT(0);
static atomic_t kasumi_proxy_live = ATOMIC_INIT(0);
static atomic_long_t kasumi_stream_memory_used = ATOMIC_LONG_INIT(0);

static struct kprobe kasumi_kp_fd_install;
static struct kprobe kasumi_kp_internal_fd_install;
static bool kasumi_fd_install_registered;
static bool kasumi_internal_fd_install_registered;
static u32 kasumi_ns_id_seed;
static int kasumi_mount_proxy_install_file(
	struct file *file, enum kasumi_proc_proxy_kind kind,
	enum kasumi_policy_scope scope);
static KASUMI_NOCFI int kasumi_mount_proxy_release(struct inode *inode,
						   struct file *file);

struct kasumi_vfs_readlink_ri_data {
	char __user *buffer;
	int buflen;
	bool candidate;
};

static u32 kasumi_fake_mnt_ns_id(void)
{
	u32 uid = (u32)__kuid_val(current_uid());
	u32 tgid = (u32)task_tgid_vnr(current);
	u32 hash = jhash_2words(uid, tgid, READ_ONCE(kasumi_ns_id_seed));

	/* Keep the synthetic inode in the conventional namespace range and stable
	 * for this process while the module remains loaded.
	 */
	return 0xf0001000U + (hash & 0x0007ffffU);
}

static bool kasumi_current_inherits_root_parent_mnt_ns(void)
{
	struct task_struct *parent;
	struct nsproxy *current_nsproxy = current->nsproxy;
	bool inherited = false;

	if (!kasumi_policy_current_is_isolated() || !current_nsproxy)
		return false;

	rcu_read_lock();
	parent = rcu_dereference(current->real_parent);
	if (parent) {
		task_lock(parent);
		inherited = __kuid_val(task_uid(parent)) == 0 &&
			parent->nsproxy &&
			parent->nsproxy->mnt_ns == current_nsproxy->mnt_ns;
		task_unlock(parent);
	}
	rcu_read_unlock();
	return inherited;
}

static int kasumi_vfs_readlink_entry(struct kretprobe_instance *ri,
				     struct pt_regs *regs)
{
	struct kasumi_vfs_readlink_ri_data *d = (void *)ri->data;
	struct dentry *dentry;

	d->buffer = NULL;
	d->buflen = 0;
	d->candidate = false;

	if (READ_ONCE(kasumi_mount_hide_mode) !=
		    KSM_MOUNT_HIDE_MODE_AGGRESSIVE ||
	    !(READ_ONCE(kasumi_feature_enabled_mask) &
	      KSM_FEATURE_MOUNT_HIDE) ||
	    !kasumi_fake_mi_active() ||
	    !kasumi_policy_current_is_spoof_target() ||
	    !kasumi_current_inherits_root_parent_mnt_ns())
		return 0;

#if defined(__aarch64__)
	dentry = (struct dentry *)regs->regs[0];
	d->buffer = (char __user *)regs->regs[1];
	d->buflen = (int)regs->regs[2];
#elif defined(__x86_64__)
	dentry = (struct dentry *)regs->di;
	d->buffer = (char __user *)regs->si;
	d->buflen = (int)regs->dx;
#else
	return 0;
#endif
	if (!dentry || !dentry->d_sb ||
	    dentry->d_sb->s_magic != PROC_SUPER_MAGIC ||
	    !d->buffer || d->buflen <= 0) {
		d->buffer = NULL;
		return 0;
	}

	d->candidate = true;
	return 0;
}

static KASUMI_NOCFI int kasumi_vfs_readlink_ret(
	struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kasumi_vfs_readlink_ri_data *d = (void *)ri->data;
	char original_prefix[sizeof("mnt:[") - 1];
	char projected[32];
	long ret;
	int len;

	if (!d->candidate || !d->buffer)
		return 0;
#if defined(__aarch64__)
	ret = (long)regs->regs[0];
#elif defined(__x86_64__)
	ret = (long)regs->ax;
#else
	return 0;
#endif
	if (ret < (long)sizeof(original_prefix) ||
	    !kasumi_copy_from_user_nofault || !kasumi_copy_to_user_nofault ||
	    kasumi_copy_from_user_nofault(original_prefix, d->buffer,
					 sizeof(original_prefix)) ||
	    memcmp(original_prefix, "mnt:[", sizeof(original_prefix)) != 0)
		return 0;

	len = scnprintf(projected, sizeof(projected), "mnt:[%u]",
			kasumi_fake_mnt_ns_id());
	len = min(len, d->buflen);
	if (kasumi_copy_to_user_nofault(d->buffer, projected, len))
		ret = -EFAULT;
	else
		ret = len;
#if defined(__aarch64__)
	regs->regs[0] = (unsigned long)ret;
#elif defined(__x86_64__)
	regs->ax = (unsigned long)ret;
#endif
	return 0;
}

static struct kretprobe kasumi_krp_vfs_readlink = {
	.entry_handler = kasumi_vfs_readlink_entry,
	.handler = kasumi_vfs_readlink_ret,
	.data_size = sizeof(struct kasumi_vfs_readlink_ri_data),
	.maxactive = 64,
};

static enum kasumi_proc_proxy_kind
kasumi_proc_proxy_kind_for_file(struct file *file,
				enum kasumi_policy_scope *scope_out)
{
	const struct qstr *name;
	enum kasumi_policy_scope scope;
	bool spoof;

	if (!file || !file->f_path.dentry || !file->f_inode ||
	    !file->f_inode->i_sb || file->f_inode->i_sb->s_magic != PROC_SUPER_MAGIC)
		return KASUMI_PROC_PROXY_NONE;

	scope = kasumi_policy_current_scope();
	if (scope_out)
		*scope_out = scope;
	spoof = scope == KASUMI_POLICY_SCOPE_SPOOF;
	if (scope == KASUMI_POLICY_SCOPE_NONE)
		return KASUMI_PROC_PROXY_NONE;

	name = &file->f_path.dentry->d_name;
	if (spoof && kasumi_policy_current_is_isolated() &&
	    (READ_ONCE(kasumi_feature_enabled_mask) & KSM_FEATURE_MOUNT_HIDE) &&
	    ((name->len == 9 && !memcmp(name->name, "mountinfo", 9)) ||
	     (name->len == 6 && !memcmp(name->name, "mounts", 6))))
		return name->len == 9 ? KASUMI_PROC_PROXY_MOUNTINFO
				      : KASUMI_PROC_PROXY_MOUNTS;
	if ((spoof && (kasumi_feature_enabled_mask & KSM_FEATURE_MAPS_SPOOF)) &&
	    ((name->len == 4 && !memcmp(name->name, "maps", 4)) ||
	     (name->len == 5 && !memcmp(name->name, "smaps", 5)) ||
	     (name->len == 12 && !memcmp(name->name, "smaps_rollup", 12))))
		return KASUMI_PROC_PROXY_MAPS;
	return KASUMI_PROC_PROXY_NONE;
}

static void kasumi_fd_install_file(struct file *file)
{
	enum kasumi_proc_proxy_kind kind;
	enum kasumi_policy_scope scope;
	const struct file_operations *fops;

	if (!READ_ONCE(kasumi_enabled))
		return;
	fops = file ? READ_ONCE(file->f_op) : NULL;
	if (!fops || READ_ONCE(fops->release) == kasumi_mount_proxy_release)
		return;
	/* The fd-install ingress normally receives a private, freshly opened file.
	 * Refuse an already-shared object rather than replacing f_op for other
	 * holders.
	 */
	if (file_count(file) != 1)
		return;
	kind = kasumi_proc_proxy_kind_for_file(file, &scope);
	if (kind == KASUMI_PROC_PROXY_NONE)
		return;
	/* The freshly opened file has not been published yet. Installing
	 * its proxy here avoids an fd-reuse window and needs no sleeping path
	 * lookup; procfs magic plus the final dentry name already identify every
	 * supported view.
	 */
	(void)kasumi_mount_proxy_install_file(file, kind, scope);
}

static int kasumi_fd_install_pre(struct kprobe *kp, struct pt_regs *regs)
{
	struct file *file;

	(void)kp;
#if defined(__aarch64__)
	file = (struct file *)regs->regs[1];
#elif defined(__x86_64__)
	file = (struct file *)regs->si;
#else
	return 0;
#endif
	kasumi_fd_install_file(file);
	return 0;
}

/* Android 12/13 5.10 LTO calls __fd_install(files, fd, file) directly from
 * do_sys_openat2(), bypassing the public fd_install() wrapper entirely.
 */
static int kasumi_internal_fd_install_pre(struct kprobe *kp,
					  struct pt_regs *regs)
{
	struct file *file;

	(void)kp;
#if defined(__aarch64__)
	file = (struct file *)regs->regs[2];
#elif defined(__x86_64__)
	file = (struct file *)regs->dx;
#else
	return 0;
#endif
	kasumi_fd_install_file(file);
	return 0;
}

/* __fput() dereferences file->f_op after ->release returns. The live proxy's
 * owner reference is transferred to this permanent fops object while the
 * per-file proxy is reclaimed.
 */
static const struct file_operations kasumi_closed_proxy_fops = {
	.owner = THIS_MODULE,
};

static bool kasumi_mount_proxy_filter_active(
	struct kasumi_mount_file_proxy *proxy)
{
	enum kasumi_policy_scope scope = kasumi_policy_current_scope();
	bool active = false;

	if (atomic_read(&proxy->filter_invalidated))
		return false;
	if (!READ_ONCE(kasumi_enabled) || scope != proxy->scope)
		goto invalidate;
	if (proxy->kind == KASUMI_PROC_PROXY_MAPS)
		active = scope == KASUMI_POLICY_SCOPE_SPOOF &&
			 (kasumi_feature_enabled_mask & KSM_FEATURE_MAPS_SPOOF);
	if (active)
		return true;

invalidate:
	atomic_set(&proxy->filter_invalidated, 1);
	return false;
}

static KASUMI_NOCFI ssize_t kasumi_mount_proxy_orig_read_iter(
	struct kasumi_mount_file_proxy *proxy, struct kiocb *iocb,
	struct iov_iter *to)
{
	if (proxy->orig_fops->read_iter)
		return proxy->orig_fops->read_iter(iocb, to);

	/* maps/smaps used ->read = seq_read on older kernels. All proc views
	 * proxied here are seq_files, so seq_read_iter is the safe kernel-buffer
	 * equivalent and avoids ever placing unfiltered bytes in userspace.
	 */
	return kasumi_seq_read_iter(iocb, to);
}

static bool kasumi_mount_proxy_stream_reserve(size_t bytes)
{
	long used;

	used = atomic_long_add_return(bytes,
				      &kasumi_stream_memory_used);
	if (used <= KASUMI_PROC_STREAM_MEMORY_BUDGET)
		return true;
	atomic_long_sub(bytes, &kasumi_stream_memory_used);
	return false;
}

static void kasumi_mount_proxy_stream_free(
	struct kasumi_mount_file_proxy *proxy)
{
	if (!proxy->stream_raw)
		goto free_filtered;
	kvfree(proxy->stream_raw);
	atomic_long_sub(proxy->stream_raw_capacity,
			&kasumi_stream_memory_used);
	proxy->stream_raw = NULL;
	proxy->stream_raw_capacity = 0;

free_filtered:
	if (!proxy->stream_filtered)
		return;
	kvfree(proxy->stream_filtered);
	atomic_long_sub(proxy->stream_filtered_capacity,
			&kasumi_stream_memory_used);
	proxy->stream_filtered = NULL;
	proxy->stream_filtered_capacity = 0;
}

static int kasumi_mount_proxy_stream_alloc(
	struct kasumi_mount_file_proxy *proxy)
{
	char *raw;

	if (proxy->stream_raw)
		return 0;
	if (!kasumi_mount_proxy_stream_reserve(KASUMI_PROC_STREAM_ALLOCATION))
		return -ENOMEM;
	raw = kvmalloc(KASUMI_PROC_STREAM_ALLOCATION, GFP_KERNEL);
	if (!raw)
		goto out_unreserve;
	proxy->stream_raw = raw;
	proxy->stream_raw_capacity = KASUMI_PROC_STREAM_ALLOCATION;
	return 0;

out_unreserve:
	atomic_long_sub(KASUMI_PROC_STREAM_ALLOCATION,
			&kasumi_stream_memory_used);
	return -ENOMEM;
}

static int kasumi_mount_proxy_stream_grow_raw(
	struct kasumi_mount_file_proxy *proxy)
{
	char *raw;
	size_t old_capacity = proxy->stream_raw_capacity;
	size_t new_capacity;
	size_t delta;

	if (old_capacity >= KASUMI_PROC_STREAM_MAX)
		return -EFBIG;
	new_capacity = min_t(size_t, old_capacity * 2,
				    KASUMI_PROC_STREAM_MAX);
	delta = new_capacity - old_capacity;
	if (!kasumi_mount_proxy_stream_reserve(delta))
		return -ENOMEM;
	raw = kvmalloc(new_capacity, GFP_KERNEL);
	if (!raw) {
		atomic_long_sub(delta, &kasumi_stream_memory_used);
		return -ENOMEM;
	}
	memcpy(raw, proxy->stream_raw, proxy->stream_raw_len);
	kvfree(proxy->stream_raw);
	proxy->stream_raw = raw;
	proxy->stream_raw_capacity = new_capacity;
	return 0;
}

static int kasumi_mount_proxy_stream_alloc_filtered(
	struct kasumi_mount_file_proxy *proxy)
{
	char *filtered;

	if (proxy->stream_filtered)
		return 0;
	if (!kasumi_mount_proxy_stream_reserve(KASUMI_PROC_STREAM_ALLOCATION))
		return -ENOMEM;
	filtered = kvmalloc(KASUMI_PROC_STREAM_ALLOCATION, GFP_KERNEL);
	if (!filtered) {
		atomic_long_sub(KASUMI_PROC_STREAM_ALLOCATION,
				&kasumi_stream_memory_used);
		return -ENOMEM;
	}
	proxy->stream_filtered = filtered;
	proxy->stream_filtered_capacity = KASUMI_PROC_STREAM_ALLOCATION;
	return 0;
}

static int kasumi_mount_proxy_stream_grow_filtered(
	struct kasumi_mount_file_proxy *proxy)
{
	char *filtered;
	size_t old_capacity = proxy->stream_filtered_capacity;
	size_t new_capacity;
	size_t delta;

	if (old_capacity >= KASUMI_PROC_STREAM_MAX)
		return -ENOSPC;
	new_capacity = min_t(size_t, old_capacity * 2,
				    KASUMI_PROC_STREAM_MAX);
	delta = new_capacity - old_capacity;
	if (!kasumi_mount_proxy_stream_reserve(delta))
		return -ENOMEM;
	filtered = kvmalloc(new_capacity, GFP_KERNEL);
	if (!filtered) {
		atomic_long_sub(delta, &kasumi_stream_memory_used);
		return -ENOMEM;
	}
	kvfree(proxy->stream_filtered);
	proxy->stream_filtered = filtered;
	proxy->stream_filtered_capacity = new_capacity;
	return 0;
}

static void kasumi_mount_proxy_stream_compact(
	struct kasumi_mount_file_proxy *proxy)
{
	size_t tail_len;

	if (!proxy->stream_out_len)
		return;
	tail_len = proxy->stream_raw_len - proxy->stream_tail_off;
	if (tail_len)
		memmove(proxy->stream_raw,
			proxy->stream_raw + proxy->stream_tail_off, tail_len);
	proxy->stream_raw_len = tail_len;
	proxy->stream_tail_off = 0;
	proxy->stream_out_len = 0;
	proxy->stream_out_off = 0;
}

static ssize_t kasumi_mount_proxy_stream_fill(
	struct kasumi_mount_file_proxy *proxy, struct file *file)
{
	struct kiocb shadow_iocb;
	struct iov_iter kernel_iter;
	struct kvec kvec;
	size_t complete_len;
	size_t tail_len;
	size_t new_len;
	bool maps_changed;
	bool maps_valid;
	ssize_t ret;

	for (;;) {
		kasumi_mount_proxy_stream_compact(proxy);
		complete_len = proxy->stream_raw_len;
		while (complete_len > 0 &&
		       proxy->stream_raw[complete_len - 1] != '\n')
			complete_len--;

		if (complete_len > 0) {
			if (proxy->kind == KASUMI_PROC_PROXY_MAPS) {
				ret = kasumi_mount_proxy_stream_alloc_filtered(proxy);
				if (ret)
					return ret;
				for (;;) {
					maps_changed = false;
					maps_valid = true;
					ret = kasumi_filter_maps_lines(
						proxy->stream_raw, complete_len,
						proxy->stream_filtered,
						proxy->stream_filtered_capacity,
						&new_len, &maps_changed, &maps_valid,
						proxy->scope);
					if (ret != -ENOSPC)
						break;
					ret = kasumi_mount_proxy_stream_grow_filtered(proxy);
					if (ret)
						return ret;
				}
				if (ret < 0 || !maps_valid)
					return ret < 0 ? ret : -EIO;
			} else {
				/* Only maps use the buffered filtering path. */
				return -EIO;
			}

			tail_len = proxy->stream_raw_len - complete_len;
			proxy->stream_tail_off = complete_len;
			proxy->stream_out_off = 0;
			proxy->stream_out_len = new_len;
			if (new_len)
				return 1;
			if (tail_len)
				memmove(proxy->stream_raw,
					proxy->stream_raw + complete_len, tail_len);
			proxy->stream_raw_len = tail_len;
			proxy->stream_tail_off = 0;
			continue;
		}

		if (proxy->stream_eof)
			return proxy->stream_raw_len ? -EIO : 0;
		if (proxy->stream_raw_len + 1 >= proxy->stream_raw_capacity) {
			ret = kasumi_mount_proxy_stream_grow_raw(proxy);
			if (ret)
				return ret;
		}

		kvec.iov_base = proxy->stream_raw + proxy->stream_raw_len;
		kvec.iov_len = proxy->stream_raw_capacity - 1 -
			proxy->stream_raw_len;
		iov_iter_kvec(&kernel_iter, READ, &kvec, 1, kvec.iov_len);
		init_sync_kiocb(&shadow_iocb, file);
		shadow_iocb.ki_pos = proxy->stream_orig_pos;
		ret = kasumi_mount_proxy_orig_read_iter(proxy, &shadow_iocb,
							 &kernel_iter);
		if (ret < 0)
			return ret;
		if (!ret) {
			proxy->stream_eof = true;
			continue;
		}
		if ((size_t)ret > kvec.iov_len)
			return -EIO;
		proxy->stream_raw_len += (size_t)ret;
		proxy->stream_orig_pos = shadow_iocb.ki_pos;
		proxy->stream_raw[proxy->stream_raw_len] = '\0';
	}
}

static int
kasumi_mount_proxy_prepare_mountinfo(struct kasumi_mount_file_proxy *proxy,
				     struct file *file)
{
	if (!proxy->mountinfo_snapshot &&
	    (!proxy->mountinfo_checked || kasumi_fake_mi_cached())) {
		proxy->mountinfo_error = kasumi_fake_mi_get_snapshot(
		    file, proxy->orig_fops, &proxy->original_mnt_ns,
		    &proxy->mountinfo_snapshot);
		proxy->mountinfo_checked = true;
	}
	return proxy->mountinfo_error;
}

static ssize_t
kasumi_mount_proxy_read_snapshot(const struct kasumi_mi_snapshot *snapshot,
				 bool mounts, char __user *buffer,
				 struct iov_iter *to, size_t count, loff_t *pos)
{
	const char *data = mounts ? snapshot->mounts : snapshot->data;
	size_t len = mounts ? snapshot->mounts_len : snapshot->len;
	size_t copied;

	if (!pos || *pos < 0)
		return -EINVAL;
	if (*pos >= len || !count)
		return 0;
	count = min_t(size_t, count, len - (size_t)*pos);
	if (to)
		copied = copy_to_iter(data + *pos, count, to);
	else
		copied = count - copy_to_user(buffer, data + *pos, count);
	if (!copied)
		return -EFAULT;
	*pos += copied;
	return copied;
}

static ssize_t kasumi_mount_proxy_filtered_read(
	struct kasumi_mount_file_proxy *proxy, struct file *file,
	char __user *userbuf, struct iov_iter *to, size_t count, loff_t *ppos)
{
	const char *outbuf;
	size_t available;
	size_t copied;
	ssize_t ret;

	if (!ppos || *ppos < 0)
		return -EINVAL;
	if (!count)
		return 0;
	mutex_lock(&proxy->stream_lock);
	if (proxy->stream_failed || *ppos != proxy->stream_user_pos) {
		ret = -EIO;
		goto out_unlock;
	}
	ret = kasumi_mount_proxy_stream_alloc(proxy);
	if (ret) {
		proxy->stream_failed = true;
		goto out_unlock;
	}

	while (proxy->stream_out_off == proxy->stream_out_len) {
		ret = kasumi_mount_proxy_stream_fill(proxy, file);
		if (ret <= 0)
			goto out_fail;
	}
	outbuf = proxy->kind == KASUMI_PROC_PROXY_MAPS ?
		proxy->stream_filtered : proxy->stream_raw;
	if (!outbuf) {
		ret = -EIO;
		goto out_fail;
	}
	available = min_t(size_t, count,
			  proxy->stream_out_len - proxy->stream_out_off);
	if (to)
		copied = copy_to_iter(outbuf + proxy->stream_out_off,
				      available, to);
	else
		copied = available - copy_to_user(
			userbuf, outbuf + proxy->stream_out_off, available);
	if (!copied) {
		ret = -EFAULT;
		goto out_unlock;
	}
	proxy->stream_out_off += copied;
	proxy->stream_user_pos += copied;
	*ppos = proxy->stream_user_pos;
	ret = (ssize_t)copied;
	goto out_unlock;

out_fail:
	if (ret < 0)
		proxy->stream_failed = true;

out_unlock:
	mutex_unlock(&proxy->stream_lock);
	return ret;
}

static KASUMI_NOCFI ssize_t kasumi_mount_proxy_read(struct file *file,
						    char __user *buf,
						    size_t count, loff_t *ppos)
{
	struct kasumi_mount_file_proxy *proxy = container_of(
	    file->f_op, struct kasumi_mount_file_proxy, proxy_fops);
	ssize_t ret = 0;
	int srcu_idx = srcu_read_lock(&kasumi_proxy_srcu);

	if (proxy->kind == KASUMI_PROC_PROXY_MOUNTINFO ||
	    proxy->kind == KASUMI_PROC_PROXY_MOUNTS) {
		mutex_lock(&proxy->stream_lock);
		if (count) {
			ret = kasumi_mount_proxy_prepare_mountinfo(proxy, file);
			if (!ret) {
				if (proxy->mountinfo_snapshot)
					ret = kasumi_mount_proxy_read_snapshot(
					    proxy->mountinfo_snapshot,
					    proxy->kind ==
						KASUMI_PROC_PROXY_MOUNTS,
					    buf, NULL, count, ppos);
				else
					ret = proxy->orig_fops->read(
					    file, buf, count, ppos);
			}
		}
		mutex_unlock(&proxy->stream_lock);
	} else if (kasumi_mount_proxy_filter_active(proxy)) {
		ret = kasumi_mount_proxy_filtered_read(
		    proxy, file, buf, NULL, count, ppos ? ppos : &file->f_pos);
	} else {
		ret = -EIO;
	}
	srcu_read_unlock(&kasumi_proxy_srcu, srcu_idx);
	return ret;
}

static ssize_t kasumi_mount_proxy_read_iter(struct kiocb *iocb,
					    struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct kasumi_mount_file_proxy *proxy = container_of(
	    file->f_op, struct kasumi_mount_file_proxy, proxy_fops);
	ssize_t ret = 0;
	int srcu_idx = srcu_read_lock(&kasumi_proxy_srcu);

	if (proxy->kind == KASUMI_PROC_PROXY_MOUNTINFO ||
	    proxy->kind == KASUMI_PROC_PROXY_MOUNTS) {
		mutex_lock(&proxy->stream_lock);
		if (iov_iter_count(to)) {
			ret = kasumi_mount_proxy_prepare_mountinfo(proxy, file);
			if (!ret) {
				if (proxy->mountinfo_snapshot)
					ret = kasumi_mount_proxy_read_snapshot(
					    proxy->mountinfo_snapshot,
					    proxy->kind ==
						KASUMI_PROC_PROXY_MOUNTS,
					    NULL, to, iov_iter_count(to),
					    &iocb->ki_pos);
				else
					ret = kasumi_mount_proxy_orig_read_iter(
					    proxy, iocb, to);
			}
		}
		mutex_unlock(&proxy->stream_lock);
	} else if (kasumi_mount_proxy_filter_active(proxy)) {
		ret = kasumi_mount_proxy_filtered_read(
		    proxy, file, NULL, to, iov_iter_count(to), &iocb->ki_pos);
	} else {
		ret = -EIO;
	}
	srcu_read_unlock(&kasumi_proxy_srcu, srcu_idx);
	return ret;
}

static KASUMI_NOCFI ssize_t kasumi_mount_proxy_splice_read(
    struct file *file, loff_t *ppos, struct pipe_inode_info *pipe, size_t len,
    unsigned int flags)
{
	struct kasumi_mount_file_proxy *proxy = container_of(
	    file->f_op, struct kasumi_mount_file_proxy, proxy_fops);
	int ret = 0;

	mutex_lock(&proxy->stream_lock);
	if (len)
		ret = kasumi_mount_proxy_prepare_mountinfo(proxy, file);
	mutex_unlock(&proxy->stream_lock);
	if (ret)
		return ret;
	/* The native proc splice helper consumes our read_iter callback. */
	return proxy->orig_fops->splice_read(file, ppos, pipe, len, flags);
}

static bool kasumi_mount_proxy_reject_ioctl(
	const struct kasumi_mount_file_proxy *proxy, unsigned int cmd)
{
#ifdef PROCMAP_QUERY
	return proxy->kind == KASUMI_PROC_PROXY_MAPS &&
	       cmd == PROCMAP_QUERY;
#else
	(void)proxy;
	(void)cmd;
	return false;
#endif
}

static KASUMI_NOCFI long kasumi_mount_proxy_ioctl(struct file *file,
						   unsigned int cmd,
						   unsigned long arg)
{
	struct kasumi_mount_file_proxy *proxy =
		container_of(file->f_op, struct kasumi_mount_file_proxy, proxy_fops);
	long ret;
	int srcu_idx;

	srcu_idx = srcu_read_lock(&kasumi_proxy_srcu);
	if (!kasumi_mount_proxy_filter_active(proxy))
		ret = -EIO;
	else if (kasumi_mount_proxy_reject_ioctl(proxy, cmd))
		ret = -EOPNOTSUPP;
	else if (proxy->orig_fops->unlocked_ioctl)
		ret = proxy->orig_fops->unlocked_ioctl(file, cmd, arg);
	else
		ret = -ENOTTY;
	srcu_read_unlock(&kasumi_proxy_srcu, srcu_idx);
	return ret;
}

#ifdef CONFIG_COMPAT
static KASUMI_NOCFI long kasumi_mount_proxy_compat_ioctl(struct file *file,
						  unsigned int cmd,
						  unsigned long arg)
{
	struct kasumi_mount_file_proxy *proxy =
		container_of(file->f_op, struct kasumi_mount_file_proxy, proxy_fops);
	long ret;
	int srcu_idx;

	srcu_idx = srcu_read_lock(&kasumi_proxy_srcu);
	if (!kasumi_mount_proxy_filter_active(proxy))
		ret = -EIO;
	else if (kasumi_mount_proxy_reject_ioctl(proxy, cmd))
		ret = -EOPNOTSUPP;
	else if (proxy->orig_fops->compat_ioctl)
		ret = proxy->orig_fops->compat_ioctl(file, cmd, arg);
	else
		ret = -ENOTTY;
	srcu_read_unlock(&kasumi_proxy_srcu, srcu_idx);
	return ret;
}
#endif

static KASUMI_NOCFI loff_t kasumi_mount_proxy_llseek(struct file *file,
						     loff_t offset, int whence)
{
	struct kasumi_mount_file_proxy *proxy = container_of(
	    file->f_op, struct kasumi_mount_file_proxy, proxy_fops);
	loff_t ret;

	if (proxy->kind == KASUMI_PROC_PROXY_MAPS)
		return -ESPIPE;
	if (whence != SEEK_SET && whence != SEEK_CUR && whence != SEEK_END)
		return -EINVAL;
	if (whence == SEEK_SET && offset < 0)
		return -EINVAL;
	mutex_lock(&proxy->stream_lock);
	if (offset || whence == SEEK_END) {
		ret = kasumi_mount_proxy_prepare_mountinfo(proxy, file);
		if (ret)
			goto unlock;
	}
	if (proxy->mountinfo_snapshot)
		ret = generic_file_llseek_size(
		    file, offset, whence, MAX_LFS_FILESIZE,
		    (proxy->kind == KASUMI_PROC_PROXY_MOUNTS
			 ? proxy->mountinfo_snapshot->mounts_len
			 : proxy->mountinfo_snapshot->len));
	else
		ret = proxy->orig_fops->llseek
			  ? proxy->orig_fops->llseek(file, offset, whence)
			  : -ESPIPE;
unlock:
	mutex_unlock(&proxy->stream_lock);
	return ret;
}

static KASUMI_NOCFI __poll_t
kasumi_mount_proxy_poll(struct file *file, struct poll_table_struct *wait)
{
	struct kasumi_mount_file_proxy *proxy = container_of(
	    file->f_op, struct kasumi_mount_file_proxy, proxy_fops);
	__poll_t mask = EPOLLIN | EPOLLRDNORM;
	u64 generation;
	bool cached;

	mutex_lock(&proxy->stream_lock);
	kasumi_fake_mi_poll_wait(file, wait);
	cached = proxy->mountinfo_snapshot || kasumi_fake_mi_cached();
	if (proxy->mountinfo_error && !cached) {
		mask = EPOLLERR;
	} else if (!cached && proxy->orig_fops->poll) {
		mask = proxy->orig_fops->poll(file, wait);
	}
	generation = kasumi_fake_mi_generation();
	if (proxy->stream_generation != generation) {
		proxy->stream_generation = generation;
		mask |= EPOLLERR | EPOLLPRI;
	}
	mutex_unlock(&proxy->stream_lock);
	return mask;
}

static KASUMI_NOCFI int kasumi_mount_proxy_release(struct inode *inode, struct file *file)
{
	struct kasumi_mount_file_proxy *proxy =
		container_of(file->f_op, struct kasumi_mount_file_proxy, proxy_fops);
	const struct file_operations *orig_fops = proxy->orig_fops;
	int ret = 0;
	int srcu_idx;

	srcu_idx = srcu_read_lock(&kasumi_proxy_srcu);
	atomic_set(&proxy->state, KASUMI_PROXY_STATE_RELEASED);
	spin_lock(&kasumi_proxy_list_lock);
	list_del_init(&proxy->node);
	spin_unlock(&kasumi_proxy_list_lock);
	atomic_dec(&kasumi_proxy_live);

	WRITE_ONCE(file->f_mode, proxy->orig_f_mode);
	if (orig_fops->release)
		ret = orig_fops->release(inode, file);
	/* A poll before the initial snapshot may still reference this
	 * namespace. */
	kasumi_fake_mi_put_ns(proxy->original_mnt_ns);
	kasumi_fake_mi_put_snapshot(proxy->mountinfo_snapshot);

	/* Keep the live proxy's THIS_MODULE reference for __fput(), but stop
	 * __fput() from touching proxy storage after this callback returns.
	 */
	WRITE_ONCE(file->f_op, &kasumi_closed_proxy_fops);
	fops_put(orig_fops);
	srcu_read_unlock(&kasumi_proxy_srcu, srcu_idx);
	kasumi_mount_proxy_stream_free(proxy);
	kfree(proxy);
	return ret;
}

static int kasumi_mount_proxy_install_file(
	struct file *file, enum kasumi_proc_proxy_kind kind,
	enum kasumi_policy_scope scope)
{
	struct kasumi_mount_file_proxy *proxy;
	const struct file_operations *orig_fops;
	const struct file_operations *new_fops;
	if (!file || kind == KASUMI_PROC_PROXY_NONE ||
	    atomic_read(&kasumi_proxy_shutdown))
		return -ESHUTDOWN;
	if ((kind == KASUMI_PROC_PROXY_MOUNTINFO ||
	     kind == KASUMI_PROC_PROXY_MOUNTS) &&
	    scope != KASUMI_POLICY_SCOPE_SPOOF)
		return -EINVAL;
	if (kind == KASUMI_PROC_PROXY_MAPS &&
	    scope != KASUMI_POLICY_SCOPE_VIEW &&
	    scope != KASUMI_POLICY_SCOPE_SPOOF)
		return -EINVAL;
	orig_fops = READ_ONCE(file->f_op);
	if (!orig_fops || orig_fops->release == kasumi_mount_proxy_release)
		return -EALREADY;
	proxy = kzalloc(sizeof(*proxy), GFP_ATOMIC);
	if (!proxy)
		return -ENOMEM;

	proxy->orig_fops = orig_fops;
	proxy->kind = kind;
	proxy->scope = scope;
	proxy->orig_f_mode = READ_ONCE(file->f_mode);
	proxy->proxy_fops = *orig_fops;
	/* Pin module text and proxy storage through VFS dispatch and ->release.
	 * An open proc proxy fd intentionally makes delete_module() return
	 * -EWOULDBLOCK until the fd closes.
	 */
	proxy->proxy_fops.owner = THIS_MODULE;
	if (proxy->orig_fops->read)
		proxy->proxy_fops.read = kasumi_mount_proxy_read;
	proxy->proxy_fops.read_iter = kasumi_mount_proxy_read_iter;
	proxy->proxy_fops.splice_read = (kind == KASUMI_PROC_PROXY_MOUNTINFO ||
					 kind == KASUMI_PROC_PROXY_MOUNTS) &&
						orig_fops->splice_read
					    ? kasumi_mount_proxy_splice_read
					    : NULL;
	proxy->proxy_fops.llseek = kasumi_mount_proxy_llseek;
	if (kind == KASUMI_PROC_PROXY_MOUNTINFO ||
	    kind == KASUMI_PROC_PROXY_MOUNTS)
		proxy->proxy_fops.poll = kasumi_mount_proxy_poll;
	if (kind == KASUMI_PROC_PROXY_MAPS) {
		proxy->proxy_fops.unlocked_ioctl = kasumi_mount_proxy_ioctl;
#ifdef CONFIG_COMPAT
		proxy->proxy_fops.compat_ioctl = kasumi_mount_proxy_compat_ioctl;
#endif
	}
	proxy->proxy_fops.release = kasumi_mount_proxy_release;
	INIT_LIST_HEAD(&proxy->node);
	atomic_set(&proxy->state, KASUMI_PROXY_STATE_OPEN);
	atomic_set(&proxy->filter_invalidated, 0);
	mutex_init(&proxy->stream_lock);
	proxy->stream_orig_pos = 0;
	proxy->stream_user_pos = 0;
	proxy->stream_generation = kasumi_fake_mi_generation();
	proxy->stream_failed = false;

	spin_lock(&kasumi_proxy_list_lock);
	/* Fd installation has not published file yet, but keep this comparison under
	 * the same lock as list publication so duplicate installers cannot
	 * overwrite and leak one another.
	 */
	if (atomic_read(&kasumi_proxy_shutdown) ||
	    READ_ONCE(file->f_op) != orig_fops) {
		spin_unlock(&kasumi_proxy_list_lock);
		kfree(proxy);
		return -EAGAIN;
	}
	new_fops = fops_get(&proxy->proxy_fops);
	if (!new_fops) {
		spin_unlock(&kasumi_proxy_list_lock);
		kfree(proxy);
		return -ENOENT;
	}
	list_add(&proxy->node, &kasumi_proxy_list);
	atomic_inc(&kasumi_proxy_live);
	if (kind == KASUMI_PROC_PROXY_MAPS)
		WRITE_ONCE(file->f_mode,
			   proxy->orig_f_mode & ~(FMODE_LSEEK | FMODE_PREAD));
	else
		WRITE_ONCE(file->f_mode,
			   proxy->orig_f_mode & ~FMODE_PREAD);
	WRITE_ONCE(file->f_op, new_fops);
	spin_unlock(&kasumi_proxy_list_lock);

	kasumi_log("proc_proxy: installed kind=%d pid=%d comm=%s\n",
		 kind, task_pid_nr(current), current->comm);
	return 0;
}

static KASUMI_NOCFI void kasumi_mount_proxy_drain(void)
{
	struct kasumi_mount_file_proxy *p, *tmp;
	LIST_HEAD(stale_proxies);

	atomic_set(&kasumi_proxy_shutdown, 1);

	/* Every installed proxy holds THIS_MODULE through its fops owner, so
	 * module exit cannot begin until its release path removes it here.
	 */
	synchronize_srcu(&kasumi_proxy_srcu);
	spin_lock(&kasumi_proxy_list_lock);
	list_splice_init(&kasumi_proxy_list, &stale_proxies);
	spin_unlock(&kasumi_proxy_list_lock);
	list_for_each_entry_safe(p, tmp, &stale_proxies, node) {
		WARN_ON_ONCE(atomic_read(&p->state) == KASUMI_PROXY_STATE_OPEN);
		list_del_init(&p->node);
		kasumi_mount_proxy_stream_free(p);
		kfree(p);
	}
}


static int kasumi_parse_maps_line(const char *line, size_t line_len,
				  unsigned long *start, unsigned long *end,
				  char *flags, unsigned long *pgoff,
				  unsigned long *dev, unsigned long *ino,
				  const char **pathname)
{
	unsigned int ma, mi;
	const char *p = line;
	char *endptr;

	if (line_len < 40)
		return -1;
	*start = simple_strtoul(p, &endptr, 16);
	if (endptr == p || *endptr != '-')
		return -1;
	p = endptr + 1;
	*end = simple_strtoul(p, &endptr, 16);
	if (endptr == p || *endptr != ' ')
		return -1;
	p = endptr + 1;
	flags[0] = p[0];
	flags[1] = p[1];
	flags[2] = p[2];
	flags[3] = p[3];
	flags[4] = '\0';
	p += 4;
	if (*p != ' ')
		return -1;
	*pgoff = simple_strtoul(p + 1, &endptr, 16);
	p = endptr;
	if (*p != ' ')
		return -1;
	ma = (unsigned int)simple_strtoul(p + 1, &endptr, 16);
	if (*endptr != ':')
		return -1;
	mi = (unsigned int)simple_strtoul(endptr + 1, &endptr, 16);
	*dev = (unsigned long)MKDEV(ma, mi);
	p = endptr;
	if (*p != ' ')
		return -1;
	*ino = simple_strtoul(p + 1, &endptr, 10);
	p = endptr;
	while (*p == ' ')
		p++;
	*pathname = p;
	return 0;
}

static bool kasumi_maps_line_looks_like_header(const char *line,
					       size_t line_len)
{
	size_t i = 0;

	while (i < line_len && isxdigit(line[i]))
		i++;
	return i > 0 && i < line_len && line[i] == '-';
}

static int kasumi_filter_maps_lines(const char *src, size_t len,
				    char *dst, size_t dst_size, size_t *written,
				    bool *changed, bool *valid,
				    enum kasumi_policy_scope scope)
{
	size_t in = 0, out = 0;
	struct kasumi_maps_rule_entry *r;
	const char *pathname;
	char replacement_path[KSM_MAX_LEN_PATHNAME];
	char header[128];
	char flags[5];
	unsigned long start, end, pgoff, dev, ino;
	unsigned long spoof_ino, spoof_dev;
	size_t path_len, original_path_len, pathname_offset;
	int header_len;
	bool have_replacement_path;
	bool line_changed;
	bool spoof = scope == KASUMI_POLICY_SCOPE_SPOOF;

	if (written)
		*written = 0;
	if (changed)
		*changed = false;
	if (valid)
		*valid = true;
	if (!src || !dst || !written)
		return -EINVAL;

	while (in < len) {
		size_t line_start = in;
		size_t line_len;
		bool complete_line;

		while (in < len && src[in] != '\n')
			in++;
		complete_line = in < len && src[in] == '\n';
		line_len = in - line_start;
		if (complete_line)
			line_len++;
		if (!complete_line) {
			if (valid)
				*valid = false;
			return -EINVAL;
		}

		if (kasumi_parse_maps_line(src + line_start, line_len, &start,
					   &end, flags, &pgoff, &dev, &ino,
					   &pathname) != 0) {
			/* smaps metadata is intentionally passed through. A line that
			 * starts like a VMA header but cannot be parsed is unsafe to expose.
			 */
			if (kasumi_maps_line_looks_like_header(src + line_start,
						       line_len)) {
				if (valid)
					*valid = false;
				return -EINVAL;
			}
			if (out > dst_size || line_len > dst_size - out)
				return -ENOSPC;
			memcpy(dst + out, src + line_start, line_len);
			out += line_len;
			in++;
			continue;
		}

		pathname_offset = (size_t)(pathname - src);
		if (pathname_offset > line_start + line_len - 1)
			return -EINVAL;
		original_path_len = line_start + line_len - 1 - pathname_offset;
		spoof_ino = ino;
		spoof_dev = dev;
		have_replacement_path = false;
		replacement_path[0] = '\0';

		if (spoof) {
			mutex_lock(&kasumi_maps_mutex);
			list_for_each_entry(r, &kasumi_maps_rules, list) {
				if (r->target_ino != ino)
					continue;
				if (r->target_dev != 0 && r->target_dev != dev)
					continue;
				spoof_ino = r->spoofed_ino;
				spoof_dev = r->spoofed_dev;
				/* Do not retain a rule-owned pointer after unlocking. */
				strscpy(replacement_path, r->spoofed_pathname,
					sizeof(replacement_path));
				have_replacement_path = true;
				break;
			}
			mutex_unlock(&kasumi_maps_mutex);
		}

		if (have_replacement_path) {
			path_len = strnlen(replacement_path,
					   sizeof(replacement_path));
			line_changed = spoof_ino != ino || spoof_dev != dev ||
				path_len != original_path_len ||
				memcmp(replacement_path, src + pathname_offset,
				       min(path_len, original_path_len)) != 0;
		} else {
			path_len = original_path_len;
			line_changed = spoof_ino != ino || spoof_dev != dev;
		}

		if (!line_changed) {
			if (out > dst_size || line_len > dst_size - out)
				return -ENOSPC;
			memcpy(dst + out, src + line_start, line_len);
			out += line_len;
			in++;
			continue;
		}

		header_len = scnprintf(header, sizeof(header),
				       "%08lx-%08lx %s %08lx %02x:%02x %lu ",
				       start, end, flags, pgoff,
				       (unsigned int)MAJOR(spoof_dev),
				       (unsigned int)MINOR(spoof_dev), spoof_ino);
		if (header_len <= 0 || header_len >= sizeof(header)) {
			if (valid)
				*valid = false;
			return -EINVAL;
		}
		if (out > dst_size || (size_t)header_len + 1 > dst_size - out ||
		    path_len > dst_size - out - (size_t)header_len - 1)
			return -ENOSPC;
		memcpy(dst + out, header, header_len);
		out += (size_t)header_len;
		if (path_len > 0) {
			if (have_replacement_path)
				memcpy(dst + out, replacement_path, path_len);
			else
				memcpy(dst + out, src + pathname_offset, path_len);
			out += path_len;
		}
		dst[out++] = '\n';
		if (changed)
			*changed = true;
		in++;
	}

	*written = out;
	return 0;
}

/*
 * get_vfs_caps_from_disk kretprobe (cold, exec path only).  When a redirected
 * setcap binary is exec'd, the kernel reads its file capabilities off the
 * *visible* dentry, which is our synthetic vnode with no on-disk
 * security.capability, so the read misses and the binary would lose its caps.
 * The source's caps were parsed and stashed on the vnode at create time; here
 * we simply replay them (atomic-safe: pure copy) and report success.
 *
 * Argument layout follows get_vfs_caps_from_disk():
 *   < 5.12: (dentry, cpu_caps)              -> reg0, reg1
 *  >= 5.12: (idmap/userns, dentry, cpu_caps)-> reg1, reg2
 */
static int kasumi_get_vfs_caps_entry(struct kretprobe_instance *ri,
				     struct pt_regs *regs)
{
	struct kasumi_fscap_ri_data *d = (void *)ri->data;
	const struct dentry *dentry;

	d->have = false;
	d->out = NULL;
	if (!READ_ONCE(kasumi_fscaps_enabled))
		return 0;
#if defined(__aarch64__)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	dentry = (const struct dentry *)regs->regs[1];
	d->out = (struct cpu_vfs_cap_data *)regs->regs[2];
#else
	dentry = (const struct dentry *)regs->regs[0];
	d->out = (struct cpu_vfs_cap_data *)regs->regs[1];
#endif
#elif defined(__x86_64__)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	dentry = (const struct dentry *)regs->si;
	d->out = (struct cpu_vfs_cap_data *)regs->dx;
#else
	dentry = (const struct dentry *)regs->di;
	d->out = (struct cpu_vfs_cap_data *)regs->si;
#endif
#else
	dentry = NULL;
	d->out = NULL;
#endif
	if (!dentry || !d->out)
		return 0;
	if (kasumi_vnode_peek_caps(dentry, &d->caps))
		d->have = true;
	return 0;
}

static int kasumi_get_vfs_caps_ret(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	struct kasumi_fscap_ri_data *d = (void *)ri->data;

	if (!d->have || !d->out)
		return 0;
	*d->out = d->caps;
	/* Report success (0) so the caller applies the replayed caps regardless of
	 * the miss the real read returned on the synthetic inode. */
#if defined(__aarch64__)
	regs->regs[0] = 0;
#elif defined(__x86_64__)
	regs->ax = 0;
#endif
	return 0;
}

static struct kretprobe kasumi_krp_get_vfs_caps = {
	.entry_handler = kasumi_get_vfs_caps_entry,
	.handler = kasumi_get_vfs_caps_ret,
	.data_size = sizeof(struct kasumi_fscap_ri_data),
	.maxactive = 64,
};

void kasumi_proc_read_hooks_init(void)
{
	unsigned long readlink_addr = kasumi_lookup_name("vfs_readlink");
	unsigned long fd_install_addr =
		kasumi_lookup_name_quiet("fd_install");
	unsigned long internal_fd_install_addr =
		kasumi_lookup_name_quiet("__fd_install");
	unsigned long caps_addr = kasumi_lookup_name("get_vfs_caps_from_disk");
	bool use_proxy_filter = false;

	atomic_set(&kasumi_proxy_shutdown, 0);
	atomic_set(&kasumi_proxy_live, 0);
	kasumi_ns_id_seed = (u32)(unsigned long)&kasumi_krp_vfs_readlink ^
			    (u32)((unsigned long)&kasumi_krp_vfs_readlink >> 32);

	if (readlink_addr) {
		kasumi_krp_vfs_readlink.kp.addr =
			(kprobe_opcode_t *)readlink_addr;
		if (!register_kretprobe(&kasumi_krp_vfs_readlink)) {
			kasumi_proc_ns_readlink_registered = 1;
			pr_info("Kasumi: aggressive mount namespace link projection ready\n");
		} else {
			pr_warn("Kasumi: register_kretprobe(vfs_readlink) failed\n");
		}
	} else {
		pr_warn("Kasumi: vfs_readlink not found, aggressive mount hide unavailable\n");
	}

	if (caps_addr) {
		kasumi_krp_get_vfs_caps.kp.addr = (kprobe_opcode_t *)caps_addr;
		if (register_kretprobe(&kasumi_krp_get_vfs_caps) == 0) {
			kasumi_fscap_kretprobe_registered = 1;
			pr_info("Kasumi: source file-capability replay via get_vfs_caps_from_disk\n");
		} else {
			pr_warn("Kasumi: register_kretprobe(get_vfs_caps_from_disk) failed\n");
		}
	} else {
		pr_warn("Kasumi: get_vfs_caps_from_disk not found, redirected fscaps disabled\n");
	}

	if (internal_fd_install_addr) {
		kasumi_kp_internal_fd_install.addr =
		    (kprobe_opcode_t *)internal_fd_install_addr;
		kasumi_kp_internal_fd_install.pre_handler =
		    kasumi_internal_fd_install_pre;
		if (!register_kprobe(&kasumi_kp_internal_fd_install)) {
			kasumi_internal_fd_install_registered = true;
			use_proxy_filter = true;
		} else {
			pr_warn(
			    "Kasumi: register_kprobe(__fd_install) failed\n");
		}
	}
	if (fd_install_addr) {
		kasumi_kp_fd_install.addr = (kprobe_opcode_t *)fd_install_addr;
		kasumi_kp_fd_install.pre_handler = kasumi_fd_install_pre;
		if (!register_kprobe(&kasumi_kp_fd_install)) {
			kasumi_fd_install_registered = true;
			use_proxy_filter = true;
		} else {
			pr_warn("Kasumi: register_kprobe(fd_install) failed\n");
		}
	}
	if (!internal_fd_install_addr && !fd_install_addr)
		pr_warn("Kasumi: no fd-install ingress found\n");

	if (use_proxy_filter) {
		kasumi_proc_proxy_registered = 1;
		if (kasumi_internal_fd_install_registered &&
		    kasumi_fd_install_registered)
			pr_info("Kasumi: proc views filtered by __fd_install+fd_install fop proxy\n");
		else if (kasumi_internal_fd_install_registered)
			pr_info("Kasumi: proc views filtered by __fd_install fop proxy\n");
		else
			pr_info("Kasumi: proc views filtered by fd_install fop proxy\n");
	}

}

void kasumi_proc_read_hooks_stop_new(void)
{
	atomic_set(&kasumi_proxy_shutdown, 1);
	if (kasumi_internal_fd_install_registered) {
		unregister_kprobe(&kasumi_kp_internal_fd_install);
		kasumi_internal_fd_install_registered = false;
	}
	if (kasumi_fd_install_registered) {
		unregister_kprobe(&kasumi_kp_fd_install);
		kasumi_fd_install_registered = false;
	}
	if (kasumi_proc_ns_readlink_registered) {
		unregister_kretprobe(&kasumi_krp_vfs_readlink);
		kasumi_proc_ns_readlink_registered = 0;
	}
	if (kasumi_fscap_kretprobe_registered) {
		unregister_kretprobe(&kasumi_krp_get_vfs_caps);
		kasumi_fscap_kretprobe_registered = 0;
	}
	kasumi_proc_proxy_registered = 0;
}

unsigned int kasumi_proc_proxy_live(void)
{
	return (unsigned int)atomic_read(&kasumi_proxy_live);
}

void kasumi_proc_read_hooks_exit(void)
{
	kasumi_proc_read_hooks_stop_new();
	/* Proxy fops pin THIS_MODULE, so final destruction starts only after all
	 * installed proc files have naturally reached ->release.
	 */
	kasumi_mount_proxy_drain();
	WARN_ON_ONCE(atomic_read(&kasumi_proxy_live));

	{
		struct kasumi_maps_rule_entry *e, *tmp;

		mutex_lock(&kasumi_maps_mutex);
		list_for_each_entry_safe(e, tmp, &kasumi_maps_rules, list) {
			list_del(&e->list);
			kfree(e);
		}
		mutex_unlock(&kasumi_maps_mutex);
	}

}
