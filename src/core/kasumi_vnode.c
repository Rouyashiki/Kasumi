/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - real-superblock virtual inode backend (Tier 3 data plane).
 *
 * See kasumi_vnode.h.  This file implements only the per-inode data plane:
 * identity projection (getattr), and delegation of open/read/write/mmap/ioctl/
 * splice/xattr/symlink to the pinned data source. Parent-directory lookup
 * and iteration callbacks manufacture these inodes.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include <linux/fs.h>
#include <linux/falloc.h>
#include <linux/overflow.h>
#include <linux/fs_stack.h>
#include <linux/fsnotify.h>
#include <linux/hashtable.h>
#include <linux/kprobes.h>
#include <linux/refcount.h>
#include <linux/security.h>
#include <linux/file.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <linux/xattr.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <linux/backing-file.h>
#endif

#include "kasumi_base.h"
#include "kasumi_dirhijack.h"
#include "kasumi_iop_override.h"
#include "kasumi_exec_view.h"
#include "kasumi_dir_view.h"
#include "kasumi_fop_override.h"
#include "kasumi_file_lock.h"
#include "kasumi_io_notify.h"
#include "kasumi_path_policy.h"
#include "kasumi_runtime.h"
#include "kasumi_sop_shadow.h"
#include "kasumi_types.h"
#include "kasumi_vnode.h"

/* i_op->getattr / *attr first argument varies across kernel versions. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
#define KVN_IDMAP_ARG		struct mnt_idmap *idmap,
#define KVN_IDMAP_CALL		idmap,
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
#define KVN_IDMAP_ARG		struct user_namespace *userns,
#define KVN_IDMAP_CALL		userns,
#else
#define KVN_IDMAP_ARG
#define KVN_IDMAP_CALL
#endif

/*
 * Idmap of the *source* mount for a delegated create/mkdir/... — the redirect
 * writes through the source's own mount, so the source idmap governs uid/gid
 * mapping, not the visible idmap the VFS handed our op.  Trailing comma so it
 * drops cleanly on pre-5.12 kernels that took no idmap argument.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
#define KVN_SRC_IDMAP(mnt)	mnt_idmap(mnt),
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
#define KVN_SRC_IDMAP(mnt)	mnt_user_ns(mnt),
#else
#define KVN_SRC_IDMAP(mnt)
#endif

static const struct inode_operations kasumi_vnode_file_iops;
static const struct inode_operations kasumi_vnode_dir_iops;
static const struct file_operations kasumi_vnode_file_fops;
static const struct file_operations kasumi_vnode_dir_fops;
static const struct file_operations kasumi_vnode_special_fops;

static void kasumi_vnode_copyattr(struct inode *inode, struct inode *source);
static void kasumi_vnode_copyattr_locked(struct inode *inode, struct inode *source);
static void kasumi_vnode_copyattr_exec(struct inode *inode, struct inode *source);
static int kasumi_vnode_clone_sid(struct inode *vnode, struct inode *source);
static struct inode *kasumi_vnode_allocate(struct super_block *sb,
	struct kasumi_inode_identity *identity);
static int kasumi_vnode_attach_source(struct inode *inode,
	const struct path *source, u8 flags);

/*
 * A dedicated i_rwsem lockdep class for every Kasumi vnode.  The vnode lives on
 * the *visible* (real) superblock — the same fs type as its source — so without
 * this a delegated vfs_unlink/vfs_rmdir on the source, run from inside our own
 * ->unlink/->rmdir while the VFS holds the visible victim's i_rwsem, would look
 * to LOCKDEP like same-class recursive locking (a false positive: one task,
 * strict visible->source order, no cycle).  Giving vnodes their own class is
 * what a stacking filesystem gets implicitly from being its own fs type.
 * Compiles out entirely without CONFIG_LOCKDEP.
 */
static struct lock_class_key kasumi_vnode_i_mutex_key;

static DEFINE_HASHTABLE(kasumi_vnode_cache, 8);
static DEFINE_SPINLOCK(kasumi_vnode_cache_lock);

static struct inode *kasumi_vnode_cached_locked(struct super_block *sb,
					       const struct path *source,
					       unsigned long ino, u8 flags)
{
	struct kasumi_vnode_info *info;
	struct inode *inode;
	unsigned long key = (unsigned long)sb ^ (unsigned long)source->dentry;

	hash_for_each_possible(kasumi_vnode_cache, info, cache_node, key) {
		if (info->inode->i_sb != sb || info->v_ino != ino ||
		    info->flags != flags || info->source.mnt != source->mnt ||
		    info->source.dentry != source->dentry)
			continue;
		inode = igrab(info->inode);
		if (inode)
			return inode;
	}
	return NULL;
}

static struct inode *kasumi_vnode_cached(struct super_block *sb,
				       const struct path *source,
				       unsigned long ino, u8 flags)
{
	struct inode *inode;

	spin_lock(&kasumi_vnode_cache_lock);
	inode = kasumi_vnode_cached_locked(sb, source, ino, flags);
	spin_unlock(&kasumi_vnode_cache_lock);
	return inode;
}

static struct inode *kasumi_vnode_cache_publish(struct inode *inode)
{
	struct kasumi_vnode_info *info = inode->i_private;
	struct inode *existing;
	unsigned long key =
	    (unsigned long)inode->i_sb ^ (unsigned long)info->source.dentry;

	spin_lock(&kasumi_vnode_cache_lock);
	existing = kasumi_vnode_cached_locked(inode->i_sb, &info->source,
					     info->v_ino, info->flags);
	if (!existing)
		hash_add(kasumi_vnode_cache, &info->cache_node, key);
	spin_unlock(&kasumi_vnode_cache_lock);
	if (existing) {
		iput(inode);
		return existing;
	}
	return inode;
}

bool kasumi_vnode_is_ours(const struct inode *inode)
{
	const struct inode_operations *iop;

	if (!inode)
		return false;
	iop = READ_ONCE(inode->i_op);
	if (iop == &kasumi_vnode_file_iops || iop == &kasumi_vnode_dir_iops)
		return true;
	iop = kasumi_iop_original_iops(inode);
	return iop == &kasumi_vnode_file_iops ||
	       iop == &kasumi_vnode_dir_iops;
}

const struct path *kasumi_vnode_caps_source(const struct dentry *dentry)
{
	const struct path *source = NULL;
	struct inode *inode;
	struct kasumi_vnode_info *info;

	/* The caller's dentry reference pins every immutable source path. */
	while (dentry && (inode = d_inode(dentry)) &&
	       kasumi_vnode_is_ours(inode)) {
		info = inode->i_private;
		if (!info || !info->source.dentry)
			return ERR_PTR(-ENODATA);
		if (!info->source.mnt)
			return ERR_PTR(-EIO);
		source = &info->source;
		dentry = source->dentry;
	}
	return source;
}

void kasumi_vnode_free_info(struct inode *inode)
{
	struct kasumi_vnode_info *info;
	bool sop_vnode_ref;

	if (!inode || !kasumi_vnode_is_ours(inode))
		return;
	info = inode->i_private;
	if (!info)
		return;
	spin_lock(&kasumi_vnode_cache_lock);
	hash_del(&info->cache_node);
	spin_unlock(&kasumi_vnode_cache_lock);
	sop_vnode_ref = info->sop_vnode_ref;
	kasumi_io_notify_detach(info->io_notify);
	if (info->source.dentry)
		kasumi_path_put(&info->source);
	kfree(info->visible_path);
	kasumi_identity_hold_free(info->identity_hold);
	kasumi_identity_domain_put(info->identity_domain);
	kasumi_identity_put(info->identity);
	inode->i_private = NULL;
	kfree(info);
	if (sop_vnode_ref)
		kasumi_sop_vnode_put(inode->i_sb);
}

static int KASUMI_NOCFI kasumi_vnode_read_sid(struct inode *inode, u32 *sid)
{
#if !IS_ENABLED(CONFIG_SECURITY_SELINUX)
	*sid = 0;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
	struct lsm_prop prop = {};

	if (!kasumi_security_inode_getlsmprop)
		return -EOPNOTSUPP;
	kasumi_security_inode_getlsmprop(inode, &prop);
	*sid = prop.selinux.secid;
#else
	if (!kasumi_security_inode_getsecid)
		return -EOPNOTSUPP;
	kasumi_security_inode_getsecid(inode, sid);
#endif
	return 0;
}

static int kasumi_vnode_refresh_sid(struct inode *inode, struct inode *source,
				   bool may_block)
{
	struct kasumi_vnode_info *info = inode->i_private;
	u32 current_sid, source_sid;
	int ret;

	ret = kasumi_vnode_read_sid(source, &source_sid);
	if (!ret)
		ret = kasumi_vnode_read_sid(inode, &current_sid);
	if (ret || source_sid == current_sid)
		return ret;
	if (!may_block)
		return -ECHILD;
	mutex_lock(&info->label_lock);
	ret = kasumi_vnode_clone_sid(inode, source);
	if (!ret)
		ret = kasumi_vnode_read_sid(source, &source_sid);
	if (!ret)
		ret = kasumi_vnode_read_sid(inode, &current_sid);
	if (!ret && source_sid != current_sid)
		ret = -EAGAIN;
	mutex_unlock(&info->label_lock);
	return ret;
}

int kasumi_vnode_refresh_label(const struct dentry *dentry)
{
	struct inode *inode = dentry ? d_inode(dentry) : NULL;
	struct kasumi_vnode_info *info;

	if (!kasumi_vnode_is_ours(inode))
		return 0;
	info = inode->i_private;
	if (!info || !info->source.dentry)
		return 0;
	if (!d_inode(info->source.dentry))
		return -ENOENT;
	return kasumi_vnode_refresh_sid(inode, d_inode(info->source.dentry), true);
}

int kasumi_vnode_source_path(const struct dentry *dentry, struct path *source)
{
	struct inode *inode = dentry ? d_inode(dentry) : NULL;
	struct kasumi_vnode_info *info;
	int ret;

	memset(source, 0, sizeof(*source));
	if (!kasumi_vnode_is_ours(inode))
		return 0;
	info = inode->i_private;
	if (!info || !info->source.dentry)
		return 0;
	if (!info->source.mnt)
		return -EIO;
	ret = kasumi_vnode_refresh_label(dentry);
	if (ret)
		return ret;
	*source = info->source;
	kasumi_path_get(source);
	return 1;
}

/* ---- identity ---------------------------------------------------------- */

static int KASUMI_NOCFI kasumi_vnode_getattr(KVN_IDMAP_ARG const struct path *path,
					     struct kstat *stat,
					     u32 request_mask,
					     unsigned int query_flags)
{
	struct inode *vi = d_inode(path->dentry);
	struct kasumi_vnode_info *info = vi ? vi->i_private : NULL;
	int ret;

	if (!info)
		return -EIO;

	/* Live attributes come from the source; identity is projected so that
	 * stat/fstat/maps/ls all report the same (dev, ino) pair — dev is this
	 * inode's real superblock (the visible path's filesystem), ino is the
	 * scheme-A stable value captured in the rule. */
	if (!info->source.dentry || !kasumi_vfs_getattr) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		generic_fillattr(KVN_IDMAP_CALL request_mask, vi, stat);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
		generic_fillattr(KVN_IDMAP_CALL vi, stat);
#else
		generic_fillattr(vi, stat);
#endif
		stat->ino = info->v_ino;
		stat->dev = vi->i_sb->s_dev;
		/* A special (char/blk/fifo) wrapper is minted S_IFREG; present the
		 * source's real type and rdev even on this source-less fallback. */
		if (info->special_mode) {
			stat->mode = (stat->mode & 07777) | (info->special_mode & S_IFMT);
			stat->rdev = info->special_rdev;
		}
		return 0;
	}

	ret = kasumi_vnode_refresh_sid(vi, d_inode(info->source.dentry), true);
	if (ret)
		return ret;
	ret = kasumi_vfs_getattr_unprojected(&info->source, stat, request_mask,
					     query_flags & AT_STATX_SYNC_TYPE);
	if (ret == 0) {
		kasumi_vnode_copyattr(vi, d_inode(info->source.dentry));
		stat->ino = info->v_ino;
		stat->dev = vi->i_sb->s_dev;
	}
	return ret;
}

static ssize_t KASUMI_NOCFI kasumi_vnode_listxattr(struct dentry *dentry,
						char *buffer, size_t size)
{
	typeof(vfs_listxattr) *native = (void *)kasumi_vfs_listxattr_addr;
	struct kasumi_internal_vfs_guard guard;
	struct path source;
	ssize_t ret;

	ret = kasumi_vnode_source_path(dentry, &source);
	if (ret <= 0)
		return ret;
	if (!native) {
		path_put(&source);
		return -EOPNOTSUPP;
	}
	kasumi_vfs_internal_enter(&guard);
	ret = native(source.dentry, buffer, size);
	kasumi_vfs_internal_leave(&guard);
	path_put(&source);
	return ret;
}

static const char *KASUMI_NOCFI kasumi_vnode_get_link(struct dentry *dentry,
						      struct inode *inode,
						      struct delayed_call *done)
{
	struct kasumi_vnode_info *info = inode ? inode->i_private : NULL;
	struct inode *r_inode;

	if (!info || !info->source.dentry)
		return ERR_PTR(-ECHILD);
	r_inode = d_inode(info->source.dentry);
	if (!r_inode || !r_inode->i_op || !r_inode->i_op->get_link)
		return ERR_PTR(-EINVAL);
	return r_inode->i_op->get_link(dentry ? info->source.dentry : NULL,
				       r_inode, done);
}

/*
 * Delegate an attribute change (chmod/chown/utimes/truncate) to the pinned
 * source, so a redirected path is writable-through like a bind mount: the
 * source's DAC/SELinux govern, evaluated against the caller's creds inside
 * notify_change.  A pure-virtual directory has no backing store and is
 * read-only.  Mutation sink (Final Phase 1a).
 */
static int KASUMI_NOCFI kasumi_vnode_setattr(KVN_IDMAP_ARG struct dentry *dentry,
					     struct iattr *attr)
{
	struct inode *vi = d_inode(dentry);
	struct kasumi_vnode_info *info = vi ? vi->i_private : NULL;
	struct dentry *src_dentry;
	struct inode *src_inode;
	struct iattr sattr;
	int ret;

	if (!info || !info->source.dentry)
		return -EROFS;
	if (!kasumi_notify_change)
		return -EOPNOTSUPP;
	/* Sleeping callback on our static i_op table — keep the module-refcount
	 * gate up against a cooperative unload, like the create family. */
	if (!try_module_get(THIS_MODULE))
		return -ENOENT;
	src_dentry = info->source.dentry;
	src_inode = d_inode(src_dentry);
	if (!src_inode) {
		module_put(THIS_MODULE);
		return -ENOENT;
	}

	/* ATTR_FILE points at the virtual file; swap it for the opened source
	 * file so a truncate reaches the source's fs/driver, not the vnode. */
	sattr = *attr;
	if (sattr.ia_valid & ATTR_FILE) {
		struct file *rf = (sattr.ia_file &&
				   sattr.ia_file->private_data) ?
				  sattr.ia_file->private_data : NULL;
		if (rf)
			sattr.ia_file = rf;
		else
			sattr.ia_valid &= ~ATTR_FILE;
	}

	inode_lock(src_inode);
	ret = kasumi_notify_change(KVN_SRC_IDMAP(info->source.mnt)
				   src_dentry, &sattr, NULL);
	if (!ret)
		kasumi_vnode_copyattr_locked(vi, src_inode);
	inode_unlock(src_inode);
	module_put(THIS_MODULE);
	return ret;
}

/* ---- data plane: delegate to the pinned source ------------------------- */

static int KASUMI_NOCFI kasumi_vnode_sync_flags(struct file *outer,
					      struct file *real)
{
	const unsigned int mask = O_APPEND | O_NONBLOCK | O_NDELAY | O_DIRECT;
	unsigned int flags = (READ_ONCE(real->f_flags) & ~mask) |
			     (READ_ONCE(outer->f_flags) & mask);
	int ret;

	if (!((flags ^ READ_ONCE(real->f_flags)) & mask))
		return 0;
	if (((flags ^ real->f_flags) & O_APPEND) && IS_APPEND(file_inode(real)))
		return -EPERM;
	if (real->f_op->check_flags) {
		ret = real->f_op->check_flags(flags);
		if (ret)
			return ret;
	}
	spin_lock(&real->f_lock);
	real->f_flags = (real->f_flags & ~mask) | (flags & mask);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	real->f_iocb_flags = iocb_flags(real);
#endif
	spin_unlock(&real->f_lock);
	return 0;
}

static unsigned long KASUMI_NOCFI kasumi_vnode_get_unmapped_area(struct file *file,
	unsigned long addr, unsigned long len, unsigned long pgoff, unsigned long flags)
{
	struct file *real = file->private_data;

	if (!real || !real->f_op->get_unmapped_area)
		return -ENODEV;
	return real->f_op->get_unmapped_area(real, addr, len, pgoff, flags);
}

struct kasumi_vnode_fops {
	struct hlist_node node;
	unsigned int key;
	struct file_operations operations;
};

static DEFINE_HASHTABLE(kasumi_vnode_fops_cache, 6);
static DEFINE_SPINLOCK(kasumi_vnode_fops_lock);

static struct kasumi_vnode_fops *kasumi_vnode_fops_find(unsigned int key)
{
	struct kasumi_vnode_fops *entry;

	hash_for_each_possible_rcu(kasumi_vnode_fops_cache, entry, node, key) {
		if (entry->key == key)
			return entry;
	}
	return NULL;
}

static int kasumi_vnode_select_fops(struct file *file, struct file *real, bool special)
{
	const struct file_operations *source = real->f_op;
	struct kasumi_vnode_fops *entry, *candidate;
	unsigned int key = special ? 1 : 0;
#ifdef FOP_UNSIGNED_OFFSET
	fop_flags_t supported = FOP_UNSIGNED_OFFSET | FOP_MMAP_SYNC |
		FOP_BUFFER_WASYNC | FOP_DIO_PARALLEL_WRITE;

#ifdef FOP_DONTCACHE
	supported |= FOP_DONTCACHE;
#endif
	/* BUFFER_RASYNC uses ki_waitq, which kiocb_clone does not preserve.
	 * Its folio callback also bypasses the ki_complete lifetime bridge. */
	key |= (__force unsigned int)(source->fop_flags & supported) << 6;
#endif
	if (source->get_unmapped_area)
		key |= 2;
	if (source->read)
		key |= 4;
	if (source->write)
		key |= 8;
	if (source->read_iter)
		key |= 16;
	if (source->write_iter)
		key |= 32;
	rcu_read_lock();
	entry = kasumi_vnode_fops_find(key);
	rcu_read_unlock();
	if (!entry) {
		candidate = kzalloc(sizeof(*candidate), GFP_NOFS);
		if (!candidate)
			return -ENOMEM;
		candidate->key = key;
		candidate->operations = special ? kasumi_vnode_special_fops :
			kasumi_vnode_file_fops;
		if (source->get_unmapped_area)
			candidate->operations.get_unmapped_area = kasumi_vnode_get_unmapped_area;
		if (!source->read)
			candidate->operations.read = NULL;
		if (!source->write)
			candidate->operations.write = NULL;
		if (!source->read_iter)
			candidate->operations.read_iter = NULL;
		if (!source->write_iter)
			candidate->operations.write_iter = NULL;
#ifdef FOP_UNSIGNED_OFFSET
		candidate->operations.fop_flags = source->fop_flags & supported;
#endif
		spin_lock(&kasumi_vnode_fops_lock);
		rcu_read_lock();
		entry = kasumi_vnode_fops_find(key);
		rcu_read_unlock();
		if (!entry) {
			entry = candidate;
			candidate = NULL;
			hash_add_rcu(kasumi_vnode_fops_cache, &entry->node, key);
		}
		spin_unlock(&kasumi_vnode_fops_lock);
		kfree(candidate);
	}
	replace_fops(file, fops_get(&entry->operations));
	return 0;
}

/* Final module teardown runs after every vnode file reference has drained. */
void kasumi_vnode_fops_exit(void)
{
	struct kasumi_vnode_fops *entry;
	struct hlist_node *next;
	unsigned int bucket;

	synchronize_rcu();
	hash_for_each_safe(kasumi_vnode_fops_cache, bucket, next, entry, node) {
		hash_del(&entry->node);
		kfree(entry);
	}
}

static void kasumi_vnode_copy_modes(struct file *file, const struct file *real)
{
	fmode_t mask = FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE | FMODE_ATOMIC_POS |
		FMODE_STREAM | FMODE_NOWAIT | FMODE_CAN_READ | FMODE_CAN_WRITE;

#ifdef FMODE_UNSIGNED_OFFSET
	mask |= FMODE_UNSIGNED_OFFSET;
#endif
#ifdef FMODE_CAN_ODIRECT
	mask |= FMODE_CAN_ODIRECT;
#endif
#ifdef FMODE_BUF_WASYNC
	mask |= FMODE_BUF_WASYNC;
#endif
#ifdef FMODE_DIO_PARALLEL_WRITE
	mask |= FMODE_DIO_PARALLEL_WRITE;
#endif
#ifdef FMODE_CAN_ATOMIC_WRITE
	mask |= FMODE_CAN_ATOMIC_WRITE;
#endif
	file->f_mode = (file->f_mode & ~mask) | (real->f_mode & mask);
#ifdef FMODE_BUF_RASYNC
	file->f_mode &= ~FMODE_BUF_RASYNC;
#endif
#ifdef FMODE_HAS_METADATA
	file->f_mode &= ~FMODE_HAS_METADATA;
#endif
}

static int kasumi_vnode_notify_open(struct inode *inode)
{
	struct kasumi_vnode_info *info = inode->i_private;
	int error;

	mutex_lock(&info->io_notify_lock);
	error = kasumi_io_notify_get(inode, &info->source, &info->io_notify);
	mutex_unlock(&info->io_notify_lock);
	return error;
}

static void kasumi_vnode_notify_close(struct inode *inode)
{
	struct kasumi_vnode_info *info = inode->i_private;

	mutex_lock(&info->io_notify_lock);
	kasumi_io_notify_put(&info->io_notify);
	mutex_unlock(&info->io_notify_lock);
}

/* Raw vnode IDs cannot carry a mount-specific set-ID mapping. */
static bool kasumi_vnode_exec_idmap_supported(const struct path *visible,
					    const struct path *source)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	return mnt_idmap(visible->mnt) == &nop_mnt_idmap &&
	       mnt_idmap(source->mnt) == &nop_mnt_idmap;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	return mnt_user_ns(visible->mnt) == &init_user_ns &&
	       mnt_user_ns(source->mnt) == &init_user_ns;
#else
	return true;
#endif
}

static int KASUMI_NOCFI kasumi_vnode_open(struct inode *inode, struct file *file)
{
	struct kasumi_vnode_info *info = inode->i_private;
	struct file *real_file;
	int ret;

	if ((file->f_flags & __FMODE_EXEC) && !kasumi_exec_view_ready())
		return -EOPNOTSUPP;
	if (!info || !info->source.dentry)
		return -ENODEV;
	if ((file->f_flags & __FMODE_EXEC) &&
	    !kasumi_vnode_exec_idmap_supported(&file->f_path, &info->source))
		return -EOPNOTSUPP;
	if ((S_ISCHR(info->special_mode) || S_ISBLK(info->special_mode)) &&
	    ((info->source.mnt->mnt_flags & MNT_NODEV) ||
	     (info->source.mnt->mnt_sb->s_iflags & SB_I_NODEV)))
		return -EACCES;
	ret = kasumi_vnode_refresh_sid(inode, d_inode(info->source.dentry), true);
	if (ret)
		return ret;
	if (!kasumi_dentry_open)
		return -EOPNOTSUPP;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	real_file = backing_file_open(&file->f_path, file->f_flags,
				      &info->source, file->f_cred);
#else
	real_file = kasumi_dentry_open(&info->source, file->f_flags,
				       file->f_cred);
#endif
	if (IS_ERR(real_file))
		return PTR_ERR(real_file);
	ret = kasumi_vnode_select_fops(file, real_file, info->special_mode != 0);
	/* file_clone_open() reaches this callback without do_filp_open(). */
	if (!ret && (file->f_flags & __FMODE_EXEC))
		ret = kasumi_exec_file_hold(file, real_file);
	if (!ret)
		ret = kasumi_vnode_notify_open(inode);
	if (ret) {
		kasumi_exec_file_release(file);
		fput(real_file);
		return ret;
	}
	file->private_data = real_file;
	file->f_mapping = real_file->f_mapping;
	kasumi_vnode_copy_modes(file, real_file);
	if (file->f_flags & __FMODE_EXEC)
		kasumi_vnode_copyattr_exec(inode, file_inode(real_file));
	else
		kasumi_vnode_copyattr(inode, file_inode(real_file));
	kasumi_file_lock_opened();
	return 0;
}

/* Validate exec restrictions without replacing the visible file. */
struct file *kasumi_vnode_exec_open(struct file *file)
{
	struct file *real;
	int ret = 0;

	if (IS_ERR_OR_NULL(file) || !kasumi_vnode_is_ours(file_inode(file)))
		return file;
	if ((file->f_path.mnt->mnt_flags & MNT_NOEXEC) ||
	    (file->f_path.mnt->mnt_sb->s_iflags & SB_I_NOEXEC)) {
		ret = -EACCES;
		goto release;
	}
	real = file;
	while (kasumi_vnode_is_ours(file_inode(real))) {
		real = real->private_data;
		if (!real) {
			ret = -EIO;
			goto release;
		}
		if ((real->f_path.mnt->mnt_flags & MNT_NOEXEC) ||
		    (real->f_path.mnt->mnt_sb->s_iflags & SB_I_NOEXEC)) {
			ret = -EACCES;
			goto release;
		}
	}
	if (!S_ISREG(file_inode(real)->i_mode)) {
		ret = -EACCES;
		goto release;
	}
	ret = inode_permission(KVN_SRC_IDMAP(real->f_path.mnt) file_inode(real),
			       MAY_EXEC);
	if (!ret)
		return file;
release:
	fput(file);
	return ERR_PTR(ret);
}

static int KASUMI_NOCFI kasumi_vnode_release(struct inode *inode, struct file *file)
{
	struct file *real_file = file->private_data;

	if (S_ISDIR(inode->i_mode))
		kasumi_dir_view_release(file);
	if (real_file) {
		kasumi_exec_file_release(file);
		kasumi_vnode_notify_close(inode);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
		/* The outer __fput already provides a sleepable release context.
		 * Keep writeback and filesystem callbacks on the deferred path.
		 * Source and visible paths remain pinned by the outer vnode/file.
		 * Older supported KMIs restrict __fput_sync to kernel threads.
		 */
		if (kasumi_fput_sync && !(real_file->f_mode & FMODE_WRITE) &&
		    S_ISREG(file_inode(real_file)->i_mode) &&
		    !real_file->f_op->release && !real_file->f_op->fasync &&
		    !real_file->f_op->lock && !real_file->f_op->flock)
			kasumi_fput_sync(real_file);
		else
#endif
			fput(real_file);
		file->private_data = NULL;
		kasumi_file_lock_released();
	}
	return 0;
}

static loff_t kasumi_vnode_llseek(struct file *file, loff_t offset, int whence)
{
	struct file *real_file = file->private_data;
	loff_t ret;

	if (S_ISDIR(file_inode(file)->i_mode))
		return kasumi_dir_view_llseek(file, real_file,
			real_file ? kasumi_fop_original_operations(real_file) : NULL,
			offset, whence);
	if (!real_file)
		return generic_file_llseek(file, offset, whence);
	real_file->f_pos = file->f_pos;
	ret = vfs_llseek(real_file, offset, whence);
	file->f_pos = real_file->f_pos;
	return ret;
}

struct kasumi_vnode_aio {
	struct kiocb iocb;
	struct kiocb *original;
	struct file *outer;
	refcount_t refs;
	struct work_struct work;
	struct hlist_node inner_node;
	struct hlist_node outer_node;
	typeof(((struct kiocb *)0)->ki_complete) complete;
	int (*cancel)(struct kiocb *);
	struct kasumi_vnode_aio *cancel_owner;
	struct kasumi_vnode_aio *cancel_target;
	spinlock_t cancel_lock;
	long result;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0)
	long result2;
#endif
	bool legacy;
	bool end_write;
	bool completed;
	bool indexed;
};

static DEFINE_HASHTABLE(kasumi_vnode_aio_inner, 6);
static DEFINE_HASHTABLE(kasumi_vnode_aio_outer, 6);
static spinlock_t kasumi_vnode_aio_locks[64];
static struct workqueue_struct *kasumi_vnode_aio_wq;
static struct kprobe kasumi_vnode_aio_cancel_probe;
static bool kasumi_vnode_aio_cancel_registered;
static bool kasumi_vnode_aio_stopping = true;
static atomic_t kasumi_vnode_aio_active = ATOMIC_INIT(0);

static void kasumi_vnode_aio_original_complete(struct kiocb *iocb, long result
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0)
					      , long result2
#endif
);
static void kasumi_vnode_aio_complete(struct kiocb *iocb, long result
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0)
				    , long result2
#endif
);

/* Caller holds the visible i_rwsem exclusively and the source i_rwsem. */
static void kasumi_vnode_copyattr_locked(struct inode *inode, struct inode *source)
{
	struct kasumi_vnode_info *info = inode->i_private;

	spin_lock(&inode->i_lock);
	fsstack_copy_attr_all(inode, source);
	if (info->special_mode)
		inode->i_mode = S_IFREG | (source->i_mode & 07777);
	inode->i_flags |= S_NOATIME | S_NOCMTIME | S_NOSEC;
	i_size_write(inode, i_size_read(source));
	inode->i_blocks = READ_ONCE(source->i_blocks);
	spin_unlock(&inode->i_lock);
}

static void kasumi_vnode_copyattr(struct inode *inode, struct inode *source)
{
	/* Attribute refresh is optional; NOWAIT I/O must not wait on these locks. */
	if (!inode_trylock(inode))
		return;
	if (inode_trylock_shared(source)) {
		kasumi_vnode_copyattr_locked(inode, source);
		inode_unlock_shared(source);
	}
	inode_unlock(inode);
}

static void kasumi_vnode_copyattr_exec(struct inode *inode, struct inode *source)
{
	/* Serialize the set-ID tuple with source chown and native bprm_fill_uid. */
	inode_lock(inode);
	inode_lock_shared_nested(source, I_MUTEX_NONDIR2);
	kasumi_vnode_copyattr_locked(inode, source);
	inode_unlock_shared(source);
	inode_unlock(inode);
}

static void kasumi_vnode_aio_put(struct kasumi_vnode_aio *request)
{
	if (refcount_dec_and_test(&request->refs)) {
		struct kasumi_vnode_aio *owner = request->cancel_owner;

		fput(request->iocb.ki_filp);
		fput(request->outer);
		kfree(request);
		if (owner)
			kasumi_vnode_aio_put(owner);
		atomic_dec(&kasumi_vnode_aio_active);
		module_put(THIS_MODULE);
	}
}

static struct kasumi_vnode_aio *kasumi_vnode_aio_find(struct kiocb *iocb,
						    bool inner)
{
	unsigned int bucket = hash_ptr(iocb, 6);
	struct kasumi_vnode_aio *request, *found = NULL;
	unsigned long flags;

	spin_lock_irqsave(&kasumi_vnode_aio_locks[bucket], flags);
	if (inner) {
		hlist_for_each_entry(request, &kasumi_vnode_aio_inner[bucket], inner_node) {
			if (&request->iocb == iocb) {
				found = request;
				break;
			}
		}
	} else {
		hlist_for_each_entry(request, &kasumi_vnode_aio_outer[bucket], outer_node) {
			if (request->original == iocb) {
				found = request;
				break;
			}
		}
	}
	if (found)
		refcount_inc(&found->refs);
	spin_unlock_irqrestore(&kasumi_vnode_aio_locks[bucket], flags);
	return found;
}

static void kasumi_vnode_aio_index(struct kasumi_vnode_aio *request, bool add)
{
	unsigned int inner = hash_ptr(&request->iocb, 6);
	unsigned int outer = hash_ptr(request->original, 6);
	unsigned long flags;

	spin_lock_irqsave(&kasumi_vnode_aio_locks[inner], flags);
	if (add)
		hlist_add_head(&request->inner_node, &kasumi_vnode_aio_inner[inner]);
	else
		hlist_del(&request->inner_node);
	spin_unlock_irqrestore(&kasumi_vnode_aio_locks[inner], flags);
	spin_lock_irqsave(&kasumi_vnode_aio_locks[outer], flags);
	if (add)
		hlist_add_head(&request->outer_node, &kasumi_vnode_aio_outer[outer]);
	else
		hlist_del(&request->outer_node);
	spin_unlock_irqrestore(&kasumi_vnode_aio_locks[outer], flags);
}

static int KASUMI_NOCFI kasumi_vnode_aio_cancel(struct kiocb *original)
{
	struct kasumi_vnode_aio *request = kasumi_vnode_aio_find(original, false);
	int ret = -EINVAL;

	if (request) {
		unsigned long flags;
		int (*cancel)(struct kiocb *) = READ_ONCE(request->cancel);

		spin_lock_irqsave(&request->cancel_lock, flags);
		if (!request->completed && cancel)
			ret = cancel(&request->cancel_target->iocb);
		spin_unlock_irqrestore(&request->cancel_lock, flags);
		kasumi_vnode_aio_put(request);
	}
	return ret;
}

static void kasumi_vnode_aio_retire_cancel(struct kasumi_vnode_aio *request)
{
	unsigned long flags;

	if (!request->indexed)
		return;
	if (request->cancel_owner)
		request = request->cancel_owner;
	/* A source driver may free iocb->private as soon as ki_complete returns.
	 * Wait for an already running cancel, then prevent any new source call.
	 * Native ki_cancel already runs under ctx_lock and cannot synchronously
	 * reenter its own ki_complete. Preserve that native lock contract here. */
	spin_lock_irqsave(&request->cancel_lock, flags);
	request->completed = true;
	spin_unlock_irqrestore(&request->cancel_lock, flags);
}

static int kasumi_vnode_aio_cancel_pre(struct kprobe *probe, struct pt_regs *regs)
{
#ifdef CONFIG_ARM64
	struct kasumi_vnode_aio *request;
	struct kasumi_vnode_aio *owner;
	unsigned long flags;

	if (!atomic_read(&kasumi_vnode_aio_active))
		return 0;
	request = kasumi_vnode_aio_find((void *)regs->regs[0], true);
	if (!request)
		return 0;
	owner = request->cancel_owner ? request->cancel_owner : request;
	/* The native function must only inspect a real aio_kiocb container.
	 * Its ctx_lock continues to serialize cancellation with completion. */
	spin_lock_irqsave(&owner->cancel_lock, flags);
	if (!owner->cancel_target) {
		WRITE_ONCE(owner->cancel, (void *)regs->regs[1]);
		owner->cancel_target = request;
		if (request != owner)
			refcount_inc(&request->refs);
	}
	spin_unlock_irqrestore(&owner->cancel_lock, flags);
	regs->regs[0] = (unsigned long)owner->original;
	regs->regs[1] = (unsigned long)kasumi_vnode_aio_cancel;
	/* The submitting reference remains held across the native function. */
	kasumi_vnode_aio_put(request);
#endif
	return 0;
}

bool kasumi_vnode_aio_busy(void)
{
	return atomic_read(&kasumi_vnode_aio_active) != 0;
}

int kasumi_vnode_aio_init(void)
{
	unsigned int i;
	int ret;

	if (kasumi_vnode_aio_wq)
		return 0;
	for (i = 0; i < ARRAY_SIZE(kasumi_vnode_aio_locks); i++)
		spin_lock_init(&kasumi_vnode_aio_locks[i]);
	kasumi_vnode_aio_wq = alloc_workqueue("kasumi_aio", WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
	if (!kasumi_vnode_aio_wq)
		return -ENOMEM;
	if (IS_ENABLED(CONFIG_AIO) && IS_ENABLED(CONFIG_ARM64)) {
		kasumi_vnode_aio_cancel_probe.addr =
			(void *)kasumi_lookup_name_quiet("kiocb_set_cancel_fn");
		kasumi_vnode_aio_cancel_probe.pre_handler = kasumi_vnode_aio_cancel_pre;
		ret = kasumi_vnode_aio_cancel_probe.addr ?
			register_kprobe(&kasumi_vnode_aio_cancel_probe) : -EOPNOTSUPP;
		if (ret) {
			destroy_workqueue(kasumi_vnode_aio_wq);
			kasumi_vnode_aio_wq = NULL;
			return ret;
		}
		kasumi_vnode_aio_cancel_registered = true;
	}
	WRITE_ONCE(kasumi_vnode_aio_stopping, false);
	return 0;
}

/* Entry points and vnode file references must be drained before teardown.
 * Each request also pins the module until its final work/cancel reference.
 * destroy_workqueue waits for the final worker to return past module_put. */
void kasumi_vnode_aio_exit(void)
{
	WRITE_ONCE(kasumi_vnode_aio_stopping, true);
	if (kasumi_vnode_aio_cancel_registered) {
		unregister_kprobe(&kasumi_vnode_aio_cancel_probe);
		kasumi_vnode_aio_cancel_registered = false;
	}
	if (kasumi_vnode_aio_wq) {
		destroy_workqueue(kasumi_vnode_aio_wq);
		kasumi_vnode_aio_wq = NULL;
	}
}

static void kasumi_vnode_aio_finish(struct kasumi_vnode_aio *request)
{
	request->original->ki_pos = request->iocb.ki_pos;
	if (request->iocb.ki_flags & IOCB_WRITE)
		kasumi_vnode_copyattr(file_inode(request->outer),
				     file_inode(request->iocb.ki_filp));
}

static void kasumi_vnode_aio_end_write(struct kiocb *iocb)
{
	if (!S_ISREG(file_inode(iocb->ki_filp)->i_mode))
		return;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 16, 0)
	kiocb_end_write(iocb);
#else
	__sb_writers_acquired(file_inode(iocb->ki_filp)->i_sb,
			      SB_FREEZE_WRITE);
	file_end_write(iocb->ki_filp);
#endif
}

static void KASUMI_NOCFI kasumi_vnode_aio_work(struct work_struct *work)
{
	struct kasumi_vnode_aio *request =
		container_of(work, struct kasumi_vnode_aio, work);
	struct kiocb *original = request->original;

	if (request->end_write)
		kasumi_vnode_aio_end_write(&request->iocb);
	kasumi_vnode_aio_finish(request);
	if (request->legacy)
		original->ki_complete = request->complete;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 16, 0)
	request->complete(original, request->result);
#else
	request->complete(original, request->result, request->result2);
#endif
	/* aio_complete_rw has now removed the native cancel-list entry under
	 * ctx_lock. No new native cancellation can find this request. */
	if (request->indexed)
		kasumi_vnode_aio_index(request, false);
	if (request->legacy && request->cancel_target) {
		struct kasumi_vnode_aio *target = request->cancel_target;

		request->cancel_target = NULL;
		if (target != request)
			kasumi_vnode_aio_put(target);
	}
	kasumi_vnode_aio_put(request);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 16, 0)
static void kasumi_vnode_aio_complete(struct kiocb *iocb, long result)
#else
static void kasumi_vnode_aio_complete(struct kiocb *iocb, long result,
				    long result2)
#endif
{
	struct kasumi_vnode_aio *request =
		container_of(iocb, struct kasumi_vnode_aio, iocb);

	/* Drivers may call us from hardirq, including before submission returns.
	 * Everything needed by this path was allocated before calling them. */
	kasumi_vnode_aio_retire_cancel(request);
	request->result = result;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0)
	request->result2 = result2;
#endif
	request->end_write = iocb->ki_flags & IOCB_WRITE;
	queue_work(kasumi_vnode_aio_wq, &request->work);
}

static void kasumi_vnode_aio_original_complete(struct kiocb *iocb, long result
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0)
					      , long result2
#endif
)
{
	struct kasumi_vnode_aio *request = kasumi_vnode_aio_find(iocb, false);

	if (WARN_ON_ONCE(!request))
		return;
	kasumi_vnode_aio_retire_cancel(request);
	/* Native aio_rw_done uses this path for immediate returns. The source
	 * write token was already ended by the submitting helper. Retain the
	 * cancel mapping until native completion removes its active-list entry. */
	request->result = result;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0)
	request->result2 = result2;
#endif
	queue_work(kasumi_vnode_aio_wq, &request->work);
	kasumi_vnode_aio_put(request);
}

static ssize_t KASUMI_NOCFI kasumi_vnode_iter_write(struct file *file,
	struct kiocb *iocb, struct iov_iter *iter)
{
	struct inode *inode = file_inode(file);
	ssize_t ret;

	if (!file->f_op->write_iter)
		return -EINVAL;
	if (!(file->f_mode & FMODE_WRITE))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_WRITE))
		return -EINVAL;
	if (!kasumi_rw_verify_area)
		return -EOPNOTSUPP;
	ret = kasumi_rw_verify_area(WRITE, file, &iocb->ki_pos, iov_iter_count(iter));
	if (ret)
		return ret;
	if (S_ISREG(inode->i_mode)) {
		if (iocb->ki_flags & IOCB_NOWAIT) {
			if (!sb_start_write_trylock(inode->i_sb))
				return -EAGAIN;
		} else {
			file_start_write(file);
		}
		__sb_writers_release(inode->i_sb, SB_FREEZE_WRITE);
	}
	ret = file->f_op->write_iter(iocb, iter);
	if (ret != -EIOCBQUEUED)
		kasumi_vnode_aio_end_write(iocb);
	return ret;
}

static ssize_t KASUMI_NOCFI kasumi_vnode_iter_read(struct file *file,
	struct kiocb *iocb, struct iov_iter *iter)
{
	ssize_t ret;

	if (!file->f_op->read_iter)
		return -EINVAL;
	if (!(file->f_mode & FMODE_READ))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_READ))
		return -EINVAL;
	if (!iov_iter_count(iter))
		return 0;
	if (!kasumi_rw_verify_area)
		return -EOPNOTSUPP;
	ret = kasumi_rw_verify_area(READ, file, &iocb->ki_pos, iov_iter_count(iter));
	if (ret)
		return ret;
	/* Native outer VFS/io_uring code emits the event in its own producer
	 * context. The inode relay carries it to the source exactly once. */
	return file->f_op->read_iter(iocb, iter);
}

static ssize_t kasumi_vnode_iter(struct kiocb *iocb, struct iov_iter *iter,
				bool write)
{
	struct file *outer = iocb->ki_filp;
	struct file *real = outer->private_data;
	struct kasumi_vnode_aio *request;
	struct kiocb synchronous;
	struct kiocb *inner;
	ssize_t ret;

	if (!real)
		return -EBADF;
	if (!iov_iter_count(iter))
		return 0;
#ifdef IOCB_WAITQ
	if (iocb->ki_flags & IOCB_WAITQ)
		return -EAGAIN;
#endif
#ifdef IOCB_HAS_METADATA
	if (iocb->ki_flags & IOCB_HAS_METADATA)
		return -EOPNOTSUPP;
#endif
	ret = kasumi_vnode_sync_flags(outer, real);
	if (ret)
		return ret;
	if (is_sync_kiocb(iocb)) {
		request = NULL;
		kiocb_clone(&synchronous, iocb, real);
		inner = &synchronous;
	} else {
		if (READ_ONCE(kasumi_vnode_aio_stopping))
			return -EOPNOTSUPP;
#ifdef IOCB_AIO_RW
		if ((iocb->ki_flags & IOCB_AIO_RW) &&
		    !kasumi_vnode_aio_cancel_registered)
			return -EOPNOTSUPP;
#endif
		request = kzalloc(sizeof(*request),
				  iocb->ki_flags & IOCB_NOWAIT ? GFP_NOWAIT :
							       GFP_KERNEL);
		if (!request)
			return iocb->ki_flags & IOCB_NOWAIT ? -EAGAIN : -ENOMEM;
		if (!try_module_get(THIS_MODULE)) {
			kfree(request);
			return -ESHUTDOWN;
		}
		atomic_inc(&kasumi_vnode_aio_active);
		request->original = iocb;
		request->complete = iocb->ki_complete;
		request->outer = get_file(outer);
		kiocb_clone(&request->iocb, iocb, get_file(real));
		request->iocb.ki_complete = kasumi_vnode_aio_complete;
		INIT_WORK(&request->work, kasumi_vnode_aio_work);
		spin_lock_init(&request->cancel_lock);
		/* Completion may run before the submission call returns. */
		refcount_set(&request->refs, 2);
#ifdef IOCB_AIO_RW
		request->legacy = iocb->ki_flags & IOCB_AIO_RW;
		if (!request->legacy && iocb->ki_complete == kasumi_vnode_aio_complete) {
			struct kasumi_vnode_aio *parent =
				container_of(iocb, struct kasumi_vnode_aio, iocb);
			struct kasumi_vnode_aio *owner = parent->cancel_owner ?: parent;

			/* Preserve native cancellation through nested vnode sources.
			 * The parent submission reference protects this lookup. */
			if (owner->legacy) {
				request->cancel_owner = owner;
				refcount_inc(&owner->refs);
			}
		}
		request->indexed = request->legacy || request->cancel_owner;
		if (request->indexed)
			kasumi_vnode_aio_index(request, true);
		if (request->legacy)
			iocb->ki_complete = kasumi_vnode_aio_original_complete;
#endif
		inner = &request->iocb;
	}
#ifdef IOCB_AIO_RW
	/* This is a kiocb clone, never the rw member of native aio_kiocb. */
	inner->ki_flags &= ~IOCB_AIO_RW;
#endif
#ifdef IOCB_DIO_CALLER_COMP
	inner->ki_flags &= ~IOCB_DIO_CALLER_COMP;
#endif
	if (write) {
		inner->ki_flags |= IOCB_WRITE;
		ret = kasumi_vnode_iter_write(real, inner, iter);
	} else {
		ret = kasumi_vnode_iter_read(real, inner, iter);
	}
	if (request) {
		if (ret != -EIOCBQUEUED)
			kasumi_vnode_aio_retire_cancel(request);
		if (ret != -EIOCBQUEUED && !request->legacy) {
			kasumi_vnode_aio_finish(request);
			if (request->indexed)
				kasumi_vnode_aio_index(request, false);
			kasumi_vnode_aio_put(request);
		}
		kasumi_vnode_aio_put(request);
	} else {
		iocb->ki_pos = inner->ki_pos;
		if (write)
			kasumi_vnode_copyattr(file_inode(outer), file_inode(real));
	}
	return ret;
}

static ssize_t kasumi_vnode_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	return kasumi_vnode_iter(iocb, to, false);
}

static ssize_t kasumi_vnode_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	return kasumi_vnode_iter(iocb, from, true);
}

static int KASUMI_NOCFI kasumi_vnode_mmap(struct file *file,
					  struct vm_area_struct *vma)
{
	struct file *real = file->private_data;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	struct backing_file_ctx ctx = {
		.cred = current_cred(),
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 16, 0)
		.user_file = file,
#endif
	};

	if (!real)
		return -ENODEV;
	return backing_file_mmap(real, vma, &ctx);
#else
	int ret;

	if (!real || !real->f_op->mmap)
		return -ENODEV;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 13, 0)
	vma_set_file(vma, real);
	ret = real->f_op->mmap(real, vma);
#else
	vma->vm_file = get_file(real);
	ret = real->f_op->mmap(real, vma);
	if (ret) {
		fput(real);
		vma->vm_file = file;
	} else {
		fput(file);
	}
#endif
	return ret;
#endif
}

static long KASUMI_NOCFI kasumi_vnode_ioctl(struct file *file, unsigned int cmd,
					    unsigned long arg)
{
	struct file *real_file = file->private_data;
	int ret;

	if (!real_file || !real_file->f_op || !real_file->f_op->unlocked_ioctl)
		return -ENOTTY;
	ret = kasumi_vnode_sync_flags(file, real_file);
	if (ret)
		return ret;
	return real_file->f_op->unlocked_ioctl(real_file, cmd, arg);
}

#ifdef CONFIG_COMPAT
static long KASUMI_NOCFI kasumi_vnode_compat_ioctl(struct file *file,
						   unsigned int cmd,
						   unsigned long arg)
{
	struct file *real_file = file->private_data;
	int ret;

	if (!real_file || !real_file->f_op || !real_file->f_op->compat_ioctl)
		return -ENOTTY;
	ret = kasumi_vnode_sync_flags(file, real_file);
	if (ret)
		return ret;
	return real_file->f_op->compat_ioctl(real_file, cmd, arg);
}
#endif

static ssize_t KASUMI_NOCFI kasumi_vnode_splice_read(struct file *in,
						     loff_t *ppos,
						     struct pipe_inode_info *pipe,
						     size_t len,
						     unsigned int flags)
{
	struct file *real_file = in->private_data;

	if (!real_file || !real_file->f_op || !real_file->f_op->splice_read)
		return -EINVAL;
	return real_file->f_op->splice_read(real_file, ppos, pipe, len, flags);
}

static int KASUMI_NOCFI kasumi_vnode_fsync(struct file *file, loff_t start,
					   loff_t end, int datasync)
{
	struct file *real_file = file->private_data;

	if (!real_file || !real_file->f_op || !real_file->f_op->fsync)
		return -EINVAL;
	return real_file->f_op->fsync(real_file, start, end, datasync);
}

static long KASUMI_NOCFI kasumi_vnode_source_fallocate(struct file *file, int mode,
	loff_t offset, loff_t len)
{
	struct inode *inode = file_inode(file);
	loff_t end;
	long ret;

	/* The outer vfs_fallocate validates the operation encoding and range.
	 * Recheck every source-dependent condition before its filesystem call.
	 * The outer success event reaches the source through the inode relay.
	 */
	if (!(file->f_mode & FMODE_WRITE))
		return -EBADF;
	if (((mode & ~FALLOC_FL_KEEP_SIZE) && IS_APPEND(inode)) || IS_IMMUTABLE(inode))
		return -EPERM;
	if (IS_SWAPFILE(inode))
		return -ETXTBSY;
	if (!kasumi_security_file_permission)
		return -EOPNOTSUPP;
	ret = kasumi_security_file_permission(file, MAY_WRITE);
	if (ret)
		return ret;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	ret = fsnotify_file_area_perm(file, MAY_WRITE, &offset, len);
	if (ret)
		return ret;
#endif
	if (S_ISFIFO(inode->i_mode))
		return -ESPIPE;
	if (S_ISDIR(inode->i_mode))
		return -EISDIR;
	if (!S_ISREG(inode->i_mode) && !S_ISBLK(inode->i_mode))
		return -ENODEV;
	if (check_add_overflow(offset, len, &end) || end > inode->i_sb->s_maxbytes)
		return -EFBIG;
	if (!file->f_op->fallocate)
		return -EOPNOTSUPP;
	file_start_write(file);
	ret = file->f_op->fallocate(file, mode, offset, len);
	file_end_write(file);
	return ret;
}

static long kasumi_vnode_fallocate(struct file *file, int mode,
				    loff_t offset, loff_t len)
{
	struct file *real = file->private_data;
	long ret;

	if (!real)
		return -EBADF;
	ret = kasumi_vnode_sync_flags(file, real);
	if (ret)
		return ret;
	ret = kasumi_vnode_source_fallocate(real, mode, offset, len);
	kasumi_vnode_copyattr(file_inode(file), file_inode(real));
	return ret;
}

static int kasumi_vnode_fadvise(struct file *file, loff_t offset,
			       loff_t len, int advice)
{
	struct file *real = file->private_data;

	return real ? vfs_fadvise(real, offset, len, advice) : -EBADF;
}

static int KASUMI_NOCFI kasumi_vnode_flush(struct file *file, fl_owner_t owner)
{
	return kasumi_file_lock_flush(file, owner);
}

static int kasumi_vnode_permission(KVN_IDMAP_ARG struct inode *inode,
				   int mask)
{
	struct kasumi_vnode_info *info = inode->i_private;
	int ret;

	if (!info)
		return -EIO;
	if (!info->source.dentry)
		return generic_permission(KVN_IDMAP_CALL inode, mask);
	ret = kasumi_vnode_refresh_sid(inode, d_inode(info->source.dentry),
				       !(mask & MAY_NOT_BLOCK));
	if (ret)
		return ret;
	return inode_permission(KVN_SRC_IDMAP(info->source.mnt)
				d_inode(info->source.dentry), mask);
}

static const struct inode_operations kasumi_vnode_file_iops = {
	.permission = kasumi_vnode_permission,
	.getattr = kasumi_vnode_getattr,
	.setattr = kasumi_vnode_setattr,
	.listxattr = kasumi_vnode_listxattr,
	.get_link = kasumi_vnode_get_link,
};

static ssize_t KASUMI_NOCFI kasumi_vnode_read(struct file *file, char __user *buf,
					     size_t len, loff_t *ppos);
static ssize_t KASUMI_NOCFI kasumi_vnode_write(struct file *file, const char __user *buf,
					      size_t len, loff_t *ppos);
static __poll_t KASUMI_NOCFI kasumi_vnode_poll(struct file *file,
					    struct poll_table_struct *wait);
static int KASUMI_NOCFI kasumi_vnode_fasync(int fd, struct file *file, int on);

static const struct file_operations kasumi_vnode_file_fops = {
	.owner = THIS_MODULE,
	.lock = kasumi_file_lock_posix,
	.flock = kasumi_file_lock_flock,
	.setlease = kasumi_file_lock_setlease,
	.open = kasumi_vnode_open,
	.release = kasumi_vnode_release,
	.llseek = kasumi_vnode_llseek,
	.read = kasumi_vnode_read,
	.write = kasumi_vnode_write,
	.poll = kasumi_vnode_poll,
	.fasync = kasumi_vnode_fasync,
	.read_iter = kasumi_vnode_read_iter,
	.write_iter = kasumi_vnode_write_iter,
	.mmap = kasumi_vnode_mmap,
	.unlocked_ioctl = kasumi_vnode_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = kasumi_vnode_compat_ioctl,
#endif
	.splice_read = kasumi_vnode_splice_read,
	.fsync = kasumi_vnode_fsync,
	.flush = kasumi_vnode_flush,
	.fallocate = kasumi_vnode_fallocate,
	.fadvise = kasumi_vnode_fadvise,
};

/* ---- special vnode: char/blk/fifo source, full fop delegation --------------
 *
 * The inode is minted S_IFREG (kasumi_vnode_new) so path_openat's may_open does
 * not apply the device (may_open_dev) check on the nodev visible mount; .open
 * (kasumi_vnode_open) then opens the *real* source via dentry_open, which routes
 * through chrdev_open/blkdev/fifo_open and bypasses may_open entirely.  Read,
 * write, poll, mmap, ioctl and fasync forward to that real file.  getattr still
 * projects the source's real type and rdev, so userspace sees a device/fifo.
 */
static ssize_t KASUMI_NOCFI kasumi_vnode_read(struct file *file,
						      char __user *buf,
						      size_t len, loff_t *ppos)
{
	struct file *real = file->private_data;
	ssize_t ret;

	if (!real)
		return -EINVAL;
	ret = kasumi_vnode_sync_flags(file, real);
	if (ret)
		return ret;
	if (!(real->f_mode & FMODE_READ))
		return -EBADF;
	if (!(real->f_mode & FMODE_CAN_READ))
		return -EINVAL;
	if (!kasumi_rw_verify_area)
		return -EOPNOTSUPP;
	ret = kasumi_rw_verify_area(READ, real, ppos, len);
	if (ret)
		return ret;
	if (!real->f_op->read)
		return -EINVAL;
	ret = real->f_op->read(real, buf, len, ppos);
	return ret;
}

static ssize_t KASUMI_NOCFI kasumi_vnode_write(struct file *file,
						       const char __user *buf,
						       size_t len, loff_t *ppos)
{
	struct file *real = file->private_data;
	ssize_t ret;

	if (!real)
		return -EINVAL;
	ret = kasumi_vnode_sync_flags(file, real);
	if (ret)
		return ret;
	if (!(real->f_mode & FMODE_WRITE))
		return -EBADF;
	if (!(real->f_mode & FMODE_CAN_WRITE))
		return -EINVAL;
	if (!kasumi_rw_verify_area)
		return -EOPNOTSUPP;
	ret = kasumi_rw_verify_area(WRITE, real, ppos, len);
	if (ret)
		return ret;
	if (!real->f_op->write)
		return -EINVAL;
	file_start_write(real);
	ret = real->f_op->write(real, buf, len, ppos);
	file_end_write(real);
	return ret;
}

static __poll_t KASUMI_NOCFI kasumi_vnode_poll(struct file *file,
						       struct poll_table_struct *wait)
{
	struct file *real = file->private_data;

	if (!real)
		return EPOLLERR;
	return vfs_poll(real, wait);
}

static int KASUMI_NOCFI kasumi_vnode_fasync(int fd, struct file *file,
						    int on)
{
	return kasumi_file_lock_fasync(fd, file, on);
}

static const struct file_operations kasumi_vnode_special_fops = {
	.owner = THIS_MODULE,
	.lock = kasumi_file_lock_posix,
	.flock = kasumi_file_lock_flock,
	.setlease = kasumi_file_lock_setlease,
	.open = kasumi_vnode_open,
	.release = kasumi_vnode_release,
	.llseek = kasumi_vnode_llseek,
	.read_iter = kasumi_vnode_read_iter,
	.write_iter = kasumi_vnode_write_iter,
	.flush = kasumi_vnode_flush,
	.read = kasumi_vnode_read,
	.write = kasumi_vnode_write,
	.poll = kasumi_vnode_poll,
	.unlocked_ioctl = kasumi_vnode_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = kasumi_vnode_compat_ioctl,
#endif
	.mmap = kasumi_vnode_mmap,
	.fasync = kasumi_vnode_fasync,
	.splice_read = kasumi_vnode_splice_read,
	.fsync = kasumi_vnode_fsync,
};

/* ---- directory vnode: lookup/iterate delegate to the pinned source dir ---- */

static int KASUMI_NOCFI kasumi_vnode_dir_open(struct inode *inode,
					      struct file *file)
{
	struct kasumi_vnode_info *info = inode->i_private;
	struct file *real_dir;
	int ret;

	if (!info)
		return -ENOTDIR;
	if (!info->source.dentry) {
		/* Pure-virtual directory: nothing to open; iterate enumerates the
		 * rule table.  release() tolerates a NULL private_data. */
		file->private_data = NULL;
		return 0;
	}
	if (!kasumi_dentry_open)
		return -EOPNOTSUPP;
	real_dir = kasumi_dentry_open(&info->source, O_RDONLY | O_DIRECTORY,
				      file->f_cred);
	if (IS_ERR(real_dir))
		return PTR_ERR(real_dir);
	ret = kasumi_vnode_notify_open(inode);
	if (ret) {
		fput(real_dir);
		return ret;
	}
	file->private_data = real_dir;
	kasumi_file_lock_opened();
	return 0;
}

char *kasumi_vnode_visible_path(struct dentry *dentry)
{
	struct dentry *cursor, *parent;
	struct kasumi_vnode_info *info;
	char *buffer, *path;
	unsigned int seq;
	bool found, retry;
	int error;
	size_t len;

	buffer = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buffer)
		return ERR_PTR(-ENOMEM);
	do {
		path = buffer + PATH_MAX - 1;
		*path = '\0';
		found = false;
		error = 0;
		cursor = dentry;
		rcu_read_lock();
		seq = read_seqbegin(&rename_lock);
		for (;;) {
			spin_lock(&cursor->d_lock);
			info = kasumi_vnode_is_ours(d_inode(cursor))
				   ? d_inode(cursor)->i_private
				   : NULL;
			if (info && info->visible_path) {
				len = strlen(info->visible_path);
				if (len == 1 && *path == '/')
					len = 0;
				if (len > path - buffer) {
					error = -ENAMETOOLONG;
				} else {
					path -= len;
					memcpy(path, info->visible_path, len);
					found = true;
				}
				spin_unlock(&cursor->d_lock);
				break;
			}
			parent = cursor->d_parent;
			if (parent == cursor) {
				spin_unlock(&cursor->d_lock);
				break;
			}
			len = cursor->d_name.len;
			if (len + 1 > path - buffer) {
				error = -ENAMETOOLONG;
				spin_unlock(&cursor->d_lock);
				break;
			}
			path -= len;
			memcpy(path, cursor->d_name.name, len);
			*--path = '/';
			spin_unlock(&cursor->d_lock);
			cursor = parent;
		}
		retry = read_seqretry(&rename_lock, seq);
		rcu_read_unlock();
	} while (retry);
	if (error || !found) {
		kfree(buffer);
		return error ? ERR_PTR(error) : NULL;
	}
	memmove(buffer, path, buffer + PATH_MAX - path);
	return buffer;
}

static int kasumi_vnode_collect_children(struct file *file,
	struct list_head *entries, u64 *generation, void *data)
{
	struct kasumi_vnode_info *info = file_inode(file)->i_private;
	struct kasumi_dir_entry *entry;
	char *visible_path;
	int ret;

	(void)data;
	visible_path = kasumi_vnode_visible_path(file->f_path.dentry);
	if (IS_ERR(visible_path))
		return PTR_ERR(visible_path);
	if (!visible_path) {
		*generation = kasumi_rules_generation();
		return 0;
	}
	ret =
	    kasumi_rule_vpath_collect(file, entries, generation, visible_path);
	kfree(visible_path);
	if (ret || !info->source.dentry)
		return ret;
	list_for_each_entry(entry, entries, list) {
		struct path child = {};
		struct inode *inode;
		struct kasumi_inode_identity *identity;

		if ((!entry->redirect && !entry->bypass_redirect) ||
		    (entry->direct_rule &&
		     (!entry->bypass_redirect || entry->bypass_direct_rule)))
			continue;
		ret = kasumi_vfs_path_lookup(info->source.dentry, info->source.mnt,
					     entry->name, 0, &child);
		if (ret == -ENOENT)
			continue;
		if (ret)
			return ret;
		inode = d_inode(child.dentry);
		if (inode && S_ISDIR(inode->i_mode)) {
			ret = kasumi_identity_domain_source_get(info->identity_domain,
				inode->i_sb->s_dev, inode->i_ino, GFP_NOFS, &identity);
			if (ret) {
				kasumi_path_put(&child);
				return ret;
			}
			if (!entry->direct_rule) {
				kasumi_identity_put(entry->identity);
				entry->identity = identity;
				kasumi_identity_get(identity);
				entry->ino = kasumi_identity_ino(identity);
			}
			if (entry->bypass_redirect && !entry->bypass_direct_rule) {
				kasumi_identity_put(entry->bypass_identity);
				entry->bypass_identity = identity;
				kasumi_identity_get(identity);
				entry->bypass_ino = kasumi_identity_ino(identity);
			}
			kasumi_identity_put(identity);
		}
		kasumi_path_put(&child);
	}
	return 0;
}

static int KASUMI_NOCFI kasumi_vnode_dir_iterate(struct file *file,
						 struct dir_context *ctx)
{
	struct file *real_dir = file->private_data;
	struct kasumi_vnode_info *info = file_inode(file)->i_private;
	struct kasumi_dir_identity identity = {};
	struct inode *source;

	if (!info || (info->source.dentry && !real_dir))
		return -ENOTDIR;
	identity.domain = info->identity_domain;
	identity.dot_ino = info->v_ino;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	identity.parent_ino = d_parent_ino(file->f_path.dentry);
#else
	identity.parent_ino = parent_ino(file->f_path.dentry);
#endif
	source = real_dir ? file_inode(real_dir) : NULL;
	identity.source_identity = source != NULL;
	identity.source_dev = source ? source->i_sb->s_dev : 0;
	return kasumi_dir_view_iterate(file, real_dir,
		real_dir ? kasumi_fop_original_operations(real_dir) : NULL, ctx,
		kasumi_vnode_collect_children, NULL, &identity);
}

struct kasumi_virtual_dop {
	struct dentry_operations ops;
	void (*release)(struct dentry *dentry);
	struct rcu_head rcu;
};

static int kasumi_vnode_resolve_child(struct inode *dir,
				      const char *visible_path,
				      const char *name, struct path *leaf,
				      umode_t *mode,
				      struct kasumi_inode_identity **identity)
{
	struct kasumi_vnode_info *info = dir->i_private;
	struct inode *source;
	int kind = KASUMI_VPATH_NONE;
	int ret;

	if (visible_path) {
		kind = kasumi_rule_vpath_child(visible_path, name, leaf, mode,
					       NULL, identity,
					       info->source.dentry);
		if (kind < 0 || kind == KASUMI_VPATH_LEAF)
			return kind;
	}
	if (!info->source.dentry)
		return kind;
	if (!kasumi_vfs_path_lookup)
		return -EOPNOTSUPP;
	ret = kasumi_vfs_path_lookup(info->source.dentry, info->source.mnt,
				     name, 0, leaf);
	if (ret == -ENOENT)
		return kind;
	if (ret)
		return ret;
	source = d_inode(leaf->dentry);
	if (!source || (kind == KASUMI_VPATH_VDIR && !S_ISDIR(source->i_mode))) {
		kasumi_path_put(leaf);
		memset(leaf, 0, sizeof(*leaf));
		return kind;
	}
	if (mode)
		*mode = source->i_mode;
	ret = kasumi_identity_domain_source_get(info->identity_domain,
		source->i_sb->s_dev, source->i_ino, GFP_NOFS, identity);
	if (ret) {
		kasumi_path_put(leaf);
		memset(leaf, 0, sizeof(*leaf));
		return ret;
	}
	return KASUMI_VPATH_LEAF;
}

static int kasumi_virtual_revalidate_child_path(struct inode *dir,
						const struct qstr *name,
						struct dentry *dentry,
						unsigned int flags)
{
	const struct kasumi_vnode_info *parent, *info;
	struct inode *inode;
	struct path leaf = {};
	struct kasumi_inode_identity *identity = NULL;
	struct dentry *parent_dentry;
	char *child, *visible_path;
	int kind, valid = 0;

	if (flags & LOOKUP_RCU)
		return -ECHILD;
	if (!kasumi_vnode_is_ours(dir))
		return 0;
	parent = dir->i_private;
	if (!parent)
		return 0;
	child = kstrndup(name->name, name->len, GFP_KERNEL);
	if (!child)
		return -ENOMEM;
	parent_dentry = dget_parent(dentry);
	if (d_inode(parent_dentry) != dir) {
		dput(parent_dentry);
		kfree(child);
		return 0;
	}
	visible_path = kasumi_vnode_visible_path(parent_dentry);
	dput(parent_dentry);
	if (IS_ERR(visible_path)) {
		kfree(child);
		return PTR_ERR(visible_path);
	}
	kind = kasumi_vnode_resolve_child(dir, visible_path, child, &leaf, NULL,
					  &identity);
	kfree(child);
	if (kind < 0) {
		kfree(visible_path);
		return kind;
	}

	inode = d_inode(dentry);
	if (kind == KASUMI_VPATH_NONE) {
		kfree(visible_path);
		return !inode;
	}
	info = kasumi_vnode_is_ours(inode) ? inode->i_private : NULL;
	if (info && kind == KASUMI_VPATH_VDIR && info->visible_path &&
	    visible_path && !info->source.dentry &&
	    (info->flags & KASUMI_VNODE_F_VIRTUAL_DIR)) {
		size_t len =
		    strcmp(visible_path, "/") ? strlen(visible_path) : 0;

		/* Keep a live cwd hashed while this observer still sees the
		 * same dir. */
		valid = strlen(info->visible_path) == len + 1 + name->len &&
			!strncmp(info->visible_path, visible_path, len) &&
			info->visible_path[len] == '/' &&
			!memcmp(info->visible_path + len + 1, name->name,
				name->len);
	} else if (info && kind == KASUMI_VPATH_LEAF) {
		valid = path_equal(&info->source, &leaf) && info->v_ino == kasumi_identity_ino(identity);
	}
	kasumi_identity_put(identity);
	if (leaf.dentry)
		kasumi_path_put(&leaf);
	kfree(visible_path);
	return valid;
}

static int kasumi_virtual_revalidate_child(struct inode *dir,
					   const struct qstr *name,
					   struct dentry *dentry,
					   unsigned int flags)
{
	struct kasumi_vnode_info *info;
	unsigned int seq;
	int ret;

	if (flags & LOOKUP_RCU)
		return -ECHILD;
	if (!kasumi_vnode_is_ours(dir) || !dir->i_private)
		return 0;
	info = dir->i_private;
	seq = atomic_read_acquire(&info->rename_seq);
	if (seq & 1)
		return -ESTALE;
	ret = kasumi_virtual_revalidate_child_path(dir, name, dentry, flags);
	smp_rmb();
	/* Do not invalidate a live dentry using an intermediate backing name.
	 */
	return seq == atomic_read(&info->rename_seq) ? ret : -ESTALE;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
static int KASUMI_NOCFI kasumi_virtual_revalidate(struct inode *dir,
						  const struct qstr *name,
						  struct dentry *dentry,
						  unsigned int flags)
{
	return kasumi_virtual_revalidate_child(dir, name, dentry, flags);
}
#else
static int KASUMI_NOCFI kasumi_virtual_revalidate(struct dentry *dentry,
						  unsigned int flags)
{
	struct dentry *parent;
	int ret;

	if (flags & LOOKUP_RCU)
		return -ECHILD;
	parent = dget_parent(dentry);
	ret = kasumi_virtual_revalidate_child(d_inode(parent), &dentry->d_name,
					      dentry, flags);
	dput(parent);
	return ret;
}
#endif

static int KASUMI_NOCFI kasumi_virtual_delete(const struct dentry *dentry)
{
	(void)dentry;
	return 1;
}

static void KASUMI_NOCFI kasumi_virtual_dop_free(struct rcu_head *rcu)
{
	struct kasumi_virtual_dop *meta =
	    container_of(rcu, struct kasumi_virtual_dop, rcu);
	kfree(meta);
	module_put(THIS_MODULE);
}

static void KASUMI_NOCFI kasumi_virtual_release(struct dentry *dentry)
{
	struct kasumi_virtual_dop *meta =
	    container_of(dentry->d_op, struct kasumi_virtual_dop, ops);
	if (meta->release)
		meta->release(dentry);
	/* RCU path walks may still hold the copied operations table. */
	call_rcu(&meta->rcu, kasumi_virtual_dop_free);
}

static int kasumi_virtual_track_dentry(struct dentry *dentry)
{
	const unsigned int backing_inode_flags =
	    DCACHE_OP_WEAK_REVALIDATE | DCACHE_OP_REAL;
	struct kasumi_virtual_dop *meta;

	if (dentry->d_op &&
	    dentry->d_op->d_revalidate == kasumi_virtual_revalidate) {
		spin_lock(&dentry->d_lock);
		dentry->d_flags = (dentry->d_flags & ~backing_inode_flags) |
				  DCACHE_OP_REVALIDATE | DCACHE_OP_DELETE;
		spin_unlock(&dentry->d_lock);
		return 0;
	}
	meta = kzalloc(sizeof(*meta), GFP_KERNEL);
	if (!meta)
		return -ENOMEM;
	if (dentry->d_op)
		meta->ops = *dentry->d_op;
	meta->release = meta->ops.d_release;
	/* Filesystem inode extensions do not exist on Kasumi child inodes. */
	meta->ops.d_weak_revalidate = NULL;
	meta->ops.d_real = NULL;
	meta->ops.d_revalidate = kasumi_virtual_revalidate;
	meta->ops.d_delete = kasumi_virtual_delete;
	meta->ops.d_release = kasumi_virtual_release;
	__module_get(THIS_MODULE);
	spin_lock(&dentry->d_lock);
	WRITE_ONCE(dentry->d_op, &meta->ops);
	dentry->d_flags = (dentry->d_flags & ~backing_inode_flags) |
			  DCACHE_OP_REVALIDATE | DCACHE_OP_DELETE;
	spin_unlock(&dentry->d_lock);
	return 0;
}

static struct dentry *KASUMI_NOCFI kasumi_vnode_dir_lookup(
	struct inode *dir, struct dentry *dentry, unsigned int flags)
{
	struct kasumi_vnode_info *info = dir->i_private;
	struct inode *child_inode = NULL;
	struct path leaf = {};
	struct kasumi_inode_identity *identity = NULL;
	umode_t mode = 0;
	char *name, *visible_path = NULL, *child_path;
	int kind, ret = 0;

	(void)flags;
	if (!info)
		return ERR_PTR(-ENOENT);
	if (dentry->d_name.len > NAME_MAX)
		return ERR_PTR(-ENAMETOOLONG);
	if (!try_module_get(THIS_MODULE))
		return ERR_PTR(-ENOENT);
	name = kstrndup(dentry->d_name.name, dentry->d_name.len, GFP_KERNEL);
	if (!name) {
		ret = -ENOMEM;
		goto out;
	}
	ret = kasumi_virtual_track_dentry(dentry);
	if (ret)
		goto out;
	visible_path = kasumi_vnode_visible_path(dentry->d_parent);
	if (IS_ERR(visible_path)) {
		ret = PTR_ERR(visible_path);
		visible_path = NULL;
		goto out;
	}
	kind = kasumi_vnode_resolve_child(dir, visible_path, name, &leaf, &mode,
					  &identity);
	if (kind < 0) {
		ret = kind;
		goto out;
	}
	if (kind == KASUMI_VPATH_NONE) {
		d_add(dentry, NULL);
		goto out;
	}
	if (kind == KASUMI_VPATH_LEAF) {
		u8 child_flags = S_ISDIR(mode) ? KASUMI_VNODE_F_DIR :
			S_ISLNK(mode) ? KASUMI_VNODE_F_LNK :
			special_file(mode) ? KASUMI_VNODE_F_SPECIAL : 0;

		child_inode = kasumi_vnode_new(dir->i_sb, &leaf, mode, child_flags);
	} else {
		child_path =
		    kasprintf(GFP_KERNEL, "%s%s%s", visible_path,
			      strcmp(visible_path, "/") ? "/" : "", name);
		if (!child_path) {
			ret = -ENOMEM;
			goto out;
		}
		child_inode =
		    kasumi_vnode_new_virtual(dir->i_sb, child_path, dir);
		kfree(child_path);
	}
	if (IS_ERR(child_inode))
		ret = PTR_ERR(child_inode);
out:
	kasumi_identity_put(identity);
	if (leaf.dentry)
		kasumi_path_put(&leaf);
	kfree(name);
	kfree(visible_path);
	module_put(THIS_MODULE);
	if (ret)
		return ERR_PTR(ret);
	return child_inode ? d_splice_alias(child_inode, dentry) : NULL;
}

/* ---- directory vnode: create family delegates to the pinned source dir ----
 *
 * When a directory-source redirect's vnode receives a namespace mutation
 * (create/mkdir/mknod/symlink/unlink/rmdir/link), forward it to the pinned
 * source directory via the captured vfs_* helper, so the redirect is
 * writable-through like a bind mount: the source's DAC/SELinux govern,
 * evaluated against the caller's creds inside the vfs_* helper.  A pure-virtual
 * directory (F_VIRTUAL_DIR, no source) is a synthetic container and read-only.
 * Mutation sink (Final Phase 1b).
 */

/* Source mutations require paired mount write protection. */
static int KASUMI_NOCFI kasumi_vnode_src_want_write(const struct path *src)
{
	int (*want)(struct vfsmount *) = kasumi_mnt_want_write_addr;

	if (!want || !kasumi_mnt_drop_write_addr)
		return -EOPNOTSUPP;
	return want(src->mnt);
}

static void KASUMI_NOCFI kasumi_vnode_src_drop_write(const struct path *src)
{
	void (*drop)(struct vfsmount *) = kasumi_mnt_drop_write_addr;

	if (drop && kasumi_mnt_want_write_addr)
		drop(src->mnt);
}

/*
 * Manufacture a child dentry inside the pinned source directory named like the
 * visible target @vis.  On success returns the source child (negative for a
 * create, positive for a remove) with the source dir inode LOCKED — the caller
 * releases with inode_unlock(*dir_out) + dput(child).  I_MUTEX_PARENT2 keeps
 * lockdep from confusing this with the visible parent our VFS caller already
 * holds at I_MUTEX_PARENT.  On error returns ERR_PTR and leaves nothing locked.
 */
static KASUMI_NOCFI struct dentry *
kasumi_vnode_src_child(struct kasumi_vnode_info *info,
		       const struct dentry *vis, struct inode **dir_out)
{
	struct inode *src_dir;
	struct dentry *child;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	struct qstr name = vis->d_name;
#endif

	if (!info->source.dentry || !info->source.mnt)
		return ERR_PTR(-EROFS);
	if (!kasumi_lookup_one)
		return ERR_PTR(-EOPNOTSUPP);
	src_dir = d_inode(info->source.dentry);
	if (!src_dir || !S_ISDIR(src_dir->i_mode))
		return ERR_PTR(-ENOTDIR);
	inode_lock_nested(src_dir, I_MUTEX_PARENT2);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	child = kasumi_lookup_one(mnt_idmap(info->source.mnt), &name,
				 info->source.dentry);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
	child = kasumi_lookup_one(KVN_SRC_IDMAP(info->source.mnt)
		vis->d_name.name, info->source.dentry, vis->d_name.len);
#else
	child = kasumi_lookup_one(vis->d_name.name, info->source.dentry,
				 vis->d_name.len);
#endif
	if (IS_ERR(child)) {
		inode_unlock(src_dir);
		return child;
	}
	*dir_out = src_dir;
	return child;
}

/*
 * Begin a delegated directory mutation.  Pin the module first: like
 * kasumi_vnode_dir_lookup, these are sleeping callbacks on our static i_op
 * table, so an in-flight op must keep the module-refcount gate raised or a
 * cooperative unload could free our text underneath it.  Then take source-mount
 * write protection and manufacture the locked source child.  On any failure
 * everything acquired here is unwound and an ERR_PTR is returned; on success
 * pair with kasumi_vnode_src_end().
 */
static struct dentry *kasumi_vnode_src_begin(struct kasumi_vnode_info *info,
					     const struct dentry *vis,
					     struct inode **dir_out)
{
	struct dentry *child;
	int ret;

	if (!try_module_get(THIS_MODULE))
		return ERR_PTR(-ENOENT);
	ret = kasumi_vnode_src_want_write(&info->source);
	if (ret) {
		module_put(THIS_MODULE);
		return ERR_PTR(ret);
	}
	child = kasumi_vnode_src_child(info, vis, dir_out);
	if (IS_ERR(child)) {
		kasumi_vnode_src_drop_write(&info->source);
		module_put(THIS_MODULE);
	}
	return child;
}

static void kasumi_vnode_src_end(struct kasumi_vnode_info *info,
				 struct inode *src_dir, struct dentry *child)
{
	kasumi_vnode_copyattr_locked(info->inode, src_dir);
	inode_unlock(src_dir);
	kasumi_vnode_src_drop_write(&info->source);
	if (child)
		dput(child);
	module_put(THIS_MODULE);
}

/* Allocate publication state before changing the source filesystem. */
static struct inode *kasumi_vnode_prepare_child(struct inode *dir,
	struct dentry *visible, umode_t mode)
{
	struct kasumi_vnode_info *parent = dir->i_private;
	struct kasumi_inode_identity *identity;
	struct kasumi_vnode_info *info;
	struct inode *inode;
	int ret;

	ret = kasumi_virtual_track_dentry(visible);
	if (ret)
		return ERR_PTR(ret);
	ret = kasumi_identity_source_reserve(&identity);
	if (ret)
		return ERR_PTR(ret);
	inode = kasumi_vnode_allocate(dir->i_sb, identity);
	if (IS_ERR(inode)) {
		kasumi_identity_put(identity);
		return inode;
	}
	info = inode->i_private;
	ret = kasumi_identity_domain_reserve(parent->identity_domain,
		&info->identity_hold);
	if (ret) {
		iput(inode);
		return ERR_PTR(ret);
	}
	if (S_ISDIR(mode)) {
		info->identity_domain = parent->identity_domain;
		kasumi_identity_domain_get(info->identity_domain);
	}
	info->flags = parent->flags & KASUMI_VNODE_F_BYPASS;
	return inode;
}

static int KASUMI_NOCFI kasumi_vnode_publish_child(struct inode **prepared,
	const struct path *src_parent, struct dentry *src_child, struct dentry *visible)
{
	struct path source = { .mnt = src_parent->mnt, .dentry = src_child };
	struct inode *backing = d_inode(src_child), *inode = *prepared;
	struct kasumi_vnode_info *info = inode->i_private;
	u8 flags = info->flags;
	int ret;

	if (!backing)
		return -ENOENT;
	info->identity = kasumi_identity_source_bind(info->identity,
		backing->i_sb->s_dev, backing->i_ino);
	kasumi_identity_domain_commit(info->identity_hold, info->identity);
	info->identity_hold = NULL;
	if (S_ISDIR(backing->i_mode))
		flags |= KASUMI_VNODE_F_DIR;
	else if (S_ISLNK(backing->i_mode))
		flags |= KASUMI_VNODE_F_LNK;
	else if (special_file(backing->i_mode))
		flags |= KASUMI_VNODE_F_SPECIAL;
	ret = kasumi_vnode_attach_source(inode, &source, flags);
	if (ret) {
		/* The source committed. Retry lookup after a label-copy failure. */
		d_drop(visible);
		return ret;
	}
	if (!S_ISDIR(backing->i_mode))
		inode = kasumi_vnode_cache_publish(inode);
	*prepared = NULL;
	d_instantiate(visible, inode);
	return 0;
}

static int KASUMI_NOCFI kasumi_vnode_dir_create(KVN_IDMAP_ARG struct inode *dir,
						struct dentry *dentry,
						umode_t mode, bool excl)
{
	struct kasumi_vnode_info *info = dir->i_private;
	struct inode *src_dir = NULL, *prepared;
	struct dentry *child;
	int ret;

	if (!info)
		return -ENOTDIR;
	if (!info->source.dentry)
		return -EROFS;
	if (!kasumi_vfs_create)
		return -EOPNOTSUPP;
	prepared = kasumi_vnode_prepare_child(dir, dentry, mode);
	if (IS_ERR(prepared))
		return PTR_ERR(prepared);
	child = kasumi_vnode_src_begin(info, dentry, &src_dir);
	if (IS_ERR(child)) {
		iput(prepared);
		return PTR_ERR(child);
	}
	ret = kasumi_vfs_create(KVN_SRC_IDMAP(info->source.mnt) src_dir, child,
				mode, excl);
	if (ret == 0)
		ret = kasumi_vnode_publish_child(&prepared, &info->source, child,
						 dentry);
	iput(prepared);
	kasumi_vnode_src_end(info, src_dir, child);
	return ret;
}

static int KASUMI_NOCFI kasumi_vnode_dir_mkdir_common(struct inode *dir,
					      struct dentry *dentry,
					      umode_t mode)
{
	struct kasumi_vnode_info *info = dir->i_private;
	struct inode *src_dir = NULL, *prepared;
	struct dentry *child;
	int ret;

	if (!info)
		return -ENOTDIR;
	if (!info->source.dentry)
		return -EROFS;
	if (!kasumi_vfs_mkdir)
		return -EOPNOTSUPP;
	prepared = kasumi_vnode_prepare_child(dir, dentry, S_IFDIR | mode);
	if (IS_ERR(prepared))
		return PTR_ERR(prepared);
	child = kasumi_vnode_src_begin(info, dentry, &src_dir);
	if (IS_ERR(child)) {
		iput(prepared);
		return PTR_ERR(child);
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	{
		struct dentry *created;

		/* vfs_mkdir() consumes @child on error or when it substitutes a
		 * different dentry, and returns the dentry the caller must release. */
		created = kasumi_vfs_mkdir(KVN_SRC_IDMAP(info->source.mnt)
					  src_dir, child, mode);
		if (IS_ERR(created)) {
			ret = PTR_ERR(created);
			child = NULL;
		} else {
			child = created;
			ret = kasumi_vnode_publish_child(&prepared, &info->source,
						 child, dentry);
		}
	}
#else
	ret = kasumi_vfs_mkdir(KVN_SRC_IDMAP(info->source.mnt) src_dir, child,
			       mode);
	if (ret == 0)
		ret = kasumi_vnode_publish_child(&prepared, &info->source, child,
						 dentry);
#endif
	iput(prepared);
	kasumi_vnode_src_end(info, src_dir, child);
	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
static struct dentry *KASUMI_NOCFI
kasumi_vnode_dir_mkdir(KVN_IDMAP_ARG struct inode *dir,
			struct dentry *dentry, umode_t mode)
{
	int ret = kasumi_vnode_dir_mkdir_common(dir, dentry, mode);

	return ret ? ERR_PTR(ret) : NULL;
}
#else
static int KASUMI_NOCFI kasumi_vnode_dir_mkdir(KVN_IDMAP_ARG struct inode *dir,
					       struct dentry *dentry,
					       umode_t mode)
{
	return kasumi_vnode_dir_mkdir_common(dir, dentry, mode);
}
#endif

static int KASUMI_NOCFI kasumi_vnode_dir_mknod(KVN_IDMAP_ARG struct inode *dir,
					       struct dentry *dentry,
					       umode_t mode, dev_t dev)
{
	struct kasumi_vnode_info *info = dir->i_private;
	struct inode *src_dir = NULL, *prepared;
	struct dentry *child;
	int ret;

	if (!info)
		return -ENOTDIR;
	if (!info->source.dentry)
		return -EROFS;
	if (!kasumi_vfs_mknod)
		return -EOPNOTSUPP;
	prepared = kasumi_vnode_prepare_child(dir, dentry, mode);
	if (IS_ERR(prepared))
		return PTR_ERR(prepared);
	child = kasumi_vnode_src_begin(info, dentry, &src_dir);
	if (IS_ERR(child)) {
		iput(prepared);
		return PTR_ERR(child);
	}
	/* A device node created on the (nodev) source is real but unopenable —
	 * consistent with the source itself; pass the result through untouched. */
	ret = kasumi_vfs_mknod(KVN_SRC_IDMAP(info->source.mnt) src_dir, child,
			       mode, dev);
	if (ret == 0)
		ret = kasumi_vnode_publish_child(&prepared, &info->source, child,
						 dentry);
	iput(prepared);
	kasumi_vnode_src_end(info, src_dir, child);
	return ret;
}

static int KASUMI_NOCFI kasumi_vnode_dir_symlink(KVN_IDMAP_ARG
						 struct inode *dir,
						 struct dentry *dentry,
						 const char *oldname)
{
	struct kasumi_vnode_info *info = dir->i_private;
	struct inode *src_dir = NULL, *prepared;
	struct dentry *child;
	int ret;

	if (!info)
		return -ENOTDIR;
	if (!info->source.dentry)
		return -EROFS;
	if (!kasumi_vfs_symlink)
		return -EOPNOTSUPP;
	prepared = kasumi_vnode_prepare_child(dir, dentry, S_IFLNK);
	if (IS_ERR(prepared))
		return PTR_ERR(prepared);
	child = kasumi_vnode_src_begin(info, dentry, &src_dir);
	if (IS_ERR(child)) {
		iput(prepared);
		return PTR_ERR(child);
	}
	ret = kasumi_vfs_symlink(KVN_SRC_IDMAP(info->source.mnt) src_dir, child,
				 oldname);
	if (ret == 0)
		ret = kasumi_vnode_publish_child(&prepared, &info->source, child,
						 dentry);
	iput(prepared);
	kasumi_vnode_src_end(info, src_dir, child);
	return ret;
}

static int KASUMI_NOCFI kasumi_vnode_dir_unlink(struct inode *dir,
						struct dentry *dentry)
{
	struct kasumi_vnode_info *info = dir->i_private;
	struct inode *src_dir = NULL;
	struct dentry *child;
	int ret;

	if (!info)
		return -ENOTDIR;
	if (!info->source.dentry)
		return -EROFS;
	if (!kasumi_vfs_unlink)
		return -EOPNOTSUPP;
	child = kasumi_vnode_src_begin(info, dentry, &src_dir);
	if (IS_ERR(child))
		return PTR_ERR(child);
	if (d_really_is_negative(child))
		ret = -ENOENT;
	else
		ret = kasumi_vfs_unlink(KVN_SRC_IDMAP(info->source.mnt) src_dir,
					child, NULL);
	kasumi_vnode_src_end(info, src_dir, child);
	/* Reflect the removal on the synthetic child so it evicts with nlink 0;
	 * the VFS caller d_delete()s the visible dentry after we return. */
	if (ret == 0 && d_really_is_positive(dentry))
		drop_nlink(d_inode(dentry));
	return ret;
}

static int KASUMI_NOCFI kasumi_vnode_dir_rmdir(struct inode *dir,
					       struct dentry *dentry)
{
	struct kasumi_vnode_info *info = dir->i_private;
	struct inode *src_dir = NULL;
	struct dentry *child;
	int ret;

	if (!info)
		return -ENOTDIR;
	if (!info->source.dentry)
		return -EROFS;
	if (!kasumi_vfs_rmdir)
		return -EOPNOTSUPP;
	child = kasumi_vnode_src_begin(info, dentry, &src_dir);
	if (IS_ERR(child))
		return PTR_ERR(child);
	if (d_really_is_negative(child))
		ret = -ENOENT;
	else
		ret = kasumi_vfs_rmdir(KVN_SRC_IDMAP(info->source.mnt) src_dir,
				       child);
	kasumi_vnode_src_end(info, src_dir, child);
	if (ret == 0 && d_really_is_positive(dentry)) {
		clear_nlink(d_inode(dentry));	/* removed dir: no more links */
	}
	return ret;
}

static int KASUMI_NOCFI kasumi_vnode_dir_link(struct dentry *old_dentry,
					      struct inode *dir,
					      struct dentry *dentry)
{
	struct kasumi_vnode_info *info = dir->i_private;
	struct inode *old_vi = d_inode(old_dentry);
	struct kasumi_vnode_info *old_info =
		(old_vi && kasumi_vnode_is_ours(old_vi)) ? old_vi->i_private :
							   NULL;
	struct inode *src_dir = NULL, *prepared;
	struct dentry *child;
	int ret;

	if (!info)
		return -ENOTDIR;
	if (!info->source.dentry)
		return -EROFS;
	if (!kasumi_vfs_link)
		return -EOPNOTSUPP;
	/* The hardlink target is a visible dentry; it must resolve to a real
	 * source (its own redirect's pinned source).  A pure-virtual or foreign
	 * inode has no backing store to link — report cross-device. */
	if (!old_info || !old_info->source.dentry)
		return -EXDEV;
	prepared = kasumi_vnode_prepare_child(dir, dentry, old_vi->i_mode);
	if (IS_ERR(prepared))
		return PTR_ERR(prepared);
	child = kasumi_vnode_src_begin(info, dentry, &src_dir);
	if (IS_ERR(child)) {
		iput(prepared);
		return PTR_ERR(child);
	}
	ret = kasumi_vfs_link(old_info->source.dentry,
			      KVN_SRC_IDMAP(info->source.mnt) src_dir, child,
			      NULL);
	if (ret == 0)
		ret = kasumi_vnode_publish_child(&prepared, &info->source, child,
						 dentry);
	iput(prepared);
	kasumi_vnode_src_end(info, src_dir, child);
	return ret;
}

/* Syscall rename is routed before VFS locking by kasumi_rename_view. */
static int kasumi_vnode_dir_rename(KVN_IDMAP_ARG struct inode *old_dir,
	struct dentry *old_dentry, struct inode *new_dir,
	struct dentry *new_dentry, unsigned int flags)
{
	/* A direct kernel caller already owns visible locks at this point. */
	return -EOPNOTSUPP;
}

static const struct inode_operations kasumi_vnode_dir_iops = {
	.permission = kasumi_vnode_permission,
	.lookup = kasumi_vnode_dir_lookup,
	.getattr = kasumi_vnode_getattr,
	.setattr = kasumi_vnode_setattr,
	.listxattr = kasumi_vnode_listxattr,
	.create = kasumi_vnode_dir_create,
	.mkdir = kasumi_vnode_dir_mkdir,
	.mknod = kasumi_vnode_dir_mknod,
	.symlink = kasumi_vnode_dir_symlink,
	.unlink = kasumi_vnode_dir_unlink,
	.rmdir = kasumi_vnode_dir_rmdir,
	.link = kasumi_vnode_dir_link,
	.rename = kasumi_vnode_dir_rename,
};

static const struct file_operations kasumi_vnode_dir_fops = {
	.owner = THIS_MODULE,
	.lock = kasumi_file_lock_posix,
	.flock = kasumi_file_lock_flock,
	.setlease = kasumi_file_lock_setlease,
	.open = kasumi_vnode_dir_open,
	.release = kasumi_vnode_release,
	.read = generic_read_dir,
	.iterate_shared = kasumi_vnode_dir_iterate,
	.llseek = kasumi_vnode_llseek,
	.fsync = kasumi_vnode_fsync,
	.flush = kasumi_vnode_flush,
	.unlocked_ioctl = kasumi_vnode_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = kasumi_vnode_compat_ioctl,
#endif
	.poll = kasumi_vnode_poll,
	.fasync = kasumi_vnode_fasync,
	.fadvise = kasumi_vnode_fadvise,
};

/* Copy through the public LSM context API and propagate every failure. */
static KASUMI_NOCFI int kasumi_vnode_clone_sid(struct inode *vnode,
					      struct inode *source)
{
	int ret;

	if (!vnode || !source || !kasumi_security_inode_getsecctx ||
	    !kasumi_security_inode_notifysecctx || !kasumi_security_release_secctx)
		return -EOPNOTSUPP;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
	{
		struct lsm_context context = {};

		ret = kasumi_security_inode_getsecctx(source, &context);
		if (!ret) {
			if (!context.context || !context.len)
				ret = -EIO;
			else
				ret = kasumi_security_inode_notifysecctx(
					vnode, context.context, context.len);
		}
		if (context.context)
			kasumi_security_release_secctx(&context);
	}
#else
	{
		void *context = NULL;
		u32 length = 0;

		ret = kasumi_security_inode_getsecctx(source, &context, &length);
		if (!ret) {
			if (!context || !length)
				ret = -EIO;
			else
				ret = kasumi_security_inode_notifysecctx(vnode, context, length);
		}
		if (context)
			kasumi_security_release_secctx(context, length);
	}
#endif
	return ret;
}

static struct inode *kasumi_vnode_allocate(struct super_block *sb,
	struct kasumi_inode_identity *identity)
{
	struct kasumi_vnode_info *info;
	struct inode *inode;

	info = kzalloc(sizeof(*info), GFP_NOFS);
	if (!info)
		return ERR_PTR(-ENOMEM);
	if (!kasumi_sop_vnode_get(sb)) {
		kfree(info);
		return ERR_PTR(-ESHUTDOWN);
	}
	inode = kasumi_sop_new_inode(sb);
	if (!inode) {
		kasumi_sop_vnode_put(sb);
		kfree(info);
		return ERR_PTR(-ENOMEM);
	}
	lockdep_set_class(&inode->i_rwsem, &kasumi_vnode_i_mutex_key);
	mutex_init(&info->label_lock);
	mutex_init(&info->io_notify_lock);
	info->identity = identity;
	info->v_ino = kasumi_identity_ino(identity);
	info->sop_vnode_ref = true;
	info->inode = inode;
	inode->i_private = info;
	inode->i_ino = info->v_ino;
	/* Mark ownership before an unpublished inode can enter reclaim. */
	inode->i_op = &kasumi_vnode_file_iops;
	return inode;
}

static int kasumi_vnode_attach_source(struct inode *inode,
	const struct path *source, u8 flags)
{
	struct kasumi_vnode_info *info = inode->i_private;
	struct inode *r_inode = d_inode(source->dentry);
	int ret;

	info->source = *source;
	kasumi_path_get(&info->source);
	info->flags = flags;
	info->v_ino = kasumi_identity_ino(info->identity);
	inode->i_ino = info->v_ino;
	inode->i_uid = r_inode->i_uid;
	inode->i_gid = r_inode->i_gid;

	if (r_inode && (flags & KASUMI_VNODE_F_SPECIAL) &&
	    (S_ISCHR(r_inode->i_mode) || S_ISBLK(r_inode->i_mode) ||
	     S_ISFIFO(r_inode->i_mode))) {
		/* char/blk/fifo source wrapper: mint S_IFREG so path_openat's
		 * may_open() does not apply may_open_dev() on the nodev visible
		 * mount; the special fops' .open delegates to the real source via
		 * dentry_open (which bypasses may_open) and the data plane forwards
		 * there.  Remember the real type+rdev so getattr still presents a
		 * device/fifo.  No shared page cache: the device owns its mapping. */
		info->special_mode = r_inode->i_mode;
		info->special_rdev = r_inode->i_rdev;
		inode->i_mode = S_IFREG | (r_inode->i_mode & 07777);
		inode->i_op = &kasumi_vnode_file_iops;
		inode->i_fop = &kasumi_vnode_special_fops;
	} else {
		inode->i_mode = r_inode->i_mode;
		if (r_inode) {
			inode->i_size = i_size_read(r_inode);
			/* Share the source page cache so the generic mmap/read path
			 * serves source content without a private snapshot.  Directories
			 * don't mmap and iterate through the pinned source, so keep their
			 * own mapping and carry the source link count. */
			if (!S_ISDIR(r_inode->i_mode))
				inode->i_mapping = r_inode->i_mapping;
			else
				set_nlink(inode, r_inode->i_nlink);
		}

		if ((flags & KASUMI_VNODE_F_DIR) ||
		    (r_inode && S_ISDIR(r_inode->i_mode))) {
			inode->i_op = &kasumi_vnode_dir_iops;
			inode->i_fop = &kasumi_vnode_dir_fops;
		} else {
			inode->i_op = &kasumi_vnode_file_iops;
			inode->i_fop = &kasumi_vnode_file_fops;
		}
	}
	/* Deliberately NOT S_PRIVATE: the vnode must stay LSM-visible so SELinux
	 * serves security.selinux from the in-core SID we clone below and applies
	 * AVC using the source's label.  S_PRIVATE would make
	 * security_inode_getsecurity() short-circuit to -EOPNOTSUPP, leaking an
	 * empty/ENODATA label through the fs xattr fallback. */
	inode->i_flags |= S_NOATIME | S_NOCMTIME | S_NOSEC;
	inode->i_opflags |= IOP_XATTR;
	if (!S_ISLNK(inode->i_mode))
		inode->i_opflags |= IOP_NOFOLLOW;

	/* Project the source's SELinux label onto the vnode (view-consistency:
	 * security.selinux must match the source).  Done last, after i_security is
	 * allocated by kasumi_sop_new_inode() and all identity is in place. */
	ret = kasumi_vnode_refresh_sid(inode, r_inode, true);
	if (ret)
		return ret;
	return 0;
}

struct inode *kasumi_vnode_new(struct super_block *sb, const struct path *source, umode_t mode, u8 flags)
{
	struct kasumi_inode_identity *identity;
	struct inode *inode, *r_inode;
	bool cacheable;
	int ret;

	if (!sb || !source || !source->dentry || !source->mnt)
		return ERR_PTR(-EINVAL);
	r_inode = d_inode(source->dentry);
	if (!r_inode)
		return ERR_PTR(-ENOENT);
	ret = kasumi_identity_source_get(r_inode->i_sb->s_dev, r_inode->i_ino, &identity);
	if (ret)
		return ERR_PTR(ret);
	if (S_ISCHR(r_inode->i_mode) || S_ISBLK(r_inode->i_mode) || S_ISFIFO(r_inode->i_mode))
		flags |= KASUMI_VNODE_F_SPECIAL;
	cacheable = !S_ISDIR(r_inode->i_mode);
#ifdef KASUMI_VNODE_F_SU
	cacheable = cacheable && !(flags & KASUMI_VNODE_F_SU);
#endif
	if (cacheable) {
		inode = kasumi_vnode_cached(sb, source, kasumi_identity_ino(identity), flags);
		if (inode) {
			kasumi_identity_put(identity);
			ret = kasumi_vnode_refresh_sid(inode, r_inode, true);
			if (ret) {
				iput(inode);
				return ERR_PTR(ret);
			}
			return inode;
		}
	}
	inode = kasumi_vnode_allocate(sb, identity);
	if (IS_ERR(inode)) {
		kasumi_identity_put(identity);
		return inode;
	}
	ret = kasumi_vnode_attach_source(inode, source, flags);
	if (ret) {
		iput(inode);
		return ERR_PTR(ret);
	}
	if (S_ISDIR(r_inode->i_mode)) {
		struct kasumi_vnode_info *info = inode->i_private;

		info->identity_domain = kasumi_identity_domain_find(identity);
	}
	return cacheable ? kasumi_vnode_cache_publish(inode) : inode;
}

int kasumi_vnode_set_visible_path(struct inode *inode, const char *path)
{
	struct kasumi_vnode_info *info = inode->i_private;

	/* Only unpublished directory inodes carry topology paths. */
	if (!S_ISDIR(inode->i_mode) || !info || info->visible_path)
		return -EINVAL;
	info->visible_path = kstrdup(path, GFP_KERNEL);
	return info->visible_path ? 0 : -ENOMEM;
}

struct inode *kasumi_vnode_new_virtual(struct super_block *sb,
				       const char *visible_path,
				       struct inode *label_donor)
{
	struct inode *inode;
	struct kasumi_vnode_info *info;
	struct kasumi_inode_identity *identity;
	unsigned long v_ino;
	int ret;

	if (!sb || !visible_path)
		return ERR_PTR(-EINVAL);
	ret = kasumi_identity_path_get(visible_path, &identity);
	if (ret)
		return ERR_PTR(ret);
	v_ino = kasumi_identity_ino(identity);
	info = kzalloc(sizeof(*info), GFP_NOFS);
	if (!info) {
		kasumi_identity_put(identity);
		return ERR_PTR(-ENOMEM);
	}
	info->identity = identity;
	mutex_init(&info->label_lock);
	mutex_init(&info->io_notify_lock);
	info->visible_path = kstrdup(visible_path, GFP_KERNEL);
	if (!info->visible_path) {
		kasumi_identity_put(identity);
		kfree(info);
		return ERR_PTR(-ENOMEM);
	}
	info->v_ino = v_ino;
	info->flags = KASUMI_VNODE_F_DIR | KASUMI_VNODE_F_VIRTUAL_DIR;
	if (!kasumi_sop_vnode_get(sb)) {
		kfree(info->visible_path);
		kasumi_identity_put(identity);
		kfree(info);
		return ERR_PTR(-ESHUTDOWN);
	}
	inode = kasumi_sop_new_inode(sb);
	if (!inode) {
		kasumi_sop_vnode_put(sb);
		kfree(info->visible_path);
		kasumi_identity_put(identity);
		kfree(info);
		return ERR_PTR(-ENOMEM);
	}
	lockdep_set_class(&inode->i_rwsem, &kasumi_vnode_i_mutex_key);
	info->sop_vnode_ref = true;
	info->inode = inode;

	inode->i_private = info;
	inode->i_ino = v_ino;
	/* A synthesized container directory: world traversable/listable, owned by
	 * root, no data source.  lookup/iterate resolve descendants from the rule
	 * table; getattr fills from this inode with the projected ino/dev.  Mode is
	 * kept permissive (0555) rather than cloned from the donor so a restrictive
	 * ancestor cannot make the injected subtree unreachable to the view app. */
	inode->i_mode = S_IFDIR | 0555;
	inode->i_uid = GLOBAL_ROOT_UID;
	inode->i_gid = GLOBAL_ROOT_GID;
	set_nlink(inode, 2);
	inode->i_op = &kasumi_vnode_dir_iops;
	inode->i_fop = &kasumi_vnode_dir_fops;
	inode->i_flags |= S_NOATIME | S_NOCMTIME | S_NOSEC;
	inode->i_opflags |= IOP_NOFOLLOW;
	/* Project the deepest real ancestor's SELinux label onto the synthesized
	 * directory so getxattr(security.selinux)/ls -Z report a plausible context
	 * instead of the pseudo default.  The donor is on the visible path the app
	 * already traversed, so its label is app-searchable and cloning it does not
	 * make the virtual dir unsearchable under AVC. */
	if (label_donor) {
		ret = kasumi_vnode_refresh_sid(inode, label_donor, true);
		if (ret) {
			iput(inode);
			return ERR_PTR(ret);
		}
	}
	return inode;
}
