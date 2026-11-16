/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - real-superblock virtual inode backend (Tier 3 data plane).
 *
 * A virtual node is a real inode allocated on the *visible path's own*
 * superblock (kasumi_sop_new_inode(dir->i_sb)), so dentry and inode share a superblock
 * (no cross-sb pairing) and stat naturally reports the containing filesystem's
 * device.  Identity (ino) is projected from Kasumi's captured rule via the
 * scheme-A vnode identity, so stat/fstat/maps/ls all agree.  Real I/O, mmap,
 * xattr and symlink resolution are delegated to the pinned data source, which
 * keeps SELinux AVC decisions and security.selinux tied to the source without
 * writing an inode SID.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _KASUMI_VNODE_H
#define _KASUMI_VNODE_H

#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/path.h>
#include <linux/types.h>

#define KASUMI_VNODE_F_DIR		(1u << 0)  /* node is a directory */
#define KASUMI_VNODE_F_VIRTUAL_DIR	(1u << 1)  /* synthesized dir, no source */
#define KASUMI_VNODE_F_LNK		(1u << 2)  /* node is a symlink */
#define KASUMI_VNODE_F_SPECIAL		(1u << 3)  /* char/blk/fifo source wrapper */
#define KASUMI_VNODE_F_BYPASS (1u << 5)

/*
 * Per virtual inode state, stored in inode->i_private.  @source is a pinned
 * reference to the data backing this visible node; it is {NULL,NULL} for a
 * pure virtual directory that only exists to host injected children.
 */
struct kasumi_inode_identity;
struct kasumi_io_notify;

struct kasumi_vnode_info {
	struct hlist_node cache_node;
	struct inode *inode;
	struct kasumi_inode_identity *identity;
	struct kasumi_identity_domain *identity_domain;
	struct kasumi_identity_hold *identity_hold;
	struct kasumi_io_notify *io_notify;
	struct mutex io_notify_lock;
	struct mutex label_lock;
	struct path source;
	unsigned long v_ino;
	u8 flags;
	/* Immutable path anchor for a configured directory. Mutable descendants
	 * derive their paths from the current dentry ancestry. */
	char *visible_path;
	/* Odd while a child rename commits its backing and visible dentries. */
	atomic_t rename_seq;
	/* Held in the per-superblock reclaim owner until destroy_inode releases
	 * this generic inode object. */
	bool sop_vnode_ref;
	/* For a char/blk/fifo source wrapper (KASUMI_VNODE_F_SPECIAL): the vnode
	 * inode is minted S_IFREG so it passes may_open_dev on a nodev visible
	 * mount and uses our special fops, but stat must present the source's real
	 * type and rdev.  0 when the node is not a special wrapper. */
	umode_t special_mode;
	dev_t special_rdev;
};

/*
 * Allocate a virtual inode on @sb (the visible parent's superblock) backed by
 * @source. The inode holds a source identity reference and @flags carry the
 * node kind. Returns ERR_PTR on failure. On success it owns a pinned copy of
 * @source and must be released through the ordinary iput()/eviction path with
 * the superblock destroy_inode shim calling kasumi_vnode_free_info().
 */
struct inode *kasumi_vnode_new(struct super_block *sb, const struct path *source, umode_t mode, u8 flags);

/*
 * Allocate a pure-virtual directory inode (KASUMI_VNODE_F_VIRTUAL_DIR) on @sb
 * with no data source.  @visible_path is the node's own visible path; its
 * lookup/iterate resolve children against the rule table (kasumi_rule_vpath_*).
 * @label_donor, if non-NULL, is the inode (the deepest real ancestor, or the
 * parent virtual dir) whose SELinux label is cloned onto the node for a
 * plausible security.selinux.  Owns a copy of @visible_path, released through
 * kasumi_vnode_free_info.
 */
/* Set once before a newly allocated directory inode is published. */
int kasumi_vnode_set_visible_path(struct inode *inode, const char *path);
/* Caller frees the snapshot; NULL means no configured ancestor. */
char *kasumi_vnode_visible_path(struct dentry *dentry);

struct inode *kasumi_vnode_new_virtual(struct super_block *sb,
				       const char *visible_path,
				       struct inode *label_donor);

/* True if @inode is a Kasumi virtual node (its i_op is one of our tables). */
bool kasumi_vnode_is_ours(const struct inode *inode);
/* Call after all vnode files and module entry points have drained. */
void kasumi_vnode_fops_exit(void);
/* Keep native handle encoders guarded until every vnode has been reclaimed. */
int kasumi_vnode_handle_init(void);
void kasumi_vnode_handle_exit(void);
/* Initialize before publishing vnode fops; exit after all file refs drain. */
int kasumi_vnode_aio_init(void);
bool kasumi_vnode_aio_busy(void);
void kasumi_vnode_aio_exit(void);

/* Return 1 with a pinned source, 0 for an unbacked inode, or a negative error. */
int kasumi_vnode_source_path(const struct dentry *dentry, struct path *source);
int kasumi_vnode_refresh_label(const struct dentry *dentry);

/* Consumes one opened file reference before the caller denies writes. */
struct file *kasumi_vnode_exec_open(struct file *file);

/* Read current source capabilities in sleepable context. */
int kasumi_vnode_read_caps(const struct dentry *dentry,
			   struct cpu_vfs_cap_data *out, bool *handled);

/*
 * Release the i_private state of a virtual inode.  Called from the hijacked
 * superblock destroy_inode path (Tier 3.1); safe on non-virtual inodes.
 */
void kasumi_vnode_free_info(struct inode *inode);

#endif /* _KASUMI_VNODE_H */
