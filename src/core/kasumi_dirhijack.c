/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - parent-directory lookup/iterate hijack engine (Tier 3.1).
 *
 * Installs, on a rule's real visible parent directory:
 *   - inode_operations->lookup shadow: resolving the visible child yields a
 *     Kasumi virtual inode (kasumi_vnode_new) through the ordinary VFS lookup
 *     chokepoint, replacing the per-syscall TSR path routes;
 *   - file_operations->iterate_shared shadow: injects the virtual children into
 *     readdir (and suppresses a real entry of the same name to avoid dupes);
 *   - a d_revalidate on manufactured dentries: gates visibility per observer so
 *     a cached virtual dentry is not served to a UID the rule does not target;
 *   - super_operations shadow (destroy/evict/drop): reclaims virtual inodes
 *     without letting the real filesystem's evict run on a manufactured inode
 *     (free_inode is left original so the fs inode container is still freed).
 *
 * Teardown safety: the shadow op vectors carry no module-owner pin, and the
 * hijacked callbacks sleep (allocation, ->lookup, path_put).  All callbacks run
 * inside an SRCU read section; kasumi_dirhijack_clear() restores the original op
 * pointers, drops the affected dentries, then Tasks-RCU plus SRCU drain any
 * stale pointer fetch and in-flight callback before the pinned dentries and
 * meta objects are freed.  SRCU is required because these callbacks may sleep.
 *
 * Scope (v1): inject a virtual *file* into an existing real directory.  Nested
 * pure-virtual directory topology is not built here.
 *
 * DEFAULT-ON (kasumi_dirhijack=1): the VFS lookup layer is the production path
 * view transport, and the coverage gate keeps TSR as a live fallback for any
 * rule class it cannot yet serve.  Set kasumi_dirhijack=0 to force legacy TSR.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/fsnotify_backend.h>
#include <linux/kprobes.h>
#include <uapi/linux/magic.h>
#include <linux/hashtable.h>
#include <linux/list.h>
#include <linux/llist.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/srcu.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/workqueue.h>

#include "kasumi_base.h"
#include "kasumi_dirhijack.h"
#include "kasumi_fop_override.h"
#include "kasumi_dir_view.h"
#include "kasumi_path_policy.h"
#include "kasumi_runtime.h"
#include "kasumi_sop_shadow.h"
#include "kasumi_vfs_hooks.h"
#include "kasumi_vnode.h"

static int kasumi_dirhijack_param = 1;
module_param_named(kasumi_dirhijack, kasumi_dirhijack_param, int, 0600);
MODULE_PARM_DESC(kasumi_dirhijack,
		 "Serve the path view through the VFS lookup layer, retiring the TSR path routes once every active view rule is covered (default 1); set 0 to force the legacy TSR transport");

static int kasumi_dirhijack_force;
module_param_named(kasumi_dirhijack_force, kasumi_dirhijack_force, int, 0600);
MODULE_PARM_DESC(kasumi_dirhijack_force,
		 "DBG: bypass view-target gating so any observer sees virtual nodes (test only)");

struct kasumi_dh_iop {
	struct inode_operations fake_iop;	/* must stay first */
	const struct inode_operations *orig_iop;
	struct kasumi_dh_dir *dir;
};

struct kasumi_dh_dir {
	struct dentry *name_parent;
	struct inode *dir_inode;	/* igrab'd real parent directory */
	struct hlist_head children;
	DECLARE_HASHTABLE(child_index, 6);
	struct kasumi_dh_iop *iop_meta;
	spinlock_t lock;
	bool iterate_bound;	/* client of the shared fop_override owner */
	bool iterate_owned;
	bool sop_client;		/* exactly one s_op client per installed dir */
	bool retiring;		/* blocks late d_op installs during CLEAR */
	struct list_head list;
	struct list_head batch_node;
	struct list_head dops;
};

/*
 * A per-dentry clone is required: real filesystems may already provide any of
 * the other dentry callbacks, and replacing their whole vector with one static
 * d_revalidate would silently discard those semantics.  @dentry is dget-held
 * until stale-result work or DEL/CLEAR has restored the vector, dropped the
 * dentry and drained SRCU.
 */
struct kasumi_dh_dop_meta {
	struct dentry_operations shadow_dop;
	struct dentry_operations native_shadow_dop;
	bool native_dop_set;
	const struct dentry_operations *orig_dop;
	struct dentry *dentry;
	struct kasumi_dh_dir *dir;
	unsigned long state;
	unsigned int orig_op_flags;
	u64 generation;
	u64 revision;
	u32 name_hash;
	u16 name_len;
	bool synthetic_negative;
	struct hlist_node node;
	struct list_head retire_node;
	struct list_head dir_node;
	char name[];
};

struct kasumi_dh_child {
	struct dentry *name_dentry;
	struct kasumi_dh_dir *dir;
	struct hlist_node binding_node;
	char *registered_path;
	u32 registered_hash;
	struct hlist_node node;
	struct hlist_node index_node;
	struct rcu_head rcu;
	struct llist_node free_node;
	struct path source;		/* pinned; {NULL} for a hide or virtual dir */
	struct kasumi_inode_identity *identity;
	unsigned long v_ino;
	u64 first_generation;
	u64 last_generation;
	u64 revision;
	u32 name_hash;
	u16 name_len;
	u8 flags;
	unsigned int hide_users;
	unsigned int bypass_hide_users;
	bool legacy;
	u8 hide;			/* 1 = suppress-only: negative lookup, no
					 * vnode, not emitted in readdir (Slice 2) */
	u8 lookup_only;			/* 1 = dh serves lookup (vnode) but not
					 * readdir: the overlay filldir owns emit
					 * and dedup for this name (Slice 4a merge
					 * materialized files) */
	char *vpath;			/* F_VIRTUAL_DIR: the synthesized dir's own
					 * visible path, for rule-table child
					 * resolution (Slice 4c-v2); NULL else */
	char name[];
};

struct kasumi_dh_change {
	struct list_head list;
	struct hlist_node node;
	struct kasumi_dh_dir *dir;
	struct kasumi_dh_child *old_child;
	struct kasumi_dh_child *new_child;
	u64 previous_last;
};

struct kasumi_dirhijack_batch {
	struct list_head changes;
	struct list_head directories;
	DECLARE_HASHTABLE(index, 8);
	u64 generation;
};

static LIST_HEAD(kasumi_dh_dirs);
/* Control-path index; protected by kasumi_dh_lock. */
static DEFINE_HASHTABLE(kasumi_dh_bindings, 10);
#define KASUMI_DH_DOP_HASH_BITS	8
static DEFINE_HASHTABLE(kasumi_dh_dops, KASUMI_DH_DOP_HASH_BITS);
static DEFINE_MUTEX(kasumi_dh_lock);
DEFINE_STATIC_SRCU(kasumi_dh_srcu);
static bool kasumi_dh_ready;
static u64 kasumi_dh_revision;
static struct kprobe kasumi_dh_fuse_probe;
static bool kasumi_dh_fuse_registered;
static struct kprobe kasumi_dh_add_probe;
static bool kasumi_dh_add_registered;
static unsigned long kasumi_dh_simple_lookup_raw;
static unsigned long kasumi_dh_simple_lookup_callable;
static struct kprobe kasumi_dh_splice_probe;
static bool kasumi_dh_splice_registered;
static seqlock_t *kasumi_dh_rename_lock;
static void (*kasumi_dh_native_move)(struct dentry *, struct dentry *, bool);
static void (*kasumi_dh_native_instantiate)(struct dentry *, struct inode *);
static struct dentry *(*kasumi_dh_native_ancestor)(struct dentry *, struct dentry *);
static void (*kasumi_dh_native_rehash)(struct dentry *);
static wait_queue_head_t *(*kasumi_dh_native_lookup_unhash)(struct dentry *);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0) && IS_ENABLED(CONFIG_FS_ENCRYPTION)
static unsigned long kasumi_dh_fscrypt_revalidate;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
static void (*kasumi_dh_native_add)(struct dentry *, struct inode *,
				  const struct dentry_operations *);
#else
static void (*kasumi_dh_native_add)(struct dentry *, struct inode *);
#endif

#define KASUMI_DH_DOP_AUTO_RETIRE	0

static void kasumi_dh_reap_dops_workfn(struct work_struct *work);
static DECLARE_WORK(kasumi_dh_reap_dops_work,
			 kasumi_dh_reap_dops_workfn);
static void kasumi_dh_free_children_workfn(struct work_struct *work);
static DECLARE_WORK(kasumi_dh_free_children_work,
			 kasumi_dh_free_children_workfn);
static LLIST_HEAD(kasumi_dh_free_children);

static struct dentry *kasumi_dh_lookup(struct inode *dir, struct dentry *dentry,
				       unsigned int flags);
static int kasumi_dh_atomic_open(struct inode *dir, struct dentry *dentry,
				struct file *file, unsigned int flags, umode_t mode);
static int kasumi_dh_iterate(struct file *file, struct dir_context *ctx,
			     kasumi_dir_iterate_fn iterate, void *data);
static int kasumi_dh_prepare_dentry_ops(struct kasumi_dh_dir *dir,
	struct dentry *dentry, u64 generation);
static void kasumi_dh_retire_unhashed(struct dentry *dentry);
static int kasumi_dh_set_dentry_ops(struct kasumi_dh_dir *dir,
				    struct dentry *dentry,
				    bool synthetic_negative,
				    bool synthetic_inode, u64 generation, u64 revision);
static void kasumi_dh_child_free(struct kasumi_dh_child *c);

bool kasumi_dirhijack_enabled(void)
{
	return READ_ONCE(kasumi_dh_ready) && READ_ONCE(kasumi_dirhijack_param);
}

/* ---- meta accessors ---------------------------------------------------- */

static struct kasumi_dh_iop *kasumi_dh_iop_of(const struct inode *inode)
{
	const struct inode_operations *iop;

	if (!inode)
		return NULL;
	iop = smp_load_acquire(&inode->i_op);
	if (iop && iop->lookup == kasumi_dh_lookup)
		return container_of(iop, struct kasumi_dh_iop, fake_iop);
	return NULL;
}

static void kasumi_dh_child_link(struct kasumi_dh_dir *dir,
				 struct kasumi_dh_child *child)
{
	child->dir = dir;
	if (child->registered_path)
		hash_add(kasumi_dh_bindings, &child->binding_node,
			 child->registered_hash);
	hlist_add_head_rcu(&child->node, &dir->children);
	hash_add_rcu(dir->child_index, &child->index_node, child->name_hash);
}

static void kasumi_dh_child_unlink(struct kasumi_dh_child *child)
{
	hash_del(&child->binding_node);
	hash_del_rcu(&child->index_node);
	hlist_del_rcu(&child->node);
}

static void kasumi_dh_unindex_dir(struct kasumi_dh_dir *dir)
{
	struct kasumi_dh_child *child;

	hlist_for_each_entry(child, &dir->children, node)
	    hash_del(&child->binding_node);
}

static bool kasumi_dh_child_visible_at(const struct kasumi_dh_child *child,
				       u64 generation)
{
	u64 last = READ_ONCE(child->last_generation);

	return child->first_generation <= generation && (!last || generation <= last);
}

static struct kasumi_dh_child *kasumi_dh_find_binding(const char *path,
						      u64 generation)
{
	struct kasumi_dh_child *child;
	u32 hash = full_name_hash(NULL, path, strlen(path));

	hash_for_each_possible(kasumi_dh_bindings, child, binding_node, hash)
	{
		if (child->registered_hash == hash &&
		    !strcmp(child->registered_path, path) &&
		    kasumi_dh_child_visible_at(child, generation))
			return child;
	}
	return NULL;
}

static struct kasumi_dh_child *kasumi_dh_find_child_at(
	struct kasumi_dh_dir *dir, const char *name, u16 len, u64 generation)
{
	struct kasumi_dh_child *child;
	u32 hash;

	if (kasumi_dir_name_hash(dir->name_parent, name, len, &hash))
		return NULL;
	hash_for_each_possible_rcu(dir->child_index, child, index_node, hash) {
		if (child->name_hash == hash && kasumi_dir_name_equal(
			dir->name_parent, child->name_dentry, child->name,
			child->name_len, name, len) &&
		    (generation == U64_MAX ||
		     kasumi_dh_child_visible_at(child, generation)))
			return child;
	}
	return NULL;
}

static struct kasumi_dh_child *kasumi_dh_find_child(struct kasumi_dh_dir *dir,
						 const char *name, u16 len)
{
	return kasumi_dh_find_child_at(dir, name, len,
				      kasumi_rules_generation());
}

const struct inode_operations *
kasumi_dirhijack_original_iops(const struct inode *inode)
{
	const struct inode_operations *original;
	struct kasumi_dh_iop *meta;
	int index = srcu_read_lock(&kasumi_dh_srcu);

	meta = kasumi_dh_iop_of(inode);
	original = meta ? READ_ONCE(meta->orig_iop) : READ_ONCE(inode->i_op);
	srcu_read_unlock(&kasumi_dh_srcu, index);
	return original;
}

/* Both the iop owner and directory owner serialize updates through this lock.
 * The lower override changes getattr only. The directory vector keeps its
 * immutable getattr trampoline while the lower vector is replaced.
 */
int kasumi_dirhijack_replace_iops(struct inode *inode,
				const struct inode_operations *expected,
				const struct inode_operations *replacement)
{
	struct kasumi_dh_iop *meta;
	int error = 0;

	if (!inode || !expected || !replacement)
		return -EINVAL;
	mutex_lock(&kasumi_dh_lock);
	meta = kasumi_dh_iop_of(inode);
	if (meta) {
		if (READ_ONCE(meta->orig_iop) != expected)
			error = -EAGAIN;
		else
			smp_store_release(&meta->orig_iop, replacement);
	} else if (cmpxchg(&inode->i_op, expected, replacement) != expected) {
		error = -EAGAIN;
	}
	mutex_unlock(&kasumi_dh_lock);
	return error;
}

void kasumi_dirhijack_synchronize_iops(void)
{
	synchronize_srcu(&kasumi_dh_srcu);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
static int KASUMI_NOCFI kasumi_dh_getattr(struct mnt_idmap *idmap,
	const struct path *path, struct kstat *stat, u32 request_mask,
	unsigned int query_flags)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
static int KASUMI_NOCFI kasumi_dh_getattr(struct user_namespace *userns,
	const struct path *path, struct kstat *stat, u32 request_mask,
	unsigned int query_flags)
#else
static int KASUMI_NOCFI kasumi_dh_getattr(const struct path *path,
	struct kstat *stat, u32 request_mask, unsigned int query_flags)
#endif
{
	struct inode *inode = d_inode(path->dentry);
	struct kasumi_dh_iop *meta;
	const struct inode_operations *original;
	int index = srcu_read_lock(&kasumi_dh_srcu);
	int result;

	meta = kasumi_dh_iop_of(inode);
	original = meta ? READ_ONCE(meta->orig_iop) : READ_ONCE(inode->i_op);
	if (original && original->getattr) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		result = original->getattr(idmap, path, stat, request_mask, query_flags);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
		result = original->getattr(userns, path, stat, request_mask, query_flags);
#else
		result = original->getattr(path, stat, request_mask, query_flags);
#endif
	} else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		generic_fillattr(idmap, request_mask, inode, stat);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
		generic_fillattr(userns, inode, stat);
#else
		generic_fillattr(inode, stat);
#endif
		result = 0;
	}
	srcu_read_unlock(&kasumi_dh_srcu, index);
	return result;
}

/* True if the current task should see this dir's injected children. */
static bool kasumi_dh_current_sees(const struct kasumi_dh_child *child)
{
	if (!kasumi_dirhijack_enabled() || kasumi_vfs_internal_current())
		return false;
	if (READ_ONCE(kasumi_dirhijack_force))
		return true;
	if (child && (child->flags & KASUMI_VNODE_F_VIRTUAL_DIR))
		return kasumi_rule_vpath_visible(child->vpath);
	return kasumi_rule_current_sees(
	    child && (child->flags & KASUMI_VNODE_F_BYPASS)
		? KSM_RULE_BYPASS_POLICY
		: 0);
}

static bool kasumi_dh_current_hides(const struct kasumi_dh_child *child,
				    const struct inode *parent)
{
	return (child->hide || READ_ONCE(child->hide_users)) &&
	       kasumi_dirhijack_enabled() &&
	       kasumi_rule_current_hides(
		   parent, ((child->legacy && child->hide &&
			     (child->flags & KASUMI_VNODE_F_BYPASS)) ||
			    READ_ONCE(child->bypass_hide_users))
			       ? KSM_RULE_BYPASS_POLICY
			       : 0);
}

static bool kasumi_dh_current_targets(const struct kasumi_dh_child *child,
				      const struct inode *parent)
{
	if (kasumi_dh_current_hides(child, parent))
		return true;
	return child->legacy && !child->hide && kasumi_dh_current_sees(child);
}

static bool kasumi_dh_hidden_name(struct inode *parent, const struct qstr *name)
{
	struct kasumi_dh_iop *m = kasumi_dh_iop_of(parent);
	struct kasumi_dh_child *child;
	bool hidden = false;

	if (!m || !m->dir || !name || READ_ONCE(m->dir->retiring))
		return false;
	rcu_read_lock();
	child = kasumi_dh_find_child(m->dir, name->name, (u16)name->len);
	if (child)
		hidden = kasumi_dh_current_hides(child, parent);
	rcu_read_unlock();
	return hidden;
}

static struct dentry *KASUMI_NOCFI kasumi_dh_lookup_inner(
	struct inode *dir, struct dentry *dentry, unsigned int flags);

static int KASUMI_NOCFI kasumi_dh_atomic_open_inner(struct inode *dir,
					    struct dentry *dentry, struct file *file,
					    unsigned int flags, umode_t mode)
{
	struct kasumi_dh_iop *m = kasumi_dh_iop_of(dir);
	const struct inode_operations *orig =
		m ? READ_ONCE(m->orig_iop) : READ_ONCE(dir->i_op);

	struct kasumi_dh_child *child;
	struct dentry *result;
	bool targeted = false;
	bool governed = false;
	u64 generation = kasumi_rules_generation();
	int ret;

	if (m && m->dir) {
		rcu_read_lock();
		child = kasumi_dh_find_child(
		    m->dir, dentry->d_name.name, (u16)dentry->d_name.len);
		if (child)
			targeted = kasumi_dh_current_targets(child, dir);
		governed = kasumi_dh_find_child_at(
		    m->dir, dentry->d_name.name, (u16)dentry->d_name.len,
		    U64_MAX) != NULL;
		rcu_read_unlock();
	}
	if (targeted) {
		result = kasumi_dh_lookup_inner(dir, dentry, LOOKUP_OPEN);
		if (IS_ERR(result))
			return PTR_ERR(result);
		return finish_no_open(file, result);
	}
	if (!orig || !orig->atomic_open ||
	    orig->atomic_open == kasumi_dh_atomic_open)
		return -EOPNOTSUPP;
	if (governed) {
		ret = kasumi_dh_prepare_dentry_ops(m->dir, dentry,
					     generation);
		if (ret && ret != -ENOENT && ret != -ESHUTDOWN)
			return ret;
	}
	ret = orig->atomic_open(dir, dentry, file, flags, mode);
	if (!ret && governed) {
		result = file->f_path.dentry ? file->f_path.dentry : dentry;
		if (kasumi_dh_set_dentry_ops(m->dir, result, false, false,
					     generation, 0)) {
			d_drop(result);
			kasumi_dh_retire_unhashed(result);
		}
	}
	kasumi_dh_retire_unhashed(dentry);
	return ret;
}

static int kasumi_dh_atomic_open(struct inode *dir, struct dentry *dentry,
				 struct file *file, unsigned int flags, umode_t mode)
{
	int idx = srcu_read_lock(&kasumi_dh_srcu);
	int ret = kasumi_dh_atomic_open_inner(dir, dentry, file, flags, mode);

	srcu_read_unlock(&kasumi_dh_srcu, idx);
	return ret;
}

/* READDIRPLUS can publish real dentries without calling the parent lookup. */
static int kasumi_dh_fuse_revalidate_pre(struct kprobe *probe,
					 struct pt_regs *regs)
{
#ifdef CONFIG_ARM64
	struct dentry *dentry;
	struct inode *parent;
	const struct qstr *name;
	bool hidden, redirected;
	int idx;

	(void)probe;
	if (!kasumi_dirhijack_enabled())
		return 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
	parent = (void *)regs->regs[0];
	name = (void *)regs->regs[1];
	dentry = (void *)regs->regs[2];
#else
	dentry = (void *)regs->regs[0];
#endif
	if (!dentry)
		return 0;
	idx = srcu_read_lock(&kasumi_dh_srcu);
	spin_lock(&dentry->d_lock);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 13, 0)
	parent = d_inode(dentry->d_parent);
	name = &dentry->d_name;
#endif
	hidden = kasumi_dh_hidden_name(parent, name);
	redirected = kasumi_dirhijack_child_visible(parent, name->name, name->len) > 0;
	spin_unlock(&dentry->d_lock);
	srcu_read_unlock(&kasumi_dh_srcu, idx);
	if (!hidden && !redirected)
		return 0;
	regs->regs[0] = hidden ? (unsigned long)-ENOENT : 0;
	instruction_pointer_set(regs, regs->regs[30]);
	return 1;
#else
	return 0;
#endif
}

/* ---- hijacked lookup (SRCU-wrapped) ------------------------------------ */

static struct dentry *KASUMI_NOCFI kasumi_dh_lookup_inner(struct inode *dir,
							  struct dentry *dentry,
							  unsigned int flags)
{
	struct kasumi_dh_iop *m = kasumi_dh_iop_of(dir);
	struct kasumi_dh_dir *dn = m ? READ_ONCE(m->dir) : NULL;
	struct kasumi_dh_child *c;
	struct path source = {};
	struct kasumi_inode_identity *identity = NULL;
	u64 generation = kasumi_rules_generation();
	u64 revision = 0;
	umode_t mode = S_IFREG | 0644;
	u8 cflags = 0;
	char *vpath = NULL;
	bool found = false;
	bool is_hide = false;
	bool allocation_failed = false;

	if (!m || !dn)
		goto orig;

	rcu_read_lock();
	c = kasumi_dh_find_child_at(
	    dn, dentry->d_name.name, (u16)dentry->d_name.len,
	    generation);
	if (c && kasumi_dh_current_targets(c, dir)) {
		revision = c->revision;
		identity = c->identity;
		kasumi_identity_get(identity);
		if (c->source.dentry) {
			source = c->source;
			path_get(&source);
			if (d_inode(source.dentry))
				mode = d_inode(source.dentry)->i_mode;
		}
		if (c->vpath) {
			vpath = kstrdup(c->vpath, GFP_ATOMIC);
			allocation_failed = !vpath;
		}
		cflags = c->flags;
		is_hide = kasumi_dh_current_hides(c, dir);
		found = true;
	}
	rcu_read_unlock();

	if (found) {
		struct inode *vi;
		struct dentry *res;
		int dop_ret;

		if (allocation_failed) {
			kasumi_identity_put(identity);
			if (source.dentry)
				kasumi_path_put(&source);
			return ERR_PTR(-ENOMEM);
		}
		if (is_hide) {
			kasumi_identity_put(identity);
			/* Hidden for this observer: confirm a negative dentry
			 * so the name resolves to -ENOENT.  Never call the real
			 * lookup (it would surface the hidden inode) and never
			 * mint a vnode (a hide has no source).  Our d_op makes
			 * a non-seeing observer re-resolve to the real entry.
			 */
			if (source.dentry)
				kasumi_path_put(&source);
			kfree(vpath);
			dop_ret = kasumi_dh_set_dentry_ops(dn, dentry, true,
							   false, generation, revision);
			if (dop_ret) {
				/* DEL/CLEAR won the race: resolve through the
				 * original filesystem instead of publishing an
				 * ungoverned negative. */
				if (dop_ret == -ENOENT || dop_ret == -ESHUTDOWN)
					goto orig;
				return ERR_PTR(dop_ret);
			}
			d_add(dentry, NULL);
			return NULL;
		}
		if ((cflags & KASUMI_VNODE_F_VIRTUAL_DIR) && vpath)
			vi = kasumi_vnode_new_virtual(dir->i_sb, vpath, dir);
		else
			vi = kasumi_vnode_new(dir->i_sb,
					      source.dentry ? &source : NULL,
					      mode, cflags);
		if (!IS_ERR(vi) && vpath && !(cflags & KASUMI_VNODE_F_VIRTUAL_DIR)) {
			dop_ret = kasumi_vnode_set_visible_path(vi, vpath);
			if (dop_ret) {
				iput(vi);
				vi = ERR_PTR(dop_ret);
			}
		}
		if (source.dentry)
			kasumi_path_put(&source);
		kfree(vpath);
		kasumi_identity_put(identity);
		if (!IS_ERR(vi)) {
			dop_ret = kasumi_dh_set_dentry_ops(dn, dentry, false,
							   true, generation, revision);
			if (dop_ret) {
				iput(vi);
				if (dop_ret == -ENOENT || dop_ret == -ESHUTDOWN)
					goto orig;
				return ERR_PTR(dop_ret);
			}
			res = d_splice_alias(vi, dentry);
			if (res && !IS_ERR(res)) {
				dop_ret = kasumi_dh_set_dentry_ops(dn, res,
								   false, true, generation, revision);
				if (dop_ret) {
					/* The alias became visible after
					 * DEL/CLEAR began. Unhash it so the
					 * next lookup reaches orig_iop. */
					d_drop(res);
					dput(res);
					return ERR_PTR(dop_ret == -ENOENT ||
							       dop_ret ==
								   -ESHUTDOWN
							   ? -EAGAIN
							   : dop_ret);
				}
			}
			return res;
		}
		return ERR_CAST(vi);
	}

orig:
	/* Not served to this observer.  If a rule nonetheless registers this
	 * name (for a different observer), govern the resulting dentry with our
	 * d_revalidate: otherwise a negative/real dentry cached here by a
	 * non-seeing observer (e.g. root probing first) would be inherited by a
	 * seeing observer without re-resolution, hiding the virtual file from
	 * the very view that must see it — and, in the reverse order, leaking
	 * it to a view that must not.  Attaching our d_op makes both orderings
	 * re-resolve through the shadow lookup per current observer. */
	{
		const struct inode_operations *original =
			m ? READ_ONCE(m->orig_iop) : NULL;
		struct dentry *res = NULL;
		bool is_child = false;
		bool simple = original &&
			(original->lookup == simple_lookup ||
			 (unsigned long)original->lookup == kasumi_dh_simple_lookup_raw ||
			 (unsigned long)original->lookup == kasumi_dh_simple_lookup_callable);

		if (m && dn) {
			rcu_read_lock();
			is_child =
			    kasumi_dh_find_child_at(
				dn, dentry->d_name.name,
				(u16)dentry->d_name.len, U64_MAX) != NULL;
			rcu_read_unlock();
		}
		/* Native lookup may hash a negative result before returning. */
		if (is_child) {
			int error;

			/* Some fixed KMIs inline d_set_d_op into simple_lookup. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
			if (simple && !dentry->d_op)
				WRITE_ONCE(dentry->d_flags, READ_ONCE(dentry->d_flags) |
							 DCACHE_DONTCACHE);
#else
			if (simple && !dentry->d_sb->s_d_op && !dentry->d_op) {
				WRITE_ONCE(dentry->d_op, &simple_dentry_operations);
				WRITE_ONCE(dentry->d_flags, READ_ONCE(dentry->d_flags) |
							 DCACHE_OP_DELETE);
			}
#endif
			error = kasumi_dh_prepare_dentry_ops(dn, dentry, generation);

			if (error && error != -ENOENT && error != -ESHUTDOWN)
				return ERR_PTR(error);
		}
		if (is_child && simple) {
			if (dentry->d_name.len > NAME_MAX)
				return ERR_PTR(-ENAMETOOLONG);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
			if (IS_ENABLED(CONFIG_UNICODE) && IS_CASEFOLDED(dir)) {
				kasumi_dh_retire_unhashed(dentry);
				return NULL;
			}
#endif
			d_add(dentry, NULL);
		} else if (original && original->lookup)
			res = original->lookup(dir, dentry, flags);
		else
			d_add(dentry, NULL);
		if (is_child && !IS_ERR(res) &&
		    kasumi_dh_set_dentry_ops(dn, res ? res : dentry, false,
					     false, generation, 0)) {
			/* Do not leave an ungoverned result cached: the current
			 * non-seeing lookup may use it, but the next observer
			 * must resolve through our lookup gate again. */
			d_drop(res ? res : dentry);
			kasumi_dh_retire_unhashed(res ? res : dentry);
		}
		kasumi_dh_retire_unhashed(dentry);
		return res;
	}
}

static struct dentry *kasumi_dh_lookup(struct inode *dir, struct dentry *dentry,
				       unsigned int flags)
{
	struct dentry *res;
	int idx = srcu_read_lock(&kasumi_dh_srcu);

	res = kasumi_dh_lookup_inner(dir, dentry, flags);
	srcu_read_unlock(&kasumi_dh_srcu, idx);
	return res;
}

static int kasumi_dh_iterate(struct file *file, struct dir_context *ctx,
			     kasumi_dir_iterate_fn iterate, void *data)
{
	return kasumi_dir_view_iterate(file, file, iterate, ctx,
				       kasumi_dirhijack_collect, NULL, NULL);
}

/* ---- per-observer d_revalidate (SRCU-wrapped) -------------------------- */

#define KASUMI_DH_DOP_FLAGS	(DCACHE_OP_HASH | DCACHE_OP_COMPARE | \
				 DCACHE_OP_REVALIDATE | \
				 DCACHE_OP_WEAK_REVALIDATE | \
				 DCACHE_OP_DELETE | DCACHE_OP_PRUNE | \
				 DCACHE_OP_REAL)

static struct kasumi_dh_dop_meta *
kasumi_dh_dop_lookup_rcu(const struct dentry *dentry)
{
	struct kasumi_dh_dop_meta *m;

	hash_for_each_possible_rcu(kasumi_dh_dops, m, node,
				   (unsigned long)dentry) {
		if (m->dentry == dentry)
			return m;
	}
	return NULL;
}

static struct kasumi_dh_dop_meta *
kasumi_dh_dop_lookup_locked(const struct dentry *dentry)
{
	struct kasumi_dh_dop_meta *m;

	hash_for_each_possible(kasumi_dh_dops, m, node,
			       (unsigned long)dentry) {
		if (m->dentry == dentry)
			return m;
	}
	return NULL;
}

/*
 * A stale per-observer dentry is about to be invalidated by the VFS.  The
 * meta's dget must not keep that now-unhashed object (and a possible vnode)
 * alive until DEL/CLEAR.  d_revalidate can run in LOOKUP_RCU, so it may only
 * mark the preallocated meta and queue sleepable retirement here.
 */
static void kasumi_dh_queue_dop_retire(struct kasumi_dh_dop_meta *m)
{
	if (!test_and_set_bit(KASUMI_DH_DOP_AUTO_RETIRE, &m->state))
		schedule_work(&kasumi_dh_reap_dops_work);
}

static void kasumi_dh_retire_unhashed(struct dentry *dentry)
{
	struct kasumi_dh_dop_meta *meta;

	rcu_read_lock();
	meta = kasumi_dh_dop_lookup_rcu(dentry);
	if (meta && d_unhashed(dentry))
		kasumi_dh_queue_dop_retire(meta);
	rcu_read_unlock();
}

static int KASUMI_NOCFI kasumi_dh_revalidate_inner(
    struct kasumi_dh_dop_meta *dm, struct inode *dir, const struct qstr *name,
    struct dentry *dentry, unsigned int flags, bool *chain_orig)
{
	struct kasumi_dh_dir *dn = READ_ONCE(dm->dir);
	struct inode *inode;
	u64 generation = kasumi_rules_generation();
	bool is_virtual;
	bool governed = false;
	bool child_hide = false;
	bool synthetic_negative;
	bool sees;

	/* SRCU pins both the saved owner and any owner selected after a rename.
	 * A live directory retains its i_op until retiring is set. Rebinding an
	 * alias can update dm->dir before native parent publication, so mismatched
	 * parents must resolve their currently installed owner instead.
	 */
	if (!dn || dir != dn->dir_inode || READ_ONCE(dn->retiring)) {
		struct kasumi_dh_iop *parent_meta = dir ? kasumi_dh_iop_of(dir) : NULL;

		dn = parent_meta ? READ_ONCE(parent_meta->dir) : NULL;
		if (dn && READ_ONCE(dn->retiring))
			dn = NULL;
	}
	*chain_orig = false;
	inode = READ_ONCE(dentry->d_inode);
	is_virtual = inode && kasumi_vnode_is_ours(inode);
	synthetic_negative = !inode && READ_ONCE(dm->synthetic_negative);
	if (!dn) {
		if (is_virtual || synthetic_negative)
			return 0;
		*chain_orig = true;
		return 1;
	}
	sees = false;

	/* A rename can leave the held dentry carrying our shadow outside the
	 * directory where it was installed.  It is no longer governed there. */
	if (dir && dir == dn->dir_inode) {
		struct kasumi_dh_child *c;

		rcu_read_lock();
		c = kasumi_dh_find_child_at(dn, name->name, (u16)name->len,
					     generation);
		if (c) {
			bool hides;

			if ((is_virtual || synthetic_negative) &&
			    READ_ONCE(dm->revision) != c->revision) {
				rcu_read_unlock();
				return 0;
			}
			governed = true;
			hides = kasumi_dh_current_hides(c, dir);
			child_hide = c->hide || hides;
			sees = hides || (c->legacy && !c->hide && kasumi_dh_current_sees(c));
		}
		rcu_read_unlock();
	}

	(void)flags;

	/*
	 * Decide, per current observer, whether the cached dentry still matches
	 * what a fresh lookup would yield; return 0 to force re-resolution.
	 * Only 0/1 is returned and nothing sleeps, so this is rcu-walk safe.
	 *
	 * Not governed: no rule touches this name.  Keep a real/negative
	 * dentry; invalidate a stale virtual left by a since-deleted rule so
	 * the name drops back to its real entry.
	 *
	 * Inject rule: a seeing observer must resolve to the virtual inode, so
	 * a cached real/negative is stale; a non-seeing observer must resolve
	 * to the real entry, so a cached virtual is stale.
	 *
	 * Hide rule: a seeing observer must resolve to a negative (hidden), so
	 * a cached real or virtual dentry is stale; a non-seeing observer (e.g.
	 * root) must resolve to the real entry, so a negative cached by a
	 * seeing observer -- and any stray virtual -- is stale.  This is the
	 * §5.2 cross-observer mirror: a correctly hidden negative must not leak
	 * to an observer the rule does not target, which still has to see the
	 * file.
	 */
	if (!governed) {
		if (is_virtual || synthetic_negative)
			return 0;
		*chain_orig = true;
		return 1;
	}
	if (!child_hide) { /* inject */
		if (sees)
			return is_virtual ? 1 : 0;
		if (is_virtual || synthetic_negative)
			return 0;
		*chain_orig = true;
		return 1;
	}
	/* hide */
	if (sees) {
		if (inode)
			return 0;
		if (!synthetic_negative)
			*chain_orig = true;
		return 1; /* valid negative */
	}
	if (inode && !is_virtual) {
		*chain_orig = true;
		return 1; /* positive-real */
	}
	if (!inode && !synthetic_negative) {
		*chain_orig = true;
		return 1; /* negative-real */
	}
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
static int KASUMI_NOCFI
kasumi_dh_revalidate(struct inode *dir, const struct qstr *name,
			 struct dentry *dentry, unsigned int flags)
{
	struct kasumi_dh_dop_meta *dm;
	bool chain_orig;
	int ret;
	/* srcu_read_lock() is non-sleeping and the inner never sleeps, so this is
	 * safe in rcu-walk; it also pins the meta against a concurrent clear(). */
	int idx = srcu_read_lock(&kasumi_dh_srcu);

	rcu_read_lock();
	dm = kasumi_dh_dop_lookup_rcu(dentry);
	rcu_read_unlock();
	if (!dm) {
		ret = 0;
		goto out;
	}
	ret = kasumi_dh_revalidate_inner(dm, dir, name, dentry, flags,
					 &chain_orig);
	if (ret > 0 && chain_orig &&
	    (READ_ONCE(dm->orig_op_flags) & DCACHE_OP_REVALIDATE) && dm->orig_dop &&
	    dm->orig_dop->d_revalidate)
		ret = dm->orig_dop->d_revalidate(dir, name, dentry, flags);
	if (ret == 0)
		kasumi_dh_queue_dop_retire(dm);
out:
	srcu_read_unlock(&kasumi_dh_srcu, idx);
	return ret;
}
#else
static int KASUMI_NOCFI
kasumi_dh_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct kasumi_dh_dop_meta *dm;
	struct inode *dir = d_inode(READ_ONCE(dentry->d_parent));
	const struct qstr *name = &dentry->d_name;
	bool chain_orig;
	int ret;
	int idx = srcu_read_lock(&kasumi_dh_srcu);

	rcu_read_lock();
	dm = kasumi_dh_dop_lookup_rcu(dentry);
	rcu_read_unlock();
	if (!dm) {
		ret = 0;
		goto out;
	}
	ret = kasumi_dh_revalidate_inner(dm, dir, name, dentry, flags,
					 &chain_orig);
	if (ret > 0 && chain_orig &&
	    (READ_ONCE(dm->orig_op_flags) & DCACHE_OP_REVALIDATE) && dm->orig_dop &&
	    dm->orig_dop->d_revalidate)
		/* Preserve the original callback's LOOKUP_RCU result verbatim,
		 * including -ECHILD when it needs a ref-walk retry. */
		ret = dm->orig_dop->d_revalidate(dentry, flags);
	if (ret == 0)
		kasumi_dh_queue_dop_retire(dm);
out:
	srcu_read_unlock(&kasumi_dh_srcu, idx);
	return ret;
}
#endif

static bool kasumi_dh_owns_dops(const struct kasumi_dh_dop_meta *meta,
				const struct dentry_operations *operations)
{
	return operations == &meta->shadow_dop ||
	       operations == &meta->native_shadow_dop;
}

static unsigned int kasumi_dh_native_dop_flags(
	const struct dentry_operations *operations)
{
	unsigned int flags = 0;

	if (!operations)
		return 0;
	if (operations->d_hash)
		flags |= DCACHE_OP_HASH;
	if (operations->d_compare)
		flags |= DCACHE_OP_COMPARE;
	if (operations->d_revalidate)
		flags |= DCACHE_OP_REVALIDATE;
	if (operations->d_weak_revalidate)
		flags |= DCACHE_OP_WEAK_REVALIDATE;
	if (operations->d_delete)
		flags |= DCACHE_OP_DELETE;
	if (operations->d_prune)
		flags |= DCACHE_OP_PRUNE;
	if (operations->d_real)
		flags |= DCACHE_OP_REAL;
	return flags;
}

/* Native lookup reserved the metadata before entering the filesystem.  Finish
 * its operation vector after native initialization and before cache publication. */
static bool kasumi_dh_publish_native_dops(struct kasumi_dh_dop_meta *meta,
	const struct dentry_operations *operations)
{
	struct dentry *dentry = meta->dentry;
	const struct dentry_operations *current_ops = READ_ONCE(dentry->d_op);
	unsigned int flags = READ_ONCE(dentry->d_flags) & KASUMI_DH_DOP_FLAGS;

	if (kasumi_dh_owns_dops(meta, current_ops)) {
		if (!operations || operations == READ_ONCE(meta->orig_dop))
			return true;
		/* d_set_d_op itself forbids replacing initialized native ops. */
		if (WARN_ON_ONCE(meta->native_dop_set || meta->orig_dop))
			return true;
		flags = 0;
	}
	if (WARN_ON_ONCE(meta->native_dop_set || !d_unhashed(dentry)))
		return false;
	if (operations)
		flags |= kasumi_dh_native_dop_flags(operations);
	else
		operations = current_ops;
	if (operations)
		meta->native_shadow_dop = *operations;
	meta->native_shadow_dop.d_revalidate = kasumi_dh_revalidate;
	WRITE_ONCE(meta->orig_op_flags, flags);
	WRITE_ONCE(meta->orig_dop, operations);
	WRITE_ONCE(meta->native_dop_set, true);
	smp_store_release(&dentry->d_op, &meta->native_shadow_dop);
	WRITE_ONCE(dentry->d_flags,
		   (READ_ONCE(dentry->d_flags) & ~KASUMI_DH_DOP_FLAGS) |
			   flags | DCACHE_OP_REVALIDATE);
	return true;
}

static int kasumi_dh_add_pre(struct kprobe *probe, struct pt_regs *regs)
{
#ifdef CONFIG_ARM64
	struct dentry *dentry = (void *)regs->regs[0];
	struct kasumi_dh_dop_meta *meta;
	int index;

	(void)probe;
	index = srcu_read_lock(&kasumi_dh_srcu);
	rcu_read_lock();
	meta = kasumi_dh_dop_lookup_rcu(dentry);
	rcu_read_unlock();
	if (meta)
		kasumi_dh_publish_native_dops(meta, NULL);
	srcu_read_unlock(&kasumi_dh_srcu, index);
#else
	(void)probe;
	(void)regs;
#endif
	return 0;
}

static int kasumi_dh_set_dentry_ops_named(struct kasumi_dh_dir *dir,
	struct dentry *dentry, const struct qstr *lookup_name,
	bool synthetic_negative, bool synthetic_inode, u64 generation,
	u64 revision, bool rebind, bool deferred, bool *created)
{
	struct kasumi_dh_dop_meta *m, *existing;
	const struct dentry_operations *orig;
	const unsigned int backing_inode_flags = DCACHE_OP_REVALIDATE |
						 DCACHE_OP_WEAK_REVALIDATE |
						 DCACHE_OP_REAL;
	const char *name;
	u32 hash;
	u16 len;
	bool governed;
	int ret = 0;

	if (!dir || !dir->dir_inode || !dentry || !lookup_name ||
	    lookup_name->len > NAME_MAX)
		return -EINVAL;
	name = lookup_name->name;
	len = (u16)lookup_name->len;
	if (created)
		*created = false;
	hash = full_name_hash(dir->dir_inode, name, len);

	m = kzalloc(sizeof(*m) + NAME_MAX + 1, GFP_KERNEL);
	if (!m)
		return -ENOMEM;
	m->dentry = dget(dentry);
	m->dir = dir;
	m->name_hash = hash;
	m->name_len = len;
	m->synthetic_negative = synthetic_negative;
	m->generation = generation;
	m->revision = revision;
	INIT_LIST_HEAD(&m->retire_node);
	memcpy(m->name, name, len);
	m->name[len] = '\0';

	mutex_lock(&kasumi_dh_lock);
	if (READ_ONCE(dir->retiring)) {
		ret = -ESHUTDOWN;
		goto out_unlock;
	}
	/* DEL removes the child while holding this mutex.  Recheck here so a
	 * lookup that copied the rule just before DEL cannot publish a late d_op. */
	rcu_read_lock();
	governed = kasumi_dh_find_child_at(dir, m->name, len, U64_MAX) != NULL;
	rcu_read_unlock();
	if (!governed) {
		ret = -ENOENT;
		goto out_unlock;
	}

	existing = kasumi_dh_dop_lookup_locked(dentry);
	if (existing) {
		spin_lock(&dentry->d_lock);
		if ((!kasumi_dh_owns_dops(existing, dentry->d_op) &&
		     (existing->native_dop_set || !d_unhashed(dentry))) ||
		    (!rebind && (existing->dir != dir ||
		     existing->name_hash != hash || existing->name_len != len ||
		     memcmp(existing->name, name, len))))
			ret = -EBUSY;
		else {
			existing->name_hash = hash;
			existing->name_len = len;
			memcpy(existing->name, name, len);
			existing->name[len] = '\0';
			if (existing->dir != dir)
				list_move_tail(&existing->dir_node, &dir->dops);
			WRITE_ONCE(existing->dir, dir);
			if (!deferred && !kasumi_dh_owns_dops(existing, dentry->d_op))
				kasumi_dh_publish_native_dops(existing, NULL);
			WRITE_ONCE(existing->synthetic_negative,
				   synthetic_negative);
			WRITE_ONCE(existing->generation, generation);
			WRITE_ONCE(existing->revision, revision);
			clear_bit(KASUMI_DH_DOP_AUTO_RETIRE, &existing->state);
			if (!list_empty(&existing->retire_node))
				list_del_init(&existing->retire_node);
			if (synthetic_inode) {
				existing->orig_op_flags &= ~backing_inode_flags;
				WRITE_ONCE(dentry->d_flags,
					   (READ_ONCE(dentry->d_flags) &
					    ~backing_inode_flags) |
						   DCACHE_OP_REVALIDATE);
			}
		}
		spin_unlock(&dentry->d_lock);
		goto out_unlock;
	}

	spin_lock(&dentry->d_lock);
	orig = READ_ONCE(dentry->d_op);
	m->orig_dop = orig;
	if (orig)
		m->shadow_dop = *orig;
	m->shadow_dop.d_revalidate = kasumi_dh_revalidate;
	m->orig_op_flags = READ_ONCE(dentry->d_flags) & KASUMI_DH_DOP_FLAGS;
	/* Backing-inode callbacks cannot operate on synthetic inodes. */
	if (synthetic_inode)
		m->orig_op_flags &= ~backing_inode_flags;
	list_add_tail(&m->dir_node, &dir->dops);
	hash_add_rcu(kasumi_dh_dops, &m->node, (unsigned long)dentry);
	if (!deferred) {
		/* Publish the initialized/hash-visible meta before pathwalk can observe
		 * DCACHE_OP_REVALIDATE and enter the shadow callback. */
		smp_wmb();
		WRITE_ONCE(dentry->d_op, &m->shadow_dop);
		WRITE_ONCE(dentry->d_flags,
			   (READ_ONCE(dentry->d_flags) & ~KASUMI_DH_DOP_FLAGS) |
				   m->orig_op_flags | DCACHE_OP_REVALIDATE);
	}
	spin_unlock(&dentry->d_lock);
	mutex_unlock(&kasumi_dh_lock);
	if (created)
		*created = true;
	return 0;

out_unlock:
	mutex_unlock(&kasumi_dh_lock);
	dput(m->dentry);
	kfree(m);
	return ret;
}

static int kasumi_dh_set_dentry_ops(struct kasumi_dh_dir *dir,
	struct dentry *dentry, bool synthetic_negative,
	bool synthetic_inode, u64 generation, u64 revision)
{
	return kasumi_dh_set_dentry_ops_named(dir, dentry, &dentry->d_name,
		synthetic_negative, synthetic_inode, generation, revision, false, false, NULL);
}

static int kasumi_dh_prepare_dentry_ops(struct kasumi_dh_dir *dir,
	struct dentry *dentry, u64 generation)
{
	return kasumi_dh_set_dentry_ops_named(dir, dentry, &dentry->d_name,
		false, false, generation, 0, false, true, NULL);
}

/* The directory inode lock selects its unique alias.  Retain that alias while
 * preparing its future location, before native rename_lock publication. */
static int kasumi_dh_prepare_alias(struct kasumi_dh_dop_meta *target,
	struct dentry *alias, struct dentry *destination, bool *created)
{
	struct kasumi_dh_dop_meta *existing;

	*created = false;
	mutex_lock(&kasumi_dh_lock);
	existing = kasumi_dh_dop_lookup_locked(alias);
	if (existing && kasumi_dh_owns_dops(existing, READ_ONCE(alias->d_op))) {
		clear_bit(KASUMI_DH_DOP_AUTO_RETIRE, &existing->state);
		if (!list_empty(&existing->retire_node))
			list_del_init(&existing->retire_node);
		mutex_unlock(&kasumi_dh_lock);
		return 0;
	}
	mutex_unlock(&kasumi_dh_lock);
	return kasumi_dh_set_dentry_ops_named(READ_ONCE(target->dir), alias,
		&destination->d_name, false, kasumi_vnode_is_ours(d_inode(alias)),
		READ_ONCE(target->generation), READ_ONCE(target->revision), true, false, created);
}

/* Equivalent to the fixed-KMI __d_unalias locking sequence. */
static int KASUMI_NOCFI kasumi_dh_unalias(struct dentry *destination,
					 struct dentry *alias)
{
	struct mutex *rename_mutex = NULL;
	struct rw_semaphore *parent_lock = NULL;
	int result = -ESTALE;

	if (alias->d_parent != destination->d_parent) {
		if (!mutex_trylock(&destination->d_sb->s_vfs_rename_mutex))
			return result;
		rename_mutex = &destination->d_sb->s_vfs_rename_mutex;
		if (!inode_trylock_shared(alias->d_parent->d_inode))
			goto out;
		parent_lock = &alias->d_parent->d_inode->i_rwsem;
	}
	kasumi_dh_native_move(alias, destination, false);
	result = 0;
out:
	if (parent_lock)
		up_read(parent_lock);
	if (rename_mutex)
		mutex_unlock(rename_mutex);
	return result;
}

static void kasumi_dh_update_moved_dops(struct dentry *dentry,
				       unsigned int previous_flags)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0) && IS_ENABLED(CONFIG_FS_ENCRYPTION)
	struct kasumi_dh_dop_meta *meta;

	if (!(previous_flags & DCACHE_NOKEY_NAME) ||
	    !kasumi_dh_fscrypt_revalidate)
		return;
	mutex_lock(&kasumi_dh_lock);
	meta = kasumi_dh_dop_lookup_locked(dentry);
	if (meta && meta->orig_dop &&
	    (unsigned long)meta->orig_dop->d_revalidate ==
		    kasumi_dh_fscrypt_revalidate &&
	    !(READ_ONCE(dentry->d_flags) & DCACHE_NOKEY_NAME))
		WRITE_ONCE(meta->orig_op_flags,
			   READ_ONCE(meta->orig_op_flags) & ~DCACHE_OP_REVALIDATE);
	mutex_unlock(&kasumi_dh_lock);
#else
	(void)dentry;
	(void)previous_flags;
#endif
}

/* __d_add can be fully inlined in GKI. This path only publishes a directory
 * with i_lock held, after its d_op has been prepared by the alias wrapper. */
static void KASUMI_NOCFI kasumi_dh_add_directory(
    struct dentry *dentry, struct inode *inode
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
    ,
    const struct dentry_operations *operations
#endif
)
{
	struct inode *parent = NULL;
	wait_queue_head_t *wait = NULL;
	unsigned int sequence = 0, flags = DCACHE_DIRECTORY_TYPE;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	WARN_ON_ONCE(operations);
#endif
	spin_lock(&dentry->d_lock);
	if (d_in_lookup(dentry)) {
		parent = d_inode(dentry->d_parent);
		preempt_disable();
		for (;;) {
			sequence = READ_ONCE(parent->i_dir_seq);
			if (!(sequence & 1) &&
			    cmpxchg(&parent->i_dir_seq, sequence,
				    sequence + 1) == sequence)
				break;
			cpu_relax();
		}
		wait = kasumi_dh_native_lookup_unhash(dentry);
	}
	if (!(inode->i_opflags & IOP_LOOKUP)) {
		if (!inode->i_op->lookup)
			flags = DCACHE_AUTODIR_TYPE;
		else
			inode->i_opflags |= IOP_LOOKUP;
	}
	if (IS_AUTOMOUNT(inode))
		flags |= DCACHE_NEED_AUTOMOUNT;
	hlist_add_head(&dentry->d_u.d_alias, &inode->i_dentry);
	raw_write_seqcount_begin(&dentry->d_seq);
	dentry->d_inode = inode;
	flags |= READ_ONCE(dentry->d_flags) & ~DCACHE_ENTRY_TYPE;
	smp_store_release(&dentry->d_flags, flags);
	raw_write_seqcount_end(&dentry->d_seq);
	fsnotify_update_flags(dentry);
	kasumi_dh_native_rehash(dentry);
	if (parent) {
		smp_store_release(&parent->i_dir_seq, sequence + 2);
		preempt_enable();
		wake_up_all(wait);
	}
	spin_unlock(&dentry->d_lock);
	spin_unlock(&inode->i_lock);
}

static struct dentry *KASUMI_NOCFI kasumi_dh_splice_alias(
	struct inode *inode, struct dentry *dentry,
	const struct dentry_operations *operations,
	struct kasumi_dh_dop_meta *target, int srcu_index)
{
	struct dentry *alias = NULL;
	unsigned int previous_flags;
	bool created = false;
	int error;

	/* The pre-handler passes only valid directory inodes and pins target
	 * through SRCU before transferring control into this sleepable body. */
	BUG_ON(!d_unhashed(dentry));
	kasumi_dh_native_instantiate(dentry, inode);
	spin_lock(&inode->i_lock);
	if (!hlist_empty(&inode->i_dentry)) {
		alias = hlist_entry(inode->i_dentry.first, struct dentry, d_u.d_alias);
		dget(alias);
	}
	if (!alias) {
		if (!kasumi_dh_publish_native_dops(target, operations)) {
			spin_unlock(&inode->i_lock);
			kasumi_dh_queue_dop_retire(target);
			iput(inode);
			srcu_read_unlock(&kasumi_dh_srcu, srcu_index);
			return ERR_PTR(-ESTALE);
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
		kasumi_dh_native_add(dentry, inode, NULL);
#else
		(void)operations;
		kasumi_dh_native_add(dentry, inode);
#endif
		srcu_read_unlock(&kasumi_dh_srcu, srcu_index);
		return NULL;
	}
	spin_unlock(&inode->i_lock);

	error = kasumi_dh_prepare_alias(target, alias, dentry, &created);
	if (error)
		goto fail;
	write_seqlock(kasumi_dh_rename_lock);
	previous_flags = READ_ONCE(alias->d_flags);
	if (kasumi_dh_native_ancestor(alias, dentry)) {
		write_sequnlock(kasumi_dh_rename_lock);
		error = -ELOOP;
		pr_warn_ratelimited("VFS: Lookup of '%s' in %s %s would have caused loop\n",
			dentry->d_name.name, inode->i_sb->s_type->name,
			inode->i_sb->s_id);
	} else if (!IS_ROOT(alias)) {
		struct dentry *old_parent = dget(alias->d_parent);

		error = kasumi_dh_unalias(dentry, alias);
		write_sequnlock(kasumi_dh_rename_lock);
		dput(old_parent);
	} else {
		kasumi_dh_native_move(alias, dentry, false);
		write_sequnlock(kasumi_dh_rename_lock);
		error = 0;
	}
	if (error)
		goto fail;
	kasumi_dh_update_moved_dops(alias, previous_flags);
	/* Revalidation uses the actual location throughout the move.  Change
	 * ownership only after success, preserving an old binding on failure. */
	error = kasumi_dh_set_dentry_ops_named(READ_ONCE(target->dir), alias,
		&alias->d_name, false, kasumi_vnode_is_ours(inode),
		READ_ONCE(target->generation), READ_ONCE(target->revision), true, false, NULL);
	if (error) {
		d_drop(alias);
		goto fail;
	}
	kasumi_dh_queue_dop_retire(target);
	iput(inode);
	srcu_read_unlock(&kasumi_dh_srcu, srcu_index);
	return alias;
fail:
	if (created || d_unhashed(alias)) {
		struct kasumi_dh_dop_meta *installed;

		mutex_lock(&kasumi_dh_lock);
		installed = kasumi_dh_dop_lookup_locked(alias);
		if (installed)
			kasumi_dh_queue_dop_retire(installed);
		mutex_unlock(&kasumi_dh_lock);
	}
	kasumi_dh_queue_dop_retire(target);
	dput(alias);
	iput(inode);
	srcu_read_unlock(&kasumi_dh_srcu, srcu_index);
	return ERR_PTR(error);
}

static int kasumi_dh_splice_pre(struct kprobe *probe, struct pt_regs *regs)
{
#ifdef CONFIG_ARM64
	struct inode *inode = (void *)regs->regs[0];
	struct dentry *dentry = (void *)regs->regs[1];
	struct kasumi_dh_dop_meta *meta;
	int index;

	(void)probe;
	if (IS_ERR(inode))
		return 0;
	index = srcu_read_lock(&kasumi_dh_srcu);
	rcu_read_lock();
	meta = kasumi_dh_dop_lookup_rcu(dentry);
	rcu_read_unlock();
	if (!meta) {
		srcu_read_unlock(&kasumi_dh_srcu, index);
		return 0;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
	regs->regs[2] = 0;
#endif
	if (!inode || !S_ISDIR(READ_ONCE(inode->i_mode))) {
		if (kasumi_dh_publish_native_dops(meta, (void *)regs->regs[2]))
			regs->regs[2] = 0;
		srcu_read_unlock(&kasumi_dh_srcu, index);
		return 0;
	}
	regs->regs[3] = (unsigned long)meta;
	regs->regs[4] = index;
	instruction_pointer_set(regs, (unsigned long)kasumi_dh_splice_alias);
	return 1;
#else
	(void)probe;
	(void)regs;
	return 0;
#endif
}


/* Keep revalidation installed until readers that found the hashed dentry have
 * drained.  A concurrent valid lookup can cancel retirement under this lock. */
static void kasumi_dh_retire_dop_locked(struct kasumi_dh_dop_meta *m,
					struct list_head *retired)
{
	set_bit(KASUMI_DH_DOP_AUTO_RETIRE, &m->state);
	d_drop(m->dentry);
	if (list_empty(&m->retire_node))
		list_add_tail(&m->retire_node, retired);
}

/* The caller has drained pre-unhash readers.  The metadata stays discoverable
 * until its wrapper is withdrawn, then a second drain covers late callbacks. */
static void kasumi_dh_free_retired_dops(struct list_head *retired)
{
	struct kasumi_dh_dop_meta *m, *tmp;
	LIST_HEAD(detached);
	bool retry;

	do {
		retry = false;
		mutex_lock(&kasumi_dh_lock);
		list_for_each_entry_safe(m, tmp, retired, retire_node) {
			struct dentry *dentry = m->dentry;

			spin_lock(&dentry->d_lock);
			/* A lookup can splice its alias after the first d_drop.
			 * Unhash it again before starting another reader drain. */
			if (!d_unhashed(dentry)) {
				spin_unlock(&dentry->d_lock);
				d_drop(dentry);
				retry = true;
				continue;
			}
			if (kasumi_dh_owns_dops(m, dentry->d_op)) {
				unsigned int flags = READ_ONCE(dentry->d_flags);

				WRITE_ONCE(dentry->d_flags,
					   (flags & ~KASUMI_DH_DOP_FLAGS) |
					   m->orig_op_flags);
				smp_wmb();
				WRITE_ONCE(dentry->d_op, m->orig_dop);
			}
			spin_unlock(&dentry->d_lock);
			hash_del_rcu(&m->node);
			list_del_init(&m->dir_node);
			list_move_tail(&m->retire_node, &detached);
		}
		mutex_unlock(&kasumi_dh_lock);
		if (retry) {
			kasumi_synchronize_rcu_tasks();
			synchronize_srcu(&kasumi_dh_srcu);
			kasumi_synchronize_rcu_tasks();
			synchronize_rcu();
		}
	} while (retry);

	if (list_empty(&detached))
		return;
	kasumi_synchronize_rcu_tasks();
	synchronize_srcu(&kasumi_dh_srcu);
	kasumi_synchronize_rcu_tasks();
	synchronize_rcu();
	list_for_each_entry_safe(m, tmp, &detached, retire_node) {
		list_del(&m->retire_node);
		dput(m->dentry);
		kfree(m);
	}
}

/*
 * Retire every dentry that a revalidation declared stale.  The mutex
 * serializes retirement-list ownership with DEL/CLEAR.  Metadata remains in
 * the hash through the first drain, so other owners leave its list node alone.
 */
static void kasumi_dh_reap_dops_workfn(struct work_struct *work)
{
	struct kasumi_dh_dop_meta *m;
	struct hlist_node *tmp;
	LIST_HEAD(retired_dops);
	int bkt;

	(void)work;
	mutex_lock(&kasumi_dh_lock);
	hash_for_each_safe(kasumi_dh_dops, bkt, tmp, m, node) {
		if (test_bit(KASUMI_DH_DOP_AUTO_RETIRE, &m->state))
			kasumi_dh_retire_dop_locked(m, &retired_dops);
	}
	mutex_unlock(&kasumi_dh_lock);

	if (list_empty(&retired_dops))
		return;

	/* Close a stale d_op load, drain callbacks that already published their
	 * meta through SRCU, then cover both the wrapper epilogue and hash readers
	 * before dropping the lifetime pin.
	 */
	kasumi_synchronize_rcu_tasks();
	synchronize_srcu(&kasumi_dh_srcu);
	kasumi_synchronize_rcu_tasks();
	synchronize_rcu();
	kasumi_dh_free_retired_dops(&retired_dops);

	/* The dput above may release the final vnode after the directory's last
	 * rule was concurrently deleted.  Give the shared s_op owner a chance to
	 * retire now that both its client and vnode counts can be zero.
	 */
	kasumi_sop_shadow_reap();
}

/* ---- virtual-inode reclaim leaf functions ------------------------------
 * Called by the unified super_operations owner (kasumi_sop_shadow) from its
 * destroy/evict/drop_inode trampolines, with @orig (the sb's original s_op)
 * already resolved under RCU.  The trampoline owns the active-counter drain, so
 * these bodies may early-return freely.  Behavior is identical to the former
 * SRCU-wrapped s_op callbacks; only the meta lookup + drain moved to the owner.
 */
void KASUMI_NOCFI kasumi_dh_reclaim_evict_inode(struct inode *inode,
					const struct super_operations *orig)
{
	if (kasumi_vnode_is_ours(inode)) {
		truncate_inode_pages_final(&inode->i_data);
		clear_inode(inode);
		return;
	}
	if (orig && orig->evict_inode) {
		orig->evict_inode(inode);
	} else {
		truncate_inode_pages_final(&inode->i_data);
		clear_inode(inode);
	}
}

int KASUMI_NOCFI kasumi_dh_reclaim_drop_inode(struct inode *inode,
					const struct super_operations *orig)
{
	if (kasumi_vnode_is_ours(inode))
		return !inode->i_nlink || inode_unhashed(inode);
	if (orig && orig->drop_inode)
		return orig->drop_inode(inode);
	return !inode->i_nlink || inode_unhashed(inode);
}

/* ---- install ----------------------------------------------------------- */

/* Install (or, on a dir already carrying our lookup shadow, upgrade to add) the
 * directory iterator so readdir runs through kasumi_dh_iterate.  Only inject
 * and hide children need it; lookup_only (merge) children leave readdir to the
 * overlay filldir, so their dir is installed iop-only and never gets this
 * shadow — lookup (i_op) and iterate (i_fop) are independent inode fields, so
 * the two layers never contend when dirhijack only owns lookup. */
static int kasumi_dh_install_iterate(struct inode *inode,
				     struct kasumi_dh_dir *dir)
{
	int ret;

	if (dir->iterate_bound)
		return 0;
	ret = kasumi_fop_get(inode, false);
	if (ret)
		return ret;
	ret = kasumi_fop_bind_iterate_client(inode, kasumi_dh_iterate, dir);
	if (ret) {
		kasumi_fop_put(inode, false);
		return ret;
	}
	dir->iterate_owned = true;
	dir->iterate_bound = true;
	return 0;
}

static struct kasumi_dh_dir *kasumi_dh_install_dir(struct dentry *parent,
						   bool need_iterate,
						   bool sop_registered,
						   int *errp)
{
	struct inode *inode = d_inode(parent);
	struct kasumi_dh_iop *iop_meta = kasumi_dh_iop_of(inode);
	struct kasumi_dh_iop *im;
	struct kasumi_dh_dir *dir;
	const struct inode_operations *orig_iop;
	int ret = 0;

	if (iop_meta) {
		if (need_iterate)
			ret = kasumi_dh_install_iterate(inode, iop_meta->dir);
		if (errp)
			*errp = ret;
		if (ret)
			return NULL;
		return iop_meta->dir;
	}
	orig_iop = READ_ONCE(inode->i_op);
	if (!orig_iop || !orig_iop->lookup)
		return NULL;

	dir = kzalloc(sizeof(*dir), GFP_KERNEL);
	if (!dir)
		return NULL;
	dir->dir_inode = igrab(inode);
	if (!dir->dir_inode) {
		kfree(dir);
		return NULL;
	}
	INIT_HLIST_HEAD(&dir->children);
	hash_init(dir->child_index);
	spin_lock_init(&dir->lock);
	INIT_LIST_HEAD(&dir->list);
	INIT_LIST_HEAD(&dir->batch_node);
	INIT_LIST_HEAD(&dir->dops);
	dir->sop_client = sop_registered;

	im = kzalloc(sizeof(*im), GFP_KERNEL);
	if (!im) {
		iput(dir->dir_inode);
		kfree(dir);
		return NULL;
	}
	im->fake_iop = *orig_iop;
	im->orig_iop = orig_iop;
	im->dir = dir;
	im->fake_iop.lookup = kasumi_dh_lookup;
	im->fake_iop.getattr = kasumi_dh_getattr;
	if (orig_iop->atomic_open)
		im->fake_iop.atomic_open = kasumi_dh_atomic_open;
	dir->iop_meta = im;

	if (need_iterate) {
		ret = kasumi_dh_install_iterate(inode, dir);
		if (ret) {
			kfree(im);
			iput(dir->dir_inode);
			kfree(dir);
			if (errp)
				*errp = ret;
			return NULL;
		}
	}
	dir->name_parent = dget(parent);
	list_add_tail(&dir->list, &kasumi_dh_dirs);
	smp_store_release(&inode->i_op, &im->fake_iop);
	if (errp)
		*errp = 0;
	return dir;
}

/* Roll back a just-published, still-empty directory after child allocation
 * failed.  Publication is withdrawn under kasumi_dh_lock; the sleepable drain
 * and owner release happen afterwards in kasumi_dh_release_detached_dir(). */
static void kasumi_dh_detach_dir_locked(struct kasumi_dh_dir *dir)
{
	struct inode *inode;

	if (!dir)
		return;
	inode = dir->dir_inode;
	WRITE_ONCE(dir->retiring, true);
	kasumi_dh_unindex_dir(dir);
	list_del_init(&dir->batch_node);
	if (inode && dir->iop_meta &&
	    READ_ONCE(inode->i_op) == &dir->iop_meta->fake_iop)
		smp_store_release(&inode->i_op, dir->iop_meta->orig_iop);
	if (inode && dir->iterate_bound) {
		kasumi_fop_unbind_iterate_client(inode, dir);
		dir->iterate_bound = false;
	}
	if (!list_empty(&dir->list))
		list_del_init(&dir->list);
}

static void kasumi_dh_release_detached_dir(struct kasumi_dh_dir *dir)
{
	struct kasumi_dh_child *c;
	struct hlist_node *tmp;
	struct inode *inode;
	struct super_block *sb;

	if (!dir)
		return;
	/* Cover a stale i_op fetch, callbacks already inside the dirhijack SRCU
	 * domain, and an iterate client that acquired @dir before unbind. */
	kasumi_synchronize_rcu_tasks();
	synchronize_srcu(&kasumi_dh_srcu);
	kasumi_fop_synchronize_iterate_clients();
	kasumi_synchronize_rcu_tasks();

	/* An auto-retirement worker may own a still-hashed dentry for this dir. */
	flush_work(&kasumi_dh_reap_dops_work);
	hlist_for_each_entry_safe(c, tmp, &dir->children, node) {
		kasumi_dh_child_unlink(c);
		kasumi_dh_child_free(c);
	}
	inode = dir->dir_inode;
	sb = inode ? inode->i_sb : NULL;
	if (dir->iterate_owned) {
		kasumi_fop_put(inode, false);
		dir->iterate_owned = false;
	}
	/* Keep the s_op client's s_active pin until the parent inode reference is
	 * gone.  A concurrent late-vnode reap may otherwise drop the final active
	 * superblock reference and start shutdown while iput still uses it.
	 */
	dput(dir->name_parent);
	dir->name_parent = NULL;
	dir->dir_inode = NULL;
	if (inode)
		iput(inode);
	if (dir->sop_client && sb) {
		kasumi_sop_shadow_unregister_dh(sb);
		dir->sop_client = false;
	}
	kfree(dir->iop_meta);
	kfree(dir);
	kasumi_sop_shadow_reap();
}

/* ---- child index ------------------------------------------------------- */

static void kasumi_dh_child_free_rcu(struct rcu_head *rcu)
{
	struct kasumi_dh_child *c = container_of(rcu, struct kasumi_dh_child, rcu);

	/* RCU callback context cannot run path_put()/dput(). Move the object to a
	 * lockless queue and finish its sleepable teardown on the system workqueue.
	 */
	llist_add(&c->free_node, &kasumi_dh_free_children);
	schedule_work(&kasumi_dh_free_children_work);
}

static void kasumi_dh_child_free(struct kasumi_dh_child *c)
{
	if (c->source.dentry)
		kasumi_path_put(&c->source);
	dput(c->name_dentry);
	kasumi_identity_put(c->identity);
	kfree(c->vpath);
	kfree(c);
}

static void kasumi_dh_free_children_workfn(struct work_struct *work)
{
	struct llist_node *head, *node, *next;

	(void)work;
	while ((head = llist_del_all(&kasumi_dh_free_children)) != NULL) {
		llist_for_each_safe(node, next, head) {
			struct kasumi_dh_child *c = container_of(
				node, struct kasumi_dh_child, free_node);

			kasumi_dh_child_free(c);
		}
	}
}

static void kasumi_dh_batch_touch(struct kasumi_dirhijack_batch *batch,
				  struct kasumi_dh_dir *dir)
{
	if (batch && list_empty(&dir->batch_node))
		list_add_tail(&dir->batch_node, &batch->directories);
}

static struct kasumi_dh_change *kasumi_dh_batch_change(
	struct kasumi_dirhijack_batch *batch, struct kasumi_dh_dir *dir,
	const char *name, u16 len)
{
	struct kasumi_dh_change *change;
	unsigned long key;
	u32 hash;

	kasumi_dh_batch_touch(batch, dir);
	if (kasumi_dir_name_hash(dir->name_parent, name, len, &hash))
		return NULL;
	key = (unsigned long)dir ^ hash;

	hash_for_each_possible(batch->index, change, node, key) {
		struct kasumi_dh_child *child = change->new_child ?
			change->new_child : change->old_child;

		if (change->dir == dir && child && child->name_hash == hash &&
		    kasumi_dir_name_equal(dir->name_parent, child->name_dentry,
			child->name, child->name_len, name, len))
			return change;
	}
	change = kzalloc(sizeof(*change), GFP_KERNEL);
	if (!change)
		return NULL;
	change->dir = dir;
	change->old_child = kasumi_dh_find_child(dir, name, len);
	if (change->old_child)
		change->previous_last = change->old_child->last_generation;
	list_add_tail(&change->list, &batch->changes);
	hash_add(batch->index, &change->node, key);
	return change;
}

static int kasumi_dh_dir_add_child(struct kasumi_dirhijack_batch *batch,
				   struct kasumi_dh_dir *dir, const char *name,
				   u16 len, const struct path *source,
				   unsigned long v_ino, u8 flags, bool hide,
				   bool lookup_only, const char *vpath,
				   const char *registered_path)
{
	struct kasumi_dh_child *c, *old;
	struct kasumi_dh_change *change = NULL;
	size_t path_size = registered_path ? strlen(registered_path) + 1 : 0;
	u32 hash;
	int ret = 0;

	kasumi_dh_batch_touch(batch, dir);
	ret = kasumi_dir_name_hash(dir->name_parent, name, len, &hash);
	if (ret)
		return ret;
	c = kzalloc(sizeof(*c) + len + 1 + path_size, GFP_KERNEL);
	if (!c)
		return -ENOMEM;
	c->name_dentry = kasumi_dir_name_probe(dir->name_parent, name, len);
	if (IS_ERR(c->name_dentry)) {
		ret = PTR_ERR(c->name_dentry);
		kfree(c);
		return ret;
	}
	if (registered_path) {
		c->registered_path = c->name + len + 1;
		memcpy(c->registered_path, registered_path, path_size);
		c->registered_hash =
		    full_name_hash(NULL, registered_path, path_size - 1);
	}
	c->vpath = NULL;
	if (vpath) {
		c->vpath = kstrdup(vpath, GFP_KERNEL);
		if (!c->vpath) {
			kasumi_dh_child_free(c);
			return -ENOMEM;
		}
	}
	memset(&c->source, 0, sizeof(c->source));
	if (source && source->dentry) {
		c->source = *source;
		path_get(&c->source);
	}
	if (source && source->dentry && d_inode(source->dentry)) {
		struct inode *inode = d_inode(source->dentry);

		ret = kasumi_identity_source_get(inode->i_sb->s_dev,
			inode->i_ino, &c->identity);
	} else if (vpath && (flags & KASUMI_VNODE_F_VIRTUAL_DIR)) {
		ret = kasumi_identity_path_get(vpath, &c->identity);
	}
	if (ret) {
		kasumi_dh_child_free(c);
		return ret;
	}
	c->v_ino = c->identity ? kasumi_identity_ino(c->identity) : v_ino;
	if (kasumi_dh_revision == U64_MAX) {
		kasumi_dh_child_free(c);
		return -EOVERFLOW;
	}
	c->revision = ++kasumi_dh_revision;
	c->first_generation = 0;
	c->last_generation = 0;
	c->name_hash = hash;
	c->name_len = len;
	c->flags = flags;
	c->hide = hide ? 1 : 0;
	c->legacy = true;
	c->hide_users = 0;
	c->bypass_hide_users = 0;
	c->lookup_only = lookup_only ? 1 : 0;
	memcpy(c->name, name, len);
	c->name[len] = '\0';

	if (batch) {
		change = kasumi_dh_batch_change(batch, dir, name, len);
		if (!change) {
			kasumi_dh_child_free(c);
			return -ENOMEM;
		}
		c->first_generation = batch->generation;
	}
	spin_lock(&dir->lock);
	old = kasumi_dh_find_child(dir, name, len);
	if (old) {
		c->hide_users = old->hide_users;
		c->bypass_hide_users = old->bypass_hide_users;
	}
	if (batch) {
		if (change->old_child)
			WRITE_ONCE(change->old_child->last_generation,
				   batch->generation - 1);
		old = change->new_child;
		change->new_child = c;
	}
	if (old)
		kasumi_dh_child_unlink(old);
	kasumi_dh_child_link(dir, c);
	spin_unlock(&dir->lock);
	if (old)
		call_rcu(&old->rcu, kasumi_dh_child_free_rcu);
	return 0;
}

/* ---- public control surface -------------------------------------------- */

static int kasumi_dh_split_parent(const char *visible_path, char **parent_out,
				  const char **child_out)
{
	char *parent;
	char *slash;

	if (!visible_path || visible_path[0] != '/')
		return -EINVAL;
	parent = kstrdup(visible_path, GFP_KERNEL);
	if (!parent)
		return -ENOMEM;
	slash = strrchr(parent, '/');
	if (!slash || !slash[1]) {
		kfree(parent);
		return -EINVAL;
	}
	*child_out = visible_path + (slash - parent) + 1;
	if (slash == parent)
		parent[1] = '\0';
	else
		*slash = '\0';
	*parent_out = parent;
	return 0;
}

/*
 * Slice 4c-v2: register a rule whose visible path has missing intermediate
 * directories.  Walk up @visible_path's parent chain to the deepest existing
 * real directory R, then register the first missing segment s1 at R as a
 * F_VIRTUAL_DIR child (visible path R/s1).  That synthesized directory resolves
 * everything below it — deeper virtual dirs and the leaf — dynamically from the
 * rule table (kasumi_rule_vpath_*), so only the top segment needs registering.
 * The child is shared across all rules under R/s1.
 */
static KASUMI_NOCFI int kasumi_dh_register_vtopo(struct kasumi_dirhijack_batch *batch,
						 const char *visible_path)
{
	char *pparent = NULL;
	char *probe;
	char *seg = NULL;
	char *vpath = NULL;
	const char *leaf;
	const char *after;
	const char *slash;
	struct path rpath;
	struct inode *rinode;
	struct kasumi_dh_dir *dir = NULL;
	struct kasumi_dh_dir *rollback_dir = NULL;
	size_t rlen, seg_len;
	bool sop_registered = false;
	int ret;

	ret = kasumi_dh_split_parent(visible_path, &pparent, &leaf);
	if (ret)
		return ret;
	probe = kstrdup(pparent, GFP_KERNEL);
	kfree(pparent);
	if (!probe)
		return -ENOMEM;

	/* Walk up to the deepest existing real directory. */
	for (;;) {
		char *ls;

		ret = kasumi_kern_path(probe, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
				       &rpath);
		if (ret == 0)
			break;
		if (ret != -ENOENT) {
			kfree(probe);
			return ret;
		}
		ls = strrchr(probe, '/');
		if (!ls) {
			kfree(probe);
			return -ENOENT;
		}
		if (ls == probe) {
			if (probe[1]) {	/* collapse "/x" -> "/" and retry root */
				probe[1] = '\0';
				continue;
			}
			kfree(probe);	/* even "/" did not resolve */
			return -ENOENT;
		}
		*ls = '\0';
	}
	rinode = d_inode(rpath.dentry);
	if (!rinode || !S_ISDIR(rinode->i_mode)) {
		kasumi_path_put(&rpath);
		kfree(probe);
		return -ENOTDIR;
	}
	rlen = (strcmp(probe, "/") == 0) ? 0 : strlen(probe);
	kfree(probe);

	/* First segment of @visible_path after R, and the virtual dir path R/s1. */
	after = visible_path + rlen + 1;
	slash = strchr(after, '/');
	seg_len = slash ? (size_t)(slash - after) : strlen(after);
	if (!seg_len || seg_len > NAME_MAX) {
		kasumi_path_put(&rpath);
		return -EINVAL;
	}
	seg = kstrndup(after, seg_len, GFP_KERNEL);
	vpath = kstrndup(visible_path, rlen + 1 + seg_len, GFP_KERNEL);
	if (!seg || !vpath) {
		kfree(seg);
		kfree(vpath);
		kasumi_path_put(&rpath);
		return -ENOMEM;
	}

	mutex_lock(&kasumi_dh_lock);
	if (!kasumi_dh_iop_of(rinode)) {
		ret = kasumi_sop_shadow_register_dh(rpath.dentry->d_sb);
		if (ret)
			goto out;
		sop_registered = true;
	}
	dir = kasumi_dh_install_dir(rpath.dentry, true, sop_registered, &ret);
	if (!dir) {
		if (!ret)
			ret = -ENOMEM;
		if (sop_registered)
			kasumi_sop_shadow_unregister_dh(rpath.dentry->d_sb);
		goto out;
	}
	{
		struct kasumi_dh_child *existing = kasumi_dh_find_child_at(
			dir, seg, seg_len,
			batch ? batch->generation : kasumi_rules_generation());

		/* An explicit backed directory also resolves its configured descendants. */
		if (existing && existing->source.dentry) {
			ret = (existing->flags & KASUMI_VNODE_F_DIR) ? 0 : -ENOTDIR;
			goto out;
		}
	}
	ret = kasumi_dh_dir_add_child(
	    batch, dir, seg, (u16)seg_len, NULL, kasumi_vnode_vpath_ino(vpath),
	    KASUMI_VNODE_F_DIR | KASUMI_VNODE_F_VIRTUAL_DIR, false, false,
	    vpath, vpath);
	if (ret) {
		if (sop_registered) {
			kasumi_dh_detach_dir_locked(dir);
			rollback_dir = dir;
		}
		goto out;
	}
	{
		struct qstr qn;
		struct dentry *cached;

		qn.name = seg;
		qn.len = (u32)seg_len;
		kasumi_dir_name_hash(rpath.dentry, seg, seg_len, &qn.hash);
		cached = kasumi_d_lookup(rpath.dentry, &qn);
		if (cached) {
			d_drop(cached);
			dput(cached);
		}
	}
out:
	mutex_unlock(&kasumi_dh_lock);
	if (rollback_dir)
		kasumi_dh_release_detached_dir(rollback_dir);
	else if (ret && sop_registered && !dir)
		kasumi_sop_shadow_reap();
	kasumi_path_put(&rpath);
	kasumi_log("dirhijack_vtopo visible=%s vdir=%s ret=%d\n",
		visible_path, vpath, ret);
	kfree(seg);
	kfree(vpath);
	return ret;
}

static KASUMI_NOCFI int
kasumi_dh_register(struct kasumi_dirhijack_batch *batch,
		   const char *visible_path, const struct path *source,
		   unsigned long v_ino, u8 flags, bool hide, bool lookup_only)
{
	char *parent = NULL;
	const char *child = NULL;
	struct path ppath;
	struct inode *pinode;
	struct kasumi_dh_dir *dir = NULL;
	struct kasumi_dh_dir *rollback_dir = NULL;
	struct dentry *cached;
	struct qstr qname;
	size_t child_len;
	bool sop_registered = false;
	int ret;

	if (!READ_ONCE(kasumi_dh_ready) || !kasumi_kern_path)
		return -EOPNOTSUPP;
	ret = kasumi_dh_split_parent(visible_path, &parent, &child);
	if (ret)
		return ret;
	child_len = strlen(child);
	if (!child_len || child_len > NAME_MAX) {
		kfree(parent);
		return -EINVAL;
	}
	ret = kasumi_kern_path(parent, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &ppath);
	if (ret) {
		kfree(parent);
		/* Missing intermediate directory: synthesize virtual topology so a
		 * deep visible path still resolves.  Only for backed inject/dir-source
		 * rules — a hide or merge-shadow with a missing parent is meaningless. */
		if (ret == -ENOENT && !hide && !lookup_only)
			return kasumi_dh_register_vtopo(batch, visible_path);
		return ret;
	}
	if (hide && ppath.dentry->d_sb->s_magic == FUSE_SUPER_MAGIC &&
	    !READ_ONCE(kasumi_dh_fuse_registered)) {
		kasumi_path_put(&ppath);
		kfree(parent);
		return -EOPNOTSUPP;
	}
	pinode = d_inode(ppath.dentry);
	if (!pinode || !S_ISDIR(pinode->i_mode)) {
		kasumi_path_put(&ppath);
		kfree(parent);
		return -ENOTDIR;
	}

	mutex_lock(&kasumi_dh_lock);
	if (!kasumi_dh_iop_of(pinode)) {
		ret = kasumi_sop_shadow_register_dh(ppath.dentry->d_sb);
		if (ret)
			goto out;
		sop_registered = true;
	}
	dir = kasumi_dh_install_dir(ppath.dentry, !lookup_only, sop_registered, &ret);
	if (!dir) {
		if (!ret)
			ret = -ENOMEM;
		if (sop_registered)
			kasumi_sop_shadow_unregister_dh(ppath.dentry->d_sb);
		goto out;
	}
	ret = kasumi_dh_dir_add_child(
	    batch, dir, child, (u16)child_len, source, v_ino, flags, hide,
	    lookup_only, flags & KASUMI_VNODE_F_DIR ? visible_path : NULL,
	    visible_path);
	if (ret) {
		if (sop_registered) {
			kasumi_dh_detach_dir_locked(dir);
			rollback_dir = dir;
		}
		goto out;
	}

	qname.name = child;
	qname.len = (u32)child_len;
	kasumi_dir_name_hash(ppath.dentry, child, child_len, &qname.hash);
	cached = kasumi_d_lookup(ppath.dentry, &qname);
	if (cached) {
		d_drop(cached);
		dput(cached);
	}
out:
	mutex_unlock(&kasumi_dh_lock);
	if (rollback_dir)
		kasumi_dh_release_detached_dir(rollback_dir);
	else if (ret && sop_registered && !dir)
		kasumi_sop_shadow_reap();
	kasumi_path_put(&ppath);
	kasumi_log("dirhijack_%s visible=%s child=%s ret=%d\n",
		hide ? "hide" : lookup_only ? "shadow" : "add",
		visible_path, child ? child : "(null)", ret);
	kfree(parent);
	return ret;
}

int kasumi_dirhijack_add(const char *visible_path, const struct path *source,
			 unsigned long v_ino, u8 flags)
{
	return kasumi_dh_register(NULL, visible_path, source, v_ino, flags, false,
				  false);
}

/*
 * Register a lookup-only child at @visible_path backed by @source: VFS lookup
 * resolves it to a Kasumi vnode (open/stat/readlink), but dirhijack does not
 * touch this dir's readdir — the overlay filldir injection owns emit and dedup
 * for the name.  Used to sink a merge-materialized file's lookup axis onto the
 * VFS layer (Slice 4a) without double-injecting the entry into getdents.
 * Sleepable context only.
 */
int kasumi_dirhijack_add_shadow(const char *visible_path,
				const struct path *source,
				unsigned long v_ino, u8 flags)
{
	return kasumi_dh_register(NULL, visible_path, source, v_ino, flags, false,
				  true);
}

/*
 * Register a suppress-only child at @visible_path: VFS lookup returns a negative
 * dentry (-ENOENT) and readdir omits the name for hide-target observers.
 * Privileged and rule-management lookups retain the real entry.
 * Sleepable context only. Returns 0 or a negative errno.
 */
int kasumi_dirhijack_hide(const char *visible_path, u32 rule_flags)
{
	if (!kasumi_dirhijack_enabled())
		return -EOPNOTSUPP;
	return kasumi_dh_register(NULL,
	    visible_path, NULL, 0,
	    (rule_flags & KSM_RULE_BYPASS_POLICY) ? KASUMI_VNODE_F_BYPASS : 0,
	    true, false);
}

struct kasumi_dirhijack_batch *kasumi_dirhijack_batch_begin(u64 generation)
{
	struct kasumi_dirhijack_batch *batch;

	if (generation <= kasumi_rules_generation() || generation == U64_MAX)
		return ERR_PTR(-EINVAL);
	batch = kzalloc(sizeof(*batch), GFP_KERNEL);
	if (!batch)
		return ERR_PTR(-ENOMEM);
	INIT_LIST_HEAD(&batch->changes);
	INIT_LIST_HEAD(&batch->directories);
	hash_init(batch->index);
	batch->generation = generation;
	return batch;
}

int kasumi_dirhijack_batch_add(struct kasumi_dirhijack_batch *batch,
	const char *visible_path, const struct path *source,
	unsigned long ino, u8 flags, bool lookup_only)
{
	if (!batch)
		return -EINVAL;
	return kasumi_dh_register(batch, visible_path, source, ino, flags,
				  false, lookup_only);
}

int kasumi_dirhijack_batch_hide(struct kasumi_dirhijack_batch *batch,
	const char *visible_path, u32 rule_flags)
{
	if (!batch || !kasumi_dirhijack_enabled())
		return -EOPNOTSUPP;
	return kasumi_dh_register(batch, visible_path, NULL, 0,
		(rule_flags & KSM_RULE_BYPASS_POLICY) ? KASUMI_VNODE_F_BYPASS : 0,
		true, false);
}

static int kasumi_dh_batch_remove(struct kasumi_dirhijack_batch *batch,
				  struct kasumi_dh_child *child)
{
	struct kasumi_dh_change *change;
	struct kasumi_dh_dir *dir = child->dir;
	struct kasumi_dh_child *old;
	int ret;

	change =
	    kasumi_dh_batch_change(batch, dir, child->name, child->name_len);
	if (!change)
		return -ENOMEM;
	if (child->hide_users) {
		ret = kasumi_dh_dir_add_child(batch, dir, child->name,
					      child->name_len, NULL, 0, 0, true,
					      false, NULL, NULL);
		if (!ret)
			change->new_child->legacy = false;
		return ret;
	}
	spin_lock(&dir->lock);
	if (change->old_child)
		WRITE_ONCE(change->old_child->last_generation, batch->generation - 1);
	old = change->new_child;
	if (old) {
		kasumi_dh_child_unlink(old);
		change->new_child = NULL;
	}
	spin_unlock(&dir->lock);
	if (old)
		call_rcu(&old->rcu, kasumi_dh_child_free_rcu);
	return 0;
}

int kasumi_dirhijack_batch_del(struct kasumi_dirhijack_batch *batch,
			       const char *visible_path)
{
	struct kasumi_dh_child *child;
	const char *name;
	int ret = -ENOENT;

	if (!batch || !visible_path || visible_path[0] != '/')
		return -EINVAL;
	name = strrchr(visible_path, '/') + 1;
	if (!*name)
		return -EINVAL;
	if (strlen(name) > NAME_MAX)
		return -ENAMETOOLONG;
	/* The parent may have moved or been replaced since registration. */
	mutex_lock(&kasumi_dh_lock);
	while (
	    (child = kasumi_dh_find_binding(visible_path, batch->generation))) {
		ret = kasumi_dh_batch_remove(batch, child);
		if (ret)
			break;
	}
	mutex_unlock(&kasumi_dh_lock);
	return ret;
}

void kasumi_dirhijack_batch_finish(struct kasumi_dirhijack_batch *batch,
				  bool published)
{
	struct kasumi_dh_change *change, *next;
	struct kasumi_dh_dir *dir, *next_dir;
	struct kasumi_dh_dop_meta *dop;
	LIST_HEAD(dead_dirs);
	LIST_HEAD(retired_dops);

	if (!batch)
		return;
	/* Published readers may have selected the old generation before sleeping. */
	if (published)
		synchronize_srcu(&kasumi_dh_srcu);
	mutex_lock(&kasumi_dh_lock);
	list_for_each_entry_safe(change, next, &batch->changes, list) {
		struct kasumi_dh_child *retired = published ?
			change->old_child : change->new_child;

		spin_lock(&change->dir->lock);
		if (!published && change->old_child)
			WRITE_ONCE(change->old_child->last_generation,
				   change->previous_last);
		if (retired)
			kasumi_dh_child_unlink(retired);
		spin_unlock(&change->dir->lock);
		if (retired)
			call_rcu(&retired->rcu, kasumi_dh_child_free_rcu);
		list_del(&change->list);
		hash_del(&change->node);
		kfree(change);
	}
	list_for_each_entry_safe(dir, next_dir, &batch->directories, batch_node) {
		list_del_init(&dir->batch_node);
		if (!hlist_empty(&dir->children))
			continue;
		kasumi_dh_detach_dir_locked(dir);
		list_add_tail(&dir->list, &dead_dirs);
		list_for_each_entry(dop, &dir->dops, dir_node)
			kasumi_dh_retire_dop_locked(dop, &retired_dops);
	}
	mutex_unlock(&kasumi_dh_lock);
	if (!list_empty(&retired_dops)) {
		kasumi_synchronize_rcu_tasks();
		synchronize_srcu(&kasumi_dh_srcu);
		kasumi_synchronize_rcu_tasks();
		synchronize_rcu();
		kasumi_dh_free_retired_dops(&retired_dops);
	}
	list_for_each_entry_safe(dir, next_dir, &dead_dirs, list) {
		list_del_init(&dir->list);
		kasumi_dh_release_detached_dir(dir);
	}
	kfree(batch);
}

static KASUMI_NOCFI int kasumi_dh_unregister(struct path ppath,
					     const char *child,
					     unsigned long su_ino, bool user,
					     bool bypass)
{
	struct kasumi_dh_iop *m;
	struct kasumi_dh_child *c = NULL, *replacement = NULL;
	bool keep = false;
	struct kasumi_dh_dir *dead_dir = NULL;
	struct kasumi_dh_dop_meta *dm;
	struct hlist_node *htmp;
	LIST_HEAD(retired_dops);
	size_t child_len = strlen(child);
	bool had_dops;
	int bkt;
	if (!child_len || child_len > NAME_MAX)
		return -EINVAL;

	mutex_lock(&kasumi_dh_lock);
	m = kasumi_dh_iop_of(d_inode(ppath.dentry));
	if (m && m->dir) {
		c = kasumi_dh_find_child(m->dir, child, (u16)child_len);
		if (!user && !su_ino && c && c->hide_users) {
			replacement = kzalloc(
			    sizeof(*replacement) + c->name_len + 1, GFP_KERNEL);
			if (!replacement) {
				mutex_unlock(&kasumi_dh_lock);
				return -ENOMEM;
			}
			replacement->name_dentry = dget(c->name_dentry);
			replacement->hide = 1;
			replacement->revision = c->revision;
			replacement->hide_users = c->hide_users;
			replacement->bypass_hide_users = c->bypass_hide_users;
			replacement->name_hash = c->name_hash;
			replacement->name_len = c->name_len;
			memcpy(replacement->name, c->name, c->name_len + 1);
		}
		spin_lock(&m->dir->lock);
		c = kasumi_dh_find_child(m->dir, child, (u16)child_len);
		if (user && c) {
			if (WARN_ON_ONCE(!c->hide_users)) {
				spin_unlock(&m->dir->lock);
				mutex_unlock(&kasumi_dh_lock);
				return -ENOENT;
			}
			WRITE_ONCE(c->hide_users, c->hide_users - 1);
			if (bypass)
				WRITE_ONCE(c->bypass_hide_users,
					   c->bypass_hide_users - 1);
			keep = c->hide_users || c->legacy;
		}
		if (c && !keep) {
			kasumi_dh_child_unlink(c);
			if (replacement)
				kasumi_dh_child_link(m->dir, replacement);
		}
		if (c && hlist_empty(&m->dir->children))
			dead_dir = m->dir;
		spin_unlock(&m->dir->lock);
		if (c && !keep)
			call_rcu(&c->rcu, kasumi_dh_child_free_rcu);

		/* A d_splice_alias path can leave more than one held dentry for
		 * the same governed name.  Retire every matching shadow, not
		 * only the object currently returned by d_lookup(). */
		hash_for_each_safe(kasumi_dh_dops, bkt, htmp, dm, node)
		{
			if (dm->dir == m->dir && kasumi_dir_name_equal(
				m->dir->name_parent, dm->dentry, dm->name,
				dm->name_len, child, child_len))
				kasumi_dh_retire_dop_locked(dm, &retired_dops);
		}
		if (dead_dir)
			kasumi_dh_detach_dir_locked(dead_dir);
	}
	if (c) {
		/* Drop any dentry cached under this name so the next resolution
		 * runs the now child-free real lookup.  Essential for a hide:
		 * the cached negative that made the name -ENOENT for a view
		 * observer must be dropped, else the name stays "hidden" after
		 * its rule is gone (revalidate treats an ungoverned negative as
		 * a genuine absence and keeps it). */
		struct qstr qname;
		struct dentry *cached;

		qname.name = child;
		qname.len = (u32)child_len;
		kasumi_dir_name_hash(ppath.dentry, child, child_len, &qname.hash);
		cached = d_lookup(ppath.dentry, &qname);
		if (cached) {
			d_drop(cached);
			dput(cached);
		}
	}
	mutex_unlock(&kasumi_dh_lock);
	had_dops = !list_empty(&retired_dops);
	if (had_dops) {
		/* Close the d_op-load-to-callback-entry window first, then
		 * drain callbacks that published their dm through the SRCU
		 * wrapper. */
		kasumi_synchronize_rcu_tasks();
		synchronize_srcu(&kasumi_dh_srcu);
		/* Cover the wrapper epilogue after srcu_read_unlock(). */
		kasumi_synchronize_rcu_tasks();
		synchronize_rcu();
		kasumi_dh_free_retired_dops(&retired_dops);
	}
	if (dead_dir) {
		/* An auto-retire worker may already own a matching dm which DEL
		 * no longer found in the hash. Drain its dget before
		 * release_detached_dir() drops the final s_op client/s_active
		 * reference for this directory.
		 */
		flush_work(&kasumi_dh_reap_dops_work);
	}
	if (c || had_dops)
		shrink_dcache_sb(ppath.dentry->d_sb);
	if (dead_dir)
		kasumi_dh_release_detached_dir(dead_dir);
	return c ? 0 : -ENOENT;
}

struct kasumi_hide_binding {
	bool bypass;
	struct dentry *parent;
	char name[];
};

bool kasumi_dirhijack_hide_matches(const struct kasumi_hide_binding *binding,
				   const struct path *parent, u32 flags)
{
	return binding &&
	       binding->bypass == !!(flags & KSM_RULE_BYPASS_POLICY) &&
	       binding->parent == parent->dentry &&
	       !d_unlinked(binding->parent);
}

int kasumi_dirhijack_hide_get(const struct path *parent, const char *name,
			      u32 flags, struct kasumi_hide_binding **result)
{
	struct inode *inode = d_inode(parent->dentry);
	struct kasumi_hide_binding *binding;
	struct kasumi_dh_dir *dir = NULL, *rollback = NULL;
	struct kasumi_dh_child *child;
	bool registered = false;
	size_t len = strlen(name);
	int ret = 0;
	struct qstr qname = QSTR_INIT(name, len);
	struct dentry *cached;

	if (!READ_ONCE(kasumi_dh_ready))
		return -EOPNOTSUPP;
	if (!inode || !S_ISDIR(inode->i_mode) || !len || len > NAME_MAX)
		return -EINVAL;
	if (inode->i_sb->s_magic == FUSE_SUPER_MAGIC &&
	    !READ_ONCE(kasumi_dh_fuse_registered))
		return -EOPNOTSUPP;
	if (kasumi_vnode_is_ours(inode))
		return -EOPNOTSUPP;
	binding = kmalloc(sizeof(*binding) + len + 1, GFP_KERNEL);
	if (!binding)
		return -ENOMEM;
	memcpy(binding->name, name, len + 1);
	binding->bypass = !!(flags & KSM_RULE_BYPASS_POLICY);
	binding->parent = dget(parent->dentry);
	mutex_lock(&kasumi_dh_lock);
	if (!kasumi_dh_iop_of(inode)) {
		ret = kasumi_sop_shadow_register_dh(inode->i_sb);
		if (ret)
			goto out;
		registered = true;
	}
	dir = kasumi_dh_install_dir(parent->dentry, true, registered, &ret);
	if (!dir) {
		ret = ret ?: -ENOMEM;
		if (registered)
			kasumi_sop_shadow_unregister_dh(inode->i_sb);
		goto out;
	}
	child = kasumi_dh_find_child(dir, name, len);

	if (!child) {
		ret = kasumi_dh_dir_add_child(NULL, dir, name, len, NULL, 0, 0,
					      true, false, NULL, NULL);
		if (ret) {
			if (registered) {
				kasumi_dh_detach_dir_locked(dir);
				rollback = dir;
			}
			goto out;
		}
		child = kasumi_dh_find_child(dir, name, len);
		WRITE_ONCE(child->legacy, false);
	}
	WRITE_ONCE(child->hide_users, child->hide_users + 1);
	if (binding->bypass)
		WRITE_ONCE(child->bypass_hide_users,
			   child->bypass_hide_users + 1);
	kasumi_dir_name_hash(parent->dentry, name, len, &qname.hash);
	cached = d_lookup(parent->dentry, &qname);
	if (cached) {
		d_drop(cached);
		dput(cached);
	}
out:
	mutex_unlock(&kasumi_dh_lock);
	if (rollback)
		kasumi_dh_release_detached_dir(rollback);
	else if (ret && registered && !dir)
		kasumi_sop_shadow_reap();
	if (ret) {
		dput(binding->parent);
		kfree(binding);
	} else {
		*result = binding;
	}
	return ret;
}

int kasumi_dirhijack_collect(struct file *file, struct list_head *entries,
			     u64 *generation, void *data)
{
	struct kasumi_dh_iop *meta;
	struct kasumi_dh_child *child;
	int error = 0;
	int index = srcu_read_lock(&kasumi_dh_srcu);

	(void)data;
	rcu_read_lock();
	*generation = kasumi_rules_generation();
	meta = kasumi_dh_iop_of(file_inode(file));
	if (!meta || !meta->dir || READ_ONCE(meta->dir->retiring))
		goto out;
	hlist_for_each_entry_rcu(child, &meta->dir->children, node) {
		struct kasumi_dir_entry *entry;
		u32 flags = (child->flags & KASUMI_VNODE_F_BYPASS) ?
			KSM_RULE_BYPASS_POLICY : 0;

		if (!kasumi_dh_child_visible_at(child, *generation))
			continue;
		if ((child->flags & KASUMI_VNODE_F_VIRTUAL_DIR) &&
		    !kasumi_rule_vpath_flags(child->vpath, *generation, &flags))
			continue;
		entry = kasumi_dir_entry_alloc(child->name, child->name_len, GFP_ATOMIC);
		if (!entry) {
			error = -ENOMEM;
			goto out;
		}
		entry->name_dentry = dget(child->name_dentry);
		entry->identity = child->identity;
		kasumi_identity_get(entry->identity);
		entry->ino = child->v_ino;
		entry->rule_flags = flags;
		entry->hide_flags = ((child->legacy && child->hide &&
				      (child->flags & KASUMI_VNODE_F_BYPASS)) ||
				     READ_ONCE(child->bypass_hide_users)) ?
			KSM_RULE_BYPASS_POLICY : 0;
		entry->redirect = child->legacy && !child->hide;
		entry->hide = child->hide || READ_ONCE(child->hide_users);
		entry->hide_storage_managed =
			kasumi_hide_storage_parent(file_inode(file));
		if (child->source.dentry && d_inode(child->source.dentry))
			entry->type = (d_inode(child->source.dentry)->i_mode & S_IFMT) >> 12;
		else
			entry->type = (child->flags & KASUMI_VNODE_F_DIR) ? DT_DIR : DT_UNKNOWN;
		list_add_tail(&entry->list, entries);
	}
out:
	rcu_read_unlock();
	srcu_read_unlock(&kasumi_dh_srcu, index);
	return error;
}

void kasumi_dirhijack_hide_put(struct kasumi_hide_binding *binding)
{
	struct super_block *sb;
	struct path parent = {};

	if (!binding)
		return;
	parent.dentry = binding->parent;
	sb = parent.dentry->d_sb;
	/* No long-lived mount reference: ordinary umount must remain possible.
	 * Keep the superblock alive until the last held dentry is released. */
	atomic_inc(&sb->s_active);
	kasumi_dh_unregister(parent, binding->name, 0, true, binding->bypass);
	dput(binding->parent);
	kfree(binding);
	deactivate_super(sb);
}

bool kasumi_dirhijack_hidden(struct inode *parent, const char *name, int len)
{
	struct qstr qname = QSTR_INIT(name, len);
	int idx = srcu_read_lock(&kasumi_dh_srcu);
	bool hidden = kasumi_dh_hidden_name(parent, &qname);

	srcu_read_unlock(&kasumi_dh_srcu, idx);
	return hidden;
}

KASUMI_NOCFI int kasumi_dirhijack_child_visible(struct inode *parent,
						const char *name, int len)
{
	struct kasumi_dh_iop *meta;
	struct kasumi_dh_child *child;
	int visible = -ENOENT;
	int idx = srcu_read_lock(&kasumi_dh_srcu);

	meta = kasumi_dh_iop_of(parent);
	if (!meta || !meta->dir)
		goto out;
	if (READ_ONCE(meta->dir->retiring)) {
		visible = 0;
		goto out;
	}
	rcu_read_lock();
	child = kasumi_dh_find_child(meta->dir, name, (u16)len);
	if (child)
		visible = kasumi_dh_current_targets(child, parent) &&
			  !kasumi_dh_current_hides(child, parent);
	rcu_read_unlock();
out:
	srcu_read_unlock(&kasumi_dh_srcu, idx);
	return visible;
}

KASUMI_NOCFI int kasumi_dirhijack_del(const char *visible_path)
{
	char *parent = NULL;
	const char *child = NULL;
	struct path ppath;
	int ret;

	ret = kasumi_dh_split_parent(visible_path, &parent, &child);
	if (ret)
		return ret;
	ret =
	    kasumi_kern_path(parent, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &ppath);
	if (!ret) {
		ret = kasumi_dh_unregister(ppath, child, 0, false, false);
		kasumi_path_put(&ppath);
	} else if (ret == -ENOENT) {
		ret = 0;
	}
	kfree(parent);
	return ret;
}

static void kasumi_dh_shrink_dead_sbs(struct list_head *dead_dirs)
{
	struct kasumi_dh_dir *dir;

	list_for_each_entry(dir, dead_dirs, list) {
		struct kasumi_dh_dir *prior;
		struct super_block *sb;
		bool seen = false;

		if (!dir->dir_inode)
			continue;
		sb = dir->dir_inode->i_sb;
		list_for_each_entry(prior, dead_dirs, list) {
			if (prior == dir)
				break;
			if (prior->dir_inode && prior->dir_inode->i_sb == sb) {
				seen = true;
				break;
			}
		}
		if (!seen)
			shrink_dcache_sb(sb);
	}
}

void kasumi_dirhijack_clear(void)
{
	struct kasumi_dh_dir *dir, *dtmp;
	struct kasumi_dh_dop_meta *dm;
	struct hlist_node *htmp;
	LIST_HEAD(dead_dirs);
	LIST_HEAD(retired_dops);
	int bkt;

	mutex_lock(&kasumi_dh_lock);

	/* Phase 1: stop late installs, restore the dir i_op vector and withdraw the
	 * shared f_op iterate client so no NEW lookup/iterate callback acquires dir
	 * metadata.  The s_op client is released only after these callbacks drain. */
	list_for_each_entry_safe(dir, dtmp, &kasumi_dh_dirs, list) {
		struct inode *inode = dir->dir_inode;

		WRITE_ONCE(dir->retiring, true);
		kasumi_dh_unindex_dir(dir);
		if (inode && dir->iop_meta)
			smp_store_release(&inode->i_op, dir->iop_meta->orig_iop);
		if (inode && dir->iterate_bound) {
			kasumi_fop_unbind_iterate_client(inode, dir);
			dir->iterate_bound = false;
		}
		list_move(&dir->list, &dead_dirs);
	}
	/* Restore each real filesystem d_op and its exact operation flags while the
	 * dget-held dentry is still alive, then unhash it. */
	hash_for_each_safe(kasumi_dh_dops, bkt, htmp, dm, node)
		kasumi_dh_retire_dop_locked(dm, &retired_dops);
	mutex_unlock(&kasumi_dh_lock);

	/* Phase 2: first close the d_op-load-to-callback-entry window, then drain
	 * every lookup/iterate/revalidate that entered before the restores above.
	 * Retain every dentry/meta dget through both windows so an old callback
	 * cannot race d_release or metadata free. */
	if (!list_empty(&dead_dirs) || !list_empty(&retired_dops))
		kasumi_synchronize_rcu_tasks();
	synchronize_srcu(&kasumi_dh_srcu);
	kasumi_fop_synchronize_iterate_clients();
	if (!list_empty(&dead_dirs) || !list_empty(&retired_dops))
		kasumi_synchronize_rcu_tasks();
	if (!list_empty(&retired_dops))
		synchronize_rcu();
	kasumi_dh_free_retired_dops(&retired_dops);
	/* No shadow callback can enqueue retirement after the drains above.  Wait
	 * for a worker that won ownership of an auto-retired meta before freeing
	 * its directory or allowing module text to go away.
	 */
	flush_work(&kasumi_dh_reap_dops_work);

	/* Drop other cached aliases/negatives after explicit d_op restoration.  Do
	 * this once per affected superblock; shrink alone is not the safety proof. */
	kasumi_dh_shrink_dead_sbs(&dead_dirs);

	/* Phase 3: no callback can reference the metas now — free them. */
	list_for_each_entry_safe(dir, dtmp, &dead_dirs, list) {
		struct kasumi_dh_child *c;
		struct hlist_node *ctmp;
		struct inode *inode = dir->dir_inode;
		struct super_block *sb = inode ? inode->i_sb : NULL;

		hlist_for_each_entry_safe(c, ctmp, &dir->children, node) {
			kasumi_dh_child_unlink(c);
			kasumi_dh_child_free(c);
		}
		list_del(&dir->list);
		if (dir->iterate_owned) {
			kasumi_fop_put(inode, false);
			dir->iterate_owned = false;
		}
		/* dh_clients owns the s_active pin that makes this final parent
		 * iput safe; publish that the dir no longer owns the inode before
		 * allowing the shared s_op meta to reap.
		 */
		dput(dir->name_parent);
		dir->name_parent = NULL;
		dir->dir_inode = NULL;
		if (inode)
			iput(inode);
		if (dir->sop_client && sb) {
			kasumi_sop_shadow_unregister_dh(sb);
			dir->sop_client = false;
		}
		kfree(dir->iop_meta);
		kfree(dir);
	}
	kasumi_sop_shadow_reap();

	/* Cover every per-child RCU bridge, then drain the sleepable path_put work
	 * before PREPARE/exit can release the module lifecycle pin.
	 */
	rcu_barrier();
	flush_work(&kasumi_dh_free_children_work);
}

int kasumi_dirhijack_init(void)
{
	unsigned long addr = kasumi_lookup_name("fuse_dentry_revalidate");
	int ret = -EOPNOTSUPP;

	hash_init(kasumi_dh_dops);
	kasumi_dh_simple_lookup_raw = kasumi_lookup_name("simple_lookup");
	kasumi_dh_simple_lookup_callable =
		kasumi_lookup_callable_quiet("simple_lookup");
#ifdef CONFIG_ARM64
	kasumi_dh_add_probe.addr =
	    (kprobe_opcode_t *)kasumi_lookup_name("d_add");
	kasumi_dh_add_probe.pre_handler = kasumi_dh_add_pre;
	if (kasumi_dh_add_probe.addr)
		ret = register_kprobe(&kasumi_dh_add_probe);
#endif
	if (ret) {
		pr_warn("kasumi: native dentry publication guard unavailable: %d\n", ret);
		return ret;
	}
	WRITE_ONCE(kasumi_dh_add_registered, true);

	kasumi_dh_native_add = (void *)kasumi_lookup_callable_quiet("__d_add");
	if (!kasumi_dh_native_add) {
		kasumi_dh_native_rehash =
		    (void *)kasumi_lookup_callable_quiet("__d_rehash");
		kasumi_dh_native_lookup_unhash =
		    (void *)kasumi_lookup_callable_quiet("__d_lookup_unhash");
		if (!kasumi_dh_native_rehash ||
		    !kasumi_dh_native_lookup_unhash) {
			ret = -EOPNOTSUPP;
			goto fail_add;
		}
		kasumi_dh_native_add = kasumi_dh_add_directory;
	}
	kasumi_dh_native_move = (void *)kasumi_lookup_name("__d_move");
	kasumi_dh_native_instantiate = (void *)kasumi_lookup_name("security_d_instantiate");
	kasumi_dh_native_ancestor = (void *)kasumi_lookup_callable_quiet("d_ancestor");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0) && IS_ENABLED(CONFIG_FS_ENCRYPTION)
	kasumi_dh_fscrypt_revalidate = kasumi_lookup_callable_quiet("fscrypt_d_revalidate");
#endif
	kasumi_dh_rename_lock = (void *)kasumi_lookup_name("rename_lock");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	kasumi_dh_splice_probe.addr = (kprobe_opcode_t *)kasumi_lookup_name("d_splice_alias_ops");
#else
	kasumi_dh_splice_probe.addr = (kprobe_opcode_t *)kasumi_lookup_name("d_splice_alias");
#endif
	kasumi_dh_splice_probe.pre_handler = kasumi_dh_splice_pre;
	ret = -EOPNOTSUPP;
	if (!kasumi_dh_native_move || !kasumi_dh_native_instantiate || !kasumi_dh_native_ancestor ||
	    !kasumi_dh_rename_lock || !kasumi_dh_splice_probe.addr ||
	    (!kasumi_dh_simple_lookup_raw && !kasumi_dh_simple_lookup_callable))
		goto fail_add;
	ret = register_kprobe(&kasumi_dh_splice_probe);
	if (ret)
		goto fail_add;
	WRITE_ONCE(kasumi_dh_splice_registered, true);
	ret = -EOPNOTSUPP;
#ifdef CONFIG_ARM64
	if (addr) {
		kasumi_dh_fuse_probe.addr = (kprobe_opcode_t *)addr;
		kasumi_dh_fuse_probe.pre_handler = kasumi_dh_fuse_revalidate_pre;
		ret = register_kprobe(&kasumi_dh_fuse_probe);
	}
#endif
	WRITE_ONCE(kasumi_dh_fuse_registered, !ret);
	if (ret)
		pr_warn("kasumi: FUSE hide cache guard unavailable: %d\n", ret);

	WRITE_ONCE(kasumi_dh_ready, true);
	pr_info("Kasumi: dirhijack initialized (param=%d FUSE cache guard=%d)\n",
		READ_ONCE(kasumi_dirhijack_param), kasumi_dh_fuse_registered);
	return 0;
fail_add:
	unregister_kprobe(&kasumi_dh_add_probe);
	WRITE_ONCE(kasumi_dh_add_registered, false);
	pr_warn("kasumi: native alias publication guard unavailable: %d\n", ret);
	return ret;
}

void kasumi_dirhijack_stop_new(void)
{
	WRITE_ONCE(kasumi_dh_ready, false);
	if (kasumi_dh_fuse_registered) {
		unregister_kprobe(&kasumi_dh_fuse_probe);
		WRITE_ONCE(kasumi_dh_fuse_registered, false);
	}
}

void kasumi_dirhijack_exit(void)
{
	kasumi_dirhijack_stop_new();
	kasumi_dirhijack_clear();
	if (kasumi_dh_splice_registered) {
		unregister_kprobe(&kasumi_dh_splice_probe);
		WRITE_ONCE(kasumi_dh_splice_registered, false);
	}
	if (kasumi_dh_add_registered) {
		unregister_kprobe(&kasumi_dh_add_probe);
		WRITE_ONCE(kasumi_dh_add_registered, false);
	}
	pr_info("kasumi: dirhijack exited\n");
}
