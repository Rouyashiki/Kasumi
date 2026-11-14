// SPDX-License-Identifier: GPL-2.0-only
/*
 * Native query helpers adapted from Linux fs/namespace.c, Android common
 * android16-6.12 and android17-6.18 (DDK 20260828).
 * (C) Copyright Al Viro 2000, 2001
 * Based on fs/super.c, copyright Linus Torvalds and others.
 */
#include <linux/version.h>
#include "kasumi_mount_query.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <linux/capability.h>
#include <linux/file.h>
#include <linux/fs_struct.h>
#include <linux/kprobes.h>
#include <linux/mnt_namespace.h>
#include <linux/nsproxy.h>
#include <linux/overflow.h>
#include <linux/proc_ns.h>
#include <linux/rcupdate.h>
#include <linux/sched/signal.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string_helpers.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <uapi/linux/mount.h>
#include <fs/pnode.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
#include <linux/nstree.h>
#endif

#include "kasumi_mount_view.h"
#include "kasumi_runtime.h"

#define KASUMI_QUERY_CAPABILITIES (KASUMI_MOUNT_CAP_STATMOUNT | KASUMI_MOUNT_CAP_LISTMOUNT)
#define KASUMI_UNIQUE_ID_OFFSET (1ULL << 31)
#define KASUMI_STATMOUNT_STRINGS (STATMOUNT_MNT_ROOT | STATMOUNT_MNT_POINT | \
	STATMOUNT_FS_TYPE | STATMOUNT_MNT_OPTS)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
#define KASUMI_STATMOUNT_EXTRA_STRINGS (STATMOUNT_FS_SUBTYPE | STATMOUNT_SB_SOURCE | \
	STATMOUNT_OPT_ARRAY | STATMOUNT_OPT_SEC_ARRAY | STATMOUNT_MNT_UIDMAP | STATMOUNT_MNT_GIDMAP)
#else
#define KASUMI_STATMOUNT_EXTRA_STRINGS 0
#endif

static struct rw_semaphore *kasumi_query_namespace_lock;
static int (*kasumi_query_show_path)(struct seq_file *, struct dentry *);
static int (*kasumi_query_dominating_id)(struct mount *, const struct path *);
static int (*kasumi_query_seq_path_root)(struct seq_file *, const struct path *,
				       const struct path *, const char *);
static int (*kasumi_query_show_options)(struct seq_file *, struct super_block *);
static int (*kasumi_query_security_statfs)(struct dentry *);
static bool (*kasumi_query_proc_ns_file)(const struct file *);
static bool (*kasumi_query_reachable)(struct mount *, struct dentry *, const struct path *);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
static typeof(ns_tree_lookup_rcu) *kasumi_query_ns_lookup;
static void (*kasumi_query_ns_release_rcu)(struct rcu_head *);
static int (*kasumi_query_mnt_idmap)(struct mnt_idmap *, struct seq_file *, bool);
#else
static rwlock_t *kasumi_query_ns_tree_lock;
static struct rb_root *kasumi_query_ns_tree;
static void (*kasumi_query_ns_release)(struct mnt_namespace *);
#endif
static long (*kasumi_query_statmount_original)(const struct pt_regs *);
static long (*kasumi_query_listmount_original)(const struct pt_regs *);
static void (*kasumi_query_tasks_barrier)(void);
static struct kprobe kasumi_query_statmount_probe;
static struct kprobe kasumi_query_listmount_probe;
static bool kasumi_query_statmount_registered;
static bool kasumi_query_listmount_registered;
static bool kasumi_query_stopping = true;
static atomic_t kasumi_query_active = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(kasumi_query_wait);

struct kstatmount {
	struct statmount __user *buf;
	size_t bufsize;
	struct vfsmount *mnt;
	struct mnt_idmap *idmap;
	u64 mask;
	struct path root;
	struct seq_file seq;

	/* Must be last --ends in a flexible-array member. */
	struct statmount sm;
};

static u64 mnt_to_attr_flags(struct vfsmount *mnt)
{
	unsigned int mnt_flags = READ_ONCE(mnt->mnt_flags);
	u64 attr_flags = 0;

	if (mnt_flags & MNT_READONLY)
		attr_flags |= MOUNT_ATTR_RDONLY;
	if (mnt_flags & MNT_NOSUID)
		attr_flags |= MOUNT_ATTR_NOSUID;
	if (mnt_flags & MNT_NODEV)
		attr_flags |= MOUNT_ATTR_NODEV;
	if (mnt_flags & MNT_NOEXEC)
		attr_flags |= MOUNT_ATTR_NOEXEC;
	if (mnt_flags & MNT_NODIRATIME)
		attr_flags |= MOUNT_ATTR_NODIRATIME;
	if (mnt_flags & MNT_NOSYMFOLLOW)
		attr_flags |= MOUNT_ATTR_NOSYMFOLLOW;

	if (mnt_flags & MNT_NOATIME)
		attr_flags |= MOUNT_ATTR_NOATIME;
	else if (mnt_flags & MNT_RELATIME)
		attr_flags |= MOUNT_ATTR_RELATIME;
	else
		attr_flags |= MOUNT_ATTR_STRICTATIME;

	if (is_idmapped_mnt(mnt))
		attr_flags |= MOUNT_ATTR_IDMAP;

	return attr_flags;
}

static u64 mnt_to_propagation_flags(struct mount *m)
{
	u64 propagation = 0;

	if (IS_MNT_SHARED(m))
		propagation |= MS_SHARED;
	if (IS_MNT_SLAVE(m))
		propagation |= MS_SLAVE;
	if (IS_MNT_UNBINDABLE(m))
		propagation |= MS_UNBINDABLE;
	if (!propagation)
		propagation |= MS_PRIVATE;

	return propagation;
}

static void statmount_sb_basic(struct kstatmount *s)
{
	struct super_block *sb = s->mnt->mnt_sb;

	s->sm.mask |= STATMOUNT_SB_BASIC;
	s->sm.sb_dev_major = MAJOR(sb->s_dev);
	s->sm.sb_dev_minor = MINOR(sb->s_dev);
	s->sm.sb_magic = sb->s_magic;
	s->sm.sb_flags = sb->s_flags & (SB_RDONLY|SB_SYNCHRONOUS|SB_DIRSYNC|SB_LAZYTIME);
}

static void statmount_mnt_basic(struct kstatmount *s)
{
	struct mount *m = real_mount(s->mnt);

	s->sm.mask |= STATMOUNT_MNT_BASIC;
	s->sm.mnt_id = m->mnt_id_unique;
	s->sm.mnt_parent_id = m->mnt_parent->mnt_id_unique;
	s->sm.mnt_id_old = m->mnt_id;
	s->sm.mnt_parent_id_old = m->mnt_parent->mnt_id;
	s->sm.mnt_attr = mnt_to_attr_flags(&m->mnt);
	s->sm.mnt_propagation = mnt_to_propagation_flags(m);
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	s->sm.mnt_peer_group = m->mnt_group_id;
#else
	s->sm.mnt_peer_group = IS_MNT_SHARED(m) ? m->mnt_group_id : 0;
#endif
	s->sm.mnt_master = IS_MNT_SLAVE(m) ? m->mnt_master->mnt_group_id : 0;
}

static void KASUMI_NOCFI statmount_propagate_from(struct kstatmount *s)
{
	struct mount *m = real_mount(s->mnt);

	s->sm.mask |= STATMOUNT_PROPAGATE_FROM;
	if (IS_MNT_SLAVE(m))
		s->sm.propagate_from = kasumi_query_dominating_id(m, &current->fs->root);
}

static int KASUMI_NOCFI statmount_mnt_root(struct kstatmount *s, struct seq_file *seq)
{
	int ret;
	size_t start = seq->count;

	ret = kasumi_query_show_path(seq, s->mnt->mnt_root);
	if (ret)
		return ret;

	if (unlikely(seq_has_overflowed(seq)))
		return -EAGAIN;

	/*
         * Unescape the result. It would be better if supplied string was not
         * escaped in the first place, but that's a pretty invasive change.
         */
	seq->buf[seq->count] = '\0';
	seq->count = start;
	seq_commit(seq, string_unescape_inplace(seq->buf + start, UNESCAPE_OCTAL));
	return 0;
}

static int KASUMI_NOCFI statmount_mnt_point(struct kstatmount *s, struct seq_file *seq)
{
	struct vfsmount *mnt = s->mnt;
	struct path mnt_path = { .dentry = mnt->mnt_root, .mnt = mnt };
	int err;

	err = kasumi_query_seq_path_root(seq, &mnt_path, &s->root, "");
	return err == SEQ_SKIP ? 0 : err;
}

static int KASUMI_NOCFI statmount_fs_type(struct kstatmount *s, struct seq_file *seq)
{
	struct super_block *sb = s->mnt->mnt_sb;

	seq_puts(seq, sb->s_type->name);
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
static void statmount_fs_subtype(struct kstatmount *s, struct seq_file *seq)
{
	struct super_block *sb = s->mnt->mnt_sb;

	if (sb->s_subtype)
		seq_puts(seq, sb->s_subtype);
}

static int KASUMI_NOCFI statmount_sb_source(struct kstatmount *s, struct seq_file *seq)
{
	struct super_block *sb = s->mnt->mnt_sb;
	struct mount *r = real_mount(s->mnt);

	if (sb->s_op->show_devname) {
		size_t start = seq->count;
		int ret;

		ret = sb->s_op->show_devname(seq, s->mnt->mnt_root);
		if (ret)
			return ret;

		if (unlikely(seq_has_overflowed(seq)))
			return -EAGAIN;

		/* Unescape the result */
		seq->buf[seq->count] = '\0';
		seq->count = start;
		seq_commit(seq, string_unescape_inplace(seq->buf + start, UNESCAPE_OCTAL));
	} else {
		seq_puts(seq, r->mnt_devname);
	}
	return 0;
}

#endif

static void statmount_mnt_ns_id(struct kstatmount *s, struct mnt_namespace *ns)
{
	s->sm.mask |= STATMOUNT_MNT_NS_ID;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	s->sm.mnt_ns_id = ns->ns.ns_id;
#else
	s->sm.mnt_ns_id = ns->seq;
#endif
}

static int KASUMI_NOCFI statmount_mnt_opts(struct kstatmount *s, struct seq_file *seq)
{
	struct vfsmount *mnt = s->mnt;
	struct super_block *sb = mnt->mnt_sb;
	size_t start = seq->count;
	int err;

	err = kasumi_query_show_options(seq, sb);
	if (err)
		return err;

	if (sb->s_op->show_options) {
		err = sb->s_op->show_options(seq, mnt->mnt_root);
		if (err)
			return err;
	}

	if (unlikely(seq_has_overflowed(seq)))
		return -EAGAIN;

	if (seq->count == start)
		return 0;

	/* skip leading comma */
	memmove(seq->buf + start, seq->buf + start + 1,
		seq->count - start - 1);
	seq->count--;

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
static inline int statmount_opt_process(struct seq_file *seq, size_t start)
{
	char *buf_end, *opt_end, *src, *dst;
	int count = 0;

	if (unlikely(seq_has_overflowed(seq)))
		return -EAGAIN;

	buf_end = seq->buf + seq->count;
	dst = seq->buf + start;
	src = dst + 1;	/* skip initial comma */

	if (src >= buf_end) {
		seq->count = start;
		return 0;
	}

	*buf_end = '\0';
	for (; src < buf_end; src = opt_end + 1) {
		opt_end = strchrnul(src, ',');
		*opt_end = '\0';
		dst += string_unescape(src, dst, 0, UNESCAPE_OCTAL) + 1;
		if (WARN_ON_ONCE(++count == INT_MAX))
			return -EOVERFLOW;
	}
	seq->count = dst - 1 - seq->buf;
	return count;
}

static int KASUMI_NOCFI statmount_opt_array(struct kstatmount *s, struct seq_file *seq)
{
	struct vfsmount *mnt = s->mnt;
	struct super_block *sb = mnt->mnt_sb;
	size_t start = seq->count;
	int err;

	if (!sb->s_op->show_options)
		return 0;

	err = sb->s_op->show_options(seq, mnt->mnt_root);
	if (err)
		return err;

	err = statmount_opt_process(seq, start);
	if (err < 0)
		return err;

	s->sm.opt_num = err;
	return 0;
}

static int KASUMI_NOCFI statmount_opt_sec_array(struct kstatmount *s, struct seq_file *seq)
{
	struct vfsmount *mnt = s->mnt;
	struct super_block *sb = mnt->mnt_sb;
	size_t start = seq->count;
	int err;

	err = kasumi_query_show_options(seq, sb);
	if (err)
		return err;

	err = statmount_opt_process(seq, start);
	if (err < 0)
		return err;

	s->sm.opt_sec_num = err;
	return 0;
}

static inline int KASUMI_NOCFI statmount_mnt_uidmap(struct kstatmount *s, struct seq_file *seq)
{
	int ret;

	ret = kasumi_query_mnt_idmap(s->idmap, seq, true);
	if (ret < 0)
		return ret;

	s->sm.mnt_uidmap_num = ret;
	/*
	 * Always raise STATMOUNT_MNT_UIDMAP even if there are no valid
	 * mappings. This allows userspace to distinguish between a
	 * non-idmapped mount and an idmapped mount where none of the
	 * individual mappings are valid in the caller's idmapping.
	 */
	if (is_valid_mnt_idmap(s->idmap))
		s->sm.mask |= STATMOUNT_MNT_UIDMAP;
	return 0;
}

static inline int KASUMI_NOCFI statmount_mnt_gidmap(struct kstatmount *s, struct seq_file *seq)
{
	int ret;

	ret = kasumi_query_mnt_idmap(s->idmap, seq, false);
	if (ret < 0)
		return ret;

	s->sm.mnt_gidmap_num = ret;
	/*
	 * Always raise STATMOUNT_MNT_GIDMAP even if there are no valid
	 * mappings. This allows userspace to distinguish between a
	 * non-idmapped mount and an idmapped mount where none of the
	 * individual mappings are valid in the caller's idmapping.
	 */
	if (is_valid_mnt_idmap(s->idmap))
		s->sm.mask |= STATMOUNT_MNT_GIDMAP;
	return 0;
}

#endif

static int KASUMI_NOCFI statmount_string(struct kstatmount *s, u64 flag)
{
	int ret = 0;
	size_t kbufsize;
	struct seq_file *seq = &s->seq;
	struct statmount *sm = &s->sm;
	u32 start, *offp;

	/* Reserve an empty string at the beginning for any unset offsets */
	if (!seq->count)
		seq_putc(seq, 0);

	start = seq->count;

	switch (flag) {
	case STATMOUNT_FS_TYPE:
		offp = &sm->fs_type;
		ret = statmount_fs_type(s, seq);
		break;
	case STATMOUNT_MNT_ROOT:
		offp = &sm->mnt_root;
		ret = statmount_mnt_root(s, seq);
		break;
	case STATMOUNT_MNT_POINT:
		offp = &sm->mnt_point;
		ret = statmount_mnt_point(s, seq);
		break;
	case STATMOUNT_MNT_OPTS:
		offp = &sm->mnt_opts;
		ret = statmount_mnt_opts(s, seq);
		break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	case STATMOUNT_OPT_ARRAY:
		offp = &sm->opt_array;
		ret = statmount_opt_array(s, seq);
		break;
	case STATMOUNT_OPT_SEC_ARRAY:
		offp = &sm->opt_sec_array;
		ret = statmount_opt_sec_array(s, seq);
		break;
	case STATMOUNT_FS_SUBTYPE:
		offp = &sm->fs_subtype;
		statmount_fs_subtype(s, seq);
		break;
	case STATMOUNT_SB_SOURCE:
		offp = &sm->sb_source;
		ret = statmount_sb_source(s, seq);
		break;
	case STATMOUNT_MNT_UIDMAP:
		offp = &sm->mnt_uidmap;
		ret = statmount_mnt_uidmap(s, seq);
		break;
	case STATMOUNT_MNT_GIDMAP:
		offp = &sm->mnt_gidmap;
		ret = statmount_mnt_gidmap(s, seq);
		break;
#endif
	default:
		WARN_ON_ONCE(true);
		return -EINVAL;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	/*
	 * If nothing was emitted, return to avoid setting the flag
	 * and terminating the buffer.
	 */
	if (seq->count == start)
		return ret;
#endif
	if (unlikely(check_add_overflow(sizeof(*sm), seq->count, &kbufsize)))
		return -EOVERFLOW;
	if (kbufsize >= s->bufsize)
		return -EOVERFLOW;

	/* signal a retry */
	if (unlikely(seq_has_overflowed(seq)))
		return -EAGAIN;

	if (ret)
		return ret;

	seq->buf[seq->count++] = '\0';
	sm->mask |= flag;
	*offp = start;
	return 0;
}

static int copy_statmount_to_user(struct kstatmount *s)
{
	struct statmount *sm = &s->sm;
	struct seq_file *seq = &s->seq;
	char __user *str = ((char __user *)s->buf) + sizeof(*sm);
	size_t copysize = min_t(size_t, s->bufsize, sizeof(*sm));

	if (seq->count && copy_to_user(str, seq->buf, seq->count))
		return -EFAULT;

	/* Return the number of bytes copied to the buffer */
	sm->size = copysize + seq->count;
	if (copy_to_user(s->buf, sm, copysize))
		return -EFAULT;

	return 0;
}

static int kasumi_query_copy_request(const struct mnt_id_req __user *request,
				    struct mnt_id_req *result)
{
	u32 size;
	int ret;

	BUILD_BUG_ON(sizeof(*result) != MNT_ID_REQ_SIZE_VER1);
	if (get_user(size, &request->size))
		return -EFAULT;
	if (size > PAGE_SIZE)
		return -E2BIG;
	if (size < MNT_ID_REQ_SIZE_VER0)
		return -EINVAL;
	memset(result, 0, sizeof(*result));
	ret = copy_struct_from_user(result, sizeof(*result), request, size);
	if (ret)
		return ret;
	if (result->mnt_ns_fd && result->mnt_ns_id)
		return -EINVAL;
	if (result->mnt_id <= KASUMI_UNIQUE_ID_OFFSET)
		return -EINVAL;
	return 0;
}

static KASUMI_NOCFI struct mnt_namespace *kasumi_query_lookup_ns(u64 id)
{
	struct mnt_namespace *ns = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	struct ns_common *common;

	rcu_read_lock();
	common = kasumi_query_ns_lookup(id, CLONE_NEWNS);
	if (common) {
		ns = container_of(common, struct mnt_namespace, ns);
		refcount_inc(&ns->passive);
	}
	rcu_read_unlock();
#else
	struct rb_node *node;

	read_lock(kasumi_query_ns_tree_lock);
	node = kasumi_query_ns_tree->rb_node;
	while (node) {
		struct mnt_namespace *candidate =
			container_of(node, struct mnt_namespace, mnt_ns_tree_node);

		if (id == candidate->seq) {
			ns = candidate;
			refcount_inc(&ns->passive);
			break;
		}
		node = id < candidate->seq ? node->rb_left : node->rb_right;
	}
	read_unlock(kasumi_query_ns_tree_lock);
#endif
	return ns;
}

static KASUMI_NOCFI struct mnt_namespace *
kasumi_query_get_ns(const struct mnt_id_req *request)
{
	struct mnt_namespace *ns;

	if (request->mnt_ns_id) {
		ns = kasumi_query_lookup_ns(request->mnt_ns_id);
		return ns ? ns : ERR_PTR(-ENOENT);
	}
	if (request->mnt_ns_fd) {
		struct file *file = fget(request->mnt_ns_fd);
		struct ns_common *common;
		bool mount_namespace;

		if (!file)
			return ERR_PTR(-EBADF);
		if (!kasumi_query_proc_ns_file(file)) {
			fput(file);
			return ERR_PTR(-EINVAL);
		}
		common = get_proc_ns(file_inode(file));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
		mount_namespace = common->ns_type == CLONE_NEWNS;
#else
		mount_namespace = common->ops->type == CLONE_NEWNS;
#endif
		if (!mount_namespace) {
			fput(file);
			return ERR_PTR(-EINVAL);
		}
		ns = container_of(common, struct mnt_namespace, ns);
		refcount_inc(&ns->passive);
		fput(file);
		return ns;
	}
	ns = current->nsproxy->mnt_ns;
	refcount_inc(&ns->passive);
	return ns;
}

static KASUMI_NOCFI void kasumi_query_put_ns(struct mnt_namespace *ns)
{
	if (!ns)
		return;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	/* The native callback performs the passive put without queueing this head. */
	kasumi_query_ns_release_rcu(&ns->ns.ns_rcu);
#else
	kasumi_query_ns_release(ns);
#endif
}

static struct mount *kasumi_query_mount_node(struct rb_node *node)
{
	return node ? rb_entry(node, struct mount, mnt_node) : NULL;
}

static int kasumi_query_root(struct mnt_namespace *ns, struct path *root)
{
	struct mount *first, *child;

	if (ns == current->nsproxy->mnt_ns) {
		get_fs_root(current->fs, root);
		return 0;
	}
	if (RB_EMPTY_ROOT(&ns->mounts))
		return -ENOENT;
	first = child = ns->root;
	for (;;) {
		child = kasumi_query_mount_node(rb_next(&child->mnt_node));
		if (!child)
			return -ENOENT;
		if (child->mnt_parent == first)
			break;
	}
	root->mnt = mntget(&child->mnt);
	root->dentry = dget(root->mnt->mnt_root);
	return 0;
}

/* Return with namespace_sem held after matching the immutable view to topology. */
static int kasumi_query_view_lock(struct mnt_namespace *ns, struct path *root,
				 struct kasumi_mount_view **view, unsigned int *attempt)
{
	int ret;

	for (;;) {
		if (fatal_signal_pending(current)) {
			ret = -EINTR;
			break;
		}
		if (*view) {
			down_read(kasumi_query_namespace_lock);
			if (kasumi_mount_view_current(*view))
				return 0;
			up_read(kasumi_query_namespace_lock);
			kasumi_mount_view_put(*view);
			*view = NULL;
			path_put(root);
			memset(root, 0, sizeof(*root));
		}
		if (*attempt >= KASUMI_MOUNT_VIEW_ATTEMPTS) {
			ret = -EAGAIN;
			break;
		}
		(*attempt)++;
		down_read(kasumi_query_namespace_lock);
		ret = kasumi_query_root(ns, root);
		up_read(kasumi_query_namespace_lock);
		if (ret)
			break;
		ret = kasumi_mount_view_get(ns, root, view);
		if (!ret)
			continue;
		path_put(root);
		memset(root, 0, sizeof(*root));
		if (ret != -EAGAIN)
			break;
		cond_resched();
	}
	kasumi_mount_view_put(*view);
	*view = NULL;
	path_put(root);
	memset(root, 0, sizeof(*root));
	return ret;
}

static bool kasumi_query_hidden(const struct kasumi_mount_record *record)
{
	return kasumi_mount_projection_active() && record && record->in_view && !record->retained;
}

static void kasumi_query_parent(struct statmount *result,
				const struct kasumi_mount_view *view,
				const struct kasumi_mount_record *record)
{
	const struct kasumi_mount_record *parent;

	if (!kasumi_mount_projection_active())
		return;
	parent = kasumi_mount_view_find(view, record->parent_unique_id, true);
	if (!parent || !parent->in_view)
		return;
	parent = kasumi_mount_view_representative(view, parent);
	if (parent) {
		result->mnt_parent_id = parent->unique_id;
		result->mnt_parent_id_old = parent->id;
	}
}

static KASUMI_NOCFI int kasumi_query_statmount_fill(struct kstatmount *state,
						 const struct mnt_id_req *request,
						 struct mnt_namespace *ns,
						 const struct kasumi_mount_view *view)
{
	const struct kasumi_mount_record *record;
	const u64 strings[] = {
		STATMOUNT_FS_TYPE, STATMOUNT_MNT_ROOT, STATMOUNT_MNT_POINT, STATMOUNT_MNT_OPTS,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
		STATMOUNT_OPT_ARRAY, STATMOUNT_OPT_SEC_ARRAY, STATMOUNT_FS_SUBTYPE,
		STATMOUNT_SB_SOURCE, STATMOUNT_MNT_UIDMAP, STATMOUNT_MNT_GIDMAP,
#endif
	};
	u32 i;
	int ret;

	if (request->mnt_ns_id && RB_EMPTY_ROOT(&ns->mounts))
		return -ENOENT;
	record = kasumi_mount_view_find(view, request->mnt_id, true);
	if (!record || kasumi_query_hidden(record))
		return -ENOENT;
	state->mnt = record->mount;
	if (!kasumi_query_reachable(real_mount(state->mnt), state->mnt->mnt_root,
				    &state->root) &&
	    !ns_capable_noaudit(ns->user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	ret = kasumi_query_security_statfs(state->mnt->mnt_root);
	if (ret)
		return ret;
	state->idmap = mnt_idmap(state->mnt);
	if (state->mask & STATMOUNT_SB_BASIC)
		statmount_sb_basic(state);
	if (state->mask & STATMOUNT_MNT_BASIC) {
		statmount_mnt_basic(state);
		kasumi_query_parent(&state->sm, view, record);
	}
	if (state->mask & STATMOUNT_PROPAGATE_FROM)
		statmount_propagate_from(state);
	for (i = 0; i < ARRAY_SIZE(strings); i++) {
		if (!(state->mask & strings[i]))
			continue;
		ret = statmount_string(state, strings[i]);
		if (ret)
			return ret;
	}
	if (state->mask & STATMOUNT_MNT_NS_ID)
		statmount_mnt_ns_id(state, ns);
	if (kasumi_mount_groups_active()) {
		if (state->sm.mask & STATMOUNT_MNT_BASIC) {
			state->sm.mnt_peer_group =
				kasumi_mount_view_group_id(view, state->sm.mnt_peer_group);
			state->sm.mnt_master =
				kasumi_mount_view_group_id(view, state->sm.mnt_master);
		}
		if (state->sm.mask & STATMOUNT_PROPAGATE_FROM)
			state->sm.propagate_from =
				kasumi_mount_view_group_id(view, state->sm.propagate_from);
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	if (state->mask & STATMOUNT_SUPPORTED_MASK) {
		state->sm.mask |= STATMOUNT_SUPPORTED_MASK;
		state->sm.supported_mask = STATMOUNT_SB_BASIC | STATMOUNT_MNT_BASIC |
			STATMOUNT_PROPAGATE_FROM | KASUMI_STATMOUNT_STRINGS |
			KASUMI_STATMOUNT_EXTRA_STRINGS | STATMOUNT_MNT_NS_ID |
			STATMOUNT_SUPPORTED_MASK;
	}
#endif
	return 0;
}

static long kasumi_query_native(const struct pt_regs *regs, bool list)
{
	struct kasumi_internal_vfs_guard guard;
	long ret;

	kasumi_vfs_internal_enter(&guard);
	ret = list ? kasumi_query_listmount_original(regs) :
		     kasumi_query_statmount_original(regs);
	kasumi_vfs_internal_leave(&guard);
	return ret;
}

static long kasumi_query_statmount(const struct pt_regs *regs)
{
	const struct mnt_id_req __user *user_request = (void __user *)regs->regs[0];
	struct statmount __user *buffer = (void __user *)regs->regs[1];
	size_t buffer_size = regs->regs[2], seq_size = 3 * PATH_MAX;
	unsigned int flags = regs->regs[3];
	struct kasumi_mount_view *view = NULL;
	struct mnt_namespace *ns;
	struct mnt_id_req request;
	struct kstatmount *state;
	struct path root = {};
	unsigned int attempt = 0;
	bool grow;
	int ret;

	if (flags)
		return -EINVAL;
	ret = kasumi_query_copy_request(user_request, &request);
	if (ret)
		return ret;
	ns = kasumi_query_get_ns(&request);
	if (IS_ERR(ns))
		return PTR_ERR(ns);
	if (request.mnt_ns_id && ns != current->nsproxy->mnt_ns &&
	    !ns_capable_noaudit(ns->user_ns, CAP_SYS_ADMIN)) {
		ret = -EPERM;
		goto put_ns;
	}
	if (ns != current->nsproxy->mnt_ns) {
		ret = kasumi_query_native(regs, false);
		goto put_ns;
	}
	state = kmalloc(sizeof(*state), GFP_KERNEL_ACCOUNT);
	if (!state) {
		ret = -ENOMEM;
		goto put_ns;
	}
	for (;;) {
		memset(state, 0, sizeof(*state));
		state->mask = request.param;
		state->buf = buffer;
		state->bufsize = buffer_size;
		if (!access_ok(buffer, buffer_size)) {
			ret = -EFAULT;
			break;
		}
		if (request.param & (KASUMI_STATMOUNT_STRINGS | KASUMI_STATMOUNT_EXTRA_STRINGS)) {
			if (buffer_size == sizeof(state->sm)) {
				ret = -EOVERFLOW;
				break;
			}
			state->seq.buf = kvmalloc(seq_size, GFP_KERNEL_ACCOUNT);
			if (!state->seq.buf) {
				ret = -ENOMEM;
				break;
			}
			state->seq.size = seq_size;
		}
		ret = kasumi_query_view_lock(ns, &root, &view, &attempt);
		if (!ret) {
			state->root = root;
			ret = kasumi_query_statmount_fill(state, &request, ns, view);
			up_read(kasumi_query_namespace_lock);
		}
		if (!ret)
			ret = copy_statmount_to_user(state);
		grow = ret == -EAGAIN && state->seq.buf && seq_has_overflowed(&state->seq);
		kvfree(state->seq.buf);
		if (!grow || check_mul_overflow(seq_size, 2, &seq_size) ||
		    seq_size > MAX_RW_COUNT)
			break;
	}
	kasumi_mount_view_put(view);
	path_put(&root);
	kfree(state);
put_ns:
	kasumi_query_put_ns(ns);
	return ret;
}

static struct mount *kasumi_query_first(struct mnt_namespace *ns, u64 last, bool reverse)
{
	struct rb_node *node = ns->mounts.rb_node;
	struct mount *result = NULL;
	u64 boundary;

	if (!last)
		return kasumi_query_mount_node(reverse ? rb_last(&ns->mounts) : rb_first(&ns->mounts));
	boundary = reverse ? last - 1 : last + 1;
	while (node) {
		struct mount *candidate = kasumi_query_mount_node(node);
		bool select = reverse ? candidate->mnt_id_unique <= boundary :
					candidate->mnt_id_unique >= boundary;

		if (select) {
			result = candidate;
			node = reverse ? node->rb_right : node->rb_left;
		} else {
			node = reverse ? node->rb_left : node->rb_right;
		}
	}
	return result;
}

static KASUMI_NOCFI long kasumi_query_listmount_fill(struct mnt_namespace *ns,
						   const struct path *root,
						   const struct kasumi_mount_view *view,
						   const struct mnt_id_req *request,
						   u64 *ids, size_t capacity, bool reverse)
{
	const struct kasumi_mount_record *record;
	struct path origin;
	struct mount *mount;
	long count = 0;
	int ret;

	if (request->mnt_id == LSMT_ROOT) {
		origin = *root;
	} else {
		record = kasumi_mount_view_find(view, request->mnt_id, true);
		if (!record || kasumi_query_hidden(record))
			return -ENOENT;
		origin.mnt = record->mount;
		origin.dentry = origin.mnt->mnt_root;
	}
	if (!kasumi_query_reachable(real_mount(origin.mnt), origin.dentry, root) &&
	    !ns_capable_noaudit(ns->user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	ret = kasumi_query_security_statfs(origin.dentry);
	if (ret)
		return ret;
	for (mount = kasumi_query_first(ns, request->param, reverse); mount && count < capacity;
	     mount = kasumi_query_mount_node(reverse ? rb_prev(&mount->mnt_node) :
						     rb_next(&mount->mnt_node))) {
		if (mount->mnt_id_unique == request->mnt_id)
			continue;
		record = kasumi_mount_view_find(view, mount->mnt_id_unique, true);
		if (kasumi_query_hidden(record))
			continue;
		if (!kasumi_query_reachable(mount, mount->mnt.mnt_root, &origin))
			continue;
		ids[count++] = mount->mnt_id_unique;
	}
	return count;
}

static long kasumi_query_listmount(const struct pt_regs *regs)
{
	const struct mnt_id_req __user *user_request = (void __user *)regs->regs[0];
	u64 __user *user_ids = (void __user *)regs->regs[1];
	size_t capacity = regs->regs[2];
	unsigned int flags = regs->regs[3];
	struct kasumi_mount_view *view = NULL;
	struct mnt_namespace *ns = NULL;
	struct mnt_id_req request;
	struct path root = {};
	u64 *ids;
	unsigned int attempt = 0;
	long ret;

	if (flags & ~LISTMOUNT_REVERSE)
		return -EINVAL;
	if (capacity > 1000000)
		return -EOVERFLOW;
	if (!access_ok(user_ids, capacity * sizeof(*user_ids)))
		return -EFAULT;
	ret = kasumi_query_copy_request(user_request, &request);
	if (ret)
		return ret;
	if (request.param && request.param <= KASUMI_UNIQUE_ID_OFFSET)
		return -EINVAL;
	ids = kvmalloc_array(capacity, sizeof(*ids), GFP_KERNEL_ACCOUNT);
	if (!ids)
		return -ENOMEM;
	ns = kasumi_query_get_ns(&request);
	if (IS_ERR(ns)) {
		ret = PTR_ERR(ns);
		ns = NULL;
		goto out;
	}
	if (request.mnt_ns_id && ns != current->nsproxy->mnt_ns &&
	    !ns_capable_noaudit(ns->user_ns, CAP_SYS_ADMIN)) {
		ret = -ENOENT;
		goto out;
	}
	if (ns != current->nsproxy->mnt_ns) {
		ret = kasumi_query_native(regs, true);
		goto out;
	}
	ret = kasumi_query_view_lock(ns, &root, &view, &attempt);
	if (!ret) {
		ret = kasumi_query_listmount_fill(ns, &root, view, &request, ids, capacity,
						flags & LISTMOUNT_REVERSE);
		up_read(kasumi_query_namespace_lock);
	}
	if (ret > 0 && copy_to_user(user_ids, ids, ret * sizeof(*ids)))
		ret = -EFAULT;
out:
	kasumi_mount_view_put(view);
	path_put(&root);
	kasumi_query_put_ns(ns);
	kvfree(ids);
	return ret;
}

static KASUMI_NOCFI long kasumi_query_dispatch(const struct pt_regs *regs, bool list)
{
	long ret;

	if (READ_ONCE(kasumi_query_stopping) ||
	    (!kasumi_mount_projection_active() && (list || !kasumi_mount_groups_active()))) {
		ret = kasumi_query_native(regs, list);
	} else {
		ret = list ? kasumi_query_listmount(regs) : kasumi_query_statmount(regs);
	}
	if (atomic_dec_and_test(&kasumi_query_active))
		wake_up_all(&kasumi_query_wait);
	return ret;
}

static long kasumi_query_statmount_entry(const struct pt_regs *regs)
{
	return kasumi_query_dispatch(regs, false);
}

static long kasumi_query_listmount_entry(const struct pt_regs *regs)
{
	return kasumi_query_dispatch(regs, true);
}

static int kasumi_query_pre(struct kprobe *probe, struct pt_regs *regs)
{
#ifdef CONFIG_ARM64
	unsigned long target;

	if (READ_ONCE(kasumi_query_stopping) || kasumi_vfs_internal_current())
		return 0;
	target = probe == &kasumi_query_listmount_probe ?
		(unsigned long)kasumi_query_listmount_entry :
		(unsigned long)kasumi_query_statmount_entry;
	atomic_inc(&kasumi_query_active);
	instruction_pointer_set(regs, target);
	return 1;
#else
	return 0;
#endif
}

KASUMI_NOCFI void kasumi_mount_query_stop(void)
{
	kasumi_mount_view_publish_capabilities(0, KASUMI_QUERY_CAPABILITIES);
	WRITE_ONCE(kasumi_query_stopping, true);
	if (kasumi_query_listmount_registered) {
		unregister_kprobe(&kasumi_query_listmount_probe);
		kasumi_query_listmount_registered = false;
	}
	if (kasumi_query_statmount_registered) {
		unregister_kprobe(&kasumi_query_statmount_probe);
		kasumi_query_statmount_registered = false;
	}
	wait_event(kasumi_query_wait, !atomic_read(&kasumi_query_active));
	if (kasumi_query_tasks_barrier)
		kasumi_query_tasks_barrier();
}

int kasumi_mount_query_init(void)
{
	int ret;

	if (!READ_ONCE(kasumi_query_stopping))
		return 0;
#ifndef CONFIG_ARM64
	return -EOPNOTSUPP;
#endif
	kasumi_query_namespace_lock = (void *)kasumi_lookup_name_quiet("namespace_sem");
	kasumi_query_show_path = (void *)kasumi_lookup_callable_quiet("show_path");
	kasumi_query_dominating_id = (void *)kasumi_lookup_callable_quiet("get_dominating_id");
	kasumi_query_seq_path_root = (void *)kasumi_lookup_callable_quiet("seq_path_root");
	kasumi_query_show_options = (void *)kasumi_lookup_callable_quiet("security_sb_show_options");
	kasumi_query_security_statfs = (void *)kasumi_lookup_callable_quiet("security_sb_statfs");
	kasumi_query_proc_ns_file = (void *)kasumi_lookup_callable_quiet("proc_ns_file");
	kasumi_query_reachable = (void *)kasumi_lookup_callable_quiet("is_path_reachable");
	kasumi_query_statmount_original = (void *)kasumi_lookup_callable_quiet("__arm64_sys_statmount");
	kasumi_query_listmount_original = (void *)kasumi_lookup_callable_quiet("__arm64_sys_listmount");
	kasumi_query_tasks_barrier = (void *)kasumi_lookup_callable_quiet("synchronize_rcu_tasks");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	kasumi_query_ns_lookup = (void *)kasumi_lookup_callable_quiet("ns_tree_lookup_rcu");
	kasumi_query_ns_release_rcu = (void *)kasumi_lookup_callable_quiet("mnt_ns_release_rcu");
	kasumi_query_mnt_idmap = (void *)kasumi_lookup_callable_quiet("statmount_mnt_idmap");
	if (!kasumi_query_ns_lookup || !kasumi_query_ns_release_rcu || !kasumi_query_mnt_idmap)
		return -EOPNOTSUPP;
#else
	kasumi_query_ns_tree_lock = (void *)kasumi_lookup_name_quiet("mnt_ns_tree_lock");
	kasumi_query_ns_tree = (void *)kasumi_lookup_name_quiet("mnt_ns_tree");
	kasumi_query_ns_release = (void *)kasumi_lookup_callable_quiet("mnt_ns_release");
	if (!kasumi_query_ns_tree_lock || !kasumi_query_ns_tree || !kasumi_query_ns_release)
		return -EOPNOTSUPP;
#endif
	if (!kasumi_query_namespace_lock || !kasumi_query_show_path ||
	    !kasumi_query_dominating_id || !kasumi_query_seq_path_root ||
	    !kasumi_query_show_options || !kasumi_query_security_statfs ||
	    !kasumi_query_proc_ns_file || !kasumi_query_reachable ||
	    !kasumi_query_statmount_original || !kasumi_query_listmount_original ||
	    !kasumi_query_tasks_barrier)
		return -EOPNOTSUPP;
	kasumi_query_statmount_probe.addr =
		(void *)kasumi_lookup_name_quiet("__arm64_sys_statmount");
	kasumi_query_statmount_probe.pre_handler = kasumi_query_pre;
	ret = register_kprobe(&kasumi_query_statmount_probe);
	if (ret)
		return ret;
	kasumi_query_statmount_registered = true;
	kasumi_query_listmount_probe.addr =
		(void *)kasumi_lookup_name_quiet("__arm64_sys_listmount");
	kasumi_query_listmount_probe.pre_handler = kasumi_query_pre;
	ret = register_kprobe(&kasumi_query_listmount_probe);
	if (ret) {
		kasumi_mount_query_stop();
		return ret;
	}
	kasumi_query_listmount_registered = true;
	WRITE_ONCE(kasumi_query_stopping, false);
	kasumi_mount_view_publish_capabilities(KASUMI_QUERY_CAPABILITIES, 0);
	return 0;
}

#else
int kasumi_mount_query_init(void)
{
	return 0;
}

void kasumi_mount_query_stop(void)
{
}
#endif

void kasumi_mount_query_exit(void)
{
	kasumi_mount_query_stop();
}
