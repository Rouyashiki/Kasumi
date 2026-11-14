#include <linux/cred.h>
#include <linux/exportfs.h>
#include <linux/fanotify.h>
#include <linux/fsnotify_backend.h>
#include <linux/hashtable.h>
#include <linux/kprobes.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/statfs.h>
#include <linux/version.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include "kasumi_notify_fanotify.h"
#include "kasumi_notify_rules.h"
#include "kasumi_notify_view.h"
#include "kasumi_path_policy.h"
#include "kasumi_runtime.h"
#include "kasumi_vnode.h"

#if defined(CONFIG_FANOTIFY) && defined(CONFIG_ARM64)

#define KASUMI_FAN_TOPOLOGY (FS_CREATE | FS_DELETE | FS_MOVED_FROM | FS_MOVED_TO | \
	FS_DELETE_SELF | FS_MOVE_SELF | FS_UNMOUNT | FS_EVENT_ON_CHILD | FS_ISDIR)
#define KASUMI_FAN_ANCHOR UINT_MAX
#ifdef FAN_MARK_IGNORE
#define KASUMI_FAN_IGNORE_BITS (FAN_MARK_IGNORED_MASK | FAN_MARK_IGNORE)
#else
#define KASUMI_FAN_IGNORE_BITS FAN_MARK_IGNORED_MASK
#endif
#ifdef FSNOTIFY_MARK_FLAG_HAS_IGNORE_FLAGS
#define kasumi_fan_native_ignore(mark) ((mark)->ignore_mask)
#else
#define kasumi_fan_native_ignore(mark) ((mark)->ignored_mask)
#endif

struct kasumi_fan_state {
	u32 mask;
	u32 ignore;
	bool survive;
	bool modern_ignore;
};

struct kasumi_fan_owner;
struct kasumi_fan_subscription;
struct kasumi_fan_record;

/* Matches native fan_fsid on object-based KMI; older KMI passes only id. */
struct kasumi_fan_fsid {
	struct super_block *sb;
	__kernel_fsid_t id;
	bool weak;
};

struct kasumi_fan_claim {
	struct list_head link;
	struct kasumi_fan_owner *owner;
	struct kasumi_fan_subscription *subscription;
	struct kasumi_fan_record *record;
	struct path path;
	struct inode *inode;
	struct kasumi_fan_fsid fsid;
	bool has_fsid;
	unsigned int index;
};

struct kasumi_fan_subscription {
	struct kasumi_notify_snapshot *snapshot;
	struct kasumi_fan_state state;
	unsigned int count;
	struct kasumi_fan_claim claims[];
};

/* One real native mark, with independently removable logical contributions.
 * The native mark owns the queue, quotas, permission objects and group lifetime.
 * record->mark holds the native reference until all claims have been removed.
 */
struct kasumi_fan_record {
	struct hlist_node node;
	struct hlist_node mark_node;
	struct list_head claims;
	struct fsnotify_group *group;
	struct inode *inode;
	struct fsnotify_mark *mark;
	struct kasumi_fan_state direct;
	bool dead;
};

struct kasumi_fan_owner {
	struct list_head link;
	struct fsnotify_group *group;
	struct path visible;
	const struct cred *cred;
	struct kasumi_notify_scope scope;
	struct kasumi_fan_subscription *subscription;
	u64 serial;
	bool dead;
	bool dirty;
};

struct kasumi_fanotify_pending {
	struct hlist_node node;
	struct task_struct *task;
	struct fsnotify_group *group;
	struct path visible;
	struct kasumi_notify_scope scope;
	struct kasumi_fan_subscription *subscription;
	struct kasumi_fan_state state;
	const struct cred *cred;
	u64 serial;
	u32 requested;
	unsigned int flags;
	bool existing;
	bool selected;
};

struct kasumi_fan_call {
	struct hlist_node node;
	struct task_struct *task;
};

/* Mutations serialize before native group->mark_mutex. Event/freeing probes
 * take only data_lock; snapshot/path release always happens after it is dropped.
 */
static DEFINE_MUTEX(kasumi_fan_mutex);
static DEFINE_RWLOCK(kasumi_fan_data_lock);
static DEFINE_HASHTABLE(kasumi_fan_records, 8);
static DEFINE_HASHTABLE(kasumi_fan_marks, 8);
static LIST_HEAD(kasumi_fan_owners);
static DEFINE_HASHTABLE(kasumi_fan_pending, 6);
static DEFINE_HASHTABLE(kasumi_fan_calls, 6);
static spinlock_t kasumi_fan_task_locks[64];
static atomic_t kasumi_fan_active = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(kasumi_fan_wait);
static struct workqueue_struct *kasumi_fan_queue;
static KASUMI_NOCFI void kasumi_fan_work(struct work_struct *work);
static DECLARE_WORK(kasumi_fan_refresh, kasumi_fan_work);
static bool kasumi_fan_ready;
static bool kasumi_fan_stopping = true;
static struct kprobe kasumi_fan_add_probe;
static struct kprobe kasumi_fan_remove_probe;
static struct kprobe kasumi_fan_event_probe;
static struct kprobe kasumi_fan_freeing_probe;
static unsigned int kasumi_fan_probes;
static typeof(fsnotify_find_mark) *kasumi_fan_find_mark;
static typeof(fsnotify_recalc_mask) *kasumi_fan_recalc_mask;
static typeof(fsnotify_get_group) *kasumi_fan_get_group;
static typeof(vfs_get_fsid) *kasumi_fan_get_fsid;
static int (*kasumi_fan_insert_event)(struct fsnotify_group *, struct fsnotify_event *,
	int (*)(struct fsnotify_group *, struct fsnotify_event *),
	void (*)(struct fsnotify_group *, struct fsnotify_event *));
static int (*kasumi_fan_add_event)(struct fsnotify_group *, struct fsnotify_event *,
	int (*)(struct fsnotify_group *, struct fsnotify_event *));
static void (*kasumi_fan_tasks_barrier)(void);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
static int (*kasumi_fan_native_add)(struct fsnotify_group *, void *, unsigned int,
	u32, unsigned int, struct kasumi_fan_fsid *);
static int (*kasumi_fan_native_remove)(struct fsnotify_group *, void *, unsigned int,
	u32, unsigned int, u32);
#else
static int (*kasumi_fan_native_add)(struct fsnotify_group *, fsnotify_connp_t *,
	unsigned int, u32, unsigned int, __kernel_fsid_t *);
static int (*kasumi_fan_native_remove)(struct fsnotify_group *, fsnotify_connp_t *,
	u32, unsigned int, u32);
#endif

static void *kasumi_fan_object(struct inode *inode)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	return inode;
#else
	return &inode->i_fsnotify_marks;
#endif
}

static struct kasumi_fan_record *kasumi_fan_find(struct fsnotify_group *group,
	void *object)
{
	struct kasumi_fan_record *record;

	hash_for_each_possible(kasumi_fan_records, record, node, (unsigned long)object) {
		if (record->group == group && kasumi_fan_object(record->inode) == object &&
		    !record->dead)
			return record;
	}
	return NULL;
}

static struct kasumi_fan_owner *kasumi_fan_owner_find(struct fsnotify_group *group,
	struct inode *inode)
{
	struct kasumi_fan_owner *owner;

	list_for_each_entry(owner, &kasumi_fan_owners, link) {
		if (owner->group == group && d_inode(owner->visible.dentry) == inode &&
		    !owner->dead)
			return owner;
	}
	return NULL;
}

static void kasumi_fan_call_enter(struct kasumi_fan_call *call)
{
	unsigned long flags;
	spinlock_t *lock = &kasumi_fan_task_locks[hash_min((unsigned long)current, 6)];

	call->task = current;
	spin_lock_irqsave(lock, flags);
	hash_add(kasumi_fan_calls, &call->node, (unsigned long)current);
	spin_unlock_irqrestore(lock, flags);
}

static void kasumi_fan_call_leave(struct kasumi_fan_call *call)
{
	unsigned long flags;
	spinlock_t *lock = &kasumi_fan_task_locks[hash_min((unsigned long)call->task, 6)];

	spin_lock_irqsave(lock, flags);
	hash_del(&call->node);
	spin_unlock_irqrestore(lock, flags);
}

bool kasumi_notify_fanotify_internal(void)
{
	struct kasumi_fan_call *call;
	unsigned long flags;
	bool found = false;
	spinlock_t *lock = &kasumi_fan_task_locks[hash_min((unsigned long)current, 6)];

	spin_lock_irqsave(lock, flags);
	hash_for_each_possible(kasumi_fan_calls, call, node, (unsigned long)current) {
		if (call->task == current) {
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(lock, flags);
	return found;
}

static struct kasumi_fanotify_pending *kasumi_fan_current(void)
{
	struct kasumi_fanotify_pending *pending, *found = NULL;
	unsigned long flags;
	spinlock_t *lock = &kasumi_fan_task_locks[hash_min((unsigned long)current, 6)];

	spin_lock_irqsave(lock, flags);
	hash_for_each_possible(kasumi_fan_pending, pending, node, (unsigned long)current) {
		if (pending->task == current) {
			found = pending;
			break;
		}
	}
	spin_unlock_irqrestore(lock, flags);
	return found;
}

static struct kasumi_fan_state kasumi_fan_capture(struct fsnotify_mark *mark)
{
	struct kasumi_fan_state state = {};

	state.mask = mark->mask;
	state.ignore = kasumi_fan_native_ignore(mark);
	state.survive = mark->flags & FSNOTIFY_MARK_FLAG_IGNORED_SURV_MODIFY;
#ifdef FSNOTIFY_MARK_FLAG_HAS_IGNORE_FLAGS
	state.modern_ignore = mark->flags & FSNOTIFY_MARK_FLAG_HAS_IGNORE_FLAGS;
#endif
	return state;
}

static int kasumi_fan_state_update(struct kasumi_fan_state *state, u32 mask,
	unsigned int flags, u32 umask)
{
	bool ignore = flags & KASUMI_FAN_IGNORE_BITS;

	if (flags & FAN_MARK_REMOVE) {
		if (!(state->mask | state->ignore))
			return -ENOENT;
		if (ignore)
			state->ignore &= ~(mask & ~umask);
		else
			state->mask &= ~(mask & ~umask);
		return 0;
	}
#ifdef FAN_MARK_IGNORE
	if ((flags & FAN_MARK_IGNORED_MASK) && state->modern_ignore)
		return -EEXIST;
	if ((flags & FAN_MARK_IGNORE) && state->survive &&
	    !(flags & FAN_MARK_IGNORED_SURV_MODIFY))
		return -EEXIST;
	if (flags & FAN_MARK_IGNORE)
		state->modern_ignore = true;
#endif
	if (ignore) {
		state->ignore |= mask;
		if (flags & FAN_MARK_IGNORED_SURV_MODIFY)
			state->survive = true;
	} else {
		state->mask |= mask;
	}
	return 0;
}

static u32 kasumi_fan_interest(const struct kasumi_fan_state *state)
{
	u32 mask = state->mask | state->ignore;

	if (state->ignore && !state->survive)
		mask |= FS_MODIFY;
	return mask;
}

/* Called with mutation mutex; native group lock precedes mark lock. The
 * raw interest is a superset; the probe applies the logical per-watch masks.
 */
static KASUMI_NOCFI void kasumi_fan_apply(struct kasumi_fan_record *record)
{
	struct kasumi_fan_claim *claim;
	struct fsnotify_mark *mark = record->mark;
	u32 mask;
	unsigned long flags;

	mutex_lock(&record->group->mark_mutex);
	read_lock_irqsave(&kasumi_fan_data_lock, flags);
	mask = kasumi_fan_interest(&record->direct);
	list_for_each_entry(claim, &record->claims, link) {
		if (claim->index == KASUMI_FAN_ANCHOR)
			mask |= kasumi_fan_interest(&claim->subscription->state);
		else {
			const struct kasumi_notify_source *source = kasumi_notify_snapshot_source(
				claim->subscription->snapshot, claim->index);
			mask |= source->kind == KASUMI_NOTIFY_SOURCE_TOPOLOGY ?
				KASUMI_FAN_TOPOLOGY : kasumi_fan_interest(&claim->subscription->state);
		}
	}
	read_unlock_irqrestore(&kasumi_fan_data_lock, flags);
	spin_lock(&mark->lock);
	if (!record->dead && mark->connector) {
		mark->mask = mask ? mask | FS_ISDIR | FS_EVENT_ON_CHILD : 0;
		kasumi_fan_native_ignore(mark) = 0;
		kasumi_fan_recalc_mask(mark->connector);
	}
	spin_unlock(&mark->lock);
	mutex_unlock(&record->group->mark_mutex);
}

static KASUMI_NOCFI struct fsnotify_mark *kasumi_fan_lookup(struct inode *inode,
	struct fsnotify_group *group)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	return kasumi_fan_find_mark(inode, FSNOTIFY_OBJ_TYPE_INODE, group);
#else
	return kasumi_fan_find_mark(&inode->i_fsnotify_marks, group);
#endif
}

/* Add with an empty mask first. The record becomes visible before its raw
 * interest, so unpublished staged sources cannot leak a native event.
 */
static KASUMI_NOCFI struct kasumi_fan_record *kasumi_fan_acquire(
	struct fsnotify_group *group, struct inode *inode,
	struct kasumi_fan_fsid *fsid)
{
	struct kasumi_fan_record *record;
	struct fsnotify_mark *mark;
	unsigned long flags;
	int error;

	record = kasumi_fan_find(group, kasumi_fan_object(inode));
	if (record)
		return record;
	record = kzalloc(sizeof(*record), GFP_KERNEL);
	if (!record)
		return ERR_PTR(-ENOMEM);
	INIT_LIST_HEAD(&record->claims);
	record->group = group;
	record->inode = inode;
	mutex_lock(&group->mark_mutex);
	mark = kasumi_fan_lookup(inode, group);
	if (mark) {
		spin_lock(&mark->lock);
		record->direct = kasumi_fan_capture(mark);
		spin_unlock(&mark->lock);
	}
	mutex_unlock(&group->mark_mutex);
	if (!mark) {
		error = kasumi_fan_native_add(group, kasumi_fan_object(inode),
			FSNOTIFY_OBJ_TYPE_INODE, 0, FAN_MARK_ADD,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
			fsid);
#else
			fsid ? &fsid->id : NULL);
#endif
		if (error) {
			kfree(record);
			return ERR_PTR(error);
		}
		mark = kasumi_fan_lookup(inode, group);
		if (!mark) {
			kfree(record);
			return ERR_PTR(-EAGAIN);
		}
	}
	record->mark = mark;
	write_lock_irqsave(&kasumi_fan_data_lock, flags);
	hash_add(kasumi_fan_records, &record->node, (unsigned long)kasumi_fan_object(inode));
	hash_add(kasumi_fan_marks, &record->mark_node, (unsigned long)mark);
	write_unlock_irqrestore(&kasumi_fan_data_lock, flags);
	return record;
}

/* Restore the direct native contribution before removing the filter record.
 * If none remains, native destroy releases quota and preserves queued waits.
 */
static KASUMI_NOCFI void kasumi_fan_record_release(struct kasumi_fan_record *record)
{
	struct fsnotify_mark *mark = record->mark;
	unsigned long flags;
	bool destroy = false;

	if (!list_empty(&record->claims)) {
		kasumi_fan_apply(record);
		return;
	}
	mutex_lock(&record->group->mark_mutex);
	spin_lock(&mark->lock);
	write_lock_irqsave(&kasumi_fan_data_lock, flags);
	if (!record->dead && mark->connector) {
		mark->mask = record->direct.mask;
		kasumi_fan_native_ignore(mark) = record->direct.ignore;
		mark->flags &= ~FSNOTIFY_MARK_FLAG_IGNORED_SURV_MODIFY;
		if (record->direct.survive)
			mark->flags |= FSNOTIFY_MARK_FLAG_IGNORED_SURV_MODIFY;
#ifdef FSNOTIFY_MARK_FLAG_HAS_IGNORE_FLAGS
		mark->flags &= ~FSNOTIFY_MARK_FLAG_HAS_IGNORE_FLAGS;
		if (record->direct.modern_ignore)
			mark->flags |= FSNOTIFY_MARK_FLAG_HAS_IGNORE_FLAGS;
#endif
		kasumi_fan_recalc_mask(mark->connector);
		destroy = !(record->direct.mask | record->direct.ignore);
	}
	spin_unlock(&mark->lock);
	hash_del(&record->node);
	hash_del(&record->mark_node);
	write_unlock_irqrestore(&kasumi_fan_data_lock, flags);
	mutex_unlock(&record->group->mark_mutex);
	if (destroy)
		fsnotify_destroy_mark(mark, record->group);
	fsnotify_put_mark(mark);
	kfree(record);
}

static void kasumi_fan_subscription_free(struct kasumi_fan_subscription *subscription)
{
	unsigned int index;
	unsigned long flags;

	if (!subscription)
		return;
	for (index = 0; index < subscription->count; index++) {
		struct kasumi_fan_claim *claim = &subscription->claims[index];

		if (claim->record) {
			write_lock_irqsave(&kasumi_fan_data_lock, flags);
			list_del(&claim->link);
			write_unlock_irqrestore(&kasumi_fan_data_lock, flags);
			kasumi_fan_record_release(claim->record);
		}
		if (claim->path.dentry)
			path_put(&claim->path);
	}
	if (subscription->snapshot)
		kasumi_notify_snapshot_put(subscription->snapshot);
	kfree(subscription);
}

static bool kasumi_fan_fid_group(struct fsnotify_group *group);

/* Mirror the supported KMI's native inode-mark fsid/exportfs checks. Never
 * present a synthetic vnode to a real filesystem's statfs/export operations.
 * The actual event handle remains allocated and encoded by native fanotify.
 */
static KASUMI_NOCFI int kasumi_fan_validate_fid(struct dentry *dentry,
	struct kasumi_fan_fsid *fsid)
{
	const struct export_operations *operations;
	__kernel_fsid_t root;
	int error;

	if (!dentry || !d_inode(dentry) || kasumi_vnode_is_ours(d_inode(dentry)) ||
	    !kasumi_fan_get_fsid)
		return -EOPNOTSUPP;
	error = kasumi_fan_get_fsid(dentry, &fsid->id);
	if (error)
		return error;
	fsid->sb = dentry->d_sb;
	fsid->weak = false;
	if (!fsid->id.val[0] && !fsid->id.val[1]) {
#ifdef FSNOTIFY_MARK_FLAG_WEAK_FSID
		fsid->weak = true;
#else
		return -ENODEV;
#endif
	} else {
		error = kasumi_fan_get_fsid(dentry->d_sb->s_root, &root);
		if (error)
			return error;
		if (root.val[0] != fsid->id.val[0] || root.val[1] != fsid->id.val[1]) {
#ifdef FSNOTIFY_MARK_FLAG_WEAK_FSID
			fsid->weak = true;
#else
			return -EXDEV;
#endif
		}
	}
	operations = dentry->d_sb->s_export_op;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	return exportfs_can_encode_fid(operations) ? 0 : -EOPNOTSUPP;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	return operations ? 0 : -EOPNOTSUPP;
#else
	return operations && operations->fh_to_dentry ? 0 : -EOPNOTSUPP;
#endif
}

static struct kasumi_fan_subscription *kasumi_fan_subscription_build(
	struct fsnotify_group *group,
	const struct path *visible, const struct kasumi_notify_scope *scope,
	const struct kasumi_fan_subscription *previous, const struct kasumi_fan_state *state)
{
	struct kasumi_notify_snapshot *snapshot;
	struct kasumi_fan_subscription *subscription;
	unsigned int index, count;
	bool fid = kasumi_fan_fid_group(group);
	int error;

	error = kasumi_notify_snapshot_build(visible, ALL_FSNOTIFY_EVENTS, scope,
		kasumi_rules_generation(), previous ? previous->snapshot : NULL, &snapshot);
	if (error)
		return ERR_PTR(error);
	count = kasumi_notify_snapshot_source_count(snapshot);
	subscription = kzalloc(struct_size(subscription, claims, count + 1), GFP_KERNEL);
	if (!subscription) {
		kasumi_notify_snapshot_put(snapshot);
		return ERR_PTR(-ENOMEM);
	}
	subscription->snapshot = snapshot;
	subscription->state = *state;
	for (index = 0; index < count; index++) {
		const struct kasumi_notify_source *source = kasumi_notify_snapshot_source(snapshot, index);
		struct kasumi_fan_claim *claim = &subscription->claims[index];

		claim->subscription = subscription;
		claim->index = index;
		subscription->count++;
		if (source->kind == KASUMI_NOTIFY_SOURCE_TOPOLOGY) {
			claim->inode = d_inode(source->topology);
		} else {
			claim->path = source->path;
			path_get(&claim->path);
			error = kasumi_notify_resolve_source(&claim->path,
				(state->mask | state->ignore) & ALL_FSNOTIFY_EVENTS);
			if (error)
				goto fail;
			claim->inode = d_inode(claim->path.dentry);
		}
		if (!claim->inode) {
			error = -ENOENT;
			goto fail;
		}
		if (fid) {
			error = kasumi_fan_validate_fid(source->kind == KASUMI_NOTIFY_SOURCE_TOPOLOGY ?
				source->topology : claim->path.dentry, &claim->fsid);
			if (error)
				goto fail;
			claim->has_fsid = true;
		}
	}
	subscription->claims[count].subscription = subscription;
	subscription->claims[count].inode = d_inode(visible->dentry);
	subscription->claims[count].index = KASUMI_FAN_ANCHOR;
	subscription->count++;
	if (fid) {
		error = kasumi_fan_validate_fid(visible->dentry, &subscription->claims[count].fsid);
		if (error)
			goto fail;
		subscription->claims[count].has_fsid = true;
	}
	return subscription;
fail:
	kasumi_fan_subscription_free(subscription);
	return ERR_PTR(error);
}

static int kasumi_fan_subscription_attach(struct kasumi_fan_owner *owner,
	struct kasumi_fan_subscription *subscription)
{
	unsigned int index;
	unsigned long flags;

	for (index = 0; index < subscription->count; index++) {
		struct kasumi_fan_claim *claim = &subscription->claims[index];
		struct kasumi_fan_record *record = kasumi_fan_acquire(owner->group, claim->inode,
			claim->has_fsid ? &claim->fsid : NULL);

		if (IS_ERR(record))
			return PTR_ERR(record);
		claim->record = record;
		claim->owner = owner;
		write_lock_irqsave(&kasumi_fan_data_lock, flags);
		list_add_tail(&claim->link, &record->claims);
		write_unlock_irqrestore(&kasumi_fan_data_lock, flags);
		kasumi_fan_apply(record);
	}
	return 0;
}

static bool kasumi_fan_fid_group(struct fsnotify_group *group)
{
	u32 bits = FAN_REPORT_FID;

#ifdef FAN_REPORT_DIR_FID
	bits |= FAN_REPORT_DIR_FID;
#endif
#ifdef FAN_REPORT_NAME
	bits |= FAN_REPORT_NAME;
#endif
	return group->fanotify_data.flags & bits;
}

static int kasumi_fan_fid_scope(struct fsnotify_group *group, struct inode *visible,
	u32 effective_mask)
{
	u32 flags = group->fanotify_data.flags;

	if (!kasumi_fan_fid_group(group))
		return 0;
	if (!(flags & FAN_REPORT_FID) || kasumi_vnode_is_ours(visible) ||
	    !kasumi_fan_get_fsid)
		return -EOPNOTSUPP;
#ifdef FAN_REPORT_DIR_FID
	if (flags & FAN_REPORT_DIR_FID)
		return -EOPNOTSUPP;
#endif
#ifdef FAN_REPORT_NAME
	if (flags & FAN_REPORT_NAME)
		return -EOPNOTSUPP;
#endif
	/* A MERGE dirent becomes visible only on live-generation publication.
	 * Relaying the source dirent immediately gives the wrong parent/time;
	 * synthesizing it on a worker loses the native producer pid.
	 */
	return effective_mask & ALL_FSNOTIFY_DIRENT_EVENTS ? -EOPNOTSUPP : 0;
}

KASUMI_NOCFI int kasumi_notify_fanotify_prepare(const struct path *visible, u64 mask,
	unsigned int type, unsigned int operation, struct fsnotify_group *group,
	struct kasumi_fanotify_pending **result)
{
	struct kasumi_fanotify_pending *pending;
	struct kasumi_fan_subscription *previous = NULL;
	struct kasumi_fan_owner *owner;
	struct kasumi_fan_call call;
	struct fsnotify_mark *mark;
	unsigned long flags;
	char *buffer, *name;
	bool overridden;
	int error = 0;

	*result = NULL;
	if (!READ_ONCE(kasumi_fan_ready) || READ_ONCE(kasumi_fan_stopping) || !group ||
	    type != FSNOTIFY_OBJ_TYPE_INODE || !S_ISDIR(d_inode(visible->dentry)->i_mode))
		return 0;
	buffer = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;
	if (kasumi_vnode_is_ours(d_inode(visible->dentry))) {
		struct kasumi_vnode_info *info = d_inode(visible->dentry)->i_private;

		name = info && info->visible_path ? info->visible_path : ERR_PTR(-EIO);
	} else {
		name = kasumi_d_absolute_path(visible, buffer, PATH_MAX);
	}
	if (IS_ERR(name)) {
		error = PTR_ERR(name);
		kfree(buffer);
		return error;
	}
	overridden = kasumi_rule_directory_overridden(name, kasumi_rules_generation());
	kfree(buffer);
	pending = kzalloc(sizeof(*pending), GFP_KERNEL);
	if (!pending)
		return -ENOMEM;
	pending->group = group; /* The admitting syscall pins its fanotify file. */
	pending->visible = *visible;
	path_get(&pending->visible);
	pending->flags = operation;
	pending->requested = (u32)mask;
	pending->cred = get_current_cred();
	kasumi_fan_call_enter(&call);
	mutex_lock(&kasumi_fan_mutex);
	owner = kasumi_fan_owner_find(group, d_inode(visible->dentry));
	if (!owner && !overridden) {
		error = 0;
		goto unlock;
	}
	/* A native watch established before composition remains removable by
	 * its native inode even if no projected owner was ever created.
	 */
	if (!owner && (operation & FAN_MARK_REMOVE) &&
	    !kasumi_vnode_is_ours(d_inode(visible->dentry))) {
		error = 0;
		goto unlock;
	}
#ifdef FAN_MARK_EVICTABLE
	if ((operation & FAN_MARK_ADD) && (operation & FAN_MARK_EVICTABLE)) {
		/* Owner and immutable snapshot hold visible/source paths, topology
		 * dentries and base-child inode references. NO_IREF on the native
		 * mark cannot make these objects evictable. Supporting this flag
		 * requires a weak-reference snapshot and refresh lifetime protocol.
		 */
		error = -EOPNOTSUPP;
		goto unlock;
	}
#endif
	if (owner) {
		pending->existing = true;
		pending->serial = owner->serial;
		pending->scope = owner->scope;
		previous = owner->subscription;
		read_lock_irqsave(&kasumi_fan_data_lock, flags);
		pending->state = previous->state;
		read_unlock_irqrestore(&kasumi_fan_data_lock, flags);
	} else {
		kasumi_notify_scope_capture(&pending->scope);
		mutex_lock(&group->mark_mutex);
		mark = kasumi_fan_lookup(d_inode(visible->dentry), group);
		if (mark) {
			struct kasumi_fan_record *record = kasumi_fan_find(group,
				kasumi_fan_object(d_inode(visible->dentry)));

			if (record && record->mark == mark) {
				read_lock_irqsave(&kasumi_fan_data_lock, flags);
				pending->state = record->direct;
				read_unlock_irqrestore(&kasumi_fan_data_lock, flags);
			} else {
				spin_lock(&mark->lock);
				pending->state = kasumi_fan_capture(mark);
				spin_unlock(&mark->lock);
			}
			fsnotify_put_mark(mark);
		}
		mutex_unlock(&group->mark_mutex);
	}
	error = kasumi_fan_state_update(&pending->state, (u32)mask, operation, 0);
	if (error)
		goto unlock;
	error = kasumi_fan_fid_scope(group, d_inode(visible->dentry), pending->state.mask);
	if (error)
		goto unlock;
	if (!(operation & FAN_MARK_REMOVE)) {
		pending->subscription = kasumi_fan_subscription_build(group, visible, &pending->scope,
			previous, &pending->state);
		if (IS_ERR(pending->subscription)) {
			error = PTR_ERR(pending->subscription);
			pending->subscription = NULL;
			goto unlock;
		}
	}
	pending->task = current;
	spin_lock_irqsave(&kasumi_fan_task_locks[hash_min((unsigned long)current, 6)], flags);
	hash_add(kasumi_fan_pending, &pending->node, (unsigned long)current);
	spin_unlock_irqrestore(&kasumi_fan_task_locks[hash_min((unsigned long)current, 6)], flags);
	*result = pending;
	error = 1;
unlock:
	mutex_unlock(&kasumi_fan_mutex);
	kasumi_fan_call_leave(&call);
	if (error <= 0)
		kasumi_notify_fanotify_complete(pending, error);
	return error;
}

void kasumi_notify_fanotify_complete(struct kasumi_fanotify_pending *pending, long result)
{
	unsigned long flags;

	if (!pending)
		return;
	if (pending->task) {
		spinlock_t *lock = &kasumi_fan_task_locks[hash_min((unsigned long)pending->task, 6)];

		spin_lock_irqsave(lock, flags);
		hash_del(&pending->node);
		spin_unlock_irqrestore(lock, flags);
	}
	/* Native add/remove is the last fallible syscall step. The wrapper owns
	 * publication or complete rollback; complete releases unused preparation.
	 */
	kasumi_fan_subscription_free(pending->subscription);
	path_put(&pending->visible);
	put_cred(pending->cred);
	kfree(pending);
}

static void kasumi_fan_owner_destroy(struct kasumi_fan_owner *owner)
{
	unsigned long flags;

	write_lock_irqsave(&kasumi_fan_data_lock, flags);
	owner->dead = true;
	list_del(&owner->link);
	write_unlock_irqrestore(&kasumi_fan_data_lock, flags);
	kasumi_fan_subscription_free(owner->subscription);
	path_put(&owner->visible);
	put_cred(owner->cred);
	fsnotify_put_group(owner->group);
	kfree(owner);
}

static KASUMI_NOCFI int kasumi_fan_commit(struct kasumi_fanotify_pending *pending,
	struct fsnotify_group *group, void *object, unsigned int operation)
{
	struct kasumi_fan_owner *owner;
	struct kasumi_fan_subscription *old;
	unsigned long flags;
	unsigned int index;
	bool created = false;
	struct kasumi_fan_state updated;
	int error;

	if (group != pending->group || object != kasumi_fan_object(d_inode(pending->visible.dentry)) ||
	    !!(pending->flags & FAN_MARK_REMOVE) != !!(operation & FAN_MARK_REMOVE))
		return -EAGAIN;
	if (READ_ONCE(kasumi_fan_stopping))
		return -ESHUTDOWN;
	owner = kasumi_fan_owner_find(group, d_inode(pending->visible.dentry));
	if (pending->existing != !!owner || (owner && owner->serial != pending->serial))
		return -EAGAIN;
	if (owner) {
		read_lock_irqsave(&kasumi_fan_data_lock, flags);
		updated = owner->subscription->state;
		read_unlock_irqrestore(&kasumi_fan_data_lock, flags);
		error = kasumi_fan_state_update(&updated, pending->requested, pending->flags, 0);
		if (error)
			return error;
		pending->state = updated;
		if (pending->subscription)
			pending->subscription->state = updated;
	}
	if (operation & FAN_MARK_REMOVE) {
		if (!owner)
			return -ENOENT;
		write_lock_irqsave(&kasumi_fan_data_lock, flags);
		updated = owner->subscription->state;
		error = kasumi_fan_state_update(&updated, pending->requested, pending->flags, 0);
		if (!error) {
			owner->subscription->state = updated;
			owner->serial++;
		}
		write_unlock_irqrestore(&kasumi_fan_data_lock, flags);
		if (error)
			return error;
		if (!(updated.mask | updated.ignore))
			kasumi_fan_owner_destroy(owner);
		else {
			for (index = 0; index < owner->subscription->count; index++)
				kasumi_fan_apply(owner->subscription->claims[index].record);
		}
		pending->selected = true;
		return 0;
	}
	if (!owner) {
		owner = kzalloc(sizeof(*owner), GFP_KERNEL);
		if (!owner)
			return -ENOMEM;
		owner->group = group;
		kasumi_fan_get_group(group);
		owner->visible = pending->visible;
		path_get(&owner->visible);
		owner->cred = get_cred(pending->cred);
		owner->scope = pending->scope;
		INIT_LIST_HEAD(&owner->link);
		created = true;
	}
	error = kasumi_fan_subscription_attach(owner, pending->subscription);
	if (error) {
		kasumi_fan_subscription_free(pending->subscription);
		pending->subscription = NULL;
		if (created) {
			path_put(&owner->visible);
			put_cred(owner->cred);
			fsnotify_put_group(group);
			kfree(owner);
		}
		return error;
	}
	mutex_lock(&group->mark_mutex);
	write_lock_irqsave(&kasumi_fan_data_lock, flags);
	error = owner->dead ? -EAGAIN : 0;
	for (index = 0; !error && index < pending->subscription->count; index++) {
		struct kasumi_fan_record *record = pending->subscription->claims[index].record;

		if (record->dead || !(record->mark->flags & FSNOTIFY_MARK_FLAG_ALIVE))
			error = -EAGAIN;
	}
	if (!error) {
		/* Source attachment can sleep while MODIFY clears the old logical
		 * ignore mask. Reapply this operation to that latest state only at
		 * publication, under the same lock used by event filtering.
		 */
		if (owner->subscription) {
			updated = owner->subscription->state;
		} else {
			struct kasumi_fan_record *anchor = pending->subscription->claims[
				pending->subscription->count - 1].record;

			/* First adoption has the same race with native MODIFY/FLUSH:
			 * use the currently attached native direct contribution, never
			 * the baseline sampled before source preparation.
			 */
			updated = anchor->direct;
		}
		error = kasumi_fan_state_update(&updated, pending->requested, pending->flags, 0);
		if (!error)
			error = kasumi_fan_fid_scope(group, d_inode(pending->visible.dentry), updated.mask);
		if (!error)
			pending->subscription->state = updated;
	}
	if (error) {
		write_unlock_irqrestore(&kasumi_fan_data_lock, flags);
		mutex_unlock(&group->mark_mutex);
		kasumi_fan_subscription_free(pending->subscription);
		pending->subscription = NULL;
		if (created) {
			path_put(&owner->visible);
			put_cred(owner->cred);
			fsnotify_put_group(group);
			kfree(owner);
		}
		return error;
	}
	old = owner->subscription;
	owner->subscription = pending->subscription;
	pending->subscription = NULL;
	owner->serial++;
	if (created) {
		struct kasumi_fan_record *anchor = owner->subscription->claims[
			owner->subscription->count - 1].record;

		/* The prior visible mark is this same logical watch. Its preexisting
		 * state was merged during prepare, so it has no independent bypass.
		 */
		memset(&anchor->direct, 0, sizeof(anchor->direct));
		list_add_tail(&owner->link, &kasumi_fan_owners);
	}
	write_unlock_irqrestore(&kasumi_fan_data_lock, flags);
	mutex_unlock(&group->mark_mutex);
	kasumi_fan_subscription_free(old);
	pending->selected = true;
	return 0;
}

static int kasumi_fan_direct_update(struct kasumi_fan_record *record, u32 mask,
	unsigned int flags, u32 umask)
{
	struct kasumi_fan_state state;
	unsigned long irqflags;
	int error;

#ifdef FAN_MARK_EVICTABLE
	if ((flags & FAN_MARK_EVICTABLE) &&
	    !(record->mark->flags & FSNOTIFY_MARK_FLAG_NO_IREF))
		return -EEXIST;
#endif
	write_lock_irqsave(&kasumi_fan_data_lock, irqflags);
	state = record->direct;
	error = kasumi_fan_state_update(&state, mask, flags, umask);
	if (!error)
		record->direct = state;
	write_unlock_irqrestore(&kasumi_fan_data_lock, irqflags);
	if (!error) {
#ifdef FSNOTIFY_MARK_FLAG_NO_IREF
		/* Native ADD upgrades an evictable inode mark irreversibly. Keep
		 * this direct-user transition even while virtual owners share it.
		 */
		if ((flags & FAN_MARK_ADD) && !(flags & FAN_MARK_EVICTABLE)) {
			mutex_lock(&record->group->mark_mutex);
			spin_lock(&record->mark->lock);
			record->mark->flags &= ~FSNOTIFY_MARK_FLAG_NO_IREF;
			spin_unlock(&record->mark->lock);
			mutex_unlock(&record->group->mark_mutex);
		}
#endif
		kasumi_fan_apply(record);
	}
	return error;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
static KASUMI_NOCFI int kasumi_fan_add_entry(struct fsnotify_group *group,
	void *object, unsigned int type, u32 mask, unsigned int flags,
	struct kasumi_fan_fsid *fsid)
#else
static KASUMI_NOCFI int kasumi_fan_add_entry(struct fsnotify_group *group,
	fsnotify_connp_t *object, unsigned int type, u32 mask, unsigned int flags,
	__kernel_fsid_t *fsid)
#endif
{
	struct kasumi_fanotify_pending *pending = kasumi_fan_current();
	struct kasumi_fan_record *record;
	struct kasumi_fan_call call;
	int result;

	kasumi_fan_call_enter(&call);
	mutex_lock(&kasumi_fan_mutex);
	record = type == FSNOTIFY_OBJ_TYPE_INODE ? kasumi_fan_find(group, object) : NULL;
	if (pending)
		result = kasumi_fan_commit(pending, group, object, FAN_MARK_ADD);
	else if (record)
		result = kasumi_fan_direct_update(record, mask, flags | FAN_MARK_ADD, 0);
	else
		result = kasumi_fan_native_add(group, object, type, mask, flags, fsid);
	mutex_unlock(&kasumi_fan_mutex);
	kasumi_fan_call_leave(&call);
	if (atomic_dec_and_test(&kasumi_fan_active))
		wake_up_all(&kasumi_fan_wait);
	return result;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
static KASUMI_NOCFI int kasumi_fan_remove_entry(struct fsnotify_group *group,
	void *object, unsigned int type, u32 mask, unsigned int flags, u32 umask)
#else
static KASUMI_NOCFI int kasumi_fan_remove_entry(struct fsnotify_group *group,
	fsnotify_connp_t *object, u32 mask, unsigned int flags, u32 umask)
#endif
{
	struct kasumi_fanotify_pending *pending = kasumi_fan_current();
	struct kasumi_fan_record *record;
	struct kasumi_fan_call call;
	int result;

	kasumi_fan_call_enter(&call);
	mutex_lock(&kasumi_fan_mutex);
	record = kasumi_fan_find(group, object);
	if (pending)
		result = kasumi_fan_commit(pending, group, object, FAN_MARK_REMOVE);
	else if (record)
		result = kasumi_fan_direct_update(record, mask, flags | FAN_MARK_REMOVE, umask);
	else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
		result = kasumi_fan_native_remove(group, object, type, mask, flags, umask);
#else
		result = kasumi_fan_native_remove(group, object, mask, flags, umask);
#endif
	}
	mutex_unlock(&kasumi_fan_mutex);
	kasumi_fan_call_leave(&call);
	if (atomic_dec_and_test(&kasumi_fan_active))
		wake_up_all(&kasumi_fan_wait);
	return result;
}

static int kasumi_fan_mutation_pre(struct kprobe *probe, struct pt_regs *regs)
{
	if (kasumi_notify_fanotify_internal())
		return 0;
	atomic_inc(&kasumi_fan_active);
	instruction_pointer_set(regs, probe == &kasumi_fan_add_probe ?
		(unsigned long)kasumi_fan_add_entry : (unsigned long)kasumi_fan_remove_entry);
	return 1;
}

static struct kasumi_fan_record *kasumi_fan_mark_record(struct fsnotify_mark *mark)
{
	struct kasumi_fan_record *record;

	hash_for_each_possible(kasumi_fan_marks, record, mark_node, (unsigned long)mark) {
		if (record->mark == mark)
			return record;
	}
	return NULL;
}

static bool kasumi_fan_applicable(u32 mask, u32 event, bool child)
{
	return (!(event & FS_ISDIR) || (mask & FS_ISDIR)) &&
		(!child || (mask & FS_EVENT_ON_CHILD));
}

static u32 kasumi_fan_ignored(const struct kasumi_fan_state *state, u32 mask, bool child)
{
	u32 ignore = state->ignore;

#ifndef FSNOTIFY_MARK_FLAG_HAS_IGNORE_FLAGS
	/* Old fanotify applies ignored_mask regardless of ONDIR/ON_CHILD. */
	return ignore & ALL_FSNOTIFY_EVENTS;
#else
	if (!state->modern_ignore) {
		ignore |= FS_ISDIR;
		ignore &= ~FS_EVENT_ON_CHILD;
		ignore |= state->mask & FS_EVENT_ON_CHILD;
	}
	if (!kasumi_fan_applicable(ignore, mask, child))
		ignore = 0;
	return ignore & ALL_FSNOTIFY_EVENTS;
#endif
}

static u32 kasumi_fan_allowed(struct kasumi_fan_state *state, u32 mask, bool child)
{
	if ((mask & FS_MODIFY) && !state->survive)
		state->ignore = 0;
	if (!kasumi_fan_applicable(state->mask, mask, child))
		return 0;
	return mask & state->mask & ~kasumi_fan_ignored(state, mask, child) & ALL_FSNOTIFY_EVENTS;
}

struct kasumi_fan_projection {
	struct kasumi_fan_state *state;
	u32 allowed;
};

static int kasumi_fan_project_emit(void *data, const struct kasumi_notify_event *event)
{
	struct kasumi_fan_projection *projection = data;

	projection->allowed |= kasumi_fan_allowed(projection->state, event->mask,
		event->named || (event->mask & FS_EVENT_ON_CHILD));
	return 0;
}

/* No wrapper calls the native handler: after this probe returns there is no
 * module frame or borrowed module object on a native permission wait's stack.
 * The data write lock pins every snapshot until filtering has completed.
 */
static u32 kasumi_fan_filter(u32 mask, const void *data, int data_type,
	struct inode *dir, const struct qstr *name, u32 cookie,
	struct fsnotify_iter_info *iterator, bool fid)
{
	struct inode *inode = fsnotify_data_inode(data, data_type);
	struct fsnotify_mark *mark;
	u32 allowed = 0, native_ignore = 0;
	unsigned long flags;
	unsigned int type;
	bool queue = false, managed = false;

	write_lock_irqsave(&kasumi_fan_data_lock, flags);
	for (type = 0; type < ARRAY_SIZE(iterator->marks); type++) {
		struct kasumi_fan_record *record;
		struct kasumi_fan_claim *claim;
		bool parent;

		if (!(iterator->report_mask & (1U << type)))
			continue;
		mark = iterator->marks[type];
		if (!mark)
			continue;
#ifdef fsnotify_foreach_iter_type
		parent = type == FSNOTIFY_ITER_TYPE_PARENT;
#else
		parent = type == FSNOTIFY_OBJ_TYPE_PARENT;
#endif
		record = kasumi_fan_mark_record(mark);
		if (!record) {
			struct kasumi_fan_state native = kasumi_fan_capture(mark);

			allowed |= kasumi_fan_allowed(&native, mask, parent);
			native_ignore |= kasumi_fan_ignored(&native, mask, parent);
			continue;
		}
		managed = true;
		if (record->dead)
			continue;
		allowed |= kasumi_fan_allowed(&record->direct, mask, parent);
		/* A direct inode ignore also vetoes this native group's mount/sb
		 * interests. Keep the native group-wide subtraction after merging
		 * all direct and projected contributions.
		 */
		native_ignore |= kasumi_fan_ignored(&record->direct, mask, parent);
		list_for_each_entry(claim, &record->claims, link) {
			struct kasumi_fan_owner *owner = claim->owner;
			struct kasumi_fan_subscription *subscription = claim->subscription;
			const struct kasumi_notify_source *source;
			const struct qstr *query = name;
			struct kasumi_fan_projection projection = { .state = &subscription->state };
			u32 projected_mask = mask;
			bool refresh = false;
			int error;

			if (owner->dead || owner->subscription != subscription ||
			    claim->index == KASUMI_FAN_ANCHOR)
				continue;
			source = kasumi_notify_snapshot_source(subscription->snapshot, claim->index);
			/* The full native fanotify callback carries the parent name even
			 * for an inode mark. A leaf receives its own event without that
			 * name; a directory leaf still excludes its grandchildren.
			 */
			if (!parent && !(mask & ALL_FSNOTIFY_DIRENT_EVENTS)) {
				query = NULL;
				projected_mask &= ~FS_EVENT_ON_CHILD;
			}
			error = kasumi_notify_snapshot_project(subscription->snapshot, claim->index,
				projected_mask, inode, dir, query, cookie, &refresh,
				kasumi_fan_project_emit, &projection);
			if (!error && source->kind != KASUMI_NOTIFY_SOURCE_TOPOLOGY)
				allowed |= projection.allowed;
			if (refresh || error) {
				owner->dirty = true;
				queue = true;
			}
		}
	}
	write_unlock_irqrestore(&kasumi_fan_data_lock, flags);
	if (queue && !READ_ONCE(kasumi_fan_stopping))
		queue_work(kasumi_fan_queue, &kasumi_fan_refresh);
	/* Even an independent native mark in the same group cannot authorize
	 * passing a vnode to the backing filesystem's exportfs callbacks.
	 * FID-only identifies dir for dirent events and data inode otherwise.
	 */
	if (managed && fid && kasumi_vnode_is_ours(
		(mask & ALL_FSNOTIFY_DIRENT_EVENTS) ? dir : inode))
		return 0;
	return managed ? (mask & ~ALL_FSNOTIFY_EVENTS) | (allowed & ~native_ignore) : mask;
}

static int kasumi_fan_event_pre(struct kprobe *probe, struct pt_regs *regs)
{
	regs->regs[1] = kasumi_fan_filter(regs->regs[1], (void *)regs->regs[2],
		regs->regs[3], (void *)regs->regs[4], (void *)regs->regs[5],
		regs->regs[6], (void *)regs->regs[7],
		kasumi_fan_fid_group((void *)regs->regs[0]));
	return 0;
}

static int kasumi_fan_freeing_pre(struct kprobe *probe, struct pt_regs *regs)
{
	struct kasumi_fan_record *record;
	struct kasumi_fan_claim *claim;
	unsigned long flags;
	bool queue = false;

	write_lock_irqsave(&kasumi_fan_data_lock, flags);
	record = kasumi_fan_mark_record((void *)regs->regs[0]);
	if (record) {
		record->dead = true;
		list_for_each_entry(claim, &record->claims, link) {
			if (claim->index == KASUMI_FAN_ANCHOR)
				claim->owner->dead = true;
			claim->owner->dirty = true;
			queue = true;
		}
	}
	write_unlock_irqrestore(&kasumi_fan_data_lock, flags);
	if (queue)
		queue_work(kasumi_fan_queue, &kasumi_fan_refresh);
	return 0;
}

static KASUMI_NOCFI void kasumi_fan_work(struct work_struct *work)
{
	struct kasumi_fan_owner *owner, *next;
	struct kasumi_fan_call call;
	unsigned long flags;

	kasumi_fan_call_enter(&call);
	mutex_lock(&kasumi_fan_mutex);
	list_for_each_entry_safe(owner, next, &kasumi_fan_owners, link) {
		struct kasumi_fan_subscription *replacement, *old;
		struct kasumi_fan_state state;
		const struct cred *saved;
		bool dirty, dead;
		int error;

		write_lock_irqsave(&kasumi_fan_data_lock, flags);
		dead = owner->dead;
		dirty = owner->dirty;
		owner->dirty = false;
		state = owner->subscription->state;
		write_unlock_irqrestore(&kasumi_fan_data_lock, flags);
		if (dead || READ_ONCE(kasumi_fan_stopping)) {
			kasumi_fan_owner_destroy(owner);
			continue;
		}
		if (!dirty)
			continue;
		saved = override_creds(owner->cred);
		replacement = kasumi_fan_subscription_build(owner->group, &owner->visible, &owner->scope,
			owner->subscription, &state);
		revert_creds(saved);
		if (IS_ERR(replacement)) {
			if (kasumi_fan_insert_event)
				kasumi_fan_insert_event(owner->group, owner->group->overflow_event, NULL, NULL);
			else
				kasumi_fan_add_event(owner->group, owner->group->overflow_event, NULL);
			continue;
		}
		if (kasumi_notify_snapshot_root_retired(replacement->snapshot)) {
			kasumi_fan_subscription_free(replacement);
			kasumi_fan_owner_destroy(owner);
			continue;
		}
		error = kasumi_fan_subscription_attach(owner, replacement);
		if (error) {
			kasumi_fan_subscription_free(replacement);
			if (kasumi_fan_insert_event)
				kasumi_fan_insert_event(owner->group, owner->group->overflow_event, NULL, NULL);
			else
				kasumi_fan_add_event(owner->group, owner->group->overflow_event, NULL);
			continue;
		}
		mutex_lock(&owner->group->mark_mutex);
		write_lock_irqsave(&kasumi_fan_data_lock, flags);
		dead = owner->dead;
		if (dead) {
			write_unlock_irqrestore(&kasumi_fan_data_lock, flags);
			mutex_unlock(&owner->group->mark_mutex);
			kasumi_fan_subscription_free(replacement);
			kasumi_fan_owner_destroy(owner);
			continue;
		}
		old = owner->subscription;
		/* A native MODIFY may have cleared ignored events during build. */
		replacement->state = old->state;
		owner->subscription = replacement;
		owner->serial++;
		write_unlock_irqrestore(&kasumi_fan_data_lock, flags);
		mutex_unlock(&owner->group->mark_mutex);
		kasumi_fan_subscription_free(old);
	}
	mutex_unlock(&kasumi_fan_mutex);
	kasumi_fan_call_leave(&call);
}

void kasumi_notify_fanotify_rules_changed(void)
{
	struct kasumi_fan_owner *owner;
	unsigned long flags;
	bool queue = false;

	if (!READ_ONCE(kasumi_fan_ready) || READ_ONCE(kasumi_fan_stopping))
		return;
	write_lock_irqsave(&kasumi_fan_data_lock, flags);
	list_for_each_entry(owner, &kasumi_fan_owners, link) {
		if (!owner->dead) {
			owner->dirty = true;
			queue = true;
		}
	}
	write_unlock_irqrestore(&kasumi_fan_data_lock, flags);
	if (queue)
		queue_work(kasumi_fan_queue, &kasumi_fan_refresh);
}

bool kasumi_notify_fanotify_supported(void)
{
	return READ_ONCE(kasumi_fan_ready) && !READ_ONCE(kasumi_fan_stopping);
}

int kasumi_notify_fanotify_init(void)
{
	struct kprobe *probes[] = { &kasumi_fan_add_probe, &kasumi_fan_remove_probe,
		&kasumi_fan_event_probe, &kasumi_fan_freeing_probe };
	const char *names[] = { "fanotify_add_mark", "fanotify_remove_mark",
		"fanotify_handle_event", "fanotify_freeing_mark" };
	unsigned int index;
	int error;

	if (kasumi_fan_ready)
		return 0;
	for (index = 0; index < ARRAY_SIZE(kasumi_fan_task_locks); index++)
		spin_lock_init(&kasumi_fan_task_locks[index]);
	kasumi_fan_native_add = (void *)kasumi_lookup_callable_quiet(names[0]);
	kasumi_fan_native_remove = (void *)kasumi_lookup_callable_quiet(names[1]);
	kasumi_fan_find_mark = (void *)kasumi_lookup_callable_quiet("fsnotify_find_mark");
	kasumi_fan_recalc_mask = (void *)kasumi_lookup_callable_quiet("fsnotify_recalc_mask");
	kasumi_fan_get_group = (void *)kasumi_lookup_callable_quiet("fsnotify_get_group");
	kasumi_fan_get_fsid = (void *)kasumi_lookup_callable_quiet("vfs_get_fsid");
	kasumi_fan_insert_event = (void *)kasumi_lookup_callable_quiet("fsnotify_insert_event");
	kasumi_fan_add_event = (void *)kasumi_lookup_callable_quiet("fsnotify_add_event");
	kasumi_fan_tasks_barrier = (void *)kasumi_lookup_callable_quiet("synchronize_rcu_tasks");
	if (!kasumi_fan_native_add || !kasumi_fan_native_remove || !kasumi_fan_find_mark ||
	    !kasumi_fan_recalc_mask || !kasumi_fan_get_group || !kasumi_fan_tasks_barrier ||
	    (!kasumi_fan_insert_event && !kasumi_fan_add_event))
		return -EOPNOTSUPP;
	kasumi_fan_queue = alloc_ordered_workqueue("kasumi-fanotify", WQ_MEM_RECLAIM);
	if (!kasumi_fan_queue)
		return -ENOMEM;
	for (index = 0; index < ARRAY_SIZE(probes); index++) {
		probes[index]->addr = (void *)kasumi_lookup_name_quiet(names[index]);
		/* Older fanotify has no freeing_mark callback. Its generic free
		 * transition can be inlined by LTO into flush and destroy paths;
		 * detach remains the shared entry before final put/SRCU destruction.
		 * The caller holds group->mark_mutex and a mark reference, so the
		 * worker cannot restore a removed contribution before detach finishes.
		 * The probe's mark hash excludes every unrelated group.
		 */
		if (index == 3 && !probes[index]->addr)
			probes[index]->addr = (void *)kasumi_lookup_name_quiet("fsnotify_detach_mark");
		if (!probes[index]->addr) {
			error = -EOPNOTSUPP;
			goto fail;
		}
		probes[index]->pre_handler = index < 2 ? kasumi_fan_mutation_pre :
			index == 2 ? kasumi_fan_event_pre : kasumi_fan_freeing_pre;
		error = register_kprobe(probes[index]);
		if (error)
			goto fail;
		kasumi_fan_probes++;
	}
	WRITE_ONCE(kasumi_fan_ready, true);
	WRITE_ONCE(kasumi_fan_stopping, false);
	return 0;
fail:
	kasumi_notify_fanotify_exit();
	return error;
}

void kasumi_notify_fanotify_stop(void)
{
	WRITE_ONCE(kasumi_fan_stopping, true);
	if (kasumi_fan_queue) {
		queue_work(kasumi_fan_queue, &kasumi_fan_refresh);
		flush_workqueue(kasumi_fan_queue);
	}
}

KASUMI_NOCFI void kasumi_notify_fanotify_exit(void)
{
	struct kprobe *probes[] = { &kasumi_fan_add_probe, &kasumi_fan_remove_probe,
		&kasumi_fan_event_probe, &kasumi_fan_freeing_probe };

	kasumi_notify_fanotify_stop();
	while (kasumi_fan_probes)
		unregister_kprobe(probes[--kasumi_fan_probes]);
	wait_event(kasumi_fan_wait, !atomic_read(&kasumi_fan_active));
	if (kasumi_fan_tasks_barrier)
		kasumi_fan_tasks_barrier();
	if (kasumi_fan_queue) {
		destroy_workqueue(kasumi_fan_queue);
		kasumi_fan_queue = NULL;
	}
	WRITE_ONCE(kasumi_fan_ready, false);
}

#else
int kasumi_notify_fanotify_prepare(const struct path *path, u64 mask,
	unsigned int type, unsigned int flags, struct fsnotify_group *group,
	struct kasumi_fanotify_pending **pending)
{
	*pending = NULL;
	return 0;
}
void kasumi_notify_fanotify_complete(struct kasumi_fanotify_pending *pending, long result) {}
bool kasumi_notify_fanotify_internal(void) { return false; }
bool kasumi_notify_fanotify_supported(void) { return false; }
void kasumi_notify_fanotify_rules_changed(void) {}
int kasumi_notify_fanotify_init(void) { return -EOPNOTSUPP; }
void kasumi_notify_fanotify_stop(void) {}
void kasumi_notify_fanotify_exit(void) {}
#endif
