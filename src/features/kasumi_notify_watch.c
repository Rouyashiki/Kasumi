#include <linux/cred.h>
#include <linux/fsnotify_backend.h>
#include <linux/hashtable.h>
#include <linux/inotify.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/user_namespace.h>
#include <linux/version.h>
#include <linux/workqueue.h>

#include "kasumi_notify_watch.h"
#include "kasumi_notify_view.h"
#include "kasumi_notify_rules.h"
#include "kasumi_path_policy.h"
#include "kasumi_runtime.h"
#include "kasumi_vnode.h"

#define KASUMI_NOTIFY_TOPOLOGY_MASK (FS_CREATE | FS_DELETE | FS_MOVED_FROM | \
	FS_MOVED_TO | FS_DELETE_SELF | FS_MOVE_SELF | FS_UNMOUNT | FS_EVENT_ON_CHILD)

struct kasumi_notify_owner;

struct kasumi_notify_source_index {
	struct inode *inode;
	struct path path;
	unsigned int index;
};

struct kasumi_notify_subscription {
	struct list_head retired;
	struct kasumi_notify_snapshot *snapshot;
	struct kasumi_notify_source_index *indices;
	struct kasumi_notify_child **children;
	unsigned int index_count;
	unsigned int child_count;
};

struct kasumi_notify_child {
	struct fsnotify_mark mark;
	refcount_t references;
	struct kasumi_notify_owner *owner;
	struct inode *inode;
	struct ucounts *ucounts;
};

struct kasumi_notify_move {
	struct list_head node;
	struct hlist_node hash;
	struct kasumi_notify_rename_hint hint;
	u64 generation;
	char old_name[NAME_MAX + 1];
	char new_name[NAME_MAX + 1];
};

struct kasumi_notify_owner {
	refcount_t references;
	struct hlist_node node;
	struct work_struct work;
	struct mutex delivery;
	struct fsnotify_group *group;
	struct fsnotify_group *children;
	struct fsnotify_mark *anchor;
	struct kasumi_notify_subscription *subscription;
	struct list_head retired;
	struct list_head moves;
	DECLARE_HASHTABLE(move_index, 6);
	unsigned int move_count;
	struct path visible;
	const struct cred *cred;
	struct kasumi_notify_scope scope;
	u64 serial;
	u64 dirty_sequence;
	u32 mask;
	bool registered;
	bool dead;
	bool dirty;
};

struct kasumi_notify_pending {
	struct kasumi_notify_owner *owner;
	struct kasumi_notify_snapshot *snapshot;
	struct kasumi_notify_subscription *subscription;
	struct fsnotify_mark *expected;
	u32 requested;
	u32 checked_mask;
	bool selected;
	bool existing_owner;
};

struct kasumi_notify_forward {
	struct hlist_node node;
	struct task_struct *task;
	struct fsnotify_mark *anchor;
};

static DEFINE_HASHTABLE(kasumi_notify_owners, 8);
static DEFINE_SPINLOCK(kasumi_notify_owner_lock);
static DEFINE_HASHTABLE(kasumi_notify_forwards, 6);
static spinlock_t kasumi_notify_forward_locks[HASH_SIZE(kasumi_notify_forwards)];
static struct workqueue_struct *kasumi_notify_owner_queue;
static bool kasumi_notify_owner_stopping = true;
static atomic_t kasumi_notify_owner_count = ATOMIC_INIT(0);
static struct kprobe kasumi_notify_owner_event_probe;
static struct kprobe kasumi_notify_owner_freeing_probe;
static bool kasumi_notify_owner_event_registered;
static bool kasumi_notify_owner_freeing_registered;
static typeof(fsnotify_alloc_group) *kasumi_watch_alloc_group;
static typeof(fsnotify_destroy_group) *kasumi_watch_destroy_group;
static typeof(fsnotify_add_mark) *kasumi_watch_add_mark;
static typeof(fsnotify_get_mark) *kasumi_watch_get_mark;
static typeof(fsnotify_get_group) *kasumi_watch_get_group;
static typeof(fsnotify_find_mark) *kasumi_watch_find_mark;
static typeof(fsnotify_recalc_mask) *kasumi_watch_recalc_mask;
static struct ucounts *(*kasumi_watch_inc_ucount)(struct user_namespace *, kuid_t,
						 enum ucount_type);
static void (*kasumi_watch_dec_ucount)(struct ucounts *, enum ucount_type);
static int (*kasumi_watch_native_event)(struct fsnotify_mark *, u32,
	struct inode *, struct inode *, const struct qstr *, u32);
static int (*kasumi_watch_insert_event)(struct fsnotify_group *, struct fsnotify_event *,
	int (*)(struct fsnotify_group *, struct fsnotify_event *),
	void (*)(struct fsnotify_group *, struct fsnotify_event *));
static int (*kasumi_watch_add_event)(struct fsnotify_group *, struct fsnotify_event *,
	int (*)(struct fsnotify_group *, struct fsnotify_event *));

static void kasumi_notify_owner_work(struct work_struct *work);

static KASUMI_NOCFI void kasumi_notify_owner_overflow(struct kasumi_notify_owner *owner)
{
	if (kasumi_watch_insert_event)
		kasumi_watch_insert_event(owner->group, owner->group->overflow_event, NULL, NULL);
	else
		kasumi_watch_add_event(owner->group, owner->group->overflow_event, NULL);
}

static void kasumi_notify_moves_retire(struct kasumi_notify_owner *owner, u64 generation)
{
	struct kasumi_notify_move *move, *next;

	list_for_each_entry_safe(move, next, &owner->moves, node) {
		if (move->generation >= generation)
			continue;
		list_del(&move->node);
		hash_del(&move->hash);
		owner->move_count--;
		iput(move->hint.inode);
		kfree(move);
	}
}

static KASUMI_NOCFI void kasumi_notify_owner_put(struct kasumi_notify_owner *owner)
{
	if (!refcount_dec_and_test(&owner->references))
		return;
	if (owner->children)
		kasumi_watch_destroy_group(owner->children);
	kasumi_notify_moves_retire(owner, U64_MAX);
	if (owner->anchor)
		fsnotify_put_mark(owner->anchor);
	fsnotify_put_group(owner->group);
	path_put(&owner->visible);
	put_cred(owner->cred);
	kfree(owner);
	atomic_dec(&kasumi_notify_owner_count);
	module_put(THIS_MODULE);
}

static void kasumi_notify_owner_queue_locked(struct kasumi_notify_owner *owner)
{
	refcount_inc(&owner->references);
	if (!queue_work(kasumi_notify_owner_queue, &owner->work))
		refcount_dec(&owner->references);
}

static struct kasumi_notify_owner *kasumi_notify_owner_find_locked(
	struct fsnotify_mark *anchor)
{
	struct kasumi_notify_owner *owner;

	hash_for_each_possible(kasumi_notify_owners, owner, node, (unsigned long)anchor) {
		if (owner->anchor == anchor)
			return owner;
	}
	return NULL;
}

static bool kasumi_notify_forwarding(struct fsnotify_mark *anchor)
{
	struct kasumi_notify_forward *forward;
	spinlock_t *lock = &kasumi_notify_forward_locks[hash_min((unsigned long)current,
						 HASH_BITS(kasumi_notify_forwards))];
	unsigned long flags;
	bool found = false;

	spin_lock_irqsave(lock, flags);
	hash_for_each_possible(kasumi_notify_forwards, forward, node, (unsigned long)current) {
		if (forward->task == current && forward->anchor == anchor) {
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(lock, flags);
	return found;
}

static KASUMI_NOCFI int kasumi_notify_owner_emit(void *data,
	const struct kasumi_notify_event *event)
{
	struct kasumi_notify_owner *owner = data;
	struct kasumi_notify_forward forward = {
		.task = current, .anchor = owner->anchor,
	};
	spinlock_t *lock = &kasumi_notify_forward_locks[hash_min((unsigned long)current,
						 HASH_BITS(kasumi_notify_forwards))];
	unsigned long flags;
	int ret;

	if (READ_ONCE(owner->dead) || !(event->mask & READ_ONCE(owner->mask) & ALL_FSNOTIFY_EVENTS))
		return 0;
	spin_lock_irqsave(lock, flags);
	hash_add(kasumi_notify_forwards, &forward.node, (unsigned long)current);
	spin_unlock_irqrestore(lock, flags);
	ret = kasumi_watch_native_event(owner->anchor, event->mask, event->inode,
		d_inode(owner->visible.dentry), event->named ? &event->name : NULL,
		event->cookie);
	spin_lock_irqsave(lock, flags);
	hash_del(&forward.node);
	spin_unlock_irqrestore(lock, flags);
	return ret;
}

static int kasumi_notify_record_move(struct kasumi_notify_owner *owner,
	u32 mask, struct inode *inode, const struct qstr *name, u32 cookie)
{
	struct kasumi_notify_move *move;
	char *destination;
	struct qstr *query;

	if (!cookie || !inode || !name || !name->len || name->len > NAME_MAX)
		return 0;
	hash_for_each_possible(owner->move_index, move, hash, cookie) {
		if (move->hint.cookie == cookie && move->hint.inode == inode)
			goto found;
	}
	if (owner->move_count >= owner->group->max_events)
		return -ENOSPC;
	move = kzalloc(sizeof(*move), GFP_KERNEL);
	if (!move)
		return -ENOMEM;
	move->hint.inode = igrab(inode);
	if (!move->hint.inode) {
		kfree(move);
		return -ESTALE;
	}
	move->hint.cookie = cookie;
	move->generation = kasumi_rules_generation();
	list_add_tail(&move->node, &owner->moves);
	hash_add(owner->move_index, &move->hash, cookie);
	owner->move_count++;
found:
	if (mask & FS_MOVED_FROM) {
		destination = move->old_name;
		query = &move->hint.old_name;
	} else {
		destination = move->new_name;
		query = &move->hint.new_name;
	}
	memcpy(destination, name->name, name->len);
	destination[name->len] = 0;
	*query = (struct qstr)QSTR_INIT(destination, name->len);
	return 0;
}

static int kasumi_notify_child_event(struct fsnotify_mark *mark, u32 mask,
	struct inode *inode, struct inode *dir, const struct qstr *name, u32 cookie)
{
	struct kasumi_notify_child *child = container_of(mark, struct kasumi_notify_child, mark);
	struct kasumi_notify_owner *owner = child->owner;
	struct kasumi_notify_subscription *subscription;
	unsigned long flags;
	unsigned int first = 0, end, index;
	bool refresh = false, topology = false;
	int ret = 0;

	spin_lock_irqsave(&kasumi_notify_owner_lock, flags);
	if (owner->dead || !owner->registered) {
		owner->dirty_sequence++;
		spin_unlock_irqrestore(&kasumi_notify_owner_lock, flags);
		return 0;
	}
	spin_unlock_irqrestore(&kasumi_notify_owner_lock, flags);
	mutex_lock(&owner->delivery);
	subscription = owner->subscription;
	if (!subscription || READ_ONCE(owner->dead))
		goto unlock;
	end = subscription->index_count;
	while (first < end) {
		unsigned int middle = first + (end - first) / 2;

		if ((unsigned long)subscription->indices[middle].inode < (unsigned long)child->inode)
			first = middle + 1;
		else
			end = middle;
	}
	for (index = first; index < subscription->index_count &&
	     subscription->indices[index].inode == child->inode; index++) {
		bool changed = false;
		const struct kasumi_notify_source *source = kasumi_notify_snapshot_source(
			subscription->snapshot, subscription->indices[index].index);

		topology |= source->kind == KASUMI_NOTIFY_SOURCE_TOPOLOGY;
		ret = kasumi_notify_snapshot_project(subscription->snapshot,
			subscription->indices[index].index, mask, inode, dir, name,
			cookie, &changed, kasumi_notify_owner_emit, owner);
		refresh |= changed;
		if (ret)
			break;
	}
	if (!ret && topology && (mask & FS_MOVE))
		ret = kasumi_notify_record_move(owner, mask, inode, name, cookie);
	refresh |= kasumi_notify_snapshot_generation(subscription->snapshot) != kasumi_rules_generation();
	if (ret) {
		kasumi_notify_owner_overflow(owner);
		refresh = true;
	}
unlock:
	mutex_unlock(&owner->delivery);
	if (refresh || !subscription) {
		spin_lock_irqsave(&kasumi_notify_owner_lock, flags);
		if (!owner->dead && !kasumi_notify_owner_stopping) {
			owner->dirty = true;
			owner->dirty_sequence++;
			if (owner->registered)
				kasumi_notify_owner_queue_locked(owner);
		}
		spin_unlock_irqrestore(&kasumi_notify_owner_lock, flags);
	}
	return ret;
}

static KASUMI_NOCFI void kasumi_notify_child_free(struct fsnotify_mark *mark)
{
	struct kasumi_notify_child *child = container_of(mark, struct kasumi_notify_child, mark);

	kasumi_watch_dec_ucount(child->ucounts, UCOUNT_INOTIFY_WATCHES);
	kfree(child);
}

static const struct fsnotify_ops kasumi_notify_child_ops = {
	.handle_inode_event = kasumi_notify_child_event,
	.free_mark = kasumi_notify_child_free,
};

static void kasumi_notify_subscription_destroy(struct kasumi_notify_subscription *subscription)
{
	unsigned int index;

	if (!subscription)
		return;
	for (index = 0; index < subscription->child_count; index++) {
		struct kasumi_notify_child *child = subscription->children[index];

		if (refcount_dec_and_test(&child->references)) {
			fsnotify_destroy_mark(&child->mark, child->owner->children);
			fsnotify_put_mark(&child->mark);
		}
	}
	for (index = 0; index < subscription->index_count; index++) {
		if (subscription->indices && subscription->indices[index].path.dentry)
			path_put(&subscription->indices[index].path);
	}
	kasumi_notify_snapshot_put(subscription->snapshot);
	kfree(subscription->children);
	kfree(subscription->indices);
	kfree(subscription);
}

static int kasumi_notify_index_compare(const void *left, const void *right)
{
	const struct kasumi_notify_source_index *a = left, *b = right;

	if ((unsigned long)a->inode < (unsigned long)b->inode)
		return -1;
	return (unsigned long)a->inode > (unsigned long)b->inode;
}

static int kasumi_notify_snapshot_permissions(struct kasumi_notify_snapshot *snapshot, u32 mask)
{
	unsigned int index;
	int error;

	for (index = 0; index < kasumi_notify_snapshot_source_count(snapshot); index++) {
		const struct kasumi_notify_source *source = kasumi_notify_snapshot_source(snapshot, index);
		struct path path;

		if (source->kind == KASUMI_NOTIFY_SOURCE_TOPOLOGY)
			continue;
		path = source->path;
		path_get(&path);
		error = kasumi_notify_resolve_source(&path, mask & IN_ALL_EVENTS);
		path_put(&path);
		if (error)
			return error;
	}
	return 0;
}

static u32 kasumi_notify_child_mask(struct kasumi_notify_subscription *subscription,
	unsigned int first, unsigned int end, u32 requested)
{
	u32 mask = FS_ATTRIB | FS_DELETE_SELF | FS_MOVE_SELF | FS_UNMOUNT;
	unsigned int index;

	for (index = first; index < end; index++) {
		const struct kasumi_notify_source *source = kasumi_notify_snapshot_source(
			subscription->snapshot, subscription->indices[index].index);

		if (source->kind == KASUMI_NOTIFY_SOURCE_TOPOLOGY)
			mask |= KASUMI_NOTIFY_TOPOLOGY_MASK;
		else if (source->kind == KASUMI_NOTIFY_SOURCE_BASE)
			mask |= requested | KASUMI_NOTIFY_TOPOLOGY_MASK;
		else
			mask |= requested & ~FS_EVENT_ON_CHILD;
	}
	return mask & ~FS_IN_IGNORED;
}

/* One native child mark per source inode remains stable across snapshot changes. */
static KASUMI_NOCFI struct kasumi_notify_subscription *kasumi_notify_subscription_build(
	struct kasumi_notify_owner *owner, struct kasumi_notify_snapshot *snapshot,
	struct kasumi_notify_subscription *previous)
{
	struct kasumi_notify_subscription *subscription;
	struct kasumi_notify_child *child;
	unsigned int count = kasumi_notify_snapshot_source_count(snapshot);
	unsigned int index, end, old_index = 0;
	int error;

	subscription = kzalloc(sizeof(*subscription), GFP_KERNEL);
	if (!subscription)
		return ERR_PTR(-ENOMEM);
	INIT_LIST_HEAD(&subscription->retired);
	if (!owner->children) {
#ifdef FSNOTIFY_GROUP_DUPS
		owner->children = kasumi_watch_alloc_group(&kasumi_notify_child_ops, 0);
#else
		owner->children = kasumi_watch_alloc_group(&kasumi_notify_child_ops);
#endif
		if (IS_ERR(owner->children)) {
			error = PTR_ERR(owner->children);
			owner->children = NULL;
			kfree(subscription);
			return ERR_PTR(error);
		}
	}
	subscription->snapshot = snapshot;
	kasumi_notify_snapshot_get(snapshot);
	subscription->index_count = count;
	subscription->indices = kcalloc(count, sizeof(*subscription->indices), GFP_KERNEL);
	subscription->children = kcalloc(count, sizeof(*subscription->children), GFP_KERNEL);
	if (count && (!subscription->indices || !subscription->children)) {
		error = -ENOMEM;
		goto fail;
	}
	for (index = 0; index < count; index++) {
		const struct kasumi_notify_source *source = kasumi_notify_snapshot_source(snapshot, index);

		subscription->indices[index].index = index;
		if (source->kind == KASUMI_NOTIFY_SOURCE_TOPOLOGY) {
			struct inode *inode = d_inode(source->topology);

			while (kasumi_vnode_is_ours(inode)) {
				struct kasumi_vnode_info *info = inode->i_private;

				if (!info || !info->source.dentry)
					break;
				inode = d_inode(info->source.dentry);
			}
			subscription->indices[index].inode = inode;
		} else {
			subscription->indices[index].path = source->path;
			path_get(&subscription->indices[index].path);
			error = kasumi_notify_resolve_source(&subscription->indices[index].path,
				owner->mask & IN_ALL_EVENTS);
			if (error)
				goto fail;
			subscription->indices[index].inode = d_inode(subscription->indices[index].path.dentry);
		}
	}
	sort(subscription->indices, count, sizeof(*subscription->indices),
		kasumi_notify_index_compare, NULL);
	for (index = 0; index < count; index = end) {
		struct inode *inode = subscription->indices[index].inode;

		for (end = index + 1; end < count && subscription->indices[end].inode == inode; end++)
			;
		while (previous && old_index < previous->child_count &&
		       (unsigned long)previous->children[old_index]->inode < (unsigned long)inode)
			old_index++;
		if (previous && old_index < previous->child_count &&
		    previous->children[old_index]->inode == inode) {
			child = previous->children[old_index++];
			refcount_inc(&child->references);
			subscription->children[subscription->child_count++] = child;
			continue;
		}
		child = kzalloc(sizeof(*child), GFP_KERNEL);
		if (!child) {
			error = -ENOMEM;
			goto fail;
		}
		child->ucounts = kasumi_watch_inc_ucount(owner->group->inotify_data.ucounts->ns,
			owner->group->inotify_data.ucounts->uid, UCOUNT_INOTIFY_WATCHES);
		if (!child->ucounts) {
			kfree(child);
			error = -ENOSPC;
			goto fail;
		}
		child->owner = owner;
		child->inode = inode;
		refcount_set(&child->references, 1);
		fsnotify_init_mark(&child->mark, owner->children);
		child->mark.mask = kasumi_notify_child_mask(subscription, index, end, owner->mask);
		subscription->children[subscription->child_count++] = child;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
		error = kasumi_watch_add_mark(&child->mark, inode, FSNOTIFY_OBJ_TYPE_INODE, 0);
#else
		error = kasumi_watch_add_mark(&child->mark, &inode->i_fsnotify_marks,
			FSNOTIFY_OBJ_TYPE_INODE, 0, NULL);
#endif
		if (error)
			goto fail;
	}
	return subscription;
fail:
	kasumi_notify_subscription_destroy(subscription);
	return ERR_PTR(error);
}

static KASUMI_NOCFI void kasumi_notify_subscription_mask(
	struct kasumi_notify_subscription *subscription, u32 mask, unsigned int flags)
{
	unsigned int index, first = 0;

	for (index = 0; index < subscription->child_count; index++) {
		struct kasumi_notify_child *child = subscription->children[index];
		unsigned int end = first;
		u32 selected, previous;

		while (end < subscription->index_count && subscription->indices[end].inode == child->inode)
			end++;
		selected = kasumi_notify_child_mask(subscription, first, end, mask);
		first = end;
		spin_lock(&child->mark.lock);
		previous = child->mark.mask;
		child->mark.mask = selected;
#ifdef FSNOTIFY_MARK_FLAG_EXCL_UNLINK
		child->mark.flags &= ~FSNOTIFY_MARK_FLAG_EXCL_UNLINK;
		child->mark.flags |= flags & FSNOTIFY_MARK_FLAG_EXCL_UNLINK;
#endif
		if (previous != selected && child->mark.connector)
			kasumi_watch_recalc_mask(child->mark.connector);
		spin_unlock(&child->mark.lock);
	}
}

static KASUMI_NOCFI struct fsnotify_mark *kasumi_notify_lookup_mark(
	struct inode *inode, struct fsnotify_group *group)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	return kasumi_watch_find_mark(inode, FSNOTIFY_OBJ_TYPE_INODE, group);
#else
	return kasumi_watch_find_mark(&inode->i_fsnotify_marks, group);
#endif
}

KASUMI_NOCFI int kasumi_notify_watch_prepare(const struct path *visible, u32 mask,
	struct fsnotify_group *group, struct kasumi_notify_pending **result)
{
	struct kasumi_notify_pending *pending;
	struct kasumi_notify_owner *owner, *existing;
	struct kasumi_notify_snapshot *snapshot = NULL;
	struct fsnotify_mark *expected;
	unsigned long flags;
	char *buffer, *name;
	u32 checked = mask & IN_ALL_EVENTS;
	bool overridden;
	int error;

	*result = NULL;
	if (READ_ONCE(kasumi_notify_owner_stopping) || !group ||
	    !S_ISDIR(d_inode(visible->dentry)->i_mode))
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
	mutex_lock(&group->mark_mutex);
	expected = kasumi_notify_lookup_mark(d_inode(visible->dentry), group);
	if (expected && (mask & IN_MASK_ADD))
		checked |= READ_ONCE(expected->mask) & IN_ALL_EVENTS;
	spin_lock_irqsave(&kasumi_notify_owner_lock, flags);
	existing = expected ? kasumi_notify_owner_find_locked(expected) : NULL;
	if (existing && !existing->dead)
		refcount_inc(&existing->references);
	else
		existing = NULL;
	spin_unlock_irqrestore(&kasumi_notify_owner_lock, flags);
	mutex_unlock(&group->mark_mutex);
	pending->expected = expected;
	pending->requested = mask;
	pending->checked_mask = checked;
	if (!existing && !overridden) {
		kasumi_notify_watch_complete(pending, 0);
		return 0;
	}
	if (existing) {
		pending->owner = existing;
		pending->existing_owner = true;
		spin_lock_irqsave(&kasumi_notify_owner_lock, flags);
		if (existing->subscription) {
			snapshot = existing->subscription->snapshot;
			kasumi_notify_snapshot_get(snapshot);
		}
		spin_unlock_irqrestore(&kasumi_notify_owner_lock, flags);
		if (!snapshot) {
			error = -EAGAIN;
			goto fail;
		}
		error = kasumi_notify_snapshot_permissions(snapshot, checked);
		kasumi_notify_snapshot_put(snapshot);
		if (error)
			goto fail;
		*result = pending;
		return 1;
	}
	owner = kzalloc(sizeof(*owner), GFP_KERNEL);
	if (!owner) {
		error = -ENOMEM;
		goto fail;
	}
	refcount_set(&owner->references, 1);
	mutex_init(&owner->delivery);
	INIT_LIST_HEAD(&owner->retired);
	INIT_LIST_HEAD(&owner->moves);
	hash_init(owner->move_index);
	INIT_WORK(&owner->work, kasumi_notify_owner_work);
	owner->group = group;
	owner->mask = checked | FS_UNMOUNT;
	kasumi_watch_get_group(group);
	owner->visible = *visible;
	path_get(&owner->visible);
	owner->cred = get_current_cred();
	kasumi_notify_scope_capture(&owner->scope);
	__module_get(THIS_MODULE);
	atomic_inc(&kasumi_notify_owner_count);
	pending->owner = owner;
	error = kasumi_notify_snapshot_build(visible, IN_ALL_EVENTS | FS_UNMOUNT,
		&owner->scope, kasumi_rules_generation(), NULL, &pending->snapshot);
	if (error)
		goto fail;
	pending->subscription = kasumi_notify_subscription_build(owner, pending->snapshot, NULL);
	if (IS_ERR(pending->subscription)) {
		error = PTR_ERR(pending->subscription);
		pending->subscription = NULL;
		goto fail;
	}
	*result = pending;
	return 1;
fail:
	kasumi_notify_watch_complete(pending, error);
	return error;
}

KASUMI_NOCFI int kasumi_notify_watch_select(struct kasumi_notify_pending *pending,
	struct fsnotify_group *group, struct fsnotify_mark *existing)
{
	struct kasumi_notify_owner *owner;

	if (!pending)
		return 0;
	owner = pending->owner;
	if (owner->group != group || existing != pending->expected ||
	    READ_ONCE(owner->dead))
		return -EAGAIN;
	if (existing && (pending->requested & IN_MASK_ADD) &&
	    ((READ_ONCE(existing->mask) & IN_ALL_EVENTS) & ~pending->checked_mask))
		return -EAGAIN;
	pending->selected = true;
	if (existing && !pending->existing_owner) {
		owner->anchor = existing;
		kasumi_watch_get_mark(existing);
	}
	return 0;
}

KASUMI_NOCFI void kasumi_notify_watch_attached(struct kasumi_notify_pending *pending,
	struct fsnotify_mark *mark, u32 mask)
{
	struct kasumi_notify_owner *owner;
	unsigned long flags;

	if (!pending || pending->existing_owner)
		return;
	owner = pending->owner;
	if (owner->anchor)
		return;
	owner->anchor = mark;
	owner->mask = mask;
	kasumi_watch_get_mark(mark);
	owner->subscription = pending->subscription;
	pending->subscription = NULL;
	kasumi_notify_subscription_mask(owner->subscription, owner->mask, READ_ONCE(mark->flags));
	spin_lock_irqsave(&kasumi_notify_owner_lock, flags);
	owner->registered = true;
	refcount_inc(&owner->references);
	hash_add(kasumi_notify_owners, &owner->node, (unsigned long)mark);
	spin_unlock_irqrestore(&kasumi_notify_owner_lock, flags);
	/* The native anchor was attached with zero interest. Publish its mask only
	 * after the logical view is ready to filter every native delivery.
	 */
	spin_lock(&mark->lock);
	mark->mask = mask;
	if (mark->connector)
		kasumi_watch_recalc_mask(mark->connector);
	spin_unlock(&mark->lock);
}

void kasumi_notify_watch_complete(struct kasumi_notify_pending *pending, long result)
{
	struct kasumi_notify_owner *owner;
	unsigned long flags;

	if (!pending)
		return;
	owner = pending->owner;
	if (owner && pending->selected && result >= 0 && owner->anchor) {
		mutex_lock(&owner->delivery);
		mutex_lock(&owner->group->mark_mutex);
		if (!READ_ONCE(owner->dead) &&
		    (owner->anchor->flags & FSNOTIFY_MARK_FLAG_ALIVE)) {
			owner->mask = READ_ONCE(owner->anchor->mask);
			spin_lock_irqsave(&kasumi_notify_owner_lock, flags);
			if (!owner->registered) {
				owner->registered = true;
				refcount_inc(&owner->references);
				hash_add(kasumi_notify_owners, &owner->node, (unsigned long)owner->anchor);
			}
			if (!owner->subscription) {
				owner->subscription = pending->subscription;
				pending->subscription = NULL;
			}
			owner->serial++;
			spin_unlock_irqrestore(&kasumi_notify_owner_lock, flags);
			if (owner->subscription) {
				kasumi_notify_subscription_mask(owner->subscription, owner->mask,
					READ_ONCE(owner->anchor->flags));
			}
			spin_lock_irqsave(&kasumi_notify_owner_lock, flags);
			owner->dirty = true;
			owner->dirty_sequence++;
			kasumi_notify_owner_queue_locked(owner);
			spin_unlock_irqrestore(&kasumi_notify_owner_lock, flags);
		}
		mutex_unlock(&owner->group->mark_mutex);
		mutex_unlock(&owner->delivery);
	} else if (owner && !pending->existing_owner && owner->registered) {
		spin_lock_irqsave(&kasumi_notify_owner_lock, flags);
		owner->dead = true;
		kasumi_notify_owner_queue_locked(owner);
		spin_unlock_irqrestore(&kasumi_notify_owner_lock, flags);
	}
	kasumi_notify_subscription_destroy(pending->subscription);
	if (pending->snapshot)
		kasumi_notify_snapshot_put(pending->snapshot);
	if (pending->expected)
		fsnotify_put_mark(pending->expected);
	if (owner)
		kasumi_notify_owner_put(owner);
	kfree(pending);
}

static void kasumi_notify_retired_destroy(struct list_head *retired)
{
	struct kasumi_notify_subscription *subscription, *next;

	list_for_each_entry_safe(subscription, next, retired, retired) {
		list_del(&subscription->retired);
		kasumi_notify_subscription_destroy(subscription);
	}
}

static void kasumi_notify_owner_work(struct work_struct *work)
{
	struct kasumi_notify_owner *owner = container_of(work, struct kasumi_notify_owner, work);
	struct kasumi_notify_snapshot *previous = NULL, *next = NULL;
	struct kasumi_notify_subscription *replacement = NULL, *old = NULL;
	struct kasumi_notify_rename_hint *hints = NULL;
	unsigned int hint_count = 0;
	const struct cred *saved;
	unsigned long flags;
	u64 serial = 0, sequence = 0;
	bool release_registry = false, refresh = false, retry = false;
	int error = 0;
	LIST_HEAD(retired);

	mutex_lock(&owner->delivery);
	mutex_lock(&owner->group->mark_mutex);
	spin_lock_irqsave(&kasumi_notify_owner_lock, flags);
	if (owner->dead) {
		if (owner->registered) {
			hash_del(&owner->node);
			owner->registered = false;
			release_registry = true;
		}
		if (owner->subscription) {
			list_add_tail(&owner->subscription->retired, &owner->retired);
			owner->subscription = NULL;
		}
	} else if (owner->dirty && owner->subscription && !kasumi_notify_owner_stopping) {
		owner->dirty = false;
		previous = owner->subscription->snapshot;
		kasumi_notify_snapshot_get(previous);
		serial = owner->serial;
		sequence = owner->dirty_sequence;
		refresh = true;
	}
	list_splice_init(&owner->retired, &retired);
	spin_unlock_irqrestore(&kasumi_notify_owner_lock, flags);
	mutex_unlock(&owner->group->mark_mutex);
	mutex_unlock(&owner->delivery);
	kasumi_notify_retired_destroy(&retired);
	if (release_registry) {
		/* A synthetic anchor must release its inode before vnode teardown. */
		if (kasumi_vnode_is_ours(d_inode(owner->visible.dentry)))
			fsnotify_destroy_mark(owner->anchor, owner->group);
		kasumi_notify_owner_put(owner);
	}
	if (!refresh)
		goto out;
	saved = override_creds(owner->cred);
	error = kasumi_notify_snapshot_build(&owner->visible, IN_ALL_EVENTS | FS_UNMOUNT,
		&owner->scope, kasumi_rules_generation(), previous, &next);
	if (!error && kasumi_notify_snapshot_root_retired(next)) {
		struct kasumi_notify_event event = {
			.mask = FS_DELETE_SELF, .inode = d_inode(owner->visible.dentry),
		};

		revert_creds(saved);
		mutex_lock(&owner->delivery);
		kasumi_notify_owner_emit(owner, &event);
		mutex_unlock(&owner->delivery);
		fsnotify_destroy_mark(owner->anchor, owner->group);
		goto failed;
	}
	if (!error) {
		replacement = kasumi_notify_subscription_build(owner, next, owner->subscription);
		if (IS_ERR(replacement)) {
			error = PTR_ERR(replacement);
			replacement = NULL;
		}
	}
	revert_creds(saved);
	if (error)
		goto failed;
	mutex_lock(&owner->delivery);
	if (owner->move_count) {
		struct kasumi_notify_move *move;

		hints = kcalloc(owner->move_count, sizeof(*hints), GFP_KERNEL);
		if (!hints) {
			mutex_unlock(&owner->delivery);
			error = -ENOMEM;
			goto failed;
		}
		list_for_each_entry(move, &owner->moves, node)
			hints[hint_count++] = move->hint;
	}
	mutex_lock(&owner->group->mark_mutex);
	spin_lock_irqsave(&kasumi_notify_owner_lock, flags);
	if (owner->dead || kasumi_notify_owner_stopping) {
		error = -ESHUTDOWN;
	} else if (owner->serial != serial || owner->dirty_sequence != sequence) {
		error = -EAGAIN;
	} else {
		old = owner->subscription;
		owner->subscription = replacement;
		replacement = NULL;
		owner->serial++;
	}
	spin_unlock_irqrestore(&kasumi_notify_owner_lock, flags);
	if (!error) {
		kasumi_notify_subscription_mask(owner->subscription, owner->mask,
			READ_ONCE(owner->anchor->flags));
	}
	mutex_unlock(&owner->group->mark_mutex);
	if (!error)
		error = kasumi_notify_snapshot_diff(previous, next, hints, hint_count,
			kasumi_notify_owner_emit, owner);
	if (!error)
		kasumi_notify_moves_retire(owner, kasumi_notify_snapshot_generation(next));
	mutex_unlock(&owner->delivery);
	kasumi_notify_subscription_destroy(old);
failed:
	if (error && error != -ESHUTDOWN) {
		if (error != -EAGAIN)
			kasumi_notify_owner_overflow(owner);
		spin_lock_irqsave(&kasumi_notify_owner_lock, flags);
		retry = error == -EAGAIN && !owner->dead && !kasumi_notify_owner_stopping;
		if (retry) {
			owner->dirty = true;
			kasumi_notify_owner_queue_locked(owner);
		}
		spin_unlock_irqrestore(&kasumi_notify_owner_lock, flags);
	}
	kfree(hints);
	kasumi_notify_subscription_destroy(replacement);
	if (next)
		kasumi_notify_snapshot_put(next);
	kasumi_notify_snapshot_put(previous);
out:
	kasumi_notify_owner_put(owner);
}

static int kasumi_notify_owner_drop_event(struct fsnotify_mark *mark, u32 mask,
	struct inode *inode, struct inode *dir, const struct qstr *name, u32 cookie)
{
	return 0;
}

static int kasumi_notify_owner_event_pre(struct kprobe *probe, struct pt_regs *regs)
{
#ifdef CONFIG_ARM64
	struct fsnotify_mark *anchor = (void *)regs->regs[0];
	unsigned long flags;
	bool owned;

	if ((regs->regs[1] & FS_IN_IGNORED) ||
	    !atomic_read(&kasumi_notify_owner_count) || kasumi_notify_forwarding(anchor))
		return 0;
	spin_lock_irqsave(&kasumi_notify_owner_lock, flags);
	owned = kasumi_notify_owner_find_locked(anchor) != NULL;
	spin_unlock_irqrestore(&kasumi_notify_owner_lock, flags);
	if (owned) {
		instruction_pointer_set(regs, (unsigned long)kasumi_notify_owner_drop_event);
		return 1;
	}
#endif
	return 0;
}

static int kasumi_notify_owner_freeing_pre(struct kprobe *probe, struct pt_regs *regs)
{
#ifdef CONFIG_ARM64
	struct kasumi_notify_owner *owner;
	unsigned long flags;

	if (!atomic_read(&kasumi_notify_owner_count))
		return 0;
	spin_lock_irqsave(&kasumi_notify_owner_lock, flags);
	owner = kasumi_notify_owner_find_locked((void *)regs->regs[0]);
	if (owner) {
		owner->dead = true;
		kasumi_notify_owner_queue_locked(owner);
	}
	spin_unlock_irqrestore(&kasumi_notify_owner_lock, flags);
#endif
	return 0;
}

void kasumi_notify_watch_rules_changed(void)
{
	struct kasumi_notify_owner *owner;
	unsigned long flags;
	unsigned int bucket;

	if (READ_ONCE(kasumi_notify_owner_stopping) || !atomic_read(&kasumi_notify_owner_count))
		return;
	spin_lock_irqsave(&kasumi_notify_owner_lock, flags);
	hash_for_each(kasumi_notify_owners, bucket, owner, node) {
		if (owner->dead)
			continue;
		owner->dirty = true;
		owner->dirty_sequence++;
		kasumi_notify_owner_queue_locked(owner);
	}
	spin_unlock_irqrestore(&kasumi_notify_owner_lock, flags);
}

int kasumi_notify_watch_init(void)
{
	unsigned int bucket;
	int error;

	if (!READ_ONCE(kasumi_notify_owner_stopping))
		return 0;
	if (!IS_ENABLED(CONFIG_ARM64) || !IS_ENABLED(CONFIG_INOTIFY_USER))
		return -EOPNOTSUPP;
	kasumi_watch_alloc_group = (void *)kasumi_lookup_callable_quiet("fsnotify_alloc_group");
	kasumi_watch_destroy_group = (void *)kasumi_lookup_callable_quiet("fsnotify_destroy_group");
	kasumi_watch_add_mark = (void *)kasumi_lookup_callable_quiet("fsnotify_add_mark");
	kasumi_watch_get_mark = (void *)kasumi_lookup_callable_quiet("fsnotify_get_mark");
	kasumi_watch_get_group = (void *)kasumi_lookup_callable_quiet("fsnotify_get_group");
	kasumi_watch_find_mark = (void *)kasumi_lookup_callable_quiet("fsnotify_find_mark");
	kasumi_watch_recalc_mask = (void *)kasumi_lookup_callable_quiet("fsnotify_recalc_mask");
	kasumi_watch_inc_ucount = (void *)kasumi_lookup_callable_quiet("inc_ucount");
	kasumi_watch_dec_ucount = (void *)kasumi_lookup_callable_quiet("dec_ucount");
	kasumi_watch_native_event = (void *)kasumi_lookup_callable_quiet("inotify_handle_inode_event");
	kasumi_watch_insert_event = (void *)kasumi_lookup_callable_quiet("fsnotify_insert_event");
	kasumi_watch_add_event = (void *)kasumi_lookup_callable_quiet("fsnotify_add_event");
	if (!kasumi_watch_alloc_group || !kasumi_watch_destroy_group || !kasumi_watch_add_mark ||
	    !kasumi_watch_get_mark || !kasumi_watch_get_group || !kasumi_watch_find_mark ||
	    !kasumi_watch_recalc_mask || !kasumi_watch_inc_ucount || !kasumi_watch_dec_ucount ||
	    !kasumi_watch_native_event ||
	    (!kasumi_watch_insert_event && !kasumi_watch_add_event))
		return -EOPNOTSUPP;
	for (bucket = 0; bucket < ARRAY_SIZE(kasumi_notify_forward_locks); bucket++)
		spin_lock_init(&kasumi_notify_forward_locks[bucket]);
	kasumi_notify_owner_queue = alloc_workqueue("kasumi-notify", WQ_UNBOUND, 1);
	if (!kasumi_notify_owner_queue)
		return -ENOMEM;
	kasumi_notify_owner_event_probe.addr =
		(void *)kasumi_lookup_name_quiet("inotify_handle_inode_event");
	kasumi_notify_owner_event_probe.pre_handler = kasumi_notify_owner_event_pre;
	error = register_kprobe(&kasumi_notify_owner_event_probe);
	if (error)
		goto fail;
	kasumi_notify_owner_event_registered = true;
	kasumi_notify_owner_freeing_probe.addr =
		(void *)kasumi_lookup_name_quiet("inotify_freeing_mark");
	kasumi_notify_owner_freeing_probe.pre_handler = kasumi_notify_owner_freeing_pre;
	error = register_kprobe(&kasumi_notify_owner_freeing_probe);
	if (error)
		goto fail;
	kasumi_notify_owner_freeing_registered = true;
	WRITE_ONCE(kasumi_notify_owner_stopping, false);
	return 0;
fail:
	kasumi_notify_watch_stop();
	return error;
}

void kasumi_notify_watch_stop(void)
{
	struct kasumi_notify_owner *owner;
	unsigned long flags;
	unsigned int bucket;

	WRITE_ONCE(kasumi_notify_owner_stopping, true);
	spin_lock_irqsave(&kasumi_notify_owner_lock, flags);
	hash_for_each(kasumi_notify_owners, bucket, owner, node) {
		owner->dead = true;
		kasumi_notify_owner_queue_locked(owner);
	}
	spin_unlock_irqrestore(&kasumi_notify_owner_lock, flags);
	if (kasumi_notify_owner_queue)
		flush_workqueue(kasumi_notify_owner_queue);
	if (kasumi_notify_owner_freeing_registered) {
		unregister_kprobe(&kasumi_notify_owner_freeing_probe);
		kasumi_notify_owner_freeing_registered = false;
	}
	if (kasumi_notify_owner_event_registered) {
		unregister_kprobe(&kasumi_notify_owner_event_probe);
		kasumi_notify_owner_event_registered = false;
	}
	if (kasumi_notify_owner_queue) {
		destroy_workqueue(kasumi_notify_owner_queue);
		kasumi_notify_owner_queue = NULL;
	}
	WARN_ON_ONCE(atomic_read(&kasumi_notify_owner_count));
}
