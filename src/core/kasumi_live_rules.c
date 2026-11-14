#include <linux/cred.h>
#include <linux/fs_struct.h>
#include <linux/hashtable.h>
#include <linux/list_sort.h>
#include <linux/rbtree.h>
#include <linux/namei.h>
#include <linux/nsproxy.h>
#include <linux/refcount.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#include "kasumi_base.h"
#include "kasumi_batch.h"
#include "kasumi_hide_events.h"
#include "kasumi_hide_rules.h"
#include "kasumi_dirhijack.h"
#include "kasumi_overlay.h"
#include "kasumi_store.h"
#include "kasumi_live_rules.h"
#include "kasumi_path_policy.h"
#include "kasumi_runtime.h"
#include "kasumi_transaction.h"

struct kasumi_live_scope {
	struct list_head node;
	refcount_t refs;
	struct fs_struct *fs;
	const struct cred *cred;
	struct mnt_namespace *namespace;
	struct kasumi_hide_events events;
	char *cwd;
};

struct kasumi_live_prefix {
	struct rb_node node;
	const char *path;
	struct kasumi_live_rule *rule;
	bool linked;
};

struct kasumi_live_rule {
	struct list_head node;
	struct list_head removal;
	struct list_head dirty;
	struct list_head materialized;
	struct list_head replay;
	struct list_head xattr;
	struct kasumi_live_prefix prefixes[2];
	struct kasumi_live_rule *previous;
	u64 sequence;
	struct hlist_node hash;
	struct kasumi_live_scope *scope;
	struct kasumi_hide_watch *watches;
	char *visible;
	char *visible_absolute;
	char *source;
	char *source_canonical;
	char *visible_canonical;
	size_t bytes;
	u32 key;
	u32 flags;
	unsigned int command;
};

struct kasumi_live_batch {
	struct list_head additions;
	struct list_head removals;
	DECLARE_HASHTABLE(index, 10);
	unsigned int count;
	size_t bytes;
};

static LIST_HEAD(live_scopes);
static LIST_HEAD(live_rules);
static LIST_HEAD(live_dirty_rules);
static LIST_HEAD(live_xattrs);
static struct rb_root live_prefixes = RB_ROOT;
static u64 live_sequence;
static DEFINE_SPINLOCK(live_dirty_lock);
static atomic64_t live_scope_dirty = ATOMIC64_INIT(0);
static s64 live_scope_applied;
static DEFINE_HASHTABLE(live_index, 10);
static struct workqueue_struct *live_workqueue;
static struct work_struct live_work;
static atomic64_t live_dirty = ATOMIC64_INIT(0);
static unsigned int live_count;
static size_t live_bytes;
static bool live_running;
static int live_error;
static struct kasumi_live_rule *live_record;
static struct task_struct *live_record_owner;
static struct kasumi_live_scope *live_replay_scope;
static struct kasumi_live_rule *live_replay_original;
static struct fs_struct *(*live_copy_fs)(struct fs_struct *);
static void (*live_free_fs)(struct fs_struct *);
static char *(*live_d_path)(const struct path *, const struct path *, char *, int);

static void live_notify(void *unused)
{
	atomic64_inc(&live_scope_dirty);
	atomic64_inc(&live_dirty);
	if (READ_ONCE(live_running))
		queue_work(live_workqueue, &live_work);
}

static void live_rule_notify(void *data)
{
	struct kasumi_live_rule *rule = data;
	unsigned long flags;

	spin_lock_irqsave(&live_dirty_lock, flags);
	if (list_empty(&rule->dirty))
		list_add_tail(&rule->dirty, &live_dirty_rules);
	atomic64_inc(&live_dirty);
	spin_unlock_irqrestore(&live_dirty_lock, flags);
	if (READ_ONCE(live_running))
		queue_work(live_workqueue, &live_work);
}

static void KASUMI_NOCFI live_fs_put(struct fs_struct *fs)
{
	bool release;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	read_seqlock_excl(&fs->seq);
#else
	spin_lock(&fs->lock);
#endif
	release = --fs->users == 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	read_sequnlock_excl(&fs->seq);
#else
	spin_unlock(&fs->lock);
#endif
	if (release)
		live_free_fs(fs);
}

static void live_scope_put(struct kasumi_live_scope *scope)
{
	if (!scope || !refcount_dec_and_test(&scope->refs))
		return;
	list_del(&scope->node);
	kasumi_hide_events_stop(&scope->events);
	kasumi_hide_events_close(&scope->events);
	live_fs_put(scope->fs);
	put_cred(scope->cred);
	kfree(scope->cwd);
	kfree(scope);
}

static struct kasumi_live_scope *KASUMI_NOCFI live_scope_get(bool needs_cwd)
{
	struct kasumi_internal_vfs_guard guard;
	struct kasumi_live_scope *scope, *existing;
	int error;

	if (live_replay_scope) {
		refcount_inc(&live_replay_scope->refs);
		return live_replay_scope;
	}
	scope = kzalloc(sizeof(*scope), GFP_KERNEL);
	if (!scope)
		return ERR_PTR(-ENOMEM);
	scope->fs = live_copy_fs(current->fs);
	if (!scope->fs) {
		kfree(scope);
		return ERR_PTR(-ENOMEM);
	}
	if (!needs_cwd) {
		path_put(&scope->fs->pwd);
		scope->fs->pwd = scope->fs->root;
		path_get(&scope->fs->pwd);
	}
	scope->cred = get_current_cred();
	scope->namespace = current->nsproxy->mnt_ns;
	list_for_each_entry(existing, &live_scopes, node) {
		if (existing->cred == scope->cred &&
		    existing->namespace == scope->namespace &&
		    path_equal(&existing->fs->root, &scope->fs->root) &&
		    path_equal(&existing->fs->pwd, &scope->fs->pwd)) {
			refcount_inc(&existing->refs);
			live_fs_put(scope->fs);
			put_cred(scope->cred);
			kfree(scope);
			return existing;
		}
	}
	kasumi_vfs_internal_enter(&guard);
	error = kasumi_hide_events_open_scope(&scope->events,
		&scope->fs->root, scope->cred, live_notify, NULL);
	kasumi_vfs_internal_leave(&guard);
	if (error)
		goto fail;
	refcount_set(&scope->refs, 1);
	list_add_tail(&scope->node, &live_scopes);
	return scope;
fail:
	live_fs_put(scope->fs);
	put_cred(scope->cred);
	kfree(scope->cwd);
	kfree(scope);
	return ERR_PTR(error);
}

static char *KASUMI_NOCFI live_absolute(struct kasumi_live_scope *scope,
				      const char *name)
{
	char *buffer, *text;
	int error = 0;

	if (*name == '/')
		return kstrdup(name, GFP_KERNEL);
	{
		kfree(scope->cwd);
		scope->cwd = NULL;
		buffer = kmalloc(PATH_MAX, GFP_KERNEL);
		if (!buffer)
			return ERR_PTR(-ENOMEM);
		text = live_d_path(&scope->fs->pwd, &scope->fs->root, buffer, PATH_MAX);
		if (IS_ERR_OR_NULL(text)) {
			error = text ? PTR_ERR(text) : -EXDEV;
		} else {
			scope->cwd = kstrdup(text, GFP_KERNEL);
			if (!scope->cwd)
				error = -ENOMEM;
		}
		kfree(buffer);
		if (error)
			return ERR_PTR(error);
	}
	return kasprintf(GFP_KERNEL, "%s/%s", scope->cwd, name);
}

static void live_prefix_link(struct kasumi_live_rule *rule)
{
	unsigned int slot;

	for (slot = 0; slot < ARRAY_SIZE(rule->prefixes); slot++) {
		struct kasumi_live_prefix *prefix = &rule->prefixes[slot];
		struct rb_node **link = &live_prefixes.rb_node, *parent = NULL;

		prefix->path = slot ? rule->visible_canonical : rule->visible_absolute;
		prefix->rule = rule;
		if (!prefix->path)
			continue;
		while (*link) {
			struct kasumi_live_prefix *other = rb_entry(*link, struct kasumi_live_prefix, node);
			int order = strcmp(prefix->path, other->path);

			if (!order)
				order = (unsigned long)prefix < (unsigned long)other ? -1 : 1;
			parent = *link;
			link = order < 0 ? &parent->rb_left : &parent->rb_right;
		}
		rb_link_node(&prefix->node, parent, link);
		rb_insert_color(&prefix->node, &live_prefixes);
		prefix->linked = true;
	}
	if (rule->command == KSM_IOC_HIDE_OVERLAY_XATTRS)
		list_add_tail(&rule->xattr, &live_xattrs);
}

static void live_prefix_unlink(struct kasumi_live_rule *rule)
{
	unsigned int slot;

	for (slot = 0; slot < ARRAY_SIZE(rule->prefixes); slot++) {
		struct kasumi_live_prefix *prefix = &rule->prefixes[slot];

		if (prefix->linked) {
			rb_erase(&prefix->node, &live_prefixes);
			prefix->linked = false;
		}
	}
}

static void live_rule_free(struct kasumi_live_rule *rule)
{
	struct kasumi_rule_lifetime *life, *next;
	unsigned long flags;

	kasumi_hide_events_unwatch(rule->watches);
	spin_lock_irqsave(&live_dirty_lock, flags);
	list_del_init(&rule->dirty);
	spin_unlock_irqrestore(&live_dirty_lock, flags);
	list_del_init(&rule->replay);
	list_del_init(&rule->xattr);
	live_prefix_unlink(rule);
	list_for_each_entry_safe(life, next, &rule->materialized, live_node) {
		list_del_init(&life->live_node);
		life->live_rule = NULL;
	}
	live_scope_put(rule->scope);
	kfree(rule->visible);
	kfree(rule->visible_absolute);
	kfree(rule->source);
	kfree(rule->source_canonical);
	kfree(rule->visible_canonical);
	kfree(rule);
}

static int live_watch(struct kasumi_live_rule *rule, const char *name,
		      bool directory)
{
	struct kasumi_internal_vfs_guard guard;
	struct path resolved = {};
	char *path, *leaf;
	bool owned_leaf = false;
	int error;

	path = live_absolute(rule->scope, name);
	if (IS_ERR_OR_NULL(path))
		return path ? PTR_ERR(path) : -ENOMEM;
	if (strlen(path) >= PATH_MAX) {
		kfree(path);
		return -ENAMETOOLONG;
	}
	if (directory) {
		leaf = "";
	} else {
		leaf = strrchr(path, '/');
		/* Every relative name above has acquired an absolute prefix. */
		if (leaf == path) {
			leaf = kstrdup(leaf + 1, GFP_KERNEL);
			if (!leaf) {
				kfree(path);
				return -ENOMEM;
			}
			owned_leaf = true;
			path[1] = '\0';
		} else {
			*leaf++ = '\0';
		}
	}
	kasumi_vfs_internal_enter(&guard);
	error = kasumi_hide_events_watch_path(&rule->scope->events, path, leaf,
		&resolved, &rule->watches, live_rule_notify, rule);
	kasumi_vfs_internal_leave(&guard);
	if (resolved.dentry)
		path_put(&resolved);
	if (owned_leaf)
		kfree(leaf);
	kfree(path);
	return error;
}

static bool live_missing(int error)
{
	return error == -ENOENT || error == -ENOTDIR;
}

/* A final symlink can be retargeted to a missing name outside its lexical
 * parent. Subscribe to that target's existing ancestors as well. */
static char *KASUMI_NOCFI live_link_target(const char *name)
{
	struct delayed_call done = {};
	struct path path, parent;
	const char *link;
	char *prefix, *end, *buffer, *base, *expanded = NULL;
	int error = 0;

	prefix = kstrdup(name, GFP_KERNEL);
	buffer = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!prefix || !buffer) {
		error = -ENOMEM;
		goto out;
	}
	end = prefix;
	while (*end) {
		char saved;

		while (*end == '/')
			end++;
		end = strchrnul(end, '/');
		saved = *end;
		*end = '\0';
		error = kasumi_kern_path(prefix, 0, &path);
		*end = saved;
		if (error)
			break;
		if (!d_is_symlink(path.dentry)) {
			path_put(&path);
			continue;
		}
		link = kasumi_vfs_get_link(path.dentry, &done);
		if (IS_ERR(link)) {
			error = PTR_ERR(link);
		} else if (!link) {
			error = -EOPNOTSUPP;
		} else if (*link == '/') {
			expanded = kasprintf(GFP_KERNEL, "%s%s", link, end);
		} else {
			parent = path;
			parent.dentry = dget_parent(path.dentry);
			base = kasumi_d_path(&parent, buffer, PATH_MAX);
			if (IS_ERR(base))
				error = PTR_ERR(base);
			else
				expanded = kasprintf(GFP_KERNEL, "%s/%s%s", base, link, end);
			dput(parent.dentry);
		}
		do_delayed_call(&done);
		path_put(&path);
		if (!expanded && !error)
			error = -ENOMEM;
		break;
	}
out:
	kfree(prefix);
	kfree(buffer);
	if (live_missing(error))
		error = 0;
	return error ? ERR_PTR(error) : expanded;
}

static int live_watch_missing_links(struct kasumi_live_rule *rule,
				    const char *name)
{
	char *path = kstrdup(name, GFP_KERNEL), *target;
	int error = 0, links;

	if (!path)
		return -ENOMEM;
	for (links = 0; links < 40; links++) {
		target = live_link_target(path);
		if (IS_ERR_OR_NULL(target)) {
			error = target ? PTR_ERR(target) : 0;
			break;
		}
		kfree(path);
		path = target;
		error = live_watch(rule, path, false);
		if (error && !live_missing(error) && error != -EOPNOTSUPP)
			break;
	}
	if (links == 40)
		error = -ELOOP;
	kfree(path);
	return error;
}

static int KASUMI_NOCFI live_watch_resolved(struct kasumi_live_rule *rule,
	const char *name, const char *previous, char **canonical)
{
	struct kasumi_internal_vfs_guard guard;
	struct path path;
	char *buffer, *text;
	int error;

	kasumi_vfs_internal_enter(&guard);
	error = kasumi_kern_path(name, LOOKUP_FOLLOW, &path);
	if (!error) {
		buffer = kmalloc(PATH_MAX, GFP_KERNEL);
		if (!buffer) {
			error = -ENOMEM;
		} else {
			text = kasumi_d_path(&path, buffer, PATH_MAX);
			if (IS_ERR(text)) {
				error = PTR_ERR(text);
			} else {
				*canonical = kstrdup(text, GFP_KERNEL);
				error = *canonical ? 0 : -ENOMEM;
			}
			kfree(buffer);
		}
		path_put(&path);
	} else if (live_missing(error)) {
		*canonical = previous ? kstrdup(previous, GFP_KERNEL) : NULL;
		error = previous && !*canonical ? -ENOMEM : 0;
		if (!error && live_replay_original)
			error = live_watch_missing_links(rule, name);
	}
	kasumi_vfs_internal_leave(&guard);
	if (error || !*canonical)
		return error;
	rule->bytes += strlen(*canonical) + 1;
	if (!strcmp(*canonical, name))
		return 0;
	error = live_watch(rule, *canonical, false);
	return live_missing(error) ? 0 : error;
}

static bool live_same_operation(const struct kasumi_live_rule *left,
				const struct kasumi_live_rule *right)
{
	if (left->key != right->key || strcmp(left->visible, right->visible))
		return false;
	if (left->command == KSM_IOC_ADD_MERGE_RULE ||
	    right->command == KSM_IOC_ADD_MERGE_RULE)
		return left->command == right->command &&
		       !strcmp(left->source, right->source);
	if (left->command == KSM_IOC_HIDE_OVERLAY_XATTRS ||
	    right->command == KSM_IOC_HIDE_OVERLAY_XATTRS)
		return left->command == right->command;
	return true;
}

static void live_remove_later(struct kasumi_live_batch *batch,
			      struct kasumi_live_rule *rule)
{
	if (!list_empty(&rule->removal))
		return;
	list_add_tail(&rule->removal, &batch->removals);
	batch->count--;
	batch->bytes -= rule->bytes;
}

struct kasumi_live_batch *kasumi_live_rules_begin(void)
{
	struct kasumi_live_batch *batch;

	if (!kasumi_live_rules_available())
		return NULL;
	batch = kzalloc(sizeof(*batch), GFP_KERNEL);
	if (!batch)
		return ERR_PTR(-ENOMEM);
	INIT_LIST_HEAD(&batch->additions);
	INIT_LIST_HEAD(&batch->removals);
	hash_init(batch->index);
	batch->count = live_count;
	batch->bytes = live_bytes;
	return batch;
}

int kasumi_live_rules_record(struct kasumi_live_batch *batch,
	unsigned int command, const char *visible, const char *source, u32 flags)
{
	struct kasumi_live_rule *rule, *other;
	struct hlist_node *next;
	int error;

	if (!batch)
		return 0;
	if (command == KSM_IOC_HIDE_OVERLAY_XATTRS && visible && !*visible) {
		kasumi_live_rules_clear_xattrs(batch);
		return 0;
	}
	if (command != KSM_IOC_ADD_RULE && command != KSM_IOC_ADD_MERGE_RULE)
		source = NULL;
	if (!visible || !*visible ||
	    ((command == KSM_IOC_ADD_RULE || command == KSM_IOC_ADD_MERGE_RULE) &&
	     (!source || !*source)))
		return -EINVAL;
	rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule)
		return -ENOMEM;
	INIT_LIST_HEAD(&rule->removal);
	INIT_LIST_HEAD(&rule->dirty);
	INIT_LIST_HEAD(&rule->materialized);
	INIT_LIST_HEAD(&rule->replay);
	INIT_LIST_HEAD(&rule->xattr);
	if (!live_replay_original && live_sequence == U64_MAX) {
		live_rule_free(rule);
		return -EOVERFLOW;
	}
	rule->previous = live_replay_original;
	rule->sequence = live_replay_original ? live_replay_original->sequence : ++live_sequence;
	rule->visible = kstrdup(visible, GFP_KERNEL);
	rule->source = source ? kstrdup(source, GFP_KERNEL) : NULL;
	rule->command = command;
	rule->flags = flags;
	rule->key = full_name_hash(NULL, visible, strlen(visible));
	rule->bytes = sizeof(*rule) + strlen(visible) + 1;
	if (source)
		rule->bytes += strlen(source) + 1;
	if (!rule->visible || (source && !rule->source)) {
		error = -ENOMEM;
		goto fail;
	}
	rule->scope = live_scope_get(visible[0] != '/' || (source && source[0] != '/'));
	if (IS_ERR(rule->scope)) {
		error = PTR_ERR(rule->scope);
		rule->scope = NULL;
		goto fail;
	}
	rule->visible_absolute = live_absolute(rule->scope, visible);
	if (IS_ERR_OR_NULL(rule->visible_absolute)) {
		error = rule->visible_absolute ? PTR_ERR(rule->visible_absolute) : -ENOMEM;
		rule->visible_absolute = NULL;
		goto fail;
	}
	rule->bytes += strlen(rule->visible_absolute) + 1;
	error = live_watch(rule, visible, false);
	if (error && !live_missing(error) && error != -EOPNOTSUPP)
		goto fail;
	if (source) {
		error = live_watch(rule, source, false);
		if (error && !live_missing(error) && error != -EOPNOTSUPP)
			goto fail;
	}
	error = live_watch_resolved(rule, visible,
		live_replay_original ? live_replay_original->visible_canonical : NULL,
		&rule->visible_canonical);
	if (error)
		goto fail;
	if (source) {
		error = live_watch_resolved(rule, source,
			live_replay_original ? live_replay_original->source_canonical : NULL,
			&rule->source_canonical);
		if (error)
			goto fail;
	}
	hash_for_each_possible(live_index, other, hash, rule->key) {
		if (live_same_operation(other, rule))
			live_remove_later(batch, other);
	}
	hash_for_each_possible_safe(batch->index, other, next, hash, rule->key) {
		if (!live_same_operation(other, rule))
			continue;
		hash_del(&other->hash);
		list_del(&other->node);
		batch->count--;
		batch->bytes -= other->bytes;
		live_rule_free(other);
	}
	if (batch->count >= KSM_TX_MAX_OPERATIONS ||
	    rule->bytes > KSM_TX_MAX_BYTES - batch->bytes) {
		error = -E2BIG;
		goto fail;
	}
	batch->count++;
	batch->bytes += rule->bytes;
	list_add_tail(&rule->node, &batch->additions);
	hash_add(batch->index, &rule->hash, rule->key);
	live_record = rule;
	live_record_owner = current;
	return 0;
fail:
	live_rule_free(rule);
	return error;
}

void kasumi_live_rules_track(struct kasumi_rule_lifetime *life)
{
	INIT_LIST_HEAD(&life->live_node);
	life->live_rule = live_record_owner == current ? live_record : NULL;
	if (life->live_rule)
		list_add_tail(&life->live_node, &life->live_rule->materialized);
}

void kasumi_live_rules_untrack(struct kasumi_rule_lifetime *life)
{
	if (life->live_node.next)
		list_del_init(&life->live_node);
	life->live_rule = NULL;
}

void kasumi_live_rules_end_record(void)
{
	if (live_record_owner != current)
		return;
	live_record = NULL;
	live_record_owner = NULL;
}

int kasumi_live_rules_watch_merge_dir(const char *source)
{
	if (live_record_owner != current || !live_record)
		return 0;
	return live_watch(live_record, source, true);
}

static void live_clear_batch(struct kasumi_live_batch *batch, bool xattrs_only)
{
	struct kasumi_live_rule *rule, *next;

	if (!batch)
		return;
	list_for_each_entry(rule, &live_rules, node) {
		if (!xattrs_only || rule->command == KSM_IOC_HIDE_OVERLAY_XATTRS)
			live_remove_later(batch, rule);
	}
	list_for_each_entry_safe(rule, next, &batch->additions, node) {
		if (xattrs_only && rule->command != KSM_IOC_HIDE_OVERLAY_XATTRS)
			continue;
		list_del(&rule->node);
		hash_del(&rule->hash);
		batch->count--;
		batch->bytes -= rule->bytes;
		live_rule_free(rule);
	}
}

void kasumi_live_rules_clear_paths(struct kasumi_live_batch *batch)
{
	live_clear_batch(batch, false);
}

void kasumi_live_rules_clear_xattrs(struct kasumi_live_batch *batch)
{
	live_clear_batch(batch, true);
}

void kasumi_live_rules_finish(struct kasumi_live_batch *batch, bool publish)
{
	struct kasumi_live_rule *rule, *next;

	if (!batch)
		return;
	kasumi_live_rules_end_record();
	list_for_each_entry_safe(rule, next, &batch->additions, node) {
		list_del(&rule->node);
		hash_del(&rule->hash);
		if (publish) {
			list_add_tail(&rule->node, rule->previous ? &rule->previous->node : &live_rules);
			rule->previous = NULL;
			live_prefix_link(rule);
			hash_add(live_index, &rule->hash, rule->key);
		} else {
			live_rule_free(rule);
		}
	}
	list_for_each_entry_safe(rule, next, &batch->removals, removal) {
		list_del_init(&rule->removal);
		if (publish) {
			list_del(&rule->node);
			hash_del(&rule->hash);
			live_rule_free(rule);
		}
	}
	if (publish) {
		WRITE_ONCE(live_count, batch->count);
		live_bytes = batch->bytes;
	}
	kfree(batch);
}

static int KASUMI_NOCFI live_parent_ready(struct kasumi_live_rule *rule)
{
	struct path parent = {};
	char *visible, *slash;
	int error;

	visible = live_absolute(rule->scope, rule->visible);
	if (IS_ERR_OR_NULL(visible))
		return visible ? PTR_ERR(visible) : -ENOMEM;
	error = kasumi_rule_projected_parent(visible, kasumi_batch_generation(), &parent);
	if (parent.dentry)
		path_put(&parent);
	if (error > 0) {
		error = 0;
	} else if (!error) {
		slash = strrchr(visible, '/');
		if (slash == visible)
			slash[1] = '\0';
		else
			*slash = '\0';
		error = kasumi_kern_path(visible, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &parent);
		if (!error)
			path_put(&parent);
	}
	kfree(visible);
	return error;
}

static int KASUMI_NOCFI live_replay_ready(struct kasumi_live_rule *rule)
{
	const char *required = rule->source;
	struct path source;
	int error;

	if (rule->command == KSM_IOC_HIDE_OVERLAY_XATTRS)
		required = rule->visible;
	if (required) {
		error = kasumi_kern_path(required, LOOKUP_FOLLOW, &source);
		if (error)
			return error;
		path_put(&source);
	}
	if (rule->command == KSM_IOC_ADD_RULE ||
	    rule->command == KSM_IOC_ADD_MERGE_RULE ||
	    rule->command == KSM_IOC_HIDE_RULE)
		return live_parent_ready(rule);
	return 0;
}

static int KASUMI_NOCFI live_replay_rule(struct kasumi_live_rule *rule)
{
	struct kasumi_internal_vfs_guard guard;
	struct fs_struct *original, *fs;
	const struct cred *cred;
	int error = 0;

	fs = live_copy_fs(rule->scope->fs);
	if (!fs)
		return -ENOMEM;
	task_lock(current);
	original = current->fs;
	current->fs = fs;
	task_unlock(current);
	cred = override_creds(rule->scope->cred);
	live_replay_scope = rule->scope;
	live_replay_original = rule;
	kasumi_vfs_internal_enter(&guard);
	error = live_replay_ready(rule);
	if (live_missing(error)) {
		error = kasumi_live_rules_record(kasumi_batch_live(), rule->command,
			rule->visible, rule->source, rule->flags);
		kasumi_live_rules_end_record();
		if (!error) {
			int ready = live_replay_ready(rule);

			/* A source can appear between the first miss and subscribing
			 * to its newly existing parent. Recheck after subscribing. */
			if (!ready)
				error = -EAGAIN;
			else if (!live_missing(ready))
				error = ready;
		}
	} else if (!error) {
		error = kasumi_apply_path_rule(rule->command, rule->visible,
					     rule->source, rule->flags);
	}
	kasumi_vfs_internal_leave(&guard);
	live_replay_scope = NULL;
	live_replay_original = NULL;
	revert_creds(cred);
	task_lock(current);
	current->fs = original;
	task_unlock(current);
	live_fs_put(fs);
	return error;
}

static const char *live_materialized_path(struct kasumi_rule_lifetime *life)
{
	if (life->batch_store == KASUMI_BATCH_PATH)
		return container_of(life, struct kasumi_entry, life)->src;
	if (life->batch_store == KASUMI_BATCH_HIDE)
		return container_of(life, struct kasumi_hide_entry, life)->path;
	if (life->batch_store == KASUMI_BATCH_MERGE)
		return container_of(life, struct kasumi_merge_entry, life)->src;
	return NULL;
}

static void live_select_rule(struct kasumi_live_rule *rule, struct list_head *replay)
{
	if (rule && list_empty(&rule->replay))
		list_add_tail(&rule->replay, replay);
}

static void live_select_materialized(struct kasumi_rule_lifetime *life, void *data)
{
	live_select_rule(life->live_rule, data);
}

static struct kasumi_live_prefix *live_prefix_first(const char *path, size_t length,
						   bool descendants)
{
	struct rb_node *node = live_prefixes.rb_node;
	struct kasumi_live_prefix *first = NULL;

	while (node) {
		struct kasumi_live_prefix *prefix = rb_entry(node, struct kasumi_live_prefix, node);
		int order = strncmp(prefix->path, path, length);

		if (!order && descendants && length != 1)
			order = (unsigned char)prefix->path[length] - '/';
		if (order < 0) {
			node = node->rb_right;
		} else {
			first = prefix;
			node = node->rb_left;
		}
	}
	return first;
}

static struct kasumi_live_prefix *live_prefix_next(struct kasumi_live_prefix *prefix)
{
	struct rb_node *node = rb_next(&prefix->node);

	return node ? rb_entry(node, struct kasumi_live_prefix, node) : NULL;
}

static void live_select_path(struct list_head *replay, const char *path)
{
	struct kasumi_live_prefix *prefix;
	size_t length, component;

	if (!path || path[0] != '/')
		return;
	length = strlen(path);
	for (component = 1; component <= length; component++) {
		if (component != 1 && component != length && path[component] != '/')
			continue;
		for (prefix = live_prefix_first(path, component, false);
		     prefix && !strncmp(prefix->path, path, component) && !prefix->path[component];
		     prefix = live_prefix_next(prefix))
			live_select_rule(prefix->rule, replay);
	}
	for (prefix = live_prefix_first(path, length, true);
	     prefix && !strncmp(prefix->path, path, length) &&
	     (length == 1 || prefix->path[length] == '/');
	     prefix = live_prefix_next(prefix))
		live_select_rule(prefix->rule, replay);
	kasumi_rule_dependencies(path, kasumi_rules_generation(), live_select_materialized, replay);
}

static int live_replay_order(void *unused,
	const struct list_head *left, const struct list_head *right)
{
	const struct kasumi_live_rule *a = container_of(left, struct kasumi_live_rule, replay);
	const struct kasumi_live_rule *b = container_of(right, struct kasumi_live_rule, replay);

	(void)unused;
	return a->sequence > b->sequence;
}

static int live_replay_order_legacy(void *unused,
	struct list_head *left, struct list_head *right)
{
	return live_replay_order(unused, left, right);
}

static bool live_select_dependencies(struct list_head *replay)
{
	struct kasumi_live_rule *rule, *xattr;
	bool xattrs = false;

	/* Appending newly discovered rules extends this walk to a fixed point. */
	list_for_each_entry(rule, replay, replay) {
		struct kasumi_rule_lifetime *life;

		live_select_path(replay, rule->visible_absolute);
		live_select_path(replay, rule->visible_canonical);
		list_for_each_entry(life, &rule->materialized, live_node)
			live_select_path(replay, live_materialized_path(life));
		if (rule->command == KSM_IOC_HIDE_OVERLAY_XATTRS && !xattrs) {
			xattrs = true;
			list_for_each_entry(xattr, &live_xattrs, xattr)
				live_select_rule(xattr, replay);
		}
	}
	/* Android backports the const comparator independently of kernel version.
	 * Select the actual declared ABI so indirect CFI checks see the right type.
	 */
	list_sort(NULL, replay, __builtin_choose_expr(
		__same_type(typeof(&list_sort),
			    void (*)(void *, struct list_head *, typeof(&live_replay_order))),
		live_replay_order, live_replay_order_legacy));
	return xattrs;
}

static int live_clear_rule(struct kasumi_live_rule *rule)
{
	struct kasumi_rule_lifetime *life;
	u64 generation = kasumi_batch_generation();
	int error;

	list_for_each_entry(life, &rule->materialized, live_node) {
		const char *path = live_materialized_path(life);

		if (!path || !kasumi_rule_visible(life, generation))
			continue;
		if (life->batch_store != KASUMI_BATCH_MERGE) {
			error = kasumi_dirhijack_batch_del(kasumi_batch_dir(), path);
			if (error && error != -ENOENT)
				return error;
		}
		mutex_lock(&kasumi_config_mutex);
		kasumi_batch_expire(life, life->batch_store);
		mutex_unlock(&kasumi_config_mutex);
	}
	return 0;
}

static void live_prune_rule(struct kasumi_live_rule *rule)
{
	struct kasumi_rule_lifetime *life;

	list_for_each_entry(life, &rule->materialized, live_node) {
		const char *path = live_materialized_path(life);

		if (!path)
			continue;
		if (life->batch_store == KASUMI_BATCH_MERGE) {
			struct kasumi_merge_entry *merge = container_of(life, struct kasumi_merge_entry, life);

			kasumi_prune_inject_dir(path);
			if (merge->resolved_src)
				kasumi_prune_inject_dir(merge->resolved_src);
		} else {
			kasumi_prune_inject_parent(path);
		}
	}
}

static int live_rebuild(void)
{
	LIST_HEAD(pending);
	LIST_HEAD(replay);
	struct kasumi_live_rule *rule, *next;
	struct kasumi_batch *batch;
	unsigned long flags;
	bool all, xattrs;
	int error = 0;
	s64 epoch = atomic64_read(&live_dirty);
	s64 scope_epoch = atomic64_read(&live_scope_dirty);

	spin_lock_irqsave(&live_dirty_lock, flags);
	list_splice_init(&live_dirty_rules, &pending);
	spin_unlock_irqrestore(&live_dirty_lock, flags);
	all = scope_epoch != live_scope_applied;
	if (all) {
		list_for_each_entry(rule, &live_rules, node)
			live_select_rule(rule, &replay);
	} else {
		list_for_each_entry(rule, &pending, dirty)
			live_select_rule(rule, &replay);
	}
	if (list_empty(&replay))
		return 0;
	xattrs = live_select_dependencies(&replay);
	batch = kasumi_batch_begin();
	if (IS_ERR(batch)) {
		error = PTR_ERR(batch);
		goto restore;
	}
	if (all) {
		error = kasumi_batch_clear_paths();
	} else {
		if (xattrs)
			error = kasumi_batch_clear_xattrs();
		if (!error) {
			list_for_each_entry(rule, &replay, replay) {
				error = live_clear_rule(rule);
				if (error)
					break;
			}
		}
	}
	if (!error) {
		list_for_each_entry(rule, &replay, replay) {
			error = live_replay_rule(rule);
			if (error)
				break;
			cond_resched();
		}
	}
	if (!error && !all) {
		list_for_each_entry(rule, &replay, replay)
			live_prune_rule(rule);
	}
	if (!error && epoch != atomic64_read(&live_dirty))
		error = -EAGAIN;
	kasumi_batch_finish(batch, !error);
	if (!error && all)
		live_scope_applied = scope_epoch;
restore:
	list_for_each_entry_safe(rule, next, &replay, replay)
		list_del_init(&rule->replay);
	/* Failed transactions retain their original rule references and queue
	 * membership. A later event retries without allocating in the callback. */
	spin_lock_irqsave(&live_dirty_lock, flags);
	list_splice_tail_init(&pending, &live_dirty_rules);
	spin_unlock_irqrestore(&live_dirty_lock, flags);
	return error;
}

static void live_worker(struct work_struct *work)
{
	struct kasumi_live_scope *scope;
	s64 epoch;
	int attempt, error = 0;

	mutex_lock(&kasumi_mutation_mutex);
	if (!live_running || list_empty(&live_rules))
		goto out;
	epoch = atomic64_read(&live_dirty);
	list_for_each_entry(scope, &live_scopes, node) {
		error = kasumi_hide_events_ack(&scope->events);
		if (error < 0)
			goto done;
	}
	for (attempt = 0; attempt < 3; attempt++) {
		error = live_rebuild();
		if (!live_missing(error) && error != -EAGAIN)
			break;
	}
done:
	WRITE_ONCE(live_error, error);
	/* A later event retries a failed generation. Only events arriving during
	 * this attempt schedule another run, so ENOMEM cannot cause a busy loop. */
	if (epoch != atomic64_read(&live_dirty))
		queue_work(live_workqueue, &live_work);
out:
	mutex_unlock(&kasumi_mutation_mutex);
}

bool kasumi_live_rules_available(void)
{
	return READ_ONCE(live_running);
}

unsigned int kasumi_live_rules_count(void)
{
	return READ_ONCE(live_count);
}

int kasumi_live_rules_error(void)
{
	return READ_ONCE(live_error);
}

void kasumi_live_rules_clear(void)
{
	struct kasumi_live_rule *rule, *next;

	list_for_each_entry_safe(rule, next, &live_rules, node) {
		list_del(&rule->node);
		hash_del(&rule->hash);
		live_rule_free(rule);
	}
	WRITE_ONCE(live_count, 0);
	live_bytes = 0;
	WRITE_ONCE(live_error, 0);
}

int kasumi_live_rules_init(void)
{
	live_copy_fs = (void *)kasumi_lookup_callable("copy_fs_struct");
	live_free_fs = (void *)kasumi_lookup_callable("free_fs_struct");
	live_d_path = (void *)kasumi_lookup_callable("__d_path");
	if (!live_copy_fs || !live_free_fs || !live_d_path || !kasumi_vfs_get_link ||
	    !kasumi_kern_path || !kasumi_d_path || !kasumi_hide_events_supported())
		return -EOPNOTSUPP;
	INIT_WORK(&live_work, live_worker);
	live_workqueue = alloc_ordered_workqueue("kasumi_live", WQ_MEM_RECLAIM);
	if (!live_workqueue)
		return -ENOMEM;
	WRITE_ONCE(live_running, true);
	return 0;
}

void kasumi_live_rules_stop(void)
{
	struct kasumi_live_scope *scope;

	mutex_lock(&kasumi_mutation_mutex);
	WRITE_ONCE(live_running, false);
	list_for_each_entry(scope, &live_scopes, node)
		kasumi_hide_events_stop(&scope->events);
	mutex_unlock(&kasumi_mutation_mutex);
	if (live_workqueue)
		cancel_work_sync(&live_work);
}

bool kasumi_live_rules_quiesce(void)
{
	struct kasumi_live_scope *scope;

	WRITE_ONCE(live_running, false);
	list_for_each_entry(scope, &live_scopes, node)
		kasumi_hide_events_stop(&scope->events);
	if (!live_workqueue)
		return true;
	cancel_work(&live_work);
	return !work_busy(&live_work);
}

void kasumi_live_rules_exit(void)
{
	kasumi_live_rules_stop();
	mutex_lock(&kasumi_mutation_mutex);
	kasumi_live_rules_clear();
	mutex_unlock(&kasumi_mutation_mutex);
	if (live_workqueue)
		destroy_workqueue(live_workqueue);
	live_workqueue = NULL;
}
