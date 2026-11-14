#include <linux/err.h>
#include <linux/dirent.h>
#include <linux/fs.h>
#include <linux/fsnotify_backend.h>
#include <linux/hashtable.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/version.h>

#include "kasumi_batch.h"
#include "kasumi_dir_view.h"
#include "kasumi_notify_rules.h"
#include "kasumi_path_policy.h"
#include "kasumi_runtime.h"
#include "kasumi_vnode.h"

#define KASUMI_NOTIFY_NO_SOURCE U32_MAX
#define KASUMI_NOTIFY_TOPOLOGY_EVENTS \
	(FS_CREATE | FS_DELETE | FS_MOVED_FROM | FS_MOVED_TO | \
	 FS_DELETE_SELF | FS_MOVE_SELF | FS_UNMOUNT | FS_IN_IGNORED)

enum kasumi_notify_name_kind {
	KASUMI_NOTIFY_NAME_ABSENT,
	KASUMI_NOTIFY_NAME_BASE,
	KASUMI_NOTIFY_NAME_LEAF,
	KASUMI_NOTIFY_NAME_VIRTUAL,
	KASUMI_NOTIFY_NAME_HIDDEN,
};

struct kasumi_notify_name {
	struct list_head list;
	struct hlist_node node;
	struct hlist_node sequence_node;
	struct kasumi_dir_entry *entry;
	struct path captured_source;
	struct dentry *base_child;
	struct inode *base_inode;
	struct kasumi_notify_name *source_next;
	char *source_name;
	u64 sequence;
	u64 ino;
	u32 source_index;
	u8 type;
	enum kasumi_notify_name_kind kind;
};

struct kasumi_notify_source_record {
	struct hlist_node node;
	struct kasumi_notify_source source;
	struct kasumi_notify_name *names;
	u32 index;
};

struct kasumi_notify_snapshot {
	refcount_t refs;
	struct path visible;
	struct dentry *name_parent;
	char *visible_path;
	struct kasumi_notify_scope scope;
	u64 generation;
	u32 mask;
	u32 base_index;
	bool root_retired;
	struct list_head entries;
	struct list_head names;
	DECLARE_HASHTABLE(name_index, 8);
	DECLARE_HASHTABLE(sequence_index, 8);
	DECLARE_HASHTABLE(source_index, 8);
	struct kasumi_notify_source_record **sources;
	unsigned int source_count;
	unsigned int source_capacity;
};

struct kasumi_notify_capture {
	struct kasumi_notify_snapshot *snapshot;
	size_t visible_length;
	struct dentry **topology;
	unsigned int count;
	unsigned int capacity;
	bool counting;
	bool root_supported;
	int error;
};

void kasumi_notify_scope_capture(struct kasumi_notify_scope *scope)
{
	u64 generation;

	do {
		generation = kasumi_rules_generation();
		scope->active = kasumi_rule_scope_active();
		scope->view = kasumi_policy_current_is_view_target();
		scope->hide = kasumi_hide_scope_allowed(false, 0);
		scope->hide_storage = kasumi_hide_scope_allowed(true, 0);
		scope->hide_bypass = kasumi_hide_scope_allowed(false, KSM_RULE_BYPASS_POLICY);
	} while (generation != kasumi_rules_generation());
}

static bool notify_entry_hidden(const struct kasumi_dir_entry *entry,
	const struct kasumi_notify_scope *scope)
{
	return entry->hide &&
		(!entry->direct_rule || entry->hide_sequence >= entry->sequence) &&
		((entry->hide_flags & KSM_RULE_BYPASS_POLICY) ? scope->hide_bypass :
		 (entry->hide_storage_managed ? scope->hide_storage : scope->hide));
}

static bool notify_entry_visible(const struct kasumi_dir_entry *entry,
	const struct kasumi_notify_scope *scope)
{
	return entry->always_visible ||
		(entry->redirect && !notify_entry_hidden(entry, scope) && scope->active &&
		 (scope->view || entry->bypass_redirect ||
		  (entry->rule_flags & KSM_RULE_BYPASS_POLICY)));
}

static bool notify_prefer(bool direct, u64 sequence, bool candidate_direct,
	u64 candidate_sequence)
{
	return (!direct && candidate_direct) ||
		(direct == candidate_direct && candidate_sequence >= sequence);
}

/* Match dir_view's casefold-name coalescing before capturing observer scope. */
static void notify_merge_entry(struct kasumi_dir_entry *entry,
	const struct kasumi_dir_entry *candidate)
{
	if (notify_prefer(entry->direct_rule, entry->sequence,
		candidate->direct_rule, candidate->sequence)) {
		kasumi_identity_get(candidate->identity);
		kasumi_identity_put(entry->identity);
		entry->identity = candidate->identity;
		entry->sequence = candidate->sequence;
		entry->direct_rule = candidate->direct_rule;
		entry->ino = candidate->ino;
		entry->type = candidate->type;
		entry->rule_flags = candidate->rule_flags;
		entry->redirect = candidate->redirect;
	}
	if (candidate->bypass_redirect &&
	    (!entry->bypass_redirect || notify_prefer(entry->bypass_direct_rule,
		entry->bypass_sequence, candidate->bypass_direct_rule,
		candidate->bypass_sequence))) {
		kasumi_identity_get(candidate->bypass_identity);
		kasumi_identity_put(entry->bypass_identity);
		entry->bypass_identity = candidate->bypass_identity;
		entry->bypass_sequence = candidate->bypass_sequence;
		entry->bypass_direct_rule = candidate->bypass_direct_rule;
		entry->bypass_ino = candidate->bypass_ino;
		entry->bypass_type = candidate->bypass_type;
		entry->bypass_redirect = true;
	}
	if (candidate->hide &&
	    (!entry->hide || candidate->hide_sequence >= entry->hide_sequence)) {
		entry->hide = true;
		entry->hide_flags = candidate->hide_flags;
		entry->hide_sequence = candidate->hide_sequence;
		entry->hide_storage_managed = candidate->hide_storage_managed;
	}
}

static struct kasumi_notify_name *notify_name_find(
	const struct kasumi_notify_snapshot *snapshot, const struct qstr *query)
{
	struct kasumi_notify_name *name;
	u32 hash;
	int error;

	error = kasumi_dir_name_hash(snapshot->name_parent, query->name, query->len, &hash);
	if (error)
		return ERR_PTR(error);
	hash_for_each_possible(snapshot->name_index, name, node, hash) {
		struct kasumi_dir_entry *entry = name->entry;

		if (entry->name_hash == hash && kasumi_dir_name_equal(snapshot->name_parent,
			entry->name_dentry, entry->name, entry->name_len,
			query->name, query->len))
			return name;
	}
	return NULL;
}

static int notify_source_add(struct kasumi_notify_snapshot *snapshot,
	enum kasumi_notify_source_kind kind, const struct path *path,
	struct dentry *topology, u32 *result)
{
	struct kasumi_notify_source_record *record;
	struct inode *inode = d_inode(kind == KASUMI_NOTIFY_SOURCE_TOPOLOGY ? topology : path->dentry);
	struct vfsmount *mount = kind == KASUMI_NOTIFY_SOURCE_TOPOLOGY ? NULL : path->mnt;
	unsigned long key = (unsigned long)inode ^ ((unsigned long)mount >> 4) ^ kind;

	if (!inode)
		return -ENOENT;
	hash_for_each_possible(snapshot->source_index, record, node, key) {
		const struct kasumi_notify_source *source = &record->source;

		if (source->kind != kind)
			continue;
		if (kind == KASUMI_NOTIFY_SOURCE_TOPOLOGY ?
		    d_inode(source->topology) == d_inode(topology) :
		    source->path.mnt == path->mnt &&
		    d_inode(source->path.dentry) == d_inode(path->dentry)) {
			*result = record->index;
			return 0;
		}
	}
	if (snapshot->source_count == snapshot->source_capacity) {
		struct kasumi_notify_source_record **sources;
		unsigned int capacity = snapshot->source_capacity ?
			snapshot->source_capacity * 2 : 8;

		if (capacity < snapshot->source_capacity)
			return -EOVERFLOW;
		sources = kcalloc(capacity, sizeof(*sources), GFP_KERNEL);
		if (!sources)
			return -ENOMEM;
		if (snapshot->source_count)
			memcpy(sources, snapshot->sources, snapshot->source_count * sizeof(*sources));
		kfree(snapshot->sources);
		snapshot->sources = sources;
		snapshot->source_capacity = capacity;
	}
	record = kzalloc(sizeof(*record), GFP_KERNEL);
	if (!record)
		return -ENOMEM;
	record->source.kind = kind;
	if (kind == KASUMI_NOTIFY_SOURCE_TOPOLOGY) {
		record->source.topology = dget(topology);
	} else {
		record->source.path = *path;
		path_get(&record->source.path);
	}
	*result = snapshot->source_count;
	record->index = snapshot->source_count;
	snapshot->sources[snapshot->source_count++] = record;
	hash_add(snapshot->source_index, &record->node, key);
	return 0;
}

static int notify_name_add(struct kasumi_notify_snapshot *snapshot,
	struct kasumi_dir_entry *entry)
{
	struct kasumi_notify_name *name;
	struct qstr query = QSTR_INIT(entry->name, entry->name_len);
	int error;

	error = kasumi_dir_name_hash(snapshot->name_parent, entry->name,
		entry->name_len, &entry->name_hash);
	if (error)
		return error;
	name = notify_name_find(snapshot, &query);
	if (IS_ERR(name))
		return PTR_ERR(name);
	if (name) {
		LIST_HEAD(discard);

		notify_merge_entry(name->entry, entry);
		list_move(&entry->list, &discard);
		kasumi_dir_entries_free(&discard);
		return 0;
	}
	if (!entry->name_dentry)
		entry->name_dentry = kasumi_dir_name_probe(snapshot->name_parent,
			entry->name, entry->name_len);
	if (IS_ERR(entry->name_dentry)) {
		error = PTR_ERR(entry->name_dentry);
		entry->name_dentry = NULL;
		return error;
	}
	name = kzalloc(sizeof(*name), GFP_KERNEL);
	if (!name)
		return -ENOMEM;
	name->entry = entry;
	name->source_index = KASUMI_NOTIFY_NO_SOURCE;
	list_add_tail(&name->list, &snapshot->names);
	hash_add(snapshot->name_index, &name->node, entry->name_hash);
	return 0;
}

static void notify_select_names(struct kasumi_notify_snapshot *snapshot)
{
	struct kasumi_notify_name *name;

	list_for_each_entry(name, &snapshot->names, list) {
		struct kasumi_dir_entry *entry = name->entry;
		bool bypass = !snapshot->scope.view && entry->bypass_redirect;

		if (notify_entry_hidden(entry, &snapshot->scope)) {
			name->kind = KASUMI_NOTIFY_NAME_HIDDEN;
			continue;
		}
		if (!notify_entry_visible(entry, &snapshot->scope))
			continue;
		name->ino = bypass ? entry->bypass_ino : entry->ino;
		name->type = bypass ? entry->bypass_type : entry->type;
		name->sequence = bypass ? entry->bypass_sequence : entry->sequence;
		if (bypass ? entry->bypass_direct_rule : entry->direct_rule) {
			name->kind = KASUMI_NOTIFY_NAME_LEAF;
			hash_add(snapshot->sequence_index, &name->sequence_node, name->sequence);
		} else {
			name->kind = KASUMI_NOTIFY_NAME_VIRTUAL;
		}
	}
}

static bool notify_rule_supports_root(const struct kasumi_notify_capture *capture,
	const char *path)
{
	return path &&
		!strncmp(path, capture->snapshot->visible_path, capture->visible_length) &&
		(!path[capture->visible_length] || capture->visible_length == 1 ||
		 path[capture->visible_length] == '/');
}

/* Rule index callback. All memory is prepared before its RCU/read-lock section. */
static void notify_capture_rule(struct kasumi_rule_lifetime *life, void *data)
{
	struct kasumi_notify_capture *capture = data;
	struct kasumi_notify_snapshot *snapshot = capture->snapshot;

	if (capture->error)
		return;
	if (life->batch_store == KASUMI_BATCH_PATH) {
		struct kasumi_entry *entry = container_of(life, struct kasumi_entry, life);
		struct kasumi_notify_name *name;

		if (capture->counting) {
			capture->root_supported |= notify_rule_supports_root(capture,
				entry->src);
			return;
		}
		hash_for_each_possible(snapshot->sequence_index, name, sequence_node, entry->sequence) {
			if (name->sequence != entry->sequence || name->captured_source.dentry)
				continue;
			if (entry->source_nofollow_path_valid)
				name->captured_source = entry->source_nofollow_path;
			else if (entry->source_path_valid)
				name->captured_source = entry->source_path;
			else {
				capture->error = -EAGAIN;
				return;
			}
			path_get(&name->captured_source);
		}
	}
	if (life->batch_store == KASUMI_BATCH_MERGE) {
		struct kasumi_merge_entry *merge = container_of(life, struct kasumi_merge_entry, life);

		if (capture->counting)
			capture->root_supported |= notify_rule_supports_root(capture,
				merge->src) || notify_rule_supports_root(capture, merge->resolved_src);
		if (!merge->target_dentry || !snapshot->scope.active ||
		    (!snapshot->scope.view && !(merge->rule_flags & KSM_RULE_BYPASS_POLICY)))
			return;
		if (capture->counting) {
			if (capture->count == U32_MAX)
				capture->error = -EOVERFLOW;
			else
				capture->count++;
		} else if (capture->count == capture->capacity) {
			capture->error = -EAGAIN;
		} else {
			capture->topology[capture->count++] = dget(merge->target_dentry);
		}
	}
}

static int notify_capture_sources(struct kasumi_notify_snapshot *snapshot)
{
	struct kasumi_notify_capture capture = {
		.snapshot = snapshot,
		.visible_length = strlen(snapshot->visible_path),
		.counting = true,
	};
	unsigned int index;
	int error;

	kasumi_rule_dependencies(snapshot->visible_path, snapshot->generation,
		notify_capture_rule, &capture);
	if (capture.error)
		return capture.error;
	snapshot->root_retired = snapshot->base_index == KASUMI_NOTIFY_NO_SOURCE &&
		!capture.root_supported;
	capture.capacity = capture.count;
	capture.topology = kcalloc(capture.capacity, sizeof(*capture.topology), GFP_KERNEL);
	if (capture.capacity && !capture.topology)
		return -ENOMEM;
	capture.count = 0;
	capture.counting = false;
	kasumi_rule_dependencies(snapshot->visible_path, snapshot->generation,
		notify_capture_rule, &capture);
	error = capture.error;
	for (index = 0; index < capture.count; index++) {
		u32 source_index;

		if (!error)
			error = notify_source_add(snapshot, KASUMI_NOTIFY_SOURCE_TOPOLOGY,
				NULL, capture.topology[index], &source_index);
		dput(capture.topology[index]);
	}
	kfree(capture.topology);
	return error;
}

static int notify_capture_leaf(struct kasumi_notify_snapshot *snapshot,
	struct kasumi_notify_name *name)
{
	struct dentry *dentry = name->captured_source.dentry;
	struct dentry *parent;
	struct kasumi_notify_source_record *source;
	u32 topology_index;
	int error;

	if (!dentry || !name->captured_source.mnt || !d_inode(dentry))
		return -EAGAIN;
	name->source_name = kmalloc(NAME_MAX + 1, GFP_KERNEL);
	if (!name->source_name)
		return -ENOMEM;
	parent = dget_parent(dentry);
	spin_lock(&dentry->d_lock);
	if (dentry->d_parent != parent || dentry->d_name.len > NAME_MAX) {
		spin_unlock(&dentry->d_lock);
		dput(parent);
		return -EAGAIN;
	}
	memcpy(name->source_name, dentry->d_name.name, dentry->d_name.len);
	name->source_name[dentry->d_name.len] = '\0';
	spin_unlock(&dentry->d_lock);
	error = notify_source_add(snapshot, KASUMI_NOTIFY_SOURCE_TOPOLOGY,
		NULL, parent, &topology_index);
	dput(parent);
	if (error)
		return error;
	error = notify_source_add(snapshot, KASUMI_NOTIFY_SOURCE_LEAF,
		&name->captured_source, NULL, &name->source_index);
	if (error)
		return error;
	source = snapshot->sources[name->source_index];
	name->source_next = source->names;
	source->names = name;
	return 0;
}

static KASUMI_NOCFI int notify_capture_base_child(struct kasumi_notify_snapshot *snapshot,
	struct kasumi_notify_name *name)
{
	const struct path *base;
	struct inode *parent;
	struct inode *inode;
	struct dentry *child;
	struct kasumi_internal_vfs_guard guard;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	struct qstr query = QSTR_INIT(name->entry->name, name->entry->name_len);
#endif

	if (snapshot->base_index == KASUMI_NOTIFY_NO_SOURCE)
		return 0;
	if (!kasumi_lookup_one)
		return -EOPNOTSUPP;
	base = &snapshot->sources[snapshot->base_index]->source.path;
	parent = d_inode(base->dentry);
	if (!parent || !S_ISDIR(parent->i_mode))
		return -ENOTDIR;
	kasumi_vfs_internal_enter(&guard);
	inode_lock(parent);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	child = kasumi_lookup_one(mnt_idmap(base->mnt), &query, base->dentry);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	child = kasumi_lookup_one(mnt_idmap(base->mnt), name->entry->name,
		base->dentry, name->entry->name_len);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
	child = kasumi_lookup_one(mnt_user_ns(base->mnt), name->entry->name,
		base->dentry, name->entry->name_len);
#else
	child = kasumi_lookup_one(name->entry->name, base->dentry, name->entry->name_len);
#endif
	inode_unlock(parent);
	kasumi_vfs_internal_leave(&guard);
	if (IS_ERR(child))
		return PTR_ERR(child);
	name->base_child = child;
	inode = d_inode(child);
	if (inode) {
		name->base_inode = igrab(inode);
		if (!name->base_inode)
			return -EAGAIN;
	}
	if (name->kind == KASUMI_NOTIFY_NAME_ABSENT && inode)
		name->kind = KASUMI_NOTIFY_NAME_BASE;
	/* Virtual ancestors inherit an existing base directory in vnode lookup.
	 * Subscribe to that directory's own events, while its grandchildren remain
	 * outside this watch and namespace changes wait for the refreshed view.
	 */
	if (name->kind == KASUMI_NOTIFY_NAME_VIRTUAL && inode && S_ISDIR(inode->i_mode)) {
		name->captured_source.mnt = base->mnt;
		name->captured_source.dentry = child;
		path_get(&name->captured_source);
		name->kind = KASUMI_NOTIFY_NAME_LEAF;
		name->ino = inode->i_ino;
	}
	return 0;
}

void kasumi_notify_snapshot_get(struct kasumi_notify_snapshot *snapshot)
{
	if (snapshot)
		refcount_inc(&snapshot->refs);
}

void kasumi_notify_snapshot_put(struct kasumi_notify_snapshot *snapshot)
{
	struct kasumi_notify_name *name, *next;
	unsigned int index;

	if (!snapshot || !refcount_dec_and_test(&snapshot->refs))
		return;
	list_for_each_entry_safe(name, next, &snapshot->names, list) {
		if (name->captured_source.dentry)
			path_put(&name->captured_source);
		iput(name->base_inode);
		dput(name->base_child);
		kfree(name->source_name);
		kfree(name);
	}
	kasumi_dir_entries_free(&snapshot->entries);
	for (index = 0; index < snapshot->source_count; index++) {
		struct kasumi_notify_source *source = &snapshot->sources[index]->source;

		if (source->kind == KASUMI_NOTIFY_SOURCE_TOPOLOGY)
			dput(source->topology);
		else
			path_put(&source->path);
		kfree(snapshot->sources[index]);
	}
	kfree(snapshot->sources);
	if (snapshot->visible.dentry)
		path_put(&snapshot->visible);
	kfree(snapshot->visible_path);
	kfree(snapshot);
}

static KASUMI_NOCFI int notify_prepare_location(struct kasumi_notify_snapshot *snapshot)
{
	struct inode *inode = d_inode(snapshot->visible.dentry);
	const struct path *base = &snapshot->visible;
	const char *visible_path;
	char *buffer = NULL;
	int error = 0;

	if (kasumi_vnode_is_ours(inode)) {
		struct kasumi_vnode_info *info = inode->i_private;

		if (!info || !info->visible_path)
			return -EOPNOTSUPP;
		visible_path = info->visible_path;
		base = info->source.dentry ? &info->source : NULL;
	} else {
		if (!kasumi_d_absolute_path)
			return -EOPNOTSUPP;
		buffer = kmalloc(PATH_MAX, GFP_KERNEL);
		if (!buffer)
			return -ENOMEM;
		visible_path = kasumi_d_absolute_path(&snapshot->visible, buffer, PATH_MAX);
		if (IS_ERR(visible_path)) {
			error = PTR_ERR(visible_path);
			goto out;
		}
	}
	snapshot->visible_path = kstrdup(visible_path, GFP_KERNEL);
	if (!snapshot->visible_path) {
		error = -ENOMEM;
		goto out;
	}
	snapshot->name_parent = base ? base->dentry : snapshot->visible.dentry;
	if (base)
		error = notify_source_add(snapshot, KASUMI_NOTIFY_SOURCE_BASE,
			base, NULL, &snapshot->base_index);
out:
	kfree(buffer);
	return error;
}

KASUMI_NOCFI int kasumi_notify_snapshot_build(const struct path *visible, u32 mask,
	const struct kasumi_notify_scope *scope, u64 generation,
	const struct kasumi_notify_snapshot *previous,
	struct kasumi_notify_snapshot **result)
{
	struct kasumi_notify_snapshot *snapshot;
	struct kasumi_dir_entry *entry, *next;
	struct kasumi_notify_name *name;
	u64 collected_generation;
	int error;

	*result = NULL;
	if (!visible || !visible->dentry || !visible->mnt || !scope ||
	    !d_inode(visible->dentry) || !S_ISDIR(d_inode(visible->dentry)->i_mode))
		return -ENOTDIR;
	if (generation != kasumi_rules_generation())
		return -EAGAIN;
	snapshot = kzalloc(sizeof(*snapshot), GFP_KERNEL);
	if (!snapshot)
		return -ENOMEM;
	refcount_set(&snapshot->refs, 1);
	INIT_LIST_HEAD(&snapshot->entries);
	INIT_LIST_HEAD(&snapshot->names);
	hash_init(snapshot->name_index);
	hash_init(snapshot->sequence_index);
	hash_init(snapshot->source_index);
	snapshot->base_index = KASUMI_NOTIFY_NO_SOURCE;
	snapshot->visible = *visible;
	path_get(&snapshot->visible);
	snapshot->scope = *scope;
	if (!kasumi_config_enabled())
		memset(&snapshot->scope, 0, sizeof(snapshot->scope));
	snapshot->generation = generation;
	snapshot->mask = mask;
	error = notify_prepare_location(snapshot);
	if (error)
		goto fail;
	error = kasumi_rule_vpath_collect(NULL, &snapshot->entries,
		&collected_generation, snapshot->visible_path);
	if (error)
		goto fail;
	if (collected_generation != generation) {
		error = -EAGAIN;
		goto fail;
	}
	list_for_each_entry_safe(entry, next, &snapshot->entries, list) {
		error = notify_name_add(snapshot, entry);
		if (error)
			goto fail;
	}
	if (previous) {
		list_for_each_entry(name, &previous->names, list) {
			struct qstr query = QSTR_INIT(name->entry->name, name->entry->name_len);
			struct kasumi_notify_name *existing;

			/* A former rule's base-only comparison key expires after one diff. */
			if (!name->entry->redirect && !name->entry->bypass_redirect && !name->entry->hide)
				continue;
			existing = notify_name_find(snapshot, &query);
			if (IS_ERR(existing)) {
				error = PTR_ERR(existing);
				goto fail;
			}
			if (existing)
				continue;
			entry = kasumi_dir_entry_alloc(query.name, query.len, GFP_KERNEL);
			if (!entry) {
				error = -ENOMEM;
				goto fail;
			}
			list_add_tail(&entry->list, &snapshot->entries);
			error = notify_name_add(snapshot, entry);
			if (error)
				goto fail;
		}
	}
	notify_select_names(snapshot);
	error = notify_capture_sources(snapshot);
	if (error)
		goto fail;
	list_for_each_entry(name, &snapshot->names, list) {
		error = notify_capture_base_child(snapshot, name);
		if (error)
			goto fail;
		if (name->kind == KASUMI_NOTIFY_NAME_LEAF) {
			error = notify_capture_leaf(snapshot, name);
			if (error)
				goto fail;
			if (previous) {
				struct qstr query = QSTR_INIT(name->entry->name, name->entry->name_len);
				struct kasumi_notify_name *old = notify_name_find(previous, &query);

				if (IS_ERR(old)) {
					error = PTR_ERR(old);
					goto fail;
				}
				/* A source rename precedes publication of its materialized rule.
				 * Keep that rule's original name until its winner is replaced.
				 */
				if (old && old->kind == KASUMI_NOTIFY_NAME_LEAF &&
				    old->sequence == name->sequence && old->source_name &&
				    d_inode(old->captured_source.dentry) == d_inode(name->captured_source.dentry))
					strscpy(name->source_name, old->source_name, NAME_MAX + 1);
			}
		}
	}
	if (generation != kasumi_rules_generation()) {
		error = -EAGAIN;
		goto fail;
	}
	*result = snapshot;
	return 0;
fail:
	kasumi_notify_snapshot_put(snapshot);
	return error;
}

u64 kasumi_notify_snapshot_generation(const struct kasumi_notify_snapshot *snapshot)
{
	return snapshot->generation;
}

bool kasumi_notify_snapshot_root_retired(const struct kasumi_notify_snapshot *snapshot)
{
	return snapshot->root_retired;
}

unsigned int kasumi_notify_snapshot_source_count(const struct kasumi_notify_snapshot *snapshot)
{
	return snapshot->source_count;
}

const struct kasumi_notify_source *kasumi_notify_snapshot_source(
	const struct kasumi_notify_snapshot *snapshot, unsigned int index)
{
	return index < snapshot->source_count ? &snapshot->sources[index]->source : NULL;
}

static int notify_emit(const struct kasumi_notify_snapshot *snapshot, u32 mask,
	struct inode *inode, const struct qstr *name, u32 cookie,
	kasumi_notify_emit_fn emit, void *data)
{
	struct kasumi_notify_event event = {
		.mask = mask,
		.cookie = cookie,
		.inode = inode,
		.named = name != NULL,
	};

	if (!(mask & snapshot->mask & ALL_FSNOTIFY_EVENTS))
		return 0;
	if (name)
		event.name = *name;
	return emit(data, &event);
}

int kasumi_notify_snapshot_project(const struct kasumi_notify_snapshot *snapshot,
	unsigned int source_index, u32 mask, struct inode *inode, struct inode *dir,
	const struct qstr *query, u32 cookie, bool *refresh,
	kasumi_notify_emit_fn emit, void *data)
{
	const struct kasumi_notify_source_record *source;
	struct kasumi_notify_name *name;
	int error;

	(void)dir;
	*refresh = false;
	if (source_index >= snapshot->source_count || !emit)
		return -EINVAL;
	source = snapshot->sources[source_index];
	if (mask & KASUMI_NOTIFY_TOPOLOGY_EVENTS)
		*refresh = true;
	if (source->source.kind == KASUMI_NOTIFY_SOURCE_TOPOLOGY)
		return 0;
	if (source->source.kind == KASUMI_NOTIFY_SOURCE_BASE) {
		if (query && query->len) {
			name = notify_name_find(snapshot, query);
			if (IS_ERR(name))
				return PTR_ERR(name);
			if (name && name->kind != KASUMI_NOTIFY_NAME_BASE &&
			    name->kind != KASUMI_NOTIFY_NAME_ABSENT)
				return 0;
		}
		return notify_emit(snapshot, mask & ~FS_IN_IGNORED, inode, query, cookie, emit, data);
	}
	/* A directory leaf is one child of the watched directory. Events from its
	 * own children belong to a deeper watch. Topology waits for live publication.
	 */
	if ((query && query->len) || (mask & KASUMI_NOTIFY_TOPOLOGY_EVENTS))
		return 0;
	for (name = source->names; name; name = name->source_next) {
		struct qstr visible_name = QSTR_INIT(name->entry->name, name->entry->name_len);

		error = notify_emit(snapshot, mask | FS_EVENT_ON_CHILD, inode,
			&visible_name, cookie, emit, data);
		if (error)
			return error;
	}
	return 0;
}

struct kasumi_notify_visible_name {
	enum kasumi_notify_name_kind kind;
	struct inode *inode;
	u64 ino;
	u8 type;
};

static struct kasumi_notify_visible_name notify_visible_name(
	const struct kasumi_notify_name *name, const struct kasumi_notify_name *fallback)
{
	struct kasumi_notify_visible_name visible = {};
	struct inode *inode;

	/* Ungoverned native changes already passed through the base mark. Compare
	 * their current base state when a rule starts or stops covering the name.
	 */
	if (!name || (fallback && (name->kind == KASUMI_NOTIFY_NAME_BASE ||
				  name->kind == KASUMI_NOTIFY_NAME_ABSENT))) {
		inode = fallback ? fallback->base_inode : NULL;
		if (inode) {
			visible.kind = KASUMI_NOTIFY_NAME_BASE;
			visible.inode = inode;
			visible.ino = inode->i_ino;
			visible.type = (inode->i_mode & S_IFMT) >> 12;
		}
		return visible;
	}
	visible.kind = name->kind;
	if (name->kind == KASUMI_NOTIFY_NAME_HIDDEN)
		visible.kind = KASUMI_NOTIFY_NAME_ABSENT;
	if (name->kind == KASUMI_NOTIFY_NAME_LEAF)
		visible.inode = d_inode(name->captured_source.dentry);
	if (name->kind == KASUMI_NOTIFY_NAME_BASE)
		visible.inode = name->base_inode;
	visible.ino = name->ino;
	visible.type = name->type;
	if (visible.kind == KASUMI_NOTIFY_NAME_BASE && visible.inode) {
		visible.ino = visible.inode->i_ino;
		visible.type = (visible.inode->i_mode & S_IFMT) >> 12;
	}
	return visible;
}

static bool notify_same_visible(struct kasumi_notify_visible_name left,
	struct kasumi_notify_visible_name right)
{
	/* Adding a virtual descendant preserves an existing native directory. */
	if ((left.kind == KASUMI_NOTIFY_NAME_BASE && right.kind == KASUMI_NOTIFY_NAME_LEAF) ||
	    (right.kind == KASUMI_NOTIFY_NAME_BASE && left.kind == KASUMI_NOTIFY_NAME_LEAF))
		return left.inode == right.inode && left.ino == right.ino && left.type == right.type;
	if (left.kind != right.kind)
		return false;
	/* Native base changes were already delivered by the directory mark. */
	if (left.kind == KASUMI_NOTIFY_NAME_BASE || left.kind == KASUMI_NOTIFY_NAME_ABSENT)
		return true;
	return left.inode == right.inode && left.ino == right.ino && left.type == right.type;
}

static bool notify_hint_matches(const struct kasumi_notify_name *name,
	const struct kasumi_notify_rename_hint *hint, bool old)
{
	const struct qstr *source_name = old ? &hint->old_name : &hint->new_name;

	return name && name->kind == KASUMI_NOTIFY_NAME_LEAF && hint->cookie &&
		d_inode(name->captured_source.dentry) == hint->inode && name->source_name &&
		strlen(name->source_name) == source_name->len &&
		!memcmp(name->source_name, source_name->name, source_name->len);
}

static const struct kasumi_notify_name *notify_unique_hint(
	const struct kasumi_notify_snapshot *snapshot,
	const struct kasumi_notify_rename_hint *hint, bool old)
{
	struct kasumi_notify_name *name;
	const struct kasumi_notify_name *found = NULL;

	list_for_each_entry(name, &snapshot->names, list) {
		if (!notify_hint_matches(name, hint, old))
			continue;
		if (found)
			return NULL;
		found = name;
	}
	return found;
}

static u32 notify_rename_cookie(const struct kasumi_notify_snapshot *previous,
	const struct kasumi_notify_snapshot *next, const struct kasumi_notify_name *name,
	const struct kasumi_notify_rename_hint *hints, size_t hint_count, bool old)
{
	size_t index;

	for (index = 0; index < hint_count; index++) {
		const struct kasumi_notify_name *from, *to;
		struct kasumi_notify_name *other;
		struct qstr query;

		if (!notify_hint_matches(name, &hints[index], old))
			continue;
		from = notify_unique_hint(previous, &hints[index], true);
		to = notify_unique_hint(next, &hints[index], false);
		/* A move can enter or leave the watched source set. The observed
		 * native half supplies its cookie independently of a second watch.
		 */
		if (old && !hints[index].new_name.len && from == name)
			return hints[index].cookie;
		if (!old && !hints[index].old_name.len && to == name)
			return hints[index].cookie;
		if (!from || !to || (old ? from : to) != name)
			continue;
		query.name = from->entry->name;
		query.len = from->entry->name_len;
		other = notify_name_find(next, &query);
		if (IS_ERR(other) || other == to ||
		    notify_same_visible(notify_visible_name(from, NULL),
				 notify_visible_name(other, NULL)))
			continue;
		query.name = to->entry->name;
		query.len = to->entry->name_len;
		other = notify_name_find(previous, &query);
		if (IS_ERR(other) ||
		    notify_same_visible(notify_visible_name(other, to),
				 notify_visible_name(to, NULL)))
			continue;
		return hints[index].cookie;
	}
	return 0;
}

int kasumi_notify_snapshot_diff(const struct kasumi_notify_snapshot *previous,
	const struct kasumi_notify_snapshot *next,
	const struct kasumi_notify_rename_hint *hints, size_t hint_count,
	kasumi_notify_emit_fn emit, void *data)
{
	struct kasumi_notify_name *name;
	unsigned int pass;

	if (!previous || !next || !emit || (hint_count && !hints))
		return -EINVAL;
	/* next was built with previous, so its names contain the union. Finish
	 * removals before additions to preserve MOVED_FROM/MOVED_TO ordering.
	 */
	for (pass = 0; pass < 2; pass++) {
		list_for_each_entry(name, &next->names, list) {
			struct qstr query = QSTR_INIT(name->entry->name, name->entry->name_len);
			struct kasumi_notify_name *old = notify_name_find(previous, &query);
			struct kasumi_notify_visible_name before, after, selected;
			u32 cookie, mask;
			int error;

			if (IS_ERR(old))
				return PTR_ERR(old);
			before = notify_visible_name(old, name);
			after = notify_visible_name(name, NULL);
			selected = pass ? after : before;
			if (notify_same_visible(before, after) ||
			    selected.kind == KASUMI_NOTIFY_NAME_ABSENT)
				continue;
			cookie = notify_rename_cookie(previous, next, pass ? name : old,
				hints, hint_count, !pass);
			mask = pass ? (cookie ? FS_MOVED_TO : FS_CREATE) :
				(cookie ? FS_MOVED_FROM : FS_DELETE);
			mask |= FS_EVENT_ON_CHILD;
			if (selected.type == DT_DIR)
				mask |= FS_ISDIR;
			error = notify_emit(next, mask, selected.inode, &query, cookie, emit, data);
			if (error)
				return error;
		}
	}
	return 0;
}
