#include <linux/err.h>
#include <linux/fs_struct.h>
#include <linux/hashtable.h>
#include <linux/mnt_namespace.h>
#include <linux/mutex.h>
#include <linux/nsproxy.h>
#include <linux/overflow.h>
#include <linux/refcount.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/seq_file.h>
#include <linux/seqlock.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/stat.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <fs/mount.h>

#include "kasumi_fake_mountinfo.h"
#include "kasumi_mount_view.h"
#include "kasumi_path_policy.h"
#include "kasumi_runtime.h"
#ifdef KASUMI_EMBEDDED
#include "feature/kernel_umount.h"
#include "policy/allowlist.h"
#endif

struct kasumi_mount_unique_index {
	u64 id;
	u32 record;
};

struct kasumi_mount_view {
	struct hlist_node cache_node;
	struct list_head cache_list;
	refcount_t refs;
	struct kasumi_mount_view *data_owner;
	bool metadata_only;
	struct mnt_namespace *ns;
	struct path root;
	u64 namespace_id;
	u64 root_mount_id;
	u64 root_ino;
	dev_t root_dev;
	u32 root_inode_generation;
	unsigned int root_sequence;
	char *root_name;
	struct kasumi_mount_record *records;
	struct kasumi_mount_unique_index *unique;
	u32 *groups;
	u32 group_count;
	u32 count;
	u64 event;
	unsigned int rename_sequence;
	u64 rules_generation;
	u64 policy_generation;
	u64 generation;
	size_t bytes;
};

static DEFINE_HASHTABLE(kasumi_mount_cache, 8);
static LIST_HEAD(kasumi_mount_cache_list);
static DEFINE_MUTEX(kasumi_mount_cache_lock);
static size_t kasumi_mount_cache_bytes;
#define KASUMI_MOUNT_CACHE_BYTES (4 * 1024 * 1024)
static atomic64_t kasumi_mount_generation = ATOMIC64_INIT(0);
static atomic64_t kasumi_mount_capabilities = ATOMIC64_INIT(0);
static atomic_t kasumi_mount_owned = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(kasumi_mount_wait);
static bool kasumi_mount_ready;
static struct rw_semaphore *kasumi_mount_namespace_lock;
static seqlock_t *kasumi_mount_rename_lock;
static typeof(copy_mnt_ns) *kasumi_mount_get_ns;
static typeof(put_mnt_ns) *kasumi_mount_put_ns;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
static void (*kasumi_mount_release_passive)(struct mnt_namespace *);
static void (*kasumi_mount_release_passive_rcu)(struct rcu_head *);
#endif
static int (*kasumi_mount_show_info)(struct seq_file *, struct vfsmount *);
static char *(*kasumi_mount_root_name)(struct dentry *, char *, int);

static KASUMI_NOCFI bool kasumi_mount_namespace_get(struct mnt_namespace *ns)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	return refcount_inc_not_zero(&ns->passive);
#else
	return kasumi_mount_get_ns(0, ns, NULL, NULL) == ns;
#endif
}

static KASUMI_NOCFI void kasumi_mount_namespace_put(struct mnt_namespace *ns)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	if (kasumi_mount_release_passive)
		kasumi_mount_release_passive(ns);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	else
		kasumi_mount_release_passive_rcu(&ns->ns.ns_rcu);
#endif
#else
	kasumi_mount_put_ns(ns);
#endif
}

static KASUMI_NOCFI void kasumi_mount_free(struct kasumi_mount_view *view)
{
	bool handle = !view->metadata_only;

	if (handle) {
		path_put(&view->root);
		kasumi_mount_namespace_put(view->ns);
	}
	if (view->data_owner) {
		kasumi_mount_view_put(view->data_owner);
	} else {
		kvfree(view->unique);
		kvfree(view->groups);
		kvfree(view->records);
		kfree(view->root_name);
	}
	kfree(view);
	if (handle && atomic_dec_and_test(&kasumi_mount_owned))
		wake_up_all(&kasumi_mount_wait);
}

void kasumi_mount_view_get_ref(struct kasumi_mount_view *view)
{
	if (view)
		refcount_inc(&view->refs);
}

void kasumi_mount_view_put(struct kasumi_mount_view *view)
{
	if (view && refcount_dec_and_test(&view->refs))
		kasumi_mount_free(view);
}

bool kasumi_mount_view_current(const struct kasumi_mount_view *view)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	if (!view || !READ_ONCE(view->ns->nr_mounts))
		return false;
#endif
	return view && !read_seqretry(kasumi_mount_rename_lock, view->rename_sequence) &&
		view->event == READ_ONCE(view->ns->event) &&
		view->rules_generation == kasumi_rules_generation() &&
		view->policy_generation == kasumi_fake_mi_policy_generation();
}

static struct mount *kasumi_mount_next(struct mount *mount, struct mount *root)
{
	if (!list_empty(&mount->mnt_mounts))
		return list_first_entry(&mount->mnt_mounts, struct mount, mnt_child);
	while (mount != root) {
		if (!list_is_last(&mount->mnt_child, &mount->mnt_parent->mnt_mounts))
			return list_next_entry(mount, mnt_child);
		mount = mount->mnt_parent;
	}
	return NULL;
}

static int kasumi_mount_compare(const void *left, const void *right)
{
	const struct kasumi_mount_record *a = left, *b = right;

	return (a->id > b->id) - (a->id < b->id);
}

static int kasumi_mount_unique_compare(const void *left, const void *right)
{
	const struct kasumi_mount_unique_index *a = left, *b = right;

	return (a->id > b->id) - (a->id < b->id);
}

struct kasumi_mount_group_field {
	size_t start;
	size_t end;
	u32 id;
};

static int kasumi_mount_group_fields(const char *line, size_t length,
				     struct kasumi_mount_group_field fields[3])
{
	size_t cursor = 0;
	unsigned int column, count = 0;

	for (column = 0; column < 6; column++) {
		const char *space = memchr(line + cursor, ' ', length - cursor);

		if (!space)
			return -EINVAL;
		cursor = space - line + 1;
	}
	while (cursor < length) {
		const char *space = memchr(line + cursor, ' ', length - cursor);
		size_t end = space ? (size_t)(space - line) : length;
		size_t prefix = 0, digit;
		u32 id = 0;

		if (end - cursor == 1 && line[cursor] == '-')
			return count;
		if (end - cursor > 7 &&
		    (!memcmp(line + cursor, "shared:", 7) ||
		     !memcmp(line + cursor, "master:", 7)))
			prefix = 7;
		else if (end - cursor > 15 && !memcmp(line + cursor, "propagate_from:", 15))
			prefix = 15;
		if (prefix) {
			if (count == 3)
				return -EOVERFLOW;
			for (digit = cursor + prefix; digit < end; digit++) {
				u32 value = line[digit] - '0';

				if (value > 9 || id > (U32_MAX - value) / 10)
					return -EINVAL;
				id = id * 10 + value;
			}
			if (!id)
				return -EINVAL;
			fields[count++] = (struct kasumi_mount_group_field) {
				.start = cursor + prefix, .end = end, .id = id,
			};
		}
		cursor = end + 1;
	}
	return -EINVAL;
}

static int kasumi_mount_group_compare(const void *left, const void *right)
{
	u32 a = *(const u32 *)left, b = *(const u32 *)right;

	return (a > b) - (a < b);
}

u32 kasumi_mount_view_group_id(const struct kasumi_mount_view *view, u32 id)
{
	u32 low = 0, high = view ? view->group_count : 0;

	if (!id)
		return 0;
	while (low < high) {
		u32 middle = low + (high - low) / 2;

		if (view->groups[middle] < id)
			low = middle + 1;
		else
			high = middle;
	}
	return view && low < view->group_count && view->groups[low] == id ? low + 1 : 0;
}

bool kasumi_mount_groups_active(void)
{
#ifdef KASUMI_EMBEDDED
	uid_t uid = __kuid_val(current_uid());

	return ksu_is_unshare_mnt_enabled() && is_appuid(uid) && ksu_uid_should_umount(uid);
#else
	return false;
#endif
}

int kasumi_mount_view_normalize_groups(const struct kasumi_mount_view *view,
				       char *record, size_t *length)
{
	struct kasumi_mount_group_field fields[3];
	size_t input = 0, output = 0;
	int count = kasumi_mount_group_fields(record, *length, fields), i;

	if (count < 0)
		return count;
	for (i = 0; i < count; i++) {
		u32 id = kasumi_mount_view_group_id(view, fields[i].id);
		char number[12];
		size_t segment;
		int width;

		if (!id)
			return -EAGAIN;
		width = scnprintf(number, sizeof(number), "%u", id);
		if ((size_t)width > fields[i].end - fields[i].start)
			return -EOVERFLOW;
		segment = fields[i].start - input;
		memmove(record + output, record + input, segment);
		output += segment;
		memcpy(record + output, number, width);
		output += width;
		input = fields[i].end;
	}
	memmove(record + output, record + input, *length - input);
	*length = output + *length - input;
	return 0;
}

const struct kasumi_mount_record *
kasumi_mount_view_find(const struct kasumi_mount_view *view, u64 id, bool unique)
{
	u32 low = 0, high;

	if (!view || (unique && !id))
		return NULL;
	high = view->count;
	while (low < high) {
		u32 middle = low + (high - low) / 2;
		u64 key = unique ? view->unique[middle].id : view->records[middle].id;

		if (id == key)
			return &view->records[unique ? view->unique[middle].record : middle];
		if (id < key)
			high = middle;
		else
			low = middle + 1;
	}
	return NULL;
}

const struct kasumi_mount_record *
kasumi_mount_view_representative(const struct kasumi_mount_view *view,
				const struct kasumi_mount_record *record)
{
	if (!view || !record || record->alias_index >= view->count)
		return NULL;
	return &view->records[record->alias_index];
}

static void kasumi_mount_aliases(struct kasumi_mount_view *view)
{
	const u32 pending = U32_MAX, visiting = U32_MAX - 1;
	u32 i;

	for (i = 0; i < view->count; i++)
		view->records[i].alias_index = view->records[i].retained ? i : pending;
	for (i = 0; i < view->count; i++) {
		struct kasumi_mount_record *entry = &view->records[i], *cursor = entry;
		u32 alias;

		if (!entry->in_view || entry->alias_index != pending)
			continue;
		while (cursor->alias_index == pending) {
			const struct kasumi_mount_record *parent;

			cursor->alias_index = visiting;
			parent = kasumi_mount_view_find(view, cursor->parent_id, false);
			if (!parent || !parent->in_view || parent == cursor ||
			    parent->alias_index == visiting) {
				cursor->retained = true;
				cursor->alias_index = cursor - view->records;
				break;
			}
			cursor = &view->records[parent - view->records];
		}
		alias = cursor->alias_index;
		cursor = entry;
		while (cursor->alias_index == visiting) {
			const struct kasumi_mount_record *parent =
				kasumi_mount_view_find(view, cursor->parent_id, false);

			cursor->alias_index = alias;
			if (!parent)
				break;
			cursor = &view->records[parent - view->records];
		}
	}
}

static KASUMI_NOCFI int kasumi_mount_capture(struct kasumi_mount_view *view,
					    u32 capacity, struct seq_file *seq)
{
	struct mount *mount;
	struct proc_mounts source = {
		.ns = view->ns,
		.root = view->root,
	};
	int ret = 0;

	seq->private = &source;
	view->rename_sequence = read_seqbegin(kasumi_mount_rename_lock);
	down_read(kasumi_mount_namespace_lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	if (RB_EMPTY_ROOT(&view->ns->mounts)) {
		up_read(kasumi_mount_namespace_lock);
		return -ENOENT;
	}
#endif
	view->event = READ_ONCE(view->ns->event);
	view->rules_generation = kasumi_rules_generation();
	view->policy_generation = kasumi_fake_mi_policy_generation();
	for (mount = view->ns->root; mount;
	     mount = kasumi_mount_next(mount, view->ns->root)) {
		struct kasumi_mount_record *entry;
		bool hidden = false;
		unsigned int root_sequence, mountpoint_sequence;

		if (fatal_signal_pending(current)) {
			ret = -EINTR;
			break;
		}
		if (view->count == capacity) {
			ret = -EAGAIN;
			break;
		}
		if (mount->mnt_ns != view->ns)
			continue;
		root_sequence = read_seqcount_begin(&mount->mnt.mnt_root->d_seq);
		mountpoint_sequence = read_seqcount_begin(&mount->mnt_mountpoint->d_seq);
		seq->count = 0;
		ret = kasumi_mount_show_info(seq, &mount->mnt);
		if (ret < 0)
			break;
		if (!ret && seq_has_overflowed(seq)) {
			ret = -EOVERFLOW;
			break;
		}
		entry = &view->records[view->count++];
		entry->mount = &mount->mnt;
		entry->root_sequence = root_sequence;
		entry->mountpoint_sequence = mountpoint_sequence;
		entry->id = mount->mnt_id;
		entry->parent_id = mount->mnt_parent->mnt_id;
#ifdef STATX_MNT_ID_UNIQUE
		entry->unique_id = mount->mnt_id_unique;
		entry->parent_unique_id = mount->mnt_parent->mnt_id_unique;
#endif
		entry->in_view = ret != SEQ_SKIP && seq->count != 0;
		if (entry->in_view) {
			struct kasumi_mount_group_field fields[3];
			int count, i;

			ret = kasumi_fake_mi_classify_mount(seq->buf, seq->count, &hidden);
			if (ret)
				break;
			count = kasumi_mount_group_fields(seq->buf, seq->count, fields);
			if (count < 0) {
				ret = count;
				break;
			}
			for (i = 0; i < count; i++)
				view->groups[view->group_count++] = fields[i].id;
		}
		entry->retained = entry->in_view &&
			(!hidden || entry->mount == view->root.mnt);
		if (read_seqcount_retry(&mount->mnt.mnt_root->d_seq, root_sequence) ||
		    read_seqcount_retry(&mount->mnt_mountpoint->d_seq, mountpoint_sequence)) {
			ret = -EAGAIN;
			break;
		}
		ret = 0;
	}
	if (!ret && !kasumi_mount_view_current(view))
		ret = -EAGAIN;
	up_read(kasumi_mount_namespace_lock);
	return ret;
}

static KASUMI_NOCFI int
kasumi_mount_build(struct mnt_namespace *ns, const struct path *root,
		   struct kasumi_mount_view **result)
{
	struct kasumi_mount_view *view;
	struct file file = { .f_cred = current_cred() };
	struct seq_file seq = { .file = &file, .size = PAGE_SIZE };
	u32 capacity, unique_groups, i;
	int ret;

	view = kzalloc(sizeof(*view), GFP_KERNEL);
	if (!view)
		return -ENOMEM;
	if (!kasumi_mount_namespace_get(ns)) {
		kfree(view);
		return -ENOENT;
	}
	view->ns = ns;
	view->root = *root;
	path_get(&view->root);
	refcount_set(&view->refs, 1);
	atomic_inc(&kasumi_mount_owned);
	for (;;) {
		if (fatal_signal_pending(current)) {
			ret = -EINTR;
			break;
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
		capacity = READ_ONCE(ns->nr_mounts);
#else
		capacity = READ_ONCE(ns->mounts);
#endif
		if (capacity == U32_MAX) {
			ret = -E2BIG;
			break;
		}
		capacity++;
		view->records = kvmalloc_array(capacity, sizeof(*view->records),
					      GFP_KERNEL | __GFP_ZERO);
		view->groups = kvmalloc_array(capacity, 3 * sizeof(*view->groups), GFP_KERNEL);
		seq.buf = kvmalloc(seq.size, GFP_KERNEL);
		if (!view->records || !view->groups || !seq.buf) {
			ret = -ENOMEM;
			break;
		}
		ret = kasumi_mount_capture(view, capacity, &seq);
		kvfree(seq.buf);
		seq.buf = NULL;
		if (!ret)
			break;
		view->count = 0;
		kvfree(view->records);
		view->records = NULL;
		kvfree(view->groups);
		view->groups = NULL;
		view->group_count = 0;
		if (ret == -EOVERFLOW) {
			if (seq.size > SIZE_MAX / 2)
				break;
			seq.size *= 2;
		} else {
			break;
		}
		cond_resched();
	}
	kvfree(seq.buf);
	if (ret)
		goto fail;
	sort(view->groups, view->group_count, sizeof(*view->groups),
	     kasumi_mount_group_compare, NULL);
	for (i = 0, unique_groups = 0; i < view->group_count; i++)
		if (!unique_groups || view->groups[i] != view->groups[unique_groups - 1])
			view->groups[unique_groups++] = view->groups[i];
	view->group_count = unique_groups;
	sort(view->records, view->count, sizeof(*view->records),
	     kasumi_mount_compare, NULL);
	view->unique = kvmalloc_array(view->count, sizeof(*view->unique), GFP_KERNEL);
	if (!view->unique && view->count) {
		ret = -ENOMEM;
		goto fail;
	}
	for (i = 0; i < view->count; i++) {
		view->unique[i].id = view->records[i].unique_id;
		view->unique[i].record = i;
	}
	sort(view->unique, view->count, sizeof(*view->unique),
	     kasumi_mount_unique_compare, NULL);
	kasumi_mount_aliases(view);
	view->generation = atomic64_inc_return(&kasumi_mount_generation);
	view->bytes = sizeof(*view) + (size_t)capacity *
		(sizeof(*view->records) + 3 * sizeof(*view->groups)) +
		(size_t)view->count * sizeof(*view->unique);
	*result = view;
	return 0;
fail:
	kasumi_mount_view_put(view);
	return ret;
}

static u64 kasumi_mount_namespace_id(const struct mnt_namespace *ns)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	return ns->ns.ns_id;
#else
	return ns->seq;
#endif
}

static KASUMI_NOCFI int kasumi_mount_key(struct mnt_namespace *ns,
					const struct path *root,
					struct kasumi_mount_view *key)
{
	struct inode *inode = d_inode(root->dentry);
	char *buffer, *name;
	size_t size = PAGE_SIZE;
	int ret;

	key->namespace_id = kasumi_mount_namespace_id(ns);
	if (!key->namespace_id || !inode || !kasumi_mount_root_name)
		return -EOPNOTSUPP;
	key->rename_sequence = read_seqbegin(kasumi_mount_rename_lock);
	key->root_sequence = read_seqcount_begin(&root->dentry->d_seq);
	key->root_mount_id = real_mount(root->mnt)->mnt_id;
	key->root_ino = inode->i_ino;
	key->root_dev = inode->i_sb->s_dev;
	key->root_inode_generation = inode->i_generation;
	key->event = READ_ONCE(ns->event);
	key->rules_generation = kasumi_rules_generation();
	key->policy_generation = kasumi_fake_mi_policy_generation();
	for (;;) {
		if (fatal_signal_pending(current))
			return -EINTR;
		buffer = kvmalloc(size, GFP_KERNEL);
		if (!buffer)
			return -ENOMEM;
		name = kasumi_mount_root_name(root->dentry, buffer, size);
		ret = IS_ERR(name) ? PTR_ERR(name) : 0;
		if (!ret) {
			key->root_name = kstrdup(name, GFP_KERNEL);
			if (!key->root_name)
				ret = -ENOMEM;
		}
		kvfree(buffer);
		if (ret != -ENAMETOOLONG || size > INT_MAX / 2)
			break;
		size *= 2;
		cond_resched();
	}
	if (!ret && (read_seqretry(kasumi_mount_rename_lock, key->rename_sequence) ||
		     read_seqcount_retry(&root->dentry->d_seq, key->root_sequence)))
		ret = -EAGAIN;
	return ret;
}

static bool kasumi_mount_same_key(const struct kasumi_mount_view *a,
				  const struct kasumi_mount_view *b)
{
	return a->namespace_id == b->namespace_id &&
		a->root_mount_id == b->root_mount_id && a->root_ino == b->root_ino &&
		a->root_dev == b->root_dev && a->root_inode_generation == b->root_inode_generation &&
		a->root_sequence == b->root_sequence && a->event == b->event &&
		a->rename_sequence == b->rename_sequence &&
		a->rules_generation == b->rules_generation &&
		a->policy_generation == b->policy_generation &&
		!strcmp(a->root_name, b->root_name);
}

static struct kasumi_mount_view *
kasumi_mount_cached(const struct kasumi_mount_view *key)
{
	struct kasumi_mount_view *data, *found = NULL;

	mutex_lock(&kasumi_mount_cache_lock);
	hash_for_each_possible(kasumi_mount_cache, data, cache_node, key->namespace_id) {
		if (kasumi_mount_same_key(data, key)) {
			kasumi_mount_view_get_ref(data);
			found = data;
			break;
		}
	}
	mutex_unlock(&kasumi_mount_cache_lock);
	return found;
}

bool kasumi_mount_view_record_current(const struct kasumi_mount_view *view,
				      const struct kasumi_mount_record *record)
{
	struct mount *mount;

	if (!record || !kasumi_mount_view_current(view))
		return false;
	mount = real_mount(record->mount);
	return !read_seqcount_retry(&mount->mnt.mnt_root->d_seq, record->root_sequence) &&
		!read_seqcount_retry(&mount->mnt_mountpoint->d_seq, record->mountpoint_sequence);
}

static bool kasumi_mount_records_current(const struct kasumi_mount_view *view)
{
	u32 i;

	if (!kasumi_mount_view_current(view))
		return false;
	for (i = 0; i < view->count; i++) {
		const struct kasumi_mount_record *record = &view->records[i];

		if (!kasumi_mount_view_record_current(view, record))
			return false;
	}
	return kasumi_mount_view_current(view);
}

static void kasumi_mount_uncache(struct kasumi_mount_view *data);

static struct kasumi_mount_view *
kasumi_mount_handle(struct kasumi_mount_view *data, struct mnt_namespace *ns,
		     const struct path *root)
{
	struct kasumi_mount_view *view = kmemdup(data, sizeof(*view), GFP_KERNEL);
	bool valid;

	if (!view) {
		kasumi_mount_view_put(data);
		return ERR_PTR(-ENOMEM);
	}
	if (!kasumi_mount_namespace_get(ns)) {
		kfree(view);
		kasumi_mount_view_put(data);
		return ERR_PTR(-ENOENT);
	}
	view->ns = ns;
	view->root = *root;
	path_get(&view->root);
	view->metadata_only = false;
	view->data_owner = data;
	refcount_set(&view->refs, 1);
	atomic_inc(&kasumi_mount_owned);
	down_read(kasumi_mount_namespace_lock);
	valid = !read_seqcount_retry(&root->dentry->d_seq, view->root_sequence) &&
		kasumi_mount_records_current(view);
	up_read(kasumi_mount_namespace_lock);
	if (!valid) {
		mutex_lock(&kasumi_mount_cache_lock);
		if (!hlist_unhashed(&data->cache_node))
			kasumi_mount_uncache(data);
		mutex_unlock(&kasumi_mount_cache_lock);
		kasumi_mount_view_put(view);
		return ERR_PTR(-EAGAIN);
	}
	return view;
}

static void kasumi_mount_uncache(struct kasumi_mount_view *data)
{
	hash_del(&data->cache_node);
	list_del(&data->cache_list);
	kasumi_mount_cache_bytes -= data->bytes;
	kasumi_mount_view_put(data);
}

static void kasumi_mount_cache_publish(struct kasumi_mount_view *view,
				      struct kasumi_mount_view *key)
{
	struct kasumi_mount_view *data, *old, *next;

	view->namespace_id = key->namespace_id;
	view->root_mount_id = key->root_mount_id;
	view->root_ino = key->root_ino;
	view->root_dev = key->root_dev;
	view->root_inode_generation = key->root_inode_generation;
	view->root_sequence = key->root_sequence;
	view->root_name = key->root_name;
	key->root_name = NULL;
	view->bytes += strlen(view->root_name) + 1;
	if (view->event != key->event || view->rename_sequence != key->rename_sequence ||
	    view->rules_generation != key->rules_generation ||
	    view->policy_generation != key->policy_generation)
		return;
	data = kmemdup(view, sizeof(*data), GFP_KERNEL);
	if (!data)
		return;
	data->metadata_only = true;
	data->ns = NULL;
	memset(&data->root, 0, sizeof(data->root));
	data->data_owner = NULL;
	refcount_set(&data->refs, 2);
	view->data_owner = data;
	mutex_lock(&kasumi_mount_cache_lock);
	list_for_each_entry_safe(old, next, &kasumi_mount_cache_list, cache_list) {
		if (old->namespace_id == data->namespace_id &&
		    old->root_mount_id == data->root_mount_id &&
		    old->root_ino == data->root_ino && !strcmp(old->root_name, data->root_name))
			kasumi_mount_uncache(old);
	}
	hash_add(kasumi_mount_cache, &data->cache_node, data->namespace_id);
	list_add_tail(&data->cache_list, &kasumi_mount_cache_list);
	kasumi_mount_cache_bytes += data->bytes;
	while (kasumi_mount_cache_bytes > KASUMI_MOUNT_CACHE_BYTES) {
		old = list_first_entry(&kasumi_mount_cache_list,
				      struct kasumi_mount_view, cache_list);
		kasumi_mount_uncache(old);
	}
	mutex_unlock(&kasumi_mount_cache_lock);
}

int kasumi_mount_view_get(struct mnt_namespace *ns, const struct path *root,
			  struct kasumi_mount_view **result)
{
	struct kasumi_internal_vfs_guard guard;
	struct kasumi_mount_view key = {}, *data;
	bool cacheable;
	int ret;

	*result = NULL;
	if (!READ_ONCE(kasumi_mount_ready))
		return -EOPNOTSUPP;
	if (!ns || !root || !root->mnt || !root->dentry)
		return -EINVAL;
	if (fatal_signal_pending(current))
		return -EINTR;
	kasumi_vfs_internal_enter(&guard);
	ret = kasumi_mount_key(ns, root, &key);
	if (ret == -EAGAIN || ret == -EINTR)
		goto out;
	cacheable = !ret;
	if (cacheable) {
		data = kasumi_mount_cached(&key);
		if (data)
			*result = kasumi_mount_handle(data, ns, root);
	}
	if (IS_ERR(*result)) {
		ret = PTR_ERR(*result);
		*result = NULL;
		goto out;
	}
	ret = *result ? 0 : kasumi_mount_build(ns, root, result);
	if (!ret && cacheable && !(*result)->data_owner)
		kasumi_mount_cache_publish(*result, &key);
out:
	kfree(key.root_name);
	kasumi_vfs_internal_leave(&guard);
	return ret;
}

int kasumi_mount_view_get_current(struct kasumi_mount_view **result)
{
	struct path root;
	int ret;

	*result = NULL;
	if (!current->fs || !current->nsproxy)
		return -ENOENT;
	get_fs_root(current->fs, &root);
	ret = kasumi_mount_view_get(current->nsproxy->mnt_ns, &root, result);
	path_put(&root);
	return ret;
}

int kasumi_mount_view_get_task(struct task_struct *task,
			       struct kasumi_mount_view **result)
{
	struct mnt_namespace *ns = NULL;
	struct path root = {};
	int ret;

	*result = NULL;
	if (!kasumi_mount_view_available())
		return -EOPNOTSUPP;
	task_lock(task);
	if (task->fs && task->nsproxy &&
	    kasumi_mount_namespace_get(task->nsproxy->mnt_ns)) {
		ns = task->nsproxy->mnt_ns;
		get_fs_root(task->fs, &root);
	}
	task_unlock(task);
	if (!ns)
		return -ENOENT;
	ret = kasumi_mount_view_get(ns, &root, result);
	path_put(&root);
	kasumi_mount_namespace_put(ns);
	return ret;
}

u32 kasumi_mount_view_count(const struct kasumi_mount_view *view)
{
	return view ? view->count : 0;
}

const struct kasumi_mount_record *
kasumi_mount_view_at(const struct kasumi_mount_view *view, u32 index)
{
	return view && index < view->count ? &view->records[index] : NULL;
}

struct mnt_namespace *
kasumi_mount_view_namespace(const struct kasumi_mount_view *view)
{
	return view ? view->ns : NULL;
}

const struct path *kasumi_mount_view_root(const struct kasumi_mount_view *view)
{
	return view ? &view->root : NULL;
}

u64 kasumi_mount_view_generation(const struct kasumi_mount_view *view)
{
	return view ? view->generation : 0;
}

bool kasumi_mount_view_available(void)
{
	return READ_ONCE(kasumi_mount_ready);
}

u64 kasumi_mount_view_capabilities(void)
{
	return atomic64_read(&kasumi_mount_capabilities);
}

u64 kasumi_mount_view_required_capabilities(void)
{
	u64 required = KASUMI_MOUNT_CAP_INFO | KASUMI_MOUNT_CAP_MOUNTS |
		KASUMI_MOUNT_CAP_STATS | KASUMI_MOUNT_CAP_FDINFO |
		KASUMI_MOUNT_CAP_STATX | KASUMI_MOUNT_CAP_STATFS;

#ifdef STATX_MNT_ID_UNIQUE
	required |= KASUMI_MOUNT_CAP_UNIQUE;
#endif
#ifdef STATMOUNT_SB_BASIC
	required |= KASUMI_MOUNT_CAP_STATMOUNT | KASUMI_MOUNT_CAP_LISTMOUNT;
#endif
	return required;
}

void kasumi_mount_view_publish_capabilities(u64 set, u64 clear)
{
	u64 previous, next;

	do {
		previous = atomic64_read(&kasumi_mount_capabilities);
		next = (previous | set) & ~clear;
	} while (atomic64_cmpxchg(&kasumi_mount_capabilities, previous, next) != previous);
}

bool kasumi_mount_projection_available(void)
{
	u64 required = kasumi_mount_view_required_capabilities();

	return kasumi_mount_view_available() &&
		(kasumi_mount_view_capabilities() & required) == required;
}

bool kasumi_mount_projection_active(void)
{
	return kasumi_mount_projection_available() &&
		kasumi_config_enabled() &&
		(kasumi_config_features() & KSM_FEATURE_MOUNT_HIDE) &&
		kasumi_policy_current_is_spoof_target();
}

int kasumi_mount_view_init(void)
{
	if (kasumi_mount_view_available())
		return 0;
	kasumi_mount_rename_lock = (void *)kasumi_lookup_name_quiet("rename_lock");
	kasumi_mount_namespace_lock =
		(void *)kasumi_lookup_name_quiet("namespace_sem");
	kasumi_mount_show_info =
		(void *)kasumi_lookup_callable_quiet("show_mountinfo");
	kasumi_mount_root_name =
		(void *)kasumi_lookup_callable_quiet("dentry_path_raw");
	kasumi_mount_get_ns = (void *)kasumi_lookup_callable_quiet("copy_mnt_ns");
	kasumi_mount_put_ns = (void *)kasumi_lookup_callable_quiet("put_mnt_ns");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	kasumi_mount_release_passive =
		(void *)kasumi_lookup_callable_quiet("mnt_ns_release");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	kasumi_mount_release_passive_rcu =
		(void *)kasumi_lookup_callable_quiet("mnt_ns_release_rcu");
#endif
	if (!kasumi_mount_release_passive && !kasumi_mount_release_passive_rcu)
		return -ENOENT;
#endif
	if (!kasumi_mount_namespace_lock || !kasumi_mount_rename_lock || !kasumi_mount_show_info ||
	    !kasumi_mount_get_ns || !kasumi_mount_put_ns)
		return -ENOENT;
	WRITE_ONCE(kasumi_mount_ready, true);
	return 0;
}

void kasumi_mount_view_exit(void)
{
	struct kasumi_mount_view *data, *next;

	WRITE_ONCE(kasumi_mount_ready, false);
	mutex_lock(&kasumi_mount_cache_lock);
	list_for_each_entry_safe(data, next, &kasumi_mount_cache_list, cache_list)
		kasumi_mount_uncache(data);
	mutex_unlock(&kasumi_mount_cache_lock);
	wait_event(kasumi_mount_wait, !atomic_read(&kasumi_mount_owned));
}
