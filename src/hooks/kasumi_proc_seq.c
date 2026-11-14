#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/sched/signal.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <uapi/linux/magic.h>
#include <fs/mount.h>
#include <fs/proc/internal.h>

#include "kasumi_dir_view.h"
#include "kasumi_fake_mountinfo.h"
#include "kasumi_maps_format.h"
#include "kasumi_maps_rules.h"
#include "kasumi_mount_query.h"
#include "kasumi_mount_stat.h"
#include "kasumi_mount_view.h"
#include "kasumi_path_policy.h"
#include "kasumi_proc_seq.h"
#include "kasumi_runtime.h"

enum kasumi_seq_kind {
	KASUMI_SEQ_NONE,
	KASUMI_SEQ_MAPS,
	KASUMI_SEQ_MOUNTINFO,
	KASUMI_SEQ_MOUNTS,
	KASUMI_SEQ_MOUNTSTATS,
	KASUMI_SEQ_FDINFO,
};

struct kasumi_seq_state {
	struct hlist_node node;
	struct rcu_head rcu;
	refcount_t refs;
	struct mutex operation_lock;
	struct seq_file *seq;
	struct seq_operations operations;
	const struct seq_operations *original;
	struct kasumi_maps_snapshot *snapshot;
	struct kasumi_mount_view *mount_view;
	enum kasumi_seq_kind kind;
	char *scratch;
	size_t scratch_capacity;
	size_t scratch_needed;
	u64 generation;
	u64 config_generation;
	u64 poll_generation;
	u64 poll_policy_generation;
	bool refresh_needed;
	bool fdinfo_projection;
	bool mount_hide;
	bool normalize_groups;
	bool attached;
};

struct kasumi_seq_guard {
	struct hlist_node node;
	struct task_struct *task;
	const struct kprobe *probe;
};

static DEFINE_HASHTABLE(kasumi_seq_states, 8);
static DEFINE_MUTEX(kasumi_seq_states_lock);
static DEFINE_HASHTABLE(kasumi_seq_guards, 6);
static spinlock_t kasumi_seq_guard_locks[HASH_SIZE(kasumi_seq_guards)] = {
	[0 ... HASH_SIZE(kasumi_seq_guards) - 1] =
		__SPIN_LOCK_UNLOCKED(kasumi_seq_guard_locks),
};
static DECLARE_WAIT_QUEUE_HEAD(kasumi_seq_wait);
static atomic_t kasumi_seq_active = ATOMIC_INIT(0);
static bool kasumi_seq_stopping = true;
static bool kasumi_seq_ready;
static bool kasumi_seq_mount_ready;
static struct kprobe kasumi_seq_read_probe;
static struct kprobe kasumi_seq_seek_probe;
static struct kprobe kasumi_seq_release_probe;
static struct kprobe kasumi_map_release_probe;
static struct kprobe kasumi_mount_release_probe;
static struct kprobe kasumi_single_release_probe;
static struct kprobe kasumi_mounts_poll_probe;
static bool kasumi_seq_read_registered;
static bool kasumi_seq_seek_registered;
static bool kasumi_seq_release_registered;
static bool kasumi_map_release_registered;
static bool kasumi_mount_release_registered;
static bool kasumi_single_release_registered;
static bool kasumi_mounts_poll_registered;
static ssize_t (*kasumi_seq_read_original)(struct kiocb *, struct iov_iter *);
static loff_t (*kasumi_seq_seek_original)(struct file *, loff_t, int);
static int (*kasumi_seq_release_original)(struct inode *, struct file *);
static int (*kasumi_map_release_original)(struct inode *, struct file *);
static int (*kasumi_mount_release_original)(struct inode *, struct file *);
static int (*kasumi_single_release_original)(struct inode *, struct file *);
static __poll_t (*kasumi_mounts_poll_original)(struct file *, poll_table *);
static int (*kasumi_maps_show_original)(struct seq_file *, void *);
static int (*kasumi_smaps_show_original)(struct seq_file *, void *);
static void (*kasumi_seq_tasks_barrier)(void);
static const struct seq_operations *kasumi_mounts_operations;
static const struct file_operations *kasumi_fdinfo_operations;
static int (*kasumi_mountinfo_show_original)(struct seq_file *, struct vfsmount *);
static int (*kasumi_mounts_show_original)(struct seq_file *, struct vfsmount *);
static int (*kasumi_mountstats_show_original)(struct seq_file *, struct vfsmount *);
#ifdef CONFIG_FILE_LOCKING
static void (*kasumi_fd_locks_show)(struct seq_file *, struct file *, struct files_struct *);
#endif

static KASUMI_NOCFI int kasumi_seq_show(struct seq_file *seq, void *item);

/* seq_file consumes -EAGAIN inside traverse(), before our sleepable wrapper
 * can resize scratch or replace a stale mount snapshot. */
#define KASUMI_SEQ_RETRY (-ENOBUFS)

static bool kasumi_seq_guarded(const struct kprobe *probe)
{
	spinlock_t *lock = &kasumi_seq_guard_locks[
		hash_min((unsigned long)current, HASH_BITS(kasumi_seq_guards))];
	struct kasumi_seq_guard *guard;
	unsigned long flags;
	bool guarded = false;

	spin_lock_irqsave(lock, flags);
	hash_for_each_possible(kasumi_seq_guards, guard, node,
			       (unsigned long)current) {
		if (guard->task == current && guard->probe == probe) {
			guarded = true;
			break;
		}
	}
	spin_unlock_irqrestore(lock, flags);
	return guarded;
}

static void kasumi_seq_guard_enter(struct kasumi_seq_guard *guard,
				  const struct kprobe *probe)
{
	spinlock_t *lock = &kasumi_seq_guard_locks[
		hash_min((unsigned long)current, HASH_BITS(kasumi_seq_guards))];
	unsigned long flags;

	guard->task = current;
	guard->probe = probe;
	spin_lock_irqsave(lock, flags);
	hash_add(kasumi_seq_guards, &guard->node, (unsigned long)current);
	spin_unlock_irqrestore(lock, flags);
}

static void kasumi_seq_guard_leave(struct kasumi_seq_guard *guard)
{
	spinlock_t *lock = &kasumi_seq_guard_locks[
		hash_min((unsigned long)guard->task, HASH_BITS(kasumi_seq_guards))];
	unsigned long flags;

	spin_lock_irqsave(lock, flags);
	hash_del(&guard->node);
	spin_unlock_irqrestore(lock, flags);
	if (atomic_dec_and_test(&kasumi_seq_active))
		wake_up_all(&kasumi_seq_wait);
}

#include "kasumi_proc_query.h"

static void kasumi_seq_state_put(struct kasumi_seq_state *state)
{
	if (!state || !refcount_dec_and_test(&state->refs))
		return;
	kvfree(state->scratch);
	kfree_rcu(state, rcu);
}

static struct kasumi_seq_state *kasumi_seq_state_get(struct seq_file *seq)
{
	struct kasumi_seq_state *state, *found = NULL;

	rcu_read_lock();
	hash_for_each_possible_rcu(kasumi_seq_states, state, node,
				   (unsigned long)seq) {
		if (state->seq == seq && refcount_inc_not_zero(&state->refs)) {
			found = state;
			break;
		}
	}
	rcu_read_unlock();
	return found;
}

static enum kasumi_seq_kind kasumi_seq_selected(struct file *file, bool *attached)
{
	struct seq_file *seq;
	const struct seq_operations *operations;
	enum kasumi_seq_kind kind = KASUMI_SEQ_NONE;

	if (!file || !file_inode(file) ||
	    file_inode(file)->i_sb->s_magic != PROC_SUPER_MAGIC)
		return KASUMI_SEQ_NONE;
	seq = file->private_data;
	if (!seq)
		return KASUMI_SEQ_NONE;
	rcu_read_lock();
	operations = READ_ONCE(seq->op);
	*attached = operations && operations->show == kasumi_seq_show;
	if (*attached) {
		struct kasumi_seq_state *state =
			container_of(operations, struct kasumi_seq_state, operations);

		kind = state->kind;
	} else if (operations &&
		   (operations->show == kasumi_maps_show_original ||
		    operations->show == kasumi_smaps_show_original)) {
		kind = KASUMI_SEQ_MAPS;
	} else if (READ_ONCE(kasumi_seq_mount_ready) &&
		   operations == kasumi_mounts_operations && seq->private) {
		struct proc_mounts *mounts = seq->private;

		if (mounts->show == kasumi_mountinfo_show_original)
			kind = KASUMI_SEQ_MOUNTINFO;
		else if (mounts->show == kasumi_mounts_show_original)
			kind = KASUMI_SEQ_MOUNTS;
		else if (mounts->show == kasumi_mountstats_show_original)
			kind = KASUMI_SEQ_MOUNTSTATS;
	} else if (READ_ONCE(kasumi_seq_mount_ready) &&
		   file->f_op == kasumi_fdinfo_operations) {
		kind = KASUMI_SEQ_FDINFO;
	}
	rcu_read_unlock();
	return kind;
}

static struct kasumi_seq_state *kasumi_seq_attach(struct file *file)
{
	struct seq_file *seq = file->private_data;
	struct kasumi_seq_state *state, *created;
	bool attached = false;

	state = kasumi_seq_state_get(seq);
	if (state)
		return state;
	created = kzalloc(sizeof(*created), GFP_KERNEL);
	if (!created)
		return ERR_PTR(-ENOMEM);
	mutex_init(&created->operation_lock);
	refcount_set(&created->refs, 2);
	created->seq = seq;
	created->kind = kasumi_seq_selected(file, &attached);
	created->poll_generation = kasumi_fake_mi_generation();
	created->poll_policy_generation = kasumi_fake_mi_policy_generation();
	mutex_lock(&seq->lock);
	mutex_lock(&kasumi_seq_states_lock);
	state = kasumi_seq_state_get(seq);
	if (state)
		goto discard;
	if (READ_ONCE(kasumi_seq_stopping)) {
		state = ERR_PTR(-ESHUTDOWN);
		goto discard;
	}
	created->original = seq->op;
	created->operations = *seq->op;
	created->operations.show = kasumi_seq_show;
	created->attached = true;
	hash_add_rcu(kasumi_seq_states, &created->node, (unsigned long)seq);
	WRITE_ONCE(seq->op, &created->operations);
	mutex_unlock(&kasumi_seq_states_lock);
	mutex_unlock(&seq->lock);
	return created;
discard:
	mutex_unlock(&kasumi_seq_states_lock);
	mutex_unlock(&seq->lock);
	kfree(created);
	return state;
}

static int kasumi_seq_scratch_grow(struct kasumi_seq_state *state, size_t size)
{
	char *scratch;

	if (size <= state->scratch_capacity)
		return 0;
	scratch = kvmalloc(size, GFP_KERNEL);
	if (!scratch)
		return -ENOMEM;
	kvfree(state->scratch);
	state->scratch = scratch;
	state->scratch_capacity = size;
	return 0;
}

static KASUMI_NOCFI int kasumi_seq_fdinfo(struct kasumi_seq_state *state,
					struct seq_file *seq)
{
	struct task_struct *task;
	struct files_struct *files = NULL;
	struct file *file = NULL;
	const struct kasumi_mount_record *record, *alias;
	loff_t position;
	unsigned int fd = PROC_I((struct inode *)seq->private)->fd;
	int flags = 0, mount_id;

	task = get_proc_task(seq->private);
	if (!task)
		return -ENOENT;
	task_lock(task);
	files = task->files;
	if (files) {
		struct fdtable *table;

		spin_lock(&files->file_lock);
		table = files_fdtable(files);
		if (fd < table->max_fds)
			file = rcu_dereference_raw(table->fd[fd]);
		if (file) {
			flags = file->f_flags;
			if (test_bit(fd, table->close_on_exec))
				flags |= O_CLOEXEC;
			get_file(file);
		}
		spin_unlock(&files->file_lock);
	}
	task_unlock(task);
	put_task_struct(task);
	if (!file)
		return -ENOENT;
	position = file->f_pos;
	if (state->fdinfo_projection)
		kasumi_dir_visible_pos(file, &position);
	mount_id = real_mount(file->f_path.mnt)->mnt_id;
	record = kasumi_mount_view_find(state->mount_view, mount_id, false);
	alias = kasumi_mount_view_representative(state->mount_view, record);
	if (alias)
		mount_id = alias->id;
	seq_printf(seq, "pos:\t%lli\nflags:\t0%o\nmnt_id:\t%i\nino:\t%lu\n",
		   (long long)position, flags, mount_id, file_inode(file)->i_ino);
#ifdef CONFIG_FILE_LOCKING
	kasumi_fd_locks_show(seq, file, files);
#endif
	if (!seq_has_overflowed(seq) && file->f_op->show_fdinfo)
		file->f_op->show_fdinfo(seq, file);
	fput(file);
	return 0;
}

static int kasumi_seq_mount_parent(struct kasumi_seq_state *state,
				    struct seq_file *seq, size_t start,
				    const struct kasumi_mount_record *record)
{
	const struct kasumi_mount_record *parent, *alias;
	char number[24], *first, *last;
	size_t prefix, suffix;
	int length;

	parent = kasumi_mount_view_find(state->mount_view, record->parent_id, false);
	alias = kasumi_mount_view_representative(state->mount_view, parent);
	if (!alias || alias->id == record->parent_id)
		return 0;
	first = memchr(seq->buf + start, ' ', seq->count - start);
	if (!first)
		return -EIO;
	first++;
	last = memchr(first, ' ', seq->count - (first - seq->buf));
	if (!last)
		return -EIO;
	length = scnprintf(number, sizeof(number), "%llu", alias->id);
	prefix = first - seq->buf;
	suffix = seq->count - (last - seq->buf);
	if (length >= seq->size - prefix || suffix >= seq->size - prefix - length) {
		seq->count = seq->size;
		return 0;
	}
	memmove(first + length, last, suffix);
	memcpy(first, number, length);
	seq->count = prefix + length + suffix;
	return 0;
}

static KASUMI_NOCFI int kasumi_seq_show(struct seq_file *seq, void *item)
{
	struct kasumi_seq_state *state =
		container_of(seq->op, struct kasumi_seq_state, operations);
	const struct kasumi_mount_record *record = NULL;
	size_t start = seq->count, in, out = 0;
	int ret;

	if (state->mount_view) {
		if (!kasumi_mount_view_current(state->mount_view)) {
			state->refresh_needed = true;
			return KASUMI_SEQ_RETRY;
		}
		if (state->kind != KASUMI_SEQ_FDINFO) {
			struct mount *mount = item;

			record = kasumi_mount_view_find(state->mount_view, mount->mnt_id, false);
			if (!kasumi_mount_view_record_current(state->mount_view, record)) {
				state->refresh_needed = true;
				return KASUMI_SEQ_RETRY;
			}
			if (state->mount_hide && !record->retained)
				return SEQ_SKIP;
		}
	}
	if (state->kind == KASUMI_SEQ_FDINFO && state->fdinfo_projection)
		return kasumi_seq_fdinfo(state, seq);
	ret = state->original->show(seq, item);
	if (ret || seq_has_overflowed(seq))
		return ret;
	if (record && state->kind == KASUMI_SEQ_MOUNTINFO) {
		size_t length;

		if (state->mount_hide) {
			ret = kasumi_seq_mount_parent(state, seq, start, record);
			if (ret || seq_has_overflowed(seq))
				return ret;
		}
		if (!state->normalize_groups)
			return 0;
		length = seq->count - start;
		ret = kasumi_mount_view_normalize_groups(state->mount_view,
						       seq->buf + start, &length);
		if (ret == -EAGAIN) {
			state->refresh_needed = true;
			seq->count = start;
			return KASUMI_SEQ_RETRY;
		}
		if (!ret)
			seq->count = start + length;
		return ret;
	}

	if (!state->snapshot)
		return ret;
	if (state->scratch_capacity < seq->size) {
		state->scratch_needed = seq->size;
		seq->count = start;
		return KASUMI_SEQ_RETRY;
	}
	for (in = start; in < seq->count;) {
		const char *line = seq->buf + in;
		const char *newline = memchr(line, '\n', seq->count - in);
		const struct kasumi_transaction_maps_rule *rule = NULL;
		struct kasumi_maps_header header;
		size_t length;

		if (!newline)
			return -EIO;
		length = newline - line + 1;
		if (kasumi_maps_parse_header(line, length, &header)) {
			rule = kasumi_maps_rules_lookup(state->snapshot,
				MKDEV(header.major, header.minor), header.inode);
		} else if (kasumi_maps_header_prefix(line, length)) {
			return -EIO;
		}
		if (rule) {
			ret = kasumi_maps_format_record(
				state->scratch + out, seq->size - start - out,
				&header,
				rule->fields & KSM_MAPS_FIELD_DEV ? MAJOR(rule->spoofed_dev) : header.major,
				rule->fields & KSM_MAPS_FIELD_DEV ? MINOR(rule->spoofed_dev) : header.minor,
				rule->fields & KSM_MAPS_FIELD_INO ? rule->spoofed_ino : header.inode,
				rule->fields & KSM_MAPS_FIELD_PATH ? rule->spoofed_pathname : NULL);
			if (ret == -ENOSPC)
				goto overflow;
			if (ret < 0)
				return ret;
			out += ret;
		} else {
			if (length > seq->size - start - out)
				goto overflow;
			memcpy(state->scratch + out, line, length);
			out += length;
		}
		in += length;
	}
	memcpy(seq->buf + start, state->scratch, out);
	seq->count = start + out;
	return 0;
overflow:
	seq->count = seq->size;
	return 0;
}

static int kasumi_seq_begin(struct kasumi_seq_state *state, unsigned int *attempt)
{
	struct kasumi_maps_snapshot *snapshot = NULL;
	struct kasumi_mount_view *mount_view = NULL;
	enum kasumi_policy_scope scope;
	u64 generation = 0, config_generation;
	bool enabled, mount_hide, normalize_groups, fdinfo_projection;
	u32 features;
	int ret = 0;

	if (!state->attached)
		return 0;
	state->refresh_needed = false;
	while (*attempt < KASUMI_MOUNT_VIEW_ATTEMPTS) {
		if (fatal_signal_pending(current))
			return -EINTR;
		(*attempt)++;
		ret = 0;
		config_generation = kasumi_rules_generation();
		enabled = !READ_ONCE(kasumi_seq_stopping) && kasumi_config_enabled();
		features = kasumi_config_features();
		scope = enabled ? kasumi_policy_current_scope() : KASUMI_POLICY_SCOPE_NONE;
		mount_hide = enabled && scope == KASUMI_POLICY_SCOPE_SPOOF &&
			(features & KSM_FEATURE_MOUNT_HIDE) && kasumi_mount_projection_available();
		normalize_groups = state->kind == KASUMI_SEQ_MOUNTINFO &&
			!READ_ONCE(kasumi_seq_stopping) && kasumi_mount_groups_active();
		fdinfo_projection = state->kind == KASUMI_SEQ_FDINFO && enabled &&
			scope != KASUMI_POLICY_SCOPE_NONE;
		if (state->kind == KASUMI_SEQ_MAPS) {
			if (enabled && scope == KASUMI_POLICY_SCOPE_SPOOF &&
			    (features & KSM_FEATURE_MAPS_SPOOF))
				snapshot = kasumi_maps_rules_get();
			generation = kasumi_maps_snapshot_generation(snapshot);
		} else if (mount_hide || normalize_groups) {
			if (state->kind == KASUMI_SEQ_FDINFO) {
				struct task_struct *task = get_proc_task(state->seq->private);

				if (!task)
					return -ENOENT;
				ret = kasumi_mount_view_get_task(task, &mount_view);
				put_task_struct(task);
			} else {
				struct proc_mounts *mounts = state->seq->private;

				ret = kasumi_mount_view_get(mounts->ns, &mounts->root, &mount_view);
			}
			if (ret && ret != -EAGAIN)
				return ret;
			generation = kasumi_mount_view_generation(mount_view);
		}
		if (!ret && config_generation == kasumi_rules_generation())
			goto ready;
		kasumi_maps_rules_put(snapshot);
		snapshot = NULL;
		kasumi_mount_view_put(mount_view);
		mount_view = NULL;
		generation = 0;
		cond_resched();
	}
	return -EAGAIN;
ready:
	state->mount_hide = mount_hide;
	state->normalize_groups = normalize_groups;
	state->fdinfo_projection = fdinfo_projection;
	if (state->kind >= KASUMI_SEQ_MOUNTINFO && state->kind <= KASUMI_SEQ_MOUNTSTATS)
		generation = (generation << 2) | ((u64)state->mount_hide << 1) |
			state->normalize_groups;
	if (state->kind == KASUMI_SEQ_FDINFO)
		generation = (generation << 1) | state->fdinfo_projection;
	if (state->generation != generation || state->config_generation != config_generation) {
		mutex_lock(&state->seq->lock);
		state->seq->read_pos = -1;
		state->seq->index = 0;
		state->seq->count = 0;
		state->seq->from = 0;
		mutex_unlock(&state->seq->lock);
		state->generation = generation;
		state->config_generation = config_generation;
	}
	state->snapshot = snapshot;
	state->mount_view = mount_view;
	if (!snapshot)
		return 0;
	return kasumi_seq_scratch_grow(
		state, max_t(size_t, PAGE_SIZE, state->scratch_needed));
}

static void kasumi_seq_end(struct kasumi_seq_state *state)
{
	kasumi_maps_rules_put(state->snapshot);
	state->snapshot = NULL;
	kasumi_mount_view_put(state->mount_view);
	state->mount_view = NULL;
}

static int kasumi_seq_retry(struct kasumi_seq_state *state, unsigned int *attempt)
{
	if (fatal_signal_pending(current))
		return -EINTR;
	if (state->scratch_needed > state->scratch_capacity)
		return kasumi_seq_scratch_grow(state, state->scratch_needed);
	if (!state->refresh_needed)
		return -EAGAIN;
	kasumi_seq_end(state);
	return kasumi_seq_begin(state, attempt);
}

static KASUMI_NOCFI ssize_t kasumi_seq_read(struct kiocb *iocb,
					  struct iov_iter *iter)
{
	struct kasumi_seq_guard guard;
	struct kasumi_seq_state *state;
	ssize_t ret;
	unsigned int attempt = 0;

	kasumi_seq_guard_enter(&guard, &kasumi_seq_read_probe);
	state = kasumi_seq_attach(iocb->ki_filp);
	if (IS_ERR(state)) {
		ret = PTR_ERR(state);
		if (ret == -ESHUTDOWN)
			ret = kasumi_seq_read_original(iocb, iter);
		goto done;
	}
	mutex_lock(&state->operation_lock);
	ret = kasumi_seq_begin(state, &attempt);
	while (!ret) {
		loff_t position = iocb->ki_pos;

		ret = kasumi_seq_read_original(iocb, iter);
		if (ret != KASUMI_SEQ_RETRY || iocb->ki_pos != position)
			break;
		ret = kasumi_seq_retry(state, &attempt);
	}
	kasumi_seq_end(state);
	mutex_unlock(&state->operation_lock);
	kasumi_seq_state_put(state);
done:
	kasumi_seq_guard_leave(&guard);
	return ret;
}

static KASUMI_NOCFI loff_t kasumi_seq_seek(struct file *file, loff_t offset,
					int whence)
{
	struct kasumi_seq_guard guard;
	struct kasumi_seq_state *state;
	loff_t ret;
	unsigned int attempt = 0;

	kasumi_seq_guard_enter(&guard, &kasumi_seq_seek_probe);
	state = kasumi_seq_attach(file);
	if (IS_ERR(state)) {
		ret = PTR_ERR(state);
		if (ret == -ESHUTDOWN)
			ret = kasumi_seq_seek_original(file, offset, whence);
		goto done;
	}
	mutex_lock(&state->operation_lock);
	ret = kasumi_seq_begin(state, &attempt);
	while (!ret) {
		loff_t position = file->f_pos;

		ret = kasumi_seq_seek_original(file, offset, whence);
		if (ret != KASUMI_SEQ_RETRY)
			break;
		file->f_pos = position;
		ret = kasumi_seq_retry(state, &attempt);
	}
	kasumi_seq_end(state);
	mutex_unlock(&state->operation_lock);
	kasumi_seq_state_put(state);
done:
	kasumi_seq_guard_leave(&guard);
	return ret;
}

static void kasumi_seq_detach(struct file *file)
{
	struct kasumi_seq_state *state;

	state = kasumi_seq_state_get(file->private_data);
	if (!state)
		return;
	mutex_lock(&state->operation_lock);
	mutex_lock(&kasumi_seq_states_lock);
	if (state->attached) {
		WRITE_ONCE(state->seq->op, state->original);
		state->attached = false;
		hash_del_rcu(&state->node);
		kasumi_seq_state_put(state);
	}
	mutex_unlock(&kasumi_seq_states_lock);
	mutex_unlock(&state->operation_lock);
	kasumi_seq_state_put(state);
}

static KASUMI_NOCFI int kasumi_seq_release(struct inode *inode, struct file *file)
{
	struct kasumi_seq_guard guard;
	int ret;

	kasumi_seq_guard_enter(&guard, &kasumi_seq_release_probe);
	kasumi_seq_detach(file);
	ret = kasumi_seq_release_original(inode, file);
	kasumi_seq_guard_leave(&guard);
	return ret;
}

static KASUMI_NOCFI int kasumi_single_release(struct inode *inode, struct file *file)
{
	struct kasumi_seq_guard guard;
	int ret;

	kasumi_seq_guard_enter(&guard, &kasumi_single_release_probe);
	kasumi_seq_detach(file);
	ret = kasumi_single_release_original(inode, file);
	kasumi_seq_guard_leave(&guard);
	return ret;
}

static KASUMI_NOCFI int kasumi_map_release(struct inode *inode, struct file *file)
{
	struct kasumi_seq_guard guard;
	int ret;

	kasumi_seq_guard_enter(&guard, &kasumi_map_release_probe);
	kasumi_seq_detach(file);
	ret = kasumi_map_release_original(inode, file);
	kasumi_seq_guard_leave(&guard);
	return ret;
}

static KASUMI_NOCFI int kasumi_mount_release(struct inode *inode, struct file *file)
{
	struct kasumi_seq_guard guard;
	int ret;

	kasumi_seq_guard_enter(&guard, &kasumi_mount_release_probe);
	kasumi_seq_detach(file);
	ret = kasumi_mount_release_original(inode, file);
	kasumi_seq_guard_leave(&guard);
	return ret;
}

static KASUMI_NOCFI __poll_t kasumi_mounts_poll(struct file *file, poll_table *wait)
{
	struct kasumi_seq_guard guard;
	struct kasumi_seq_state *state;
	__poll_t result;
	u64 generation, policy_generation;

	kasumi_seq_guard_enter(&guard, &kasumi_mounts_poll_probe);
	result = kasumi_mounts_poll_original(file, wait);
	state = kasumi_seq_attach(file);
	if (IS_ERR(state)) {
		result |= EPOLLERR;
		goto out;
	}
	mutex_lock(&state->operation_lock);
	kasumi_fake_mi_poll_wait(file, wait);
	generation = kasumi_fake_mi_generation();
	policy_generation = kasumi_fake_mi_policy_generation();
	if (state->poll_generation != generation ||
	    state->poll_policy_generation != policy_generation) {
		state->poll_generation = generation;
		state->poll_policy_generation = policy_generation;
		result |= EPOLLERR | EPOLLPRI;
	}
	mutex_unlock(&state->operation_lock);
	kasumi_seq_state_put(state);
out:
	kasumi_seq_guard_leave(&guard);
	return result;
}

static int kasumi_seq_pre(struct kprobe *probe, struct pt_regs *regs)
{
#if defined(CONFIG_ARM64)
	struct file *file;
	unsigned long target;
	enum kasumi_seq_kind kind;
	bool attached = false;

	if (kasumi_vfs_internal_current())
		return 0;
#ifdef PROCMAP_QUERY
	if (probe == &kasumi_seq_query_probe) {
		if (regs->regs[1] != PROCMAP_QUERY ||
		    READ_ONCE(kasumi_seq_stopping) ||
		    !kasumi_config_enabled() ||
		    !(kasumi_config_features() & KSM_FEATURE_MAPS_SPOOF) ||
		    kasumi_policy_current_scope() != KASUMI_POLICY_SCOPE_SPOOF ||
		    kasumi_seq_guarded(probe))
			return 0;
		atomic_inc(&kasumi_seq_active);
		instruction_pointer_set(regs, (unsigned long)kasumi_seq_query);
		return 1;
	}
#endif
	if (probe == &kasumi_seq_read_probe) {
		struct kiocb *iocb = (void *)regs->regs[0];
		struct iov_iter *iter = (void *)regs->regs[1];

		if (!iov_iter_count(iter))
			return 0;
		file = iocb->ki_filp;
		target = (unsigned long)kasumi_seq_read;
	} else if (probe == &kasumi_seq_seek_probe) {
		if (regs->regs[2] != SEEK_SET && regs->regs[2] != SEEK_CUR)
			return 0;
		file = (void *)regs->regs[0];
		target = (unsigned long)kasumi_seq_seek;
	} else if (probe == &kasumi_mounts_poll_probe) {
		file = (void *)regs->regs[0];
		target = (unsigned long)kasumi_mounts_poll;
	} else {
		file = (void *)regs->regs[1];
		if (probe == &kasumi_map_release_probe)
			target = (unsigned long)kasumi_map_release;
		else if (probe == &kasumi_mount_release_probe)
			target = (unsigned long)kasumi_mount_release;
		else
			target = probe == &kasumi_single_release_probe ?
				(unsigned long)kasumi_single_release : (unsigned long)kasumi_seq_release;
	}
	kind = kasumi_seq_selected(file, &attached);
	if (kind == KASUMI_SEQ_NONE)
		return 0;
	if (!attached) {
		if (probe == &kasumi_seq_release_probe ||
		    probe == &kasumi_map_release_probe ||
		    probe == &kasumi_mount_release_probe ||
		    probe == &kasumi_single_release_probe ||
		    READ_ONCE(kasumi_seq_stopping))
			return 0;
		if (kind == KASUMI_SEQ_MAPS) {
			if (!kasumi_config_enabled() ||
			    !(kasumi_config_features() & KSM_FEATURE_MAPS_SPOOF) ||
			    kasumi_policy_current_scope() != KASUMI_POLICY_SCOPE_SPOOF)
				return 0;
		} else if (kind == KASUMI_SEQ_FDINFO) {
			if (!kasumi_config_enabled() ||
			    kasumi_policy_current_scope() == KASUMI_POLICY_SCOPE_NONE)
				return 0;
		} else if (!kasumi_mount_projection_active() &&
			   !(kind == KASUMI_SEQ_MOUNTINFO && kasumi_mount_groups_active())) {
			return 0;
		}
	}
	if (kasumi_seq_guarded(probe))
		return 0;
	atomic_inc(&kasumi_seq_active);
	instruction_pointer_set(regs, target);
	return 1;
#else
	return 0;
#endif
}

static int kasumi_seq_register(struct kprobe *probe, unsigned long address)
{
	probe->addr = (kprobe_opcode_t *)address;
	probe->pre_handler = kasumi_seq_pre;
	return register_kprobe(probe);
}

bool kasumi_proc_seq_available(void)
{
	return READ_ONCE(kasumi_seq_ready);
}

bool kasumi_proc_maps_available(void)
{
#ifdef PROCMAP_QUERY
	if (!READ_ONCE(kasumi_seq_query_registered))
		return false;
#endif
	return kasumi_proc_seq_available();
}

u64 kasumi_proc_seq_capabilities(void)
{
	u64 capabilities;

	if (!kasumi_proc_seq_available())
		return 0;
	capabilities = KASUMI_PROC_SEQ_CAP_READ | KASUMI_PROC_SEQ_CAP_SEEK |
		KASUMI_PROC_SEQ_CAP_PREAD | KASUMI_PROC_SEQ_CAP_HISTORICAL_FD |
		KASUMI_PROC_SEQ_CAP_SHARED_FD;
#ifdef PROCMAP_QUERY
	if (kasumi_seq_query_registered)
		capabilities |= KASUMI_PROC_SEQ_CAP_QUERY;
#endif
	return capabilities;
}

KASUMI_NOCFI void kasumi_proc_seq_stop(void)
{
	struct kasumi_seq_state *state, *candidate;
	int bucket;

	WRITE_ONCE(kasumi_seq_ready, false);
	WRITE_ONCE(kasumi_seq_mount_ready, false);
	WRITE_ONCE(kasumi_seq_stopping, true);
	kasumi_mount_view_publish_capabilities(0, KASUMI_MOUNT_CAP_INFO |
		KASUMI_MOUNT_CAP_MOUNTS | KASUMI_MOUNT_CAP_STATS | KASUMI_MOUNT_CAP_FDINFO);
	kasumi_mount_query_stop();
	kasumi_mount_stat_stop();
#ifdef PROCMAP_QUERY
	if (kasumi_seq_query_registered) {
		unregister_kprobe(&kasumi_seq_query_probe);
		kasumi_seq_query_registered = false;
	}
#endif
	for (;;) {
		state = NULL;
		mutex_lock(&kasumi_seq_states_lock);
		hash_for_each(kasumi_seq_states, bucket, candidate, node) {
			if (refcount_inc_not_zero(&candidate->refs)) {
				state = candidate;
				break;
			}
		}
		mutex_unlock(&kasumi_seq_states_lock);
		if (!state)
			break;
		mutex_lock(&state->operation_lock);
		if (state->attached) {
			mutex_lock(&state->seq->lock);
			mutex_lock(&kasumi_seq_states_lock);
			WRITE_ONCE(state->seq->op, state->original);
			state->seq->read_pos = -1;
			state->seq->count = 0;
			state->attached = false;
			hash_del_rcu(&state->node);
			kasumi_seq_state_put(state);
			mutex_unlock(&kasumi_seq_states_lock);
			mutex_unlock(&state->seq->lock);
		}
		mutex_unlock(&state->operation_lock);
		kasumi_seq_state_put(state);
	}
	if (kasumi_seq_read_registered) {
		unregister_kprobe(&kasumi_seq_read_probe);
		kasumi_seq_read_registered = false;
	}
	if (kasumi_seq_seek_registered) {
		unregister_kprobe(&kasumi_seq_seek_probe);
		kasumi_seq_seek_registered = false;
	}
	if (kasumi_seq_release_registered) {
		unregister_kprobe(&kasumi_seq_release_probe);
		kasumi_seq_release_registered = false;
	}
	if (kasumi_map_release_registered) {
		unregister_kprobe(&kasumi_map_release_probe);
		kasumi_map_release_registered = false;
	}
	if (kasumi_mount_release_registered) {
		unregister_kprobe(&kasumi_mount_release_probe);
		kasumi_mount_release_registered = false;
	}
	if (kasumi_single_release_registered) {
		unregister_kprobe(&kasumi_single_release_probe);
		kasumi_single_release_registered = false;
	}
	if (kasumi_mounts_poll_registered) {
		unregister_kprobe(&kasumi_mounts_poll_probe);
		kasumi_mounts_poll_registered = false;
	}
	wait_event(kasumi_seq_wait, !atomic_read(&kasumi_seq_active));
	if (kasumi_seq_tasks_barrier)
		kasumi_seq_tasks_barrier();
	rcu_barrier();
}

int kasumi_proc_seq_init(void)
{
	int ret;
	bool mount_supported;

	if (kasumi_proc_seq_available())
		return 0;
#if !defined(CONFIG_ARM64)
	return -EOPNOTSUPP;
#endif
	kasumi_seq_read_original =
		(void *)kasumi_lookup_callable_quiet("seq_read_iter");
	kasumi_seq_seek_original =
		(void *)kasumi_lookup_callable_quiet("seq_lseek");
	kasumi_seq_release_original =
		(void *)kasumi_lookup_callable_quiet("seq_release");
	kasumi_map_release_original =
		(void *)kasumi_lookup_callable_quiet("proc_map_release");
	kasumi_mount_release_original =
		(void *)kasumi_lookup_callable_quiet("mounts_release");
	kasumi_single_release_original =
		(void *)kasumi_lookup_callable_quiet("single_release");
	kasumi_mounts_poll_original =
		(void *)kasumi_lookup_callable_quiet("mounts_poll");
	kasumi_maps_show_original =
		(void *)kasumi_lookup_callable_quiet("show_map");
	kasumi_smaps_show_original =
		(void *)kasumi_lookup_callable_quiet("show_smap");
	kasumi_seq_tasks_barrier =
		(void *)kasumi_lookup_callable_quiet("synchronize_rcu_tasks");
	kasumi_mounts_operations =
		(void *)kasumi_lookup_name_quiet("mounts_op");
	kasumi_fdinfo_operations =
		(void *)kasumi_lookup_name_quiet("proc_fdinfo_file_operations");
	kasumi_mountinfo_show_original =
		(void *)kasumi_lookup_callable_quiet("show_mountinfo");
	kasumi_mounts_show_original =
		(void *)kasumi_lookup_callable_quiet("show_vfsmnt");
	kasumi_mountstats_show_original =
		(void *)kasumi_lookup_callable_quiet("show_vfsstat");
#ifdef CONFIG_FILE_LOCKING
	kasumi_fd_locks_show = (void *)kasumi_lookup_callable_quiet("show_fd_locks");
#endif
	if (!kasumi_seq_read_original || !kasumi_seq_seek_original ||
	    !kasumi_seq_release_original || !kasumi_map_release_original ||
	    !kasumi_maps_show_original ||
	    !kasumi_smaps_show_original || !kasumi_seq_tasks_barrier)
		return -ENOENT;
	mount_supported = kasumi_single_release_original && kasumi_mounts_poll_original &&
		kasumi_mounts_operations && kasumi_fdinfo_operations &&
		kasumi_mountinfo_show_original && kasumi_mounts_show_original &&
		kasumi_mountstats_show_original && kasumi_mount_release_original;
#ifdef CONFIG_FILE_LOCKING
	mount_supported = mount_supported && kasumi_fd_locks_show;
#endif
#ifdef PROCMAP_QUERY
	ret = kasumi_query_resolve();
	if (!ret)
		ret = kasumi_seq_register(
		    &kasumi_seq_query_probe,
		    kasumi_lookup_name_quiet("procfs_procmap_ioctl"));
	if (!ret)
		kasumi_seq_query_registered = true;
	else
		pr_warn("kasumi: proc map query unavailable: %d; maps "
			"projection disabled\n",
			ret);
#endif
	ret = kasumi_seq_register(&kasumi_seq_release_probe,
				 kasumi_lookup_name_quiet("seq_release"));
	if (ret)
		goto fail;
	kasumi_seq_release_registered = true;
	/* These fops targets remain real calls even when the compiler inlines
	 * seq_release into seq_release_private in the native helper. */
	ret = kasumi_seq_register(&kasumi_map_release_probe,
				 kasumi_lookup_name_quiet("proc_map_release"));
	if (ret)
		goto fail;
	kasumi_map_release_registered = true;
	ret = kasumi_seq_register(&kasumi_seq_seek_probe,
				 kasumi_lookup_name_quiet("seq_lseek"));
	if (ret)
		goto fail;
	kasumi_seq_seek_registered = true;
	ret = kasumi_seq_register(&kasumi_seq_read_probe,
				 kasumi_lookup_name_quiet("seq_read_iter"));
	if (ret)
		goto fail;
	kasumi_seq_read_registered = true;
	if (mount_supported) {
		ret = kasumi_seq_register(&kasumi_single_release_probe,
					 kasumi_lookup_name_quiet("single_release"));
		if (!ret) {
			kasumi_single_release_registered = true;
			ret = kasumi_seq_register(&kasumi_mount_release_probe,
						 kasumi_lookup_name_quiet("mounts_release"));
			if (!ret)
				kasumi_mount_release_registered = true;
		}
		if (!ret) {
			ret = kasumi_seq_register(&kasumi_mounts_poll_probe,
						 kasumi_lookup_name_quiet("mounts_poll"));
			if (!ret)
				kasumi_mounts_poll_registered = true;
		}
		if (ret) {
			if (kasumi_single_release_registered) {
				unregister_kprobe(&kasumi_single_release_probe);
				kasumi_single_release_registered = false;
			}
			if (kasumi_mount_release_registered) {
				unregister_kprobe(&kasumi_mount_release_probe);
				kasumi_mount_release_registered = false;
			}
		}
	}
	WRITE_ONCE(kasumi_seq_stopping, false);
	WRITE_ONCE(kasumi_seq_ready, true);
	if (kasumi_mounts_poll_registered) {
		WRITE_ONCE(kasumi_seq_mount_ready, true);
		kasumi_mount_view_publish_capabilities(KASUMI_MOUNT_CAP_INFO |
			KASUMI_MOUNT_CAP_MOUNTS | KASUMI_MOUNT_CAP_STATS | KASUMI_MOUNT_CAP_FDINFO, 0);
	}
	(void)kasumi_mount_query_init();
	(void)kasumi_mount_stat_init();
	return 0;
fail:
	kasumi_proc_seq_stop();
	return ret;
}
