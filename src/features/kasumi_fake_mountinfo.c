/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - shared immutable mountinfo snapshots for isolated readers.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include "kasumi_fake_mountinfo.h"
#include "kasumi_entrypoints.h"
#include "kasumi_path_policy.h"
#include "kasumi_runtime.h"
#ifdef KASUMI_EMBEDDED
#include "infra/mount_policy.h"
#endif

#include <linux/cred.h>
#include <linux/fs_struct.h>
#include <linux/jhash.h>
#include <linux/mnt_namespace.h>
#include <linux/nsproxy.h>
#include <linux/pid.h>
#include <linux/random.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/uio.h>
#include <linux/vmalloc.h>

static typeof(copy_mnt_ns) *kasumi_copy_mnt_ns;
static typeof(put_mnt_ns) *kasumi_put_mnt_ns;
static bool fake_mi_initialized;
static atomic64_t fake_mi_view_gen = ATOMIC64_INIT(1);
static DECLARE_WAIT_QUEUE_HEAD(fake_mi_view_wait);

typedef int (*kasumi_mi_show_fn)(struct seq_file *, struct vfsmount *);
static kasumi_mi_show_fn kasumi_mi_mountinfo_raw;
static kasumi_mi_show_fn kasumi_mi_mounts_raw;

/* This prefix is shared by proc_mounts across supported kernels. */
struct kasumi_proc_mounts_prefix {
	struct mnt_namespace *ns;
	struct path root;
	kasumi_mi_show_fn show;
};

bool kasumi_fake_mi_native_view(struct file *file)
{
	struct seq_file *seq = file ? file->private_data : NULL;
	struct kasumi_proc_mounts_prefix *pm = seq ? seq->private : NULL;
	struct task_struct *init;
	struct pid *pid;
	bool native_view = false;

	if (!current->nsproxy ||
	    (file && (!pm || pm->ns != current->nsproxy->mnt_ns)))
		return false;
	pid = find_get_pid(1);
	if (!pid)
		return false;
	init = get_pid_task(pid, PIDTYPE_PID);
	put_pid(pid);
	if (!init)
		return false;
	task_lock(init);
	native_view =
	    init->nsproxy && init->nsproxy->mnt_ns == current->nsproxy->mnt_ns;
	task_unlock(init);
	put_task_struct(init);
	return native_view;
}

/* Module-owned callbacks preserve old Clang CFI jump-table types. */
static KASUMI_NOCFI int kasumi_mi_show_mountinfo(struct seq_file *seq,
						 struct vfsmount *mnt)
{
	return kasumi_mi_mountinfo_raw(seq, mnt);
}

static KASUMI_NOCFI int kasumi_mi_show_mounts(struct seq_file *seq,
					      struct vfsmount *mnt)
{
	return kasumi_mi_mounts_raw(seq, mnt);
}

static bool kasumi_mountinfo_donor_live(struct task_struct *task)
{
	return pid_alive(task) && !READ_ONCE(task->exit_state) &&
	       !(READ_ONCE(task->flags) & (PF_EXITING | PF_KTHREAD)) &&
	       task->mm && task->fs && task->nsproxy && task->nsproxy->mnt_ns;
}

static struct task_struct *kasumi_mountinfo_pick_app(uid_t *selected_uid)
{
	struct task_struct *group, *task, *selected = NULL;
	u32 seed = get_random_u32();
	u32 best = 0;

	rcu_read_lock();
	for_each_process_thread(group, task)
	{
		uid_t uid = __kuid_val(task_uid(task));
		uid_t appid = uid % 100000;
		u32 score;
		bool live;

		if (appid < 10000 || appid > 19999 ||
		    !kasumi_policy_uid_is_spoof_target(uid))
			continue;
		/* All processes of one UID share a score, avoiding
		 * process-count bias. */
		score = jhash_1word(uid, seed);
		if (selected && score >= best)
			continue;
		task_lock(task);
		live = kasumi_mountinfo_donor_live(task) &&
		       __kuid_val(task_uid(task)) == uid;
		task_unlock(task);
		if (!live)
			continue;
		selected = task;
		*selected_uid = uid;
		best = score;
	}
	if (selected)
		get_task_struct(selected);
	rcu_read_unlock();
	return selected;
}

/* Called before the first seq read or seek that can start mount traversal. */
static KASUMI_NOCFI bool
kasumi_fake_mi_redirect(struct file *file, struct mnt_namespace **original_ns)
{
	struct seq_file *seq = file->private_data;
	struct kasumi_proc_mounts_prefix *pm;
	struct task_struct *task;
	struct mnt_namespace *ns = NULL;
	struct path root = {}, old_root;
	uid_t uid = 0;

	if (!READ_ONCE(fake_mi_initialized) || !seq ||
	    !kasumi_policy_current_is_isolated() ||
	    !kasumi_policy_current_is_spoof_target() ||
	    !(READ_ONCE(kasumi_feature_enabled_mask) & KSM_FEATURE_MOUNT_HIDE))
		return false;
	pm = seq->private;
	if (!pm || !pm->ns || !pm->root.mnt || !pm->root.dentry || !pm->show)
		return false;
	task = kasumi_mountinfo_pick_app(&uid);
	if (!task)
		return false;
	task_lock(task);
	if (kasumi_mountinfo_donor_live(task) &&
	    __kuid_val(task_uid(task)) == uid &&
	    kasumi_policy_uid_is_spoof_target(uid)) {
		/* With no CLONE_NEWNS, copy_mnt_ns only takes a namespace
		 * reference. */
		ns = kasumi_copy_mnt_ns(0, task->nsproxy->mnt_ns, NULL, NULL);
		if (!IS_ERR_OR_NULL(ns))
			get_fs_root(task->fs, &root);
	}
	task_unlock(task);
	put_task_struct(task);
	if (IS_ERR_OR_NULL(ns))
		return false;

	mutex_lock(&seq->lock);
	*original_ns = pm->ns;
	old_root = pm->root;
	pm->ns = ns;
	pm->root = root;
	mutex_unlock(&seq->lock);
	/* Native release now owns the donor references and its traversal
	 * cursor. */
	path_put(&old_root);
	kasumi_log("mountinfo: donor uid=%u reader=%d\n", uid,
		   task_pid_nr(current));
	return true;
}

KASUMI_NOCFI void kasumi_fake_mi_put_ns(struct mnt_namespace *ns)
{
	if (ns)
		kasumi_put_mnt_ns(ns);
}

#define KASUMI_MI_INITIAL_SIZE 65536
#define KASUMI_MI_MAX_SIZE (1024 * 1024)

static DEFINE_MUTEX(kasumi_mi_snapshot_lock);
/* The first successful snapshot is retained until Kasumi exits. */
static struct kasumi_mi_snapshot *kasumi_mi_snapshot;
static bool kasumi_mi_snapshot_ready;

void kasumi_fake_mi_put_snapshot(struct kasumi_mi_snapshot *snapshot)
{
	if (!snapshot || !refcount_dec_and_test(&snapshot->refs))
		return;
	kvfree(snapshot->data);
	kvfree(snapshot->mounts);
	kfree(snapshot);
}

static KASUMI_NOCFI int
kasumi_mi_read_snapshot(struct file *file, const struct file_operations *ops,
			char **buffer, size_t *length, size_t *capacity)
{
	loff_t pos = 0;

	(*length) = 0;
	for (;;) {
		struct kiocb iocb;
		struct iov_iter iter;
		struct kvec vec;
		char overflow;
		ssize_t ret;

		if ((*length) == *capacity && *capacity < KASUMI_MI_MAX_SIZE) {
			size_t size =
			    min_t(size_t, *capacity * 2, KASUMI_MI_MAX_SIZE);
			char *data = kvmalloc(size, GFP_KERNEL);

			if (!data)
				return -ENOMEM;
			memcpy(data, (*buffer), (*length));
			kvfree((*buffer));
			(*buffer) = data;
			*capacity = size;
		}
		vec.iov_base =
		    (*length) == *capacity ? &overflow : (*buffer) + (*length);
		vec.iov_len =
		    (*length) == *capacity ? 1 : *capacity - (*length);
		iov_iter_kvec(&iter, READ, &vec, 1, vec.iov_len);
		init_sync_kiocb(&iocb, file);
		iocb.ki_pos = pos;
		ret = ops->read_iter ? ops->read_iter(&iocb, &iter)
				     : seq_read_iter(&iocb, &iter);
		if (ret < 0)
			return ret;
		if (!ret)
			return (*length) ? 0 : -EIO;
		if ((*length) == *capacity)
			return -EFBIG;
		if (ret > vec.iov_len || iocb.ki_pos <= pos)
			return -EIO;
		(*length) += ret;
		pos = iocb.ki_pos;
	}
}

struct kasumi_mi_prop_ref {
	size_t start;
	size_t end;
	u32 id;
};

static int kasumi_mi_collect_props(const char *data, size_t len,
				   struct kasumi_mi_prop_ref *refs,
				   size_t *count)
{
	size_t line = 0, found = 0;

	while (line < len) {
		const char *newline = memchr(data + line, '\n', len - line);
		size_t end = newline ? (size_t)(newline - data) : len;
		size_t cursor = line;
		unsigned int field;
		bool separator = false;

		for (field = 0; field < 6; field++) {
			const char *space =
			    memchr(data + cursor, ' ', end - cursor);

			if (!space || space == data + cursor)
				return -EINVAL;
			cursor = space - data + 1;
		}
		while (cursor < end) {
			const char *space =
			    memchr(data + cursor, ' ', end - cursor);
			size_t token_end = space ? (size_t)(space - data) : end;
			size_t token_len = token_end - cursor;
			size_t prefix = 0, i;
			u32 id = 0;

			if (!token_len)
				return -EINVAL;
			if (token_len == 1 && data[cursor] == '-') {
				separator = true;
				break;
			}
			if (token_len >= 7 &&
			    !memcmp(data + cursor, "shared:", 7))
				prefix = 7;
			else if (token_len >= 7 &&
				 !memcmp(data + cursor, "master:", 7))
				prefix = 7;
			else if (token_len >= 15 &&
				 !memcmp(data + cursor, "propagate_from:", 15))
				prefix = 15;
			if (prefix) {
				if (prefix == token_len)
					return -EINVAL;
				for (i = cursor + prefix; i < token_end; i++) {
					u32 digit = data[i] - '0';

					if (digit > 9 ||
					    id > (~0U - digit) / 10)
						return -EINVAL;
					id = id * 10 + digit;
				}
				if (!id)
					return -EINVAL;
				if (refs) {
					if (found >= *count)
						return -ENOSPC;
					refs[found] =
					    (struct kasumi_mi_prop_ref){
						.start = cursor + prefix,
						.end = token_end,
						.id = id};
				}
				found++;
			}
			cursor = token_end + 1;
		}
		if (!separator)
			return -EINVAL;
		line = end + 1;
	}
	*count = found;
	return 0;
}

static int kasumi_mi_compare_ids(const void *a, const void *b)
{
	u32 left = *(const u32 *)a, right = *(const u32 *)b;

	return (left > right) - (left < right);
}

/* Only propagation numbers change; sorted positive IDs never grow in width. */
static int kasumi_mi_normalize_groups(char *data, size_t *len)
{
	struct kasumi_mi_prop_ref *refs = NULL;
	u32 *ids = NULL;
	size_t count = 0, unique = 0, i, input = 0, output = 0;
	int ret;

	ret = kasumi_mi_collect_props(data, *len, NULL, &count);
	if (ret || !count)
		return ret;
	refs = kvmalloc_array(count, sizeof(*refs), GFP_KERNEL);
	ids = kvmalloc_array(count, sizeof(*ids), GFP_KERNEL);
	if (!refs || !ids) {
		ret = -ENOMEM;
		goto out;
	}
	ret = kasumi_mi_collect_props(data, *len, refs, &count);
	if (ret)
		goto out;
	for (i = 0; i < count; i++)
		ids[i] = refs[i].id;
	sort(ids, count, sizeof(*ids), kasumi_mi_compare_ids, NULL);
	for (i = 0; i < count; i++)
		if (!unique || ids[i] != ids[unique - 1])
			ids[unique++] = ids[i];
	for (i = 0; i < count; i++) {
		size_t low = 0, high = unique, segment;
		char number[16];
		int width;

		while (low < high) {
			size_t mid = low + (high - low) / 2;

			if (ids[mid] < refs[i].id)
				low = mid + 1;
			else
				high = mid;
		}
		if (low == unique || ids[low] != refs[i].id) {
			ret = -EINVAL;
			goto out;
		}
		width = scnprintf(number, sizeof(number), "%u", (u32)low + 1);
		if (width > refs[i].end - refs[i].start) {
			ret = -EOVERFLOW;
			goto out;
		}
		segment = refs[i].start - input;
		memmove(data + output, data + input, segment);
		output += segment;
		memcpy(data + output, number, width);
		output += width;
		input = refs[i].end;
	}
	memmove(data + output, data + input, *len - input);
	*len = output + *len - input;
out:
	kvfree(ids);
	kvfree(refs);
	return ret;
}

static bool kasumi_mi_line_target(const char *line, size_t len,
				  unsigned int field, const char **target,
				  size_t *target_len)
{
	size_t start = 0;
	unsigned int i;

	for (i = 0; i <= field; i++) {
		const char *space = memchr(line + start, ' ', len - start);
		size_t end = space ? (size_t)(space - line) : len;

		if (start == end)
			return false;
		if (i == field) {
			*target = line + start;
			*target_len = end - start;
			return true;
		}
		if (!space)
			return false;
		start = end + 1;
	}
	return false;
}

static bool kasumi_mi_pair_matches(const struct kasumi_mi_snapshot *snapshot)
{
	size_t mi = 0, mo = 0;

	while (mi < snapshot->len && mo < snapshot->mounts_len) {
		const char *mi_end =
		    memchr(snapshot->data + mi, '\n', snapshot->len - mi);
		const char *mo_end = memchr(snapshot->mounts + mo, '\n',
					    snapshot->mounts_len - mo);
		size_t mi_len = mi_end ? (size_t)(mi_end - snapshot->data) - mi
				       : snapshot->len - mi;
		size_t mo_len = mo_end
				    ? (size_t)(mo_end - snapshot->mounts) - mo
				    : snapshot->mounts_len - mo;
		const char *mi_target, *mo_target;
		size_t mi_target_len, mo_target_len;

		if (!kasumi_mi_line_target(snapshot->data + mi, mi_len, 4,
					   &mi_target, &mi_target_len) ||
		    !kasumi_mi_line_target(snapshot->mounts + mo, mo_len, 1,
					   &mo_target, &mo_target_len) ||
		    mi_target_len != mo_target_len ||
		    memcmp(mi_target, mo_target, mi_target_len))
			return false;
		mi += mi_len + !!mi_end;
		mo += mo_len + !!mo_end;
	}
	return mi == snapshot->len && mo == snapshot->mounts_len;
}

struct kasumi_mi_row {
	u32 id;
	u32 parent;
	u8 state;
};

enum {
	KASUMI_MI_UNVISITED,
	KASUMI_MI_VISITING,
	KASUMI_MI_VISIBLE,
	KASUMI_MI_HIDDEN,
};

static size_t kasumi_mi_line_size(const char *data, size_t len)
{
	const char *end = memchr(data, '\n', len);

	return end ? (size_t)(end - data) + 1 : len;
}

static int kasumi_mi_line_id(const char *line, size_t len, unsigned int field,
			     u32 *id)
{
	const char *value;
	size_t size;
	char number[12];

	if (!kasumi_mi_line_target(line, len, field, &value, &size) || !size ||
	    size >= sizeof(number) || value[0] < '0' || value[0] > '9')
		return -EINVAL;
	memcpy(number, value, size);
	number[size] = '\0';
	if (kstrtou32(number, 10, id) || !*id)
		return -EINVAL;
	return 0;
}

#ifndef KASUMI_EMBEDDED
static bool kasumi_mi_field_matches(const char *data, size_t len,
				    const char *text, bool path)
{
	size_t pos = 0;

	while (*text) {
		unsigned char c;

		if (pos == len)
			return false;
		c = data[pos++];
		if (c == '\\' && pos + 2 < len && data[pos] >= '0' &&
		    data[pos] <= '3' && data[pos + 1] >= '0' &&
		    data[pos + 1] <= '7' && data[pos + 2] >= '0' &&
		    data[pos + 2] <= '7') {
			c = ((data[pos] - '0') << 6) |
			    ((data[pos + 1] - '0') << 3) |
			    (data[pos + 2] - '0');
			pos += 3;
		}
		if (c != (unsigned char)*text++)
			return false;
	}
	return pos == len || (path && data[pos] == '/');
}

static bool kasumi_mi_private_path(const char *data, size_t len)
{
	return kasumi_mi_field_matches(data, len, "/adb", true) ||
	       kasumi_mi_field_matches(data, len, "/data/adb", true);
}
#endif

static int kasumi_mi_module_line(const char *line, size_t len, bool *hidden)
{
	const char *values[6], *separator;
	size_t sizes[6], after_len;
	unsigned int i;
	static const unsigned int fields[] = {2, 3, 4, 0, 1, 2};

	separator = strnstr(line, " - ", len);
	if (!separator)
		return -EINVAL;
	after_len = len - (separator + 3 - line);
	for (i = 0; i < ARRAY_SIZE(fields); i++) {
		if (!kasumi_mi_line_target(i < 3 ? line : separator + 3,
					   i < 3 ? separator - line : after_len,
					   fields[i], &values[i], &sizes[i]))
			return -EINVAL;
	}
#ifdef KASUMI_EMBEDDED
	{
		struct ksu_mount_fields mount = {
		    .dev = {values[0], sizes[0]},
		    .root = {values[1], sizes[1]},
		    .target = {values[2], sizes[2]},
		    .fstype = {values[3], sizes[3]},
		    .source = {values[4], sizes[4]},
		    .super = {values[5], sizes[5]},
		    .escaped = true,
		};

		*hidden = ksu_mount_is_module(&mount);
	}
#else
	*hidden =
	    kasumi_mi_private_path(values[1], sizes[1]) ||
	    kasumi_mi_private_path(values[2], sizes[2]) ||
	    kasumi_mi_private_path(values[4], sizes[4]) ||
	    kasumi_mi_field_matches(values[4], sizes[4], "KSU", false) ||
	    kasumi_mi_field_matches(values[4], sizes[4], "magisk", false) ||
	    kasumi_mi_field_matches(values[4], sizes[4], "APatch", false);
	for (i = 0; !*hidden && i < sizes[5]; i++) {
		size_t end;

		if (values[5][i] != '/' ||
		    (i && values[5][i - 1] != '=' && values[5][i - 1] != ':' &&
		     values[5][i - 1] != ','))
			continue;
		for (end = i; end < sizes[5] && values[5][end] != ',' &&
			      values[5][end] != ':';
		     end++)
			;
		*hidden = kasumi_mi_private_path(values[5] + i, end - i);
	}
#endif
	return 0;
}

static int kasumi_mi_compare_rows(const void *a, const void *b)
{
	const struct kasumi_mi_row *left = a, *right = b;

	return (left->id > right->id) - (left->id < right->id);
}

static struct kasumi_mi_row *kasumi_mi_find_row(struct kasumi_mi_row *rows,
						size_t count, u32 id)
{
	size_t low = 0, high = count;

	while (low < high) {
		size_t mid = low + (high - low) / 2;

		if (rows[mid].id < id)
			low = mid + 1;
		else
			high = mid;
	}
	return low < count && rows[low].id == id ? rows + low : NULL;
}

/* Compact both files by ordinal; mount IDs and propagation stay native. */
static int kasumi_mi_filter_native(struct kasumi_mi_snapshot *snapshot)
{
	struct kasumi_mi_row *rows, *row;
	size_t count = 0, mi = 0, mo = 0, mi_out = 0, mo_out = 0, i;
	int ret = -EINVAL;

	if (!kasumi_mi_pair_matches(snapshot))
		return -EINVAL;
	while (mi < snapshot->len) {
		mi += kasumi_mi_line_size(snapshot->data + mi,
					  snapshot->len - mi);
		count++;
	}
	rows = kvcalloc(count, sizeof(*rows), GFP_KERNEL);
	if (!rows)
		return -ENOMEM;
	for (i = 0, mi = 0; i < count; i++) {
		const char *line = snapshot->data + mi;
		size_t size = kasumi_mi_line_size(line, snapshot->len - mi);
		size_t len = size - (line[size - 1] == '\n');
		bool hidden;

		if (kasumi_mi_line_id(line, len, 0, &rows[i].id) ||
		    kasumi_mi_line_id(line, len, 1, &rows[i].parent) ||
		    kasumi_mi_module_line(line, len, &hidden))
			goto out;
		rows[i].state = hidden ? KASUMI_MI_HIDDEN : KASUMI_MI_UNVISITED;
		mi += size;
	}
	sort(rows, count, sizeof(*rows), kasumi_mi_compare_rows, NULL);
	for (i = 1; i < count; i++)
		if (rows[i - 1].id == rows[i].id)
			goto out;
	for (i = 0; i < count; i++) {
		u8 state;

		row = rows + i;
		while (row && row->state == KASUMI_MI_UNVISITED) {
			row->state = KASUMI_MI_VISITING;
			row =
			    row->id == row->parent
				? NULL
				: kasumi_mi_find_row(rows, count, row->parent);
		}
		if (row && row->state == KASUMI_MI_VISITING)
			goto out;
		state = row ? row->state : KASUMI_MI_VISIBLE;
		row = rows + i;
		while (row && row->state == KASUMI_MI_VISITING) {
			row->state = state;
			row = kasumi_mi_find_row(rows, count, row->parent);
		}
	}
	for (mi = 0; mi < snapshot->len;) {
		size_t mi_size = kasumi_mi_line_size(snapshot->data + mi,
						     snapshot->len - mi);
		size_t mo_size = kasumi_mi_line_size(snapshot->mounts + mo,
						     snapshot->mounts_len - mo);
		u32 id;

		if (kasumi_mi_line_id(snapshot->data + mi, mi_size, 0, &id))
			goto out;
		row = kasumi_mi_find_row(rows, count, id);
		if (!row)
			goto out;
		if (row->state == KASUMI_MI_VISIBLE) {
			memmove(snapshot->data + mi_out, snapshot->data + mi,
				mi_size);
			memmove(snapshot->mounts + mo_out,
				snapshot->mounts + mo, mo_size);
			mi_out += mi_size;
			mo_out += mo_size;
		}
		mi += mi_size;
		mo += mo_size;
	}
	if (mi_out && mo_out) {
		snapshot->len = mi_out;
		snapshot->mounts_len = mo_out;
		ret = 0;
	}
out:
	kvfree(rows);
	return ret;
}

static KASUMI_NOCFI int kasumi_mi_render(struct file *file,
					 const struct file_operations *ops,
					 kasumi_mi_show_fn show, char **data,
					 size_t *len, size_t *capacity)
{
	struct seq_file *seq = file->private_data;
	struct kasumi_proc_mounts_prefix *pm = seq->private;
	int ret;

	WRITE_ONCE(pm->show, show);
	ret = ops->llseek(file, 0, SEEK_SET);
	if (ret < 0)
		return ret;
	return kasumi_mi_read_snapshot(file, ops, data, len, capacity);
}

int KASUMI_NOCFI kasumi_fake_mi_get_snapshot(struct file *file,
					     const struct file_operations *ops,
					     bool native_view,
					     struct mnt_namespace **original_ns,
					     struct kasumi_mi_snapshot **out)
{
	struct kasumi_mi_snapshot *snapshot = NULL;
	struct seq_file *seq = file->private_data;
	struct kasumi_proc_mounts_prefix *pm = NULL;
	kasumi_mi_show_fn original_show = NULL;
	size_t mi_capacity = KASUMI_MI_INITIAL_SIZE;
	size_t mo_capacity = KASUMI_MI_INITIAL_SIZE;
	int attempt, ret = 0;

	*out = NULL;
	mutex_lock(&kasumi_mi_snapshot_lock);
	/* Cache hits never consult donor liveness or UID policy again. */
	if (!native_view && kasumi_mi_snapshot) {
		refcount_inc(&kasumi_mi_snapshot->refs);
		*out = kasumi_mi_snapshot;
		goto unlock;
	}
	if (!ops->llseek) {
		ret = native_view ? -EOPNOTSUPP : 0;
		goto unlock;
	}
	if (!native_view && !kasumi_fake_mi_redirect(file, original_ns))
		goto unlock;
	pm = seq ? seq->private : NULL;
	if (!pm || !pm->ns || !pm->root.mnt || !pm->root.dentry || !pm->show) {
		ret = -EINVAL;
		goto unlock;
	}
	original_show = READ_ONCE(pm->show);
	snapshot = kzalloc(sizeof(*snapshot), GFP_KERNEL);
	if (!snapshot) {
		ret = -ENOMEM;
		goto unlock;
	}
	refcount_set(&snapshot->refs, 1);
	snapshot->data = kvmalloc(mi_capacity, GFP_KERNEL);
	snapshot->mounts = kvmalloc(mo_capacity, GFP_KERNEL);
	if (!snapshot->data || !snapshot->mounts) {
		ret = -ENOMEM;
		goto unlock;
	}
	for (attempt = 0; attempt < 3; attempt++) {
		unsigned long event;
#ifdef KASUMI_EMBEDDED
		u64 policy = native_view ? ksu_mount_policy_generation() : 0;

		if (policy & 1)
			continue;
#endif

		if (ops->poll)
			(void)ops->poll(file, NULL);
		event = READ_ONCE(seq->poll_event);
		ret = kasumi_mi_render(file, ops, kasumi_mi_show_mountinfo,
				       &snapshot->data, &snapshot->len,
				       &mi_capacity);
		if (ret)
			goto unlock;
		ret = kasumi_mi_render(file, ops, kasumi_mi_show_mounts,
				       &snapshot->mounts, &snapshot->mounts_len,
				       &mo_capacity);
		if (ret)
			goto unlock;
		if (ops->poll)
			(void)ops->poll(file, NULL);
		if (event != READ_ONCE(seq->poll_event) ||
		    !kasumi_mi_pair_matches(snapshot))
			continue;
		if (native_view) {
			ret = kasumi_mi_filter_native(snapshot);
			if (ret)
				goto unlock;
			if (ops->poll)
				(void)ops->poll(file, NULL);
			if (event != READ_ONCE(seq->poll_event))
				continue;
#ifdef KASUMI_EMBEDDED
			if (policy != ksu_mount_policy_generation())
				continue;
#endif
		}
		break;
	}
	if (attempt == 3) {
		ret = -EAGAIN;
		goto unlock;
	}
	ret = kasumi_mi_normalize_groups(snapshot->data, &snapshot->len);
	if (ret)
		goto unlock;
	if (native_view) {
		*out = snapshot;
		snapshot = NULL;
		goto unlock;
	}
	kasumi_mi_snapshot = snapshot;
	refcount_inc(&snapshot->refs);
	*out = snapshot;
	snapshot = NULL;
	smp_store_release(&kasumi_mi_snapshot_ready, true);
	kasumi_fake_mi_invalidate_all();
	kasumi_log("mountinfo: published shared snapshot mi=%zu mounts=%zu\n",
		   (*out)->len, (*out)->mounts_len);
unlock:
	if (original_show)
		WRITE_ONCE(pm->show, original_show);
	mutex_unlock(&kasumi_mi_snapshot_lock);
	kasumi_fake_mi_put_snapshot(snapshot);
	return ret;
}

bool kasumi_fake_mi_cached(void)
{
	return smp_load_acquire(&kasumi_mi_snapshot_ready);
}

void kasumi_fake_mi_invalidate_all(void)
{
	atomic64_inc(&fake_mi_view_gen);
	wake_up_all(&fake_mi_view_wait);
}

u64 kasumi_fake_mi_generation(void)
{
	return (u64)atomic64_read(&fake_mi_view_gen);
}

void kasumi_fake_mi_poll_wait(struct file *file, struct poll_table_struct *wait)
{
	poll_wait(file, &fake_mi_view_wait, wait);
}

int kasumi_fake_mi_init(void)
{
	kasumi_copy_mnt_ns = (void *)kasumi_lookup_callable("copy_mnt_ns");
	kasumi_put_mnt_ns = (void *)kasumi_lookup_callable("put_mnt_ns");
	kasumi_mi_mountinfo_raw = (void *)kasumi_lookup_name("show_mountinfo");
	kasumi_mi_mounts_raw = (void *)kasumi_lookup_name("show_vfsmnt");
	if (!kasumi_copy_mnt_ns || !kasumi_put_mnt_ns ||
	    !kasumi_mi_mountinfo_raw || !kasumi_mi_mounts_raw)
		return -ENOSYS;
	atomic64_set(&fake_mi_view_gen, 1);
	WRITE_ONCE(fake_mi_initialized, true);
	return 0;
}

void kasumi_fake_mi_exit(void)
{
	struct kasumi_mi_snapshot *snapshot;

	mutex_lock(&kasumi_mi_snapshot_lock);
	WRITE_ONCE(fake_mi_initialized, false);
	smp_store_release(&kasumi_mi_snapshot_ready, false);
	snapshot = kasumi_mi_snapshot;
	kasumi_mi_snapshot = NULL;
	mutex_unlock(&kasumi_mi_snapshot_lock);
	kasumi_fake_mi_put_snapshot(snapshot);
	kasumi_fake_mi_invalidate_all();
}

bool kasumi_fake_mi_active(void)
{
	return READ_ONCE(fake_mi_initialized);
}
