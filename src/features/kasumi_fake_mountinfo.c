/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - live app mountinfo views for isolated readers.
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

#include <linux/cred.h>
#include <linux/fs_struct.h>
#include <linux/jhash.h>
#include <linux/mnt_namespace.h>
#include <linux/nsproxy.h>
#include <linux/random.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/seq_file.h>

static typeof(copy_mnt_ns) *kasumi_copy_mnt_ns;
static typeof(put_mnt_ns) *kasumi_put_mnt_ns;
static bool fake_mi_initialized;
static atomic64_t fake_mi_view_gen = ATOMIC64_INIT(1);
static DECLARE_WAIT_QUEUE_HEAD(fake_mi_view_wait);

/* This prefix is shared by proc_mounts across supported kernels. */
struct kasumi_proc_mounts_prefix {
	struct mnt_namespace *ns;
	struct path root;
	int (*show)(struct seq_file *, struct vfsmount *);
};

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
KASUMI_NOCFI bool kasumi_fake_mi_redirect(struct file *file,
					  struct mnt_namespace **original_ns)
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
	if (!kasumi_copy_mnt_ns || !kasumi_put_mnt_ns)
		return -ENOSYS;
	atomic64_set(&fake_mi_view_gen, 1);
	WRITE_ONCE(fake_mi_initialized, true);
	return 0;
}

void kasumi_fake_mi_exit(void)
{
	WRITE_ONCE(fake_mi_initialized, false);
	kasumi_fake_mi_invalidate_all();
}

bool kasumi_fake_mi_active(void)
{
	return READ_ONCE(fake_mi_initialized);
}
