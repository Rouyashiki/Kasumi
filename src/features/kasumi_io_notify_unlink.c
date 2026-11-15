#include <linux/fsnotify_backend.h>
#include <linux/kprobes.h>
#include <linux/srcu.h>
#include <linux/version.h>
#include <linux/wait.h>

#include "kasumi_io_notify.h"
#include "kasumi_runtime.h"
#include "kasumi_vnode.h"

static void (*kasumi_io_destroy_marks)(struct fsnotify_mark_connector __rcu **);
static typeof(fsnotify_get_mark) *kasumi_io_get_mark;
static void (*kasumi_io_unlink_barrier)(void);
static atomic_t kasumi_io_unlink_active = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(kasumi_io_unlink_wait);
static bool kasumi_io_unlink_registered;
static struct srcu_struct *kasumi_io_mark_srcu;

struct kasumi_io_unlink_guard {
	struct hlist_node node;
	struct task_struct *task;
	struct fsnotify_mark_connector __rcu **object;
};

static DEFINE_SPINLOCK(kasumi_io_unlink_guard_lock);
static HLIST_HEAD(kasumi_io_unlink_guards);

static bool kasumi_io_unlink_guarded(struct fsnotify_mark_connector __rcu **object)
{
	struct kasumi_io_unlink_guard *guard;
	bool found = false;

	spin_lock(&kasumi_io_unlink_guard_lock);
	hlist_for_each_entry(guard, &kasumi_io_unlink_guards, node) {
		if (guard->task == current && guard->object == object) {
			found = true;
			break;
		}
	}
	spin_unlock(&kasumi_io_unlink_guard_lock);
	return found;
}

static void KASUMI_NOCFI kasumi_io_notify_native_delete(struct inode *inode)
{
	struct kasumi_io_unlink_guard guard = {
		.task = current, .object = &inode->i_fsnotify_marks,
	};

	spin_lock(&kasumi_io_unlink_guard_lock);
	hlist_add_head(&guard.node, &kasumi_io_unlink_guards);
	spin_unlock(&kasumi_io_unlink_guard_lock);
	kasumi_io_destroy_marks(guard.object);
	spin_lock(&kasumi_io_unlink_guard_lock);
	hlist_del(&guard.node);
	spin_unlock(&kasumi_io_unlink_guard_lock);
}

/* dentry_unlink_inode can retire native watches while another hardlink's
 * open file still owns this inode. Keep the private transport mark attached;
 * user marks already received DELETE_SELF and retain their native teardown.
 * The owner reference pins keep->connector throughout this traversal.
 */
static void KASUMI_NOCFI kasumi_io_notify_clear_others(struct fsnotify_mark *keep)
{
	struct fsnotify_mark_connector *connector = keep->connector;
	struct fsnotify_mark *mark, *previous = NULL;

	spin_lock(&connector->lock);
	hlist_for_each_entry(mark, &connector->list, obj_list) {
		if (mark == keep)
			continue;
		kasumi_io_get_mark(mark);
		spin_unlock(&connector->lock);
		if (previous)
			fsnotify_put_mark(previous);
		previous = mark;
		fsnotify_destroy_mark(mark, mark->group);
		spin_lock(&connector->lock);
	}
	spin_unlock(&connector->lock);
	if (previous)
		fsnotify_put_mark(previous);
}

static void KASUMI_NOCFI kasumi_io_notify_delete_inode(struct inode *inode)
{
	struct kasumi_vnode_info *info = inode->i_private;
	struct fsnotify_mark *keep;

	mutex_lock(&info->io_notify_lock);
	keep = kasumi_io_notify_alive_mark(info->io_notify);
	if (keep && !(READ_ONCE(inode->i_state) & I_FREEING))
		kasumi_io_notify_clear_others(keep);
	else
		kasumi_io_notify_native_delete(inode);
	mutex_unlock(&info->io_notify_lock);
	if (atomic_dec_and_test(&kasumi_io_unlink_active))
		wake_up_all(&kasumi_io_unlink_wait);
}

static int kasumi_io_notify_delete_pre(struct kprobe *probe, struct pt_regs *regs)
{
#ifdef CONFIG_ARM64
	struct fsnotify_mark_connector __rcu **object = (void *)regs->regs[0];
	struct fsnotify_mark_connector *connector;
	struct inode *inode = NULL;
	int index;

	(void)probe;
	if (!object || kasumi_io_unlink_guarded(object))
		return 0;
	/* LTO can inline __fsnotify_inode_delete at dentry removal. The native
	 * destroy-marks entry also handles mounts/superblocks, so resolve the
	 * object only while its connector is protected exactly as in the core.
	 */
	index = srcu_read_lock(kasumi_io_mark_srcu);
	connector = srcu_dereference(*object, kasumi_io_mark_srcu);
	if (connector) {
		spin_lock(&connector->lock);
		if (connector->type == FSNOTIFY_OBJ_TYPE_INODE) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
			inode = connector->obj;
#else
			inode = container_of(connector->obj, struct inode, i_fsnotify_marks);
#endif
		}
		spin_unlock(&connector->lock);
	}
	srcu_read_unlock(kasumi_io_mark_srcu, index);
	/* The native caller owns the object containing this exact connp until
	 * destroy_marks returns, including inode deletion with I_FREEING set.
	 */
	if (!inode || &inode->i_fsnotify_marks != object ||
	    (READ_ONCE(inode->i_state) & I_FREEING) ||
	    !kasumi_vnode_is_ours(inode))
		return 0;
	atomic_inc(&kasumi_io_unlink_active);
	regs->regs[0] = (unsigned long)inode;
	instruction_pointer_set(regs, (unsigned long)kasumi_io_notify_delete_inode);
	return 1;
#else
	(void)probe;
	(void)regs;
	return 0;
#endif
}

static struct kprobe kasumi_io_unlink_probe = {
	.symbol_name = "fsnotify_destroy_marks",
	.pre_handler = kasumi_io_notify_delete_pre,
};

int kasumi_io_notify_unlink_init(void)
{
	int error;

	if (kasumi_io_unlink_registered)
		return 0;
	if (!IS_ENABLED(CONFIG_ARM64))
		return -EOPNOTSUPP;
	kasumi_io_destroy_marks = (void *)kasumi_lookup_callable_quiet("fsnotify_destroy_marks");
	kasumi_io_get_mark = (void *)kasumi_lookup_callable_quiet("fsnotify_get_mark");
	kasumi_io_unlink_barrier = (void *)kasumi_lookup_callable_quiet("synchronize_rcu_tasks");
	kasumi_io_mark_srcu = (void *)kasumi_lookup_name_quiet("fsnotify_mark_srcu");
	if (!kasumi_io_destroy_marks || !kasumi_io_get_mark || !kasumi_io_unlink_barrier ||
	    !kasumi_io_mark_srcu)
		return -EOPNOTSUPP;
	kasumi_io_unlink_probe.addr = NULL;
	error = register_kprobe(&kasumi_io_unlink_probe);
	if (!error)
		kasumi_io_unlink_registered = true;
	return error;
}

void KASUMI_NOCFI kasumi_io_notify_unlink_exit(void)
{
	if (!kasumi_io_unlink_registered)
		return;
	unregister_kprobe(&kasumi_io_unlink_probe);
	kasumi_io_unlink_registered = false;
	wait_event(kasumi_io_unlink_wait, !atomic_read(&kasumi_io_unlink_active));
	kasumi_io_unlink_barrier();
}
