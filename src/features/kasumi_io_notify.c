#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/fsnotify_backend.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/wait.h>

#include "kasumi_io_notify.h"
#include "kasumi_runtime.h"

#define KASUMI_IO_NOTIFY_MASK (FS_ACCESS | FS_MODIFY)

static bool kasumi_io_notify_admitting;

/* Run in the native producer, including io_uring completion task_work. The
 * original file wrapper already applied FMODE_NONOTIFY and result semantics.
 * Re-enter the native source path dispatcher for its parent, mount and inode
 * watchers, preserving the producer credentials and pid.
 */
static void kasumi_io_notify_source(const struct path *source, u32 mask)
{
	fsnotify_parent(source->dentry, mask & KASUMI_IO_NOTIFY_MASK,
		source, FSNOTIFY_EVENT_PATH);
}


struct kasumi_io_notify {
	unsigned int users;
	struct fsnotify_mark mark;
	struct path source;
};

static struct fsnotify_group *kasumi_io_notify_group;
static typeof(fsnotify_alloc_group) *kasumi_io_alloc_group;
static typeof(fsnotify_destroy_group) *kasumi_io_destroy_group;
static typeof(fsnotify_add_mark) *kasumi_io_add_mark;
static atomic_t kasumi_io_notify_marks = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(kasumi_io_notify_wait);

static int kasumi_io_notify_event(struct fsnotify_group *group, u32 mask,
	const void *data, int data_type, struct inode *dir,
	const struct qstr *name, u32 cookie, struct fsnotify_iter_info *iterator)
{
	struct fsnotify_mark *mark = fsnotify_iter_inode_mark(iterator);
	struct kasumi_io_notify *relay;

	(void)group;
	(void)data;
	(void)dir;
	(void)name;
	(void)cookie;
	/* Metadata operations can also emit MODIFY with INODE/DENTRY data after
	 * the delegated source operation already sent its native notification.
	 */
	if (!mark || data_type != FSNOTIFY_EVENT_PATH || !(mask & KASUMI_IO_NOTIFY_MASK))
		return 0;
	relay = container_of(mark, struct kasumi_io_notify, mark);
	kasumi_io_notify_source(&relay->source, mask);
	return 0;
}

static void kasumi_io_notify_free(struct fsnotify_mark *mark)
{
	struct kasumi_io_notify *relay = container_of(mark, struct kasumi_io_notify, mark);

	path_put(&relay->source);
	kfree(relay);
	if (atomic_dec_and_test(&kasumi_io_notify_marks))
		wake_up_all(&kasumi_io_notify_wait);
}

static const struct fsnotify_ops kasumi_io_notify_ops = {
	.handle_event = kasumi_io_notify_event,
	.free_mark = kasumi_io_notify_free,
};

struct fsnotify_mark *kasumi_io_notify_alive_mark(struct kasumi_io_notify *relay)
{
	unsigned int needed = FSNOTIFY_MARK_FLAG_ATTACHED | FSNOTIFY_MARK_FLAG_ALIVE;

	return relay && (READ_ONCE(relay->mark.flags) & needed) == needed ?
		&relay->mark : NULL;
}

int KASUMI_NOCFI kasumi_io_notify_attach(struct inode *inode,
	const struct path *source, struct kasumi_io_notify **result)
{
	struct kasumi_io_notify *relay;
	unsigned int nofs;
	int error;

	*result = NULL;
	if (!READ_ONCE(kasumi_io_notify_admitting))
		return -ESHUTDOWN;
	if (!source || !source->dentry || !source->mnt || !d_inode(source->dentry))
		return -EINVAL;
	/* Sources are immutable and already published before a new vnode is
	 * attached, so nested vnode sources form an acyclic ownership chain.
	 */
	if (d_inode(source->dentry) == inode)
		return -ELOOP;
	relay = kzalloc(sizeof(*relay), GFP_NOFS);
	if (!relay)
		return -ENOMEM;
	relay->source = *source;
	path_get(&relay->source);
	atomic_inc(&kasumi_io_notify_marks);
	fsnotify_init_mark(&relay->mark, kasumi_io_notify_group);
	relay->mark.mask = KASUMI_IO_NOTIFY_MASK;
#ifdef FSNOTIFY_MARK_FLAG_NO_IREF
	relay->mark.flags |= FSNOTIFY_MARK_FLAG_NO_IREF;
#endif
	/* Child publication can still hold the delegated source directory lock. */
	nofs = memalloc_nofs_save();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	error = kasumi_io_add_mark(&relay->mark, inode, FSNOTIFY_OBJ_TYPE_INODE, 0);
#else
	error = kasumi_io_add_mark(&relay->mark, &inode->i_fsnotify_marks,
		FSNOTIFY_OBJ_TYPE_INODE, 0, NULL);
#endif
	memalloc_nofs_restore(nofs);
	if (error) {
		fsnotify_put_mark(&relay->mark);
		return error;
	}
	/* The initial reference belongs to vnode_info until detach. It also
	 * keeps this pointer valid if eviction or unmount detaches the mark first.
	 */
	*result = relay;
	return 0;
}

void kasumi_io_notify_detach(struct kasumi_io_notify *relay)
{
	if (!relay)
		return;
	fsnotify_destroy_mark(&relay->mark, relay->mark.group);
	fsnotify_put_mark(&relay->mark);
}

int KASUMI_NOCFI kasumi_io_notify_init(void)
{
	int error;

	if (kasumi_io_notify_group)
		return 0;
	kasumi_io_alloc_group = (void *)kasumi_lookup_callable_quiet("fsnotify_alloc_group");
	kasumi_io_destroy_group = (void *)kasumi_lookup_callable_quiet("fsnotify_destroy_group");
	kasumi_io_add_mark = (void *)kasumi_lookup_callable_quiet("fsnotify_add_mark");
	if (!kasumi_io_alloc_group || !kasumi_io_destroy_group || !kasumi_io_add_mark)
		return -EOPNOTSUPP;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	kasumi_io_notify_group = kasumi_io_alloc_group(&kasumi_io_notify_ops, 0);
#else
	kasumi_io_notify_group = kasumi_io_alloc_group(&kasumi_io_notify_ops);
#endif
	if (IS_ERR(kasumi_io_notify_group)) {
		int error = PTR_ERR(kasumi_io_notify_group);

		kasumi_io_notify_group = NULL;
		return error;
	}
	error = kasumi_io_notify_unlink_init();
	if (error) {
		kasumi_io_destroy_group(kasumi_io_notify_group);
		kasumi_io_notify_group = NULL;
		return error;
	}
	WRITE_ONCE(kasumi_io_notify_admitting, true);
	return 0;
}

void KASUMI_NOCFI kasumi_io_notify_exit(void)
{
	kasumi_io_notify_stop();
	if (!kasumi_io_notify_group)
		return;
	kasumi_io_notify_unlink_exit();
	kasumi_io_destroy_group(kasumi_io_notify_group);
	kasumi_io_notify_group = NULL;
	wait_event(kasumi_io_notify_wait, !atomic_read(&kasumi_io_notify_marks));
}

/* The caller holds its per-inode notification mutex. Each successful native
 * open retains one user until ->release, including all queued I/O file refs.
 * Old kernels pin the inode from the mark. Last release detaches that mark
 * while the outer file still owns its inode, breaking the ownership cycle.
 * NO_IREF marks stay cached until inode reclaim, so repeated open/close does
 * not rebuild connectors or repeatedly schedule native mark retirement.
 */
int kasumi_io_notify_get(struct inode *inode, const struct path *source,
	struct kasumi_io_notify **slot)
{
	struct kasumi_io_notify *previous = *slot, *replacement;
	int error;

	if (!READ_ONCE(kasumi_io_notify_admitting))
		return -ESHUTDOWN;
	if (kasumi_io_notify_alive_mark(previous)) {
		(*slot)->users++;
		return 0;
	}
	error = kasumi_io_notify_attach(inode, source, &replacement);
	if (!error) {
		replacement->users = (previous ? previous->users : 0) + 1;
		*slot = replacement;
		kasumi_io_notify_detach(previous);
	}
	return error;
}

void kasumi_io_notify_put(struct kasumi_io_notify **slot)
{
	struct kasumi_io_notify *relay = *slot;

	if (!relay || --relay->users)
		return;
#ifndef FSNOTIFY_MARK_FLAG_NO_IREF
	*slot = NULL;
	kasumi_io_notify_detach(relay);
#endif
}

void kasumi_io_notify_stop(void)
{
	WRITE_ONCE(kasumi_io_notify_admitting, false);
}
