#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/fsnotify_backend.h>
#include <linux/pid.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/version.h>

#include "kasumi_base.h"
#include "kasumi_hide_events.h"
#include "kasumi_runtime.h"

static typeof(file_open_root) *hide_file_open_root;
static void (*hide_fput_sync)(struct file *file);
static const struct file_operations *hide_mountinfo_ops;
static typeof(fsnotify_alloc_group) *hide_alloc_group;
static typeof(fsnotify_destroy_group) *hide_destroy_group;
static typeof(fsnotify_init_mark) *hide_init_mark;
static typeof(fsnotify_add_mark) *hide_add_mark;
static typeof(fsnotify_destroy_mark) *hide_destroy_mark;
static typeof(fsnotify_put_mark) *hide_put_mark;

struct kasumi_hide_watch {
	struct fsnotify_mark mark;
	struct kasumi_hide_events *events;
	struct kasumi_hide_watch *next;
	size_t len;
	char name[];
};

static int hide_directory_event(struct fsnotify_mark *mark, u32 mask,
				struct inode *inode, struct inode *dir,
				const struct qstr *name, u32 cookie)
{
	struct kasumi_hide_watch *watch =
	    container_of(mark, struct kasumi_hide_watch, mark);
	struct kasumi_hide_events *events = watch->events;

	if (!READ_ONCE(events->stopping) &&
	    ((mask & (FS_DELETE_SELF | FS_MOVE_SELF | FS_UNMOUNT)) || !name ||
	     (name->len == watch->len &&
	      !memcmp(name->name, watch->name, watch->len))))
		events->notify(events->data);
	return 0;
}

static void hide_free_mark(struct fsnotify_mark *mark)
{
	kfree(container_of(mark, struct kasumi_hide_watch, mark));
}

static const struct fsnotify_ops hide_directory_ops = {
    .handle_inode_event = hide_directory_event,
    .free_mark = hide_free_mark,
};

static int KASUMI_NOCFI hide_watch_add(struct kasumi_hide_events *events,
				       struct inode *inode, const char *name,
				       size_t len,
				       struct kasumi_hide_watch **head)
{
	struct kasumi_hide_watch *watch;
	int ret;

	watch = kzalloc(sizeof(*watch) + len + 1, GFP_KERNEL);
	if (!watch)
		return -ENOMEM;
	watch->events = events;
	watch->len = len;
	memcpy(watch->name, name, len);
	hide_init_mark(&watch->mark, events->directories);
	watch->mark.mask = FS_CREATE | FS_DELETE | FS_MOVED_FROM | FS_MOVED_TO |
			   FS_DELETE_SELF | FS_MOVE_SELF | FS_UNMOUNT |
			   FS_EVENT_ON_CHILD;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	ret = hide_add_mark(&watch->mark, inode, FSNOTIFY_OBJ_TYPE_INODE, 0);
#else
	ret = hide_add_mark(&watch->mark, &inode->i_fsnotify_marks,
			    FSNOTIFY_OBJ_TYPE_INODE,
#ifdef FSNOTIFY_GROUP_DUPS
			    0,
#else
			    1,
#endif
			    NULL);
#endif
	if (ret) {
		hide_put_mark(&watch->mark);
		return ret;
	}
	watch->next = *head;
	*head = watch;
	return 0;
}

void KASUMI_NOCFI kasumi_hide_events_unwatch(struct kasumi_hide_watch *watch)
{
	while (watch) {
		struct kasumi_hide_watch *next = watch->next;

		hide_destroy_mark(&watch->mark, watch->events->directories);
		hide_put_mark(&watch->mark);
		watch = next;
	}
}

static struct file *KASUMI_NOCFI
hide_open_root(struct kasumi_hide_events *events, const char *name, int flags)
{
	const struct cred *old = override_creds(events->cred);
	struct file *file;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
	file = hide_file_open_root(events->root.dentry, events->root.mnt, name,
				   flags, 0);
#else
	file = hide_file_open_root(&events->root, name, flags, 0);
#endif
	revert_creds(old);
	return file;
}

static int hide_wake(wait_queue_entry_t *wait, unsigned int mode, int sync,
		     void *key)
{
	struct kasumi_hide_events *events =
	    container_of(wait, struct kasumi_hide_events, wait);
	__poll_t mask = key_to_poll(key);

	if (mask & POLLFREE) {
		WRITE_ONCE(events->error, -EIO);
		list_del_init(&wait->entry);
		WRITE_ONCE(events->head, NULL);
	}
	if (!READ_ONCE(events->stopping) &&
	    (!key || (mask & (EPOLLPRI | EPOLLERR | EPOLLHUP | POLLFREE))))
		events->notify(events->data);
	return 0;
}

static void hide_queue(struct file *file, wait_queue_head_t *head,
		       poll_table *table)
{
	struct kasumi_hide_events *events =
	    container_of(table, struct kasumi_hide_events, table);

	if (events->head) {
		events->error = -EOPNOTSUPP;
		return;
	}
	events->head = head;
	add_wait_queue(head, &events->wait);
}

static __poll_t KASUMI_NOCFI hide_poll(struct file *file, poll_table *table)
{
	return file->f_op->poll(file, table);
}

int kasumi_hide_events_ack(struct kasumi_hide_events *events)
{
	__poll_t mask;

	if (READ_ONCE(events->error))
		return READ_ONCE(events->error);
	mask = hide_poll(events->mountinfo, NULL);
	if (mask & EPOLLHUP) {
		WRITE_ONCE(events->error, -EIO);
		return -EIO;
	}
	return (mask & (EPOLLPRI | EPOLLERR)) ? 1 : 0;
}

static void KASUMI_NOCFI hide_close_path_file(struct file *file)
{
	/* A kworker's deferred fput would retain the target mount after BOUND
	 * is published, making a subsequent ordinary umount spuriously busy. */
	if (current->flags & PF_KTHREAD)
		hide_fput_sync(file);
	else
		fput(file);
}

int kasumi_hide_events_resolve(struct kasumi_hide_events *events,
			       const char *name, struct path *path)
{
	struct file *file = hide_open_root(events, name, O_PATH | O_DIRECTORY);
	int ret;

	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		if (ret != -ENOENT)
			return ret;
		file = hide_open_root(events, name, O_PATH | O_NOFOLLOW);
		if (IS_ERR(file))
			return ret;
		/* A dangling symlink can point outside the watched ancestor
		 * chain. Report this limit instead of promising a
		 * target-creation event. */
		ret = S_ISLNK(file_inode(file)->i_mode) ? -EOPNOTSUPP : -EAGAIN;
		hide_close_path_file(file);
		return ret;
	}
	*path = file->f_path;
	path_get(path);
	hide_close_path_file(file);
	return 0;
}

int kasumi_hide_events_watch_path(struct kasumi_hide_events *events,
				  const char *parent, const char *leaf,
				  struct path *resolved,
				  struct kasumi_hide_watch **watches)
{
	struct path path = {}, next;
	char *buffer = kstrdup(parent, GFP_KERNEL), *cursor, *end;
	int ret;

	if (!buffer)
		return -ENOMEM;
	ret = kasumi_hide_events_resolve(events, "/", &path);
	if (ret)
		goto out;
	cursor = buffer;
	while (*cursor) {
		while (*cursor == '/')
			cursor++;
		if (!*cursor)
			break;
		end = strchrnul(cursor, '/');
		ret = hide_watch_add(events, d_inode(path.dentry), cursor,
				     end - cursor, watches);
		if (ret)
			goto out;
		/* Subscribe before resolving the next component, including
		 * missing ancestors. No lexical folding of symlinks or '..' is
		 * performed. */
		if (*end) {
			*end = '\0';
			ret = kasumi_hide_events_resolve(events, buffer, &next);
			*end = '/';
		} else {
			ret = kasumi_hide_events_resolve(events, buffer, &next);
		}
		if (ret)
			goto out;
		path_put(&path);
		path = next;
		cursor = end;
	}
	ret = hide_watch_add(events, d_inode(path.dentry), leaf, strlen(leaf),
			     watches);
	if (!ret) {
		*resolved = path;
		memset(&path, 0, sizeof(path));
	}
out:
	if (path.dentry)
		path_put(&path);
	kfree(buffer);
	return ret;
}

int KASUMI_NOCFI kasumi_hide_events_open(struct kasumi_hide_events *events,
					 void (*notify)(void *), void *data)
{
	struct task_struct *task = NULL;
	struct pid *pid;
	int ret = -ESRCH;

	memset(events, 0, sizeof(*events));
	events->stopping = true;
	hide_file_open_root = (void *)kasumi_lookup_callable("file_open_root");
	hide_fput_sync = (void *)kasumi_lookup_callable("__fput_sync");
	hide_mountinfo_ops =
	    (void *)kasumi_lookup_callable("proc_mountinfo_operations");
	hide_alloc_group =
	    (void *)kasumi_lookup_callable("fsnotify_alloc_group");
	hide_destroy_group =
	    (void *)kasumi_lookup_callable("fsnotify_destroy_group");
	hide_init_mark = (void *)kasumi_lookup_callable("fsnotify_init_mark");
	hide_add_mark = (void *)kasumi_lookup_callable("fsnotify_add_mark");
	hide_destroy_mark =
	    (void *)kasumi_lookup_callable("fsnotify_destroy_mark");
	hide_put_mark = (void *)kasumi_lookup_callable("fsnotify_put_mark");
	if (!hide_file_open_root || !hide_mountinfo_ops || !hide_fput_sync ||
	    !hide_alloc_group || !hide_destroy_group || !hide_init_mark ||
	    !hide_add_mark || !hide_destroy_mark || !hide_put_mark)
		return -EOPNOTSUPP;
	pid = find_get_pid(1);
	if (!pid)
		return ret;
	rcu_read_lock();
	task = pid_task(pid, PIDTYPE_PID);
	if (task && task_pid_nr(task) == 1)
		get_task_struct(task);
	else
		task = NULL;
	rcu_read_unlock();
	put_pid(pid);
	if (!task)
		return ret;
	task_lock(task);
	if (task->fs) {
		get_fs_root(task->fs, &events->root);
		ret = 0;
	}
	task_unlock(task);
	events->cred = get_task_cred(task);
	put_task_struct(task);
	if (ret)
		goto fail;
	events->mountinfo =
	    hide_open_root(events, "/proc/1/mountinfo", O_RDONLY);
	if (IS_ERR(events->mountinfo)) {
		ret = PTR_ERR(events->mountinfo);
		events->mountinfo = NULL;
		goto fail;
	}
	/* A native proc file owns both the namespace and its poll queue. */
	if (events->mountinfo->f_op != hide_mountinfo_ops ||
	    !events->mountinfo->f_op->poll) {
		ret = -EOPNOTSUPP;
		goto fail;
	}
	events->notify = notify;
	events->data = data;
#ifdef FSNOTIFY_GROUP_DUPS
	events->directories =
	    hide_alloc_group(&hide_directory_ops, FSNOTIFY_GROUP_DUPS);
#else
	events->directories = hide_alloc_group(&hide_directory_ops);
#endif
	if (IS_ERR(events->directories)) {
		ret = PTR_ERR(events->directories);
		events->directories = NULL;
		goto fail;
	}
	init_waitqueue_func_entry(&events->wait, hide_wake);
	init_poll_funcptr(&events->table, hide_queue);
	events->table._key = EPOLLPRI | EPOLLERR;
	hide_poll(events->mountinfo, &events->table);
	if (!events->head || events->error) {
		ret = events->error ?: -EOPNOTSUPP;
		goto fail;
	}
	WRITE_ONCE(events->stopping, false);
	return 0;
fail:
	kasumi_hide_events_stop(events);
	kasumi_hide_events_close(events);
	return ret;
}

void kasumi_hide_events_stop(struct kasumi_hide_events *events)
{
	wait_queue_head_t *head;

	WRITE_ONCE(events->stopping, true);
	/* mountinfo keeps the native namespace alive until close, including
	 * while this removal waits for an in-flight wake callback. */
	head = READ_ONCE(events->head);
	if (head)
		remove_wait_queue(head, &events->wait);
	events->head = NULL;
}

void KASUMI_NOCFI kasumi_hide_events_close(struct kasumi_hide_events *events)
{
	if (events->directories)
		hide_destroy_group(events->directories);
	if (events->mountinfo)
		fput(events->mountinfo);
	if (events->root.dentry)
		path_put(&events->root);
	if (events->cred)
		put_cred(events->cred);
	memset(events, 0, sizeof(*events));
}
