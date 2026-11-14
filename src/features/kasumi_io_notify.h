#ifndef _KASUMI_IO_NOTIFY_H
#define _KASUMI_IO_NOTIFY_H

struct inode;
struct path;
struct kasumi_io_notify;
struct fsnotify_mark;

/* Initialize before publishing source-backed vnodes. */
int kasumi_io_notify_init(void);
/* Stop admitting new files. Existing inode notifications remain available. */
void kasumi_io_notify_stop(void);
/* Call after vnode users and inode owners have drained. */
void kasumi_io_notify_exit(void);

int kasumi_io_notify_attach(struct inode *inode, const struct path *source,
	struct kasumi_io_notify **result);
/* Releases the inode owner's reference. The native mark SRCU grace period
 * protects callbacks and the independently held source path until final free.
 */
void kasumi_io_notify_detach(struct kasumi_io_notify *relay);
/* Serialize get/put with the vnode notification mutex. Last put runs while
 * the releasing outer file still pins its inode. */
int kasumi_io_notify_get(struct inode *inode, const struct path *source,
	struct kasumi_io_notify **slot);
void kasumi_io_notify_put(struct kasumi_io_notify **slot);

/* Borrowed under the vnode notification mutex; NULL for a retired mark. */
struct fsnotify_mark *kasumi_io_notify_alive_mark(struct kasumi_io_notify *relay);
int kasumi_io_notify_unlink_init(void);
void kasumi_io_notify_unlink_exit(void);

#endif
