#ifndef _KASUMI_NOTIFY_FANOTIFY_H
#define _KASUMI_NOTIFY_FANOTIFY_H

#include <linux/types.h>

struct path;
struct fsnotify_group;
struct kasumi_fanotify_pending;

/* Called after the original visible-path LSM check, without native mark locks.
 * A positive result retains the visible inode for the native fanotify operation.
 * Zero leaves the existing single-source/mount/filesystem path in charge.
 */
int kasumi_notify_fanotify_prepare(const struct path *path, u64 mask,
	unsigned int type, unsigned int flags, struct fsnotify_group *expected_group,
	struct kasumi_fanotify_pending **pending);
void kasumi_notify_fanotify_complete(struct kasumi_fanotify_pending *pending,
	long result);
bool kasumi_notify_fanotify_internal(void);
void kasumi_notify_fanotify_rules_changed(void);
bool kasumi_notify_fanotify_supported(void);
int kasumi_notify_fanotify_init(void);
void kasumi_notify_fanotify_stop(void);
void kasumi_notify_fanotify_exit(void);

#endif
