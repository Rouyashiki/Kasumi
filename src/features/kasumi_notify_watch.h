#ifndef _KASUMI_NOTIFY_WATCH_H
#define _KASUMI_NOTIFY_WATCH_H

#include <linux/fsnotify_backend.h>
#include <linux/path.h>

struct kasumi_notify_pending;

/* Build paths, names and permission decisions before taking native mark locks. */
int kasumi_notify_watch_prepare(const struct path *visible, u32 mask,
	struct fsnotify_group *group, struct kasumi_notify_pending **pending);
/* Called under the admitted native group's mark_mutex, before mask mutation. */
int kasumi_notify_watch_select(struct kasumi_notify_pending *pending,
	struct fsnotify_group *group, struct fsnotify_mark *existing);
void kasumi_notify_watch_attached(struct kasumi_notify_pending *pending,
	struct fsnotify_mark *mark, u32 mask);
/* Consumes pending after the native syscall has released its mark locks. */
void kasumi_notify_watch_complete(struct kasumi_notify_pending *pending, long result);
void kasumi_notify_watch_rules_changed(void);
int kasumi_notify_watch_init(void);
void kasumi_notify_watch_stop(void);

#endif
