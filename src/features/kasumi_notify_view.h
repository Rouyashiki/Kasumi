#ifndef _KASUMI_NOTIFY_VIEW_H
#define _KASUMI_NOTIFY_VIEW_H

#include <linux/types.h>

#define KASUMI_NOTIFY_INOTIFY (1U << 0)
#define KASUMI_NOTIFY_FANOTIFY_INODE (1U << 1)
#define KASUMI_NOTIFY_MULTISOURCE_INOTIFY (1U << 2)
#define KASUMI_NOTIFY_MULTISOURCE_FANOTIFY (1U << 3)

struct path;
int kasumi_notify_resolve_source(struct path *source, u64 mask);
u32 kasumi_notify_view_capabilities(void);
int kasumi_notify_view_init(void);
void kasumi_notify_view_stop(void);
void kasumi_notify_view_exit(void);

#endif
