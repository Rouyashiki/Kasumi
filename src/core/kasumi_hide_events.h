#ifndef _KASUMI_HIDE_EVENTS_H
#define _KASUMI_HIDE_EVENTS_H

#include <linux/cred.h>
#include <linux/hashtable.h>
#include <linux/mutex.h>
#include <linux/path.h>
#include <linux/poll.h>
#include <linux/wait.h>

struct kasumi_hide_events {
	DECLARE_HASHTABLE(marks, 8);
	struct mutex watch_mutex;
	struct path root;
	const struct cred *cred;
	struct file *mountinfo;
	struct fsnotify_group *directories;
	poll_table table;
	wait_queue_entry_t wait;
	wait_queue_head_t *head;
	void (*notify)(void *data);
	void *data;
	bool stopping;
	int error;
};

struct kasumi_hide_watch;
bool kasumi_hide_events_supported(void);
int kasumi_hide_events_watch_path(struct kasumi_hide_events *events,
				  const char *parent, const char *leaf,
				  struct path *resolved,
				  struct kasumi_hide_watch **watches,
				  void (*notify)(void *), void *data);
void kasumi_hide_events_unwatch(struct kasumi_hide_watch *watches);

int kasumi_hide_events_open(struct kasumi_hide_events *events,
			    void (*notify)(void *), void *data);
int kasumi_hide_events_open_scope(struct kasumi_hide_events *events,
	const struct path *root, const struct cred *cred,
	void (*notify)(void *), void *data);
int kasumi_hide_events_ack(struct kasumi_hide_events *events);
int kasumi_hide_events_resolve(struct kasumi_hide_events *events,
			       const char *name, struct path *path);
void kasumi_hide_events_stop(struct kasumi_hide_events *events);
/* The caller drains its resolver before closing the scope. */
void kasumi_hide_events_close(struct kasumi_hide_events *events);

#endif
