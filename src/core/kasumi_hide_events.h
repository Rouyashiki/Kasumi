#ifndef _KASUMI_HIDE_EVENTS_H
#define _KASUMI_HIDE_EVENTS_H

#include <linux/cred.h>
#include <linux/path.h>
#include <linux/poll.h>
#include <linux/wait.h>

struct kasumi_hide_events {
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
int kasumi_hide_events_watch_path(struct kasumi_hide_events *events,
				  const char *parent, const char *leaf,
				  struct path *resolved,
				  struct kasumi_hide_watch **watches);
void kasumi_hide_events_unwatch(struct kasumi_hide_watch *watches);

int kasumi_hide_events_open(struct kasumi_hide_events *events,
			    void (*notify)(void *), void *data);
int kasumi_hide_events_ack(struct kasumi_hide_events *events);
int kasumi_hide_events_resolve(struct kasumi_hide_events *events,
			       const char *name, struct path *path);
void kasumi_hide_events_stop(struct kasumi_hide_events *events);
/* The caller drains its resolver before closing the scope. */
void kasumi_hide_events_close(struct kasumi_hide_events *events);

#endif
