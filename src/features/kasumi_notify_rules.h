#ifndef _KASUMI_NOTIFY_RULES_H
#define _KASUMI_NOTIFY_RULES_H

#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/types.h>

/* Captured by the admitting watcher. Event producers never supply this scope. */
struct kasumi_notify_scope {
	bool active;
	bool view;
	bool hide;
	bool hide_storage;
	bool hide_bypass;
};

enum kasumi_notify_source_kind {
	KASUMI_NOTIFY_SOURCE_BASE,
	KASUMI_NOTIFY_SOURCE_LEAF,
	KASUMI_NOTIFY_SOURCE_TOPOLOGY,
};

struct kasumi_notify_source {
	enum kasumi_notify_source_kind kind;
	/* BASE and LEAF own this path and require the caller's source permission checks. */
	struct path path;
	/* TOPOLOGY owns only this internal refresh subscription, without user events. */
	struct dentry *topology;
};

struct kasumi_notify_event {
	u32 mask;
	u32 cookie;
	struct inode *inode;
	struct qstr name;
	bool named;
};

/* Names and inodes are borrowed until the emit callback returns. */
typedef int (*kasumi_notify_emit_fn)(void *data,
	const struct kasumi_notify_event *event);

struct kasumi_notify_rename_hint {
	struct inode *inode;
	struct qstr old_name;
	struct qstr new_name;
	u32 cookie;
};

struct kasumi_notify_snapshot;

void kasumi_notify_scope_capture(struct kasumi_notify_scope *scope);

/* Sleepable. Caller holds no native group/mark locks. A successful build owns
 * every source and name reference, and returns -EAGAIN across a generation change.
 * previous preserves names whose redirect or hide disappeared in this generation.
 */
int kasumi_notify_snapshot_build(const struct path *visible, u32 mask,
	const struct kasumi_notify_scope *scope, u64 generation,
	const struct kasumi_notify_snapshot *previous,
	struct kasumi_notify_snapshot **result);
void kasumi_notify_snapshot_get(struct kasumi_notify_snapshot *snapshot);
/* The final put releases paths and dentries and may sleep. */
void kasumi_notify_snapshot_put(struct kasumi_notify_snapshot *snapshot);
u64 kasumi_notify_snapshot_generation(const struct kasumi_notify_snapshot *snapshot);
/* True only for a successfully sampled pure virtual root whose supporting
 * rule prefixes disappeared. Temporary policy disablement never retires it.
 */
bool kasumi_notify_snapshot_root_retired(const struct kasumi_notify_snapshot *snapshot);
unsigned int kasumi_notify_snapshot_source_count(const struct kasumi_notify_snapshot *snapshot);
const struct kasumi_notify_source *kasumi_notify_snapshot_source(
	const struct kasumi_notify_snapshot *snapshot, unsigned int index);

/* Caller pins snapshot. Source indices remain stable for its lifetime. Sources
 * may share an inode through different mounts or roles. A native mark can serve
 * several indices, each passed here once. No lookup, iteration, or current-task
 * policy evaluation occurs here. refresh requests a new published-generation
 * snapshot and namespace diff after a source topology event.
 */
int kasumi_notify_snapshot_project(const struct kasumi_notify_snapshot *snapshot,
	unsigned int source_index, u32 mask, struct inode *inode, struct inode *dir,
	const struct qstr *name, u32 cookie, bool *refresh,
	kasumi_notify_emit_fn emit, void *data);

/* next was built with previous. Both snapshots and optional hint inode/name
 * references are held by caller.
 * Only a matching source inode and old/new source-name pair retains a rename
 * cookie. Other namespace replacements produce delete/create events.
 */
int kasumi_notify_snapshot_diff(const struct kasumi_notify_snapshot *previous,
	const struct kasumi_notify_snapshot *next,
	const struct kasumi_notify_rename_hint *hints, size_t hint_count,
	kasumi_notify_emit_fn emit, void *data);

#endif
