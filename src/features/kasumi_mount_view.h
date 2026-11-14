#ifndef KASUMI_MOUNT_VIEW_H
#define KASUMI_MOUNT_VIEW_H

#include <linux/path.h>
#include <linux/types.h>

struct mnt_namespace;
struct task_struct;
struct kasumi_mount_view;

#define KASUMI_MOUNT_VIEW_ATTEMPTS 3

#define KASUMI_MOUNT_CAP_INFO (1ULL << 0)
#define KASUMI_MOUNT_CAP_MOUNTS (1ULL << 1)
#define KASUMI_MOUNT_CAP_STATS (1ULL << 2)
#define KASUMI_MOUNT_CAP_FDINFO (1ULL << 3)
#define KASUMI_MOUNT_CAP_STATX (1ULL << 4)
#define KASUMI_MOUNT_CAP_UNIQUE (1ULL << 5)
#define KASUMI_MOUNT_CAP_STATFS (1ULL << 6)
#define KASUMI_MOUNT_CAP_STATMOUNT (1ULL << 7)
#define KASUMI_MOUNT_CAP_LISTMOUNT (1ULL << 8)

struct kasumi_mount_record {
	/* Dereference only under namespace_sem after view_current succeeds. */
	struct vfsmount *mount;
	u64 id;
	u64 unique_id;
	u64 parent_id;
	u64 parent_unique_id;
	u32 alias_index;
	unsigned int root_sequence;
	unsigned int mountpoint_sequence;
	bool in_view;
	bool retained;
};

int kasumi_mount_view_init(void);
void kasumi_mount_view_exit(void);
/* One topology attempt. Callers bound retries across the complete operation. */
int kasumi_mount_view_get(struct mnt_namespace *ns, const struct path *root,
			  struct kasumi_mount_view **result);
int kasumi_mount_view_get_current(struct kasumi_mount_view **result);
int kasumi_mount_view_get_task(struct task_struct *task,
			       struct kasumi_mount_view **result);
void kasumi_mount_view_get_ref(struct kasumi_mount_view *view);
/* Caller must be in sleepable context. */
void kasumi_mount_view_put(struct kasumi_mount_view *view);
u32 kasumi_mount_view_count(const struct kasumi_mount_view *view);
const struct kasumi_mount_record *
kasumi_mount_view_at(const struct kasumi_mount_view *view, u32 index);
const struct kasumi_mount_record *
kasumi_mount_view_find(const struct kasumi_mount_view *view, u64 id, bool unique);
const struct kasumi_mount_record *
kasumi_mount_view_representative(const struct kasumi_mount_view *view,
				const struct kasumi_mount_record *record);
struct mnt_namespace *
kasumi_mount_view_namespace(const struct kasumi_mount_view *view);
const struct path *kasumi_mount_view_root(const struct kasumi_mount_view *view);
u64 kasumi_mount_view_generation(const struct kasumi_mount_view *view);
bool kasumi_mount_view_current(const struct kasumi_mount_view *view);
bool kasumi_mount_view_record_current(const struct kasumi_mount_view *view,
				      const struct kasumi_mount_record *record);
int kasumi_mount_view_normalize_groups(const struct kasumi_mount_view *view,
				       char *record, size_t *length);
u32 kasumi_mount_view_group_id(const struct kasumi_mount_view *view, u32 id);
bool kasumi_mount_groups_active(void);
bool kasumi_mount_view_available(void);
u64 kasumi_mount_view_capabilities(void);
u64 kasumi_mount_view_required_capabilities(void);
void kasumi_mount_view_publish_capabilities(u64 set, u64 clear);
bool kasumi_mount_projection_active(void);
bool kasumi_mount_projection_available(void);

#endif
