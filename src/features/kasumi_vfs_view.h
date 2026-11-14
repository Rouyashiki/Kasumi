#ifndef KASUMI_VFS_VIEW_H
#define KASUMI_VFS_VIEW_H

#include <linux/types.h>

struct kasumi_xattr_sb_entry;

int kasumi_vfs_view_init(void);
void kasumi_vfs_view_stop(void);
void kasumi_vfs_view_drain(void);
void kasumi_vfs_view_exit(void);
bool kasumi_overlay_xattr_available(void);
bool kasumi_source_xattr_available(void);
bool kasumi_statfs_view_available(void);
int kasumi_overlay_xattr_mark(const char *path);
int kasumi_overlay_xattr_mark_at(const char *path, u64 generation);
void kasumi_overlay_xattr_retire(struct kasumi_xattr_sb_entry *entry);

#endif
