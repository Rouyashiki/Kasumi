#ifndef KASUMI_DIR_VIEW_H
#define KASUMI_DIR_VIEW_H

#include <linux/fs.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/version.h>

struct kasumi_inode_identity;

struct kasumi_dir_entry {
	struct list_head list;
	struct hlist_node name_node;
	struct dentry *name_dentry;
	u32 name_hash;
	struct kasumi_inode_identity *identity;
	struct kasumi_inode_identity *bypass_identity;
	u64 sequence;
	u64 bypass_sequence;
	u64 hide_sequence;
	u64 ino;
	u64 bypass_ino;
	u32 rule_flags;
	u32 hide_flags;
	u16 name_len;
	u8 type;
	u8 bypass_type;
	bool redirect;
	bool hide;
	bool hide_storage_managed;
	bool always_visible;
	bool bypass_redirect;
	bool direct_rule;
	bool bypass_direct_rule;
	char name[];
};

struct kasumi_dir_identity {
	struct kasumi_identity_domain *domain;
	dev_t source_dev;
	u64 dot_ino;
	u64 parent_ino;
	bool source_identity;
};

struct kasumi_dir_state;
struct kasumi_dir_native_guard {
	struct kasumi_dir_state *state;
	bool locked;
};

typedef int (*kasumi_dir_iterate_fn)(struct file *, struct dir_context *);

static inline kasumi_dir_iterate_fn
kasumi_dir_iterator(const struct file_operations *ops)
{
	if (!ops)
		return NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
	if (!ops->iterate_shared)
		return ops->iterate;
#endif
	return ops->iterate_shared;
}

typedef int (*kasumi_dir_collect_fn)(struct file *file,
				     struct list_head *entries, u64 *generation,
				     void *data);

int kasumi_dir_name_hash(struct dentry *parent, const char *name, size_t len,
			 u32 *hash);
struct dentry *kasumi_dir_name_probe(struct dentry *parent, const char *name,
				     size_t len);
bool kasumi_dir_name_equal(struct dentry *parent, struct dentry *candidate,
			   const char *candidate_name, size_t candidate_len,
			   const char *name, size_t len);

struct kasumi_dir_entry *kasumi_dir_entry_alloc(const char *name, size_t len,
						gfp_t flags);
void kasumi_dir_entries_free(struct list_head *entries);
int kasumi_dir_view_iterate(struct file *file, struct file *native,
			    kasumi_dir_iterate_fn iterate,
			    struct dir_context *ctx,
			    kasumi_dir_collect_fn collect, void *data,
			    const struct kasumi_dir_identity *identity);
loff_t kasumi_dir_view_llseek(struct file *file, struct file *native,
			      const struct file_operations *operations,
			      loff_t offset, int whence);
void kasumi_dir_view_release(struct file *file);
bool kasumi_dir_visible_pos(const struct file *file, loff_t *position);
void kasumi_dir_native_enter(struct file *file,
			     struct kasumi_dir_native_guard *guard);
void kasumi_dir_native_leave(struct file *file,
			     struct kasumi_dir_native_guard *guard);

#endif
