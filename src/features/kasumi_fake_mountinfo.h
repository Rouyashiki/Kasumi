/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - interfaces for isolated mountinfo views.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _KASUMI_FAKE_MOUNTINFO_H
#define _KASUMI_FAKE_MOUNTINFO_H

#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/refcount.h>

struct mnt_namespace;

struct kasumi_mi_snapshot {
	refcount_t refs;
	char *data;
	size_t len;
	char *mounts;
	size_t mounts_len;
};

int kasumi_fake_mi_init(void);
void kasumi_fake_mi_exit(void);
bool kasumi_fake_mi_active(void);
int kasumi_fake_mi_get_snapshot(struct file *file,
				const struct file_operations *ops,
				struct mnt_namespace **original_ns,
				struct kasumi_mi_snapshot **out);
void kasumi_fake_mi_put_snapshot(struct kasumi_mi_snapshot *snapshot);
bool kasumi_fake_mi_cached(void);
void kasumi_fake_mi_put_ns(struct mnt_namespace *ns);
void kasumi_fake_mi_invalidate_all(void);
u64 kasumi_fake_mi_generation(void);
void kasumi_fake_mi_poll_wait(struct file *file,
			      struct poll_table_struct *wait);

#endif
