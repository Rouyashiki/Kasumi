/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - overlay merge and injection helper interfaces.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _KASUMI_OVERLAY_H
#define _KASUMI_OVERLAY_H

#include <linux/fs.h>
#include <linux/list.h>

void kasumi_add_inject_rule(char *dir);
void kasumi_materialize_merge(const char *src_prefix, const char *target_dir,
			      int depth, u32 rule_flags);
void kasumi_populate_injected_list(const char *dir_path, struct dentry *parent,
				   struct list_head *head);

#endif /* _KASUMI_OVERLAY_H */
