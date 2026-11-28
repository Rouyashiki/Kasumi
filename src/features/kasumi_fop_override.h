/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - directory file_operations shadow overrides for readdir filtering.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _KASUMI_FOP_OVERRIDE_H
#define _KASUMI_FOP_OVERRIDE_H

#include "kasumi_dir_view.h"

typedef int (*kasumi_fop_iterate_client_fn)(struct file *file,
					    struct dir_context *ctx,
					    kasumi_dir_iterate_fn iterate,
					    void *data);

int kasumi_fop_override_init(void);
int kasumi_fop_live_count(void);
int kasumi_fop_retiring_count(void);
void kasumi_fop_override_stop_new(void);
void kasumi_fop_override_exit(void);
/* Retire all inode bindings without permanently disabling future installs.
 * Dynamic fops and their original-owner reference remain allocated until
 * module exit so already-open directory files stay safe. */
void kasumi_fop_override_clear(void);

int kasumi_fop_get(struct inode *inode, bool inject);
void kasumi_fop_put(struct inode *inode, bool inject);
/* Bind one specialized iterate client to an installed inode shadow.  The data
 * pointer is release-published with @client and is protected by the client SRCU
 * domain while callbacks execute. */
int kasumi_fop_bind_iterate_client(struct inode *inode,
				   kasumi_fop_iterate_client_fn client, void *data);
/* Withdraw a matching client.  Call synchronize_iterate_clients() before
 * freeing @data or rebinding this inode to different client data. */
void kasumi_fop_unbind_iterate_client(struct inode *inode, void *data);
void kasumi_fop_synchronize_iterate_clients(void);
bool kasumi_fop_file_is_shadowed(const struct file *file);
const struct file_operations *kasumi_fop_original_operations(const struct file *file);

#endif /* _KASUMI_FOP_OVERRIDE_H */
