/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - interfaces for lookup-time inode_operations shadow overrides.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _KASUMI_IOP_OVERRIDE_H
#define _KASUMI_IOP_OVERRIDE_H

#include <linux/fs.h>

/* Module init/exit. Returns 0 on success. */
int kasumi_iop_override_init(void);
void kasumi_iop_override_stop_new(void);
void kasumi_iop_override_exit(void);
unsigned int kasumi_iop_override_active(void);
bool kasumi_iop_override_quiesced(void);

/* Rule owners retain their source path until the matching put. */
int kasumi_iop_get(const struct path *path);
void kasumi_iop_put(const struct path *path);
void kasumi_iop_override_drain(void);
void kasumi_iop_retire_batch_begin(void);
void kasumi_iop_retire_batch_end(void);
const struct inode_operations *kasumi_iop_original_iops(const struct inode *inode);
int kasumi_iop_install(struct inode *inode);

/*
 * Apply kstat spoofing in place. Extracted from the original vfs_getattr
 * kretprobe ret handler so both the legacy kprobe and the new shadow getattr
 * share one implementation.
 *
 * Caller must have a valid inode and stat. Safe to call from atomic context.
 */
void kasumi_apply_kstat_spoof(struct inode *inode, struct kstat *stat);

#endif /* _KASUMI_IOP_OVERRIDE_H */
