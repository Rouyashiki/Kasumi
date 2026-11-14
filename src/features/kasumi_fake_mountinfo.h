/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - interfaces for isolated mountinfo views.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef KASUMI_FAKE_MOUNTINFO_H
#define KASUMI_FAKE_MOUNTINFO_H

#include <linux/fs.h>
#include <linux/poll.h>

u64 kasumi_fake_mi_policy_generation(void);
int kasumi_fake_mi_classify_mount(const char *line, size_t len, bool *hidden);
int kasumi_fake_mi_init(void);
void kasumi_fake_mi_exit(void);
bool kasumi_fake_mi_active(void);
void kasumi_fake_mi_invalidate_all(void);
u64 kasumi_fake_mi_generation(void);
void kasumi_fake_mi_poll_wait(struct file *file, struct poll_table_struct *wait);

#endif
