/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _KASUMI_INSTANCE_H
#define _KASUMI_INSTANCE_H

#include <linux/compiler_types.h>

long kasumi_instance_watch(void __user *arg);
void kasumi_instance_exit(void);

#endif
